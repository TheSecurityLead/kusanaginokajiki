//! Infrastructure device role classification.
//!
//! Identifies network infrastructure devices (switches, routers, firewalls,
//! access points, gateways) from asset metadata, protocol evidence, and LLDP
//! capability flags. Infrastructure devices are typically not ICS endpoints
//! but are critical to ICS network security.
//!
//! ## Classification Priority
//!
//! 1. Device type already set by LLDP (switch/router) → use directly
//! 2. Vendor + product name hints
//! 3. Protocol evidence (SNMP = managed, LLDP = infrastructure)
//! 4. Port / protocol profile (no OT protocols, only management protocols)

use serde::{Deserialize, Serialize};

use crate::AssetSnapshot;

// ─── Enum ─────────────────────────────────────────────────────────────────────

/// The network infrastructure role of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InfrastructureRole {
    /// Layer-2 forwarding device with management capabilities (SNMP, web UI).
    /// Includes industrial-grade OT switches.
    ManagedSwitch,
    /// Layer-2 forwarding device with no detected management interface.
    UnmanagedSwitch,
    /// Layer-3 device that routes between subnets.
    Router,
    /// Security boundary device (firewall, UTM, NGFW).
    Firewall,
    /// Wireless infrastructure (AP, WLAN controller).
    AccessPoint,
    /// Protocol or network gateway (e.g., IT/OT boundary, Modbus ↔ EtherNet/IP).
    Gateway,
    /// Device does not appear to be network infrastructure.
    NotInfrastructure,
}

impl InfrastructureRole {
    /// Return a human-readable label for display in the UI.
    pub fn label(self) -> &'static str {
        match self {
            Self::ManagedSwitch => "Managed Switch",
            Self::UnmanagedSwitch => "Unmanaged Switch",
            Self::Router => "Router",
            Self::Firewall => "Firewall",
            Self::AccessPoint => "Access Point",
            Self::Gateway => "Gateway",
            Self::NotInfrastructure => "Endpoint",
        }
    }

    /// Return the recommended Purdue level for this infrastructure role.
    ///
    /// Switches and APs are at the same level as the devices they connect;
    /// this returns a *maximum* boundary for violation detection purposes.
    pub fn purdue_level(self) -> Option<u8> {
        match self {
            // Switches/APs span levels — assign L2 (the HMI/SCADA layer) as default
            Self::ManagedSwitch | Self::UnmanagedSwitch | Self::AccessPoint => Some(2),
            // Routers sit at the DMZ (L3.5 represented as L3)
            Self::Router => Some(3),
            // Firewalls are DMZ devices
            Self::Firewall => Some(3),
            // Gateways sit between L3 (SCADA) and enterprise
            Self::Gateway => Some(3),
            Self::NotInfrastructure => None,
        }
    }

    /// Returns true if this device is any kind of infrastructure device.
    pub fn is_infrastructure(self) -> bool {
        !matches!(self, Self::NotInfrastructure)
    }
}

// ─── Classification ────────────────────────────────────────────────────────────

/// Classify the infrastructure role of an asset.
///
/// Uses device_type (set by LLDP or port analysis), vendor name, and protocol
/// profile to determine whether the device is network infrastructure and what
/// kind. Returns [`InfrastructureRole::NotInfrastructure`] for OT field devices
/// and IT servers that are not forwarding/routing devices.
pub fn classify_infrastructure(asset: &AssetSnapshot) -> InfrastructureRole {
    let device_type = asset.device_type.to_lowercase();
    let vendor = asset.vendor.as_deref().unwrap_or("").to_lowercase();
    let protocols: Vec<&str> = asset.protocols.iter().map(|s| s.as_str()).collect();

    // ── Step 1: Direct device_type match (set by LLDP or signature) ──────────

    if device_type == "switch" {
        // Check for management protocols to distinguish managed vs unmanaged
        return if has_management_protocol(&protocols) {
            InfrastructureRole::ManagedSwitch
        } else {
            InfrastructureRole::UnmanagedSwitch
        };
    }
    if device_type == "router" {
        return InfrastructureRole::Router;
    }
    if device_type == "firewall" || device_type == "utm" || device_type == "ngfw" {
        return InfrastructureRole::Firewall;
    }
    if device_type == "access_point" || device_type == "wlan_ap" {
        return InfrastructureRole::AccessPoint;
    }
    if device_type == "gateway" {
        return InfrastructureRole::Gateway;
    }

    // ── Step 1b: SCALANCE model detection from product/hostname/vendor ────────
    //
    // Siemens SCALANCE devices are identifiable from LLDP system_description,
    // SNMP sysDescr, PROFINET DCP name_of_station, or signature product_family.
    // The model prefix determines the infrastructure role:
    //   X/XC/XR/XB/XF/XP → ManagedSwitch
    //   W                → AccessPoint (industrial WLAN)
    //   M                → Router
    //   S/SC             → Firewall (security appliance)

    // Check product_family first (set from LLDP model or signatures)
    if let Some(ref pf) = asset.product_family {
        if let Some(role) = classify_scalance_model(pf) {
            return role;
        }
    }
    // Check hostname (from LLDP system_name or SNMP sysName, e.g. "scalance-xm408")
    if let Some(ref hn) = asset.hostname {
        if let Some(role) = classify_scalance_model(hn) {
            return role;
        }
    }
    // Check device_type (may carry model string from enrichment)
    if let Some(role) = classify_scalance_model(&device_type) {
        return role;
    }
    // Check vendor field (may contain "SCALANCE" if set from SNMP sysDescr)
    if let Some(role) = classify_scalance_model(&vendor) {
        return role;
    }

    // ── Step 2: Vendor + product name hints ────────────────────────────────────

    // Known OT switch vendors
    if is_ot_switch_vendor(&vendor) {
        return if has_management_protocol(&protocols) {
            InfrastructureRole::ManagedSwitch
        } else {
            InfrastructureRole::UnmanagedSwitch
        };
    }

    // Known firewall/router vendors
    if is_firewall_vendor(&vendor) {
        return InfrastructureRole::Firewall;
    }
    if is_router_vendor(&vendor) {
        return InfrastructureRole::Router;
    }

    // ── Step 3: Protocol-based inference ──────────────────────────────────────

    // Protocol-only devices (Spanning Tree, LLDP, etc. but no OT or server roles)
    // are likely infrastructure even if we didn't get LLDP caps
    let has_ot = protocols.iter().any(|p| is_ot_protocol(p));
    let has_management = has_management_protocol(&protocols);
    let has_snmp = protocols.contains(&"snmp");
    let has_only_management = !has_ot && has_management;

    if has_snmp && has_only_management {
        // SNMP-only with management suggests a managed switch or router
        return InfrastructureRole::ManagedSwitch;
    }

    // Tags check: if someone tagged the device as infrastructure
    for tag in &asset.tags {
        let t = tag.to_lowercase();
        if t == "switch" || t == "managed-switch" {
            return InfrastructureRole::ManagedSwitch;
        }
        if t == "unmanaged-switch" {
            return InfrastructureRole::UnmanagedSwitch;
        }
        if t == "router" {
            return InfrastructureRole::Router;
        }
        if t == "firewall" {
            return InfrastructureRole::Firewall;
        }
        if t == "access-point" || t == "ap" {
            return InfrastructureRole::AccessPoint;
        }
        if t == "gateway" {
            return InfrastructureRole::Gateway;
        }
    }

    InfrastructureRole::NotInfrastructure
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns true if the device has management protocols visible.
fn has_management_protocol(protocols: &[&str]) -> bool {
    protocols
        .iter()
        .any(|p| matches!(*p, "snmp" | "http" | "https" | "ssh" | "telnet" | "netconf"))
}

/// Returns true if the vendor is a known OT switch manufacturer.
fn is_ot_switch_vendor(vendor: &str) -> bool {
    let known = [
        "hirschmann",            // Hirschmann (Belden) MACH / OCTOPUS / MICE / SPIDER / EAGLE
        "ruggedcom",             // Siemens RuggedCom (RUGGEDSWITCH)
        "scalance",              // Siemens SCALANCE (may appear in product field)
        "moxa",                  // Moxa EDS / ICS series
        "westermo",              // Westermo (RED / MRD series)
        "phoenix contact",       // Phoenix Contact FL SWITCH
        "belden",                // Belden industrial switches
        "cisco ie",              // Cisco Industrial Ethernet
        "rockwell",              // Rockwell Stratix
        "stratix",               // Allen-Bradley Stratix
        "perle",                 // Perle industrial switches
        "korenix",               // Korenix (Westermo subsidiary)
        "antaira",               // Antaira
        "red lion",              // Red Lion N-Tron
        "n-tron",                // N-Tron (Red Lion)
        "contemporary controls", // Contemporary Controls BASrouter
        "garrettcom",            // GarrettCom (Belden)
        "datalogger",            // Various data acquisition switches
        "prosoft",               // ProSoft Technology gateways
    ];
    known.iter().any(|k| vendor.contains(k))
}

/// Returns true if the vendor is a known firewall vendor.
fn is_firewall_vendor(vendor: &str) -> bool {
    let known = [
        "palo alto",
        "fortinet",
        "checkpoint",
        "cisco asa",
        "cisco ftd",
        "juniper srx",
        "sonicwall",
        "watchguard",
        "barracuda",
        "sophos",
        "forcepoint",
        "tufin",
        "ixia",
    ];
    known.iter().any(|k| vendor.contains(k))
}

/// Returns true if the vendor is a known general-purpose router vendor.
fn is_router_vendor(vendor: &str) -> bool {
    let known = [
        "juniper",
        "mikrotik",
        "ubiquiti",
        "opnsense",
        "pfsense",
        "extreme networks",
        "hp networking",
        "aruba",
        "dell networking",
    ];
    known.iter().any(|k| vendor.contains(k))
}

/// Classify a Siemens SCALANCE device by model prefix.
///
/// Accepts any string that may contain a SCALANCE model designation
/// (e.g., SNMP sysDescr, LLDP system_description, hostname, product_family).
/// Returns the appropriate infrastructure role based on the product line:
///   - X, XC, XR, XB, XF, XP series → ManagedSwitch
///   - W series → AccessPoint (industrial WLAN)
///   - M series → Router
///   - S, SC series → Firewall (security appliance)
///
/// Returns `None` if the string does not contain "SCALANCE".
fn classify_scalance_model(model_string: &str) -> Option<InfrastructureRole> {
    let upper = model_string.to_uppercase();
    if !upper.contains("SCALANCE") {
        return None;
    }
    // Extract the letter after "SCALANCE " to determine product line
    if let Some(idx) = upper.find("SCALANCE") {
        let after = &upper[idx + "SCALANCE".len()..].trim_start();
        // W series: industrial wireless access points / controllers
        if after.starts_with('W') {
            return Some(InfrastructureRole::AccessPoint);
        }
        // M series: industrial routers (M800, M876, etc.)
        if after.starts_with('M') {
            return Some(InfrastructureRole::Router);
        }
        // SC series must be checked before S to avoid false match
        // S/SC series: industrial security appliances (firewalls)
        if after.starts_with("SC") || after.starts_with('S') {
            return Some(InfrastructureRole::Firewall);
        }
    }
    // Default for SCALANCE without a recognized letter prefix:
    // X, XC, XR, XB, XF, XP, or just "SCALANCE" → managed switch
    Some(InfrastructureRole::ManagedSwitch)
}

/// Returns true if a protocol string represents an OT/ICS protocol.
fn is_ot_protocol(proto: &str) -> bool {
    matches!(
        proto,
        "modbus"
            | "dnp3"
            | "ethernetip"
            | "bacnet"
            | "s7comm"
            | "opcua"
            | "profinet"
            | "iec104"
            | "mqtt"
            | "hartip"
            | "foundationfieldbus"
            | "gesrtp"
            | "wonderwaresuiteline"
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_asset(device_type: &str, vendor: Option<&str>, protocols: &[&str]) -> AssetSnapshot {
        AssetSnapshot {
            ip_address: "10.0.0.1".to_string(),
            device_type: device_type.to_string(),
            protocols: protocols.iter().map(|s| s.to_string()).collect(),
            purdue_level: None,
            is_public_ip: false,
            tags: Vec::new(),
            vendor: vendor.map(|v| v.to_string()),
            hostname: None,
            product_family: None,
        }
    }

    /// Helper to create an asset with product_family and hostname fields.
    fn make_scalance_asset(
        product_family: Option<&str>,
        hostname: Option<&str>,
        vendor: Option<&str>,
    ) -> AssetSnapshot {
        AssetSnapshot {
            ip_address: "10.0.0.1".to_string(),
            device_type: "unknown".to_string(),
            protocols: vec!["profinet".to_string(), "snmp".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: Vec::new(),
            vendor: vendor.map(|v| v.to_string()),
            hostname: hostname.map(|h| h.to_string()),
            product_family: product_family.map(|p| p.to_string()),
        }
    }

    #[test]
    fn test_switch_from_device_type() {
        let asset = make_asset("switch", None, &["snmp"]);
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::ManagedSwitch
        );
    }

    #[test]
    fn test_unmanaged_switch() {
        let asset = make_asset("switch", None, &[]); // no management protocols
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::UnmanagedSwitch
        );
    }

    #[test]
    fn test_router_from_device_type() {
        let asset = make_asset("router", None, &[]);
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::Router);
    }

    #[test]
    fn test_hirschmann_switch() {
        let asset = make_asset("unknown", Some("Hirschmann"), &["http", "snmp"]);
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::ManagedSwitch
        );
    }

    #[test]
    fn test_moxa_switch_no_mgmt() {
        let asset = make_asset("unknown", Some("Moxa"), &["modbus"]);
        // Moxa vendor but has OT protocol → still infrastructure (OT switch)
        // classify_infrastructure uses vendor hint, returns ManagedSwitch since
        // it's a known OT switch vendor even without mgmt protocols
        let role = classify_infrastructure(&asset);
        assert!(role.is_infrastructure());
    }

    #[test]
    fn test_plc_is_not_infrastructure() {
        let asset = make_asset("plc", Some("Siemens"), &["s7comm"]);
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::NotInfrastructure
        );
    }

    #[test]
    fn test_infrastructure_purdue_level() {
        assert_eq!(InfrastructureRole::ManagedSwitch.purdue_level(), Some(2));
        assert_eq!(InfrastructureRole::Router.purdue_level(), Some(3));
        assert_eq!(InfrastructureRole::NotInfrastructure.purdue_level(), None);
    }

    #[test]
    fn test_tag_based_classification() {
        let mut asset = make_asset("unknown", None, &[]);
        asset.tags = vec!["firewall".to_string()];
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::Firewall
        );
    }

    #[test]
    fn test_snmp_only_device() {
        // Device with only SNMP and HTTP (management) but no OT protocols
        let asset = make_asset("unknown", None, &["snmp", "http"]);
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::ManagedSwitch
        );
    }

    // ── SCALANCE detection tests ─────────────────────────────────────────────

    #[test]
    fn test_scalance_x_switch_from_snmp() {
        // SNMP sysDescr "SCALANCE X208-2 PN" in product_family → ManagedSwitch
        let asset = make_scalance_asset(Some("SCALANCE X208-2 PN"), None, Some("Siemens"));
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::ManagedSwitch
        );
    }

    #[test]
    fn test_scalance_xr_switch_from_lldp() {
        // LLDP system_name "SCALANCE XR524-8C 2PS" in product_family → ManagedSwitch
        let asset = make_scalance_asset(
            Some("SCALANCE XR524-8C 2PS"),
            Some("scalance-xr524"),
            Some("Siemens"),
        );
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::ManagedSwitch
        );
    }

    #[test]
    fn test_scalance_w_wireless() {
        // SCALANCE W788-2 M12 → AccessPoint
        let asset = make_scalance_asset(Some("SCALANCE W788-2 M12"), None, Some("Siemens"));
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::AccessPoint
        );
    }

    #[test]
    fn test_scalance_m_router() {
        // SCALANCE M876-4 → Router
        let asset = make_scalance_asset(Some("SCALANCE M876-4"), None, Some("Siemens"));
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::Router);
    }

    #[test]
    fn test_scalance_s_firewall() {
        // SCALANCE SC646-2C → Firewall
        let asset = make_scalance_asset(Some("SCALANCE SC646-2C"), None, Some("Siemens"));
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::Firewall
        );
    }

    #[test]
    fn test_scalance_from_hostname_only() {
        // Hostname "scalance-xm408" (lowercase, no product_family) → ManagedSwitch
        let asset = make_scalance_asset(None, Some("scalance-xm408"), Some("Siemens"));
        assert_eq!(
            classify_infrastructure(&asset),
            InfrastructureRole::ManagedSwitch
        );
    }

    #[test]
    fn test_non_scalance_siemens() {
        // Siemens device without "SCALANCE" in any field → not classified as infrastructure
        let asset = make_scalance_asset(Some("S7-1500"), Some("plc-cabinet-01"), Some("Siemens"));
        // Should fall through to standard vendor/protocol checks, not SCALANCE
        let role = classify_infrastructure(&asset);
        assert_ne!(role, InfrastructureRole::ManagedSwitch);
        assert_ne!(role, InfrastructureRole::AccessPoint);
        assert_ne!(role, InfrastructureRole::Router);
        assert_ne!(role, InfrastructureRole::Firewall);
    }

    #[test]
    fn test_classify_scalance_model_helper() {
        // Direct tests of the helper function
        assert_eq!(
            classify_scalance_model("SCALANCE X208-2"),
            Some(InfrastructureRole::ManagedSwitch)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE XC206-2"),
            Some(InfrastructureRole::ManagedSwitch)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE XR524-8C"),
            Some(InfrastructureRole::ManagedSwitch)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE XB205-3"),
            Some(InfrastructureRole::ManagedSwitch)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE XF204"),
            Some(InfrastructureRole::ManagedSwitch)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE XP208"),
            Some(InfrastructureRole::ManagedSwitch)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE W788-2 M12"),
            Some(InfrastructureRole::AccessPoint)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE W1788"),
            Some(InfrastructureRole::AccessPoint)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE M876-4"),
            Some(InfrastructureRole::Router)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE M812-1"),
            Some(InfrastructureRole::Router)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE S615"),
            Some(InfrastructureRole::Firewall)
        );
        assert_eq!(
            classify_scalance_model("SCALANCE SC646-2C"),
            Some(InfrastructureRole::Firewall)
        );
        assert_eq!(classify_scalance_model("not a switch"), None);
        assert_eq!(classify_scalance_model("Siemens S7-1500"), None);
    }
}
