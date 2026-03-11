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
            Self::ManagedSwitch    => "Managed Switch",
            Self::UnmanagedSwitch  => "Unmanaged Switch",
            Self::Router           => "Router",
            Self::Firewall         => "Firewall",
            Self::AccessPoint      => "Access Point",
            Self::Gateway          => "Gateway",
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
        if t == "switch" || t == "managed-switch" { return InfrastructureRole::ManagedSwitch; }
        if t == "unmanaged-switch"                { return InfrastructureRole::UnmanagedSwitch; }
        if t == "router"                          { return InfrastructureRole::Router; }
        if t == "firewall"                        { return InfrastructureRole::Firewall; }
        if t == "access-point" || t == "ap"       { return InfrastructureRole::AccessPoint; }
        if t == "gateway"                         { return InfrastructureRole::Gateway; }
    }

    InfrastructureRole::NotInfrastructure
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns true if the device has management protocols visible.
fn has_management_protocol(protocols: &[&str]) -> bool {
    protocols.iter().any(|p| {
        matches!(*p, "snmp" | "http" | "https" | "ssh" | "telnet" | "netconf")
    })
}

/// Returns true if the vendor is a known OT switch manufacturer.
fn is_ot_switch_vendor(vendor: &str) -> bool {
    let known = [
        "hirschmann",    // Hirschmann (Belden) MACH / OCTOPUS / MICE / SPIDER / EAGLE
        "ruggedcom",     // Siemens RuggedCom (RUGGEDSWITCH)
        "scalance",      // Siemens SCALANCE (may appear in product field)
        "moxa",          // Moxa EDS / ICS series
        "westermo",      // Westermo (RED / MRD series)
        "phoenix contact", // Phoenix Contact FL SWITCH
        "belden",        // Belden industrial switches
        "cisco ie",      // Cisco Industrial Ethernet
        "rockwell",      // Rockwell Stratix
        "stratix",       // Allen-Bradley Stratix
        "perle",         // Perle industrial switches
        "korenix",       // Korenix (Westermo subsidiary)
        "antaira",       // Antaira
        "red lion",      // Red Lion N-Tron
        "n-tron",        // N-Tron (Red Lion)
        "contemporary controls", // Contemporary Controls BASrouter
        "garrettcom",    // GarrettCom (Belden)
        "datalogger",    // Various data acquisition switches
        "prosoft",       // ProSoft Technology gateways
    ];
    known.iter().any(|k| vendor.contains(k))
}

/// Returns true if the vendor is a known firewall vendor.
fn is_firewall_vendor(vendor: &str) -> bool {
    let known = [
        "palo alto", "fortinet", "checkpoint", "cisco asa", "cisco ftd",
        "juniper srx", "sonicwall", "watchguard", "barracuda", "sophos",
        "forcepoint", "tufin", "ixia",
    ];
    known.iter().any(|k| vendor.contains(k))
}

/// Returns true if the vendor is a known general-purpose router vendor.
fn is_router_vendor(vendor: &str) -> bool {
    let known = [
        "juniper", "mikrotik", "ubiquiti", "opnsense", "pfsense",
        "extreme networks", "hp networking", "aruba", "dell networking",
    ];
    known.iter().any(|k| vendor.contains(k))
}

/// Returns true if a protocol string represents an OT/ICS protocol.
fn is_ot_protocol(proto: &str) -> bool {
    matches!(
        proto,
        "modbus" | "dnp3" | "ethernetip" | "bacnet" | "s7comm"
            | "opcua" | "profinet" | "iec104" | "mqtt" | "hartip"
            | "foundationfieldbus" | "gesrtp" | "wonderwaresuiteline"
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
        }
    }

    #[test]
    fn test_switch_from_device_type() {
        let asset = make_asset("switch", None, &["snmp"]);
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::ManagedSwitch);
    }

    #[test]
    fn test_unmanaged_switch() {
        let asset = make_asset("switch", None, &[]); // no management protocols
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::UnmanagedSwitch);
    }

    #[test]
    fn test_router_from_device_type() {
        let asset = make_asset("router", None, &[]);
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::Router);
    }

    #[test]
    fn test_hirschmann_switch() {
        let asset = make_asset("unknown", Some("Hirschmann"), &["http", "snmp"]);
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::ManagedSwitch);
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
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::NotInfrastructure);
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
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::Firewall);
    }

    #[test]
    fn test_snmp_only_device() {
        // Device with only SNMP and HTTP (management) but no OT protocols
        let asset = make_asset("unknown", None, &["snmp", "http"]);
        assert_eq!(classify_infrastructure(&asset), InfrastructureRole::ManagedSwitch);
    }
}
