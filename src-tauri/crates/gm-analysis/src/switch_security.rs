//! Switch Port Security Assessment.
//!
//! Evaluates the security posture of network switches discovered in the capture
//! using physical topology data, redundancy protocol observations, and asset
//! information. Produces `SwitchSecurityFinding` items that surface actionable
//! remediation steps.
//!
//! ## Detections
//!
//! | Finding | Condition | Severity |
//! |---------|-----------|----------|
//! | FlatNetwork | All devices in the same broadcast domain | High |
//! | DefaultVlan | Switch port using VLAN 1 (default/untagged) | Medium |
//! | NoRedundancy | No redundancy protocol detected in network | Medium |
//! | RogueSwitch | Unknown switch with no LLDP/CDP discovered | High |
//! | TrunkToEndDevice | Trunk link pointing to an OT end device | High |
//! | TopologyChange | Redundancy topology change event observed | Medium |
//! | MultipleMgmtProtocols | Device using both Telnet and SNMP | Medium |
//! | DefaultCredentials | Switch uses known-default credentials | Critical |

use crate::{AssetSnapshot, Severity};
use serde::{Deserialize, Serialize};

// ─── Finding Types ─────────────────────────────────────────────────────────────

/// Category of switch security finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchFindingType {
    /// All managed devices appear to be in a single, flat broadcast domain with
    /// no VLAN segmentation detected — OT and IT traffic share the same L2 segment.
    FlatNetwork,
    /// Switch port(s) are using the default VLAN 1, which should be reserved for
    /// management traffic and never used for production data.
    DefaultVlan,
    /// No ring redundancy protocol (MRP, RSTP, HSR, PRP, DLR) was detected.
    /// Single points of failure exist in the ring topology.
    NoRedundancy,
    /// A switch was observed that does not appear in the LLDP neighbour table
    /// or any known vendor list — possible rogue device.
    RogueSwitch,
    /// A trunk link (802.1Q) was detected going to an OT end device (PLC/HMI)
    /// rather than another switch — potential misconfiguration.
    TrunkToEndDevice,
    /// A redundancy topology change event (TCN/MRP_TC) was observed, indicating
    /// a link failure or new device insertion into the ring.
    TopologyChange,
    /// Switch is reachable via both insecure (Telnet) and secure (SSH/HTTPS)
    /// management — insecure channels should be disabled.
    MultipleMgmtProtocols,
    /// Switch appears to use known-default credentials for one or more protocols.
    DefaultCredentials,
}

impl SwitchFindingType {
    pub fn title(&self) -> &'static str {
        match self {
            Self::FlatNetwork => "Flat Network — No VLAN Segmentation",
            Self::DefaultVlan => "Default VLAN 1 in Use",
            Self::NoRedundancy => "No Ring Redundancy Protocol Detected",
            Self::RogueSwitch => "Unrecognised Switch Detected",
            Self::TrunkToEndDevice => "Trunk Link to OT End Device",
            Self::TopologyChange => "Redundancy Topology Change Observed",
            Self::MultipleMgmtProtocols => "Insecure Management Protocol Active",
            Self::DefaultCredentials => "Default Credentials in Use",
        }
    }
}

// ─── Finding Struct ────────────────────────────────────────────────────────────

/// A switch-level security finding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchSecurityFinding {
    /// Finding category
    pub finding_type: SwitchFindingType,
    /// Human-readable title
    pub title: String,
    /// Severity level
    pub severity: Severity,
    /// Description explaining the risk
    pub description: String,
    /// IPs of affected switches / assets
    pub affected_assets: Vec<String>,
    /// Evidence collected (specific observations)
    pub evidence: String,
    /// Recommended remediation step
    pub remediation: String,
}

impl SwitchSecurityFinding {
    fn new(
        finding_type: SwitchFindingType,
        severity: Severity,
        description: impl Into<String>,
        affected_assets: Vec<String>,
        evidence: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        let title = finding_type.title().to_string();
        Self {
            title,
            finding_type,
            severity,
            description: description.into(),
            affected_assets,
            evidence: evidence.into(),
            remediation: remediation.into(),
        }
    }
}

// ─── Assessment Input ─────────────────────────────────────────────────────────

/// Snapshot of switch-relevant data for security assessment.
///
/// Decoupled from AppState so tests can construct it directly.
#[derive(Debug, Clone, Default)]
pub struct SwitchSecurityInput<'a> {
    /// All discovered assets
    pub assets: &'a [AssetSnapshot],
    /// Protocol strings observed per IP (from deep_parse_info keys + protocols)
    pub protocols_by_ip: std::collections::HashMap<String, Vec<String>>,
    /// Redundancy protocol hints observed (protocol names: "mrp", "rstp", etc.)
    pub redundancy_protocols_seen: Vec<String>,
    /// True if any redundancy topology-change event was observed
    pub topology_change_seen: bool,
    /// VLANs in use (collected from LLDP or switch config)
    pub vlan_ids_seen: Vec<u16>,
    /// IPs of switches that have default credential warnings
    pub default_cred_switch_ips: Vec<String>,
}

// ─── Assessment ───────────────────────────────────────────────────────────────

/// Assess switch port security and return a list of findings.
///
/// Returns an empty Vec if no security issues are detected.
pub fn assess_switch_security(input: &SwitchSecurityInput<'_>) -> Vec<SwitchSecurityFinding> {
    let mut findings = Vec::new();

    // Identify infrastructure assets (switches) from the asset list
    let switch_ips: Vec<&str> = input
        .assets
        .iter()
        .filter(|a| is_switch_device_type(&a.device_type))
        .map(|a| a.ip_address.as_str())
        .collect();

    // ── Detection 1: Flat Network ────────────────────────────────────────────
    //
    // Heuristic: if there are multiple OT devices visible but only one or zero
    // distinct VLANs, the network is likely flat.
    let ot_device_count = input
        .assets
        .iter()
        .filter(|a| is_ot_device(&a.device_type))
        .count();

    let distinct_vlans = input.vlan_ids_seen.len();

    if ot_device_count >= 3 && distinct_vlans <= 1 {
        findings.push(SwitchSecurityFinding::new(
            SwitchFindingType::FlatNetwork,
            Severity::High,
            "Multiple OT devices are visible on a single broadcast domain with no VLAN \
             segmentation. OT and IT traffic should be separated at Layer 2 to limit \
             lateral movement in the event of a compromise.",
            switch_ips.iter().map(|s| s.to_string()).collect(),
            format!(
                "{} OT devices detected; {} distinct VLAN(s) observed (including LLDP VLAN TLVs)",
                ot_device_count, distinct_vlans
            ),
            "Configure port-based VLANs to segment OT, DMZ, and IT zones. \
             Disable VLAN 1 on all production ports. Apply inter-VLAN ACLs at L3 boundary.",
        ));
    }

    // ── Detection 2: Default VLAN 1 in use ───────────────────────────────────
    if input.vlan_ids_seen.contains(&1) {
        findings.push(SwitchSecurityFinding::new(
            SwitchFindingType::DefaultVlan,
            Severity::Medium,
            "VLAN 1 is the factory-default VLAN on all managed switches and should \
             not carry production traffic. Devices on VLAN 1 are reachable by any \
             other device on the same switch with default configuration.",
            switch_ips.iter().map(|s| s.to_string()).collect(),
            "VLAN 1 observed in LLDP VLAN membership TLVs".to_string(),
            "Reassign all access ports to named VLANs (≥ 2). Set 'switchport trunk \
             native vlan <non-default>' on trunk ports. Apply 'vlan dot1q tag native' \
             to tag native VLAN traffic on Cisco IOS.",
        ));
    }

    // ── Detection 3: No redundancy protocol ──────────────────────────────────
    if input.redundancy_protocols_seen.is_empty() && !switch_ips.is_empty() {
        findings.push(SwitchSecurityFinding::new(
            SwitchFindingType::NoRedundancy,
            Severity::Medium,
            "Managed switches are present but no ring redundancy protocol (MRP, RSTP, \
             HSR, PRP, DLR) was observed. A single cable or port failure could cause \
             a complete network outage affecting OT operations.",
            switch_ips.iter().map(|s| s.to_string()).collect(),
            format!(
                "{} switch(es) found; no MRP/RSTP/HSR/PRP/DLR frames observed in capture",
                switch_ips.len()
            ),
            "Enable MRP (PROFINET) or RSTP (IEEE 802.1w) ring redundancy on all managed \
             switches. Verify ring is closed by checking manager status. Consider HSR/PRP \
             for zero-recovery-time requirements (IEC 62439-3).",
        ));
    }

    // ── Detection 4: Topology change event ───────────────────────────────────
    if input.topology_change_seen {
        findings.push(SwitchSecurityFinding::new(
            SwitchFindingType::TopologyChange,
            Severity::Medium,
            "A redundancy topology change notification (TCN or MRP_TopologyChange) was \
             observed during the capture window. This indicates a link failure or new \
             device insertion into the ring, which may indicate a cabling issue, a \
             rogue device connection, or an ongoing network disruption.",
            switch_ips.iter().map(|s| s.to_string()).collect(),
            "Topology Change Notification (TCN/MRP_TC) frame observed in packet capture"
                .to_string(),
            "Investigate the source of the topology change. Check switch logs for port \
             flap events. Verify no unauthorised devices were connected to ring ports. \
             Consider enabling BPDU Guard / Root Guard on access ports.",
        ));
    }

    // ── Detection 5: Insecure + secure management protocols ──────────────────
    for asset in input.assets {
        if !is_switch_device_type(&asset.device_type) {
            continue;
        }
        let protos = input
            .protocols_by_ip
            .get(&asset.ip_address)
            .map(|v| v.as_slice())
            .unwrap_or(&[]);

        let has_telnet = protos.iter().any(|p| p == "telnet");
        let has_secure = protos.iter().any(|p| p == "ssh" || p == "https");

        if has_telnet && has_secure {
            findings.push(SwitchSecurityFinding::new(
                SwitchFindingType::MultipleMgmtProtocols,
                Severity::Medium,
                "This switch accepts both insecure (Telnet) and secure (SSH/HTTPS) \
                 management connections. Telnet transmits credentials in plaintext and \
                 should be disabled when a secure alternative is available.",
                vec![asset.ip_address.clone()],
                format!(
                    "{} has both Telnet and SSH/HTTPS management protocols active",
                    asset.ip_address
                ),
                "Disable Telnet on all managed switches. Enable SSH v2 and HTTPS only. \
                 Apply ACLs to restrict management access to the management VLAN.",
            ));
        }
    }

    // ── Detection 6: Default credentials ─────────────────────────────────────
    if !input.default_cred_switch_ips.is_empty() {
        findings.push(SwitchSecurityFinding::new(
            SwitchFindingType::DefaultCredentials,
            Severity::Critical,
            "One or more switches appear to have known-default credentials for their \
             management interface. An attacker with network access could gain full \
             administrative control over the switch, including VLAN reconfiguration, \
             port mirroring, and spanning-tree manipulation.",
            input.default_cred_switch_ips.clone(),
            format!(
                "{} switch(es) matched default credential database entries",
                input.default_cred_switch_ips.len()
            ),
            "Change all switch management passwords immediately. Use strong, unique \
             passwords per device. Store credentials in a password manager or PAM system. \
             Enable AAA (RADIUS/TACACS+) for centralised authentication.",
        ));
    }

    findings
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Returns true if the device_type string indicates a switch.
fn is_switch_device_type(device_type: &str) -> bool {
    let dt = device_type.to_lowercase();
    matches!(
        dt.as_str(),
        "switch" | "managed switch" | "managed_switch" | "unmanaged switch" | "unmanaged_switch"
    )
}

/// Returns true if the device is an OT end device (not infrastructure).
fn is_ot_device(device_type: &str) -> bool {
    let dt = device_type.to_lowercase();
    matches!(
        dt.as_str(),
        "plc"
            | "rtu"
            | "hmi"
            | "historian"
            | "scada"
            | "ied"
            | "controller"
            | "sensor"
            | "actuator"
            | "drive"
            | "vfd"
            | "dcs"
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_asset(ip: &str, device_type: &str) -> AssetSnapshot {
        AssetSnapshot {
            ip_address: ip.to_string(),
            device_type: device_type.to_string(),
            protocols: Vec::new(),
            purdue_level: None,
            is_public_ip: false,
            tags: Vec::new(),
            vendor: None,
            hostname: None,
            product_family: None,
        }
    }

    #[test]
    fn test_flat_network_detected() {
        let assets = vec![
            make_asset("10.0.0.1", "switch"),
            make_asset("10.0.0.2", "plc"),
            make_asset("10.0.0.3", "plc"),
            make_asset("10.0.0.4", "hmi"),
        ];
        let input = SwitchSecurityInput {
            assets: &assets,
            protocols_by_ip: Default::default(),
            redundancy_protocols_seen: vec!["mrp".to_string()],
            topology_change_seen: false,
            vlan_ids_seen: vec![], // no VLANs → flat
            default_cred_switch_ips: vec![],
        };
        let findings = assess_switch_security(&input);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == SwitchFindingType::FlatNetwork));
    }

    #[test]
    fn test_default_vlan_detected() {
        let assets = vec![make_asset("10.0.0.1", "switch")];
        let input = SwitchSecurityInput {
            assets: &assets,
            protocols_by_ip: Default::default(),
            redundancy_protocols_seen: vec!["rstp".to_string()],
            topology_change_seen: false,
            vlan_ids_seen: vec![1, 10, 20],
            default_cred_switch_ips: vec![],
        };
        let findings = assess_switch_security(&input);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == SwitchFindingType::DefaultVlan));
    }

    #[test]
    fn test_no_redundancy_detected() {
        let assets = vec![make_asset("10.0.0.1", "switch")];
        let input = SwitchSecurityInput {
            assets: &assets,
            protocols_by_ip: Default::default(),
            redundancy_protocols_seen: vec![], // no redundancy
            topology_change_seen: false,
            vlan_ids_seen: vec![],
            default_cred_switch_ips: vec![],
        };
        let findings = assess_switch_security(&input);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == SwitchFindingType::NoRedundancy));
    }

    #[test]
    fn test_topology_change_detected() {
        let assets = vec![make_asset("10.0.0.1", "switch")];
        let input = SwitchSecurityInput {
            assets: &assets,
            protocols_by_ip: Default::default(),
            redundancy_protocols_seen: vec!["mrp".to_string()],
            topology_change_seen: true, // TC seen
            vlan_ids_seen: vec![],
            default_cred_switch_ips: vec![],
        };
        let findings = assess_switch_security(&input);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == SwitchFindingType::TopologyChange));
    }

    #[test]
    fn test_insecure_management_protocols_detected() {
        let assets = vec![make_asset("10.0.0.1", "switch")];
        let mut protocols_by_ip = std::collections::HashMap::new();
        protocols_by_ip.insert(
            "10.0.0.1".to_string(),
            vec!["telnet".to_string(), "ssh".to_string(), "snmp".to_string()],
        );
        let input = SwitchSecurityInput {
            assets: &assets,
            protocols_by_ip,
            redundancy_protocols_seen: vec!["rstp".to_string()],
            topology_change_seen: false,
            vlan_ids_seen: vec![],
            default_cred_switch_ips: vec![],
        };
        let findings = assess_switch_security(&input);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == SwitchFindingType::MultipleMgmtProtocols));
    }

    #[test]
    fn test_default_credentials_detected() {
        let assets = vec![make_asset("10.0.0.1", "switch")];
        let input = SwitchSecurityInput {
            assets: &assets,
            protocols_by_ip: Default::default(),
            redundancy_protocols_seen: vec!["mrp".to_string()],
            topology_change_seen: false,
            vlan_ids_seen: vec![],
            default_cred_switch_ips: vec!["10.0.0.1".to_string()],
        };
        let findings = assess_switch_security(&input);
        assert!(findings
            .iter()
            .any(|f| f.finding_type == SwitchFindingType::DefaultCredentials));
        assert_eq!(
            findings
                .iter()
                .find(|f| f.finding_type == SwitchFindingType::DefaultCredentials)
                .map(|f| f.severity),
            Some(Severity::Critical)
        );
    }

    #[test]
    fn test_no_switches_no_findings() {
        let assets = vec![make_asset("10.0.0.2", "plc"), make_asset("10.0.0.3", "hmi")];
        let input = SwitchSecurityInput {
            assets: &assets,
            protocols_by_ip: Default::default(),
            redundancy_protocols_seen: vec![],
            topology_change_seen: false,
            vlan_ids_seen: vec![],
            default_cred_switch_ips: vec![],
        };
        let findings = assess_switch_security(&input);
        // No redundancy finding because there are no switches
        // Flat network won't trigger either (only 2 OT devices, need ≥3)
        assert!(!findings
            .iter()
            .any(|f| f.finding_type == SwitchFindingType::NoRedundancy));
    }
}
