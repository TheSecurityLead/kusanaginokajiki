//! Juniper JunOS parser for physical topology data.
//!
//! Parses output from:
//! - `show configuration` (or `show interfaces` + hostname sections)
//! - `show interfaces terse`
//! - `show ethernet-switching table`
//! - `show lldp neighbors`
//! - `show arp`

use std::collections::HashMap;
use std::path::Path;

use crate::{ArpEntry, CdpNeighbor, MacTableEntry, PhysicalError, PhysicalPort, PhysicalSwitch};

// ─── JunOS Config Parser ──────────────────────────────────────────

/// Parse JunOS `show configuration` output into a PhysicalSwitch.
///
/// Extracts: hostname (from `set system host-name`), interfaces with
/// IP addresses (from `set interfaces`), and VLAN definitions.
pub fn parse_junos_config(content: &str) -> Result<PhysicalSwitch, PhysicalError> {
    let hostname = parse_junos_hostname(content);
    let vlans = parse_junos_vlans(content);
    let ports = parse_junos_interfaces_from_config(content);
    let management_ip = find_junos_management_ip(&ports);

    Ok(PhysicalSwitch {
        hostname,
        management_ip,
        model: None,
        ios_version: None,
        ports,
        vlans,
    })
}

/// Load and parse a JunOS config from a file path.
pub fn parse_junos_config_file(path: &Path) -> Result<PhysicalSwitch, PhysicalError> {
    let content = std::fs::read_to_string(path)?;
    parse_junos_config(&content)
}

fn parse_junos_hostname(content: &str) -> String {
    // JunOS set-format: "set system host-name HOSTNAME"
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("set system host-name ") {
            let hostname = rest.trim().to_string();
            if !hostname.is_empty() {
                return hostname;
            }
        }
    }
    "unknown".to_string()
}

fn parse_junos_vlans(content: &str) -> HashMap<u16, String> {
    let mut vlans = HashMap::new();

    // JunOS set-format: "set vlans NAME vlan-id ID"
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("set vlans ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            // parts = ["NAME", "vlan-id", "ID"]
            if parts.len() >= 3 && parts[1] == "vlan-id" {
                if let Ok(id) = parts[2].parse::<u16>() {
                    vlans.insert(id, parts[0].to_string());
                }
            }
        }
    }

    vlans
}

fn parse_junos_interfaces_from_config(content: &str) -> Vec<PhysicalPort> {
    let mut ports: HashMap<String, PhysicalPort> = HashMap::new();

    // JunOS set-format: "set interfaces ge-0/0/0 unit 0 family inet address 192.168.1.1/24"
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("set interfaces ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.is_empty() {
                continue;
            }
            let iface_name = parts[0].to_string();

            // Strip unit suffix for the canonical name (ge-0/0/0.0 → ge-0/0/0)
            let canonical = strip_unit_suffix(&iface_name);

            let entry = ports
                .entry(canonical.clone())
                .or_insert_with(|| PhysicalPort {
                    name: canonical.clone(),
                    short_name: canonical.clone(),
                    description: None,
                    vlans: Vec::new(),
                    mode: "unknown".to_string(),
                    shutdown: false,
                    ip_address: None,
                    subnet_mask: None,
                    mac_addresses: Vec::new(),
                    ip_addresses: Vec::new(),
                    cdp_neighbor: None,
                    speed: None,
                    duplex: None,
                });

            // Parse IP address: "ge-0/0/0 unit 0 family inet address X.X.X.X/Y"
            if parts.len() >= 6
                && parts[1] == "unit"
                && parts[3] == "family"
                && parts[4] == "inet"
                && parts[5] == "address"
            {
                if let Some(addr_cidr) = parts.get(6) {
                    if let Some((ip, prefix)) = addr_cidr.split_once('/') {
                        entry.ip_address = Some(ip.to_string());
                        // Convert prefix length to dotted mask
                        entry.subnet_mask = prefix_to_mask(prefix.parse::<u8>().unwrap_or(24));
                    }
                }
            }

            // Parse description: "ge-0/0/0 description TEXT"
            if parts.len() >= 3 && parts[1] == "description" {
                entry.description = Some(parts[2..].join(" "));
            }

            // Parse disable (shutdown equivalent)
            if parts.len() >= 2 && parts[1] == "disable" {
                entry.shutdown = true;
            }

            // Parse unit VLAN: "ge-0/0/0 unit 0 vlan-id ID"
            if parts.len() >= 5 && parts[1] == "unit" && parts[3] == "vlan-id" {
                if let Ok(v) = parts[4].parse::<u16>() {
                    if !entry.vlans.contains(&v) {
                        entry.vlans.push(v);
                    }
                }
            }
        }
    }

    let mut result: Vec<PhysicalPort> = ports.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

fn find_junos_management_ip(ports: &[PhysicalPort]) -> Option<String> {
    // Prefer loopback (lo0) management address
    for port in ports {
        if port.name.starts_with("lo") {
            if let Some(ref ip) = port.ip_address {
                if !ip.starts_with("127.") {
                    return Some(ip.clone());
                }
            }
        }
    }
    // Fall back to first port with an IP
    for port in ports {
        if let Some(ref ip) = port.ip_address {
            return Some(ip.clone());
        }
    }
    None
}

/// Strip JunOS unit suffix from interface name: "ge-0/0/0.0" → "ge-0/0/0"
fn strip_unit_suffix(name: &str) -> String {
    // If name ends with ".N" (unit number), strip it
    if let Some(dot_pos) = name.rfind('.') {
        let suffix = &name[dot_pos + 1..];
        if suffix.chars().all(|c| c.is_ascii_digit()) {
            return name[..dot_pos].to_string();
        }
    }
    name.to_string()
}

fn prefix_to_mask(prefix: u8) -> Option<String> {
    if prefix > 32 {
        return None;
    }
    let mask: u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    Some(format!(
        "{}.{}.{}.{}",
        (mask >> 24) & 0xff,
        (mask >> 16) & 0xff,
        (mask >> 8) & 0xff,
        mask & 0xff
    ))
}

// ─── show interfaces terse ────────────────────────────────────────

/// Parse `show interfaces terse` output into PhysicalPort list.
///
/// Format:
/// ```text
/// Interface               Admin Link Proto    Local                 Remote
/// ge-0/0/0                up    up
/// ge-0/0/0.0              up    up   inet     192.168.1.1/24
/// ge-0/0/1                up    down
/// lo0.0                   up    up   inet     127.0.0.1           --> 0/0
/// ```
pub fn parse_interfaces_terse(content: &str) -> Vec<PhysicalPort> {
    let mut ports: HashMap<String, PhysicalPort> = HashMap::new();

    for line in content.lines() {
        // Skip header lines
        if line.starts_with("Interface") || line.starts_with('-') || line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let raw_name = parts[0];
        // Skip continuation lines (Proto/address rows that have no interface name in col 0)
        // They start with spaces in the original, but split_whitespace absorbs them
        // We detect them by checking if the first field looks like a protocol keyword
        if matches!(raw_name, "inet" | "inet6" | "mpls" | "iso" | "vpls") {
            continue;
        }

        let canonical = strip_unit_suffix(raw_name);

        // Admin state
        let admin_up = parts.get(1).map(|s| *s == "up").unwrap_or(false);
        // Link state
        let _link_up = parts.get(2).map(|s| *s == "up").unwrap_or(false);

        let entry = ports
            .entry(canonical.clone())
            .or_insert_with(|| PhysicalPort {
                name: canonical.clone(),
                short_name: canonical.clone(),
                description: None,
                vlans: Vec::new(),
                mode: "unknown".to_string(),
                shutdown: !admin_up,
                ip_address: None,
                subnet_mask: None,
                mac_addresses: Vec::new(),
                ip_addresses: Vec::new(),
                cdp_neighbor: None,
                speed: None,
                duplex: None,
            });

        // Only update shutdown if we're looking at the physical (non-unit) interface
        if !raw_name.contains('.') {
            entry.shutdown = !admin_up;
        }

        // Parse IP from "inet   X.X.X.X/Y" columns
        let proto = parts.get(3);
        if proto == Some(&"inet") {
            if let Some(addr_cidr) = parts.get(4) {
                if let Some((ip, prefix)) = addr_cidr.split_once('/') {
                    if entry.ip_address.is_none() {
                        entry.ip_address = Some(ip.to_string());
                        entry.subnet_mask = prefix_to_mask(prefix.parse::<u8>().unwrap_or(24));
                    }
                }
            }
        }
    }

    let mut result: Vec<PhysicalPort> = ports.into_values().collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

// ─── show ethernet-switching table ───────────────────────────────

/// Parse JunOS `show ethernet-switching table` output.
///
/// Format:
/// ```text
/// Ethernet switching table : 3 entries, 3 learned
/// Routing instance : default-switch
///   VLAN              MAC                 Type         Age Interfaces
///   default           00:50:79:66:68:00   Learn          0 ge-0/0/0.0
///   OT_NET            00:1a:2b:3c:4d:5e   Static         - ge-0/0/1.0
/// ```
pub fn parse_ethernet_switching_table(content: &str, _hostname: &str) -> Vec<MacTableEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip headers and separators
        if line.is_empty()
            || line.starts_with("Ethernet switching")
            || line.starts_with("Routing instance")
            || line.starts_with("VLAN")
            || line.starts_with('-')
        {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        // Expected: VLAN_NAME, MAC, Type, Age, Interface
        // Sometimes Age can be "-" so index 4 is interface
        if parts.len() < 5 {
            continue;
        }

        let _vlan_name = parts[0];
        let mac_str = parts[1];
        let entry_type = parts[2].to_lowercase();
        // parts[3] is age (skip)
        let raw_port = parts[4];

        // Validate MAC: must contain colons or be 12 hex chars
        if mac_str.len() < 12 {
            continue;
        }
        let mac = crate::normalize_mac(mac_str);

        // Strip unit suffix from port name (ge-0/0/0.0 → ge-0/0/0)
        let port = strip_unit_suffix(raw_port);

        // We use vlan=1 as a default since JunOS ethernet-switching table
        // doesn't always provide a numeric VLAN ID in this format.
        // If we can parse a numeric VLAN from the name, use it.
        let vlan: u16 = 1;

        // Skip self/router entries
        if entry_type == "self" || entry_type == "router" {
            continue;
        }

        entries.push(MacTableEntry {
            mac_address: mac,
            vlan,
            port,
            entry_type: if entry_type == "learn" {
                "dynamic".to_string()
            } else {
                entry_type
            },
        });
    }

    log::info!(
        "Parsed {} JunOS ethernet-switching table entries",
        entries.len()
    );
    entries
}

/// Load and parse a JunOS ethernet-switching table from a file.
pub fn parse_ethernet_switching_table_file(path: &Path, hostname: &str) -> Vec<MacTableEntry> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_ethernet_switching_table(&content, hostname),
        Err(e) => {
            log::error!("Failed to read JunOS MAC table file: {}", e);
            Vec::new()
        }
    }
}

// ─── show lldp neighbors ─────────────────────────────────────────

/// Parse JunOS `show lldp neighbors` output.
///
/// Returns pairs of (local_port, CdpNeighbor) — reuses CdpNeighbor type
/// since LLDP provides equivalent information to CDP.
///
/// Format:
/// ```text
/// Local Interface    Parent Interface    Chassis Id          Port info       System Name
/// ge-0/0/0.0         -                   00:1a:2b:3c:4d:5e  ge-0/0/1        SW-DIST-1
/// ge-0/0/1.0         -                   aa:bb:cc:dd:ee:ff  Gi1/0/24        CORE-SW
/// ```
pub fn parse_lldp_neighbors(content: &str) -> Vec<(String, CdpNeighbor)> {
    let mut neighbors = Vec::new();

    let mut in_table = false;
    for line in content.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.is_empty() {
            continue;
        }

        // Detect header row
        if line_trimmed.starts_with("Local Interface") || line_trimmed.starts_with("Local Port") {
            in_table = true;
            continue;
        }
        if line_trimmed.starts_with('-') {
            continue;
        }
        if !in_table {
            continue;
        }

        // Split on 2+ spaces to handle fixed-width columns
        let parts: Vec<&str> = line_trimmed
            .split("  ")
            .filter(|s| !s.trim().is_empty())
            .collect();
        if parts.len() < 5 {
            // Try whitespace split as fallback
            let ws_parts: Vec<&str> = line_trimmed.split_whitespace().collect();
            if ws_parts.len() < 5 {
                continue;
            }
            let local_port = strip_unit_suffix(ws_parts[0].trim());
            // ws_parts[1] = parent interface ("-" usually)
            let chassis_id = ws_parts[2].trim().to_string();
            let remote_port = ws_parts[3].trim().to_string();
            let system_name = ws_parts[4..].join(" ").trim().to_string();

            neighbors.push((
                local_port,
                CdpNeighbor {
                    device_id: system_name,
                    remote_port,
                    platform: None,
                    ip_address: Some(chassis_id),
                    capabilities: Vec::new(),
                },
            ));
            continue;
        }

        let local_port = strip_unit_suffix(parts[0].trim());
        // parts[1] = parent interface
        let chassis_id = parts[2].trim().to_string();
        let remote_port = parts[3].trim().to_string();
        let system_name = parts[4].trim().to_string();

        neighbors.push((
            local_port,
            CdpNeighbor {
                device_id: system_name,
                remote_port,
                platform: None,
                ip_address: Some(chassis_id),
                capabilities: Vec::new(),
            },
        ));
    }

    log::info!("Parsed {} JunOS LLDP neighbors", neighbors.len());
    neighbors
}

/// Load and parse JunOS LLDP neighbors from a file.
pub fn parse_lldp_neighbors_file(path: &Path) -> Vec<(String, CdpNeighbor)> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_lldp_neighbors(&content),
        Err(e) => {
            log::error!("Failed to read JunOS LLDP file: {}", e);
            Vec::new()
        }
    }
}

// ─── show arp ────────────────────────────────────────────────────

/// Parse JunOS `show arp` output.
///
/// Format:
/// ```text
/// MAC Address       Address         Name                      Interface           Flags
/// 00:50:79:66:68:00 192.168.1.10    192.168.1.10              ge-0/0/0.0          none
/// 00:1a:2b:3c:4d:5e 192.168.1.20    plc-line1                 ge-0/0/1.0          permanent
/// ```
pub fn parse_arp_junos(content: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip header, separator, and empty lines
        if line.is_empty() || line.starts_with("MAC") || line.starts_with('-') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: MAC_ADDRESS  IP_ADDRESS  NAME  INTERFACE  FLAGS
        if parts.len() < 4 {
            continue;
        }

        let mac_str = parts[0];
        let ip = parts[1];
        // parts[2] = name (skip)
        let raw_iface = parts[3];

        // Validate IP
        if !ip.contains('.') {
            continue;
        }

        // Validate MAC
        let mac = crate::normalize_mac(mac_str);
        if mac.len() != 17 {
            continue;
        }

        let interface = strip_unit_suffix(raw_iface).to_string();

        entries.push(ArpEntry {
            ip_address: ip.to_string(),
            mac_address: mac,
            interface: Some(interface),
            vlan: None,
        });
    }

    log::info!("Parsed {} JunOS ARP entries", entries.len());
    entries
}

/// Load and parse JunOS ARP table from a file.
pub fn parse_arp_file_junos(path: &Path) -> Vec<ArpEntry> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_arp_junos(&content),
        Err(e) => {
            log::error!("Failed to read JunOS ARP file: {}", e);
            Vec::new()
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JUNOS_CONFIG: &str = r#"
set system host-name JunOS-SW1
set vlans OT_NETWORK vlan-id 100
set vlans IT_NETWORK vlan-id 200
set interfaces ge-0/0/0 description PLC-Line1
set interfaces ge-0/0/0 unit 0 family inet address 192.168.100.1/24
set interfaces ge-0/0/1 description HMI-Station1
set interfaces ge-0/0/1 unit 0 vlan-id 100
set interfaces ge-0/0/2 disable
set interfaces ge-0/0/2 description Unused-Port
set interfaces lo0 unit 0 family inet address 10.0.0.1/32
"#;

    #[test]
    fn test_parse_junos_hostname() {
        assert_eq!(parse_junos_hostname(SAMPLE_JUNOS_CONFIG), "JunOS-SW1");
    }

    #[test]
    fn test_parse_junos_vlans() {
        let vlans = parse_junos_vlans(SAMPLE_JUNOS_CONFIG);
        assert_eq!(vlans.get(&100), Some(&"OT_NETWORK".to_string()));
        assert_eq!(vlans.get(&200), Some(&"IT_NETWORK".to_string()));
    }

    #[test]
    fn test_parse_junos_config_full() {
        let sw = parse_junos_config(SAMPLE_JUNOS_CONFIG).unwrap();
        assert_eq!(sw.hostname, "JunOS-SW1");
        // Should have lo0, ge-0/0/0, ge-0/0/1, ge-0/0/2
        assert!(sw.ports.len() >= 3);

        let ge0 = sw.ports.iter().find(|p| p.name == "ge-0/0/0").unwrap();
        assert_eq!(ge0.description.as_deref(), Some("PLC-Line1"));
        assert_eq!(ge0.ip_address.as_deref(), Some("192.168.100.1"));

        let ge2 = sw.ports.iter().find(|p| p.name == "ge-0/0/2").unwrap();
        assert!(ge2.shutdown);
    }

    #[test]
    fn test_parse_junos_management_ip() {
        let sw = parse_junos_config(SAMPLE_JUNOS_CONFIG).unwrap();
        // lo0 has 10.0.0.1 — should be management IP
        assert_eq!(sw.management_ip.as_deref(), Some("10.0.0.1"));
    }

    const SAMPLE_INTERFACES_TERSE: &str = r#"
Interface               Admin Link Proto    Local                 Remote
ge-0/0/0                up    up
ge-0/0/0.0              up    up   inet     192.168.1.1/24
ge-0/0/1                up    down
ge-0/0/1.0              up    down inet     10.0.0.1/30
ge-0/0/2                down  down
lo0                     up    up
lo0.0                   up    up   inet     127.0.0.1/8
"#;

    #[test]
    fn test_parse_interfaces_terse() {
        let ports = parse_interfaces_terse(SAMPLE_INTERFACES_TERSE);
        assert!(ports.len() >= 3);

        let ge0 = ports.iter().find(|p| p.name == "ge-0/0/0").unwrap();
        assert!(!ge0.shutdown);
        assert_eq!(ge0.ip_address.as_deref(), Some("192.168.1.1"));

        let ge2 = ports.iter().find(|p| p.name == "ge-0/0/2").unwrap();
        assert!(ge2.shutdown);
    }

    const SAMPLE_ETH_SW_TABLE: &str = r#"
Ethernet switching table : 3 entries, 3 learned
Routing instance : default-switch
  VLAN              MAC                 Type         Age Interfaces
  default           00:50:79:66:68:00   Learn          0 ge-0/0/0.0
  OT_NET            00:1a:2b:3c:4d:5e   Static         - ge-0/0/1.0
  default           aa:bb:cc:dd:ee:ff   Learn          5 ge-0/0/2.0
"#;

    #[test]
    fn test_parse_ethernet_switching_table() {
        let entries = parse_ethernet_switching_table(SAMPLE_ETH_SW_TABLE, "JunOS-SW1");
        assert_eq!(entries.len(), 3);

        let first = &entries[0];
        assert_eq!(first.mac_address, "00:50:79:66:68:00");
        assert_eq!(first.port, "ge-0/0/0");
        assert_eq!(first.entry_type, "dynamic");

        let second = &entries[1];
        assert_eq!(second.mac_address, "00:1a:2b:3c:4d:5e");
        assert_eq!(second.port, "ge-0/0/1");
        assert_eq!(second.entry_type, "static");
    }

    const SAMPLE_LLDP: &str = r#"
Local Interface    Parent Interface    Chassis Id          Port info       System Name
ge-0/0/0.0         -                   00:1a:2b:3c:4d:5e   ge-0/0/1.0     SW-DIST-1
ge-0/0/1.0         -                   aa:bb:cc:dd:ee:ff   Gi1/0/24       CORE-SW
"#;

    #[test]
    fn test_parse_lldp_neighbors() {
        let neighbors = parse_lldp_neighbors(SAMPLE_LLDP);
        assert_eq!(neighbors.len(), 2);

        let (local_port, neighbor) = &neighbors[0];
        assert_eq!(local_port, "ge-0/0/0");
        assert_eq!(neighbor.device_id, "SW-DIST-1");
        assert_eq!(neighbor.remote_port, "ge-0/0/1.0");
    }

    const SAMPLE_ARP_JUNOS: &str = r#"
MAC Address       Address         Name                      Interface           Flags
00:50:79:66:68:00 192.168.1.10    192.168.1.10              ge-0/0/0.0          none
00:1a:2b:3c:4d:5e 192.168.1.20    plc-line1                 ge-0/0/1.0          permanent
aa:bb:cc:dd:ee:ff 10.0.0.2        router.example.com        ge-0/0/2.0          none
"#;

    #[test]
    fn test_parse_arp_junos() {
        let entries = parse_arp_junos(SAMPLE_ARP_JUNOS);
        assert_eq!(entries.len(), 3);

        let first = &entries[0];
        assert_eq!(first.ip_address, "192.168.1.10");
        assert_eq!(first.mac_address, "00:50:79:66:68:00");
        assert_eq!(first.interface.as_deref(), Some("ge-0/0/0"));

        let second = &entries[1];
        assert_eq!(second.ip_address, "192.168.1.20");
        assert_eq!(second.mac_address, "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn test_strip_unit_suffix() {
        assert_eq!(strip_unit_suffix("ge-0/0/0.0"), "ge-0/0/0");
        assert_eq!(strip_unit_suffix("ge-0/0/0"), "ge-0/0/0");
        assert_eq!(strip_unit_suffix("ae0.0"), "ae0");
        assert_eq!(strip_unit_suffix("lo0.0"), "lo0");
    }
}
