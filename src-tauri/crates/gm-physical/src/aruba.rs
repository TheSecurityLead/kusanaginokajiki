//! HP/Aruba ProCurve parser for physical topology data.
//!
//! Parses output from:
//! - `show running-config`
//! - `show mac-address`
//! - `show lldp info remote-device`
//! - `show arp`

use std::collections::HashMap;
use std::path::Path;

use crate::{ArpEntry, CdpNeighbor, MacTableEntry, PhysicalPort, PhysicalSwitch, PhysicalError};

// ─── Running Config Parser ────────────────────────────────────────

/// Parse HP/Aruba ProCurve `show running-config` output.
///
/// Extracts: hostname, interfaces with descriptions and VLANs.
pub fn parse_aruba_config(content: &str) -> Result<PhysicalSwitch, PhysicalError> {
    let hostname = parse_aruba_hostname(content);
    let vlans = parse_aruba_vlans(content);
    let ports = parse_aruba_interfaces(content);
    let management_ip = find_aruba_management_ip(&ports);

    Ok(PhysicalSwitch {
        hostname,
        management_ip,
        model: None,
        ios_version: None,
        ports,
        vlans,
    })
}

/// Load and parse an HP/Aruba config from a file path.
pub fn parse_aruba_config_file(path: &Path) -> Result<PhysicalSwitch, PhysicalError> {
    let content = std::fs::read_to_string(path)?;
    parse_aruba_config(&content)
}

fn parse_aruba_hostname(content: &str) -> String {
    for line in content.lines() {
        let line = line.trim();
        // HP/Aruba: hostname "HOSTNAME" or hostname HOSTNAME
        if let Some(rest) = line.strip_prefix("hostname") {
            let name = rest.trim().trim_matches('"').to_string();
            if !name.is_empty() {
                return name;
            }
        }
    }
    "unknown".to_string()
}

fn parse_aruba_vlans(content: &str) -> HashMap<u16, String> {
    let mut vlans = HashMap::new();

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        // VLAN block: "vlan N" (the line must be non-indented)
        let is_indented = lines[i].starts_with(' ') || lines[i].starts_with('\t');
        if !is_indented {
            if let Some(rest) = line.strip_prefix("vlan ") {
                if let Ok(vlan_id) = rest.trim().parse::<u16>() {
                    let mut name = format!("VLAN{}", vlan_id);
                    // Look for "name" in the indented block that follows
                    let mut j = i + 1;
                    while j < lines.len() {
                        // Block ends when we hit a non-indented non-empty line
                        let next_raw = lines[j];
                        let is_next_indented = next_raw.starts_with(' ') || next_raw.starts_with('\t');
                        if !is_next_indented && !next_raw.trim().is_empty() {
                            break;
                        }
                        let inner = next_raw.trim();
                        if let Some(name_rest) = inner.strip_prefix("name ") {
                            name = name_rest.trim().trim_matches('"').to_string();
                        }
                        j += 1;
                    }
                    // Only insert if not already present with a real name,
                    // or if we found a name in this block
                    let has_real_name = !name.starts_with("VLAN");
                    if has_real_name || !vlans.contains_key(&vlan_id) {
                        vlans.insert(vlan_id, name);
                    }
                }
            }
        }

        i += 1;
    }

    vlans
}

fn parse_aruba_interfaces(content: &str) -> Vec<PhysicalPort> {
    let mut ports = Vec::new();

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();

        // Interface block: "interface N" or "interface A1"
        if let Some(rest) = line.strip_prefix("interface ") {
            let iface_name = rest.trim().to_string();
            let mut description = None;
            let mut ip_address = None;
            let mut subnet_mask = None;
            let mut vlans_list: Vec<u16> = Vec::new();

            i += 1;
            while i < lines.len() {
                let inner_raw = lines[i];
                let inner = inner_raw.trim();

                // End of block: non-indented line or next "interface" or "vlan" block
                if !inner_raw.starts_with(' ') && !inner_raw.starts_with('\t') {
                    break;
                }

                if let Some(desc) = inner.strip_prefix("name ") {
                    description = Some(desc.trim().trim_matches('"').to_string());
                } else if inner.starts_with("ip address ") {
                    let parts: Vec<&str> = inner.split_whitespace().collect();
                    if parts.len() >= 4 {
                        ip_address = Some(parts[2].to_string());
                        subnet_mask = Some(parts[3].to_string());
                    }
                } else if inner.starts_with("untagged ") {
                    // "untagged 1-10,15" — parse port list as VLANs? Actually for interface
                    // blocks the untagged is a VLAN assignment in some ProCurve formats.
                    // Skip for interface-level parsing; VLAN assignments come from vlan blocks.
                } else if inner.starts_with("tagged ") {
                    // Tagged VLANs on this interface
                    if let Some(rest) = inner.strip_prefix("tagged ") {
                        parse_port_range(rest, &mut vlans_list);
                    }
                }

                i += 1;
            }

            ports.push(PhysicalPort {
                name: iface_name.clone(),
                short_name: iface_name,
                description,
                vlans: vlans_list,
                mode: "unknown".to_string(),
                shutdown: false,
                ip_address,
                subnet_mask,
                mac_addresses: Vec::new(),
                ip_addresses: Vec::new(),
                cdp_neighbor: None,
                speed: None,
                duplex: None,
            });
        } else {
            i += 1;
        }
    }

    ports
}

/// Parse a ProCurve port/VLAN range like "1-10,15,20-25" into a Vec<u16>.
fn parse_port_range(s: &str, out: &mut Vec<u16>) {
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                for v in s..=e {
                    if !out.contains(&v) {
                        out.push(v);
                    }
                }
            }
        } else if let Ok(v) = part.parse::<u16>() {
            if !out.contains(&v) {
                out.push(v);
            }
        }
    }
}

fn find_aruba_management_ip(ports: &[PhysicalPort]) -> Option<String> {
    for port in ports {
        if let Some(ref ip) = port.ip_address {
            return Some(ip.clone());
        }
    }
    None
}

// ─── MAC Address Table Parser ─────────────────────────────────────

/// Parse HP/Aruba `show mac-address` output.
///
/// Format:
/// ```text
///  MAC Address    Port  VLAN   Type
///  -------------- ----- ------ -------
///  aabbcc-ddeeff  1     100    Dynamic
///  001122-334455  A1    1      Static
/// ```
pub fn parse_aruba_mac_table(content: &str) -> Vec<MacTableEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        // Skip headers and separators
        if line.is_empty() || line.starts_with("MAC") || line.starts_with('-') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }

        let mac_str = parts[0];
        let port = parts[1].to_string();
        let vlan_str = parts[2];
        let entry_type = parts[3].to_lowercase();

        // Validate MAC (HP/Aruba format: aabbcc-ddeeff)
        let mac = crate::normalize_mac(mac_str);
        if mac.len() != 17 {
            continue;
        }

        let vlan = vlan_str.parse::<u16>().unwrap_or(1);

        entries.push(MacTableEntry {
            mac_address: mac,
            vlan,
            port,
            entry_type,
        });
    }

    log::info!("Parsed {} HP/Aruba MAC table entries", entries.len());
    entries
}

/// Load and parse HP/Aruba MAC table from a file.
pub fn parse_aruba_mac_table_file(path: &Path) -> Vec<MacTableEntry> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_aruba_mac_table(&content),
        Err(e) => {
            log::error!("Failed to read HP/Aruba MAC table file: {}", e);
            Vec::new()
        }
    }
}

// ─── LLDP Neighbor Parser ─────────────────────────────────────────

/// Parse HP/Aruba `show lldp info remote-device` output.
///
/// Returns pairs of (local_port, CdpNeighbor).
///
/// Format:
/// ```text
///  LocalPort  | ChassisId         | PortId      | SysName     | Capabilities
///  ----------   ------------------   -----------   -----------   -----------
///  1          | aa:bb:cc:dd:ee:ff | 24          | SW-CORE-1   | B, R
///  A1         | 00:1a:2b:3c:4d:5e | A2          | SW-ACCESS-2 | B
/// ```
pub fn parse_aruba_lldp_neighbors(content: &str) -> Vec<(String, CdpNeighbor)> {
    let mut neighbors = Vec::new();

    let mut in_table = false;
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Detect header row
        if line.starts_with("Local Port") || line.starts_with("LocalPort") || line.contains("ChassisId") {
            in_table = true;
            continue;
        }
        if line.starts_with('-') || line.starts_with('=') {
            continue;
        }
        if !in_table {
            continue;
        }

        // Split by "|" for pipe-separated format
        let fields: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if fields.len() < 4 {
            // Try whitespace-separated
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }
            let local_port = parts[0].to_string();
            let chassis_id = parts[1].to_string();
            let remote_port = parts[2].to_string();
            let system_name = parts[3].to_string();
            let caps: Vec<String> = if parts.len() > 4 { parts[4..].iter().map(|s| s.to_string()).collect() } else { Vec::new() };

            neighbors.push((local_port, CdpNeighbor {
                device_id: system_name,
                remote_port,
                platform: None,
                ip_address: Some(chassis_id),
                capabilities: caps,
            }));
            continue;
        }

        let local_port = fields[0].to_string();
        let chassis_id = fields[1].to_string();
        let remote_port = fields[2].to_string();
        let system_name = fields[3].to_string();
        let caps: Vec<String> = if fields.len() > 4 {
            fields[4].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        } else {
            Vec::new()
        };

        if local_port.is_empty() || system_name.is_empty() {
            continue;
        }

        neighbors.push((local_port, CdpNeighbor {
            device_id: system_name,
            remote_port,
            platform: None,
            ip_address: Some(chassis_id),
            capabilities: caps,
        }));
    }

    log::info!("Parsed {} HP/Aruba LLDP neighbors", neighbors.len());
    neighbors
}

/// Load and parse HP/Aruba LLDP neighbors from a file.
pub fn parse_aruba_lldp_file(path: &Path) -> Vec<(String, CdpNeighbor)> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_aruba_lldp_neighbors(&content),
        Err(e) => {
            log::error!("Failed to read HP/Aruba LLDP file: {}", e);
            Vec::new()
        }
    }
}

// ─── ARP Table Parser ─────────────────────────────────────────────

/// Parse HP/Aruba `show arp` output.
///
/// Format:
/// ```text
///  IP Address     MAC Address       Type     Age(min)  Port
///  -----------    ----------------  -------  --------  ------
///  192.168.1.1    001122-334455     dynamic  -         1
///  192.168.1.10   aabbcc-ddeeff     dynamic  15        2
/// ```
pub fn parse_aruba_arp(content: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("IP") || line.starts_with('-') {
            continue;
        }

        let parts: Vec<&str> = line.split_whitespace().collect();
        // IP, MAC, Type, Age, Port
        if parts.len() < 5 {
            continue;
        }

        let ip = parts[0];
        let mac_str = parts[1];
        // parts[2] = type (skip)
        // parts[3] = age (skip)
        let port = parts[4];

        if !ip.contains('.') {
            continue;
        }

        let mac = crate::normalize_mac(mac_str);
        if mac.len() != 17 {
            continue;
        }

        entries.push(ArpEntry {
            ip_address: ip.to_string(),
            mac_address: mac,
            interface: Some(port.to_string()),
            vlan: None,
        });
    }

    log::info!("Parsed {} HP/Aruba ARP entries", entries.len());
    entries
}

/// Load and parse HP/Aruba ARP table from a file.
pub fn parse_aruba_arp_file(path: &Path) -> Vec<ArpEntry> {
    match std::fs::read_to_string(path) {
        Ok(content) => parse_aruba_arp(&content),
        Err(e) => {
            log::error!("Failed to read HP/Aruba ARP file: {}", e);
            Vec::new()
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_ARUBA_CONFIG: &str = r#"
hostname "SW-PLANT-ARUBA"

vlan 1
   name "DEFAULT"
vlan 100
   name "OT_NETWORK"
   untagged 1-10
vlan 200
   name "IT_NETWORK"
   tagged 11-20

interface 1
   name "PLC-Line1"
vlan 100
   untagged 1

interface A1
   name "Uplink-to-CORE"

interface 5
   ip address 192.168.100.1 255.255.255.0
"#;

    #[test]
    fn test_parse_aruba_hostname() {
        assert_eq!(parse_aruba_hostname(SAMPLE_ARUBA_CONFIG), "SW-PLANT-ARUBA");
    }

    #[test]
    fn test_parse_aruba_vlans() {
        let vlans = parse_aruba_vlans(SAMPLE_ARUBA_CONFIG);
        assert!(vlans.contains_key(&100));
        assert!(vlans.contains_key(&200));
        assert_eq!(vlans.get(&100).map(|s| s.as_str()), Some("OT_NETWORK"));
        assert_eq!(vlans.get(&200).map(|s| s.as_str()), Some("IT_NETWORK"));
    }

    #[test]
    fn test_parse_aruba_config_full() {
        let sw = parse_aruba_config(SAMPLE_ARUBA_CONFIG).unwrap();
        assert_eq!(sw.hostname, "SW-PLANT-ARUBA");
        assert!(sw.ports.len() >= 2);

        let port1 = sw.ports.iter().find(|p| p.name == "1").unwrap();
        assert_eq!(port1.description.as_deref(), Some("PLC-Line1"));

        let port_a1 = sw.ports.iter().find(|p| p.name == "A1").unwrap();
        assert_eq!(port_a1.description.as_deref(), Some("Uplink-to-CORE"));
    }

    #[test]
    fn test_parse_aruba_management_ip() {
        let sw = parse_aruba_config(SAMPLE_ARUBA_CONFIG).unwrap();
        assert_eq!(sw.management_ip.as_deref(), Some("192.168.100.1"));
    }

    const SAMPLE_ARUBA_MAC: &str = r#"
 MAC Address    Port  VLAN   Type
 -------------- ----- ------ -------
 aabbcc-ddeeff  1     100    Dynamic
 001122-334455  A1    1      Static
 005079-666800  2     100    Dynamic
"#;

    #[test]
    fn test_parse_aruba_mac_table() {
        let entries = parse_aruba_mac_table(SAMPLE_ARUBA_MAC);
        assert_eq!(entries.len(), 3);

        let first = &entries[0];
        assert_eq!(first.mac_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(first.port, "1");
        assert_eq!(first.vlan, 100);
        assert_eq!(first.entry_type, "dynamic");

        let second = &entries[1];
        assert_eq!(second.mac_address, "00:11:22:33:44:55");
        assert_eq!(second.port, "A1");
        assert_eq!(second.entry_type, "static");
    }

    const SAMPLE_ARUBA_LLDP: &str = r#"
 LocalPort  | ChassisId         | PortId      | SysName     | Capabilities
 ----------   ------------------   -----------   -----------   -----------
 1          | aa:bb:cc:dd:ee:ff | 24          | SW-CORE-1   | B, R
 A1         | 00:1a:2b:3c:4d:5e | A2          | SW-ACCESS-2 | B
"#;

    #[test]
    fn test_parse_aruba_lldp() {
        let neighbors = parse_aruba_lldp_neighbors(SAMPLE_ARUBA_LLDP);
        assert_eq!(neighbors.len(), 2);

        let (local_port, neighbor) = &neighbors[0];
        assert_eq!(local_port, "1");
        assert_eq!(neighbor.device_id, "SW-CORE-1");
        assert_eq!(neighbor.remote_port, "24");

        let (local_port2, neighbor2) = &neighbors[1];
        assert_eq!(local_port2, "A1");
        assert_eq!(neighbor2.device_id, "SW-ACCESS-2");
    }

    const SAMPLE_ARUBA_ARP: &str = r#"
 IP Address     MAC Address       Type     Age(min)  Port
 -----------    ----------------  -------  --------  ------
 192.168.1.1    001122-334455     dynamic  -         1
 192.168.1.10   aabbcc-ddeeff     dynamic  15        2
 192.168.1.20   005079-666800     dynamic  5         3
"#;

    #[test]
    fn test_parse_aruba_arp() {
        let entries = parse_aruba_arp(SAMPLE_ARUBA_ARP);
        assert_eq!(entries.len(), 3);

        let first = &entries[0];
        assert_eq!(first.ip_address, "192.168.1.1");
        assert_eq!(first.mac_address, "00:11:22:33:44:55");
        assert_eq!(first.interface.as_deref(), Some("1"));

        let second = &entries[1];
        assert_eq!(second.ip_address, "192.168.1.10");
        assert_eq!(second.mac_address, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_normalize_mac_aruba_format() {
        // HP/Aruba format: aabbcc-ddeeff
        assert_eq!(crate::normalize_mac("aabbcc-ddeeff"), "aa:bb:cc:dd:ee:ff");
        assert_eq!(crate::normalize_mac("001122-334455"), "00:11:22:33:44:55");
    }
}
