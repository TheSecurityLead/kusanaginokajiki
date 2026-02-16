//! Cisco IOS parser for running-config, MAC address table,
//! CDP neighbors, and ARP table output.
//!
//! These parsers work on text output (e.g., from `show running-config`,
//! `show mac address-table`, `show cdp neighbors detail`, `show arp`).

use std::collections::HashMap;
use std::path::Path;

use regex::Regex;

use crate::{
    ArpEntry, CdpNeighbor, MacTableEntry, PhysicalPort, PhysicalSwitch,
    PhysicalError,
};

// ─── Running Config Parser ──────────────────────────────────────

/// Parse a Cisco IOS running-config file into a PhysicalSwitch.
///
/// Extracts: hostname, interfaces (with descriptions, VLANs, IPs,
/// shutdown state, speed/duplex), VLAN definitions, and management IP.
pub fn parse_running_config(content: &str) -> Result<PhysicalSwitch, PhysicalError> {
    let hostname = parse_hostname(content);
    let ios_version = parse_ios_version(content);
    let vlans = parse_vlan_definitions(content);
    let ports = parse_interfaces(content);
    let management_ip = find_management_ip(&ports);

    Ok(PhysicalSwitch {
        hostname,
        management_ip,
        model: None,
        ios_version,
        ports,
        vlans,
    })
}

/// Load and parse a running-config from a file path.
pub fn parse_running_config_file(path: &Path) -> Result<PhysicalSwitch, PhysicalError> {
    let content = std::fs::read_to_string(path)?;
    parse_running_config(&content)
}

fn parse_hostname(content: &str) -> String {
    // Safety: static regex pattern — cannot fail, but handle gracefully anyway
    let Ok(re) = Regex::new(r"(?m)^hostname\s+(\S+)") else {
        return "Unknown".to_string();
    };
    re.captures(content)
        .map(|c| c[1].to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn parse_ios_version(content: &str) -> Option<String> {
    let re = Regex::new(r"(?m)^version\s+(.+)").ok()?;
    re.captures(content).map(|c| c[1].trim().to_string())
}

fn parse_vlan_definitions(content: &str) -> HashMap<u16, String> {
    let mut vlans = HashMap::new();
    // Match "vlan <id>" followed by optional " name <name>"
    let (Ok(re_vlan), Ok(re_name)) = (
        Regex::new(r"(?m)^vlan\s+(\d+)"),
        Regex::new(r"(?m)^\s+name\s+(.+)"),
    ) else {
        return vlans;
    };

    let lines: Vec<&str> = content.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if let Some(caps) = re_vlan.captures(line) {
            if let Ok(id) = caps[1].parse::<u16>() {
                let name = if i + 1 < lines.len() {
                    re_name.captures(lines[i + 1])
                        .map(|c| c[1].trim().to_string())
                        .unwrap_or_else(|| format!("VLAN{}", id))
                } else {
                    format!("VLAN{}", id)
                };
                vlans.insert(id, name);
            }
        }
    }

    vlans
}

/// Parse all interface blocks from the running-config.
fn parse_interfaces(content: &str) -> Vec<PhysicalPort> {
    let mut ports = Vec::new();

    // Split the config into interface blocks
    // Each block starts with "interface <name>" and ends at the next "!" or "interface"
    let Ok(re_iface) = Regex::new(r"(?m)^interface\s+(.+)") else {
        return ports;
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        if let Some(caps) = re_iface.captures(lines[i]) {
            let iface_name = caps[1].trim().to_string();
            let short = shorten_interface_name(&iface_name);

            let mut description = None;
            let mut vlans = Vec::new();
            let mut mode = "unknown".to_string();
            let mut shutdown = false;
            let mut ip_address = None;
            let mut subnet_mask = None;
            let mut speed = None;
            let mut duplex = None;

            i += 1;
            // Parse the interface block lines until we hit "!" or another "interface"
            while i < lines.len() {
                let line = lines[i].trim();
                if line == "!" || re_iface.is_match(lines[i]) {
                    break;
                }

                if let Some(desc) = line.strip_prefix("description ") {
                    description = Some(desc.to_string());
                } else if line.starts_with("switchport mode access") {
                    mode = "access".to_string();
                } else if line.starts_with("switchport mode trunk") {
                    mode = "trunk".to_string();
                } else if let Some(rest) = line.strip_prefix("switchport access vlan ") {
                    if let Ok(v) = rest.trim().parse::<u16>() {
                        if !vlans.contains(&v) {
                            vlans.push(v);
                        }
                    }
                } else if let Some(rest) = line.strip_prefix("switchport trunk allowed vlan ") {
                    for part in rest.split(',') {
                        let part = part.trim();
                        if let Some((start, end)) = part.split_once('-') {
                            if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                                for v in s..=e {
                                    if !vlans.contains(&v) {
                                        vlans.push(v);
                                    }
                                }
                            }
                        } else if let Ok(v) = part.parse::<u16>() {
                            if !vlans.contains(&v) {
                                vlans.push(v);
                            }
                        }
                    }
                } else if line.starts_with("switchport trunk native vlan ") {
                    if let Some(rest) = line.strip_prefix("switchport trunk native vlan ") {
                        if let Ok(v) = rest.trim().parse::<u16>() {
                            if !vlans.contains(&v) {
                                vlans.push(v);
                            }
                        }
                    }
                } else if line == "shutdown" {
                    shutdown = true;
                } else if line.starts_with("ip address ") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        ip_address = Some(parts[2].to_string());
                        subnet_mask = Some(parts[3].to_string());
                    }
                } else if let Some(rest) = line.strip_prefix("speed ") {
                    speed = Some(rest.trim().to_string());
                } else if let Some(rest) = line.strip_prefix("duplex ") {
                    duplex = Some(rest.trim().to_string());
                }

                i += 1;
            }

            // Default to VLAN 1 for access ports with no explicit VLAN
            if mode == "access" && vlans.is_empty() {
                vlans.push(1);
            }

            ports.push(PhysicalPort {
                name: iface_name,
                short_name: short,
                description,
                vlans,
                mode,
                shutdown,
                ip_address,
                subnet_mask,
                mac_addresses: Vec::new(),
                ip_addresses: Vec::new(),
                cdp_neighbor: None,
                speed,
                duplex,
            });
        } else {
            i += 1;
        }
    }

    ports
}

/// Find the management IP from parsed interfaces.
/// Looks for Vlan1 or the first SVI or Loopback with an IP.
fn find_management_ip(ports: &[PhysicalPort]) -> Option<String> {
    // Priority: Vlan1 > any other Vlan SVI > Loopback0 > first interface with IP
    for port in ports {
        if port.name == "Vlan1" || port.short_name == "Vl1" {
            if let Some(ref ip) = port.ip_address {
                return Some(ip.clone());
            }
        }
    }
    for port in ports {
        if port.name.starts_with("Vlan") || port.name.starts_with("Vl") {
            if let Some(ref ip) = port.ip_address {
                return Some(ip.clone());
            }
        }
    }
    for port in ports {
        if port.name.starts_with("Loopback") || port.name.starts_with("Lo") {
            if let Some(ref ip) = port.ip_address {
                return Some(ip.clone());
            }
        }
    }
    for port in ports {
        if let Some(ref ip) = port.ip_address {
            return Some(ip.clone());
        }
    }
    None
}

/// Shorten a Cisco interface name.
///
/// "GigabitEthernet1/0/14" → "Gi1/0/14"
/// "FastEthernet0/1" → "Fa0/1"
/// "TenGigabitEthernet1/1/1" → "Te1/1/1"
/// "Vlan100" → "Vl100"
/// "Loopback0" → "Lo0"
fn shorten_interface_name(name: &str) -> String {
    let prefixes = [
        ("TenGigabitEthernet", "Te"),
        ("GigabitEthernet", "Gi"),
        ("FastEthernet", "Fa"),
        ("Ethernet", "Et"),
        ("Loopback", "Lo"),
        ("Tunnel", "Tu"),
        ("Port-channel", "Po"),
        ("Vlan", "Vl"),
    ];

    for (long, short) in &prefixes {
        if let Some(rest) = name.strip_prefix(long) {
            return format!("{}{}", short, rest);
        }
    }

    name.to_string()
}

// ─── MAC Address Table Parser ───────────────────────────────────

/// Parse `show mac address-table` output.
///
/// Handles formats:
/// ```text
///           Mac Address Table
/// -------------------------------------------
/// Vlan    Mac Address       Type        Ports
/// ----    -----------       --------    -----
///  100    0050.7966.6800    DYNAMIC     Gi1/0/1
///  100    001a.2b3c.4d5e    STATIC      Gi1/0/24
/// ```
pub fn parse_mac_table(content: &str) -> Result<Vec<MacTableEntry>, PhysicalError> {
    let mut entries = Vec::new();

    // Pattern matches lines like: "  100    0050.7966.6800    DYNAMIC     Gi1/0/1"
    // Also handles colon/dash MAC formats
    let re = Regex::new(
        r"(?m)^\s*(\d+)\s+([\da-fA-F]{4}\.[\da-fA-F]{4}\.[\da-fA-F]{4}|[\da-fA-F:.\-]+)\s+(DYNAMIC|STATIC|SELF|dynamic|static|self)\s+(\S+)"
    ).map_err(|e| PhysicalError::Parse(format!("MAC table regex: {}", e)))?;

    for caps in re.captures_iter(content) {
        let vlan = caps[1].parse::<u16>()
            .map_err(|e| PhysicalError::Parse(format!("Invalid VLAN: {}", e)))?;
        let mac = crate::normalize_mac(&caps[2]);
        let entry_type = caps[3].to_lowercase();
        let port = caps[4].to_string();

        entries.push(MacTableEntry {
            mac_address: mac,
            vlan,
            port,
            entry_type,
        });
    }

    log::info!("Parsed {} MAC table entries", entries.len());
    Ok(entries)
}

/// Load and parse MAC address table from a file.
pub fn parse_mac_table_file(path: &Path) -> Result<Vec<MacTableEntry>, PhysicalError> {
    let content = std::fs::read_to_string(path)?;
    parse_mac_table(&content)
}

// ─── CDP Neighbors Parser ───────────────────────────────────────

/// Parse `show cdp neighbors detail` output.
///
/// Returns pairs of (local_port, CdpNeighbor).
///
/// Example input:
/// ```text
/// -------------------------
/// Device ID: SW-DIST-1.example.com
/// Entry address(es):
///   IP address: 10.1.1.1
/// Platform: cisco WS-C3750G-24TS, Capabilities: Router Switch IGMP
/// Interface: GigabitEthernet1/0/24,  Port ID (outgoing port): GigabitEthernet0/1
/// ```
pub fn parse_cdp_neighbors(content: &str) -> Result<Vec<(String, CdpNeighbor)>, PhysicalError> {
    let mut neighbors = Vec::new();

    // Split by the separator lines that delimit each neighbor entry
    let entries: Vec<&str> = content.split("-------------------------").collect();

    let map_re = |e: regex::Error| PhysicalError::Parse(format!("CDP regex: {}", e));
    let re_device_id = Regex::new(r"(?m)Device ID:\s*(.+)").map_err(&map_re)?;
    let re_ip = Regex::new(r"(?m)IP address:\s*(\S+)").map_err(&map_re)?;
    let re_platform = Regex::new(r"(?m)Platform:\s*([^,]+)").map_err(&map_re)?;
    let re_capabilities = Regex::new(r"(?m)Capabilities:\s*(.+)").map_err(&map_re)?;
    let re_interface = Regex::new(
        r"(?m)Interface:\s*(\S+),\s*Port ID \(outgoing port\):\s*(\S+)"
    ).map_err(&map_re)?;

    for entry in &entries {
        let device_id = match re_device_id.captures(entry) {
            Some(caps) => caps[1].trim().to_string(),
            None => continue,
        };

        let local_port = match re_interface.captures(entry) {
            Some(caps) => {
                let local = caps[1].trim().trim_end_matches(',').to_string();
                let remote = caps[2].trim().to_string();

                let ip_address = re_ip.captures(entry).map(|c| c[1].trim().to_string());
                let platform = re_platform.captures(entry).map(|c| c[1].trim().to_string());
                let capabilities = re_capabilities.captures(entry)
                    .map(|c| {
                        c[1].split_whitespace()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();

                let neighbor = CdpNeighbor {
                    device_id,
                    remote_port: remote,
                    platform,
                    ip_address,
                    capabilities,
                };

                (local, neighbor)
            }
            None => continue,
        };

        neighbors.push(local_port);
    }

    log::info!("Parsed {} CDP neighbors", neighbors.len());
    Ok(neighbors)
}

/// Load and parse CDP neighbors from a file.
pub fn parse_cdp_neighbors_file(path: &Path) -> Result<Vec<(String, CdpNeighbor)>, PhysicalError> {
    let content = std::fs::read_to_string(path)?;
    parse_cdp_neighbors(&content)
}

// ─── ARP Table Parser ──────────────────────────────────────────

/// Parse `show arp` or `show ip arp` output.
///
/// Example input:
/// ```text
/// Protocol  Address          Age (min)  Hardware Addr   Type   Interface
/// Internet  192.168.1.1            -   001a.2b3c.4d5e  ARPA   Vlan100
/// Internet  192.168.1.100         10   0050.7966.6800  ARPA   Vlan100
/// ```
pub fn parse_arp_table(content: &str) -> Result<Vec<ArpEntry>, PhysicalError> {
    let mut entries = Vec::new();

    // Match lines like: "Internet  192.168.1.1   -   001a.2b3c.4d5e  ARPA   Vlan100"
    let re = Regex::new(
        r"(?m)^\s*Internet\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+([\da-fA-F]{4}\.[\da-fA-F]{4}\.[\da-fA-F]{4}|[\da-fA-F:.\-]+)\s+\S+\s+(\S+)"
    ).map_err(|e| PhysicalError::Parse(format!("ARP regex: {}", e)))?;

    for caps in re.captures_iter(content) {
        let ip = caps[1].to_string();
        let mac = crate::normalize_mac(&caps[2]);
        let interface = caps[3].to_string();

        // Extract VLAN number from interface name (e.g., "Vlan100" → 100)
        let vlan = interface.strip_prefix("Vlan")
            .or_else(|| interface.strip_prefix("Vl"))
            .and_then(|s| s.parse::<u16>().ok());

        entries.push(ArpEntry {
            ip_address: ip,
            mac_address: mac,
            interface: Some(interface),
            vlan,
        });
    }

    log::info!("Parsed {} ARP entries", entries.len());
    Ok(entries)
}

/// Load and parse ARP table from a file.
pub fn parse_arp_table_file(path: &Path) -> Result<Vec<ArpEntry>, PhysicalError> {
    let content = std::fs::read_to_string(path)?;
    parse_arp_table(&content)
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONFIG: &str = r#"
!
version 15.2
!
hostname SW-PLANT-3
!
vlan 100
 name OT_NETWORK
!
vlan 200
 name IT_NETWORK
!
interface GigabitEthernet1/0/1
 description PLC-Line1
 switchport access vlan 100
 switchport mode access
 speed 100
 duplex full
!
interface GigabitEthernet1/0/2
 description HMI-Station1
 switchport access vlan 100
 switchport mode access
!
interface GigabitEthernet1/0/14
 description PLC-Line2
 switchport access vlan 100
 switchport mode access
 shutdown
!
interface GigabitEthernet1/0/24
 description Uplink-to-DIST
 switchport trunk allowed vlan 100,200
 switchport mode trunk
!
interface Vlan1
 no ip address
 shutdown
!
interface Vlan100
 ip address 192.168.100.1 255.255.255.0
!
"#;

    #[test]
    fn test_parse_hostname() {
        assert_eq!(parse_hostname(SAMPLE_CONFIG), "SW-PLANT-3");
    }

    #[test]
    fn test_parse_ios_version() {
        assert_eq!(parse_ios_version(SAMPLE_CONFIG), Some("15.2".to_string()));
    }

    #[test]
    fn test_parse_vlan_definitions() {
        let vlans = parse_vlan_definitions(SAMPLE_CONFIG);
        assert_eq!(vlans.get(&100), Some(&"OT_NETWORK".to_string()));
        assert_eq!(vlans.get(&200), Some(&"IT_NETWORK".to_string()));
    }

    #[test]
    fn test_parse_interfaces() {
        let ports = parse_interfaces(SAMPLE_CONFIG);
        assert!(ports.len() >= 5);

        // Check GigabitEthernet1/0/1
        let gi1 = ports.iter().find(|p| p.name == "GigabitEthernet1/0/1").unwrap();
        assert_eq!(gi1.short_name, "Gi1/0/1");
        assert_eq!(gi1.description.as_deref(), Some("PLC-Line1"));
        assert_eq!(gi1.vlans, vec![100]);
        assert_eq!(gi1.mode, "access");
        assert!(!gi1.shutdown);
        assert_eq!(gi1.speed.as_deref(), Some("100"));
        assert_eq!(gi1.duplex.as_deref(), Some("full"));

        // Check shutdown port
        let gi14 = ports.iter().find(|p| p.name == "GigabitEthernet1/0/14").unwrap();
        assert!(gi14.shutdown);

        // Check trunk port
        let gi24 = ports.iter().find(|p| p.name == "GigabitEthernet1/0/24").unwrap();
        assert_eq!(gi24.mode, "trunk");
        assert!(gi24.vlans.contains(&100));
        assert!(gi24.vlans.contains(&200));

        // Check SVI with IP
        let vlan100 = ports.iter().find(|p| p.name == "Vlan100").unwrap();
        assert_eq!(vlan100.ip_address.as_deref(), Some("192.168.100.1"));
        assert_eq!(vlan100.subnet_mask.as_deref(), Some("255.255.255.0"));
    }

    #[test]
    fn test_parse_running_config() {
        let sw = parse_running_config(SAMPLE_CONFIG).unwrap();
        assert_eq!(sw.hostname, "SW-PLANT-3");
        assert_eq!(sw.management_ip.as_deref(), Some("192.168.100.1"));
        assert!(sw.ports.len() >= 5);
    }

    #[test]
    fn test_shorten_interface_name() {
        assert_eq!(shorten_interface_name("GigabitEthernet1/0/14"), "Gi1/0/14");
        assert_eq!(shorten_interface_name("FastEthernet0/1"), "Fa0/1");
        assert_eq!(shorten_interface_name("TenGigabitEthernet1/1/1"), "Te1/1/1");
        assert_eq!(shorten_interface_name("Vlan100"), "Vl100");
        assert_eq!(shorten_interface_name("Loopback0"), "Lo0");
        assert_eq!(shorten_interface_name("Port-channel1"), "Po1");
    }

    const SAMPLE_MAC_TABLE: &str = r#"
          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 100    0050.7966.6800    DYNAMIC     Gi1/0/1
 100    001a.2b3c.4d5e    DYNAMIC     Gi1/0/2
 100    00d0.c9a1.b2c3    STATIC      Gi1/0/14
 200    aabb.ccdd.eeff    DYNAMIC     Gi1/0/10
   1    0011.2233.4455    DYNAMIC     Gi1/0/24
Total Mac Addresses for this criterion: 5
"#;

    #[test]
    fn test_parse_mac_table() {
        let entries = parse_mac_table(SAMPLE_MAC_TABLE).unwrap();
        assert_eq!(entries.len(), 5);

        let first = &entries[0];
        assert_eq!(first.vlan, 100);
        assert_eq!(first.mac_address, "00:50:79:66:68:00");
        assert_eq!(first.entry_type, "dynamic");
        assert_eq!(first.port, "Gi1/0/1");

        let static_entry = entries.iter().find(|e| e.entry_type == "static").unwrap();
        assert_eq!(static_entry.mac_address, "00:d0:c9:a1:b2:c3");
        assert_eq!(static_entry.port, "Gi1/0/14");
    }

    const SAMPLE_CDP: &str = r#"
-------------------------
Device ID: SW-DIST-1.example.com
Entry address(es):
  IP address: 10.1.1.1
Platform: cisco WS-C3750G-24TS,  Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/24,  Port ID (outgoing port): GigabitEthernet0/1

Holdtime : 157 sec

Version :
Cisco IOS Software, C3750 Software

-------------------------
Device ID: SW-ACCESS-2
Entry address(es):
  IP address: 10.1.1.2
Platform: cisco WS-C2960-24TT-L,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/23,  Port ID (outgoing port): GigabitEthernet0/2

Holdtime : 145 sec
"#;

    #[test]
    fn test_parse_cdp_neighbors() {
        let neighbors = parse_cdp_neighbors(SAMPLE_CDP).unwrap();
        assert_eq!(neighbors.len(), 2);

        let (local_port, neighbor) = &neighbors[0];
        assert_eq!(local_port, "GigabitEthernet1/0/24");
        assert_eq!(neighbor.device_id, "SW-DIST-1.example.com");
        assert_eq!(neighbor.remote_port, "GigabitEthernet0/1");
        assert_eq!(neighbor.ip_address.as_deref(), Some("10.1.1.1"));
        assert_eq!(neighbor.platform.as_deref(), Some("cisco WS-C3750G-24TS"));
        assert!(neighbor.capabilities.contains(&"Router".to_string()));
        assert!(neighbor.capabilities.contains(&"Switch".to_string()));

        let (local_port2, neighbor2) = &neighbors[1];
        assert_eq!(local_port2, "GigabitEthernet1/0/23");
        assert_eq!(neighbor2.device_id, "SW-ACCESS-2");
    }

    const SAMPLE_ARP: &str = r#"
Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  192.168.100.1           -   001a.2b3c.4d5e  ARPA   Vlan100
Internet  192.168.100.10         15   0050.7966.6800  ARPA   Vlan100
Internet  192.168.100.20          5   00d0.c9a1.b2c3  ARPA   Vlan100
Internet  192.168.200.1           -   001a.2b3c.4d60  ARPA   Vlan200
Internet  10.1.1.1              120   aabb.ccdd.0001  ARPA   Vlan1
"#;

    #[test]
    fn test_parse_arp_table() {
        let entries = parse_arp_table(SAMPLE_ARP).unwrap();
        assert_eq!(entries.len(), 5);

        let first = &entries[0];
        assert_eq!(first.ip_address, "192.168.100.1");
        assert_eq!(first.mac_address, "00:1a:2b:3c:4d:5e");
        assert_eq!(first.interface.as_deref(), Some("Vlan100"));
        assert_eq!(first.vlan, Some(100));

        let last = &entries[4];
        assert_eq!(last.ip_address, "10.1.1.1");
        assert_eq!(last.vlan, Some(1)); // Vlan1 → strip "Vlan" → 1
    }

    #[test]
    fn test_management_ip_priority() {
        // Vlan100 has IP, Vlan1 has no IP → should pick Vlan100
        let sw = parse_running_config(SAMPLE_CONFIG).unwrap();
        assert_eq!(sw.management_ip.as_deref(), Some("192.168.100.1"));
    }
}
