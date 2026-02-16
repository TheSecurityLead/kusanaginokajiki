//! Physical topology parsing for Kusanagi Kajiki.
//!
//! Parses Cisco IOS config files, MAC address tables, CDP neighbor
//! output, and ARP tables to build a physical switch-port topology.
//! Stubs provided for Juniper and HP/Aruba (not yet implemented).

pub mod error;
pub mod cisco;
pub mod juniper;
pub mod aruba;

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

pub use error::PhysicalError;

/// A physical network switch with its ports and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalSwitch {
    /// Hostname from the running-config or CDP
    pub hostname: String,
    /// Management IP (if found in config)
    pub management_ip: Option<String>,
    /// Switch model/platform (if found)
    pub model: Option<String>,
    /// IOS version (if found)
    pub ios_version: Option<String>,
    /// All physical ports on this switch
    pub ports: Vec<PhysicalPort>,
    /// VLANs configured on this switch (VLAN ID → name)
    pub vlans: HashMap<u16, String>,
}

/// A physical switch port with associated devices and configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalPort {
    /// Interface name, e.g. "GigabitEthernet1/0/14" or "Gi1/0/14"
    pub name: String,
    /// Normalized short name, e.g. "Gi1/0/14"
    pub short_name: String,
    /// Human-readable description from the config
    pub description: Option<String>,
    /// VLAN(s) assigned to this port
    pub vlans: Vec<u16>,
    /// Port mode: "access", "trunk", or "unknown"
    pub mode: String,
    /// Whether the port is administratively shut down
    pub shutdown: bool,
    /// IP address configured on this interface (for L3 ports/SVIs)
    pub ip_address: Option<String>,
    /// Subnet mask for the IP address
    pub subnet_mask: Option<String>,
    /// MAC addresses learned on this port (from MAC address table)
    pub mac_addresses: Vec<String>,
    /// IP addresses associated with MACs on this port (from ARP)
    pub ip_addresses: Vec<String>,
    /// CDP neighbor connected to this port (if any)
    pub cdp_neighbor: Option<CdpNeighbor>,
    /// Speed setting
    pub speed: Option<String>,
    /// Duplex setting
    pub duplex: Option<String>,
}

/// A CDP/LLDP neighbor discovered on a port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CdpNeighbor {
    /// Neighbor device ID (hostname)
    pub device_id: String,
    /// The neighbor's port that connects back to us
    pub remote_port: String,
    /// Platform/model of the neighbor
    pub platform: Option<String>,
    /// IP address of the neighbor
    pub ip_address: Option<String>,
    /// Capabilities (Router, Switch, Host, etc.)
    pub capabilities: Vec<String>,
}

/// An ARP table entry mapping IP → MAC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip_address: String,
    pub mac_address: String,
    /// Interface the ARP entry was learned on
    pub interface: Option<String>,
    /// VLAN if applicable
    pub vlan: Option<u16>,
}

/// A MAC address table entry from `show mac address-table`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacTableEntry {
    pub mac_address: String,
    pub vlan: u16,
    pub port: String,
    /// "dynamic", "static", or "self"
    pub entry_type: String,
}

/// A link between two physical switches (discovered via CDP/LLDP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhysicalLink {
    /// Source switch hostname
    pub src_switch: String,
    /// Source port name
    pub src_port: String,
    /// Destination switch hostname (CDP neighbor device_id)
    pub dst_switch: String,
    /// Destination port name (CDP neighbor remote_port)
    pub dst_port: String,
}

/// Aggregated physical topology containing all switches, links, and
/// the MAC/ARP correlation data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PhysicalTopology {
    /// All switches discovered from configs
    pub switches: Vec<PhysicalSwitch>,
    /// Inter-switch links discovered from CDP
    pub links: Vec<PhysicalLink>,
    /// Device mapping: IP → (switch hostname, port name)
    /// Built by correlating ARP + MAC table + config
    pub device_locations: HashMap<String, DeviceLocation>,
}

/// Where a device (by IP) is physically located.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceLocation {
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub switch_hostname: String,
    pub port_name: String,
    pub vlan: Option<u16>,
}

impl PhysicalTopology {
    /// Correlate ARP entries with MAC table entries to build device_locations.
    ///
    /// For each ARP entry, look up the MAC in a switch's MAC address table
    /// to find which switch port the device is connected to.
    pub fn correlate_arp_to_ports(&mut self) {
        // Build a lookup: MAC (normalized) → (switch hostname, port, vlan)
        let mut mac_to_port: HashMap<String, (String, String, u16)> = HashMap::new();

        for sw in &self.switches {
            for port in &sw.ports {
                for mac in &port.mac_addresses {
                    let normalized = normalize_mac(mac);
                    // For each MAC on this port, also figure out which VLAN
                    let vlan = port.vlans.first().copied().unwrap_or(1);
                    mac_to_port.insert(normalized, (sw.hostname.clone(), port.name.clone(), vlan));
                }
            }
        }

        // For each switch, look at the ARP-derived ip_addresses on ports
        // and also do global ARP correlation
        for sw in &self.switches {
            for port in &sw.ports {
                for ip in &port.ip_addresses {
                    if !self.device_locations.contains_key(ip) {
                        // Find the MAC for this IP from the port's MAC list
                        let mac = port.mac_addresses.first().cloned();
                        let vlan = port.vlans.first().copied();
                        self.device_locations.insert(ip.clone(), DeviceLocation {
                            ip_address: ip.clone(),
                            mac_address: mac,
                            switch_hostname: sw.hostname.clone(),
                            port_name: port.name.clone(),
                            vlan,
                        });
                    }
                }
            }
        }
    }

    /// Build inter-switch links from CDP neighbor data.
    pub fn build_links(&mut self) {
        self.links.clear();
        for sw in &self.switches {
            for port in &sw.ports {
                if let Some(ref neighbor) = port.cdp_neighbor {
                    self.links.push(PhysicalLink {
                        src_switch: sw.hostname.clone(),
                        src_port: port.name.clone(),
                        dst_switch: neighbor.device_id.clone(),
                        dst_port: neighbor.remote_port.clone(),
                    });
                }
            }
        }
    }

    /// Merge ARP entries into the topology by correlating with MAC table.
    pub fn apply_arp_entries(&mut self, arp_entries: &[ArpEntry]) {
        // Build MAC → (switch, port, vlan) from all switches
        let mut mac_to_port: HashMap<String, (String, String, u16)> = HashMap::new();
        for sw in &self.switches {
            for port in &sw.ports {
                for mac in &port.mac_addresses {
                    let normalized = normalize_mac(mac);
                    let vlan = port.vlans.first().copied().unwrap_or(1);
                    mac_to_port.insert(normalized, (sw.hostname.clone(), port.name.clone(), vlan));
                }
            }
        }

        for entry in arp_entries {
            let normalized_mac = normalize_mac(&entry.mac_address);
            if let Some((switch_hostname, port_name, vlan)) = mac_to_port.get(&normalized_mac) {
                // Add IP to the port's ip_addresses list
                for sw in &mut self.switches {
                    if sw.hostname == *switch_hostname {
                        for port in &mut sw.ports {
                            if port.name == *port_name && !port.ip_addresses.contains(&entry.ip_address) {
                                port.ip_addresses.push(entry.ip_address.clone());
                            }
                        }
                    }
                }

                // Add to device_locations
                self.device_locations.entry(entry.ip_address.clone()).or_insert_with(|| {
                    DeviceLocation {
                        ip_address: entry.ip_address.clone(),
                        mac_address: Some(entry.mac_address.clone()),
                        switch_hostname: switch_hostname.clone(),
                        port_name: port_name.clone(),
                        vlan: Some(*vlan),
                    }
                });
            }
        }
    }

    /// Merge MAC table entries into switches.
    ///
    /// `switch_hostname` identifies which switch these entries belong to.
    /// Each MAC is added to the matching port's mac_addresses list.
    pub fn apply_mac_table(&mut self, switch_hostname: &str, entries: &[MacTableEntry]) {
        for sw in &mut self.switches {
            if sw.hostname == switch_hostname {
                for entry in entries {
                    for port in &mut sw.ports {
                        if port.name == entry.port || port.short_name == entry.port {
                            let normalized = normalize_mac(&entry.mac_address);
                            if !port.mac_addresses.contains(&normalized) {
                                port.mac_addresses.push(normalized);
                            }
                            // Also ensure the VLAN is tracked
                            if !port.vlans.contains(&entry.vlan) {
                                port.vlans.push(entry.vlan);
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Merge CDP neighbors into switches.
    pub fn apply_cdp_neighbors(&mut self, switch_hostname: &str, neighbors: &[(String, CdpNeighbor)]) {
        for sw in &mut self.switches {
            if sw.hostname == switch_hostname {
                for (port_name, neighbor) in neighbors {
                    for port in &mut sw.ports {
                        if port.name == *port_name || port.short_name == *port_name {
                            port.cdp_neighbor = Some(neighbor.clone());
                            break;
                        }
                    }
                }
            }
        }
    }
}

/// Normalize a MAC address to lowercase colon-separated format.
///
/// Handles formats like "0000.1111.2222", "00:00:11:11:22:22",
/// "00-00-11-11-22-22", etc.
pub fn normalize_mac(mac: &str) -> String {
    // Strip all separators, lowercase
    let hex: String = mac.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_lowercase();

    if hex.len() != 12 {
        return mac.to_lowercase();
    }

    format!(
        "{}:{}:{}:{}:{}:{}",
        &hex[0..2], &hex[2..4], &hex[4..6],
        &hex[6..8], &hex[8..10], &hex[10..12]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_mac_colon() {
        assert_eq!(normalize_mac("00:1A:2B:3C:4D:5E"), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn test_normalize_mac_cisco_format() {
        assert_eq!(normalize_mac("001a.2b3c.4d5e"), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn test_normalize_mac_dash() {
        assert_eq!(normalize_mac("00-1A-2B-3C-4D-5E"), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn test_normalize_mac_bare() {
        assert_eq!(normalize_mac("001a2b3c4d5e"), "00:1a:2b:3c:4d:5e");
    }

    #[test]
    fn test_correlate_arp_to_ports() {
        let mut topo = PhysicalTopology::default();
        topo.switches.push(PhysicalSwitch {
            hostname: "SW1".to_string(),
            management_ip: None,
            model: None,
            ios_version: None,
            ports: vec![PhysicalPort {
                name: "Gi1/0/1".to_string(),
                short_name: "Gi1/0/1".to_string(),
                description: None,
                vlans: vec![100],
                mode: "access".to_string(),
                shutdown: false,
                ip_address: None,
                subnet_mask: None,
                mac_addresses: vec!["00:1a:2b:3c:4d:5e".to_string()],
                ip_addresses: vec![],
                cdp_neighbor: None,
                speed: None,
                duplex: None,
            }],
            vlans: HashMap::new(),
        });

        let arp_entries = vec![ArpEntry {
            ip_address: "192.168.1.100".to_string(),
            mac_address: "00:1a:2b:3c:4d:5e".to_string(),
            interface: None,
            vlan: Some(100),
        }];

        topo.apply_arp_entries(&arp_entries);

        assert_eq!(topo.device_locations.len(), 1);
        let loc = topo.device_locations.get("192.168.1.100").unwrap();
        assert_eq!(loc.switch_hostname, "SW1");
        assert_eq!(loc.port_name, "Gi1/0/1");
    }
}
