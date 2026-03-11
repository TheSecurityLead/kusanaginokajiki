//! Generic CSV/JSON device import for vendor-neutral physical topology.
//!
//! Accepts a simple flat format with fields:
//! `hostname, ip_address, mac_address, device_type, port, vlan`

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{PhysicalPort, PhysicalSwitch, PhysicalTopology, PhysicalError};

/// A generic device record from CSV or JSON import.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GenericDevice {
    pub hostname: Option<String>,
    pub ip_address: Option<String>,
    pub mac_address: Option<String>,
    pub device_type: Option<String>,
    pub port: Option<String>,
    pub vlan: Option<u16>,
}

// ─── CSV Parser ───────────────────────────────────────────────────

/// Parse a CSV file with header: `hostname,ip_address,mac_address,device_type,port,vlan`
///
/// Uses manual parsing — no external csv crate dependency.
pub fn parse_devices_csv(content: &str) -> Result<Vec<GenericDevice>, PhysicalError> {
    let mut devices = Vec::new();
    let mut lines = content.lines();

    // Parse header row to determine column order
    let header_line = match lines.next() {
        Some(l) => l,
        None => return Ok(devices),
    };

    let headers: Vec<&str> = header_line.split(',').map(|s| s.trim().trim_matches('"')).collect();

    // Build column index map
    let col_idx: HashMap<&str, usize> = headers.iter()
        .enumerate()
        .map(|(i, h)| (*h, i))
        .collect();

    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Split by comma, strip whitespace and quotes from each field
        let fields: Vec<&str> = line.split(',').map(|s| s.trim().trim_matches('"')).collect();

        let get_field = |name: &str| -> Option<String> {
            let idx = col_idx.get(name)?;
            let val = fields.get(*idx)?;
            if val.is_empty() { None } else { Some(val.to_string()) }
        };

        let vlan = get_field("vlan").and_then(|s| s.parse::<u16>().ok());

        devices.push(GenericDevice {
            hostname: get_field("hostname"),
            ip_address: get_field("ip_address"),
            mac_address: get_field("mac_address"),
            device_type: get_field("device_type"),
            port: get_field("port"),
            vlan,
        });
    }

    log::info!("Parsed {} devices from CSV", devices.len());
    Ok(devices)
}

/// Load and parse a CSV device list from a file.
pub fn parse_devices_csv_file(path: &Path) -> Result<Vec<GenericDevice>, PhysicalError> {
    let content = std::fs::read_to_string(path)?;
    parse_devices_csv(&content)
}

// ─── JSON Parser ──────────────────────────────────────────────────

/// Parse a JSON array of device objects.
///
/// Each object may have any subset of the fields:
/// `hostname`, `ip_address`, `mac_address`, `device_type`, `port`, `vlan`
pub fn parse_devices_json(content: &str) -> Result<Vec<GenericDevice>, PhysicalError> {
    let devices: Vec<GenericDevice> = serde_json::from_str(content)
        .map_err(|e| PhysicalError::Parse(format!("JSON parse error: {}", e)))?;
    log::info!("Parsed {} devices from JSON", devices.len());
    Ok(devices)
}

/// Load and parse a JSON device list from a file.
pub fn parse_devices_json_file(path: &Path) -> Result<Vec<GenericDevice>, PhysicalError> {
    let content = std::fs::read_to_string(path)?;
    parse_devices_json(&content)
}

// ─── Topology Builder ─────────────────────────────────────────────

/// Convert a list of GenericDevice records to a PhysicalTopology.
///
/// Groups records by hostname → switches. Each unique port becomes a PhysicalPort.
/// IP and MAC addresses are associated with the port they belong to.
pub fn csv_to_switch(devices: &[GenericDevice]) -> PhysicalTopology {
    // Group by hostname. Records with no hostname go under "unknown".
    let mut switch_map: HashMap<String, HashMap<String, PhysicalPort>> = HashMap::new();

    for device in devices {
        let hostname = device.hostname.clone().unwrap_or_else(|| "unknown".to_string());
        let port_name = device.port.clone().unwrap_or_else(|| "port0".to_string());

        let switch_ports = switch_map.entry(hostname).or_default();

        let port = switch_ports.entry(port_name.clone()).or_insert_with(|| PhysicalPort {
            name: port_name.clone(),
            short_name: port_name.clone(),
            description: device.device_type.clone(),
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

        // Add VLAN
        if let Some(v) = device.vlan {
            if !port.vlans.contains(&v) {
                port.vlans.push(v);
            }
        }

        // Add MAC address
        if let Some(ref mac) = device.mac_address {
            let normalized = crate::normalize_mac(mac);
            if !port.mac_addresses.contains(&normalized) {
                port.mac_addresses.push(normalized);
            }
        }

        // Add IP address
        if let Some(ref ip) = device.ip_address {
            if !port.ip_addresses.contains(ip) {
                port.ip_addresses.push(ip.clone());
            }
        }
    }

    let mut topology = PhysicalTopology::default();

    for (hostname, ports_map) in switch_map {
        let mut ports: Vec<PhysicalPort> = ports_map.into_values().collect();
        ports.sort_by(|a, b| a.name.cmp(&b.name));

        topology.switches.push(PhysicalSwitch {
            hostname,
            management_ip: None,
            model: None,
            ios_version: None,
            ports,
            vlans: HashMap::new(),
        });
    }

    // Correlate ARP and MAC data
    topology.correlate_arp_to_ports();
    topology
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CSV: &str = r#"hostname,ip_address,mac_address,device_type,port,vlan
SW-OT-1,192.168.1.10,00:1a:2b:3c:4d:5e,plc,Gi1/0/1,100
SW-OT-1,192.168.1.20,aa:bb:cc:dd:ee:ff,hmi,Gi1/0/2,100
SW-OT-1,192.168.1.30,,it_device,Gi1/0/3,200
SW-OT-2,10.0.0.1,00:50:79:66:68:00,rtu,1,100
"#;

    #[test]
    fn test_parse_devices_csv() {
        let devices = parse_devices_csv(SAMPLE_CSV).unwrap();
        assert_eq!(devices.len(), 4);

        let first = &devices[0];
        assert_eq!(first.hostname.as_deref(), Some("SW-OT-1"));
        assert_eq!(first.ip_address.as_deref(), Some("192.168.1.10"));
        assert_eq!(first.mac_address.as_deref(), Some("00:1a:2b:3c:4d:5e"));
        assert_eq!(first.device_type.as_deref(), Some("plc"));
        assert_eq!(first.port.as_deref(), Some("Gi1/0/1"));
        assert_eq!(first.vlan, Some(100));

        // Third record has no MAC
        assert!(devices[2].mac_address.is_none());
    }

    const SAMPLE_JSON: &str = r#"[
  {"hostname": "SW-OT-1", "ip_address": "192.168.1.10", "mac_address": "00:1a:2b:3c:4d:5e", "device_type": "plc", "port": "Gi1/0/1", "vlan": 100},
  {"hostname": "SW-OT-1", "ip_address": "192.168.1.20", "mac_address": "aa:bb:cc:dd:ee:ff", "port": "Gi1/0/2"},
  {"hostname": "SW-OT-2", "ip_address": "10.0.0.1", "port": "1", "vlan": 100}
]"#;

    #[test]
    fn test_parse_devices_json() {
        let devices = parse_devices_json(SAMPLE_JSON).unwrap();
        assert_eq!(devices.len(), 3);

        let first = &devices[0];
        assert_eq!(first.hostname.as_deref(), Some("SW-OT-1"));
        assert_eq!(first.vlan, Some(100));

        let second = &devices[1];
        assert!(second.vlan.is_none());
        assert!(second.device_type.is_none());
    }

    #[test]
    fn test_csv_to_switch() {
        let devices = parse_devices_csv(SAMPLE_CSV).unwrap();
        let topo = csv_to_switch(&devices);

        // Should create 2 switches: SW-OT-1 and SW-OT-2
        assert_eq!(topo.switches.len(), 2);

        let sw1 = topo.switches.iter().find(|s| s.hostname == "SW-OT-1").unwrap();
        assert_eq!(sw1.ports.len(), 3);

        let gi1 = sw1.ports.iter().find(|p| p.name == "Gi1/0/1").unwrap();
        assert!(gi1.ip_addresses.contains(&"192.168.1.10".to_string()));
    }

    #[test]
    fn test_csv_invalid_json_fails() {
        let result = parse_devices_json("not valid json");
        assert!(result.is_err());
    }
}
