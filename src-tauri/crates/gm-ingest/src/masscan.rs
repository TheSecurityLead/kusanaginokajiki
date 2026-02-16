//! Masscan JSON output parser.
//!
//! Masscan outputs results in JSON list format (with `-oJ`).
//! Each entry contains: ip, ports (with port, proto, status, service info).
//!
//! **IMPORTANT:** This tool NEVER runs Masscan scans.
//! It only imports results from scans performed externally.
//! All imported data is tagged as `IngestSource::Masscan` (active scan).

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::{
    IngestError, IngestResult, IngestSource,
    IngestedAsset, PortService,
};

/// Parse a Masscan JSON output file (-oJ format).
pub fn parse_masscan_json(path: &Path) -> Result<IngestResult, IngestError> {
    let content = std::fs::read_to_string(path)?;

    // Masscan JSON is an array of objects, but may have trailing comma issues.
    // Clean up: remove trailing commas before ] and handle incomplete arrays.
    let cleaned = clean_masscan_json(&content);

    let entries: Vec<MasscanEntry> = serde_json::from_str(&cleaned)
        .map_err(|e| IngestError::InvalidFormat(format!("Masscan JSON parse error: {}", e)))?;

    let mut result = IngestResult {
        source: Some(IngestSource::Masscan),
        ..Default::default()
    };

    // Group by IP to build assets
    let mut ip_ports: HashMap<String, Vec<PortService>> = HashMap::new();
    let mut ip_protocols: HashMap<String, Vec<String>> = HashMap::new();

    for entry in &entries {
        let ip = &entry.ip;

        for port_info in &entry.ports {
            let port_num = port_info.port;
            let proto_name = port_to_protocol(port_num, port_info.service.as_ref());

            ip_ports.entry(ip.clone()).or_default().push(PortService {
                port: port_num,
                protocol: port_info.proto.clone().unwrap_or_else(|| "tcp".to_string()),
                service_name: port_info.service.as_ref().map(|s| s.name.clone()),
                service_version: port_info.service.as_ref().and_then(|s| s.version.clone()),
                product: port_info.service.as_ref().and_then(|s| s.product.clone()),
            });

            let protocols = ip_protocols.entry(ip.clone()).or_default();
            if !protocols.contains(&proto_name) {
                protocols.push(proto_name);
            }
        }
    }

    for (ip, ports) in ip_ports {
        let protocols = ip_protocols.remove(&ip).unwrap_or_default();
        result.assets.push(IngestedAsset {
            ip_address: ip,
            mac_address: None,
            hostname: None,
            device_type: None,
            vendor: None,
            protocols,
            open_ports: ports,
            os_info: None,
            source: IngestSource::Masscan,
            is_active: true,
        });
    }

    result.files_processed = 1;
    Ok(result)
}

/// Clean up Masscan JSON quirks (trailing commas, missing brackets).
fn clean_masscan_json(content: &str) -> String {
    let trimmed = content.trim();

    // Masscan sometimes outputs: [ {...}, {...}, ] with trailing comma
    // Also sometimes ends with ",\n" without closing bracket
    let mut s = trimmed.to_string();

    // Remove the "finished" sentinel line that Masscan appends
    // e.g.: { "finished": 1 }
    if let Some(last_brace) = s.rfind('{') {
        let tail = &s[last_brace..];
        if tail.contains("\"finished\"") {
            // Remove from the comma before this entry
            if let Some(comma_pos) = s[..last_brace].rfind(',') {
                s = format!("{}]", &s[..comma_pos]);
            }
        }
    }

    // Fix trailing comma before ]
    let s = s.replace(",\n]", "\n]").replace(",]", "]");

    // Ensure it starts with [ and ends with ]
    let s = s.trim().to_string();
    if !s.starts_with('[') {
        format!("[{}]", s)
    } else {
        s
    }
}

/// Map port to protocol name using service hint.
fn port_to_protocol(port: u16, service: Option<&MasscanService>) -> String {
    if let Some(svc) = service {
        match svc.name.as_str() {
            "modbus" => return "modbus".to_string(),
            "dnp3" | "dnp" => return "dnp3".to_string(),
            "enip" | "ethernetip" => return "ethernet_ip".to_string(),
            "s7comm" | "iso-tsap" => return "s7comm".to_string(),
            "http" | "http-proxy" => return "http".to_string(),
            "https" | "ssl" | "tls" => return "https".to_string(),
            "ssh" => return "ssh".to_string(),
            _ => {}
        }
    }

    use gm_parsers::identify_by_port;
    let proto = identify_by_port(0, port);
    proto.to_name().to_string()
}

// ── Masscan JSON schema ──────────────────────────────────────

#[derive(Debug, Deserialize)]
struct MasscanEntry {
    ip: String,
    #[serde(default)]
    ports: Vec<MasscanPort>,
}

#[derive(Debug, Deserialize)]
struct MasscanPort {
    port: u16,
    proto: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    status: Option<String>,
    service: Option<MasscanService>,
}

#[derive(Debug, Clone, Deserialize)]
struct MasscanService {
    name: String,
    #[serde(rename = "banner")]
    product: Option<String>,
    version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_file(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_parse_masscan_json() {
        let content = r#"[
{"ip": "192.168.1.100", "ports": [{"port": 502, "proto": "tcp", "status": "open"}, {"port": 80, "proto": "tcp", "status": "open"}]},
{"ip": "192.168.1.200", "ports": [{"port": 44818, "proto": "tcp", "status": "open"}]}
]"#;

        let f = write_temp_file(content);
        let result = parse_masscan_json(f.path()).unwrap();

        assert_eq!(result.assets.len(), 2);

        // Find the asset with modbus
        let plc = result.assets.iter().find(|a| a.ip_address == "192.168.1.100").unwrap();
        assert_eq!(plc.open_ports.len(), 2);
        assert!(plc.protocols.contains(&"modbus".to_string()));
        assert!(plc.is_active);

        let ab = result.assets.iter().find(|a| a.ip_address == "192.168.1.200").unwrap();
        assert!(ab.protocols.contains(&"ethernet_ip".to_string()));
    }

    #[test]
    fn test_parse_masscan_with_trailing_comma() {
        let content = r#"[
{"ip": "10.0.0.1", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]},
{ "finished": 1 }
]"#;

        let f = write_temp_file(content);
        let result = parse_masscan_json(f.path()).unwrap();
        assert_eq!(result.assets.len(), 1);
        assert_eq!(result.assets[0].ip_address, "10.0.0.1");
    }

    #[test]
    fn test_parse_masscan_with_service() {
        let content = r#"[
{"ip": "192.168.1.50", "ports": [{"port": 502, "proto": "tcp", "status": "open", "service": {"name": "modbus", "banner": "Schneider Electric"}}]}
]"#;

        let f = write_temp_file(content);
        let result = parse_masscan_json(f.path()).unwrap();
        assert_eq!(result.assets.len(), 1);
        assert!(result.assets[0].protocols.contains(&"modbus".to_string()));
        let port = &result.assets[0].open_ports[0];
        assert_eq!(port.product, Some("Schneider Electric".to_string()));
    }
}
