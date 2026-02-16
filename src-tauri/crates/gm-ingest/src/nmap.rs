//! Nmap XML output parser.
//!
//! Parses standard Nmap `-oX` output format.
//! Extracts: hosts, open ports, services, OS detection.
//!
//! **IMPORTANT:** This tool NEVER runs Nmap scans.
//! It only imports results from scans performed externally.
//! All imported data is tagged as `IngestSource::Nmap` (active scan).

use std::path::Path;

use serde::Deserialize;

use crate::{
    IngestError, IngestResult, IngestSource,
    IngestedAsset, PortService,
};

/// Parse an Nmap XML file (-oX output).
pub fn parse_nmap_xml(path: &Path) -> Result<IngestResult, IngestError> {
    let content = std::fs::read_to_string(path)?;
    let nmaprun: NmapRun = quick_xml::de::from_str(&content)?;

    let mut result = IngestResult {
        source: Some(IngestSource::Nmap),
        ..Default::default()
    };

    for host in &nmaprun.hosts {
        if let Some(asset) = parse_host(host) {
            result.assets.push(asset);
        }
    }

    result.files_processed = 1;
    Ok(result)
}

/// Convert an Nmap host element to an IngestedAsset.
fn parse_host(host: &NmapHost) -> Option<IngestedAsset> {
    // Get the IP address from <address> elements
    let ip = host.addresses.iter()
        .find(|a| a.addrtype == "ipv4" || a.addrtype == "ipv6")
        .map(|a| a.addr.clone())?;

    let mac = host.addresses.iter()
        .find(|a| a.addrtype == "mac")
        .map(|a| a.addr.clone());

    let mac_vendor = host.addresses.iter()
        .find(|a| a.addrtype == "mac")
        .and_then(|a| a.vendor.clone());

    // Get hostname from <hostnames>
    let hostname = host.hostnames.as_ref()
        .and_then(|hn| hn.hostnames.first())
        .map(|h| h.name.clone());

    // Get open ports and services
    let mut open_ports = Vec::new();
    let mut protocols = Vec::new();

    if let Some(ref ports) = host.ports {
        for port in &ports.ports {
            // Only include open ports
            if let Some(ref state) = port.state {
                if state.state != "open" {
                    continue;
                }
            }

            let port_num: u16 = match port.portid.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let service_name = port.service.as_ref().map(|s| s.name.clone());
            let service_version = port.service.as_ref().and_then(|s| s.version.clone());
            let product = port.service.as_ref().and_then(|s| s.product.clone());

            // Map port to protocol name
            let proto = port_to_protocol(port_num, service_name.as_deref());
            if !protocols.contains(&proto) {
                protocols.push(proto.clone());
            }

            open_ports.push(PortService {
                port: port_num,
                protocol: port.protocol.clone(),
                service_name,
                service_version,
                product,
            });
        }
    }

    // Get OS detection
    let os_info = host.os.as_ref()
        .and_then(|os| os.osmatches.first())
        .map(|m| {
            if let Some(ref accuracy) = m.accuracy {
                format!("{} ({}%)", m.name, accuracy)
            } else {
                m.name.clone()
            }
        });

    Some(IngestedAsset {
        ip_address: ip,
        mac_address: mac,
        hostname,
        device_type: None,
        vendor: mac_vendor,
        protocols,
        open_ports,
        os_info,
        source: IngestSource::Nmap,
        is_active: true,
    })
}

/// Map a port number to our protocol name, using service hint if available.
fn port_to_protocol(port: u16, service_name: Option<&str>) -> String {
    // Check service name first
    if let Some(svc) = service_name {
        match svc {
            "modbus" => return "modbus".to_string(),
            "dnp3" | "dnp" => return "dnp3".to_string(),
            "enip" | "ethernetip" | "cip" => return "ethernet_ip".to_string(),
            "bacnet" => return "bacnet".to_string(),
            "s7comm" | "iso-tsap" => return "s7comm".to_string(),
            "opc-ua-tcp" | "opcua" => return "opc_ua".to_string(),
            "mqtt" => return "mqtt".to_string(),
            "http" | "http-proxy" => return "http".to_string(),
            "https" | "ssl" | "tls" => return "https".to_string(),
            "dns" | "domain" => return "dns".to_string(),
            "ssh" => return "ssh".to_string(),
            "ms-wbt-server" | "rdp" => return "rdp".to_string(),
            "snmp" => return "snmp".to_string(),
            _ => {}
        }
    }

    // Fall back to port-based
    use gm_parsers::identify_by_port;
    let proto = identify_by_port(0, port);
    proto.to_name().to_string()
}

// ── Nmap XML schema (deserialization structs) ─────────────────

#[derive(Debug, Deserialize)]
#[serde(rename = "nmaprun")]
struct NmapRun {
    #[serde(rename = "host", default)]
    hosts: Vec<NmapHost>,
}

#[derive(Debug, Deserialize)]
struct NmapHost {
    #[serde(rename = "address", default)]
    addresses: Vec<NmapAddress>,
    #[serde(rename = "hostnames")]
    hostnames: Option<NmapHostnames>,
    #[serde(rename = "ports")]
    ports: Option<NmapPorts>,
    #[serde(rename = "os")]
    os: Option<NmapOs>,
}

#[derive(Debug, Deserialize)]
struct NmapAddress {
    #[serde(rename = "@addr")]
    addr: String,
    #[serde(rename = "@addrtype")]
    addrtype: String,
    #[serde(rename = "@vendor")]
    vendor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NmapHostnames {
    #[serde(rename = "hostname", default)]
    hostnames: Vec<NmapHostname>,
}

#[derive(Debug, Deserialize)]
struct NmapHostname {
    #[serde(rename = "@name")]
    name: String,
}

#[derive(Debug, Deserialize)]
struct NmapPorts {
    #[serde(rename = "port", default)]
    ports: Vec<NmapPort>,
}

#[derive(Debug, Deserialize)]
struct NmapPort {
    #[serde(rename = "@protocol")]
    protocol: String,
    #[serde(rename = "@portid")]
    portid: String,
    #[serde(rename = "state")]
    state: Option<NmapPortState>,
    #[serde(rename = "service")]
    service: Option<NmapService>,
}

#[derive(Debug, Deserialize)]
struct NmapPortState {
    #[serde(rename = "@state")]
    state: String,
}

#[derive(Debug, Deserialize)]
struct NmapService {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@product")]
    product: Option<String>,
    #[serde(rename = "@version")]
    version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NmapOs {
    #[serde(rename = "osmatch", default)]
    osmatches: Vec<NmapOsMatch>,
}

#[derive(Debug, Deserialize)]
struct NmapOsMatch {
    #[serde(rename = "@name")]
    name: String,
    #[serde(rename = "@accuracy")]
    accuracy: Option<String>,
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
    fn test_parse_nmap_xml() {
        let content = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX output.xml 192.168.1.0/24" start="1609459200">
  <host starttime="1609459200" endtime="1609459210">
    <address addr="192.168.1.100" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Siemens"/>
    <hostnames>
      <hostname name="plc-01.scada.local" type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="102">
        <state state="open" reason="syn-ack"/>
        <service name="iso-tsap" product="Siemens S7" version=""/>
      </port>
      <port protocol="tcp" portid="502">
        <state state="open" reason="syn-ack"/>
        <service name="modbus"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="lighttpd"/>
      </port>
    </ports>
    <os>
      <osmatch name="Siemens S7-300 PLC" accuracy="95"/>
    </os>
  </host>
  <host starttime="1609459200" endtime="1609459210">
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed" reason="reset"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;

        let f = write_temp_file(content);
        let result = parse_nmap_xml(f.path()).unwrap();

        assert_eq!(result.assets.len(), 2);

        let plc = &result.assets[0];
        assert_eq!(plc.ip_address, "192.168.1.100");
        assert_eq!(plc.mac_address, Some("AA:BB:CC:DD:EE:FF".to_string()));
        assert_eq!(plc.hostname, Some("plc-01.scada.local".to_string()));
        assert_eq!(plc.vendor, Some("Siemens".to_string()));
        assert_eq!(plc.os_info, Some("Siemens S7-300 PLC (95%)".to_string()));
        assert_eq!(plc.open_ports.len(), 3);
        assert!(plc.protocols.contains(&"s7comm".to_string()));
        assert!(plc.protocols.contains(&"modbus".to_string()));
        assert!(plc.is_active);

        let ws = &result.assets[1];
        assert_eq!(ws.ip_address, "192.168.1.10");
        // Port 443 is closed, so only SSH should be in open_ports
        assert_eq!(ws.open_ports.len(), 1);
        assert_eq!(ws.open_ports[0].port, 22);
    }
}
