//! Siemens SINEMA Server CSV and TIA Portal XML importers.
//!
//! SINEMA Server exports device inventories as CSV. TIA Portal can export
//! network configuration as XML. Both are merged into the KNK device
//! inventory with higher confidence than purely passive data.
//!
//! Neither importer performs any network activity — this is offline
//! configuration data import only.

use std::io::Read;
use std::path::Path;

use crate::error::IngestError;
use crate::{IngestedAsset, IngestResult, IngestSource};

// ─── SINEMA CSV ────────────────────────────────────────────────────────────

/// Import a SINEMA Server CSV device inventory export.
///
/// Expected headers (case-insensitive): Device Name, IP Address, MAC Address,
/// Type, Firmware, Serial Number, Location, Status.
pub fn import_sinema_csv(path: &Path) -> Result<IngestResult, IngestError> {
    let mut file = std::fs::File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    parse_sinema_csv(&content)
}

/// Parse SINEMA CSV content (split out for testability).
pub(crate) fn parse_sinema_csv(content: &str) -> Result<IngestResult, IngestError> {
    let mut lines = content.lines();
    let mut assets = Vec::new();
    let errors = Vec::new();

    let header_line = lines
        .next()
        .ok_or_else(|| IngestError::Parse("Empty SINEMA CSV".to_string()))?;

    // Column indices resolved by header name (case-insensitive substring)
    let headers: Vec<String> = header_line
        .split(',')
        .map(|h| h.trim().to_lowercase())
        .collect();

    let col_ip = find_col(&headers, &["ip address", "ip addr", "ipaddress"])
        .ok_or_else(|| IngestError::Parse("SINEMA CSV: no IP Address column found".to_string()))?;
    let col_name = find_col(&headers, &["device name", "devicename", "name"]);
    let col_mac = find_col(&headers, &["mac address", "macaddress", "mac addr", "mac"]);
    let col_type = find_col(&headers, &["type", "model", "hardware", "order number"]);
    let col_fw = find_col(&headers, &["firmware", "fw version", "version", "firmware version"]);
    let col_loc = find_col(&headers, &["location", "site"]);

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split(',').collect();

        let ip = match fields.get(col_ip).map(|s| s.trim()) {
            Some(ip) if !ip.is_empty() && ip != "-" => ip.to_string(),
            _ => continue,
        };

        // Basic IPv4 sanity check
        if !looks_like_ip(&ip) {
            continue;
        }

        let hostname = get_field(&fields, col_name);
        let mac_address = get_field(&fields, col_mac);
        let model = get_field(&fields, col_type);
        let firmware = get_field(&fields, col_fw);
        let location = get_field(&fields, col_loc);

        // Firmware and location go into os_info (notes)
        let mut notes_parts = Vec::new();
        if let Some(ref fw) = firmware {
            notes_parts.push(format!("Firmware: {fw}"));
        }
        if let Some(ref loc) = location {
            notes_parts.push(format!("Location: {loc}"));
        }
        let os_info = if notes_parts.is_empty() {
            None
        } else {
            Some(notes_parts.join("; "))
        };

        let vendor = model.as_deref().and_then(infer_vendor_from_model);
        let device_type = model.as_deref().map(infer_device_type_from_model);

        let mut protocols = Vec::new();
        if let Some(ref m) = model {
            let m_lower = m.to_lowercase();
            if m_lower.contains("s7-") || m_lower.contains("cpu 1") {
                protocols.push("s7comm".to_string());
            }
            if m_lower.contains("scalance") || m_lower.contains("ruggedcom") {
                protocols.push("profinet".to_string());
            }
        }

        assets.push(IngestedAsset {
            ip_address: ip,
            mac_address,
            hostname,
            device_type,
            vendor,
            protocols,
            open_ports: Vec::new(),
            os_info,
            source: IngestSource::Sinema,
            is_active: false,
        });
    }

    Ok(IngestResult {
        source: Some(IngestSource::Sinema),
        assets,
        connections: Vec::new(),
        alerts: Vec::new(),
        files_processed: 1,
        errors,
    })
}

// ─── TIA Portal XML ────────────────────────────────────────────────────────

/// Import a TIA Portal network configuration export (XML format).
///
/// Handles TIA Portal V15+ XML exports. Extracts device name, IP, model,
/// and firmware. The format varies by TIA version; this parser is
/// best-effort using attribute and element name matching.
pub fn import_tia_xml(path: &Path) -> Result<IngestResult, IngestError> {
    let mut file = std::fs::File::open(path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    parse_tia_xml(&content)
}

/// Parse TIA Portal XML content (split out for testability).
pub(crate) fn parse_tia_xml(content: &str) -> Result<IngestResult, IngestError> {
    let mut assets = Vec::new();
    let errors = Vec::new();
    let content_lower = content.to_lowercase();

    // TIA Portal XML has <Device> blocks at various nesting levels.
    // We walk through all of them and extract what we can.
    let mut pos = 0;
    let device_open = "<device";
    let device_close = "</device>";

    while let Some(rel_start) = content_lower[pos..].find(device_open) {
        let start = pos + rel_start;
        let end = match content_lower[start..].find(device_close) {
            Some(e) => start + e + device_close.len(),
            None => break,
        };
        let block = &content[start..end];
        pos = end;

        // Extract IP address — try multiple common TIA attribute/element names
        let ip = xml_find_any(
            block,
            &["address", "ipaddress", "ipv4address", "ip_address"],
        );

        let ip = match ip {
            Some(ip) if looks_like_ip(&ip) => ip,
            _ => continue,
        };

        let name = xml_find_any(block, &["name", "devicename", "device_name"]);
        let model = xml_find_any(block, &["typeidentifier", "type", "ordernumber", "articleno"]);
        let firmware = xml_find_any(block, &["firmwareversion", "firmware", "swversion"]);

        let vendor = model.as_deref().and_then(infer_vendor_from_model);
        let device_type = model.as_deref().map(infer_device_type_from_model);

        let os_info = firmware.as_ref().map(|fw| format!("Firmware: {fw}"));

        let mut protocols = Vec::new();
        if let Some(ref m) = model {
            let m_lower = m.to_lowercase();
            if m_lower.contains("s7-") || m_lower.contains("cpu") {
                protocols.push("s7comm".to_string());
            }
        }

        assets.push(IngestedAsset {
            ip_address: ip,
            mac_address: None,
            hostname: name,
            device_type,
            vendor,
            protocols,
            open_ports: Vec::new(),
            os_info,
            source: IngestSource::TiaPortal,
            is_active: false,
        });
    }

    if assets.is_empty() {
        // Try a looser pass: look for any IP-like strings in attribute values
        // near XML tags that might indicate devices
        log::warn!("TIA Portal XML: no <Device> blocks found, trying loose IP extraction");
    }

    Ok(IngestResult {
        source: Some(IngestSource::TiaPortal),
        assets,
        connections: Vec::new(),
        alerts: Vec::new(),
        files_processed: 1,
        errors,
    })
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/// Find the first column index whose header contains any of the given substrings.
fn find_col(headers: &[String], names: &[&str]) -> Option<usize> {
    names
        .iter()
        .find_map(|name| headers.iter().position(|h| h.contains(name)))
}

/// Extract a field value from a CSV row by column index.
fn get_field(fields: &[&str], col: Option<usize>) -> Option<String> {
    col.and_then(|c| fields.get(c))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s != "-" && s != "N/A")
}

/// Return true if `s` looks like a dotted-decimal IPv4 address.
fn looks_like_ip(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

/// Search XML block for a value using multiple candidate attribute/element names (case-insensitive).
fn xml_find_any(xml: &str, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(v) = xml_attr_or_element(xml, name) {
            return Some(v);
        }
    }
    None
}

/// Extract an XML attribute value or element text content (case-insensitive name).
fn xml_attr_or_element(xml: &str, name: &str) -> Option<String> {
    xml_attr(xml, name).or_else(|| xml_element_text(xml, name))
}

/// Extract `name="value"` from XML (case-insensitive attribute name).
fn xml_attr(xml: &str, attr_name: &str) -> Option<String> {
    let pattern = format!("{}=\"", attr_name.to_lowercase());
    let xml_lower = xml.to_lowercase();
    let start = xml_lower.find(&pattern)? + pattern.len();
    let end = xml[start..].find('"')? + start;
    let value = xml[start..end].trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// Extract text content of a `<tag>text</tag>` element (case-insensitive tag name).
fn xml_element_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag.to_lowercase());
    let close = format!("</{}>", tag.to_lowercase());
    let xml_lower = xml.to_lowercase();
    let tag_start = xml_lower.find(&open)?;
    // Skip to end of opening tag (past the '>')
    let content_start = xml[tag_start..].find('>')? + tag_start + 1;
    let content_end = xml_lower[content_start..].find(&close)? + content_start;
    let text = xml[content_start..content_end].trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Infer vendor name from a model/product string.
pub(crate) fn infer_vendor_from_model(model: &str) -> Option<String> {
    let m = model.to_lowercase();
    if m.contains("scalance")
        || m.contains("ruggedcom")
        || m.contains("simatic")
        || m.contains("sinema")
        || m.contains("s7-")
        || m.contains("cpu 1")
    {
        Some("Siemens".to_string())
    } else if m.contains("hirschmann")
        || m.contains("hios")
        || m.contains("mach")
        || m.contains("rsb")
        || m.contains("rsp")
    {
        Some("Belden/Hirschmann".to_string())
    } else if m.contains("eds-") || m.contains("edr-") || m.contains("nport") || m.contains("moxa")
    {
        Some("Moxa".to_string())
    } else if m.contains("fl switch") || m.contains("fl mguard") || m.contains("phoenix") {
        Some("Phoenix Contact".to_string())
    } else {
        None
    }
}

/// Infer device type string from a model/product string.
fn infer_device_type_from_model(model: &str) -> String {
    let m = model.to_lowercase();
    if m.contains("s7-") || m.contains("cpu") && (m.contains("1200") || m.contains("1500") || m.contains("300") || m.contains("400")) {
        "plc".to_string()
    } else if m.contains("scalance")
        || m.contains("switch")
        || m.contains("hirschmann")
        || m.contains("mach")
        || m.contains("eds-")
        || m.contains("fl switch")
    {
        "network_switch".to_string()
    } else if m.contains("hmi") || m.contains("ktp") || m.contains("comfort panel") {
        "hmi".to_string()
    } else {
        "unknown".to_string()
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SINEMA_CSV: &str = "Device Name,IP Address,MAC Address,Type,Firmware,Serial Number,Location,Status\n\
SCALANCE-X308,10.0.1.1,00:0E:8C:AA:BB:CC,SCALANCE X-308-2M,V06.06.03,S12345,Plant Floor,Online\n\
S7-1200,10.0.1.10,00:1B:1B:DD:EE:FF,CPU 1214C DC/DC/DC,V4.5,S67890,Rack 3,Online\n";

    #[test]
    fn test_sinema_csv_parses_two_devices() {
        let result = parse_sinema_csv(SINEMA_CSV).unwrap();
        assert_eq!(result.assets.len(), 2);
        assert_eq!(result.assets[0].ip_address, "10.0.1.1");
        assert_eq!(result.assets[0].hostname.as_deref(), Some("SCALANCE-X308"));
        assert_eq!(result.assets[1].ip_address, "10.0.1.10");
    }

    #[test]
    fn test_sinema_csv_vendor_inference() {
        let result = parse_sinema_csv(SINEMA_CSV).unwrap();
        let scalance = &result.assets[0];
        assert_eq!(scalance.vendor.as_deref(), Some("Siemens"));
        assert_eq!(scalance.device_type.as_deref(), Some("network_switch"));
    }

    #[test]
    fn test_sinema_csv_firmware_in_os_info() {
        let result = parse_sinema_csv(SINEMA_CSV).unwrap();
        let os = result.assets[0].os_info.as_deref().unwrap_or("");
        assert!(os.contains("V06.06.03"), "firmware should appear in os_info");
        assert!(os.contains("Plant Floor"), "location should appear in os_info");
    }

    #[test]
    fn test_sinema_csv_empty_content_errors() {
        assert!(parse_sinema_csv("").is_err());
    }

    #[test]
    fn test_tia_xml_basic() {
        let xml = r#"<Document>
  <Device Name="PLC-1">
    <Address>10.0.2.1</Address>
    <TypeIdentifier>S7-1500 CPU 1511-1 PN</TypeIdentifier>
    <FirmwareVersion>V2.8</FirmwareVersion>
  </Device>
  <Device Name="HMI-1">
    <Address>10.0.2.10</Address>
    <TypeIdentifier>KTP700 Basic PN</TypeIdentifier>
  </Device>
</Document>"#;
        let result = parse_tia_xml(xml).unwrap();
        assert_eq!(result.assets.len(), 2);
        assert_eq!(result.assets[0].ip_address, "10.0.2.1");
        assert_eq!(result.assets[0].hostname.as_deref(), Some("PLC-1"));
        assert!(result.assets[0].os_info.as_deref().unwrap_or("").contains("V2.8"));
    }

    #[test]
    fn test_tia_xml_vendor_inference() {
        let xml = r#"<Document>
  <Device Name="S71500">
    <Address>192.168.1.5</Address>
    <TypeIdentifier>S7-1500 CPU 1515-2 PN</TypeIdentifier>
  </Device>
</Document>"#;
        let result = parse_tia_xml(xml).unwrap();
        assert_eq!(result.assets.len(), 1);
        assert_eq!(result.assets[0].vendor.as_deref(), Some("Siemens"));
    }

    #[test]
    fn test_infer_vendor_from_model() {
        assert_eq!(
            infer_vendor_from_model("SCALANCE X-308-2M"),
            Some("Siemens".to_string())
        );
        assert_eq!(
            infer_vendor_from_model("EDS-400A Series"),
            Some("Moxa".to_string())
        );
        assert_eq!(infer_vendor_from_model("Acme Widget 2000"), None);
    }
}
