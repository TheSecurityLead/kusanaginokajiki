//! CSV export for assets and connections.
//!
//! Generates RFC 4180-compliant CSV files suitable for import into
//! spreadsheets, SIEM tools, or asset management systems.

use std::io::Write;

use crate::{ExportAsset, ExportConnection, ReportError};

/// Escape a CSV field: wrap in quotes if it contains comma, quote, or newline.
fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Generate CSV content for assets.
pub fn assets_to_csv(assets: &[ExportAsset]) -> Result<String, ReportError> {
    let mut buf = Vec::new();

    // Header
    writeln!(
        buf,
        "IP Address,MAC Address,Hostname,Device Type,Vendor,Product Family,\
         Protocols,Confidence,Purdue Level,OUI Vendor,Country,Public IP,\
         First Seen,Last Seen,Packet Count,Tags,Notes"
    )?;

    for asset in assets {
        writeln!(
            buf,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&asset.ip_address),
            csv_escape(asset.mac_address.as_deref().unwrap_or("")),
            csv_escape(asset.hostname.as_deref().unwrap_or("")),
            csv_escape(&asset.device_type),
            csv_escape(asset.vendor.as_deref().unwrap_or("")),
            csv_escape(asset.product_family.as_deref().unwrap_or("")),
            csv_escape(&asset.protocols.join("; ")),
            asset.confidence,
            asset.purdue_level.map_or(String::new(), |l| l.to_string()),
            csv_escape(asset.oui_vendor.as_deref().unwrap_or("")),
            csv_escape(asset.country.as_deref().unwrap_or("")),
            asset.is_public_ip,
            csv_escape(&asset.first_seen),
            csv_escape(&asset.last_seen),
            asset.packet_count,
            csv_escape(&asset.tags.join("; ")),
            csv_escape(&asset.notes),
        )?;
    }

    String::from_utf8(buf).map_err(|e| ReportError::Pdf(e.to_string()))
}

/// Generate CSV content for connections.
pub fn connections_to_csv(connections: &[ExportConnection]) -> Result<String, ReportError> {
    let mut buf = Vec::new();

    // Header
    writeln!(
        buf,
        "Source IP,Source Port,Destination IP,Destination Port,Protocol,\
         Transport,Packet Count,Byte Count,First Seen,Last Seen"
    )?;

    for conn in connections {
        writeln!(
            buf,
            "{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&conn.src_ip),
            conn.src_port,
            csv_escape(&conn.dst_ip),
            conn.dst_port,
            csv_escape(&conn.protocol),
            csv_escape(&conn.transport),
            conn.packet_count,
            conn.byte_count,
            csv_escape(&conn.first_seen),
            csv_escape(&conn.last_seen),
        )?;
    }

    String::from_utf8(buf).map_err(|e| ReportError::Pdf(e.to_string()))
}

/// Write CSV string to a file path.
pub fn write_csv_file(path: &str, content: &str) -> Result<(), ReportError> {
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_asset() -> ExportAsset {
        ExportAsset {
            ip_address: "192.168.1.10".to_string(),
            mac_address: Some("00:11:22:33:44:55".to_string()),
            hostname: Some("plc-01".to_string()),
            device_type: "plc".to_string(),
            vendor: Some("Siemens".to_string()),
            product_family: Some("S7-300".to_string()),
            protocols: vec!["s7comm".to_string(), "modbus".to_string()],
            confidence: 4,
            purdue_level: Some(1),
            oui_vendor: Some("Siemens AG".to_string()),
            country: None,
            is_public_ip: false,
            first_seen: "2025-01-01T00:00:00Z".to_string(),
            last_seen: "2025-01-02T00:00:00Z".to_string(),
            notes: "Main PLC".to_string(),
            tags: vec!["critical".to_string()],
            packet_count: 1500,
        }
    }

    fn sample_connection() -> ExportConnection {
        ExportConnection {
            src_ip: "192.168.1.10".to_string(),
            src_port: 502,
            dst_ip: "192.168.1.20".to_string(),
            dst_port: 502,
            protocol: "modbus".to_string(),
            transport: "tcp".to_string(),
            packet_count: 100,
            byte_count: 5000,
            first_seen: "2025-01-01T00:00:00Z".to_string(),
            last_seen: "2025-01-02T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_assets_to_csv() {
        let csv = assets_to_csv(&[sample_asset()]).unwrap();
        assert!(csv.starts_with("IP Address,"));
        assert!(csv.contains("192.168.1.10"));
        assert!(csv.contains("Siemens"));
        assert!(csv.contains("s7comm; modbus"));
    }

    #[test]
    fn test_connections_to_csv() {
        let csv = connections_to_csv(&[sample_connection()]).unwrap();
        assert!(csv.starts_with("Source IP,"));
        assert!(csv.contains("192.168.1.10"));
        assert!(csv.contains("modbus"));
    }

    #[test]
    fn test_csv_escape_special_chars() {
        assert_eq!(csv_escape("hello"), "hello");
        assert_eq!(csv_escape("hello,world"), "\"hello,world\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[test]
    fn test_empty_assets_csv() {
        let csv = assets_to_csv(&[]).unwrap();
        // Should have header only
        let lines: Vec<&str> = csv.trim().lines().collect();
        assert_eq!(lines.len(), 1);
    }
}
