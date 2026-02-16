//! JSON export for topology, assets, and connections.
//!
//! Provides machine-readable export suitable for integration with
//! other tools, dashboards, or SIEM platforms.

use serde::Serialize;

use crate::{ExportAsset, ExportConnection, ExportProtocolStat, ReportError};

/// Full topology export as JSON.
#[derive(Debug, Serialize)]
pub struct TopologyExport {
    pub metadata: ExportMetadata,
    pub assets: Vec<ExportAsset>,
    pub connections: Vec<ExportConnection>,
    pub protocol_stats: Vec<ExportProtocolStat>,
}

/// Metadata included in JSON exports.
#[derive(Debug, Serialize)]
pub struct ExportMetadata {
    pub tool: String,
    pub version: String,
    pub export_date: String,
    pub session_name: Option<String>,
    pub asset_count: usize,
    pub connection_count: usize,
}

/// Generate the full topology as a pretty-printed JSON string.
pub fn topology_to_json(
    assets: &[ExportAsset],
    connections: &[ExportConnection],
    protocol_stats: &[ExportProtocolStat],
    session_name: Option<&str>,
) -> Result<String, ReportError> {
    let export = TopologyExport {
        metadata: ExportMetadata {
            tool: "Kusanagi Kajiki".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            export_date: chrono::Utc::now().to_rfc3339(),
            session_name: session_name.map(|s| s.to_string()),
            asset_count: assets.len(),
            connection_count: connections.len(),
        },
        assets: assets.to_vec(),
        connections: connections.to_vec(),
        protocol_stats: protocol_stats.to_vec(),
    };

    Ok(serde_json::to_string_pretty(&export)?)
}

/// Generate assets only as a pretty-printed JSON string.
pub fn assets_to_json(assets: &[ExportAsset]) -> Result<String, ReportError> {
    Ok(serde_json::to_string_pretty(assets)?)
}

/// Write JSON string to a file path.
pub fn write_json_file(path: &str, content: &str) -> Result<(), ReportError> {
    std::fs::write(path, content)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_topology_to_json() {
        let json = topology_to_json(&[], &[], &[], Some("Test")).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["metadata"]["tool"], "Kusanagi Kajiki");
        assert_eq!(parsed["metadata"]["session_name"], "Test");
        assert_eq!(parsed["metadata"]["asset_count"], 0);
    }

    #[test]
    fn test_assets_to_json() {
        let assets = vec![ExportAsset {
            ip_address: "10.0.0.1".to_string(),
            mac_address: None,
            hostname: None,
            device_type: "plc".to_string(),
            vendor: None,
            product_family: None,
            protocols: vec!["modbus".to_string()],
            confidence: 3,
            purdue_level: Some(1),
            oui_vendor: None,
            country: None,
            is_public_ip: false,
            first_seen: "2025-01-01T00:00:00Z".to_string(),
            last_seen: "2025-01-01T01:00:00Z".to_string(),
            notes: String::new(),
            tags: vec![],
            packet_count: 42,
        }];
        let json = assets_to_json(&assets).unwrap();
        assert!(json.contains("10.0.0.1"));
        assert!(json.contains("modbus"));
    }
}
