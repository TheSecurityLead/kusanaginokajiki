//! gm-report: PDF report generation, CSV/JSON/SBOM/STIX export
//! for Kusanagi Kajiki ICS/SCADA network assessment tool.

pub mod error;
pub mod pdf;
pub mod csv_export;
pub mod json_export;
pub mod sbom;
pub mod stix;

pub use error::ReportError;

use serde::{Serialize, Deserialize};

/// Configuration for PDF report generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    /// Assessor / analyst name
    pub assessor_name: String,
    /// Client / organization name
    pub client_name: String,
    /// Assessment date (ISO 8601)
    pub assessment_date: String,
    /// Report title override (default: "ICS/SCADA Network Assessment Report")
    pub title: Option<String>,
    /// Whether to include the executive summary section
    pub include_executive_summary: bool,
    /// Whether to include the asset inventory table
    pub include_asset_inventory: bool,
    /// Whether to include protocol analysis
    pub include_protocol_analysis: bool,
    /// Whether to include the findings section
    pub include_findings: bool,
    /// Whether to include the recommendations section
    pub include_recommendations: bool,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            assessor_name: String::new(),
            client_name: String::new(),
            assessment_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            title: None,
            include_executive_summary: true,
            include_asset_inventory: true,
            include_protocol_analysis: true,
            include_findings: true,
            include_recommendations: true,
        }
    }
}

/// Asset data for export (decoupled from main crate's AssetInfo).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportAsset {
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub device_type: String,
    pub vendor: Option<String>,
    pub product_family: Option<String>,
    pub protocols: Vec<String>,
    pub confidence: u8,
    pub purdue_level: Option<u8>,
    pub oui_vendor: Option<String>,
    pub country: Option<String>,
    pub is_public_ip: bool,
    pub first_seen: String,
    pub last_seen: String,
    pub notes: String,
    pub tags: Vec<String>,
    pub packet_count: u64,
}

/// Connection data for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConnection {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub transport: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

/// Protocol statistics for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportProtocolStat {
    pub protocol: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub connection_count: u64,
    pub unique_devices: u64,
}

/// A finding from analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportFinding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub affected_assets: Vec<String>,
    pub recommendation: String,
}

/// Complete data bundle for report generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportData {
    pub assets: Vec<ExportAsset>,
    pub connections: Vec<ExportConnection>,
    pub protocol_stats: Vec<ExportProtocolStat>,
    pub findings: Vec<ExportFinding>,
    pub session_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_config_default() {
        let config = ReportConfig::default();
        assert!(config.include_executive_summary);
        assert!(config.include_asset_inventory);
        assert!(config.include_protocol_analysis);
        assert!(config.include_findings);
        assert!(config.include_recommendations);
        assert!(config.assessor_name.is_empty());
    }

    #[test]
    fn test_report_data_serialize() {
        let data = ReportData {
            assets: vec![],
            connections: vec![],
            protocol_stats: vec![],
            findings: vec![],
            session_name: Some("Test Session".to_string()),
        };
        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("Test Session"));
    }
}
