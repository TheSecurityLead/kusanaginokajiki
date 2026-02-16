//! Software Bill of Materials (SBOM) export.
//!
//! Generates asset inventory in formats aligned with CISA BOD 23-01
//! requirements for federal agencies. Outputs CSV and JSON formats
//! with fields: IP, MAC, hostname, vendor, product, firmware,
//! protocols, Purdue zone.

use std::io::Write;

use serde::Serialize;

use crate::{ExportAsset, ReportError};

/// A single SBOM entry representing one networked asset.
#[derive(Debug, Clone, Serialize)]
pub struct SbomEntry {
    pub ip_address: String,
    pub mac_address: String,
    pub hostname: String,
    pub vendor: String,
    pub product: String,
    pub firmware_version: String,
    pub protocols: String,
    pub purdue_zone: String,
    pub device_type: String,
    pub confidence: u8,
    pub first_seen: String,
    pub last_seen: String,
    pub country: String,
    pub tags: String,
}

/// Convert an ExportAsset to an SBOM entry.
fn asset_to_sbom_entry(asset: &ExportAsset) -> SbomEntry {
    let purdue_zone = match asset.purdue_level {
        Some(0) => "L0 - Process".to_string(),
        Some(1) => "L1 - Basic Control".to_string(),
        Some(2) => "L2 - Area Supervisory".to_string(),
        Some(3) => "L3 - Site Operations".to_string(),
        Some(4) => "L4 - Enterprise".to_string(),
        Some(5) => "L5 - Enterprise".to_string(),
        _ => "Unassigned".to_string(),
    };

    SbomEntry {
        ip_address: asset.ip_address.clone(),
        mac_address: asset.mac_address.clone().unwrap_or_default(),
        hostname: asset.hostname.clone().unwrap_or_default(),
        vendor: asset.vendor.clone()
            .or_else(|| asset.oui_vendor.clone())
            .unwrap_or_default(),
        product: asset.product_family.clone().unwrap_or_default(),
        firmware_version: String::new(), // Not available from passive discovery
        protocols: asset.protocols.join("; "),
        purdue_zone,
        device_type: asset.device_type.clone(),
        confidence: asset.confidence,
        first_seen: asset.first_seen.clone(),
        last_seen: asset.last_seen.clone(),
        country: asset.country.clone().unwrap_or_default(),
        tags: asset.tags.join("; "),
    }
}

/// Generate SBOM entries from assets.
pub fn assets_to_sbom(assets: &[ExportAsset]) -> Vec<SbomEntry> {
    assets.iter().map(asset_to_sbom_entry).collect()
}

/// Generate SBOM as CSV string.
pub fn sbom_to_csv(entries: &[SbomEntry]) -> Result<String, ReportError> {
    let mut buf = Vec::new();

    writeln!(
        buf,
        "IP Address,MAC Address,Hostname,Vendor,Product,Firmware Version,\
         Protocols,Purdue Zone,Device Type,Confidence,First Seen,Last Seen,\
         Country,Tags"
    )?;

    for entry in entries {
        writeln!(
            buf,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            csv_escape(&entry.ip_address),
            csv_escape(&entry.mac_address),
            csv_escape(&entry.hostname),
            csv_escape(&entry.vendor),
            csv_escape(&entry.product),
            csv_escape(&entry.firmware_version),
            csv_escape(&entry.protocols),
            csv_escape(&entry.purdue_zone),
            csv_escape(&entry.device_type),
            entry.confidence,
            csv_escape(&entry.first_seen),
            csv_escape(&entry.last_seen),
            csv_escape(&entry.country),
            csv_escape(&entry.tags),
        )?;
    }

    String::from_utf8(buf).map_err(|e| ReportError::Pdf(e.to_string()))
}

/// Generate SBOM as pretty-printed JSON.
pub fn sbom_to_json(entries: &[SbomEntry]) -> Result<String, ReportError> {
    #[derive(Serialize)]
    struct SbomExport {
        format: String,
        version: String,
        tool: String,
        export_date: String,
        entry_count: usize,
        entries: Vec<SbomEntry>,
    }

    let export = SbomExport {
        format: "CISA BOD 23-01 Asset Inventory".to_string(),
        version: "1.0".to_string(),
        tool: "Kusanagi Kajiki".to_string(),
        export_date: chrono::Utc::now().to_rfc3339(),
        entry_count: entries.len(),
        entries: entries.to_vec(),
    };

    Ok(serde_json::to_string_pretty(&export)?)
}

fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_asset() -> ExportAsset {
        ExportAsset {
            ip_address: "10.0.1.50".to_string(),
            mac_address: Some("00:1A:2B:3C:4D:5E".to_string()),
            hostname: Some("rtu-field-01".to_string()),
            device_type: "rtu".to_string(),
            vendor: Some("ABB".to_string()),
            product_family: Some("RTU560".to_string()),
            protocols: vec!["dnp3".to_string(), "modbus".to_string()],
            confidence: 4,
            purdue_level: Some(1),
            oui_vendor: Some("ABB Ltd".to_string()),
            country: None,
            is_public_ip: false,
            first_seen: "2025-01-01T00:00:00Z".to_string(),
            last_seen: "2025-01-02T00:00:00Z".to_string(),
            notes: String::new(),
            tags: vec!["field".to_string()],
            packet_count: 500,
        }
    }

    #[test]
    fn test_assets_to_sbom() {
        let entries = assets_to_sbom(&[sample_asset()]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip_address, "10.0.1.50");
        assert_eq!(entries[0].vendor, "ABB");
        assert_eq!(entries[0].purdue_zone, "L1 - Basic Control");
    }

    #[test]
    fn test_sbom_to_csv() {
        let entries = assets_to_sbom(&[sample_asset()]);
        let csv = sbom_to_csv(&entries).unwrap();
        assert!(csv.starts_with("IP Address,"));
        assert!(csv.contains("10.0.1.50"));
        assert!(csv.contains("ABB"));
        assert!(csv.contains("L1 - Basic Control"));
    }

    #[test]
    fn test_sbom_to_json() {
        let entries = assets_to_sbom(&[sample_asset()]);
        let json = sbom_to_json(&entries).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["format"], "CISA BOD 23-01 Asset Inventory");
        assert_eq!(parsed["entry_count"], 1);
    }
}
