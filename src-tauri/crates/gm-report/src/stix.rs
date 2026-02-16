//! STIX 2.1 bundle export.
//!
//! Generates STIX Cyber Observable Objects for discovered assets,
//! Relationship objects for connections, and Indicator objects for findings.
//! Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html

use serde::Serialize;

use crate::{ExportAsset, ExportConnection, ExportFinding, ReportError};

/// A STIX 2.1 Bundle containing all objects.
#[derive(Debug, Serialize)]
pub struct StixBundle {
    #[serde(rename = "type")]
    pub stix_type: String,
    pub id: String,
    pub objects: Vec<serde_json::Value>,
}

/// Generate a STIX 2.1 bundle from assets, connections, and findings.
pub fn generate_stix_bundle(
    assets: &[ExportAsset],
    connections: &[ExportConnection],
    findings: &[ExportFinding],
) -> Result<String, ReportError> {
    let mut objects: Vec<serde_json::Value> = Vec::new();

    // Identity object for the tool itself
    let tool_identity = serde_json::json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": format!("identity--kusanagi-kajiki-{}", deterministic_id("tool")),
        "created": chrono::Utc::now().to_rfc3339(),
        "modified": chrono::Utc::now().to_rfc3339(),
        "name": "Kusanagi Kajiki",
        "description": "ICS/SCADA passive network discovery tool",
        "identity_class": "system"
    });
    objects.push(tool_identity);

    // Observed Data / SCO (STIX Cyber Observables) for each asset
    for asset in assets {
        let ipv4_id = format!("ipv4-addr--{}", deterministic_id(&asset.ip_address));

        // IPv4 Address SCO
        let mut ipv4 = serde_json::json!({
            "type": "ipv4-addr",
            "spec_version": "2.1",
            "id": &ipv4_id,
            "value": &asset.ip_address
        });

        // Add custom properties if available
        if let Some(ref country) = asset.country {
            ipv4["x_country"] = serde_json::Value::String(country.clone());
        }
        objects.push(ipv4);

        // MAC Address SCO (if available)
        if let Some(ref mac) = asset.mac_address {
            let mac_id = format!("mac-addr--{}", deterministic_id(mac));
            let mac_obj = serde_json::json!({
                "type": "mac-addr",
                "spec_version": "2.1",
                "id": &mac_id,
                "value": mac
            });
            objects.push(mac_obj);

            // Relationship: IP resolves-to MAC
            let rel = serde_json::json!({
                "type": "relationship",
                "spec_version": "2.1",
                "id": format!("relationship--{}", deterministic_id(&format!("{}-resolves-{}", asset.ip_address, mac))),
                "created": chrono::Utc::now().to_rfc3339(),
                "modified": chrono::Utc::now().to_rfc3339(),
                "relationship_type": "resolves-to",
                "source_ref": &ipv4_id,
                "target_ref": &mac_id
            });
            objects.push(rel);
        }

        // Infrastructure SDO for each asset with type/vendor info
        let infra_id = format!("infrastructure--{}", deterministic_id(&asset.ip_address));
        let mut infra = serde_json::json!({
            "type": "infrastructure",
            "spec_version": "2.1",
            "id": &infra_id,
            "created": chrono::Utc::now().to_rfc3339(),
            "modified": chrono::Utc::now().to_rfc3339(),
            "name": asset.hostname.as_deref().unwrap_or(&asset.ip_address),
            "infrastructure_types": [map_device_type(&asset.device_type)],
            "first_seen": &asset.first_seen,
            "last_seen": &asset.last_seen
        });

        if let Some(ref vendor) = asset.vendor {
            infra["x_vendor"] = serde_json::Value::String(vendor.clone());
        }
        if let Some(ref product) = asset.product_family {
            infra["x_product"] = serde_json::Value::String(product.clone());
        }
        if let Some(level) = asset.purdue_level {
            infra["x_purdue_level"] = serde_json::Value::Number(level.into());
        }
        if !asset.protocols.is_empty() {
            infra["x_protocols"] = serde_json::json!(asset.protocols);
        }

        objects.push(infra);

        // Relationship: infrastructure consists-of IP
        let rel = serde_json::json!({
            "type": "relationship",
            "spec_version": "2.1",
            "id": format!("relationship--{}", deterministic_id(&format!("{}-consists-of-{}", infra_id, ipv4_id))),
            "created": chrono::Utc::now().to_rfc3339(),
            "modified": chrono::Utc::now().to_rfc3339(),
            "relationship_type": "consists-of",
            "source_ref": &infra_id,
            "target_ref": &ipv4_id
        });
        objects.push(rel);
    }

    // Network Traffic SCOs for connections
    for conn in connections {
        let src_ref = format!("ipv4-addr--{}", deterministic_id(&conn.src_ip));
        let dst_ref = format!("ipv4-addr--{}", deterministic_id(&conn.dst_ip));
        let traffic_id = format!(
            "network-traffic--{}",
            deterministic_id(&format!("{}:{}-{}:{}", conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port))
        );

        let traffic = serde_json::json!({
            "type": "network-traffic",
            "spec_version": "2.1",
            "id": &traffic_id,
            "src_ref": &src_ref,
            "dst_ref": &dst_ref,
            "src_port": conn.src_port,
            "dst_port": conn.dst_port,
            "protocols": [&conn.transport, &conn.protocol],
            "start": &conn.first_seen,
            "end": &conn.last_seen,
            "x_packet_count": conn.packet_count,
            "x_byte_count": conn.byte_count
        });
        objects.push(traffic);
    }

    // Indicator SDOs for findings
    for (i, finding) in findings.iter().enumerate() {
        let indicator_id = format!(
            "indicator--{}",
            deterministic_id(&format!("finding-{}-{}", i, finding.title))
        );

        let indicator = serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": &indicator_id,
            "created": chrono::Utc::now().to_rfc3339(),
            "modified": chrono::Utc::now().to_rfc3339(),
            "name": &finding.title,
            "description": &finding.description,
            "indicator_types": ["anomalous-activity"],
            "pattern": format!("[x-finding:severity = '{}']", finding.severity),
            "pattern_type": "stix",
            "valid_from": chrono::Utc::now().to_rfc3339(),
            "x_severity": &finding.severity,
            "x_affected_assets": &finding.affected_assets,
            "x_recommendation": &finding.recommendation
        });
        objects.push(indicator);
    }

    let bundle = StixBundle {
        stix_type: "bundle".to_string(),
        id: format!("bundle--{}", deterministic_id(&format!("kusanagi-{}", chrono::Utc::now().timestamp()))),
        objects,
    };

    Ok(serde_json::to_string_pretty(&bundle)?)
}

/// Map internal device types to STIX infrastructure types.
fn map_device_type(device_type: &str) -> &str {
    match device_type {
        "plc" | "rtu" => "control-system",
        "hmi" => "workstation",
        "historian" => "hosting-target-lists",
        "scada_server" => "command-and-control",
        "engineering_workstation" => "workstation",
        "it_device" => "unknown",
        _ => "unknown",
    }
}

/// Generate a deterministic ID from a string (simple hash, not cryptographic).
fn deterministic_id(input: &str) -> String {
    // Simple FNV-1a hash for deterministic IDs
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in input.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_assets() -> Vec<ExportAsset> {
        vec![ExportAsset {
            ip_address: "192.168.1.10".to_string(),
            mac_address: Some("00:11:22:33:44:55".to_string()),
            hostname: Some("plc-01".to_string()),
            device_type: "plc".to_string(),
            vendor: Some("Siemens".to_string()),
            product_family: Some("S7-300".to_string()),
            protocols: vec!["s7comm".to_string()],
            confidence: 4,
            purdue_level: Some(1),
            oui_vendor: None,
            country: None,
            is_public_ip: false,
            first_seen: "2025-01-01T00:00:00Z".to_string(),
            last_seen: "2025-01-02T00:00:00Z".to_string(),
            notes: String::new(),
            tags: vec![],
            packet_count: 100,
        }]
    }

    fn sample_connections() -> Vec<ExportConnection> {
        vec![ExportConnection {
            src_ip: "192.168.1.20".to_string(),
            src_port: 12345,
            dst_ip: "192.168.1.10".to_string(),
            dst_port: 102,
            protocol: "s7comm".to_string(),
            transport: "tcp".to_string(),
            packet_count: 50,
            byte_count: 2500,
            first_seen: "2025-01-01T00:00:00Z".to_string(),
            last_seen: "2025-01-02T00:00:00Z".to_string(),
        }]
    }

    #[test]
    fn test_generate_stix_bundle() {
        let json = generate_stix_bundle(&sample_assets(), &sample_connections(), &[]).unwrap();
        let bundle: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle["type"], "bundle");
        // Should have: identity, ipv4, mac, resolves-to, infrastructure, consists-of, network-traffic
        assert!(bundle["objects"].as_array().unwrap().len() >= 7);
    }

    #[test]
    fn test_deterministic_ids() {
        let id1 = deterministic_id("test");
        let id2 = deterministic_id("test");
        assert_eq!(id1, id2);

        let id3 = deterministic_id("different");
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_stix_with_findings() {
        let findings = vec![ExportFinding {
            severity: "high".to_string(),
            title: "Unencrypted Modbus".to_string(),
            description: "Modbus traffic is unencrypted".to_string(),
            affected_assets: vec!["192.168.1.10".to_string()],
            recommendation: "Segment network".to_string(),
        }];
        let json = generate_stix_bundle(&[], &[], &findings).unwrap();
        let bundle: serde_json::Value = serde_json::from_str(&json).unwrap();
        // identity + indicator
        assert!(bundle["objects"].as_array().unwrap().len() >= 2);
    }
}
