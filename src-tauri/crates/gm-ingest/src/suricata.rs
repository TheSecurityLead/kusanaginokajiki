//! Suricata eve.json parser.
//!
//! Suricata outputs line-delimited JSON events to `eve.json`.
//! Each line is a self-contained JSON object with `event_type` field:
//! - `"flow"` — connection/flow records
//! - `"alert"` — IDS signature matches
//! - `"dns"`, `"tls"`, `"http"` — protocol metadata
//!
//! We extract flows for connection data and alerts for findings.

use std::io::{BufRead, BufReader};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::{
    IngestError, IngestResult, IngestSource,
    IngestedAsset, IngestedConnection, IngestedAlert,
};

/// Parse a Suricata eve.json file.
pub fn parse_eve_json(path: &Path) -> Result<IngestResult, IngestError> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    let mut result = IngestResult {
        source: Some(IngestSource::Suricata),
        ..Default::default()
    };

    let mut line_count: usize = 0;

    for line in reader.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        line_count += 1;

        // Try to parse as an Eve event
        match serde_json::from_str::<EveEvent>(trimmed) {
            Ok(event) => {
                process_eve_event(&event, &mut result);
            }
            Err(e) => {
                // Log but don't fail on individual lines — eve.json can be huge
                if line_count <= 5 {
                    log::debug!("Skipping eve.json line {}: {}", line_count, e);
                }
            }
        }
    }

    // Deduplicate assets
    deduplicate_assets(&mut result.assets);
    result.files_processed = 1;

    Ok(result)
}

/// Process a single Eve event into our result.
fn process_eve_event(event: &EveEvent, result: &mut IngestResult) {
    let ts = event.timestamp.unwrap_or_else(Utc::now);

    match event.event_type.as_str() {
        "flow" => {
            if let Some(flow) = &event.flow {
                let protocol = determine_protocol(event);

                let conn = IngestedConnection {
                    src_ip: event.src_ip.clone(),
                    src_port: event.src_port.unwrap_or(0),
                    dst_ip: event.dest_ip.clone(),
                    dst_port: event.dest_port.unwrap_or(0),
                    protocol: protocol.clone(),
                    transport: event.proto.clone().unwrap_or_else(|| "tcp".to_string()).to_lowercase(),
                    packet_count: flow.pkts_toserver.unwrap_or(0) + flow.pkts_toclient.unwrap_or(0),
                    byte_count: flow.bytes_toserver.unwrap_or(0) + flow.bytes_toclient.unwrap_or(0),
                    first_seen: flow.start.or(Some(ts)),
                    last_seen: flow.end.or(Some(ts)),
                    source: IngestSource::Suricata,
                };

                // Create assets for endpoints
                add_asset_from_flow(&mut result.assets, &conn);
                result.connections.push(conn);
            }
        }
        "alert" => {
            if let Some(alert) = &event.alert {
                let ingested_alert = IngestedAlert {
                    timestamp: ts,
                    src_ip: event.src_ip.clone(),
                    src_port: event.src_port.unwrap_or(0),
                    dst_ip: event.dest_ip.clone(),
                    dst_port: event.dest_port.unwrap_or(0),
                    signature_id: alert.signature_id,
                    signature: alert.signature.clone(),
                    category: alert.category.clone().unwrap_or_default(),
                    severity: alert.severity.unwrap_or(3),
                    source: IngestSource::Suricata,
                };
                result.alerts.push(ingested_alert);
            }
        }
        _ => {
            // dns, tls, http, etc. — could extract metadata but for now skip
        }
    }
}

/// Determine protocol name from Eve event fields.
fn determine_protocol(event: &EveEvent) -> String {
    // Check app_proto field first
    if let Some(ref app_proto) = event.app_proto {
        return match app_proto.as_str() {
            "modbus" => "modbus".to_string(),
            "dnp3" => "dnp3".to_string(),
            "enip" | "cip" => "ethernet_ip".to_string(),
            "s7comm" => "s7comm".to_string(),
            "mqtt" => "mqtt".to_string(),
            "http" => "http".to_string(),
            "tls" | "ssl" => "https".to_string(),
            "dns" => "dns".to_string(),
            "ssh" => "ssh".to_string(),
            "snmp" => "snmp".to_string(),
            other => other.to_lowercase(),
        };
    }

    // Fall back to port-based detection
    let dst_port = event.dest_port.unwrap_or(0);
    use gm_parsers::identify_by_port;
    let proto = identify_by_port(0, dst_port);
    proto.to_name().to_string()
}

fn add_asset_from_flow(assets: &mut Vec<IngestedAsset>, conn: &IngestedConnection) {
    for ip in [&conn.src_ip, &conn.dst_ip] {
        assets.push(IngestedAsset {
            ip_address: ip.clone(),
            mac_address: None,
            hostname: None,
            device_type: None,
            vendor: None,
            protocols: vec![conn.protocol.clone()],
            open_ports: Vec::new(),
            os_info: None,
            source: IngestSource::Suricata,
            is_active: false,
        });
    }
}

/// Deduplicate assets by IP, merging protocols.
fn deduplicate_assets(assets: &mut Vec<IngestedAsset>) {
    use std::collections::HashMap;
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut deduped: Vec<IngestedAsset> = Vec::new();

    for asset in assets.drain(..) {
        if let Some(&idx) = seen.get(&asset.ip_address) {
            let existing = &mut deduped[idx];
            for proto in &asset.protocols {
                if !existing.protocols.contains(proto) {
                    existing.protocols.push(proto.clone());
                }
            }
        } else {
            seen.insert(asset.ip_address.clone(), deduped.len());
            deduped.push(asset);
        }
    }

    *assets = deduped;
}

// ── Suricata Eve JSON schema (subset) ────────────────────────

#[derive(Debug, Deserialize)]
struct EveEvent {
    #[serde(default)]
    timestamp: Option<DateTime<Utc>>,
    event_type: String,
    src_ip: String,
    src_port: Option<u16>,
    dest_ip: String,
    dest_port: Option<u16>,
    proto: Option<String>,
    app_proto: Option<String>,
    flow: Option<EveFlow>,
    alert: Option<EveAlert>,
}

#[derive(Debug, Deserialize)]
struct EveFlow {
    pkts_toserver: Option<u64>,
    pkts_toclient: Option<u64>,
    bytes_toserver: Option<u64>,
    bytes_toclient: Option<u64>,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct EveAlert {
    #[serde(default)]
    signature_id: u64,
    #[serde(default)]
    signature: String,
    category: Option<String>,
    severity: Option<u8>,
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
    fn test_parse_flow_event() {
        let content = r#"{"timestamp":"2021-01-01T00:00:00.000000+0000","event_type":"flow","src_ip":"192.168.1.10","src_port":49152,"dest_ip":"192.168.1.100","dest_port":502,"proto":"TCP","app_proto":"modbus","flow":{"pkts_toserver":100,"pkts_toclient":100,"bytes_toserver":5000,"bytes_toclient":3000,"start":"2021-01-01T00:00:00.000000+0000","end":"2021-01-01T00:01:00.000000+0000"}}"#;

        let f = write_temp_file(content);
        let result = parse_eve_json(f.path()).unwrap();

        assert_eq!(result.connections.len(), 1);
        let conn = &result.connections[0];
        assert_eq!(conn.protocol, "modbus");
        assert_eq!(conn.src_ip, "192.168.1.10");
        assert_eq!(conn.dst_port, 502);
        assert_eq!(conn.packet_count, 200);
    }

    #[test]
    fn test_parse_alert_event() {
        let content = r#"{"timestamp":"2021-01-01T00:00:00.000000+0000","event_type":"alert","src_ip":"10.0.0.5","src_port":55000,"dest_ip":"10.0.0.100","dest_port":502,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2024001,"rev":1,"signature":"ET SCADA Modbus Write Single Coil","category":"Attempted Information Leak","severity":2}}"#;

        let f = write_temp_file(content);
        let result = parse_eve_json(f.path()).unwrap();

        assert_eq!(result.alerts.len(), 1);
        let alert = &result.alerts[0];
        assert_eq!(alert.signature_id, 2024001);
        assert!(alert.signature.contains("Modbus"));
        assert_eq!(alert.severity, 2);
    }

    #[test]
    fn test_parse_multiple_events() {
        let content = r#"{"timestamp":"2021-01-01T00:00:00.000000+0000","event_type":"flow","src_ip":"192.168.1.10","src_port":49152,"dest_ip":"192.168.1.100","dest_port":502,"proto":"TCP","app_proto":"modbus","flow":{"pkts_toserver":50,"pkts_toclient":50,"bytes_toserver":2500,"bytes_toclient":1500}}
{"timestamp":"2021-01-01T00:00:01.000000+0000","event_type":"flow","src_ip":"192.168.1.20","src_port":50000,"dest_ip":"192.168.1.100","dest_port":20000,"proto":"TCP","app_proto":"dnp3","flow":{"pkts_toserver":30,"pkts_toclient":30,"bytes_toserver":1200,"bytes_toclient":900}}"#;

        let f = write_temp_file(content);
        let result = parse_eve_json(f.path()).unwrap();

        assert_eq!(result.connections.len(), 2);
        // 3 unique IPs → 3 assets after dedup
        assert_eq!(result.assets.len(), 3);
    }
}
