//! Zeek (formerly Bro) TSV log parser.
//!
//! Zeek logs use a tab-separated format with `#fields` and `#types` header lines.
//! This parser handles:
//! - `conn.log` — connection records (flows)
//! - `modbus.log` — Modbus-specific fields
//! - `dnp3.log` — DNP3-specific fields
//! - `s7comm.log` — Siemens S7comm fields
//!
//! Fields are accessed by name (position from `#fields` header),
//! so we handle schema variations across Zeek versions.

use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

use chrono::{DateTime, Utc};

use crate::{
    IngestError, IngestResult, IngestSource,
    IngestedAsset, IngestedConnection,
};

/// Parse one or more Zeek log files.
///
/// Accepts paths to individual log files (conn.log, modbus.log, etc.).
/// Detects the log type from the `#path` header line.
pub fn parse_zeek_logs(paths: &[&Path]) -> Result<IngestResult, IngestError> {
    let mut result = IngestResult {
        source: Some(IngestSource::Zeek),
        ..Default::default()
    };

    for path in paths {
        match parse_single_log(path) {
            Ok(partial) => {
                result.connections.extend(partial.connections);
                result.assets.extend(partial.assets);
                result.files_processed += 1;
            }
            Err(e) => {
                let filename = path.file_name()
                    .map(|f| f.to_string_lossy().to_string())
                    .unwrap_or_else(|| path.display().to_string());
                result.errors.push(format!("{}: {}", filename, e));
            }
        }
    }

    // Deduplicate assets by IP
    deduplicate_assets(&mut result.assets);

    Ok(result)
}

/// Parse a single Zeek log file.
fn parse_single_log(path: &Path) -> Result<IngestResult, IngestError> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    let mut fields: Vec<String> = Vec::new();
    let mut log_path = String::new();
    let mut result = IngestResult {
        source: Some(IngestSource::Zeek),
        ..Default::default()
    };

    for line in reader.lines() {
        let line = line?;

        // Header lines start with #
        if line.starts_with('#') {
            if let Some(rest) = line.strip_prefix("#fields\t") {
                fields = rest.split('\t').map(|s| s.to_string()).collect();
            } else if let Some(rest) = line.strip_prefix("#path\t") {
                log_path = rest.trim().to_string();
            }
            continue;
        }

        // Skip empty lines
        if line.is_empty() {
            continue;
        }

        // We need fields to parse data
        if fields.is_empty() {
            continue;
        }

        // Parse the tab-separated values
        let values: Vec<&str> = line.split('\t').collect();
        let record = build_record(&fields, &values);

        match log_path.as_str() {
            "conn" => {
                if let Some(conn) = parse_conn_record(&record) {
                    // Create assets for src and dst
                    add_asset_from_conn(&mut result.assets, &conn);
                    result.connections.push(conn);
                }
            }
            "modbus" => {
                if let Some(conn) = parse_modbus_record(&record) {
                    add_asset_from_conn(&mut result.assets, &conn);
                    result.connections.push(conn);
                }
            }
            "dnp3" => {
                if let Some(conn) = parse_dnp3_record(&record) {
                    add_asset_from_conn(&mut result.assets, &conn);
                    result.connections.push(conn);
                }
            }
            "s7comm" => {
                if let Some(conn) = parse_s7comm_record(&record) {
                    add_asset_from_conn(&mut result.assets, &conn);
                    result.connections.push(conn);
                }
            }
            _ => {
                // Generic connection log — try to parse as conn format
                if let Some(conn) = parse_conn_record(&record) {
                    add_asset_from_conn(&mut result.assets, &conn);
                    result.connections.push(conn);
                }
            }
        }
    }

    result.files_processed = 1;
    Ok(result)
}

/// Build a field name → value map from fields header and values.
fn build_record<'a>(fields: &[String], values: &[&'a str]) -> HashMap<String, &'a str> {
    let mut record = HashMap::new();
    for (i, field) in fields.iter().enumerate() {
        if let Some(&val) = values.get(i) {
            // Zeek uses "-" for empty/missing values
            if val != "-" && val != "(empty)" {
                record.insert(field.clone(), val);
            }
        }
    }
    record
}

/// Parse a Zeek timestamp (epoch seconds with microseconds).
fn parse_zeek_timestamp(ts_str: &str) -> Option<DateTime<Utc>> {
    let ts: f64 = ts_str.parse().ok()?;
    let secs = ts as i64;
    let nanos = ((ts - secs as f64) * 1_000_000_000.0) as u32;
    DateTime::from_timestamp(secs, nanos)
}

/// Parse a conn.log record.
fn parse_conn_record(record: &HashMap<String, &str>) -> Option<IngestedConnection> {
    let src_ip = record.get("id.orig_h")?.to_string();
    let dst_ip = record.get("id.resp_h")?.to_string();
    let src_port: u16 = record.get("id.orig_p")?.parse().ok()?;
    let dst_port: u16 = record.get("id.resp_p")?.parse().ok()?;

    let transport = record.get("proto")
        .map(|p| p.to_string())
        .unwrap_or_else(|| "tcp".to_string());

    let service = record.get("service")
        .map(|s| s.to_string())
        .unwrap_or_else(|| zeek_port_to_protocol(dst_port));

    let ts = record.get("ts").and_then(|t| parse_zeek_timestamp(t));

    // Zeek conn.log has orig_pkts/resp_pkts and orig_bytes/resp_bytes
    let orig_pkts: u64 = record.get("orig_pkts").and_then(|v| v.parse().ok()).unwrap_or(1);
    let resp_pkts: u64 = record.get("resp_pkts").and_then(|v| v.parse().ok()).unwrap_or(0);
    let orig_bytes: u64 = record.get("orig_bytes").and_then(|v| v.parse().ok()).unwrap_or(0);
    let resp_bytes: u64 = record.get("resp_bytes").and_then(|v| v.parse().ok()).unwrap_or(0);

    Some(IngestedConnection {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol: service,
        transport,
        packet_count: orig_pkts + resp_pkts,
        byte_count: orig_bytes + resp_bytes,
        first_seen: ts,
        last_seen: ts,
        source: IngestSource::Zeek,
    })
}

/// Parse a modbus.log record.
fn parse_modbus_record(record: &HashMap<String, &str>) -> Option<IngestedConnection> {
    let src_ip = record.get("id.orig_h")?.to_string();
    let dst_ip = record.get("id.resp_h")?.to_string();
    let src_port: u16 = record.get("id.orig_p")?.parse().ok()?;
    let dst_port: u16 = record.get("id.resp_p")?.parse().ok()?;
    let ts = record.get("ts").and_then(|t| parse_zeek_timestamp(t));

    Some(IngestedConnection {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol: "modbus".to_string(),
        transport: "tcp".to_string(),
        packet_count: 1,
        byte_count: 0,
        first_seen: ts,
        last_seen: ts,
        source: IngestSource::Zeek,
    })
}

/// Parse a dnp3.log record.
fn parse_dnp3_record(record: &HashMap<String, &str>) -> Option<IngestedConnection> {
    let src_ip = record.get("id.orig_h")?.to_string();
    let dst_ip = record.get("id.resp_h")?.to_string();
    let src_port: u16 = record.get("id.orig_p")?.parse().ok()?;
    let dst_port: u16 = record.get("id.resp_p")?.parse().ok()?;
    let ts = record.get("ts").and_then(|t| parse_zeek_timestamp(t));

    Some(IngestedConnection {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol: "dnp3".to_string(),
        transport: "tcp".to_string(),
        packet_count: 1,
        byte_count: 0,
        first_seen: ts,
        last_seen: ts,
        source: IngestSource::Zeek,
    })
}

/// Parse a s7comm.log record.
fn parse_s7comm_record(record: &HashMap<String, &str>) -> Option<IngestedConnection> {
    let src_ip = record.get("id.orig_h")?.to_string();
    let dst_ip = record.get("id.resp_h")?.to_string();
    let src_port: u16 = record.get("id.orig_p")?.parse().ok()?;
    let dst_port: u16 = record.get("id.resp_p")?.parse().ok()?;
    let ts = record.get("ts").and_then(|t| parse_zeek_timestamp(t));

    Some(IngestedConnection {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol: "s7comm".to_string(),
        transport: "tcp".to_string(),
        packet_count: 1,
        byte_count: 0,
        first_seen: ts,
        last_seen: ts,
        source: IngestSource::Zeek,
    })
}

/// Map Zeek service names / well-known ports to our protocol names.
fn zeek_port_to_protocol(port: u16) -> String {
    use gm_parsers::identify_by_port;
    let proto = identify_by_port(0, port);
    proto.to_name().to_string()
}

/// Create asset entries from a connection record.
fn add_asset_from_conn(assets: &mut Vec<IngestedAsset>, conn: &IngestedConnection) {
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
            source: IngestSource::Zeek,
            is_active: false,
        });
    }
}

/// Deduplicate assets by IP, merging protocols.
fn deduplicate_assets(assets: &mut Vec<IngestedAsset>) {
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut deduped: Vec<IngestedAsset> = Vec::new();

    for asset in assets.drain(..) {
        if let Some(&idx) = seen.get(&asset.ip_address) {
            // Merge protocols
            let existing = &mut deduped[idx];
            for proto in &asset.protocols {
                if !existing.protocols.contains(proto) {
                    existing.protocols.push(proto.clone());
                }
            }
            // Merge open ports
            for port in &asset.open_ports {
                if !existing.open_ports.iter().any(|p| p.port == port.port) {
                    existing.open_ports.push(port.clone());
                }
            }
            // Prefer non-None values
            if existing.hostname.is_none() && asset.hostname.is_some() {
                existing.hostname = asset.hostname;
            }
            if existing.os_info.is_none() && asset.os_info.is_some() {
                existing.os_info = asset.os_info;
            }
            if existing.vendor.is_none() && asset.vendor.is_some() {
                existing.vendor = asset.vendor;
            }
        } else {
            seen.insert(asset.ip_address.clone(), deduped.len());
            deduped.push(asset);
        }
    }

    *assets = deduped;
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
    fn test_parse_conn_log() {
        let content = "\
#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\torig_pkts\tresp_pkts\torig_bytes\tresp_bytes
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tcount\tcount\tcount\tcount
1609459200.000000\tCabcdef\t192.168.1.10\t49152\t192.168.1.100\t502\ttcp\tmodbus\t100\t100\t5000\t3000
1609459201.000000\tCxyz123\t192.168.1.20\t50000\t10.0.0.1\t443\ttcp\tssl\t50\t40\t2000\t8000
";
        let f = write_temp_file(content);
        let result = parse_zeek_logs(&[f.path()]).unwrap();

        assert_eq!(result.files_processed, 1);
        assert_eq!(result.connections.len(), 2);

        let c1 = &result.connections[0];
        assert_eq!(c1.src_ip, "192.168.1.10");
        assert_eq!(c1.dst_ip, "192.168.1.100");
        assert_eq!(c1.dst_port, 502);
        assert_eq!(c1.protocol, "modbus");
        assert_eq!(c1.packet_count, 200);
        assert_eq!(c1.byte_count, 8000);
    }

    #[test]
    fn test_parse_modbus_log() {
        let content = "\
#path\tmodbus
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfunc\texception
#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring
1609459200.000000\tCmod123\t192.168.1.10\t49152\t192.168.1.100\t502\tREAD_HOLDING_REGISTERS\t-
";
        let f = write_temp_file(content);
        let result = parse_zeek_logs(&[f.path()]).unwrap();

        assert_eq!(result.connections.len(), 1);
        assert_eq!(result.connections[0].protocol, "modbus");
    }

    #[test]
    fn test_parse_dnp3_log() {
        let content = "\
#path\tdnp3
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tfc_request\tfc_reply
#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring
1609459200.000000\tCdnp456\t10.0.0.5\t55000\t10.0.0.100\t20000\tREAD\tRESPONSE
";
        let f = write_temp_file(content);
        let result = parse_zeek_logs(&[f.path()]).unwrap();

        assert_eq!(result.connections.len(), 1);
        assert_eq!(result.connections[0].protocol, "dnp3");
        assert_eq!(result.connections[0].dst_port, 20000);
    }

    #[test]
    fn test_asset_deduplication() {
        let mut assets = vec![
            IngestedAsset {
                ip_address: "192.168.1.1".to_string(),
                mac_address: None,
                hostname: None,
                device_type: None,
                vendor: None,
                protocols: vec!["modbus".to_string()],
                open_ports: Vec::new(),
                os_info: None,
                source: IngestSource::Zeek,
                is_active: false,
            },
            IngestedAsset {
                ip_address: "192.168.1.1".to_string(),
                mac_address: None,
                hostname: Some("plc-01".to_string()),
                device_type: None,
                vendor: None,
                protocols: vec!["dnp3".to_string()],
                open_ports: Vec::new(),
                os_info: None,
                source: IngestSource::Zeek,
                is_active: false,
            },
        ];
        deduplicate_assets(&mut assets);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].protocols.len(), 2);
        assert_eq!(assets[0].hostname, Some("plc-01".to_string()));
    }
}
