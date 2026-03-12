//! Communication Allowlist Generation (Phase 14E)
//!
//! After PCAP analysis, generates a structured communication matrix of every
//! observed legitimate flow. Exports as CSV or firewall rule text.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{AssetSnapshot, ConnectionSnapshot};
use crate::comm_patterns::ConnectionStats;

/// A single entry in the communication allowlist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowlistEntry {
    /// Source IP address
    pub src_ip: String,
    /// Destination IP address
    pub dst_ip: String,
    /// Protocol name (e.g., "Modbus", "EthernetIp", "Http")
    pub protocol: String,
    /// Destination port
    pub dst_port: u16,
    /// "bidirectional" if symmetric traffic observed, "unidirectional" otherwise
    pub direction: String,
    /// "continuous", "periodic (100ms)", or "occasional"
    pub frequency: String,
    /// Average inter-packet interval in milliseconds, if known
    pub avg_interval_ms: Option<f64>,
    /// "operational" | "management" | "monitoring" | "it"
    pub classification: String,
    /// Human-readable description (e.g., "HMI polling PLC via Modbus")
    pub justification: String,
}

/// OT/ICS protocols — connections using these are classified as operational.
const ICS_PROTOCOLS: &[&str] = &[
    "Modbus",
    "Dnp3",
    "EthernetIp",
    "S7comm",
    "Bacnet",
    "OpcUa",
    "Iec104",
    "ProfinetDcp",
    "HartIp",
    "GeSrtp",
    "WonderwareSuitelink",
    "FfHse",
];

/// UDP-based protocols (for firewall rule transport label).
const UDP_PORTS: &[u16] = &[47808, 34962, 34963, 34964, 2222];

/// Generate a communication allowlist from the current capture data.
///
/// For each observed connection, produces an `AllowlistEntry` with:
/// - Frequency classification from timing statistics
/// - Operational classification from device types
/// - Human-readable justification from source/destination device roles
pub fn generate_allowlist(
    connections: &[ConnectionSnapshot],
    assets: &[AssetSnapshot],
    comm_stats: &[ConnectionStats],
) -> Vec<AllowlistEntry> {
    // Build IP → asset lookup
    let asset_map: HashMap<&str, &AssetSnapshot> = assets
        .iter()
        .map(|a| (a.ip_address.as_str(), a))
        .collect();

    // Build comm stats lookup: (src_ip, dst_ip, port, protocol) → stats
    let stats_map: HashMap<(&str, &str, u16, &str), &ConnectionStats> = comm_stats
        .iter()
        .map(|s| {
            (
                (s.src_ip.as_str(), s.dst_ip.as_str(), s.port, s.protocol.as_str()),
                s,
            )
        })
        .collect();

    // Track which (src, dst, port, protocol) pairs we have seen, and whether
    // the reverse direction was also observed (for bidirectional detection).
    let reverse_set: HashSet<(&str, &str, u16, &str)> = connections
        .iter()
        .map(|c| (c.src_ip.as_str(), c.dst_ip.as_str(), c.dst_port, c.protocol.as_str()))
        .collect();

    let mut entries = Vec::new();
    let mut seen: HashSet<(&str, &str, u16, &str)> = HashSet::new();

    for conn in connections {
        let key = (
            conn.src_ip.as_str(),
            conn.dst_ip.as_str(),
            conn.dst_port,
            conn.protocol.as_str(),
        );
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);

        let src_asset = asset_map.get(conn.src_ip.as_str()).copied();
        let dst_asset = asset_map.get(conn.dst_ip.as_str()).copied();

        let src_type = src_asset.map(|a| a.device_type.as_str()).unwrap_or("unknown");
        let dst_type = dst_asset.map(|a| a.device_type.as_str()).unwrap_or("unknown");

        let src_level = src_asset.and_then(|a| a.purdue_level);
        let dst_level = dst_asset.and_then(|a| a.purdue_level);

        // Frequency from timing stats
        let stats = stats_map.get(&key).copied();
        let (frequency, avg_interval_ms) = classify_frequency(stats);

        // Direction: check if reverse flow was also seen
        let has_reverse =
            reverse_set.contains(&(conn.dst_ip.as_str(), conn.src_ip.as_str(), conn.dst_port, conn.protocol.as_str()))
            || reverse_set.contains(&(conn.dst_ip.as_str(), conn.src_ip.as_str(), conn.src_port, conn.protocol.as_str()));
        let direction = if has_reverse { "bidirectional" } else { "unidirectional" }.to_string();

        let classification =
            classify_connection(src_type, dst_type, src_level, dst_level, &conn.protocol);
        let justification =
            build_justification(src_type, dst_type, &conn.protocol, conn.dst_port);

        entries.push(AllowlistEntry {
            src_ip: conn.src_ip.clone(),
            dst_ip: conn.dst_ip.clone(),
            protocol: conn.protocol.clone(),
            dst_port: conn.dst_port,
            direction,
            frequency,
            avg_interval_ms,
            classification,
            justification,
        });
    }

    // Sort: OT operational first, then management, monitoring, IT; then by src_ip
    entries.sort_by(|a, b| {
        classification_rank(&a.classification)
            .cmp(&classification_rank(&b.classification))
            .then(a.src_ip.cmp(&b.src_ip))
            .then(a.dst_port.cmp(&b.dst_port))
    });

    entries
}

/// Generate CSV representation of the allowlist.
pub fn allowlist_to_csv(entries: &[AllowlistEntry]) -> String {
    let mut lines =
        vec!["src_ip,dst_ip,protocol,port,direction,frequency,avg_interval_ms,classification,justification".to_string()];

    for e in entries {
        let interval = e
            .avg_interval_ms
            .map(|ms| format!("{ms:.1}"))
            .unwrap_or_default();
        lines.push(format!(
            "{},{},{},{},{},{},{},{},\"{}\"",
            e.src_ip,
            e.dst_ip,
            e.protocol,
            e.dst_port,
            e.direction,
            e.frequency,
            interval,
            e.classification,
            e.justification.replace('"', "'"),
        ));
    }

    lines.join("\n")
}

/// Generate human-readable firewall rule suggestions.
///
/// Produces ALLOW rules for each allowlist entry and a catch-all DENY
/// rule for traffic not explicitly listed.
pub fn format_firewall_rules(entries: &[AllowlistEntry]) -> String {
    let mut lines = vec![
        "# Communication Allowlist — Auto-generated by Kusanagi Kajiki".to_string(),
        "# Review and adapt before applying to a production firewall.".to_string(),
        "# Passive observation only — verify rules against your network policy.".to_string(),
        String::new(),
        "# ALLOW rules (observed legitimate flows):".to_string(),
    ];

    for e in entries {
        let transport = if UDP_PORTS.contains(&e.dst_port) { "udp" } else { "tcp" };
        lines.push(format!(
            "ALLOW {transport} {src} → {dst}:{port}  # {just}",
            transport = transport,
            src = e.src_ip,
            dst = e.dst_ip,
            port = e.dst_port,
            just = e.justification,
        ));
    }

    lines.push(String::new());
    lines.push("# Default deny — block all unlisted flows:".to_string());
    lines.push("DENY all * → *  # Implicit deny for any unmatched traffic".to_string());

    lines.join("\n")
}

// ─── Helpers ─────────────────────────────────────────────────

/// Derive frequency label and avg_interval_ms from connection stats.
fn classify_frequency(stats: Option<&ConnectionStats>) -> (String, Option<f64>) {
    let Some(s) = stats else {
        return ("occasional".to_string(), None);
    };

    if s.packet_count == 1 {
        return ("one-off".to_string(), None);
    }

    if s.is_periodic {
        let ms = s.avg_interval_ms;
        let label = if ms < 1_000.0 {
            format!("periodic ({ms:.0}ms)")
        } else if ms < 60_000.0 {
            format!("periodic ({:.1}s)", ms / 1_000.0)
        } else {
            format!("periodic ({:.1}min)", ms / 60_000.0)
        };
        return (label, Some(ms));
    }

    if s.packets_per_sec > 1.0 && s.duration_secs > 60.0 {
        return ("continuous".to_string(), Some(s.avg_interval_ms));
    }

    ("occasional".to_string(), Some(s.avg_interval_ms))
}

/// Classify a connection as operational / management / monitoring / it.
fn classify_connection(
    src_type: &str,
    dst_type: &str,
    src_level: Option<u8>,
    dst_level: Option<u8>,
    protocol: &str,
) -> String {
    let is_ot = ICS_PROTOCOLS.contains(&protocol);

    if !is_ot {
        // Pure IT traffic
        return "it".to_string();
    }

    let src_lo = src_type.to_lowercase();
    let dst_lo = dst_type.to_lowercase();

    // Engineering workstation = management
    if src_lo.contains("engineer") || dst_lo.contains("engineer") {
        return "management".to_string();
    }

    // Historian or SCADA reading from field devices = monitoring
    if src_lo.contains("historian")
        || src_lo.contains("scada")
        || dst_lo.contains("historian")
        || src_level == Some(3)
        || dst_level == Some(3)
    {
        return "monitoring".to_string();
    }

    "operational".to_string()
}

/// Build a human-readable justification string for the allowlist entry.
fn build_justification(src_type: &str, dst_type: &str, protocol: &str, dst_port: u16) -> String {
    let src = prettify_device_type(src_type);
    let dst = prettify_device_type(dst_type);

    if src_type != "unknown" && dst_type != "unknown" {
        format!("{src} communicating with {dst} via {protocol}")
    } else if src_type != "unknown" {
        format!("{src} → {protocol}:{dst_port}")
    } else if dst_type != "unknown" {
        format!("{protocol} traffic to {dst} on port {dst_port}")
    } else {
        format!("{protocol} traffic on port {dst_port}")
    }
}

/// Convert snake_case device type to a readable label.
fn prettify_device_type(dt: &str) -> String {
    match dt {
        "plc" => "PLC".to_string(),
        "rtu" => "RTU".to_string(),
        "hmi" => "HMI".to_string(),
        "historian" => "Historian".to_string(),
        "scada_server" => "SCADA Server".to_string(),
        "engineering_workstation" => "Engineering Workstation".to_string(),
        "io_server" => "I/O Server".to_string(),
        "field_device" => "Field Device".to_string(),
        "controller" => "Controller".to_string(),
        "switch" => "Switch".to_string(),
        "router" => "Router".to_string(),
        "server" => "Server".to_string(),
        "workstation" => "Workstation".to_string(),
        "unknown" => "Unknown Device".to_string(),
        other => {
            // Capitalise first letter
            let mut chars = other.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().to_string() + chars.as_str(),
            }
        }
    }
}

fn classification_rank(c: &str) -> u8 {
    match c {
        "operational" => 0,
        "management" => 1,
        "monitoring" => 2,
        "it" => 3,
        _ => 4,
    }
}

// ─── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn(src: &str, dst: &str, port: u16, proto: &str) -> ConnectionSnapshot {
        ConnectionSnapshot {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: 12345,
            dst_port: port,
            protocol: proto.to_string(),
            packet_count: 10,
        }
    }

    fn make_asset(ip: &str, device_type: &str, level: u8) -> AssetSnapshot {
        AssetSnapshot {
            ip_address: ip.to_string(),
            device_type: device_type.to_string(),
            protocols: vec![],
            purdue_level: Some(level),
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        }
    }

    #[test]
    fn test_generate_allowlist_empty() {
        let result = generate_allowlist(&[], &[], &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_generate_allowlist_basic() {
        let connections = vec![
            make_conn("10.0.2.10", "10.0.1.20", 502, "Modbus"),
        ];
        let assets = vec![
            make_asset("10.0.2.10", "hmi", 2),
            make_asset("10.0.1.20", "plc", 1),
        ];

        let result = generate_allowlist(&connections, &assets, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src_ip, "10.0.2.10");
        assert_eq!(result[0].dst_port, 502);
        assert_eq!(result[0].protocol, "Modbus");
        assert_eq!(result[0].classification, "operational");
        assert!(result[0].justification.contains("HMI"));
        assert!(result[0].justification.contains("PLC"));
    }

    #[test]
    fn test_allowlist_csv_format() {
        let entries = vec![AllowlistEntry {
            src_ip: "10.0.2.10".to_string(),
            dst_ip: "10.0.1.20".to_string(),
            protocol: "Modbus".to_string(),
            dst_port: 502,
            direction: "bidirectional".to_string(),
            frequency: "periodic (100ms)".to_string(),
            avg_interval_ms: Some(100.0),
            classification: "operational".to_string(),
            justification: "HMI communicating with PLC via Modbus".to_string(),
        }];

        let csv = allowlist_to_csv(&entries);
        assert!(csv.contains("10.0.2.10,10.0.1.20,Modbus,502"));
        assert!(csv.contains("operational"));
        // Header row present
        assert!(csv.starts_with("src_ip,dst_ip"));
    }

    #[test]
    fn test_firewall_rules_format() {
        let entries = vec![AllowlistEntry {
            src_ip: "10.0.2.10".to_string(),
            dst_ip: "10.0.1.20".to_string(),
            protocol: "Modbus".to_string(),
            dst_port: 502,
            direction: "bidirectional".to_string(),
            frequency: "periodic (100ms)".to_string(),
            avg_interval_ms: Some(100.0),
            classification: "operational".to_string(),
            justification: "HMI → PLC Modbus polling".to_string(),
        }];

        let rules = format_firewall_rules(&entries);
        assert!(rules.contains("ALLOW tcp 10.0.2.10 → 10.0.1.20:502"));
        assert!(rules.contains("DENY all"));
        assert!(rules.contains("HMI → PLC Modbus polling"));
    }

    #[test]
    fn test_it_classification_for_non_ot_protocol() {
        let connections = vec![make_conn("10.0.4.5", "10.0.4.1", 80, "Http")];
        let assets = vec![make_asset("10.0.4.5", "workstation", 4)];

        let result = generate_allowlist(&connections, &assets, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].classification, "it");
    }

    #[test]
    fn test_deduplication_no_duplicate_entries() {
        // Same connection should appear only once even if listed twice
        let connections = vec![
            make_conn("10.0.2.10", "10.0.1.20", 502, "Modbus"),
            make_conn("10.0.2.10", "10.0.1.20", 502, "Modbus"),
        ];
        let result = generate_allowlist(&connections, &[], &[]);
        assert_eq!(result.len(), 1, "Duplicate connections should be deduplicated");
    }
}
