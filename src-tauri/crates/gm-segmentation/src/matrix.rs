//! Phase 15C — Least-Privilege Communication Matrix Generator.
//!
//! Derives a per-zone-pair minimum allow-rule set from observed traffic.
//!
//! ## Algorithm
//!
//! Extends `allowlist.rs` from per-connection to per-zone-pair granularity:
//! 1. Map each asset IP to a zone via Purdue level.
//! 2. Skip intra-zone and unzoned connections.
//! 3. Group inter-zone flows by (src_zone, dst_zone, protocol, dst_port).
//!    Accumulate: unique IPs, packet count, time range, OR of flags, ATT&CK union.
//! 4. Classify each group as low (read) / medium (write) / high (config).
//! 5. Build one [`ZonePairPolicy`] per zone pair with all its rules.
//! 6. Coverage = matched_inter_zone / total_inter_zone × 100.
//!    `default_action` is always `"deny"`.

use std::collections::{HashMap, HashSet};

use crate::{
    AssetProfile, CommunicationMatrix, PolicyRule, RuleRisk, SegmentationError, SegmentationInput,
    Zone, ZoneModel, ZonePairPolicy,
};

// ── Public API ──────────────────────────────────────────────────────────────

/// Build a per-zone-pair least-privilege communication matrix.
///
/// Thin wrapper around [`generate_matrix`] — maps errors to an empty matrix,
/// preserving the `pub use matrix::build_communication_matrix` re-export in `lib.rs`.
pub fn build_communication_matrix(
    zone_model: &ZoneModel,
    input: &SegmentationInput,
) -> CommunicationMatrix {
    generate_matrix(zone_model, input).unwrap_or_else(|_| CommunicationMatrix {
        zone_pairs: Vec::new(),
        default_action: "deny".to_string(),
        coverage_percent: 0.0,
    })
}

/// Generate a per-zone-pair least-privilege communication matrix.
///
/// Returns an empty (but valid) matrix when `zone_model` has no zones.
pub fn generate_matrix(
    zone_model: &ZoneModel,
    input: &SegmentationInput,
) -> Result<CommunicationMatrix, SegmentationError> {
    if zone_model.zones.is_empty() {
        return Ok(CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        });
    }

    // a) IP → zone_id, derived from asset Purdue levels.
    let ip_to_zone = build_ip_to_zone_from_assets(&zone_model.zones, &input.assets);

    // b+c) Group inter-zone connections by (src_zone_id, dst_zone_id, protocol, dst_port).
    struct FlowGroup {
        src_ips: HashSet<String>,
        dst_ips: HashSet<String>,
        packet_count: u64,
        first_seen: String,
        last_seen: String,
        has_write: bool,
        has_read: bool,
        has_config: bool,
        attack_techniques: Vec<String>,
        any_allowlisted: bool,
    }

    type GroupKey = (String, String, String, u16); // (src_zone, dst_zone, proto, port)
    let mut flow_groups: HashMap<GroupKey, FlowGroup> = HashMap::new();
    let mut total_inter_zone: usize = 0;
    let mut matched_inter_zone: usize = 0;

    for conn in &input.connections {
        let src_zone = ip_to_zone.get(&conn.src_ip);
        let dst_zone = ip_to_zone.get(&conn.dst_ip);

        match (src_zone, dst_zone) {
            // Intra-zone: skip entirely.
            (Some(sz), Some(dz)) if sz == dz => {}

            // Both zoned, different zones: create/update a flow group.
            (Some(sz), Some(dz)) => {
                total_inter_zone += 1;
                matched_inter_zone += 1;
                let key: GroupKey = (sz.clone(), dz.clone(), conn.protocol.clone(), conn.dst_port);

                let g = flow_groups.entry(key).or_insert_with(|| FlowGroup {
                    src_ips: HashSet::new(),
                    dst_ips: HashSet::new(),
                    packet_count: 0,
                    first_seen: conn.first_seen.clone(),
                    last_seen: conn.last_seen.clone(),
                    has_write: false,
                    has_read: false,
                    has_config: false,
                    attack_techniques: Vec::new(),
                    any_allowlisted: false,
                });

                g.src_ips.insert(conn.src_ip.clone());
                g.dst_ips.insert(conn.dst_ip.clone());
                g.packet_count += conn.packet_count;
                if conn.first_seen < g.first_seen {
                    g.first_seen = conn.first_seen.clone();
                }
                if conn.last_seen > g.last_seen {
                    g.last_seen = conn.last_seen.clone();
                }
                g.has_write |= conn.has_write_operations;
                g.has_read |= conn.has_read_operations;
                g.has_config |= conn.has_config_operations;
                for tech in &conn.attack_techniques {
                    if !g.attack_techniques.contains(tech) {
                        g.attack_techniques.push(tech.clone());
                    }
                }
                g.any_allowlisted |= conn.is_in_allowlist;
            }

            // One or both ends unzoned: count as inter-zone candidate (lowers coverage).
            // Skip if both ends are fully unzoned — undefined zone ≠ inter-zone.
            (Some(_), None) | (None, Some(_)) => {
                total_inter_zone += 1;
            }
            (None, None) => {}
        }
    }

    // d) Build PolicyRule per flow group, grouped by zone pair.
    let mut pair_to_rules: HashMap<(String, String), Vec<PolicyRule>> = HashMap::new();

    // Sort keys for deterministic output ordering.
    let mut group_keys: Vec<GroupKey> = flow_groups.keys().cloned().collect();
    group_keys.sort();

    for key in group_keys {
        let g = match flow_groups.get(&key) {
            Some(g) => g,
            None => continue,
        };
        let (src_zone_id, dst_zone_id, ref protocol, dst_port) = key;

        let risk = classify_connection_risk(g.has_config, g.has_write, g.has_read);
        let justification = build_rule_justification(
            protocol,
            dst_port,
            g.packet_count,
            g.src_ips.len(),
            g.dst_ips.len(),
            &g.first_seen,
            &g.last_seen,
            &g.attack_techniques,
            g.any_allowlisted,
        );

        pair_to_rules
            .entry((src_zone_id, dst_zone_id))
            .or_default()
            .push(PolicyRule {
                protocol: protocol.clone(),
                dst_port: Some(dst_port),
                risk,
                justification,
                packet_count: g.packet_count,
            });
    }

    // e) Build one ZonePairPolicy per zone pair (sorted for deterministic output).
    let mut pair_keys: Vec<(String, String)> = pair_to_rules.keys().cloned().collect();
    pair_keys.sort();

    let mut zone_pairs: Vec<ZonePairPolicy> = Vec::new();
    for (src_zone_id, dst_zone_id) in pair_keys {
        let rules = pair_to_rules
            .remove(&(src_zone_id.clone(), dst_zone_id.clone()))
            .unwrap_or_default();
        zone_pairs.push(ZonePairPolicy {
            src_zone_id,
            dst_zone_id,
            rules,
        });
    }

    // f) Coverage percentage.
    let coverage_percent = if total_inter_zone == 0 {
        100.0
    } else {
        matched_inter_zone as f64 / total_inter_zone as f64 * 100.0
    };

    Ok(CommunicationMatrix {
        zone_pairs,
        default_action: "deny".to_string(),
        coverage_percent,
    })
}

// ── Public helper ────────────────────────────────────────────────────────────

/// Classify the risk of a policy rule based on observed operation types.
///
/// - `High`   — config/program transfer operations detected.
/// - `Medium` — write operations detected (no config).
/// - `Low`    — read-only or no operations detected.
pub fn classify_connection_risk(has_config: bool, has_write: bool, _has_read: bool) -> RuleRisk {
    if has_config {
        RuleRisk::High
    } else if has_write {
        RuleRisk::Medium
    } else {
        RuleRisk::Low
    }
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// Build an IP → zone_id map from asset Purdue levels and zone Purdue level sets.
///
/// For each zone, every entry in `zone.purdue_levels` is registered; first match
/// wins for overlapping levels (e.g., sub-zones A/B that share the same level).
/// Assets with `purdue_level = None` fall into the Unclassified Zone (if present).
/// Assets with `purdue_level >= 4` are normalized to level 4 (Enterprise Zone).
pub(crate) fn build_ip_to_zone_from_assets(
    zones: &[Zone],
    assets: &[AssetProfile],
) -> HashMap<String, String> {
    let mut purdue_to_zone: HashMap<u8, String> = HashMap::new();
    let mut unclassified_zone_id: Option<String> = None;

    for zone in zones {
        if zone.purdue_levels.is_empty() {
            if unclassified_zone_id.is_none() {
                unclassified_zone_id = Some(zone.id.clone());
            }
        } else {
            for &level in &zone.purdue_levels {
                // First zone registered for a given level wins (sub-zone determinism).
                purdue_to_zone
                    .entry(level)
                    .or_insert_with(|| zone.id.clone());
            }
        }
    }

    let mut ip_to_zone: HashMap<String, String> = HashMap::new();
    for asset in assets {
        let zone_id = match asset.purdue_level {
            Some(level) => {
                // Normalize L5+ to L4 (all Enterprise IT).
                let lookup = if level >= 4 { 4 } else { level };
                purdue_to_zone.get(&lookup).cloned()
            }
            None => unclassified_zone_id.clone(),
        };
        if let Some(zid) = zone_id {
            ip_to_zone.insert(asset.ip.clone(), zid);
        }
    }
    ip_to_zone
}

/// Build a human-readable justification string for a policy rule.
#[allow(clippy::too_many_arguments)]
fn build_rule_justification(
    protocol: &str,
    dst_port: u16,
    packet_count: u64,
    src_count: usize,
    dst_count: usize,
    first_seen: &str,
    last_seen: &str,
    attack_techniques: &[String],
    any_allowlisted: bool,
) -> String {
    // Show only the date portion of RFC 3339 timestamps.
    let first_date = first_seen.split('T').next().unwrap_or(first_seen);
    let last_date = last_seen.split('T').next().unwrap_or(last_seen);
    let time_range = if first_date == last_date {
        first_date.to_string()
    } else {
        format!("{first_date} to {last_date}")
    };

    let mut parts = vec![format!(
        "Observed {packet_count} packets, {protocol}/{dst_port} \
         | {src_count} source(s) → {dst_count} destination(s) | {time_range}",
    )];

    if !attack_techniques.is_empty() {
        parts.push(format!(
            "WARNING: ATT&CK techniques: {}",
            attack_techniques.join(", ")
        ));
    }

    if any_allowlisted {
        parts.push("Pre-approved in allowlist".to_string());
    }

    parts.join("; ")
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AssetProfile, ObservedConnection, SecurityLevel, SegmentationInput, Zone, ZoneModel,
    };

    fn make_zone(id: &str, name: &str, purdue_levels: Vec<u8>) -> Zone {
        Zone {
            id: id.to_string(),
            name: name.to_string(),
            purdue_levels,
            policy_group_ids: Vec::new(),
            security_level: SecurityLevel::Sl2,
            asset_count: 0,
        }
    }

    fn make_asset(ip: &str, purdue_level: Option<u8>) -> AssetProfile {
        AssetProfile {
            ip: ip.to_string(),
            mac: None,
            hostname: None,
            vendor: None,
            device_type: "plc".to_string(),
            product_name: None,
            purdue_level,
            protocols: Vec::new(),
            protocol_roles: Vec::new(),
            confidence: 3,
            criticality: None,
            subnet: None,
            is_ot: true,
            is_it: false,
            is_dual_homed: false,
            connection_count: 5,
            has_cves: false,
            has_default_creds: false,
        }
    }

    fn make_conn(src: &str, dst: &str, proto: &str, dst_port: u16) -> ObservedConnection {
        ObservedConnection {
            src_ip: src.to_string(),
            src_port: 50000,
            dst_ip: dst.to_string(),
            dst_port,
            protocol: proto.to_string(),
            packet_count: 100,
            byte_count: 5000,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T01:00:00Z".to_string(),
            is_periodic: true,
            pattern_anomaly: false,
            has_write_operations: false,
            has_read_operations: true,
            has_config_operations: false,
            attack_techniques: Vec::new(),
            is_in_allowlist: false,
        }
    }

    /// Standard two-zone model (Control L1, Enterprise L4) with two assets.
    fn two_zone_setup() -> (ZoneModel, SegmentationInput) {
        let zones = vec![
            make_zone("z-ctrl", "Control Zone", vec![0, 1]),
            make_zone("z-ent", "Enterprise Zone", vec![4]),
        ];
        let model = ZoneModel {
            zones,
            conduits: Vec::new(),
            zone_score: 1.0,
            recommendations: Vec::new(),
        };
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.1.1", Some(1)),
                make_asset("192.168.1.10", Some(4)),
            ],
            ..Default::default()
        };
        (model, input)
    }

    // ── test_empty_zones ──────────────────────────────────────────────────────

    #[test]
    fn test_empty_zones() {
        let model = ZoneModel {
            zones: Vec::new(),
            conduits: Vec::new(),
            zone_score: 0.0,
            recommendations: Vec::new(),
        };
        let input = SegmentationInput::default();
        let matrix = build_communication_matrix(&model, &input);
        assert!(matrix.zone_pairs.is_empty());
        assert_eq!(matrix.default_action, "deny");
        assert_eq!(matrix.coverage_percent, 0.0);
    }

    // ── test_single_rule ─────────────────────────────────────────────────────

    #[test]
    fn test_single_rule() {
        let (model, mut input) = two_zone_setup();
        input.connections = vec![make_conn("10.0.1.1", "192.168.1.10", "modbus", 502)];
        let matrix = generate_matrix(&model, &input).unwrap();
        assert_eq!(matrix.zone_pairs.len(), 1, "expected exactly one zone pair");
        assert_eq!(
            matrix.zone_pairs[0].rules.len(),
            1,
            "expected exactly one rule"
        );
        assert_eq!(matrix.zone_pairs[0].rules[0].protocol, "modbus");
        assert_eq!(matrix.zone_pairs[0].rules[0].dst_port, Some(502));
    }

    // ── test_multiple_rules ──────────────────────────────────────────────────

    #[test]
    fn test_multiple_rules() {
        let (model, mut input) = two_zone_setup();
        input.connections = vec![
            make_conn("10.0.1.1", "192.168.1.10", "modbus", 502),
            make_conn("10.0.1.1", "192.168.1.10", "http", 80),
            make_conn("10.0.1.1", "192.168.1.10", "snmp", 161),
        ];
        let matrix = generate_matrix(&model, &input).unwrap();
        assert_eq!(matrix.zone_pairs.len(), 1);
        assert_eq!(
            matrix.zone_pairs[0].rules.len(),
            3,
            "each distinct (proto, port) should produce a separate rule"
        );
    }

    // ── test_risk_classification ─────────────────────────────────────────────

    #[test]
    fn test_risk_classification() {
        assert_eq!(
            classify_connection_risk(true, false, false),
            RuleRisk::High,
            "config ops → high"
        );
        assert_eq!(
            classify_connection_risk(false, true, false),
            RuleRisk::Medium,
            "write ops → medium"
        );
        assert_eq!(
            classify_connection_risk(false, false, true),
            RuleRisk::Low,
            "read-only → low"
        );
        assert_eq!(
            classify_connection_risk(false, false, false),
            RuleRisk::Low,
            "no ops observed → low (safe default)"
        );
    }

    // ── test_intra_zone_excluded ─────────────────────────────────────────────

    #[test]
    fn test_intra_zone_excluded() {
        let zones = vec![make_zone("z1", "Control Zone", vec![0, 1])];
        let model = ZoneModel {
            zones,
            conduits: Vec::new(),
            zone_score: 1.0,
            recommendations: Vec::new(),
        };
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.1.1", Some(1)),
                make_asset("10.0.1.2", Some(1)),
            ],
            connections: vec![make_conn("10.0.1.1", "10.0.1.2", "modbus", 502)],
            ..Default::default()
        };
        let matrix = generate_matrix(&model, &input).unwrap();
        assert!(
            matrix.zone_pairs.is_empty(),
            "intra-zone traffic must not generate a zone-pair policy"
        );
    }

    // ── test_justification_format ────────────────────────────────────────────

    #[test]
    fn test_justification_format() {
        let (model, mut input) = two_zone_setup();
        let mut conn = make_conn("10.0.1.1", "192.168.1.10", "modbus", 502);
        conn.packet_count = 1243;
        conn.first_seen = "2026-01-01T00:00:00Z".to_string();
        conn.last_seen = "2026-01-15T00:00:00Z".to_string();
        input.connections = vec![conn];

        let matrix = generate_matrix(&model, &input).unwrap();
        let just = &matrix.zone_pairs[0].rules[0].justification;
        assert!(
            just.contains("1243"),
            "justification must include packet count"
        );
        assert!(
            just.contains("modbus"),
            "justification must include protocol"
        );
        assert!(
            just.contains("502"),
            "justification must include destination port"
        );
        assert!(
            just.contains("2026-01-01"),
            "justification must include start date"
        );
        assert!(
            just.contains("2026-01-15"),
            "justification must include end date"
        );
    }

    // ── test_allowlist_noted ─────────────────────────────────────────────────

    #[test]
    fn test_allowlist_noted() {
        let (model, mut input) = two_zone_setup();
        let mut conn = make_conn("10.0.1.1", "192.168.1.10", "modbus", 502);
        conn.is_in_allowlist = true;
        input.connections = vec![conn];

        let matrix = generate_matrix(&model, &input).unwrap();
        let just = &matrix.zone_pairs[0].rules[0].justification;
        assert!(
            just.contains("Pre-approved in allowlist"),
            "pre-approved connections must be noted in the justification"
        );
    }

    // ── test_attack_technique_warning ────────────────────────────────────────

    #[test]
    fn test_attack_technique_warning() {
        let (model, mut input) = two_zone_setup();
        let mut conn = make_conn("10.0.1.1", "192.168.1.10", "modbus", 502);
        conn.attack_techniques = vec!["T0855".to_string()];
        input.connections = vec![conn];

        let matrix = generate_matrix(&model, &input).unwrap();
        let just = &matrix.zone_pairs[0].rules[0].justification;
        assert!(
            just.contains("WARNING") && just.contains("T0855"),
            "ATT&CK techniques must be flagged in the justification"
        );
    }

    // ── test_coverage_full_when_all_zoned ────────────────────────────────────

    #[test]
    fn test_coverage_full_when_all_zoned() {
        let (model, mut input) = two_zone_setup();
        input.connections = vec![make_conn("10.0.1.1", "192.168.1.10", "modbus", 502)];
        let matrix = generate_matrix(&model, &input).unwrap();
        assert!(
            (matrix.coverage_percent - 100.0).abs() < f64::EPSILON,
            "coverage should be 100% when all connections are zoned"
        );
    }

    // ── test_packet_count_accumulated ───────────────────────────────────────

    #[test]
    fn test_packet_count_accumulated() {
        let (model, mut input) = two_zone_setup();
        // Two connections with same (proto, port) → merged into one rule, packets summed.
        let mut c1 = make_conn("10.0.1.1", "192.168.1.10", "modbus", 502);
        c1.packet_count = 300;
        let mut c2 = make_conn("10.0.1.1", "192.168.1.10", "modbus", 502);
        c2.packet_count = 200;
        input.connections = vec![c1, c2];

        let matrix = generate_matrix(&model, &input).unwrap();
        assert_eq!(
            matrix.zone_pairs[0].rules.len(),
            1,
            "same proto/port should merge"
        );
        assert_eq!(
            matrix.zone_pairs[0].rules[0].packet_count, 500,
            "packet counts should be summed"
        );
    }
}
