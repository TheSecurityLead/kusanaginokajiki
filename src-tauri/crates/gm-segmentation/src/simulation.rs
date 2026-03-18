//! Phase 15E — Policy Simulation Engine.
//!
//! Replays observed traffic against the proposed policy to quantify impact
//! before enforcement. Inspired by Elisity's Simulation Mode.
//!
//! ## Algorithm
//!
//! For each observed connection:
//! 1. Map src_ip and dst_ip to their zones via asset Purdue level.
//! 2. Check whether (src_zone, dst_zone, protocol, port) matches any
//!    `PolicyRule` in the `CommunicationMatrix`.
//! 3. Match → allowed; no match → blocked.
//!
//! **False positive detection**: A blocked connection is a false positive
//! candidate when it is periodic AND read-only AND was in the allowlist
//! (`is_periodic=true`, `has_write_operations=false`, `is_in_allowlist=true`).
//!
//! **Risk reduction scoring**: Count how many SecurityFindings are "blocked"
//! (all `affected_ips` are in zones that have no conduit allowing their traffic),
//! weighted: critical=4, high=3, medium=2, low=1.
//!
//! **Deployment score** (Elisity-inspired):
//! Zone coverage weighted by IEC 62443 Security Level:
//! SL4=4, SL3=3, SL2=2, SL1=1. A zone contributes its weight when at least
//! one conduit rule exists in the matrix for connections from/to it.

use std::collections::{HashMap, HashSet};

use crate::{
    matrix::build_ip_to_zone_from_assets, BlockedConnection, CommunicationMatrix, SecurityLevel,
    SegmentationError, SegmentationInput, SimulationResult, ZoneBlockSummary, ZoneModel,
};

// ── Public API ────────────────────────────────────────────────────────────────

/// Simulate the proposed policy against observed traffic and quantify impact.
///
/// Returns `Err` only if the zone model contains no zones at all (empty input).
pub fn simulate_policy(
    matrix: &CommunicationMatrix,
    zone_model: &ZoneModel,
    input: &SegmentationInput,
) -> Result<SimulationResult, SegmentationError> {
    if zone_model.zones.is_empty() {
        return Err(SegmentationError::EmptyInput(
            "zone model has no zones".into(),
        ));
    }

    // Build IP → zone_id lookup from asset Purdue levels.
    let ip_to_zone = build_ip_to_zone_from_assets(&zone_model.zones, &input.assets);

    // Build a fast allow-set: (src_zone, dst_zone, protocol, Option<port>).
    // A connection is allowed when either an exact port rule OR a port=None
    // wildcard rule exists for the (zone_pair, proto).
    let allow_set = build_allow_set(matrix);

    // ── Per-connection simulation ─────────────────────────────────────────────
    let mut allowed: usize = 0;
    let mut blocked: usize = 0;
    let mut critical_blocks: Vec<BlockedConnection> = Vec::new();
    let mut false_positive_candidates: Vec<BlockedConnection> = Vec::new();
    // (src_zone, dst_zone) → blocked count
    let mut zone_block_counts: HashMap<(String, String), usize> = HashMap::new();

    for conn in &input.connections {
        let src_zone = ip_to_zone.get(&conn.src_ip).cloned();
        let dst_zone = ip_to_zone.get(&conn.dst_ip).cloned();

        let (src_z, dst_z) = match (src_zone, dst_zone) {
            (Some(s), Some(d)) => (s, d),
            _ => {
                // At least one endpoint not in any zone — treat as allowed
                // (unclassified traffic is out of scope for this policy).
                allowed += 1;
                continue;
            }
        };

        if is_allowed(&allow_set, &src_z, &dst_z, &conn.protocol, conn.dst_port) {
            allowed += 1;
        } else {
            blocked += 1;
            *zone_block_counts
                .entry((src_z.clone(), dst_z.clone()))
                .or_insert(0) += 1;

            let is_fp = conn.is_periodic && !conn.has_write_operations && conn.is_in_allowlist;
            let reason = build_block_reason(&src_z, &dst_z, &conn.protocol, conn.dst_port);

            let entry = BlockedConnection {
                src_ip: conn.src_ip.clone(),
                dst_ip: conn.dst_ip.clone(),
                protocol: conn.protocol.clone(),
                dst_port: conn.dst_port,
                is_false_positive_candidate: is_fp,
                reason,
            };

            if is_fp {
                false_positive_candidates.push(entry);
            } else {
                critical_blocks.push(entry);
            }
        }
    }

    // ── Scores ────────────────────────────────────────────────────────────────
    let total = allowed + blocked;
    let blocked_percent = if total == 0 {
        0.0
    } else {
        blocked as f64 / total as f64 * 100.0
    };

    let risk_reduction_score =
        compute_risk_reduction(&input.findings, &ip_to_zone, &allow_set, matrix);

    let deployment_score = compute_deployment_score(zone_model, matrix);

    // ── Zone block summaries ──────────────────────────────────────────────────
    let zone_block_summaries: Vec<ZoneBlockSummary> = zone_block_counts
        .into_iter()
        .map(|((src, dst), count)| ZoneBlockSummary {
            src_zone_id: src,
            dst_zone_id: dst,
            blocked_count: count,
        })
        .collect();

    Ok(SimulationResult {
        allowed,
        blocked,
        blocked_percent,
        risk_reduction_score,
        deployment_score,
        critical_blocks,
        false_positive_candidates,
        zone_block_summaries,
    })
}

/// Wrapper that calls `simulate_policy` and returns a zero-result on error.
pub fn run_simulation(
    zone_model: &ZoneModel,
    matrix: &CommunicationMatrix,
    input: &SegmentationInput,
) -> SimulationResult {
    simulate_policy(matrix, zone_model, input).unwrap_or(SimulationResult {
        allowed: 0,
        blocked: 0,
        blocked_percent: 0.0,
        risk_reduction_score: 0.0,
        deployment_score: 0.0,
        critical_blocks: Vec::new(),
        false_positive_candidates: Vec::new(),
        zone_block_summaries: Vec::new(),
    })
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Key type for the allow set.
///
/// `(src_zone_id, dst_zone_id, protocol, dst_port_or_wildcard)`
/// where `None` = wildcard (matches any port for this protocol).
type AllowKey = (String, String, String, Option<u16>);

/// Build a HashSet of `(src_zone, dst_zone, protocol, port_option)` tuples
/// from the matrix.  Both intra-zone and cross-zone rules are included.
fn build_allow_set(matrix: &CommunicationMatrix) -> HashSet<AllowKey> {
    let mut set = HashSet::new();
    for zp in &matrix.zone_pairs {
        for rule in &zp.rules {
            set.insert((
                zp.src_zone_id.clone(),
                zp.dst_zone_id.clone(),
                rule.protocol.clone(),
                rule.dst_port,
            ));
        }
    }
    set
}

/// Check whether a connection is permitted by the allow-set.
///
/// A connection is allowed if:
/// - An exact `(src, dst, proto, port)` key exists, OR
/// - A wildcard `(src, dst, proto, None)` key exists (any port).
fn is_allowed(
    allow_set: &HashSet<AllowKey>,
    src_zone: &str,
    dst_zone: &str,
    protocol: &str,
    dst_port: u16,
) -> bool {
    let exact_key = (
        src_zone.to_string(),
        dst_zone.to_string(),
        protocol.to_string(),
        Some(dst_port),
    );
    let wildcard_key = (
        src_zone.to_string(),
        dst_zone.to_string(),
        protocol.to_string(),
        None,
    );
    allow_set.contains(&exact_key) || allow_set.contains(&wildcard_key)
}

/// Build a human-readable reason explaining why a connection was blocked.
fn build_block_reason(src_zone: &str, dst_zone: &str, protocol: &str, dst_port: u16) -> String {
    format!("No rule allows {protocol}:{dst_port} from zone {src_zone} to zone {dst_zone}")
}

/// Compute risk reduction score.
///
/// For each SecurityFinding, check whether any of its `affected_ips` are in
/// connections that would be blocked.  A finding is "blocked" if at least one
/// of its affected IPs belongs to a blocked connection pair.
///
/// Weight: critical=4, high=3, medium=2, low=1, info=0.
/// Score = sum(blocked_weight) / sum(all_weight).  Returns 0.0 if no findings.
fn compute_risk_reduction(
    findings: &[crate::SecurityFinding],
    ip_to_zone: &HashMap<String, String>,
    allow_set: &HashSet<AllowKey>,
    matrix: &CommunicationMatrix,
) -> f64 {
    if findings.is_empty() {
        return 0.0;
    }

    // Build the set of (src_zone, dst_zone) pairs that are blocked.
    // A pair is blocked when no zone-pair policy exists for it at all.
    let allowed_pairs: HashSet<(String, String)> = matrix
        .zone_pairs
        .iter()
        .map(|zp| (zp.src_zone_id.clone(), zp.dst_zone_id.clone()))
        .collect();

    let severity_weight = |s: &str| -> f64 {
        match s {
            "critical" => 4.0,
            "high" => 3.0,
            "medium" => 2.0,
            "low" => 1.0,
            _ => 0.0,
        }
    };

    let mut total_weight: f64 = 0.0;
    let mut blocked_weight: f64 = 0.0;

    for finding in findings {
        let w = severity_weight(&finding.severity);
        total_weight += w;

        // A finding is "blocked" if every affected IP is in a zone where
        // the relevant connections would be blocked.
        let is_blocked = is_finding_blocked(finding, ip_to_zone, allow_set, &allowed_pairs);
        if is_blocked {
            blocked_weight += w;
        }
    }

    if total_weight == 0.0 {
        0.0
    } else {
        blocked_weight / total_weight
    }
}

/// Returns true if this finding's affected IPs are all in blocked-zone regions.
///
/// Simple heuristic: if any affected IP has no zone, the finding is
/// considered not blockable.  Otherwise, a finding is blocked when its
/// affected IPs' zones don't appear in any allowed (src, dst) pair.
fn is_finding_blocked(
    finding: &crate::SecurityFinding,
    ip_to_zone: &HashMap<String, String>,
    _allow_set: &HashSet<AllowKey>,
    allowed_pairs: &HashSet<(String, String)>,
) -> bool {
    if finding.affected_ips.is_empty() {
        return false;
    }
    // Collect zone IDs for all affected IPs.
    let zones: Vec<&String> = finding
        .affected_ips
        .iter()
        .filter_map(|ip| ip_to_zone.get(ip))
        .collect();

    if zones.is_empty() {
        return false;
    }

    // A finding is blocked if none of its affected zones appear as a src
    // in any allowed pair (meaning all outbound traffic from these zones
    // is denied — they are isolated).
    zones
        .iter()
        .all(|z| !allowed_pairs.iter().any(|(src, _)| src == *z))
}

/// Compute IEC 62443-inspired deployment score.
///
/// For each zone with security_level >= SL2, assign a weight equal to the
/// SL number (SL4=4, SL3=3, SL2=2, SL1=1). A zone "has coverage" when at
/// least one matrix zone-pair has it as a src or dst.
///
/// Score = sum(weight_i * coverage_i) / sum(weight_i).
fn compute_deployment_score(zone_model: &ZoneModel, matrix: &CommunicationMatrix) -> f64 {
    // Zones that appear in at least one zone-pair rule.
    let covered_zones: HashSet<&str> = matrix
        .zone_pairs
        .iter()
        .flat_map(|zp| [zp.src_zone_id.as_str(), zp.dst_zone_id.as_str()])
        .collect();

    let sl_weight = |sl: SecurityLevel| -> f64 {
        match sl {
            SecurityLevel::Sl1 => 1.0,
            SecurityLevel::Sl2 => 2.0,
            SecurityLevel::Sl3 => 3.0,
            SecurityLevel::Sl4 => 4.0,
        }
    };

    let mut total_weight: f64 = 0.0;
    let mut covered_weight: f64 = 0.0;

    for zone in &zone_model.zones {
        let w = sl_weight(zone.security_level);
        total_weight += w;
        if covered_zones.contains(zone.id.as_str()) {
            covered_weight += w;
        }
    }

    if total_weight == 0.0 {
        0.0
    } else {
        covered_weight / total_weight
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AssetProfile, CommunicationMatrix, ObservedConnection, PolicyRule, RuleRisk,
        SecurityFinding, SecurityLevel, SegmentationInput, Zone, ZoneModel, ZonePairPolicy,
    };

    fn make_zone(id: &str, name: &str, sl: SecurityLevel, levels: Vec<u8>) -> Zone {
        Zone {
            id: id.to_string(),
            name: name.to_string(),
            purdue_levels: levels,
            policy_group_ids: Vec::new(),
            security_level: sl,
            asset_count: 1,
        }
    }

    fn make_asset(ip: &str, purdue: u8) -> AssetProfile {
        AssetProfile {
            ip: ip.to_string(),
            mac: None,
            hostname: None,
            vendor: None,
            device_type: "plc".to_string(),
            product_name: None,
            purdue_level: Some(purdue),
            protocols: vec!["modbus".to_string()],
            protocol_roles: Vec::new(),
            confidence: 3,
            criticality: None,
            subnet: None,
            is_ot: true,
            is_it: false,
            is_dual_homed: false,
            connection_count: 10,
            has_cves: false,
            has_default_creds: false,
        }
    }

    fn make_conn(src: &str, dst: &str, proto: &str, port: u16) -> ObservedConnection {
        ObservedConnection {
            src_ip: src.to_string(),
            src_port: 50000,
            dst_ip: dst.to_string(),
            dst_port: port,
            protocol: proto.to_string(),
            packet_count: 100,
            byte_count: 10000,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T01:00:00Z".to_string(),
            is_periodic: false,
            pattern_anomaly: false,
            has_write_operations: false,
            has_read_operations: true,
            has_config_operations: false,
            attack_techniques: Vec::new(),
            is_in_allowlist: false,
        }
    }

    fn make_matrix_with_rule(
        src_zone: &str,
        dst_zone: &str,
        proto: &str,
        port: Option<u16>,
    ) -> CommunicationMatrix {
        CommunicationMatrix {
            zone_pairs: vec![ZonePairPolicy {
                src_zone_id: src_zone.to_string(),
                dst_zone_id: dst_zone.to_string(),
                rules: vec![PolicyRule {
                    protocol: proto.to_string(),
                    dst_port: port,
                    risk: RuleRisk::Low,
                    justification: "test rule".to_string(),
                    packet_count: 10,
                }],
            }],
            default_action: "deny".to_string(),
            coverage_percent: 100.0,
        }
    }

    fn empty_zone_model(zones: Vec<Zone>) -> ZoneModel {
        ZoneModel {
            zones,
            conduits: Vec::new(),
            zone_score: 1.0,
            recommendations: Vec::new(),
        }
    }

    // ── Test 1: All intra-zone connections allowed ──────────────────────────

    #[test]
    fn test_all_intra_zone() {
        // Both assets in L1 → same zone; intra-zone rule present.
        let zone = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let assets = vec![make_asset("10.0.1.1", 1), make_asset("10.0.1.2", 1)];
        let conns = vec![make_conn("10.0.1.1", "10.0.1.2", "modbus", 502)];
        let matrix = make_matrix_with_rule("z1", "z1", "modbus", Some(502));
        let zone_model = empty_zone_model(vec![zone]);
        let input = SegmentationInput {
            assets,
            connections: conns,
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        assert_eq!(result.allowed, 1);
        assert_eq!(result.blocked, 0);
        assert_eq!(result.blocked_percent, 0.0);
    }

    // ── Test 2: All connections allowed (cross-zone rule present) ───────────

    #[test]
    fn test_all_allowed() {
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let z2 = make_zone("z2", "Supervisory", SecurityLevel::Sl2, vec![2]);
        let assets = vec![make_asset("10.0.1.1", 1), make_asset("10.0.2.1", 2)];
        let conns = vec![make_conn("10.0.2.1", "10.0.1.1", "modbus", 502)];
        let matrix = make_matrix_with_rule("z2", "z1", "modbus", Some(502));
        let zone_model = empty_zone_model(vec![z1, z2]);
        let input = SegmentationInput {
            assets,
            connections: conns,
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        assert_eq!(result.allowed, 1);
        assert_eq!(result.blocked, 0);
    }

    // ── Test 3: Blocked when no conduit/rule exists ─────────────────────────

    #[test]
    fn test_blocked_no_conduit() {
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let z2 = make_zone("z2", "Enterprise", SecurityLevel::Sl1, vec![4]);
        let assets = vec![make_asset("10.0.1.1", 1), make_asset("10.0.4.1", 4)];
        // Connection from z2 to z1 — no rule allowing it.
        let conns = vec![make_conn("10.0.4.1", "10.0.1.1", "modbus", 502)];
        let matrix = CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        };
        let zone_model = empty_zone_model(vec![z1, z2]);
        let input = SegmentationInput {
            assets,
            connections: conns,
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        assert_eq!(result.blocked, 1);
        assert_eq!(result.allowed, 0);
        assert_eq!(result.critical_blocks.len(), 1);
        assert!(result.critical_blocks[0]
            .reason
            .contains("No rule allows modbus"));
    }

    // ── Test 4: Blocked when wrong port ─────────────────────────────────────

    #[test]
    fn test_blocked_wrong_port() {
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let z2 = make_zone("z2", "Supervisory", SecurityLevel::Sl2, vec![2]);
        let assets = vec![make_asset("10.0.1.1", 1), make_asset("10.0.2.1", 2)];
        // Rule is for port 502 only; connection is on port 503.
        let conns = vec![make_conn("10.0.2.1", "10.0.1.1", "modbus", 503)];
        let matrix = make_matrix_with_rule("z2", "z1", "modbus", Some(502));
        let zone_model = empty_zone_model(vec![z1, z2]);
        let input = SegmentationInput {
            assets,
            connections: conns,
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        assert_eq!(result.blocked, 1);
        assert_eq!(result.allowed, 0);
    }

    // ── Test 5: Critical block flagged correctly ─────────────────────────────

    #[test]
    fn test_critical_block() {
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let z2 = make_zone("z2", "Enterprise", SecurityLevel::Sl1, vec![4]);
        let assets = vec![make_asset("10.0.1.1", 1), make_asset("10.0.4.1", 4)];
        let mut conn = make_conn("10.0.4.1", "10.0.1.1", "s7comm", 102);
        conn.has_write_operations = true; // Not a false positive.
        let matrix = CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        };
        let zone_model = empty_zone_model(vec![z1, z2]);
        let input = SegmentationInput {
            assets,
            connections: vec![conn],
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        assert_eq!(result.critical_blocks.len(), 1);
        assert_eq!(result.false_positive_candidates.len(), 0);
        assert!(!result.critical_blocks[0].is_false_positive_candidate);
    }

    // ── Test 6: False positive detection ────────────────────────────────────

    #[test]
    fn test_false_positive() {
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let z2 = make_zone("z2", "Supervisory", SecurityLevel::Sl2, vec![2]);
        let assets = vec![make_asset("10.0.1.1", 1), make_asset("10.0.2.1", 2)];
        let mut conn = make_conn("10.0.2.1", "10.0.1.1", "modbus", 502);
        // Periodic, read-only, allowlisted — should be flagged as FP.
        conn.is_periodic = true;
        conn.has_write_operations = false;
        conn.is_in_allowlist = true;
        let matrix = CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        };
        let zone_model = empty_zone_model(vec![z1, z2]);
        let input = SegmentationInput {
            assets,
            connections: vec![conn],
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        assert_eq!(result.false_positive_candidates.len(), 1);
        assert_eq!(result.critical_blocks.len(), 0);
        assert!(result.false_positive_candidates[0].is_false_positive_candidate);
    }

    // ── Test 7: Risk reduction score ─────────────────────────────────────────

    #[test]
    fn test_risk_reduction() {
        // One zone, one asset.  A critical finding is attached to that asset.
        // Because the zone has no outbound allowed pairs, the finding is "blocked"
        // → risk_reduction = 4/4 = 1.0.
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let assets = vec![make_asset("10.0.1.1", 1)];
        let matrix = CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        };
        let zone_model = empty_zone_model(vec![z1]);
        let finding = SecurityFinding {
            id: "F1".to_string(),
            technique_id: Some("T0855".to_string()),
            severity: "critical".to_string(),
            affected_ips: vec!["10.0.1.1".to_string()],
            description: "Unauthorized command".to_string(),
        };
        let input = SegmentationInput {
            assets,
            connections: Vec::new(),
            findings: vec![finding],
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        // Isolated zone → finding blocked → risk_reduction_score = 1.0
        assert!(
            (result.risk_reduction_score - 1.0).abs() < 0.001,
            "expected ~1.0 got {}",
            result.risk_reduction_score
        );
    }

    // ── Test 8: Deployment score ──────────────────────────────────────────────

    #[test]
    fn test_deployment_score() {
        // Two zones: SL3 (weight 3) and SL1 (weight 1).
        // Only the SL3 zone appears in the matrix.
        // Expected deployment score = 3 / (3 + 1) = 0.75.
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let z2 = make_zone("z2", "Enterprise", SecurityLevel::Sl1, vec![4]);
        let assets = vec![make_asset("10.0.1.1", 1), make_asset("10.0.4.1", 4)];
        // Rule only for z1→z1 (SL3 covered); z2 (SL1) not in any rule.
        let matrix = make_matrix_with_rule("z1", "z1", "modbus", Some(502));
        let zone_model = empty_zone_model(vec![z1, z2]);
        let input = SegmentationInput {
            assets,
            connections: Vec::new(),
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        let expected = 3.0 / 4.0;
        assert!(
            (result.deployment_score - expected).abs() < 0.001,
            "expected {expected:.3} got {:.3}",
            result.deployment_score
        );
    }

    // ── Test 9: Empty zone model returns error ────────────────────────────────

    #[test]
    fn test_empty_zone_model_errors() {
        let zone_model = empty_zone_model(Vec::new());
        let matrix = CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        };
        let input = SegmentationInput::default();
        assert!(simulate_policy(&matrix, &zone_model, &input).is_err());
    }

    // ── Test 10: Wildcard port rule allows any port ───────────────────────────

    #[test]
    fn test_wildcard_port_rule() {
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let assets = vec![make_asset("10.0.1.1", 1), make_asset("10.0.1.2", 1)];
        // Wildcard port rule (port=None) should allow port 502 AND 503.
        let conns = vec![
            make_conn("10.0.1.1", "10.0.1.2", "modbus", 502),
            make_conn("10.0.1.1", "10.0.1.2", "modbus", 503),
        ];
        let matrix = make_matrix_with_rule("z1", "z1", "modbus", None);
        let zone_model = empty_zone_model(vec![z1]);
        let input = SegmentationInput {
            assets,
            connections: conns,
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        assert_eq!(result.allowed, 2);
        assert_eq!(result.blocked, 0);
    }

    // ── Test 11: run_simulation wrapper returns zero on empty input ───────────

    #[test]
    fn test_run_simulation_wrapper_empty() {
        let zone_model = empty_zone_model(Vec::new()); // Will fail simulate_policy.
        let matrix = CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        };
        let input = SegmentationInput::default();
        let result = run_simulation(&zone_model, &matrix, &input);
        assert_eq!(result.allowed, 0);
        assert_eq!(result.blocked, 0);
    }

    // ── Test 12: zone_block_summaries counts per zone pair ────────────────────

    #[test]
    fn test_zone_block_summaries() {
        let z1 = make_zone("z1", "Control", SecurityLevel::Sl3, vec![1]);
        let z2 = make_zone("z2", "Enterprise", SecurityLevel::Sl1, vec![4]);
        let assets = vec![
            make_asset("10.0.1.1", 1),
            make_asset("10.0.1.2", 1),
            make_asset("10.0.4.1", 4),
        ];
        // Two blocked connections from z2→z1.
        let conns = vec![
            make_conn("10.0.4.1", "10.0.1.1", "modbus", 502),
            make_conn("10.0.4.1", "10.0.1.2", "modbus", 502),
        ];
        let matrix = CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        };
        let zone_model = empty_zone_model(vec![z1, z2]);
        let input = SegmentationInput {
            assets,
            connections: conns,
            findings: Vec::new(),
        };

        let result = simulate_policy(&matrix, &zone_model, &input).unwrap();
        assert_eq!(result.zone_block_summaries.len(), 1);
        assert_eq!(result.zone_block_summaries[0].blocked_count, 2);
    }
}
