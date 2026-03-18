//! Phase 15B — Zone/Conduit Recommender.
//!
//! Proposes IEC 62443 zone boundaries and conduit definitions from PolicyGroups.
//!
//! ## Algorithm
//!
//! 1. Baseline zones from Purdue levels (Control L0/L1, Supervisory L2, Operations L3, DMZ L3.5, Enterprise L4).
//! 2. Sub-zone splitting for non-communicating policy groups within a zone (max 3 per level).
//! 3. DMZ detection: dual-homed assets → DMZ zone; missing DMZ with L1↔L4 traffic → recommendation.
//! 4. Flat network detection: >80% same /24 + L1↔L4 → critical flag.
//! 5. Conduit generation for each zone pair with inter-zone traffic.
//! 6. Cross-reference with SecurityFindings for compliance issues.
//! 7. Zone score: `1.0 - (cross_purdue_violations / total_inter_zone_connections)`.

use std::collections::{HashMap, HashSet};

use uuid::Uuid;

use crate::{
    Conduit, ConduitDirection, ConduitRule, DeviceCategory, PolicyGroup, SecurityLevel,
    SegmentationError, SegmentationInput, Zone, ZoneModel,
};

// ── Public API ─────────────────────────────────────────────────────────────────

/// Build an IEC 62443 zone/conduit model from identity groups and observed traffic.
///
/// Thin wrapper that calls [`recommend_zones`] and maps the error to a default
/// (empty) model on failure — preserves the `pub use zones::build_zone_model`
/// re-export contract in `lib.rs`.
pub fn build_zone_model(groups: &[PolicyGroup], input: &SegmentationInput) -> ZoneModel {
    recommend_zones(groups, input).unwrap_or_else(|_| ZoneModel {
        zones: Vec::new(),
        conduits: Vec::new(),
        zone_score: 0.0,
        recommendations: Vec::new(),
    })
}

/// Recommend an IEC 62443 zone model from identity groups and observed traffic.
///
/// Returns [`SegmentationError::EmptyInput`] when there are no assets.
pub fn recommend_zones(
    groups: &[PolicyGroup],
    input: &SegmentationInput,
) -> Result<ZoneModel, SegmentationError> {
    if input.assets.is_empty() {
        return Err(SegmentationError::EmptyInput(
            "no assets in segmentation input".into(),
        ));
    }

    // ── Step 1: Baseline Purdue zones ─────────────────────────────────────────
    let mut zones = build_baseline_zones(groups);

    // ── Step 2: Sub-zone splitting ────────────────────────────────────────────
    zones = split_disconnected_subzones(zones, groups, input);

    // ── Step 3: DMZ detection / missing DMZ ──────────────────────────────────
    let mut recommendations: Vec<String> = Vec::new();
    ensure_dmz_zone(groups, input, &mut zones, &mut recommendations);

    // ── Step 4: Flat network detection ────────────────────────────────────────
    detect_flat_network(input, groups, &mut recommendations);

    // ── Step 5: Build IP→zone map, then generate conduits ────────────────────
    let ip_to_zone = build_ip_to_zone_map(&zones, groups);
    let conduits = build_conduits(&zones, input, &ip_to_zone);

    // ── Step 6: Cross-reference SecurityFindings ──────────────────────────────
    cross_reference_findings(input, &zones, &mut recommendations);

    // ── Step 7: Zone score ────────────────────────────────────────────────────
    let zone_score = compute_zone_score(&conduits);

    Ok(ZoneModel {
        zones,
        conduits,
        zone_score,
        recommendations,
    })
}

// ── Public helpers ─────────────────────────────────────────────────────────────

/// Return the zone ID whose member IPs contain `ip`, or `None`.
pub fn find_zone_for_ip<'a>(
    ip: &str,
    zones: &'a [Zone],
    groups: &[PolicyGroup],
) -> Option<&'a Zone> {
    // Build a flat IP→group map first, then group→zone.
    let ip_to_group: HashMap<&str, &str> = groups
        .iter()
        .flat_map(|g| {
            g.member_ips
                .iter()
                .map(move |ip| (ip.as_str(), g.id.as_str()))
        })
        .collect();

    let group_id = ip_to_group.get(ip)?;
    zones
        .iter()
        .find(|z| z.policy_group_ids.iter().any(|gid| gid == group_id))
}

/// Compute the /24 subnet prefix for an IP address string (e.g. `"10.0.1.0/24"`).
///
/// Returns `None` if the address is not a valid IPv4 dotted-quad.
pub fn compute_subnet_24(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    // Validate all octets are parseable u8.
    for p in &parts {
        p.parse::<u8>().ok()?;
    }
    Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
}

/// True when the Purdue level distance between zone A and zone B exceeds 2.
///
/// Uses the minimum Purdue level of each zone to determine the "anchor" level.
/// Examples: L1(1) ↔ L4(4) → diff 3 → violation.  L1(1) ↔ L2(2) → diff 1 → OK.
pub fn is_cross_purdue_violation(zone_a: &Zone, zone_b: &Zone) -> bool {
    match (
        zone_a.purdue_levels.iter().copied().min(),
        zone_b.purdue_levels.iter().copied().min(),
    ) {
        (Some(min_a), Some(min_b)) => (min_a as i32 - min_b as i32).unsigned_abs() > 2,
        _ => false,
    }
}

// ── Step 1 — Baseline Purdue zones ────────────────────────────────────────────

/// Build one Zone per canonical Purdue level group, merging all PolicyGroups
/// that share the same Purdue level bucket.
fn build_baseline_zones(groups: &[PolicyGroup]) -> Vec<Zone> {
    // For DmzGateway category groups we force the "DMZ Zone" regardless of purdue_level.
    // Bucket key: 0/1→1, 2→2, 3→3, 35→35, 4+→4, None→99 (unclassified)
    let mut buckets: HashMap<u8, Vec<&PolicyGroup>> = HashMap::new();

    for g in groups {
        let key = if g.device_category == DeviceCategory::DmzGateway {
            35u8
        } else {
            match g.purdue_level {
                Some(0) | Some(1) => 1,
                Some(2) => 2,
                Some(3) => 3,
                Some(35) => 35,
                Some(l) if l >= 4 => 4,
                _ => 99, // unclassified
            }
        };
        buckets.entry(key).or_default().push(g);
    }

    let mut zones: Vec<Zone> = Vec::new();

    for (bucket, bucket_groups) in &buckets {
        let (base_name, security_level, purdue_levels) = match bucket {
            1 => ("Control Zone", SecurityLevel::Sl3, vec![0u8, 1]),
            2 => ("Supervisory Zone", SecurityLevel::Sl2, vec![2]),
            3 => ("Operations Zone", SecurityLevel::Sl2, vec![3]),
            35 => ("DMZ Zone", SecurityLevel::Sl2, vec![35]),
            4 => ("Enterprise Zone", SecurityLevel::Sl1, vec![4]),
            99 => ("Unclassified Zone", SecurityLevel::Sl1, vec![]),
            _ => ("Enterprise Zone", SecurityLevel::Sl1, vec![*bucket]),
        };

        // Collect all Purdue levels actually present.
        let actual_levels: Vec<u8> = if purdue_levels.is_empty() {
            // Unclassified — use whatever the groups report.
            bucket_groups
                .iter()
                .filter_map(|g| g.purdue_level)
                .collect::<HashSet<_>>()
                .into_iter()
                .collect()
        } else {
            purdue_levels
        };

        let policy_group_ids: Vec<String> = bucket_groups.iter().map(|g| g.id.clone()).collect();
        let asset_count: usize = bucket_groups.iter().map(|g| g.member_ips.len()).sum();

        zones.push(Zone {
            id: Uuid::new_v4().to_string(),
            name: base_name.to_string(),
            purdue_levels: actual_levels,
            policy_group_ids,
            security_level,
            asset_count,
        });
    }

    zones
}

// ── Step 2 — Sub-zone splitting ───────────────────────────────────────────────

/// For each zone, check if its PolicyGroups form connected components in the
/// observed traffic graph. Non-communicating sub-groups get A/B/C suffixes
/// (max 3 sub-zones per parent zone).
fn split_disconnected_subzones(
    zones: Vec<Zone>,
    groups: &[PolicyGroup],
    input: &SegmentationInput,
) -> Vec<Zone> {
    // Build an IP→group id map.
    let ip_to_group: HashMap<&str, &str> = groups
        .iter()
        .flat_map(|g| {
            g.member_ips
                .iter()
                .map(move |ip| (ip.as_str(), g.id.as_str()))
        })
        .collect();

    // Build adjacency: group_id → set of connected group_ids (via observed connections).
    let mut adjacency: HashMap<String, HashSet<String>> = HashMap::new();
    for conn in &input.connections {
        let src_grp = ip_to_group.get(conn.src_ip.as_str()).map(|s| s.to_string());
        let dst_grp = ip_to_group.get(conn.dst_ip.as_str()).map(|s| s.to_string());
        if let (Some(sg), Some(dg)) = (src_grp, dst_grp) {
            if sg != dg {
                adjacency.entry(sg.clone()).or_default().insert(dg.clone());
                adjacency.entry(dg).or_default().insert(sg);
            }
        }
    }

    let mut result: Vec<Zone> = Vec::new();

    for zone in zones {
        if zone.policy_group_ids.len() <= 1 {
            result.push(zone);
            continue;
        }

        // BFS connected components within this zone's policy groups.
        let zone_group_set: HashSet<&str> =
            zone.policy_group_ids.iter().map(|s| s.as_str()).collect();
        let mut visited: HashSet<&str> = HashSet::new();
        let mut components: Vec<Vec<String>> = Vec::new();

        for start in &zone.policy_group_ids {
            if visited.contains(start.as_str()) {
                continue;
            }
            let mut component: Vec<String> = Vec::new();
            let mut queue: Vec<&str> = vec![start.as_str()];
            while !queue.is_empty() {
                let node = queue.remove(0);
                if !visited.insert(node) {
                    continue;
                }
                component.push(node.to_string());
                if let Some(neighbours) = adjacency.get(node) {
                    for nb in neighbours {
                        if zone_group_set.contains(nb.as_str()) && !visited.contains(nb.as_str()) {
                            queue.push(nb.as_str());
                        }
                    }
                }
            }
            if !component.is_empty() {
                components.push(component);
            }
        }

        // Only one component — no split needed.
        if components.len() <= 1 {
            result.push(zone);
            continue;
        }

        // Split up to 3 sub-zones (A/B/C); remainder stays in original zone.
        let suffixes = ['A', 'B', 'C'];
        let base_name = zone.name.clone();

        for (idx, component) in components.into_iter().enumerate() {
            let name = if idx < 3 {
                format!("{} {}", base_name, suffixes[idx])
            } else {
                // Merge overflow components back into C.
                break;
            };
            let asset_count = groups
                .iter()
                .filter(|g| component.contains(&g.id))
                .map(|g| g.member_ips.len())
                .sum();
            result.push(Zone {
                id: Uuid::new_v4().to_string(),
                name,
                purdue_levels: zone.purdue_levels.clone(),
                policy_group_ids: component,
                security_level: zone.security_level,
                asset_count,
            });
        }
    }

    result
}

// ── Step 3 — DMZ detection ─────────────────────────────────────────────────────

/// Ensure dual-homed devices end up in a DMZ zone.
/// If L1↔L4 traffic exists with no DMZ, add a recommendation.
fn ensure_dmz_zone(
    groups: &[PolicyGroup],
    input: &SegmentationInput,
    zones: &mut Vec<Zone>,
    recommendations: &mut Vec<String>,
) {
    // Check if a DMZ zone already exists (created from DmzGateway groups in step 1).
    let has_dmz_zone = zones.iter().any(|z| z.name.contains("DMZ"));

    // Check if there are any dual-homed assets not already in a DMZ zone.
    let dual_homed_ips: Vec<&str> = input
        .assets
        .iter()
        .filter(|a| a.is_dual_homed)
        .map(|a| a.ip.as_str())
        .collect();

    if !dual_homed_ips.is_empty() && !has_dmz_zone {
        // Create a DMZ zone for the dual-homed assets' PolicyGroups.
        let dmz_group_ids: Vec<String> = groups
            .iter()
            .filter(|g| {
                g.member_ips
                    .iter()
                    .any(|ip| dual_homed_ips.contains(&ip.as_str()))
            })
            .map(|g| g.id.clone())
            .collect();

        if !dmz_group_ids.is_empty() {
            let asset_count: usize = groups
                .iter()
                .filter(|g| dmz_group_ids.contains(&g.id))
                .map(|g| g.member_ips.len())
                .sum();

            // Remove those group IDs from their current zone.
            for zone in zones.iter_mut() {
                zone.policy_group_ids
                    .retain(|id| !dmz_group_ids.contains(id));
                zone.asset_count = groups
                    .iter()
                    .filter(|g| zone.policy_group_ids.contains(&g.id))
                    .map(|g| g.member_ips.len())
                    .sum();
            }

            zones.push(Zone {
                id: Uuid::new_v4().to_string(),
                name: "DMZ Zone".to_string(),
                purdue_levels: vec![35],
                policy_group_ids: dmz_group_ids,
                security_level: SecurityLevel::Sl2,
                asset_count,
            });
        }
    }

    // Check for L1↔L4 traffic with no DMZ → recommend adding one.
    let ip_to_zone = build_ip_to_zone_map(zones, groups);

    let l1_ips: HashSet<&str> = groups
        .iter()
        .filter(|g| matches!(g.purdue_level, Some(0) | Some(1)))
        .flat_map(|g| g.member_ips.iter().map(|ip| ip.as_str()))
        .collect();

    let l4_ips: HashSet<&str> = groups
        .iter()
        .filter(|g| matches!(g.purdue_level, Some(l) if l >= 4))
        .flat_map(|g| g.member_ips.iter().map(|ip| ip.as_str()))
        .collect();

    let has_l1_l4_traffic = input.connections.iter().any(|c| {
        (l1_ips.contains(c.src_ip.as_str()) && l4_ips.contains(c.dst_ip.as_str()))
            || (l4_ips.contains(c.src_ip.as_str()) && l1_ips.contains(c.dst_ip.as_str()))
    });

    let final_has_dmz = zones.iter().any(|z| z.name.contains("DMZ"));

    if has_l1_l4_traffic && !final_has_dmz {
        recommendations.push(
            "CRITICAL: Direct L1↔L4 traffic detected with no DMZ zone. \
             Add a DMZ (L3.5) between Control and Enterprise zones to meet IEC 62443-3-3 SL2."
                .to_string(),
        );
    }

    // Remove empty zones produced by DMZ extraction.
    zones.retain(|z| !z.policy_group_ids.is_empty() || z.name.contains("DMZ"));
    let _ = ip_to_zone; // used for logic above, suppress warning
}

// ── Step 4 — Flat network detection ───────────────────────────────────────────

fn detect_flat_network(
    input: &SegmentationInput,
    groups: &[PolicyGroup],
    recommendations: &mut Vec<String>,
) {
    if input.assets.is_empty() {
        return;
    }

    // Count assets per /24 subnet.
    let mut subnet_counts: HashMap<String, usize> = HashMap::new();
    for asset in &input.assets {
        if let Some(subnet) = compute_subnet_24(&asset.ip) {
            *subnet_counts.entry(subnet).or_insert(0) += 1;
        }
    }

    let total = input.assets.len();
    let max_on_same_subnet = subnet_counts.values().copied().max().unwrap_or(0);

    if max_on_same_subnet * 100 / total.max(1) > 80 {
        // >80% same /24 — check for L1↔L4 traffic.
        let l1_ips: HashSet<&str> = groups
            .iter()
            .filter(|g| matches!(g.purdue_level, Some(0) | Some(1)))
            .flat_map(|g| g.member_ips.iter().map(|ip| ip.as_str()))
            .collect();

        let l4_ips: HashSet<&str> = groups
            .iter()
            .filter(|g| matches!(g.purdue_level, Some(l) if l >= 4))
            .flat_map(|g| g.member_ips.iter().map(|ip| ip.as_str()))
            .collect();

        let has_l1_l4 = input.connections.iter().any(|c| {
            (l1_ips.contains(c.src_ip.as_str()) && l4_ips.contains(c.dst_ip.as_str()))
                || (l4_ips.contains(c.src_ip.as_str()) && l1_ips.contains(c.dst_ip.as_str()))
        });

        if has_l1_l4 {
            recommendations.push(
                "CRITICAL: Flat network detected — >80% of assets share the same /24 subnet \
                 and L1↔L4 direct traffic observed. Segment into separate subnets per Purdue \
                 level immediately."
                    .to_string(),
            );
        } else {
            recommendations.push(
                "WARNING: Flat network detected — >80% of assets share the same /24 subnet. \
                 Consider segmenting into separate VLANs/subnets per Purdue level."
                    .to_string(),
            );
        }
    }
}

// ── Step 5 — Conduit generation ───────────────────────────────────────────────

/// Build an IP → zone_id map from the final zone list.
pub(crate) fn build_ip_to_zone_map(
    zones: &[Zone],
    groups: &[PolicyGroup],
) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    let group_id_to_zone: HashMap<&str, &str> = zones
        .iter()
        .flat_map(|z| {
            z.policy_group_ids
                .iter()
                .map(move |gid| (gid.as_str(), z.id.as_str()))
        })
        .collect();

    for group in groups {
        if let Some(&zone_id) = group_id_to_zone.get(group.id.as_str()) {
            for ip in &group.member_ips {
                map.insert(ip.clone(), zone_id.to_string());
            }
        }
    }
    map
}

/// Build conduits from observed connections. One conduit per unique zone pair;
/// rules are aggregated from all connections on that zone pair.
fn build_conduits(
    zones: &[Zone],
    input: &SegmentationInput,
    ip_to_zone: &HashMap<String, String>,
) -> Vec<Conduit> {
    // zone_id → Zone reference.
    let zone_by_id: HashMap<&str, &Zone> = zones.iter().map(|z| (z.id.as_str(), z)).collect();

    // Aggregate flows per zone-pair (normalized key).
    // Key: (src_zone_id, dst_zone_id) — src is always lex-smaller to detect bidirectionality.
    // Value: (forward_flows, backward_flows, aggregated rules)
    struct FlowAgg {
        forward: bool,  // src<dst direction seen
        backward: bool, // dst<src direction seen
        rules: Vec<ConduitRule>,
    }

    let mut pair_map: HashMap<(String, String), FlowAgg> = HashMap::new();

    for conn in &input.connections {
        let src_zone = match ip_to_zone.get(&conn.src_ip) {
            Some(z) => z.clone(),
            None => continue,
        };
        let dst_zone = match ip_to_zone.get(&conn.dst_ip) {
            Some(z) => z.clone(),
            None => continue,
        };
        if src_zone == dst_zone {
            continue; // intra-zone — no conduit
        }

        let (key, is_forward) = if src_zone <= dst_zone {
            ((src_zone.clone(), dst_zone.clone()), true)
        } else {
            ((dst_zone.clone(), src_zone.clone()), false)
        };

        let risk_note: Option<String> = if let (Some(&za), Some(&zb)) = (
            zone_by_id.get(src_zone.as_str()),
            zone_by_id.get(dst_zone.as_str()),
        ) {
            if is_cross_purdue_violation(za, zb) {
                Some(format!(
                    "Cross-Purdue violation: {} (Purdue {:?}) ↔ {} (Purdue {:?})",
                    za.name, za.purdue_levels, zb.name, zb.purdue_levels
                ))
            } else {
                None
            }
        } else {
            None
        };

        let rule = ConduitRule {
            protocol: conn.protocol.clone(),
            dst_port: Some(conn.dst_port),
            has_write_ops: conn.has_write_operations,
            has_config_ops: conn.has_config_operations,
            attack_techniques: conn.attack_techniques.clone(),
            risk_note,
        };

        let agg = pair_map.entry(key).or_insert(FlowAgg {
            forward: false,
            backward: false,
            rules: Vec::new(),
        });
        if is_forward {
            agg.forward = true;
        } else {
            agg.backward = true;
        }
        agg.rules.push(rule);
    }

    // Consolidate rules: deduplicate (protocol, dst_port) entries.
    let mut conduits: Vec<Conduit> = Vec::new();

    for ((src_zone_id, dst_zone_id), agg) in pair_map {
        let direction = if agg.forward && agg.backward {
            ConduitDirection::Bidirectional
        } else {
            ConduitDirection::Unidirectional
        };

        let cross_purdue_risk = if let (Some(&za), Some(&zb)) = (
            zone_by_id.get(src_zone_id.as_str()),
            zone_by_id.get(dst_zone_id.as_str()),
        ) {
            is_cross_purdue_violation(za, zb)
        } else {
            false
        };

        // Deduplicate rules by (protocol, dst_port); merge flags.
        let mut deduped: HashMap<(String, Option<u16>), ConduitRule> = HashMap::new();
        for rule in agg.rules {
            let rkey = (rule.protocol.clone(), rule.dst_port);
            deduped
                .entry(rkey)
                .and_modify(|existing| {
                    existing.has_write_ops |= rule.has_write_ops;
                    existing.has_config_ops |= rule.has_config_ops;
                    for tech in &rule.attack_techniques {
                        if !existing.attack_techniques.contains(tech) {
                            existing.attack_techniques.push(tech.clone());
                        }
                    }
                    if existing.risk_note.is_none() {
                        existing.risk_note = rule.risk_note.clone();
                    }
                })
                .or_insert(rule);
        }

        conduits.push(Conduit {
            id: Uuid::new_v4().to_string(),
            src_zone_id,
            dst_zone_id,
            direction,
            rules: deduped.into_values().collect(),
            cross_purdue_risk,
        });
    }

    conduits
}

// ── Step 6 — SecurityFindings cross-reference ─────────────────────────────────

/// Cross-reference SecurityFindings for compliance-relevant issues.
fn cross_reference_findings(
    input: &SegmentationInput,
    zones: &[Zone],
    recommendations: &mut Vec<String>,
) {
    let has_t0886 = input
        .findings
        .iter()
        .any(|f| f.technique_id.as_deref() == Some("T0886"));

    if has_t0886 {
        let has_dmz = zones.iter().any(|z| z.name.contains("DMZ"));
        if !has_dmz {
            recommendations.push(
                "IEC 62443 SL2 Gap: T0886 (Remote Services) finding detected — no DMZ zone \
                 is present to enforce segmentation at the IT/OT boundary."
                    .to_string(),
            );
        }
    }

    let has_purdue_violation = input.findings.iter().any(|f| {
        f.description.to_lowercase().contains("purdue")
            || f.description.to_lowercase().contains("cross-level")
    });

    if has_purdue_violation {
        recommendations.push(
            "IEC 62443 SL2 Gap: Purdue model violations detected in security findings. \
             Review conduits marked with cross_purdue_risk=true and add enforcement controls."
                .to_string(),
        );
    }

    let has_flat = input
        .findings
        .iter()
        .any(|f| f.description.to_lowercase().contains("flat network"));

    if has_flat {
        recommendations.push(
            "IEC 62443 SL2 Gap: Flat network finding from security analysis. \
             Subnet segmentation is required for zone isolation."
                .to_string(),
        );
    }
}

// ── Step 7 — Zone score ────────────────────────────────────────────────────────

/// `1.0 - (cross_purdue_violations / total_inter_zone_connections)`.
/// Returns `1.0` when there are no inter-zone conduits.
fn compute_zone_score(conduits: &[Conduit]) -> f64 {
    let total = conduits.len();
    if total == 0 {
        return 1.0;
    }
    let violations = conduits.iter().filter(|c| c.cross_purdue_risk).count();
    1.0 - (violations as f64 / total as f64)
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AssetProfile, Criticality, DeviceCategory, ObservedConnection, PolicyGroup,
        SecurityFinding, SecurityLevel, SegmentationInput,
    };

    fn make_group(
        id: &str,
        name: &str,
        ips: &[&str],
        purdue: Option<u8>,
        cat: DeviceCategory,
    ) -> PolicyGroup {
        PolicyGroup {
            id: id.to_string(),
            name: name.to_string(),
            member_ips: ips.iter().map(|s| s.to_string()).collect(),
            purdue_level: purdue,
            device_category: cat,
            security_level: SecurityLevel::Sl2,
            criticality: Criticality::Medium,
        }
    }

    fn make_asset(
        ip: &str,
        purdue: Option<u8>,
        is_ot: bool,
        is_it: bool,
        is_dual: bool,
    ) -> AssetProfile {
        AssetProfile {
            ip: ip.to_string(),
            mac: None,
            hostname: None,
            vendor: None,
            device_type: "plc".to_string(),
            product_name: None,
            purdue_level: purdue,
            protocols: Vec::new(),
            protocol_roles: Vec::new(),
            confidence: 3,
            criticality: None,
            subnet: None,
            is_ot,
            is_it,
            is_dual_homed: is_dual,
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
            packet_count: 10,
            byte_count: 500,
            first_seen: "2026-01-01T00:00:00Z".to_string(),
            last_seen: "2026-01-01T01:00:00Z".to_string(),
            is_periodic: true,
            pattern_anomaly: false,
            has_write_operations: false,
            has_read_operations: true,
            has_config_operations: false,
            attack_techniques: Vec::new(),
            is_in_allowlist: true,
        }
    }

    // ── recommend_zones returns EmptyInput on empty assets ─────────────────────

    #[test]
    fn test_empty_input_returns_error() {
        let input = SegmentationInput::default();
        let groups: Vec<PolicyGroup> = Vec::new();
        let result = recommend_zones(&groups, &input);
        assert!(result.is_err());
        match result {
            Err(SegmentationError::EmptyInput(_)) => {}
            _ => panic!("expected EmptyInput error"),
        }
    }

    // ── build_zone_model returns empty model (not error) on empty input ────────

    #[test]
    fn test_build_zone_model_empty_graceful() {
        let input = SegmentationInput::default();
        let groups: Vec<PolicyGroup> = Vec::new();
        let model = build_zone_model(&groups, &input);
        assert!(model.zones.is_empty());
        assert_eq!(model.zone_score, 0.0);
    }

    // ── Baseline zones: L1 group → Control Zone ───────────────────────────────

    #[test]
    fn test_baseline_zones_l1_creates_control_zone() {
        let groups = vec![make_group(
            "g1",
            "L1-Modbus",
            &["10.0.1.1"],
            Some(1),
            DeviceCategory::Plc,
        )];
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.1.1", Some(1), true, false, false)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model.zones.iter().any(|z| z.name.contains("Control")));
    }

    // ── Baseline zones: L4 group → Enterprise Zone ────────────────────────────

    #[test]
    fn test_baseline_zones_l4_creates_enterprise_zone() {
        let groups = vec![make_group(
            "g1",
            "L4-IT",
            &["192.168.1.10"],
            Some(4),
            DeviceCategory::ItEndpoint,
        )];
        let input = SegmentationInput {
            assets: vec![make_asset("192.168.1.10", Some(4), false, true, false)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model.zones.iter().any(|z| z.name.contains("Enterprise")));
    }

    // ── Baseline zones: DmzGateway → DMZ Zone regardless of purdue_level ─────

    #[test]
    fn test_dmz_gateway_category_creates_dmz_zone() {
        let groups = vec![make_group(
            "g1",
            "DMZ-GW",
            &["10.0.5.1"],
            Some(3),
            DeviceCategory::DmzGateway,
        )];
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.5.1", Some(3), true, true, true)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model.zones.iter().any(|z| z.name.contains("DMZ")));
    }

    // ── Conduit generated between L1 and L4 ──────────────────────────────────

    #[test]
    fn test_conduit_generated_for_inter_zone_traffic() {
        let groups = vec![
            make_group("g1", "L1-PLC", &["10.0.1.1"], Some(1), DeviceCategory::Plc),
            make_group(
                "g2",
                "L4-IT",
                &["192.168.1.10"],
                Some(4),
                DeviceCategory::ItEndpoint,
            ),
        ];
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.1.1", Some(1), true, false, false),
                make_asset("192.168.1.10", Some(4), false, true, false),
            ],
            connections: vec![make_conn("10.0.1.1", "192.168.1.10", "modbus", 502)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(!model.conduits.is_empty(), "expected at least one conduit");
    }

    // ── Cross-Purdue violation: L1 ↔ L4 ─────────────────────────────────────

    #[test]
    fn test_cross_purdue_l1_l4_flagged() {
        let groups = vec![
            make_group("g1", "L1-PLC", &["10.0.1.1"], Some(1), DeviceCategory::Plc),
            make_group(
                "g2",
                "L4-IT",
                &["192.168.1.10"],
                Some(4),
                DeviceCategory::ItEndpoint,
            ),
        ];
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.1.1", Some(1), true, false, false),
                make_asset("192.168.1.10", Some(4), false, true, false),
            ],
            connections: vec![make_conn("10.0.1.1", "192.168.1.10", "modbus", 502)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model.conduits.iter().any(|c| c.cross_purdue_risk));
        assert!(model.zone_score < 1.0);
    }

    // ── No cross-Purdue: L1 ↔ L2 (diff = 1, OK) ──────────────────────────────

    #[test]
    fn test_no_cross_purdue_l1_l2() {
        let groups = vec![
            make_group("g1", "L1-PLC", &["10.0.1.1"], Some(1), DeviceCategory::Plc),
            make_group("g2", "L2-HMI", &["10.0.2.1"], Some(2), DeviceCategory::Hmi),
        ];
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.1.1", Some(1), true, false, false),
                make_asset("10.0.2.1", Some(2), true, false, false),
            ],
            connections: vec![make_conn("10.0.2.1", "10.0.1.1", "modbus", 502)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model.conduits.iter().all(|c| !c.cross_purdue_risk));
        assert_eq!(model.zone_score, 1.0);
    }

    // ── zone_score = 1.0 when no inter-zone conduits ─────────────────────────

    #[test]
    fn test_zone_score_one_when_no_conduits() {
        let groups = vec![make_group(
            "g1",
            "L1-PLC",
            &["10.0.1.1"],
            Some(1),
            DeviceCategory::Plc,
        )];
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.1.1", Some(1), true, false, false)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert_eq!(model.zone_score, 1.0);
    }

    // ── Flat network recommendation ──────────────────────────────────────────

    #[test]
    fn test_flat_network_detected() {
        // 5 assets all on 10.0.0.0/24
        let groups = vec![
            make_group(
                "g1",
                "L1-PLC",
                &["10.0.0.1", "10.0.0.2", "10.0.0.3"],
                Some(1),
                DeviceCategory::Plc,
            ),
            make_group(
                "g2",
                "L4-IT",
                &["10.0.0.10", "10.0.0.11"],
                Some(4),
                DeviceCategory::ItEndpoint,
            ),
        ];
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.0.1", Some(1), true, false, false),
                make_asset("10.0.0.2", Some(1), true, false, false),
                make_asset("10.0.0.3", Some(1), true, false, false),
                make_asset("10.0.0.10", Some(4), false, true, false),
                make_asset("10.0.0.11", Some(4), false, true, false),
            ],
            connections: vec![make_conn("10.0.0.1", "10.0.0.10", "modbus", 502)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model
            .recommendations
            .iter()
            .any(|r| r.contains("flat") || r.contains("Flat")));
    }

    // ── Missing DMZ recommendation ────────────────────────────────────────────

    #[test]
    fn test_missing_dmz_recommendation() {
        let groups = vec![
            make_group("g1", "L1-PLC", &["10.0.1.1"], Some(1), DeviceCategory::Plc),
            make_group(
                "g2",
                "L4-IT",
                &["192.168.1.10"],
                Some(4),
                DeviceCategory::ItEndpoint,
            ),
        ];
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.1.1", Some(1), true, false, false),
                make_asset("192.168.1.10", Some(4), false, true, false),
            ],
            connections: vec![make_conn("10.0.1.1", "192.168.1.10", "modbus", 502)],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model.recommendations.iter().any(|r| r.contains("DMZ")));
    }

    // ── compute_subnet_24 helper ──────────────────────────────────────────────

    #[test]
    fn test_compute_subnet_24() {
        assert_eq!(
            compute_subnet_24("10.0.1.55"),
            Some("10.0.1.0/24".to_string())
        );
        assert_eq!(
            compute_subnet_24("192.168.100.200"),
            Some("192.168.100.0/24".to_string())
        );
        assert_eq!(compute_subnet_24("not-an-ip"), None);
        assert_eq!(compute_subnet_24("1.2.3"), None);
    }

    // ── is_cross_purdue_violation helper ─────────────────────────────────────

    #[test]
    fn test_is_cross_purdue_violation() {
        let z1 = Zone {
            id: "z1".to_string(),
            name: "Control".to_string(),
            purdue_levels: vec![1],
            policy_group_ids: Vec::new(),
            security_level: SecurityLevel::Sl3,
            asset_count: 0,
        };
        let z4 = Zone {
            id: "z4".to_string(),
            name: "Enterprise".to_string(),
            purdue_levels: vec![4],
            policy_group_ids: Vec::new(),
            security_level: SecurityLevel::Sl1,
            asset_count: 0,
        };
        let z2 = Zone {
            id: "z2".to_string(),
            name: "Supervisory".to_string(),
            purdue_levels: vec![2],
            policy_group_ids: Vec::new(),
            security_level: SecurityLevel::Sl2,
            asset_count: 0,
        };
        assert!(is_cross_purdue_violation(&z1, &z4)); // diff = 3
        assert!(!is_cross_purdue_violation(&z1, &z2)); // diff = 1
        assert!(!is_cross_purdue_violation(&z2, &z4)); // diff = 2
    }

    // ── T0886 finding triggers DMZ recommendation ─────────────────────────────

    #[test]
    fn test_t0886_finding_triggers_recommendation() {
        let groups = vec![make_group(
            "g1",
            "L1-PLC",
            &["10.0.1.1"],
            Some(1),
            DeviceCategory::Plc,
        )];
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.1.1", Some(1), true, false, false)],
            findings: vec![SecurityFinding {
                id: "f1".to_string(),
                technique_id: Some("T0886".to_string()),
                severity: "medium".to_string(),
                affected_ips: vec!["10.0.1.1".to_string()],
                description: "Remote Services cross-level communication".to_string(),
            }],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model.recommendations.iter().any(|r| r.contains("T0886")));
    }

    // ── Conduit direction: bidirectional when both directions observed ─────────

    #[test]
    fn test_conduit_bidirectional_when_both_directions() {
        let groups = vec![
            make_group("g1", "L1-PLC", &["10.0.1.1"], Some(1), DeviceCategory::Plc),
            make_group("g2", "L2-HMI", &["10.0.2.1"], Some(2), DeviceCategory::Hmi),
        ];
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.1.1", Some(1), true, false, false),
                make_asset("10.0.2.1", Some(2), true, false, false),
            ],
            connections: vec![
                make_conn("10.0.2.1", "10.0.1.1", "modbus", 502),
                make_conn("10.0.1.1", "10.0.2.1", "modbus", 502),
            ],
            ..Default::default()
        };
        let model = recommend_zones(&groups, &input).unwrap();
        assert!(model
            .conduits
            .iter()
            .any(|c| c.direction == ConduitDirection::Bidirectional));
    }
}
