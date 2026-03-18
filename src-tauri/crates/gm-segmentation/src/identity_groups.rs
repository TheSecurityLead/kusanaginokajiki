//! Phase 15A — Identity Group Engine.
//!
//! Clusters every discovered asset into exactly one [`PolicyGroup`] by identity
//! attributes (Purdue level, protocol role, vendor, communication community).
//!
//! ## Algorithm
//!
//! 1. **Primary partition** by Purdue level (unassigned → separate pool).
//! 2. **Secondary partition** by device role within each level:
//!    - L0/L1: protocol server role (Modbus slave, DNP3 outstation, S7 server, EtherNet/IP adapter, …)
//!    - L2: HMI (read clients) vs Engineering (config/program operations observed)
//!    - L3: Historian vs SCADA server vs dual-homed DMZ gateway
//!    - L4+: by IT protocol type (web, remote access, other)
//! 3. **Tertiary vendor split** — split a role subgroup by vendor only if the
//!    vendor subgroups communicate with disjoint peer sets (Jaccard similarity
//!    of neighbor sets < 0.3). Otherwise keep together.
//! 4. **Community detection** for unassigned assets — greedy clustering by
//!    neighbor overlap (merge into existing community if Jaccard > 0.6).
//! 5. **Auto-naming, SecurityLevel, Criticality** assignment.

use std::collections::{HashMap, HashSet};

use crate::{
    AssetProfile, Criticality, DeviceCategory, ObservedConnection, PolicyGroup, SecurityLevel,
    SegmentationInput,
};

// ── Public entry point ────────────────────────────────────────────────────────

/// Build identity-based policy groups from the segmentation input.
///
/// Returns one [`PolicyGroup`] per identity cluster. Every asset in
/// `input.assets` ends up in exactly one group.
pub fn build_policy_groups(input: &SegmentationInput) -> Vec<PolicyGroup> {
    // Build per-IP neighbor sets (used for vendor split and community detection).
    let neighbor_sets = build_neighbor_sets(&input.connections);

    // Step 1: Partition by Purdue level.
    let mut by_level: HashMap<Option<u8>, Vec<&AssetProfile>> = HashMap::new();
    for asset in &input.assets {
        by_level.entry(asset.purdue_level).or_default().push(asset);
    }

    // Process levels in sorted order for deterministic output.
    let mut sorted_keys: Vec<Option<u8>> = by_level.keys().copied().collect();
    sorted_keys.sort();

    let mut groups: Vec<PolicyGroup> = Vec::new();

    for key in sorted_keys {
        // Unassigned (None) is handled separately after all levels.
        let Some(level) = key else { continue };
        let assets = &by_level[&Some(level)];

        // Step 2: Role-based sub-groups within this level.
        let role_subgroups = split_by_role(level, assets, input);

        // Step 3: Optional vendor split within each role sub-group.
        for (role_label, ips, category) in role_subgroups {
            let vendor_subgroups = maybe_split_by_vendor(&ips, input, &neighbor_sets);
            for (vendor_label, vendor_ips) in vendor_subgroups {
                let group_name = if vendor_label.is_empty() {
                    format!("L{}-{}", level, role_label)
                } else {
                    format!("L{}-{}-{}", level, role_label, vendor_label)
                };

                let security_level = security_level_from_purdue(Some(level));
                let criticality = max_criticality_for_ips(&vendor_ips, &input.assets);

                groups.push(PolicyGroup::new(
                    group_name,
                    vendor_ips,
                    Some(level),
                    category,
                    security_level,
                    criticality,
                ));
            }
        }
    }

    // Step 4: Community detection for unassigned assets.
    if let Some(unassigned) = by_level.get(&None) {
        let community_groups = detect_communities(unassigned, input, &neighbor_sets);
        groups.extend(community_groups);
    }

    groups
}

/// Map Purdue level to IEC 62443 Security Level.
///
/// - L0/L1 → SL3 (basic control, direct process impact)
/// - L2/L3/L3.5 → SL2 (supervisory access control)
/// - L4+ / unassigned → SL1 (IT network baseline)
pub fn security_level_from_purdue(level: Option<u8>) -> SecurityLevel {
    match level {
        Some(0) | Some(1) => SecurityLevel::Sl3,
        Some(2) | Some(3) => SecurityLevel::Sl2,
        _ => SecurityLevel::Sl1,
    }
}

// ── Step 2: Role-based partitioning ──────────────────────────────────────────

/// Dispatch to level-specific role-split logic.
fn split_by_role(
    level: u8,
    assets: &[&AssetProfile],
    input: &SegmentationInput,
) -> Vec<(String, Vec<String>, DeviceCategory)> {
    match level {
        0 | 1 => split_l1_by_protocol_role(level, assets),
        2 => split_l2_hmi_engineering(assets, input),
        3 => split_l3_by_server_type(assets),
        _ => split_l4_by_it_protocol(assets),
    }
}

/// L0/L1: group by primary OT protocol server role.
///
/// Uses `protocol_roles` from deep parse (preferred) then falls back to
/// checking the `protocols` list.
fn split_l1_by_protocol_role(
    level: u8,
    assets: &[&AssetProfile],
) -> Vec<(String, Vec<String>, DeviceCategory)> {
    let category = if level == 0 {
        DeviceCategory::Sensor
    } else {
        DeviceCategory::Plc
    };

    let mut role_buckets: HashMap<String, Vec<String>> = HashMap::new();
    for asset in assets {
        let role = detect_l1_role(asset);
        role_buckets.entry(role).or_default().push(asset.ip.clone());
    }

    role_buckets
        .into_iter()
        .map(|(role, ips)| (role, ips, category))
        .collect()
}

/// Identify the primary OT server role for an L0/L1 asset.
fn detect_l1_role(asset: &AssetProfile) -> String {
    // Prefer explicit protocol_roles (from deep parse).
    for pr in &asset.protocol_roles {
        let role = pr.role.as_str();
        let proto = pr.protocol.as_str();
        let is_server_role = matches!(
            role,
            "slave" | "server" | "outstation" | "adapter" | "io_device"
        );
        if !is_server_role {
            continue;
        }
        let label = match proto {
            "modbus" => "Modbus",
            "dnp3" => "DNP3",
            "s7comm" => "S7",
            "ethernet_ip" | "enip" => "EtherNetIP",
            "iec104" => "IEC104",
            "profinet" | "profinet_dcp" => "PROFINET",
            "bacnet" => "BACnet",
            _ => continue,
        };
        return label.to_string();
    }

    // Fallback: use protocols list.
    for proto in &asset.protocols {
        let label = match proto.as_str() {
            "modbus" => "Modbus",
            "dnp3" => "DNP3",
            "s7comm" => "S7",
            "ethernet_ip" | "enip" => "EtherNetIP",
            "iec104" => "IEC104",
            "profinet" | "profinet_dcp" => "PROFINET",
            "bacnet" => "BACnet",
            _ => continue,
        };
        return label.to_string();
    }

    // Default role label if no specific protocol identified.
    "Control".to_string()
}

/// L2: split HMIs (read clients) from Engineering workstations (config ops).
fn split_l2_hmi_engineering(
    assets: &[&AssetProfile],
    input: &SegmentationInput,
) -> Vec<(String, Vec<String>, DeviceCategory)> {
    // Build set of IPs that appear in connections with config operations.
    let config_ips: HashSet<&str> = input
        .connections
        .iter()
        .filter(|c| c.has_config_operations)
        .flat_map(|c| [c.src_ip.as_str(), c.dst_ip.as_str()])
        .collect();

    let mut hmi_ips: Vec<String> = Vec::new();
    let mut eng_ips: Vec<String> = Vec::new();

    for asset in assets {
        let is_engineering = config_ips.contains(asset.ip.as_str())
            || asset.device_type.contains("engineering")
            || asset.device_type.contains("ews");

        if is_engineering {
            eng_ips.push(asset.ip.clone());
        } else {
            hmi_ips.push(asset.ip.clone());
        }
    }

    let mut result = Vec::new();
    if !hmi_ips.is_empty() {
        result.push(("HMI".to_string(), hmi_ips, DeviceCategory::Hmi));
    }
    if !eng_ips.is_empty() {
        result.push((
            "Engineering".to_string(),
            eng_ips,
            DeviceCategory::EngineeringStation,
        ));
    }
    result
}

/// L3: split Historian, SCADA, and DMZ gateways (dual-homed assets).
fn split_l3_by_server_type(assets: &[&AssetProfile]) -> Vec<(String, Vec<String>, DeviceCategory)> {
    let mut dmz_ips: Vec<String> = Vec::new();
    let mut historian_ips: Vec<String> = Vec::new();
    let mut scada_ips: Vec<String> = Vec::new();
    let mut other_ips: Vec<String> = Vec::new();

    for asset in assets {
        if asset.is_dual_homed {
            dmz_ips.push(asset.ip.clone());
        } else if asset.device_type.contains("historian")
            || asset.protocols.iter().any(|p| p == "opc_ua")
        {
            historian_ips.push(asset.ip.clone());
        } else if asset.device_type.contains("scada") {
            scada_ips.push(asset.ip.clone());
        } else {
            other_ips.push(asset.ip.clone());
        }
    }

    let mut result = Vec::new();
    if !dmz_ips.is_empty() {
        result.push(("DMZ".to_string(), dmz_ips, DeviceCategory::DmzGateway));
    }
    if !historian_ips.is_empty() {
        result.push((
            "Historian".to_string(),
            historian_ips,
            DeviceCategory::Historian,
        ));
    }
    if !scada_ips.is_empty() {
        result.push(("SCADA".to_string(), scada_ips, DeviceCategory::ScadaServer));
    }
    if !other_ips.is_empty() {
        result.push((
            "Operations".to_string(),
            other_ips,
            DeviceCategory::ScadaServer,
        ));
    }
    result
}

/// L4+: split by IT protocol type (web, remote access, general IT).
fn split_l4_by_it_protocol(assets: &[&AssetProfile]) -> Vec<(String, Vec<String>, DeviceCategory)> {
    let mut web_ips: Vec<String> = Vec::new();
    let mut remote_ips: Vec<String> = Vec::new();
    let mut other_ips: Vec<String> = Vec::new();

    for asset in assets {
        if asset
            .protocols
            .iter()
            .any(|p| matches!(p.as_str(), "http" | "https"))
        {
            web_ips.push(asset.ip.clone());
        } else if asset
            .protocols
            .iter()
            .any(|p| matches!(p.as_str(), "rdp" | "ssh" | "vnc" | "telnet"))
        {
            remote_ips.push(asset.ip.clone());
        } else {
            other_ips.push(asset.ip.clone());
        }
    }

    let mut result = Vec::new();
    if !web_ips.is_empty() {
        result.push(("Web".to_string(), web_ips, DeviceCategory::ItEndpoint));
    }
    if !remote_ips.is_empty() {
        result.push((
            "RemoteAccess".to_string(),
            remote_ips,
            DeviceCategory::ItEndpoint,
        ));
    }
    if !other_ips.is_empty() {
        result.push(("IT".to_string(), other_ips, DeviceCategory::ItEndpoint));
    }
    result
}

// ── Step 3: Vendor split ──────────────────────────────────────────────────────

/// Optionally split a role sub-group by vendor.
///
/// Splits only if the vendor subgroups communicate with disjoint peer sets
/// (average pairwise Jaccard similarity < 0.3). If any vendor pair shares
/// enough neighbors (≥ 0.3), the whole group is kept together.
///
/// Returns a list of `(vendor_label, ips)` pairs. `vendor_label` is empty when
/// no split is performed (group name will be `"L{N}-{role}"`).
fn maybe_split_by_vendor(
    ips: &[String],
    input: &SegmentationInput,
    neighbor_sets: &HashMap<String, HashSet<String>>,
) -> Vec<(String, Vec<String>)> {
    if ips.len() < 2 {
        return vec![(String::new(), ips.to_vec())];
    }

    // Group IPs by vendor name.
    let mut by_vendor: HashMap<String, Vec<String>> = HashMap::new();
    for ip in ips {
        let vendor = input
            .assets
            .iter()
            .find(|a| &a.ip == ip)
            .and_then(|a| a.vendor.as_deref())
            .unwrap_or("unknown")
            .to_string();
        by_vendor.entry(vendor).or_default().push(ip.clone());
    }

    // Single vendor bucket — no split possible.
    if by_vendor.len() <= 1 {
        return vec![(String::new(), ips.to_vec())];
    }

    // Check if any vendor pair is "close enough" to keep together.
    // Use a block so the borrows on by_vendor drop before we move it.
    let should_split = {
        let vendors: Vec<(&String, &Vec<String>)> = by_vendor.iter().collect();
        let mut split = true;
        'outer: for i in 0..vendors.len() {
            for j in (i + 1)..vendors.len() {
                if avg_group_jaccard(vendors[i].1, vendors[j].1, neighbor_sets) >= 0.3 {
                    split = false;
                    break 'outer;
                }
            }
        }
        split
    };

    if should_split {
        // Return each vendor as a separate group with its vendor name as label.
        by_vendor.into_iter().collect()
    } else {
        // Keep all IPs together; no vendor qualifier in the group name.
        vec![(String::new(), ips.to_vec())]
    }
}

// ── Step 4: Community detection for unassigned assets ────────────────────────

/// Greedy community detection for assets without a Purdue level assignment.
///
/// Iterates over unassigned assets. For each asset, computes Jaccard similarity
/// of its neighbor set against each existing community. If the best match
/// exceeds 0.6, the asset joins that community; otherwise it starts a new one.
fn detect_communities(
    unassigned: &[&AssetProfile],
    input: &SegmentationInput,
    neighbor_sets: &HashMap<String, HashSet<String>>,
) -> Vec<PolicyGroup> {
    if unassigned.is_empty() {
        return Vec::new();
    }

    let mut communities: Vec<Vec<String>> = Vec::new();

    for asset in unassigned {
        let ip = &asset.ip;
        let single = std::slice::from_ref(ip);

        let mut best_match: Option<usize> = None;
        let mut best_sim = 0.6f64; // threshold — must exceed (not equal) 0.6

        for (idx, members) in communities.iter().enumerate() {
            let sim = avg_group_jaccard(single, members, neighbor_sets);
            if sim > best_sim {
                best_sim = sim;
                best_match = Some(idx);
            }
        }

        if let Some(idx) = best_match {
            communities[idx].push(ip.clone());
        } else {
            communities.push(vec![ip.clone()]);
        }
    }

    // Build PolicyGroups from communities.
    communities
        .into_iter()
        .enumerate()
        .map(|(idx, ips)| {
            // Classify by OT neighbor ratio.
            let has_ot_neighbor = ips.iter().any(|ip| {
                if let Some(neighbors) = neighbor_sets.get(ip) {
                    neighbors
                        .iter()
                        .any(|nb| input.assets.iter().any(|a| &a.ip == nb && a.is_ot))
                } else {
                    false
                }
            });

            let category = if has_ot_neighbor {
                DeviceCategory::NetworkInfra
            } else {
                DeviceCategory::Unknown
            };

            let criticality = max_criticality_for_ips(&ips, &input.assets);

            PolicyGroup::new(
                format!("Unclassified-{}", idx + 1),
                ips,
                None,
                category,
                SecurityLevel::Sl1, // Conservative default for unclassified devices.
                criticality,
            )
        })
        .collect()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build per-IP neighbor sets from observed connections (bidirectional).
fn build_neighbor_sets(connections: &[ObservedConnection]) -> HashMap<String, HashSet<String>> {
    let mut neighbors: HashMap<String, HashSet<String>> = HashMap::new();
    for conn in connections {
        neighbors
            .entry(conn.src_ip.clone())
            .or_default()
            .insert(conn.dst_ip.clone());
        neighbors
            .entry(conn.dst_ip.clone())
            .or_default()
            .insert(conn.src_ip.clone());
    }
    neighbors
}

/// Jaccard similarity between two neighbor sets.
///
/// Returns 1.0 if both sets are empty (identical empty neighborhoods),
/// and 0.0 if the union is non-empty but the intersection is empty.
fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let intersection = a.intersection(b).count();
    let union_size = a.union(b).count();
    if union_size == 0 {
        1.0
    } else {
        intersection as f64 / union_size as f64
    }
}

/// Average pairwise Jaccard similarity between two groups of IPs.
///
/// Returns 0.0 if either group is empty.
fn avg_group_jaccard(
    group_a: &[String],
    group_b: &[String],
    neighbor_sets: &HashMap<String, HashSet<String>>,
) -> f64 {
    let empty: HashSet<String> = HashSet::new();
    let mut total = 0.0f64;
    let mut count = 0usize;

    for ip_a in group_a {
        for ip_b in group_b {
            let na = neighbor_sets.get(ip_a).unwrap_or(&empty);
            let nb = neighbor_sets.get(ip_b).unwrap_or(&empty);
            total += jaccard(na, nb);
            count += 1;
        }
    }

    if count == 0 {
        0.0
    } else {
        total / count as f64
    }
}

/// Return the maximum criticality level across a set of member IPs.
fn max_criticality_for_ips(ips: &[String], assets: &[AssetProfile]) -> Criticality {
    ips.iter()
        .filter_map(|ip| assets.iter().find(|a| &a.ip == ip))
        .map(|a| parse_criticality(a.criticality.as_deref()))
        .max()
        .unwrap_or(Criticality::Unknown)
}

/// Parse a criticality string from `risk.rs` output into a [`Criticality`] enum.
fn parse_criticality(s: Option<&str>) -> Criticality {
    match s {
        Some("critical") => Criticality::Critical,
        Some("high") => Criticality::High,
        Some("medium") => Criticality::Medium,
        Some("low") => Criticality::Low,
        _ => Criticality::Unknown,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObservedConnection, ProtocolRole, SegmentationInput};

    /// Minimal AssetProfile for use in tests.
    fn make_asset(ip: &str, device_type: &str, purdue_level: Option<u8>) -> AssetProfile {
        AssetProfile {
            ip: ip.to_string(),
            mac: None,
            hostname: None,
            vendor: None,
            device_type: device_type.to_string(),
            product_name: None,
            purdue_level,
            protocols: Vec::new(),
            protocol_roles: Vec::new(),
            confidence: 1,
            criticality: None,
            subnet: None,
            is_ot: purdue_level.map(|l| l <= 3).unwrap_or(false),
            is_it: purdue_level.map(|l| l >= 4).unwrap_or(false),
            is_dual_homed: false,
            connection_count: 0,
            has_cves: false,
            has_default_creds: false,
        }
    }

    /// Minimal ObservedConnection for use in tests.
    fn make_conn(src: &str, dst: &str) -> ObservedConnection {
        ObservedConnection {
            src_ip: src.to_string(),
            src_port: 1024,
            dst_ip: dst.to_string(),
            dst_port: 502,
            protocol: "modbus".to_string(),
            packet_count: 100,
            byte_count: 1000,
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

    #[test]
    fn test_empty_input_returns_no_groups() {
        let input = SegmentationInput::default();
        let groups = build_policy_groups(&input);
        assert!(groups.is_empty());
    }

    #[test]
    fn test_single_l1_asset_gets_one_group() {
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.0.1", "plc", Some(1))],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].member_ips, vec!["10.0.0.1"]);
        assert_eq!(groups[0].purdue_level, Some(1));
    }

    #[test]
    fn test_l1_and_l2_get_separate_groups() {
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.0.1", "plc", Some(1)),
                make_asset("10.0.0.10", "hmi", Some(2)),
            ],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);
        assert_eq!(groups.len(), 2);
        let levels: Vec<Option<u8>> = groups.iter().map(|g| g.purdue_level).collect();
        assert!(levels.contains(&Some(1)));
        assert!(levels.contains(&Some(2)));
    }

    #[test]
    fn test_l1_split_by_protocol_role() {
        // Modbus slave and PROFINET IO-device should land in separate groups.
        let mut modbus_plc = make_asset("10.0.0.1", "plc", Some(1));
        modbus_plc.protocol_roles = vec![ProtocolRole {
            protocol: "modbus".to_string(),
            role: "slave".to_string(),
        }];

        let mut profinet_plc = make_asset("10.0.0.2", "plc", Some(1));
        profinet_plc.protocol_roles = vec![ProtocolRole {
            protocol: "profinet".to_string(),
            role: "io_device".to_string(),
        }];

        let input = SegmentationInput {
            assets: vec![modbus_plc, profinet_plc],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);
        // Two distinct role buckets at L1.
        assert_eq!(groups.len(), 2);
        assert!(groups.iter().all(|g| g.purdue_level == Some(1)));
        // Names must differ (one contains "Modbus", other "PROFINET").
        assert_ne!(groups[0].name, groups[1].name);
    }

    #[test]
    fn test_l2_engineering_splits_from_hmi() {
        let hmi = make_asset("10.0.0.10", "hmi", Some(2));
        let eng = make_asset("10.0.0.11", "engineering_workstation", Some(2));

        let mut config_conn = make_conn("10.0.0.11", "10.0.0.1");
        config_conn.has_config_operations = true;

        let input = SegmentationInput {
            assets: vec![hmi, eng],
            connections: vec![config_conn],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);

        let categories: Vec<DeviceCategory> = groups
            .iter()
            .filter(|g| g.purdue_level == Some(2))
            .map(|g| g.device_category)
            .collect();

        assert!(categories.contains(&DeviceCategory::Hmi));
        assert!(categories.contains(&DeviceCategory::EngineeringStation));
    }

    #[test]
    fn test_l1_security_level_is_sl3() {
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.0.1", "plc", Some(1))],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);
        assert_eq!(groups[0].security_level, SecurityLevel::Sl3);
    }

    #[test]
    fn test_l0_security_level_is_sl3() {
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.0.1", "sensor", Some(0))],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);
        assert_eq!(groups[0].security_level, SecurityLevel::Sl3);
    }

    #[test]
    fn test_l2_security_level_is_sl2() {
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.0.10", "hmi", Some(2))],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);
        assert_eq!(groups[0].security_level, SecurityLevel::Sl2);
    }

    #[test]
    fn test_l4_security_level_is_sl1() {
        let input = SegmentationInput {
            assets: vec![make_asset("192.168.1.100", "it_device", Some(4))],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);
        assert_eq!(groups[0].security_level, SecurityLevel::Sl1);
    }

    #[test]
    fn test_criticality_max_of_members() {
        // Two PLCs in the same L1 role bucket — group criticality should be max.
        let mut plc1 = make_asset("10.0.0.1", "plc", Some(1));
        plc1.criticality = Some("critical".to_string());
        let mut plc2 = make_asset("10.0.0.2", "plc", Some(1));
        plc2.criticality = Some("medium".to_string());

        let input = SegmentationInput {
            assets: vec![plc1, plc2],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);

        // Both end up in the "Control" bucket at L1.
        let l1_group = groups
            .iter()
            .find(|g| g.purdue_level == Some(1))
            .expect("L1 group should exist");
        assert_eq!(l1_group.criticality, Criticality::Critical);
    }

    #[test]
    fn test_vendor_split_disjoint_neighbors() {
        // Rockwell and Siemens PLCs with completely disjoint neighbor sets
        // should be split into separate groups (Jaccard = 0 < 0.3).
        let mut rock_plc = make_asset("10.0.0.1", "plc", Some(1));
        rock_plc.vendor = Some("Rockwell".to_string());
        rock_plc.protocol_roles = vec![ProtocolRole {
            protocol: "ethernet_ip".to_string(),
            role: "adapter".to_string(),
        }];

        let mut sie_plc = make_asset("10.0.0.2", "plc", Some(1));
        sie_plc.vendor = Some("Siemens".to_string());
        sie_plc.protocol_roles = vec![ProtocolRole {
            protocol: "ethernet_ip".to_string(),
            role: "adapter".to_string(),
        }];

        // Each PLC is polled by a different HMI — completely disjoint neighbors.
        let input = SegmentationInput {
            assets: vec![rock_plc, sie_plc],
            connections: vec![
                make_conn("10.0.1.1", "10.0.0.1"), // HMI-A → Rockwell
                make_conn("10.0.2.1", "10.0.0.2"), // HMI-B → Siemens
            ],
            ..Default::default()
        };

        let groups = build_policy_groups(&input);
        let l1_groups: Vec<&PolicyGroup> = groups
            .iter()
            .filter(|g| g.purdue_level == Some(1))
            .collect();
        assert_eq!(
            l1_groups.len(),
            2,
            "Disjoint vendors should split into 2 groups"
        );
    }

    #[test]
    fn test_vendor_no_split_shared_neighbors() {
        // Two PLCs from different vendors that share the same HMI neighbor
        // should NOT be split (Jaccard = 1.0 ≥ 0.3).
        let mut rock_plc = make_asset("10.0.0.1", "plc", Some(1));
        rock_plc.vendor = Some("Rockwell".to_string());
        rock_plc.protocol_roles = vec![ProtocolRole {
            protocol: "ethernet_ip".to_string(),
            role: "adapter".to_string(),
        }];

        let mut sie_plc = make_asset("10.0.0.2", "plc", Some(1));
        sie_plc.vendor = Some("Siemens".to_string());
        sie_plc.protocol_roles = vec![ProtocolRole {
            protocol: "ethernet_ip".to_string(),
            role: "adapter".to_string(),
        }];

        // Same HMI polls both PLCs — shared neighbor set.
        let input = SegmentationInput {
            assets: vec![rock_plc, sie_plc],
            connections: vec![
                make_conn("10.0.1.1", "10.0.0.1"), // HMI → Rockwell
                make_conn("10.0.1.1", "10.0.0.2"), // same HMI → Siemens
            ],
            ..Default::default()
        };

        let groups = build_policy_groups(&input);
        let l1_groups: Vec<&PolicyGroup> = groups
            .iter()
            .filter(|g| g.purdue_level == Some(1))
            .collect();
        assert_eq!(
            l1_groups.len(),
            1,
            "Shared neighbors should merge into 1 group"
        );
    }

    #[test]
    fn test_unassigned_merged_into_community() {
        // Two unassigned assets with identical neighbor sets should merge.
        let a1 = make_asset("10.0.0.1", "unknown", None);
        let a2 = make_asset("10.0.0.2", "unknown", None);

        // Both talk to the same 4 OT devices — Jaccard = 4/4 = 1.0 > 0.6.
        let conns: Vec<ObservedConnection> = (1u8..=4)
            .flat_map(|i| {
                let target = format!("10.0.1.{}", i);
                vec![
                    make_conn("10.0.0.1", &target),
                    make_conn("10.0.0.2", &target),
                ]
            })
            .collect();

        let input = SegmentationInput {
            assets: vec![a1, a2],
            connections: conns,
            ..Default::default()
        };

        let groups = build_policy_groups(&input);
        let unassigned: Vec<&PolicyGroup> =
            groups.iter().filter(|g| g.purdue_level.is_none()).collect();

        assert_eq!(
            unassigned.len(),
            1,
            "High-overlap assets should merge into one community"
        );
        assert_eq!(
            unassigned[0].member_ips.len(),
            2,
            "Community should contain both assets"
        );
    }

    #[test]
    fn test_group_name_starts_with_level() {
        let input = SegmentationInput {
            assets: vec![
                make_asset("10.0.0.1", "plc", Some(1)),
                make_asset("10.0.0.10", "hmi", Some(2)),
                make_asset("192.168.1.1", "it_device", Some(4)),
            ],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);

        for group in &groups {
            if let Some(level) = group.purdue_level {
                assert!(
                    group.name.starts_with(&format!("L{}-", level)),
                    "Group '{}' at L{} should start with 'L{}-'",
                    group.name,
                    level,
                    level
                );
            }
        }
    }

    #[test]
    fn test_l0_gets_sensor_category() {
        let input = SegmentationInput {
            assets: vec![make_asset("10.0.0.1", "sensor", Some(0))],
            ..Default::default()
        };
        let groups = build_policy_groups(&input);
        assert_eq!(groups[0].device_category, DeviceCategory::Sensor);
    }

    #[test]
    fn test_security_level_from_purdue_mapping() {
        assert_eq!(security_level_from_purdue(Some(0)), SecurityLevel::Sl3);
        assert_eq!(security_level_from_purdue(Some(1)), SecurityLevel::Sl3);
        assert_eq!(security_level_from_purdue(Some(2)), SecurityLevel::Sl2);
        assert_eq!(security_level_from_purdue(Some(3)), SecurityLevel::Sl2);
        assert_eq!(security_level_from_purdue(Some(4)), SecurityLevel::Sl1);
        assert_eq!(security_level_from_purdue(None), SecurityLevel::Sl1);
    }
}
