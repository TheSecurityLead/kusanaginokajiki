//! Traffic-inferred network topology analysis.
//!
//! Derives network structure (subnets, gateways, switch candidates,
//! broadcast domains) from observed IP-level traffic — no switch
//! config files required.

use std::collections::{HashMap, HashSet};

use crate::{InferredTopology, InferredSubnet, InferredGateway, SwitchCandidate, BroadcastDomain};

/// Decoupled input for topology inference — no Tauri state dependency.
#[derive(Debug, Clone, Default)]
pub struct InferenceInput {
    /// IP address + optional MAC for each known asset
    pub assets: Vec<AssetSnapshot>,
    /// Observed connections (IP-level)
    pub connections: Vec<ConnSnapshot>,
}

/// A snapshot of a single asset for inference.
#[derive(Debug, Clone)]
pub struct AssetSnapshot {
    pub ip_address: String,
    pub mac_address: Option<String>,
}

/// A snapshot of a single connection for inference.
#[derive(Debug, Clone)]
pub struct ConnSnapshot {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub packet_count: u64,
}

/// Run traffic-based topology inference on the provided snapshot.
///
/// Returns an `InferredTopology` with subnets, gateways, switch candidates,
/// and broadcast domains derived purely from observed traffic patterns.
pub fn infer_topology(input: &InferenceInput) -> InferredTopology {
    // Collect all IPs (from assets + connections)
    let mut all_ips: HashSet<String> = input.assets.iter()
        .map(|a| a.ip_address.clone())
        .collect();
    for conn in &input.connections {
        all_ips.insert(conn.src_ip.clone());
        all_ips.insert(conn.dst_ip.clone());
    }

    let subnets = infer_subnets(&all_ips, input);
    let gateways = detect_gateways(input, &subnets);
    let switch_candidates = detect_switch_candidates(input, &subnets);
    let broadcast_domains = detect_broadcast_domains(&subnets, &gateways);

    InferredTopology {
        subnets,
        gateways,
        switch_candidates,
        broadcast_domains,
    }
}

// ─── Subnet Grouping ──────────────────────────────────────────────

/// Group IPs by /24 prefix into inferred subnets.
///
/// For each group, tries to identify the gateway IP (.1 or .254 that
/// also connects to other subnets).
fn infer_subnets(all_ips: &HashSet<String>, input: &InferenceInput) -> Vec<InferredSubnet> {
    // Group by /24 prefix
    let mut subnet_map: HashMap<String, Vec<String>> = HashMap::new();

    for ip in all_ips {
        let prefix = ip_slash24_prefix(ip);
        subnet_map.entry(prefix).or_default().push(ip.clone());
    }

    // Build cross-subnet connection set to help identify gateways
    let cross_subnet_ips: HashSet<String> = detect_cross_subnet_ips(input);

    let mut subnets: Vec<InferredSubnet> = subnet_map.into_iter().map(|(prefix, mut members)| {
        members.sort();

        // Look for a gateway: .1 or .254 in this subnet that also talks across subnets
        let gateway_ip = find_subnet_gateway(&members, &prefix, &cross_subnet_ips);

        InferredSubnet {
            network: format!("{}.0/24", prefix),
            member_ips: members,
            gateway_ip,
        }
    }).collect();

    subnets.sort_by(|a, b| a.network.cmp(&b.network));
    subnets
}

/// Extract the /24 prefix ("x.x.x") from an IPv4 address string.
fn ip_slash24_prefix(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() >= 3 {
        format!("{}.{}.{}", parts[0], parts[1], parts[2])
    } else {
        ip.to_string()
    }
}

/// Find IPs that communicate with more than one /24 subnet.
fn detect_cross_subnet_ips(input: &InferenceInput) -> HashSet<String> {
    let mut ip_subnets: HashMap<String, HashSet<String>> = HashMap::new();

    for conn in &input.connections {
        let src_prefix = ip_slash24_prefix(&conn.src_ip);
        let dst_prefix = ip_slash24_prefix(&conn.dst_ip);

        // If src and dst are in different /24s, both are cross-subnet communicators
        if src_prefix != dst_prefix {
            ip_subnets.entry(conn.src_ip.clone()).or_default().insert(dst_prefix);
            ip_subnets.entry(conn.dst_ip.clone()).or_default().insert(src_prefix);
        }
    }

    ip_subnets.into_iter()
        .filter(|(_, subnets)| !subnets.is_empty())
        .map(|(ip, _)| ip)
        .collect()
}

/// Try to find a gateway IP within a subnet's member list.
fn find_subnet_gateway(
    members: &[String],
    prefix: &str,
    cross_subnet_ips: &HashSet<String>,
) -> Option<String> {
    // Candidates: .1, .254, or any cross-subnet communicator in this subnet
    let candidate_1 = format!("{}.1", prefix);
    let candidate_254 = format!("{}.254", prefix);

    // Prefer cross-subnet IPs that are also .1 or .254
    if members.contains(&candidate_1) && cross_subnet_ips.contains(&candidate_1) {
        return Some(candidate_1);
    }
    if members.contains(&candidate_254) && cross_subnet_ips.contains(&candidate_254) {
        return Some(candidate_254);
    }

    // Fall back to .1 or .254 by heuristic even without confirmed cross-subnet traffic
    if members.contains(&candidate_1) {
        return Some(candidate_1);
    }
    if members.contains(&candidate_254) {
        return Some(candidate_254);
    }

    // Fall back to any cross-subnet IP in this subnet
    for ip in members {
        if cross_subnet_ips.contains(ip) {
            return Some(ip.clone());
        }
    }

    None
}

// ─── Gateway Detection ────────────────────────────────────────────

/// Identify gateway IPs based on cross-subnet connectivity patterns.
///
/// - confidence = 1: only .1/.254 heuristic
/// - confidence = 2: cross-subnet connections observed
/// - confidence = 3: both (cross-subnet AND .1/.254)
fn detect_gateways(input: &InferenceInput, _subnets: &[InferredSubnet]) -> Vec<InferredGateway> {
    // Count distinct /24 subnets each IP connects to (as either src or dst)
    let mut ip_subnet_connections: HashMap<String, HashSet<String>> = HashMap::new();

    for conn in &input.connections {
        let src_prefix = ip_slash24_prefix(&conn.src_ip);
        let dst_prefix = ip_slash24_prefix(&conn.dst_ip);

        if src_prefix != dst_prefix {
            ip_subnet_connections
                .entry(conn.src_ip.clone())
                .or_default()
                .insert(dst_prefix.clone());
            ip_subnet_connections
                .entry(conn.dst_ip.clone())
                .or_default()
                .insert(src_prefix);
        }
    }

    // Build MAC address lookup from assets
    let mac_by_ip: HashMap<String, String> = input.assets.iter()
        .filter_map(|a| a.mac_address.as_ref().map(|mac| (a.ip_address.clone(), mac.clone())))
        .collect();

    let mut gateways: Vec<InferredGateway> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for (ip, connected_subnets) in &ip_subnet_connections {
        if !seen.insert(ip.clone()) {
            continue;
        }

        // Any IP with observed cross-subnet traffic is a gateway candidate
        // (must have at least one connection to a different /24)
        if connected_subnets.is_empty() {
            continue;
        }

        let last_octet = ip.split('.').next_back().unwrap_or("0");
        let is_gateway_heuristic = last_octet == "1" || last_octet == "254";
        // "strong" cross-subnet = connects to 2+ distinct other /24s
        let strong_cross_subnet = connected_subnets.len() >= 2;

        let confidence = match (is_gateway_heuristic, strong_cross_subnet) {
            (true, true) => 3,
            (false, true) => 2,
            (true, false) => 2,   // .1/.254 with at least one cross-subnet connection
            (false, false) => 1,  // plain cross-subnet, no heuristic
        };

        let mut subnet_list: Vec<String> = connected_subnets.iter()
            .map(|prefix| format!("{}.0/24", prefix))
            .collect();
        subnet_list.sort();

        gateways.push(InferredGateway {
            ip_address: ip.clone(),
            mac_address: mac_by_ip.get(ip).cloned(),
            connected_subnets: subnet_list,
            confidence,
        });
    }

    gateways.sort_by(|a, b| b.confidence.cmp(&a.confidence).then(a.ip_address.cmp(&b.ip_address)));
    gateways
}

// ─── Switch Candidate Detection ───────────────────────────────────

/// Detect potential switch/hub candidates based on high fan-out within a /24.
///
/// An IP that connects to 5+ other IPs in the same /24 subnet may be
/// a switch management address or a device behind a hub.
///
/// - confidence = 1: fan-out > 5 within subnet
/// - confidence = 2: fan-out > 10 within subnet
fn detect_switch_candidates(input: &InferenceInput, _subnets: &[InferredSubnet]) -> Vec<SwitchCandidate> {
    // Count connections within same /24 for each IP
    let mut intra_subnet_neighbors: HashMap<String, HashSet<String>> = HashMap::new();

    for conn in &input.connections {
        let src_prefix = ip_slash24_prefix(&conn.src_ip);
        let dst_prefix = ip_slash24_prefix(&conn.dst_ip);

        if src_prefix == dst_prefix {
            intra_subnet_neighbors
                .entry(conn.src_ip.clone())
                .or_default()
                .insert(conn.dst_ip.clone());
            intra_subnet_neighbors
                .entry(conn.dst_ip.clone())
                .or_default()
                .insert(conn.src_ip.clone());
        }
    }

    // Build MAC address lookup from assets
    let mac_by_ip: HashMap<String, String> = input.assets.iter()
        .filter_map(|a| a.mac_address.as_ref().map(|mac| (a.ip_address.clone(), mac.clone())))
        .collect();

    let mut candidates: Vec<SwitchCandidate> = Vec::new();

    for (ip, neighbors) in &intra_subnet_neighbors {
        let fan_out = neighbors.len();
        if fan_out <= 5 {
            continue;
        }

        let confidence = if fan_out > 10 { 2 } else { 1 };

        let mut connected_ips: Vec<String> = neighbors.iter().cloned().collect();
        connected_ips.sort();

        candidates.push(SwitchCandidate {
            ip_address: Some(ip.clone()),
            mac_address: mac_by_ip.get(ip).cloned(),
            connected_ips,
            confidence,
        });
    }

    candidates.sort_by(|a, b| {
        b.confidence.cmp(&a.confidence)
            .then(b.connected_ips.len().cmp(&a.connected_ips.len()))
    });
    candidates
}

// ─── Broadcast Domain Detection ──────────────────────────────────

/// Group subnets into broadcast domains.
///
/// Each /24 subnet becomes its own broadcast domain by default.
/// If two subnets share a common gateway IP, they are noted as
/// potentially routed (but remain separate broadcast domains).
fn detect_broadcast_domains(
    subnets: &[InferredSubnet],
    gateways: &[InferredGateway],
) -> Vec<BroadcastDomain> {
    // Build gateway → subnets mapping
    let mut gateway_subnets: HashMap<String, Vec<String>> = HashMap::new();
    for gw in gateways {
        for subnet in &gw.connected_subnets {
            gateway_subnets.entry(gw.ip_address.clone()).or_default().push(subnet.clone());
        }
    }

    subnets.iter().enumerate().map(|(i, subnet)| {
        // Check if this subnet has a gateway and what the inferred_from value is
        let inferred_from = if subnet.gateway_ip.is_some() {
            "gateway".to_string()
        } else {
            "subnet".to_string()
        };

        BroadcastDomain {
            id: format!("bd-{}", i),
            network: subnet.network.clone(),
            member_ips: subnet.member_ips.clone(),
            gateway_ip: subnet.gateway_ip.clone(),
            inferred_from,
        }
    }).collect()
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input() -> InferenceInput {
        InferenceInput {
            assets: vec![
                AssetSnapshot { ip_address: "192.168.1.1".to_string(), mac_address: Some("00:11:22:33:44:01".to_string()) },
                AssetSnapshot { ip_address: "192.168.1.10".to_string(), mac_address: Some("00:11:22:33:44:10".to_string()) },
                AssetSnapshot { ip_address: "192.168.1.20".to_string(), mac_address: None },
                AssetSnapshot { ip_address: "192.168.2.1".to_string(), mac_address: Some("00:11:22:33:44:02".to_string()) },
                AssetSnapshot { ip_address: "192.168.2.10".to_string(), mac_address: None },
                AssetSnapshot { ip_address: "10.0.0.1".to_string(), mac_address: None },
            ],
            connections: vec![
                // Within 192.168.1.0/24
                ConnSnapshot { src_ip: "192.168.1.10".to_string(), dst_ip: "192.168.1.1".to_string(), src_mac: None, dst_mac: None, packet_count: 100 },
                ConnSnapshot { src_ip: "192.168.1.20".to_string(), dst_ip: "192.168.1.1".to_string(), src_mac: None, dst_mac: None, packet_count: 50 },
                // Cross-subnet: 192.168.1.1 (gateway) → 192.168.2.0/24
                ConnSnapshot { src_ip: "192.168.1.1".to_string(), dst_ip: "192.168.2.10".to_string(), src_mac: None, dst_mac: None, packet_count: 30 },
                ConnSnapshot { src_ip: "192.168.1.1".to_string(), dst_ip: "192.168.2.1".to_string(), src_mac: None, dst_mac: None, packet_count: 20 },
                // Cross-subnet: 192.168.2.1 (gateway) → 10.0.0.0/8
                ConnSnapshot { src_ip: "192.168.2.1".to_string(), dst_ip: "10.0.0.1".to_string(), src_mac: None, dst_mac: None, packet_count: 10 },
            ],
        }
    }

    #[test]
    fn test_subnet_grouping() {
        let input = make_input();
        let all_ips: std::collections::HashSet<String> = input.assets.iter()
            .map(|a| a.ip_address.clone())
            .collect();
        let subnets = infer_subnets(&all_ips, &input);

        assert!(subnets.len() >= 3);

        let subnet_192_168_1 = subnets.iter().find(|s| s.network == "192.168.1.0/24").unwrap();
        assert!(subnet_192_168_1.member_ips.contains(&"192.168.1.1".to_string()));
        assert!(subnet_192_168_1.member_ips.contains(&"192.168.1.10".to_string()));
    }

    #[test]
    fn test_gateway_detection() {
        let input = make_input();
        let all_ips: HashSet<String> = input.assets.iter()
            .map(|a| a.ip_address.clone())
            .collect();
        let subnets = infer_subnets(&all_ips, &input);
        let gateways = detect_gateways(&input, &subnets);

        // 192.168.1.1 connects to both .1.x and .2.x subnets → gateway
        let gw = gateways.iter().find(|g| g.ip_address == "192.168.1.1");
        assert!(gw.is_some());
        let gw = gw.unwrap();
        assert!(gw.confidence >= 2, "Expected confidence >= 2, got {}", gw.confidence);
        assert!(!gw.connected_subnets.is_empty());
    }

    #[test]
    fn test_gateway_confidence_heuristic() {
        let input = make_input();
        let all_ips: HashSet<String> = input.assets.iter()
            .map(|a| a.ip_address.clone())
            .collect();
        let subnets = infer_subnets(&all_ips, &input);
        let gateways = detect_gateways(&input, &subnets);

        // 192.168.1.1 ends in .1 AND has cross-subnet traffic → confidence >= 2
        if let Some(gw) = gateways.iter().find(|g| g.ip_address == "192.168.1.1") {
            assert!(gw.confidence >= 2, "192.168.1.1 should have confidence >= 2, got {}", gw.confidence);
        }
    }

    #[test]
    fn test_switch_candidate_detection_high_fanout() {
        // Create an IP that connects to 6+ others in the same /24
        let input = InferenceInput {
            assets: Vec::new(),
            connections: (1..=8).map(|i| ConnSnapshot {
                src_ip: "10.0.0.100".to_string(),
                dst_ip: format!("10.0.0.{}", i),
                src_mac: None,
                dst_mac: None,
                packet_count: 10,
            }).collect(),
        };

        let all_ips: HashSet<String> = input.connections.iter()
            .flat_map(|c| [c.src_ip.clone(), c.dst_ip.clone()])
            .collect();
        let subnets = infer_subnets(&all_ips, &input);
        let candidates = detect_switch_candidates(&input, &subnets);

        // 10.0.0.100 connects to 8 hosts in same /24 → switch candidate
        let candidate = candidates.iter().find(|c| c.ip_address.as_deref() == Some("10.0.0.100"));
        assert!(candidate.is_some(), "Expected 10.0.0.100 to be a switch candidate");
        assert_eq!(candidate.unwrap().confidence, 1);
    }

    #[test]
    fn test_switch_candidate_high_confidence() {
        // 11+ connections in same /24 → confidence 2
        let input = InferenceInput {
            assets: Vec::new(),
            connections: (1..=12).map(|i| ConnSnapshot {
                src_ip: "10.0.0.100".to_string(),
                dst_ip: format!("10.0.0.{}", i),
                src_mac: None,
                dst_mac: None,
                packet_count: 5,
            }).collect(),
        };

        let all_ips: HashSet<String> = input.connections.iter()
            .flat_map(|c| [c.src_ip.clone(), c.dst_ip.clone()])
            .collect();
        let subnets = infer_subnets(&all_ips, &input);
        let candidates = detect_switch_candidates(&input, &subnets);

        let candidate = candidates.iter().find(|c| c.ip_address.as_deref() == Some("10.0.0.100"));
        assert!(candidate.is_some());
        assert_eq!(candidate.unwrap().confidence, 2);
    }

    #[test]
    fn test_broadcast_domain_detection() {
        let input = make_input();
        let result = infer_topology(&input);

        assert!(!result.broadcast_domains.is_empty());
        for bd in &result.broadcast_domains {
            assert!(!bd.id.is_empty());
            assert!(!bd.network.is_empty());
            assert!(!bd.member_ips.is_empty());
        }
    }

    #[test]
    fn test_infer_topology_empty_input() {
        let input = InferenceInput::default();
        let result = infer_topology(&input);

        assert!(result.subnets.is_empty());
        assert!(result.gateways.is_empty());
        assert!(result.switch_candidates.is_empty());
        assert!(result.broadcast_domains.is_empty());
    }

    #[test]
    fn test_ip_slash24_prefix() {
        assert_eq!(ip_slash24_prefix("192.168.1.100"), "192.168.1");
        assert_eq!(ip_slash24_prefix("10.0.0.1"), "10.0.0");
        assert_eq!(ip_slash24_prefix("172.16.100.254"), "172.16.100");
    }
}
