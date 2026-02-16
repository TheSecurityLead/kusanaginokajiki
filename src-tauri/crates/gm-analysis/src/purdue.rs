//! Purdue Model auto-assignment and violation detection.
//!
//! ## Purdue Levels
//!
//! - **L0** — Sensors/actuators (process level)
//! - **L1** — PLCs/RTUs (basic control)
//! - **L2** — HMIs, engineering workstations (supervisory control)
//! - **L3** — Historians, SCADA servers (site operations)
//! - **L3.5** — DMZ (not used in auto-assignment; manual only)
//! - **L4-5** — Enterprise IT (business network)
//!
//! ## Auto-Assignment Heuristics
//!
//! - Port 502/44818/102 responder → L1 (PLC/RTU)
//! - Multi-OT polling client → L2 (HMI)
//! - OPC UA / high fan-out → L3 (Historian/SCADA)
//! - IT-only protocols → L4 (Enterprise IT)
//!
//! ## Cross-Level Violations
//!
//! Direct communication between L1 and L4-5 is flagged as a security
//! finding (T0886 Remote Services).

use std::collections::HashMap;

use crate::{
    AnalysisInput, Finding, FindingType, Severity,
    PurdueAssignment, PurdueMethod,
};

/// OT server ports that indicate L1 devices (PLCs/RTUs).
const L1_SERVER_PORTS: &[u16] = &[502, 44818, 2222, 102, 20000, 2404, 34962, 34963, 34964];

/// Auto-assign Purdue levels based on device classification and behavior.
///
/// Manual overrides (already set purdue_level) are preserved — only
/// devices without a level get auto-assigned.
pub fn auto_assign_purdue_levels(input: &AnalysisInput) -> Vec<PurdueAssignment> {
    let mut assignments = Vec::new();

    // Pre-compute per-IP connection fan-out (as client)
    let mut client_targets: HashMap<&str, Vec<u16>> = HashMap::new();
    for conn in &input.connections {
        client_targets
            .entry(&conn.src_ip)
            .or_default()
            .push(conn.dst_port);
    }

    // Pre-compute per-IP server ports (ports this IP receives connections on)
    let mut server_ports: HashMap<&str, Vec<u16>> = HashMap::new();
    for conn in &input.connections {
        server_ports
            .entry(&conn.dst_ip)
            .or_default()
            .push(conn.dst_port);
    }

    for asset in &input.assets {
        // Preserve manual assignments
        if asset.purdue_level.is_some() {
            assignments.push(PurdueAssignment {
                ip_address: asset.ip_address.clone(),
                level: asset.purdue_level.unwrap(),
                method: PurdueMethod::Manual,
                reason: "Manually assigned by user".to_string(),
            });
            continue;
        }

        let (level, reason) = assign_level(asset, &client_targets, &server_ports, input);

        assignments.push(PurdueAssignment {
            ip_address: asset.ip_address.clone(),
            level,
            method: PurdueMethod::Auto,
            reason,
        });
    }

    assignments
}

/// Determine the Purdue level for a single asset.
fn assign_level(
    asset: &crate::AssetSnapshot,
    client_targets: &HashMap<&str, Vec<u16>>,
    server_ports: &HashMap<&str, Vec<u16>>,
    input: &AnalysisInput,
) -> (u8, String) {
    let dt = asset.device_type.as_str();
    let ip = asset.ip_address.as_str();

    // Device type-based assignment (most reliable)
    match dt {
        "plc" | "rtu" => return (1, format!("Device type '{}' maps to L1 (Basic Control)", dt)),
        "hmi" | "engineering_workstation" => return (2, format!("Device type '{}' maps to L2 (Supervisory Control)", dt)),
        "historian" | "scada_server" => return (3, format!("Device type '{}' maps to L3 (Site Operations)", dt)),
        _ => {}
    }

    // Check if this device responds on L1 server ports
    let serves_ot = server_ports.get(ip)
        .map(|ports| ports.iter().any(|p| L1_SERVER_PORTS.contains(p)))
        .unwrap_or(false);

    if serves_ot {
        return (1, "Responds on OT server ports (502/44818/102/etc.)".to_string());
    }

    // Check OT protocol usage as a client
    let ot_protocols: Vec<&str> = asset.protocols.iter()
        .map(|p| p.as_str())
        .filter(|p| is_ot_protocol_name(p))
        .collect();

    let has_opc_ua = ot_protocols.contains(&"opc_ua");

    // Count distinct OT targets this device polls
    let ot_target_count = client_targets.get(ip)
        .map(|ports| ports.iter().filter(|p| L1_SERVER_PORTS.contains(p)).count())
        .unwrap_or(0);

    // High fan-out OT client or OPC UA → L3 (Historian/SCADA)
    if has_opc_ua || ot_target_count >= 10 {
        return (3, if has_opc_ua {
            "Uses OPC UA protocol (typical for historians/SCADA)".to_string()
        } else {
            format!("High fan-out OT client ({} OT targets)", ot_target_count)
        });
    }

    // Multi-OT protocol client → L2 (HMI)
    if ot_protocols.len() >= 2 || ot_target_count >= 2 {
        return (2, format!(
            "Multi-OT client ({} protocols, {} OT targets)",
            ot_protocols.len(), ot_target_count
        ));
    }

    // Single OT connection (client side) → L2
    if !ot_protocols.is_empty() {
        return (2, format!("OT protocol client ({})", ot_protocols.join(", ")));
    }

    // Check for deep parse data suggesting OT involvement
    if let Some(dp) = input.deep_parse.get(ip) {
        if dp.modbus.is_some() || dp.dnp3.is_some() {
            return (2, "Deep parse data shows OT protocol activity".to_string());
        }
    }

    // IT-only devices → L4
    if dt == "it_device" || asset.protocols.iter().all(|p| !is_ot_protocol_name(p)) {
        return (4, "IT-only protocols, no OT activity detected".to_string());
    }

    // Default: unknown → L4 (conservative — treat unknown as IT until proven OT)
    (4, "Unknown device type, defaulting to L4 (Enterprise IT)".to_string())
}

/// Detect cross-Purdue-level violations.
///
/// Direct communication between L1 (basic control) and L4-5 (enterprise IT)
/// bypasses the DMZ and is a security concern (T0886 Remote Services).
pub fn detect_purdue_violations(
    input: &AnalysisInput,
    assignments: &[PurdueAssignment],
) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build IP → Purdue level map
    let level_map: HashMap<&str, u8> = assignments.iter()
        .map(|a| (a.ip_address.as_str(), a.level))
        .collect();

    // Check each connection for cross-level violations
    for conn in &input.connections {
        let src_level = match level_map.get(conn.src_ip.as_str()) {
            Some(&l) => l,
            None => continue,
        };
        let dst_level = match level_map.get(conn.dst_ip.as_str()) {
            Some(&l) => l,
            None => continue,
        };

        // Flag L1 <-> L4+ direct communication
        let is_violation = (src_level <= 1 && dst_level >= 4)
            || (src_level >= 4 && dst_level <= 1);

        if is_violation {
            findings.push(Finding::new(
                FindingType::PurdueViolation,
                Severity::Medium,
                format!(
                    "Cross-zone communication: L{} ({}) <-> L{} ({})",
                    src_level, conn.src_ip, dst_level, conn.dst_ip
                ),
                format!(
                    "Direct communication detected between Purdue Level {} and Level {}. \
                     The Purdue Model requires a DMZ (L3.5) between control systems (L0-L3) \
                     and enterprise IT (L4-5). Direct L1<->L4+ communication bypasses this \
                     security boundary.",
                    src_level.min(dst_level),
                    src_level.max(dst_level)
                ),
                vec![conn.src_ip.clone(), conn.dst_ip.clone()],
                format!(
                    "{} (L{}) communicating with {} (L{}) on port {} ({} packets)",
                    conn.src_ip, src_level, conn.dst_ip, dst_level,
                    conn.dst_port, conn.packet_count
                ),
                Some("T0886".to_string()),
            ));
        }

        // Also flag L2 <-> L4+ (skip DMZ)
        let is_l2_l4_violation = (src_level == 2 && dst_level >= 4)
            || (src_level >= 4 && dst_level == 2);

        if is_l2_l4_violation {
            findings.push(Finding::new(
                FindingType::PurdueViolation,
                Severity::Low,
                format!(
                    "L2-L4 direct communication: {} <-> {}",
                    conn.src_ip, conn.dst_ip
                ),
                "HMI/supervisory (L2) communicating directly with enterprise IT (L4+). \
                     Best practice requires routing through a DMZ (L3.5).".to_string(),
                vec![conn.src_ip.clone(), conn.dst_ip.clone()],
                format!(
                    "{} (L{}) <-> {} (L{}) on port {}, {} packets",
                    conn.src_ip, src_level, conn.dst_ip, dst_level,
                    conn.dst_port, conn.packet_count
                ),
                Some("T0886".to_string()),
            ));
        }
    }

    // Deduplicate: group by (src, dst) pair, keep highest severity
    let mut seen: HashMap<(String, String), usize> = HashMap::new();
    let mut deduped: Vec<Finding> = Vec::new();

    for finding in findings {
        if finding.affected_assets.len() >= 2 {
            let key = (
                finding.affected_assets[0].clone(),
                finding.affected_assets[1].clone(),
            );
            let rev_key = (key.1.clone(), key.0.clone());

            if let Some(&idx) = seen.get(&key).or_else(|| seen.get(&rev_key)) {
                // Keep the higher severity one
                if finding.severity > deduped[idx].severity {
                    deduped[idx] = finding;
                }
            } else {
                let idx = deduped.len();
                seen.insert(key, idx);
                deduped.push(finding);
            }
        } else {
            deduped.push(finding);
        }
    }

    deduped
}

/// Check if a protocol name is an OT protocol.
fn is_ot_protocol_name(name: &str) -> bool {
    matches!(
        name,
        "modbus" | "dnp3" | "ethernet_ip" | "bacnet" | "s7comm"
            | "opc_ua" | "profinet" | "iec104" | "mqtt" | "hart_ip"
            | "foundation_fieldbus" | "ge_srtp" | "wonderware_suitelink"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    #[test]
    fn test_plc_gets_l1() {
        let mut input = AnalysisInput::default();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.1".to_string(),
            device_type: "plc".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        let assignments = auto_assign_purdue_levels(&input);
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].level, 1);
        assert_eq!(assignments[0].method, PurdueMethod::Auto);
    }

    #[test]
    fn test_hmi_gets_l2() {
        let mut input = AnalysisInput::default();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.10".to_string(),
            device_type: "hmi".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        let assignments = auto_assign_purdue_levels(&input);
        assert_eq!(assignments[0].level, 2);
    }

    #[test]
    fn test_historian_gets_l3() {
        let mut input = AnalysisInput::default();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.20".to_string(),
            device_type: "historian".to_string(),
            protocols: vec!["opc_ua".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        let assignments = auto_assign_purdue_levels(&input);
        assert_eq!(assignments[0].level, 3);
    }

    #[test]
    fn test_it_device_gets_l4() {
        let mut input = AnalysisInput::default();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.50".to_string(),
            device_type: "it_device".to_string(),
            protocols: vec!["http".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        let assignments = auto_assign_purdue_levels(&input);
        assert_eq!(assignments[0].level, 4);
    }

    #[test]
    fn test_manual_override_preserved() {
        let mut input = AnalysisInput::default();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.1".to_string(),
            device_type: "unknown".to_string(),
            protocols: vec![],
            purdue_level: Some(3), // Manually set to L3
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        let assignments = auto_assign_purdue_levels(&input);
        assert_eq!(assignments[0].level, 3);
        assert_eq!(assignments[0].method, PurdueMethod::Manual);
    }

    #[test]
    fn test_ot_server_port_gets_l1() {
        let mut input = AnalysisInput::default();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.5".to_string(),
            device_type: "unknown".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });
        input.connections.push(ConnectionSnapshot {
            src_ip: "10.0.0.100".to_string(),
            dst_ip: "10.0.0.5".to_string(),
            src_port: 49152,
            dst_port: 502,
            protocol: "Modbus".to_string(),
            packet_count: 1000,
        });

        let assignments = auto_assign_purdue_levels(&input);
        let a = assignments.iter().find(|a| a.ip_address == "10.0.0.5").unwrap();
        assert_eq!(a.level, 1);
    }

    #[test]
    fn test_cross_level_violation_l1_l4() {
        let input = AnalysisInput {
            assets: vec![],
            connections: vec![ConnectionSnapshot {
                src_ip: "10.0.0.1".to_string(),
                dst_ip: "192.168.1.50".to_string(),
                src_port: 502,
                dst_port: 80,
                protocol: "Http".to_string(),
                packet_count: 100,
            }],
            deep_parse: Default::default(),
        };

        let assignments = vec![
            PurdueAssignment {
                ip_address: "10.0.0.1".to_string(),
                level: 1,
                method: PurdueMethod::Auto,
                reason: "PLC".to_string(),
            },
            PurdueAssignment {
                ip_address: "192.168.1.50".to_string(),
                level: 4,
                method: PurdueMethod::Auto,
                reason: "IT".to_string(),
            },
        ];

        let findings = detect_purdue_violations(&input, &assignments);
        assert!(!findings.is_empty());
        assert!(findings.iter().any(|f| f.finding_type == FindingType::PurdueViolation));
        assert!(findings.iter().any(|f| f.technique_id == Some("T0886".to_string())));
    }

    #[test]
    fn test_same_level_no_violation() {
        let input = AnalysisInput {
            assets: vec![],
            connections: vec![ConnectionSnapshot {
                src_ip: "10.0.0.1".to_string(),
                dst_ip: "10.0.0.2".to_string(),
                src_port: 502,
                dst_port: 502,
                protocol: "Modbus".to_string(),
                packet_count: 1000,
            }],
            deep_parse: Default::default(),
        };

        let assignments = vec![
            PurdueAssignment {
                ip_address: "10.0.0.1".to_string(),
                level: 1,
                method: PurdueMethod::Auto,
                reason: "PLC".to_string(),
            },
            PurdueAssignment {
                ip_address: "10.0.0.2".to_string(),
                level: 1,
                method: PurdueMethod::Auto,
                reason: "PLC".to_string(),
            },
        ];

        let findings = detect_purdue_violations(&input, &assignments);
        assert!(findings.is_empty(), "Same-level communication should not be flagged");
    }
}
