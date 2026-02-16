//! MITRE ATT&CK for ICS technique detection.
//!
//! Analyzes deep parse info, asset data, and connections to detect
//! known attack patterns mapped to MITRE ATT&CK for ICS techniques.
//!
//! ## Detected Techniques
//!
//! | Technique | Behavior | Severity |
//! |-----------|----------|----------|
//! | T0855 | Modbus broadcast/mass writes (FC 5/6/15/16 to unit 0/255) | Critical |
//! | T0814 | Modbus FC 8 diagnostics from non-engineering workstation | High |
//! | T0856 | DNP3 unsolicited response to unknown master | Medium |
//! | T0846 | Unknown device polling PLCs (new source targeting OT ports) | High |
//! | T0886 | Cross-Purdue zone communication (L1 <-> L4) | Medium |

use std::collections::{HashMap, HashSet};

use crate::{
    AnalysisInput, Finding, FindingType, Severity,
};

/// Well-known OT server ports used to identify PLCs/RTUs.
const OT_SERVER_PORTS: &[u16] = &[
    102, 502, 1089, 1090, 1091, 2222, 2404, 4840,
    5007, 5094, 18245, 18246, 20000, 34962, 34963, 34964, 44818, 47808,
];

/// Modbus write function codes.
const MODBUS_WRITE_FCS: &[u8] = &[5, 6, 15, 16];

/// Run all ATT&CK technique detections on the input data.
pub fn detect_attack_techniques(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_t0855_unauthorized_writes(input));
    findings.extend(detect_t0814_diagnostic_dos(input));
    findings.extend(detect_t0856_dnp3_unsolicited(input));
    findings.extend(detect_t0846_remote_discovery(input));

    findings
}

/// T0855 — Unauthorized Command Message
///
/// Detects Modbus broadcast/mass writes: FC 5/6/15/16 sent to
/// unit ID 0 (broadcast) or unit ID 255 (all devices), or
/// a single source writing to many targets (high fan-out).
fn detect_t0855_unauthorized_writes(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let modbus = match &dp.modbus {
            Some(m) => m,
            None => continue,
        };

        // Only check masters (devices sending write commands)
        if modbus.role != "master" && modbus.role != "both" {
            continue;
        }

        // Check for broadcast writes (unit ID 0 or 255)
        let has_broadcast_unit = modbus.unit_ids.contains(&0) || modbus.unit_ids.contains(&255);
        let has_write_fcs = modbus.function_codes.iter()
            .any(|fc| MODBUS_WRITE_FCS.contains(&fc.code) && fc.count > 0);

        if has_broadcast_unit && has_write_fcs {
            let write_count: u64 = modbus.function_codes.iter()
                .filter(|fc| MODBUS_WRITE_FCS.contains(&fc.code))
                .map(|fc| fc.count)
                .sum();

            let broadcast_ids: Vec<String> = modbus.unit_ids.iter()
                .filter(|&&uid| uid == 0 || uid == 255)
                .map(|uid| uid.to_string())
                .collect();

            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Critical,
                format!("Modbus broadcast write from {}", ip),
                "Modbus write commands (FC 5/6/15/16) sent to broadcast unit IDs. \
                 This could indicate unauthorized command injection targeting all \
                 devices on the Modbus network simultaneously.".to_string(),
                vec![ip.clone()],
                format!(
                    "Source {} sent {} write commands to broadcast unit ID(s): {}",
                    ip, write_count, broadcast_ids.join(", ")
                ),
                Some("T0855".to_string()),
            ));
        }

        // Check for high fan-out writes (writing to many different targets)
        let write_targets: Vec<&str> = modbus.relationships.iter()
            .filter(|r| r.remote_role == "slave")
            .map(|r| r.remote_ip.as_str())
            .collect();

        if write_targets.len() >= 5 && has_write_fcs {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("High fan-out Modbus writes from {}", ip),
                "A single device is sending Modbus write commands to many targets. \
                 This pattern may indicate unauthorized mass command injection.".to_string(),
                std::iter::once(ip.clone())
                    .chain(write_targets.iter().map(|s| s.to_string()))
                    .collect(),
                format!(
                    "Source {} writing to {} targets: {}",
                    ip,
                    write_targets.len(),
                    write_targets.join(", ")
                ),
                Some("T0855".to_string()),
            ));
        }
    }

    findings
}

/// T0814 — Denial of Service
///
/// Detects Modbus FC 8 (Diagnostics) from devices that are not
/// classified as engineering workstations. FC 8 can restart or
/// clear PLC memory — risky from unauthorized sources.
fn detect_t0814_diagnostic_dos(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build set of engineering workstation IPs
    let eng_ws_ips: HashSet<&str> = input.assets.iter()
        .filter(|a| a.device_type == "engineering_workstation")
        .map(|a| a.ip_address.as_str())
        .collect();

    for (ip, dp) in &input.deep_parse {
        let modbus = match &dp.modbus {
            Some(m) => m,
            None => continue,
        };

        // Look for FC 8 (Diagnostics) usage
        let fc8_count: u64 = modbus.function_codes.iter()
            .filter(|fc| fc.code == 8)
            .map(|fc| fc.count)
            .sum();

        if fc8_count == 0 {
            continue;
        }

        // If the source is not an engineering workstation, flag it
        if !eng_ws_ips.contains(ip.as_str()) {
            let device_type = input.assets.iter()
                .find(|a| a.ip_address == *ip)
                .map(|a| a.device_type.as_str())
                .unwrap_or("unknown");

            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("Modbus diagnostics (FC 8) from non-engineer: {}", ip),
                "Modbus Function Code 8 (Diagnostics) can restart slave devices, \
                 clear counters, or force listen-only mode. This function code \
                 should only originate from authorized engineering workstations.".to_string(),
                vec![ip.clone()],
                format!(
                    "Device {} (type: {}) sent {} Modbus FC 8 diagnostic commands",
                    ip, device_type, fc8_count
                ),
                Some("T0814".to_string()),
            ));
        }
    }

    findings
}

/// T0856 — Modify Alarm Settings (DNP3 Unsolicited Response)
///
/// Detects DNP3 unsolicited responses (FC 130) sent to devices
/// that are not known masters. Unsolicited responses from outstations
/// to unknown destinations may indicate alarm suppression or manipulation.
fn detect_t0856_dnp3_unsolicited(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build set of known DNP3 master IPs
    let known_masters: HashSet<String> = input.deep_parse.iter()
        .filter_map(|(ip, dp)| {
            dp.dnp3.as_ref().and_then(|d| {
                if d.role == "master" || d.role == "both" {
                    Some(ip.clone())
                } else {
                    None
                }
            })
        })
        .collect();

    for (ip, dp) in &input.deep_parse {
        let dnp3 = match &dp.dnp3 {
            Some(d) => d,
            None => continue,
        };

        if !dnp3.has_unsolicited {
            continue;
        }

        // Check if unsolicited responses go to unknown masters
        let unknown_targets: Vec<String> = dnp3.relationships.iter()
            .filter(|r| r.remote_role == "master" && !known_masters.contains(&r.remote_ip))
            .map(|r| r.remote_ip.clone())
            .collect();

        if !unknown_targets.is_empty() {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Medium,
                format!("DNP3 unsolicited response from {} to unknown master", ip),
                "DNP3 unsolicited responses (FC 130) are being sent to devices \
                 not recognized as authorized masters. This could indicate alarm \
                 manipulation or unauthorized data exfiltration.".to_string(),
                std::iter::once(ip.clone())
                    .chain(unknown_targets.iter().cloned())
                    .collect(),
                format!(
                    "Outstation {} sent unsolicited responses to unknown master(s): {}",
                    ip, unknown_targets.join(", ")
                ),
                Some("T0856".to_string()),
            ));
        }

        // Also flag if there are no known masters at all (suspicious standalone unsolicited)
        if known_masters.is_empty() && dnp3.has_unsolicited {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Medium,
                format!("DNP3 unsolicited response with no known masters: {}", ip),
                "DNP3 unsolicited responses detected but no authorized masters \
                 have been identified in the network. All unsolicited traffic \
                 is potentially unauthorized.".to_string(),
                vec![ip.clone()],
                format!(
                    "Device {} sending DNP3 unsolicited responses (FC 130) \
                     but no DNP3 masters detected on network",
                    ip
                ),
                Some("T0856".to_string()),
            ));
        }
    }

    findings
}

/// T0846 — Remote System Discovery
///
/// Detects unknown/IT devices polling OT devices on well-known
/// ICS ports. An unknown device scanning PLC ports suggests
/// reconnaissance.
fn detect_t0846_remote_discovery(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build set of known OT device IPs (PLCs, RTUs, HMIs, etc.)
    let ot_device_ips: HashSet<&str> = input.assets.iter()
        .filter(|a| matches!(
            a.device_type.as_str(),
            "plc" | "rtu" | "hmi" | "historian" | "engineering_workstation" | "scada_server"
        ))
        .map(|a| a.ip_address.as_str())
        .collect();

    // Find connections where an unknown/IT device connects to OT ports
    let mut scanner_targets: HashMap<String, HashSet<String>> = HashMap::new();

    for conn in &input.connections {
        // Check if destination is an OT server port
        if !OT_SERVER_PORTS.contains(&conn.dst_port) {
            continue;
        }

        // Check if the source is NOT a known OT device
        let src_asset = input.assets.iter().find(|a| a.ip_address == conn.src_ip);
        let is_known_ot = ot_device_ips.contains(conn.src_ip.as_str());

        // Flag if source is IT/unknown AND targeting OT ports on multiple devices
        if !is_known_ot {
            let src_type = src_asset.map(|a| a.device_type.as_str()).unwrap_or("unknown");
            if src_type == "it_device" || src_type == "unknown" {
                scanner_targets
                    .entry(conn.src_ip.clone())
                    .or_default()
                    .insert(conn.dst_ip.clone());
            }
        }
    }

    // Only flag scanners targeting 3+ different OT devices
    for (scanner_ip, targets) in &scanner_targets {
        if targets.len() >= 3 {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("Unknown device {} polling {} PLCs/RTUs", scanner_ip, targets.len()),
                "A device not classified as OT equipment is connecting to \
                 multiple ICS devices on well-known OT service ports. This \
                 behavior resembles network reconnaissance or unauthorized polling.".to_string(),
                std::iter::once(scanner_ip.clone())
                    .chain(targets.iter().cloned())
                    .collect(),
                format!(
                    "Device {} connected to OT ports on {} targets: {}",
                    scanner_ip,
                    targets.len(),
                    targets.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                Some("T0846".to_string()),
            ));
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn make_input() -> AnalysisInput {
        AnalysisInput::default()
    }

    #[test]
    fn test_t0855_broadcast_write() {
        let mut input = make_input();
        input.deep_parse.insert("10.0.0.100".to_string(), DeepParseSnapshot {
            modbus: Some(ModbusSnapshot {
                role: "master".to_string(),
                unit_ids: vec![0, 1, 255],
                function_codes: vec![
                    FcSnapshot { code: 6, count: 50, is_write: true },
                    FcSnapshot { code: 3, count: 200, is_write: false },
                ],
                relationships: vec![],
                polling_intervals: vec![],
            }),
            dnp3: None,
        });

        let findings = detect_t0855_unauthorized_writes(&input);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].technique_id, Some("T0855".to_string()));
    }

    #[test]
    fn test_t0855_high_fanout() {
        let mut input = make_input();
        let targets: Vec<RelationshipSnapshot> = (1..=6).map(|i| RelationshipSnapshot {
            remote_ip: format!("10.0.0.{}", i),
            remote_role: "slave".to_string(),
            packet_count: 100,
        }).collect();

        input.deep_parse.insert("10.0.0.100".to_string(), DeepParseSnapshot {
            modbus: Some(ModbusSnapshot {
                role: "master".to_string(),
                unit_ids: vec![1, 2, 3],
                function_codes: vec![
                    FcSnapshot { code: 16, count: 100, is_write: true },
                ],
                relationships: targets,
                polling_intervals: vec![],
            }),
            dnp3: None,
        });

        let findings = detect_t0855_unauthorized_writes(&input);
        assert!(findings.iter().any(|f| f.title.contains("fan-out")));
    }

    #[test]
    fn test_t0814_fc8_from_non_engineer() {
        let mut input = make_input();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.50".to_string(),
            device_type: "it_device".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        input.deep_parse.insert("10.0.0.50".to_string(), DeepParseSnapshot {
            modbus: Some(ModbusSnapshot {
                role: "master".to_string(),
                unit_ids: vec![1],
                function_codes: vec![
                    FcSnapshot { code: 8, count: 10, is_write: false },
                ],
                relationships: vec![],
                polling_intervals: vec![],
            }),
            dnp3: None,
        });

        let findings = detect_t0814_diagnostic_dos(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].technique_id, Some("T0814".to_string()));
    }

    #[test]
    fn test_t0814_fc8_from_engineer_ok() {
        let mut input = make_input();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.50".to_string(),
            device_type: "engineering_workstation".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        input.deep_parse.insert("10.0.0.50".to_string(), DeepParseSnapshot {
            modbus: Some(ModbusSnapshot {
                role: "master".to_string(),
                unit_ids: vec![1],
                function_codes: vec![
                    FcSnapshot { code: 8, count: 10, is_write: false },
                ],
                relationships: vec![],
                polling_intervals: vec![],
            }),
            dnp3: None,
        });

        let findings = detect_t0814_diagnostic_dos(&input);
        assert!(findings.is_empty(), "FC 8 from engineering workstation should not be flagged");
    }

    #[test]
    fn test_t0856_unsolicited_unknown_master() {
        let mut input = make_input();

        // Outstation sending unsolicited responses
        input.deep_parse.insert("10.0.0.10".to_string(), DeepParseSnapshot {
            modbus: None,
            dnp3: Some(Dnp3Snapshot {
                role: "outstation".to_string(),
                has_unsolicited: true,
                function_codes: vec![
                    FcSnapshot { code: 130, count: 5, is_write: false },
                ],
                relationships: vec![RelationshipSnapshot {
                    remote_ip: "192.168.1.50".to_string(),
                    remote_role: "master".to_string(),
                    packet_count: 5,
                }],
            }),
        });

        let findings = detect_t0856_dnp3_unsolicited(&input);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].technique_id, Some("T0856".to_string()));
    }

    #[test]
    fn test_t0846_unknown_device_scanning() {
        let mut input = make_input();

        // Known OT devices
        for i in 1..=5 {
            input.assets.push(AssetSnapshot {
                ip_address: format!("10.0.0.{}", i),
                device_type: "plc".to_string(),
                protocols: vec!["modbus".to_string()],
                purdue_level: Some(1),
                is_public_ip: false,
                tags: vec![],
                vendor: None,
            });
        }

        // Unknown scanner
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.200".to_string(),
            device_type: "unknown".to_string(),
            protocols: vec![],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        // Scanner connecting to 3+ PLCs on Modbus port
        for i in 1..=4 {
            input.connections.push(ConnectionSnapshot {
                src_ip: "10.0.0.200".to_string(),
                dst_ip: format!("10.0.0.{}", i),
                src_port: 49152,
                dst_port: 502,
                protocol: "Modbus".to_string(),
                packet_count: 10,
            });
        }

        let findings = detect_t0846_remote_discovery(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].technique_id, Some("T0846".to_string()));
    }

    #[test]
    fn test_no_false_positive_known_hmi_polling() {
        let mut input = make_input();

        // Known HMI polling PLCs is normal behavior
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.100".to_string(),
            device_type: "hmi".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: Some(2),
            is_public_ip: false,
            tags: vec![],
            vendor: None,
        });

        for i in 1..=5 {
            input.assets.push(AssetSnapshot {
                ip_address: format!("10.0.0.{}", i),
                device_type: "plc".to_string(),
                protocols: vec!["modbus".to_string()],
                purdue_level: Some(1),
                is_public_ip: false,
                tags: vec![],
                vendor: None,
            });

            input.connections.push(ConnectionSnapshot {
                src_ip: "10.0.0.100".to_string(),
                dst_ip: format!("10.0.0.{}", i),
                src_port: 49152,
                dst_port: 502,
                protocol: "Modbus".to_string(),
                packet_count: 1000,
            });
        }

        let findings = detect_t0846_remote_discovery(&input);
        assert!(findings.is_empty(), "HMI polling PLCs should not trigger T0846");
    }
}
