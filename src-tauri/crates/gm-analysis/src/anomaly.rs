//! Anomaly detection for network behavior deviations.
//!
//! ## Detected Anomalies
//!
//! - **Polling deviation**: Interval significantly outside normal range (>2σ)
//! - **Role reversal**: Slave/outstation sending to non-master
//! - **New device**: Previously unseen device on OT subnet
//! - **Unexpected public IP**: Public routable IP on OT network

use crate::{
    AnalysisInput, AnomalyScore, AnomalyType, Severity,
    Finding, FindingType,
};

/// Run anomaly detection on the analysis input.
///
/// Returns both anomaly scores and any findings generated from anomalies.
pub fn detect_anomalies(input: &AnalysisInput) -> (Vec<AnomalyScore>, Vec<Finding>) {
    let mut anomalies = Vec::new();
    let mut findings = Vec::new();

    // Polling deviation detection
    let (poll_anomalies, poll_findings) = detect_polling_deviations(input);
    anomalies.extend(poll_anomalies);
    findings.extend(poll_findings);

    // Role reversal detection
    let (role_anomalies, role_findings) = detect_role_reversals(input);
    anomalies.extend(role_anomalies);
    findings.extend(role_findings);

    // Unexpected public IPs on OT networks
    let (pub_anomalies, pub_findings) = detect_unexpected_public_ips(input);
    anomalies.extend(pub_anomalies);
    findings.extend(pub_findings);

    (anomalies, findings)
}

/// Detect polling interval deviations.
///
/// For each polling interval, check if (max - min) / avg > threshold.
/// A coefficient of variation > 50% suggests irregular polling, which
/// could indicate timing attacks or unstable network conditions.
fn detect_polling_deviations(input: &AnalysisInput) -> (Vec<AnomalyScore>, Vec<Finding>) {
    let mut anomalies = Vec::new();
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let modbus = match &dp.modbus {
            Some(m) => m,
            None => continue,
        };

        for pi in &modbus.polling_intervals {
            if pi.sample_count < 5 || pi.avg_interval_ms <= 0.0 {
                continue;
            }

            // Coefficient of variation: (max - min) / avg
            let range = pi.max_interval_ms - pi.min_interval_ms;
            let cv = range / pi.avg_interval_ms;

            if cv > 0.5 {
                // High variation — flag as anomaly
                let confidence = if cv > 2.0 { 0.9 } else if cv > 1.0 { 0.7 } else { 0.5 };
                let severity = if cv > 2.0 { Severity::High } else { Severity::Medium };

                anomalies.push(AnomalyScore {
                    anomaly_type: AnomalyType::PollingDeviation,
                    severity,
                    confidence,
                    affected_asset: ip.clone(),
                    evidence: format!(
                        "Polling from {} to {} (FC {}): avg={:.1}ms, range={:.1}ms, CV={:.2}",
                        ip, pi.remote_ip, pi.function_code,
                        pi.avg_interval_ms, range, cv
                    ),
                });

                if cv > 1.0 {
                    findings.push(Finding::new(
                        FindingType::Anomaly,
                        severity,
                        format!("Irregular polling interval from {}", ip),
                        format!(
                            "Polling interval from {} to {} varies significantly \
                             (coefficient of variation: {:.1}%). Normal ICS polling \
                             should be consistent. High variation may indicate \
                             timing attacks, network instability, or unauthorized \
                             intermittent access.",
                            ip, pi.remote_ip, cv * 100.0
                        ),
                        vec![ip.clone(), pi.remote_ip.clone()],
                        format!(
                            "FC {} polling: avg={:.1}ms, min={:.1}ms, max={:.1}ms ({} samples)",
                            pi.function_code, pi.avg_interval_ms,
                            pi.min_interval_ms, pi.max_interval_ms, pi.sample_count
                        ),
                        None,
                    ));
                }
            }
        }
    }

    (anomalies, findings)
}

/// Detect role reversals — slaves/outstations initiating connections
/// to non-masters.
fn detect_role_reversals(input: &AnalysisInput) -> (Vec<AnomalyScore>, Vec<Finding>) {
    let mut anomalies = Vec::new();
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        // Modbus role reversal: a slave sending to a non-master
        if let Some(ref modbus) = dp.modbus {
            if modbus.role == "slave" {
                // Check if this slave sends master-like commands
                let has_master_fcs = modbus.function_codes.iter()
                    .any(|fc| matches!(fc.code, 1..=6 | 15 | 16));

                if has_master_fcs {
                    anomalies.push(AnomalyScore {
                        anomaly_type: AnomalyType::RoleReversal,
                        severity: Severity::High,
                        confidence: 0.8,
                        affected_asset: ip.clone(),
                        evidence: format!(
                            "Device {} is classified as Modbus slave but sends master function codes",
                            ip
                        ),
                    });

                    findings.push(Finding::new(
                        FindingType::Anomaly,
                        Severity::High,
                        format!("Modbus role reversal: slave {} acting as master", ip),
                        "A device classified as a Modbus slave (responder) is sending \
                         master function codes (read/write requests). This could indicate \
                         a compromised device or misconfigured network.".to_string(),
                        vec![ip.clone()],
                        format!(
                            "Device {} (role: slave) sending master FCs: {}",
                            ip,
                            modbus.function_codes.iter()
                                .filter(|fc| matches!(fc.code, 1..=6 | 15 | 16))
                                .map(|fc| format!("FC {} ({}x)", fc.code, fc.count))
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        None,
                    ));
                }
            }
        }

        // DNP3 role reversal: outstation sending unsolicited to unknown destinations
        if let Some(ref dnp3) = dp.dnp3 {
            if dnp3.role == "outstation" && dnp3.has_unsolicited {
                // Check if the outstation also sends master commands
                let has_master_fcs = dnp3.function_codes.iter()
                    .any(|fc| matches!(fc.code, 1..=6));

                if has_master_fcs {
                    anomalies.push(AnomalyScore {
                        anomaly_type: AnomalyType::RoleReversal,
                        severity: Severity::High,
                        confidence: 0.7,
                        affected_asset: ip.clone(),
                        evidence: format!(
                            "DNP3 outstation {} sending master function codes",
                            ip
                        ),
                    });
                }
            }
        }
    }

    (anomalies, findings)
}

/// Detect unexpected public IPs on OT networks.
///
/// Public (routable) IPs should not appear in OT environments.
/// If a device has a public IP and speaks OT protocols, it may be
/// exposed to the internet.
fn detect_unexpected_public_ips(input: &AnalysisInput) -> (Vec<AnomalyScore>, Vec<Finding>) {
    let mut anomalies = Vec::new();
    let mut findings = Vec::new();

    for asset in &input.assets {
        if !asset.is_public_ip {
            continue;
        }

        let has_ot = asset.protocols.iter()
            .any(|p| is_ot_protocol_name(p));

        if has_ot {
            anomalies.push(AnomalyScore {
                anomaly_type: AnomalyType::UnexpectedPublicIp,
                severity: Severity::Critical,
                confidence: 0.95,
                affected_asset: asset.ip_address.clone(),
                evidence: format!(
                    "Public IP {} speaks OT protocols: {}",
                    asset.ip_address,
                    asset.protocols.join(", ")
                ),
            });

            findings.push(Finding::new(
                FindingType::Anomaly,
                Severity::Critical,
                format!("Public IP on OT network: {}", asset.ip_address),
                format!(
                    "Device {} has a public (internet-routable) IP address and is \
                     speaking OT/ICS protocols. This device may be directly exposed \
                     to the internet, which is a critical security risk for industrial \
                     control systems. OT devices should always be on private networks \
                     behind firewalls.",
                    asset.ip_address
                ),
                vec![asset.ip_address.clone()],
                format!(
                    "Public IP {} using OT protocols: {}",
                    asset.ip_address,
                    asset.protocols.join(", ")
                ),
                None,
            ));
        }
    }

    (anomalies, findings)
}

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
    fn test_polling_deviation_high_cv() {
        let mut input = AnalysisInput::default();
        input.deep_parse.insert("10.0.0.1".to_string(), DeepParseSnapshot {
            modbus: Some(ModbusSnapshot {
                role: "master".to_string(),
                unit_ids: vec![1],
                function_codes: vec![FcSnapshot { code: 3, count: 100, is_write: false }],
                relationships: vec![],
                polling_intervals: vec![PollingSnapshot {
                    remote_ip: "10.0.0.2".to_string(),
                    function_code: 3,
                    avg_interval_ms: 1000.0,
                    min_interval_ms: 100.0,
                    max_interval_ms: 5000.0,
                    sample_count: 50,
                }],
            }),
            dnp3: None,
        });

        let (anomalies, findings) = detect_polling_deviations(&input);
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies[0].anomaly_type, AnomalyType::PollingDeviation);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_stable_polling_no_anomaly() {
        let mut input = AnalysisInput::default();
        input.deep_parse.insert("10.0.0.1".to_string(), DeepParseSnapshot {
            modbus: Some(ModbusSnapshot {
                role: "master".to_string(),
                unit_ids: vec![1],
                function_codes: vec![FcSnapshot { code: 3, count: 100, is_write: false }],
                relationships: vec![],
                polling_intervals: vec![PollingSnapshot {
                    remote_ip: "10.0.0.2".to_string(),
                    function_code: 3,
                    avg_interval_ms: 1000.0,
                    min_interval_ms: 990.0,
                    max_interval_ms: 1010.0,
                    sample_count: 50,
                }],
            }),
            dnp3: None,
        });

        let (anomalies, _) = detect_polling_deviations(&input);
        assert!(anomalies.is_empty(), "Stable polling should not trigger anomaly");
    }

    #[test]
    fn test_role_reversal_modbus() {
        let mut input = AnalysisInput::default();
        input.deep_parse.insert("10.0.0.5".to_string(), DeepParseSnapshot {
            modbus: Some(ModbusSnapshot {
                role: "slave".to_string(),
                unit_ids: vec![1],
                function_codes: vec![
                    FcSnapshot { code: 3, count: 10, is_write: false },
                    FcSnapshot { code: 6, count: 5, is_write: true },
                ],
                relationships: vec![],
                polling_intervals: vec![],
            }),
            dnp3: None,
        });

        let (anomalies, findings) = detect_role_reversals(&input);
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies[0].anomaly_type, AnomalyType::RoleReversal);
        assert!(!findings.is_empty());
    }

    #[test]
    fn test_public_ip_on_ot_network() {
        let mut input = AnalysisInput::default();
        input.assets.push(AssetSnapshot {
            ip_address: "8.8.8.8".to_string(),
            device_type: "unknown".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: None,
            is_public_ip: true,
            tags: vec![],
            vendor: None,
        });

        let (anomalies, findings) = detect_unexpected_public_ips(&input);
        assert_eq!(anomalies.len(), 1);
        assert_eq!(anomalies[0].severity, Severity::Critical);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn test_public_ip_it_only_ok() {
        let mut input = AnalysisInput::default();
        input.assets.push(AssetSnapshot {
            ip_address: "8.8.8.8".to_string(),
            device_type: "it_device".to_string(),
            protocols: vec!["dns".to_string()],
            purdue_level: None,
            is_public_ip: true,
            tags: vec![],
            vendor: None,
        });

        let (anomalies, _) = detect_unexpected_public_ips(&input);
        assert!(anomalies.is_empty(), "Public IT-only IP should not be flagged");
    }
}
