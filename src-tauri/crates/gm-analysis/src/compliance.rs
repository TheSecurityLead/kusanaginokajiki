//! Compliance Framework Mapping (Phase 14E)
//!
//! Maps KNK analysis findings to IEC 62443, NIST 800-82, and NERC CIP
//! requirements. Produces a compliance report showing which requirements
//! are met, partially met, have gaps, or cannot be assessed passively.
//!
//! ## Supported Frameworks
//!
//! | ID | Name |
//! |----|------|
//! | `iec62443` | IEC 62443 Industrial Cybersecurity Standard |
//! | `nist80082` | NIST SP 800-82 Rev 3 (ICS Security Guide) |
//! | `nerccip` | NERC CIP (Critical Infrastructure Protection — power sector) |

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::{AssetSnapshot, ConnectionSnapshot, Finding, FindingType};

// Embedded compliance mapping database — loaded at compile time.
const COMPLIANCE_MAPPINGS_JSON: &str = include_str!("../data/compliance_mappings.json");

/// A raw compliance mapping entry from the embedded JSON database.
#[derive(Debug, Clone, Deserialize)]
struct MappingEntry {
    framework: String,
    requirement_id: String,
    requirement_name: String,
    check_type: String,
    description: String,
}

/// The compliance status of a single requirement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ComplianceStatus {
    /// Findings confirm a violation or gap in this control.
    Gap,
    /// Some evidence of compliance but incomplete (e.g., some devices hardened).
    Partial,
    /// No violations found; passive evidence supports compliance.
    Met,
    /// Insufficient data to determine compliance from passive analysis.
    NotAssessed,
}

/// A compliance finding for a single framework requirement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceMapping {
    /// Framework identifier: "iec62443", "nist80082", "nerccip"
    pub framework: String,
    /// Requirement identifier (e.g., "SR 5.1", "5.3.2", "CIP-005-7 R1")
    pub requirement_id: String,
    /// Short name of the requirement
    pub requirement_name: String,
    /// Compliance status determined from analysis results
    pub status: ComplianceStatus,
    /// Human-readable description of what was found
    pub evidence: String,
    /// Full requirement description from the standard
    pub description: String,
}

/// Findings title keywords used to match specific security issues.
struct CheckInputs<'a> {
    findings: &'a [Finding],
    assets: &'a [AssetSnapshot],
    connections: &'a [ConnectionSnapshot],
}

/// Generate a compliance report for the given framework.
///
/// `framework` must be one of: `"iec62443"`, `"nist80082"`, `"nerccip"`.
/// Returns all requirement mappings for that framework with their evaluated status.
pub fn generate_compliance_report(
    findings: &[Finding],
    assets: &[AssetSnapshot],
    connections: &[ConnectionSnapshot],
    framework: &str,
) -> Vec<ComplianceMapping> {
    let entries: Vec<MappingEntry> =
        serde_json::from_str(COMPLIANCE_MAPPINGS_JSON).unwrap_or_default();

    let inputs = CheckInputs {
        findings,
        assets,
        connections,
    };

    entries
        .into_iter()
        .filter(|e| e.framework == framework)
        .map(|entry| {
            let (status, evidence) = evaluate_check(&entry.check_type, &inputs);
            ComplianceMapping {
                framework: entry.framework,
                requirement_id: entry.requirement_id,
                requirement_name: entry.requirement_name,
                status,
                evidence,
                description: entry.description,
            }
        })
        .collect()
}

/// Returns a sorted list of supported framework identifiers.
pub fn supported_frameworks() -> Vec<&'static str> {
    vec!["iec62443", "nist80082", "nerccip"]
}

// ─── Check Evaluation ─────────────────────────────────────────

/// Evaluate a single compliance check type against the current analysis state.
///
/// Returns (status, evidence_string).
fn evaluate_check(check_type: &str, inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    match check_type {
        "flat_network" => check_flat_network(inputs),
        "purdue_violations" => check_purdue_violations(inputs),
        "default_creds" => check_default_creds(inputs),
        "cleartext_ot" => check_cleartext_ot(inputs),
        "attack_findings" => check_attack_findings(inputs),
        "device_inventory" => check_device_inventory(inputs),
        "purdue_assigned" => check_purdue_assigned(inputs),
        "external_access" => check_external_access(inputs),
        "no_encryption" => check_no_encryption(inputs),
        "redundancy" => check_redundancy(inputs),
        "internet_exposure" => check_internet_exposure(inputs),
        _ => (
            ComplianceStatus::NotAssessed,
            format!("Unknown check type: {check_type}"),
        ),
    }
}

/// Check for flat network architecture (no segmentation).
fn check_flat_network(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    let flat = inputs.findings.iter().find(|f| {
        f.title.to_lowercase().contains("flat network")
            || (f.technique_id.as_deref() == Some("T0869"))
    });

    if let Some(f) = flat {
        return (
            ComplianceStatus::Gap,
            format!("VIOLATION: {} — {}", f.title, f.evidence),
        );
    }

    // Check for Purdue violations as evidence of segmentation issues
    let purdue_violations = inputs
        .findings
        .iter()
        .filter(|f| f.finding_type == FindingType::PurdueViolation)
        .count();

    if purdue_violations > 0 {
        return (
            ComplianceStatus::Partial,
            format!(
                "{purdue_violations} cross-zone communication violation(s) detected. \
                 Network has some segmentation but zone boundaries are not enforced."
            ),
        );
    }

    if inputs.assets.is_empty() {
        return (
            ComplianceStatus::NotAssessed,
            "No asset data available. Import a PCAP and run analysis first.".to_string(),
        );
    }

    (
        ComplianceStatus::Met,
        format!(
            "No flat network findings detected across {} observed assets. \
             Note: passive analysis cannot confirm firewall rule completeness.",
            inputs.assets.len()
        ),
    )
}

/// Check for cross-Purdue zone violations.
fn check_purdue_violations(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    let violations: Vec<&Finding> = inputs
        .findings
        .iter()
        .filter(|f| f.finding_type == FindingType::PurdueViolation)
        .collect();

    if violations.is_empty() {
        if inputs.assets.is_empty() {
            return (
                ComplianceStatus::NotAssessed,
                "No asset data. Run analysis to evaluate zone boundaries.".to_string(),
            );
        }
        return (
            ComplianceStatus::Met,
            format!(
                "No cross-zone violations detected. {} asset(s) analyzed.",
                inputs.assets.len()
            ),
        );
    }

    let affected: Vec<String> = violations
        .iter()
        .flat_map(|f| f.affected_assets.iter().cloned())
        .collect::<HashSet<_>>()
        .into_iter()
        .take(5)
        .collect();

    (
        ComplianceStatus::Gap,
        format!(
            "{} cross-Purdue-zone violation(s) found. Affected assets include: {}{}",
            violations.len(),
            affected.join(", "),
            if violations.len() > 5 {
                " (and more)"
            } else {
                ""
            }
        ),
    )
}

/// Check for default credential warnings.
fn check_default_creds(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    let cred_findings: Vec<&Finding> = inputs
        .findings
        .iter()
        .filter(|f| {
            f.title.to_lowercase().contains("default credential")
                || f.title.to_lowercase().contains("default password")
        })
        .collect();

    if !cred_findings.is_empty() {
        return (
            ComplianceStatus::Gap,
            format!(
                "{} device(s) match known default credential patterns. \
                 Immediate password changes required.",
                cred_findings.len()
            ),
        );
    }

    if inputs.assets.is_empty() {
        return (
            ComplianceStatus::NotAssessed,
            "No asset data. Import PCAP and run analysis to check default credentials.".to_string(),
        );
    }

    (
        ComplianceStatus::Met,
        format!(
            "No default credential matches detected across {} asset(s). \
             Note: passive analysis cannot verify authentication is enforced.",
            inputs.assets.len()
        ),
    )
}

/// Check for cleartext OT protocol usage.
fn check_cleartext_ot(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    let cleartext_finding = inputs.findings.iter().find(|f| {
        f.title.to_lowercase().contains("cleartext")
            || f.title.to_lowercase().contains("unencrypted ot")
    });

    if cleartext_finding.is_some() {
        // Count OT connections for context
        let ot_conns: usize = inputs
            .connections
            .iter()
            .filter(|c| is_ot_protocol(&c.protocol))
            .count();

        return (
            ComplianceStatus::Gap,
            format!(
                "Cleartext OT protocols detected in {ot_conns} connection(s). \
                 Modbus, DNP3, IEC 104, and similar protocols transmit commands without encryption."
            ),
        );
    }

    // If we have OT connections but no cleartext finding, check directly
    let ot_protocols_seen: HashSet<&str> = inputs
        .connections
        .iter()
        .filter(|c| is_ot_protocol(&c.protocol))
        .map(|c| c.protocol.as_str())
        .collect();

    if !ot_protocols_seen.is_empty() {
        let mut protos: Vec<&str> = ot_protocols_seen.into_iter().collect();
        protos.sort_unstable();
        return (
            ComplianceStatus::Gap,
            format!(
                "Unencrypted OT protocols observed: {}. \
                 These protocols transmit process data and control commands in plaintext.",
                protos.join(", ")
            ),
        );
    }

    if inputs.connections.is_empty() {
        return (
            ComplianceStatus::NotAssessed,
            "No connection data. Import a PCAP to evaluate encryption coverage.".to_string(),
        );
    }

    (
        ComplianceStatus::Met,
        "No unencrypted OT protocol traffic detected.".to_string(),
    )
}

/// Check for active ATT&CK findings.
fn check_attack_findings(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    let attack_findings: Vec<&Finding> = inputs
        .findings
        .iter()
        .filter(|f| f.finding_type == FindingType::AttackTechnique)
        .collect();

    if attack_findings.is_empty() {
        if inputs.assets.is_empty() {
            return (
                ComplianceStatus::NotAssessed,
                "No analysis data. Run analysis to evaluate security posture.".to_string(),
            );
        }
        return (
            ComplianceStatus::Met,
            format!(
                "No ATT&CK for ICS techniques detected. {} asset(s) and {} connection(s) analyzed.",
                inputs.assets.len(),
                inputs.connections.len()
            ),
        );
    }

    let critical = attack_findings
        .iter()
        .filter(|f| f.severity == crate::Severity::Critical)
        .count();
    let high = attack_findings
        .iter()
        .filter(|f| f.severity == crate::Severity::High)
        .count();

    (
        ComplianceStatus::Gap,
        format!(
            "{} ATT&CK finding(s): {} critical, {} high. Active adversary techniques detected — \
             immediate investigation and incident response required.",
            attack_findings.len(),
            critical,
            high
        ),
    )
}

/// Check device inventory completeness.
fn check_device_inventory(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    if inputs.assets.is_empty() {
        return (
            ComplianceStatus::NotAssessed,
            "No asset data. Import a PCAP to begin device discovery.".to_string(),
        );
    }

    let identified = inputs
        .assets
        .iter()
        .filter(|a| a.device_type != "unknown")
        .count();
    let total = inputs.assets.len();
    let pct = (identified * 100) / total.max(1);

    if pct >= 80 {
        (
            ComplianceStatus::Met,
            format!(
                "{total} device(s) discovered. {identified} ({pct}%) have identified device types. \
                 Passive discovery provides inventory evidence (active confirmation recommended)."
            ),
        )
    } else {
        (
            ComplianceStatus::Partial,
            format!(
                "{total} device(s) discovered. Only {identified} ({pct}%) have identified device types. \
                 Additional active discovery or physical inspection needed for complete inventory."
            ),
        )
    }
}

/// Check Purdue level assignment coverage.
fn check_purdue_assigned(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    if inputs.assets.is_empty() {
        return (
            ComplianceStatus::NotAssessed,
            "No asset data. Run analysis to auto-assign Purdue levels.".to_string(),
        );
    }

    let assigned = inputs
        .assets
        .iter()
        .filter(|a| a.purdue_level.is_some())
        .count();
    let total = inputs.assets.len();
    let pct = (assigned * 100) / total.max(1);

    if pct >= 90 {
        (
            ComplianceStatus::Met,
            format!("{assigned}/{total} ({pct}%) device(s) assigned to Purdue Model zones."),
        )
    } else if pct >= 50 {
        (
            ComplianceStatus::Partial,
            format!(
                "{assigned}/{total} ({pct}%) device(s) assigned. \
                 Run analysis to auto-assign remaining devices."
            ),
        )
    } else {
        (
            ComplianceStatus::Gap,
            format!(
                "Only {assigned}/{total} ({pct}%) device(s) have Purdue zone assignments. \
                 Zone design cannot proceed without complete assignment."
            ),
        )
    }
}

/// Check for external/remote access findings.
fn check_external_access(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    // T0822 = External Remote Services
    let remote_finding = inputs.findings.iter().find(|f| {
        f.technique_id.as_deref() == Some("T0822")
            || f.title.to_lowercase().contains("remote access")
            || f.title.to_lowercase().contains("external remote")
    });

    let external_conns = inputs
        .connections
        .iter()
        .filter(|c| {
            inputs
                .assets
                .iter()
                .find(|a| a.ip_address == c.src_ip || a.ip_address == c.dst_ip)
                .map(|a| a.is_public_ip)
                .unwrap_or(false)
        })
        .count();

    if let Some(f) = remote_finding {
        return (
            ComplianceStatus::Gap,
            format!(
                "FINDING: {} — {}. External remote access detected and requires authorization review.",
                f.title, f.evidence
            ),
        );
    }

    if external_conns > 0 {
        return (
            ComplianceStatus::Partial,
            format!(
                "{external_conns} connection(s) involve public IP addresses. \
                 Verify all external access is authorized and monitored."
            ),
        );
    }

    if inputs.connections.is_empty() {
        return (
            ComplianceStatus::NotAssessed,
            "No connection data. Import a PCAP to evaluate remote access.".to_string(),
        );
    }

    (
        ComplianceStatus::Met,
        "No external remote access connections detected in captured traffic.".to_string(),
    )
}

/// Check for encryption / TLS usage.
fn check_no_encryption(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    check_cleartext_ot(inputs)
}

/// Check for redundancy protocol evidence.
fn check_redundancy(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    // Redundancy findings are tagged in findings by the switch_security module
    let redundancy_finding = inputs.findings.iter().find(|f| {
        f.title.to_lowercase().contains("redundancy")
            || f.title.to_lowercase().contains("mrp")
            || f.title.to_lowercase().contains("rstp")
            || f.title.to_lowercase().contains("hsr")
            || f.title.to_lowercase().contains("prp")
            || f.title.to_lowercase().contains("dlr")
    });

    // If a switch security finding mentions no redundancy
    let no_redundancy = inputs.findings.iter().find(|f| {
        f.title.to_lowercase().contains("no redundancy")
            || (f.title.to_lowercase().contains("redundanc")
                && f.description.to_lowercase().contains("not detected"))
    });

    if no_redundancy.is_some() {
        return (
            ComplianceStatus::Gap,
            "No redundancy protocols (MRP/RSTP/HSR/PRP/DLR) detected. \
             Network has no observable DoS protection mechanisms."
                .to_string(),
        );
    }

    if redundancy_finding.is_some() {
        return (
            ComplianceStatus::Met,
            "Redundancy protocol frames observed (MRP/RSTP/HSR/PRP/DLR). \
             Network resilience mechanisms are in place."
                .to_string(),
        );
    }

    (
        ComplianceStatus::NotAssessed,
        "Redundancy protocol status cannot be determined from available data. \
         Import a PCAP from the OT network segment to evaluate redundancy."
            .to_string(),
    )
}

/// Check for internet-exposed ICS devices.
fn check_internet_exposure(inputs: &CheckInputs<'_>) -> (ComplianceStatus, String) {
    let exposure_finding = inputs.findings.iter().find(|f| {
        f.title.to_lowercase().contains("internet")
            || f.title.to_lowercase().contains("public ip")
            || f.title.to_lowercase().contains("internet-exposed")
    });

    if let Some(f) = exposure_finding {
        return (
            ComplianceStatus::Gap,
            format!(
                "CRITICAL VIOLATION: {} — {}. ICS devices must not be directly internet-accessible.",
                f.title, f.evidence
            ),
        );
    }

    let public_ot_devices: Vec<&AssetSnapshot> = inputs
        .assets
        .iter()
        .filter(|a| {
            a.is_public_ip
                && (a.purdue_level.map(|l| l <= 3).unwrap_or(false)
                    || a.protocols.iter().any(|p| is_ot_protocol(p)))
        })
        .collect();

    if !public_ot_devices.is_empty() {
        let ips: Vec<&str> = public_ot_devices
            .iter()
            .map(|a| a.ip_address.as_str())
            .take(5)
            .collect();
        return (
            ComplianceStatus::Gap,
            format!(
                "{} OT device(s) have public IP addresses: {}",
                public_ot_devices.len(),
                ips.join(", ")
            ),
        );
    }

    if inputs.assets.is_empty() {
        return (
            ComplianceStatus::NotAssessed,
            "No asset data. Import a PCAP to evaluate internet exposure.".to_string(),
        );
    }

    (
        ComplianceStatus::Met,
        format!(
            "No internet-exposed OT devices detected across {} asset(s).",
            inputs.assets.len()
        ),
    )
}

// ─── Helpers ─────────────────────────────────────────────────

fn is_ot_protocol(proto: &str) -> bool {
    matches!(
        proto,
        "Modbus"
            | "Dnp3"
            | "EthernetIp"
            | "S7comm"
            | "Bacnet"
            | "OpcUa"
            | "Iec104"
            | "ProfinetDcp"
            | "HartIp"
            | "GeSrtp"
            | "WonderwareSuitelink"
            | "FfHse"
    )
}

// ─── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, FindingType, Severity};

    fn make_finding(
        title: &str,
        finding_type: FindingType,
        severity: Severity,
        technique_id: Option<&str>,
    ) -> Finding {
        Finding::new(
            finding_type,
            severity,
            title.to_string(),
            "Test description".to_string(),
            vec![],
            "Test evidence".to_string(),
            technique_id.map(|t| t.to_string()),
        )
    }

    fn make_asset(ip: &str, device_type: &str, level: Option<u8>) -> AssetSnapshot {
        AssetSnapshot {
            ip_address: ip.to_string(),
            device_type: device_type.to_string(),
            protocols: vec!["Modbus".to_string()],
            purdue_level: level,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
            hostname: None,
            product_family: None,
        }
    }

    #[test]
    fn test_iec62443_returns_correct_framework() {
        let result = generate_compliance_report(&[], &[], &[], "iec62443");
        assert!(!result.is_empty(), "IEC 62443 should have mappings");
        for m in &result {
            assert_eq!(m.framework, "iec62443");
        }
    }

    #[test]
    fn test_nist80082_returns_correct_framework() {
        let result = generate_compliance_report(&[], &[], &[], "nist80082");
        assert!(!result.is_empty(), "NIST 800-82 should have mappings");
        for m in &result {
            assert_eq!(m.framework, "nist80082");
        }
    }

    #[test]
    fn test_nerccip_returns_correct_framework() {
        let result = generate_compliance_report(&[], &[], &[], "nerccip");
        assert!(!result.is_empty(), "NERC CIP should have mappings");
        for m in &result {
            assert_eq!(m.framework, "nerccip");
        }
    }

    #[test]
    fn test_unknown_framework_returns_empty() {
        let result = generate_compliance_report(&[], &[], &[], "iso27001");
        assert!(result.is_empty(), "Unknown framework should return empty");
    }

    #[test]
    fn test_attack_finding_produces_gap() {
        let findings = vec![make_finding(
            "Unauthorized Command Message",
            FindingType::AttackTechnique,
            Severity::Critical,
            Some("T0855"),
        )];
        let assets = vec![make_asset("10.0.1.1", "plc", Some(1))];

        let result = generate_compliance_report(&findings, &assets, &[], "iec62443");
        let attack_row = result
            .iter()
            .find(|m| m.requirement_id == "SR 3.3")
            .unwrap();
        assert_eq!(attack_row.status, ComplianceStatus::Gap);
    }

    #[test]
    fn test_purdue_violations_gap() {
        let findings = vec![make_finding(
            "Cross-Zone Communication",
            FindingType::PurdueViolation,
            Severity::Medium,
            Some("T0886"),
        )];
        let assets = vec![make_asset("10.0.1.1", "plc", Some(1))];

        let result = generate_compliance_report(&findings, &assets, &[], "iec62443");
        let sr51 = result
            .iter()
            .find(|m| m.requirement_id == "SR 5.1")
            .unwrap();
        // Purdue violations may trigger partial on SR 5.1
        assert!(
            sr51.status == ComplianceStatus::Gap || sr51.status == ComplianceStatus::Partial,
            "SR 5.1 should be Gap or Partial when violations exist"
        );
    }

    #[test]
    fn test_device_inventory_met_with_identified_assets() {
        let assets: Vec<AssetSnapshot> = (1..=10)
            .map(|i| make_asset(&format!("10.0.1.{i}"), "plc", Some(1)))
            .collect();

        let result = generate_compliance_report(&[], &assets, &[], "iec62443");
        let inv = result.iter().find(|m| m.requirement_id == "FR 1").unwrap();
        assert_eq!(inv.status, ComplianceStatus::Met);
    }

    #[test]
    fn test_supported_frameworks() {
        let fw = supported_frameworks();
        assert!(fw.contains(&"iec62443"));
        assert!(fw.contains(&"nist80082"));
        assert!(fw.contains(&"nerccip"));
    }
}
