//! Asset criticality scoring for ICS/SCADA environments.
//!
//! Assigns a criticality level to each device based on its role,
//! protocols, and Purdue level assignment. Used for remediation
//! prioritization in the assessment report.

use serde::{Deserialize, Serialize};

/// Criticality level for an ICS asset.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum CriticalityLevel {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl CriticalityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            CriticalityLevel::Critical => "critical",
            CriticalityLevel::High => "high",
            CriticalityLevel::Medium => "medium",
            CriticalityLevel::Low => "low",
            CriticalityLevel::Unknown => "unknown",
        }
    }
}

/// Criticality assessment for a single device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriticalityAssessment {
    pub ip_address: String,
    pub level: CriticalityLevel,
    pub reason: String,
}

/// Assess the criticality of a device.
///
/// Priority order:
/// 1. Safety-related keywords → Critical
/// 2. PLC/RTU/IED/relay/controller → Critical
/// 3. HMI/EWS/SCADA → High
/// 4. Historian/Gateway/OPC → Medium
/// 5. Purdue level fallback (L1→Critical, L2→High, L3→Medium, L4+→Low)
/// 6. No info → Low
pub fn assess_criticality(
    role: &str,
    protocols: &[String],
    purdue_level: Option<u8>,
) -> CriticalityLevel {
    let role_lower = role.to_lowercase();

    // Safety override — highest priority
    if role_lower.contains("safety") || role_lower.contains("sis") || role_lower.contains("sil") {
        return CriticalityLevel::Critical;
    }

    // Control devices (L1)
    if role_lower.contains("plc")
        || role_lower.contains("rtu")
        || role_lower.contains("ied")
        || role_lower.contains("relay")
        || role_lower.contains("controller")
        || role_lower.contains("outstation")
    {
        return CriticalityLevel::Critical;
    }

    // Supervisory / operator layer (L2)
    if role_lower.contains("hmi")
        || role_lower.contains("scada")
        || role_lower.contains("engineering")
        || role_lower.contains("ews")
        || role_lower.contains("dcs")
    {
        return CriticalityLevel::High;
    }

    // Data / integration layer (L3)
    if role_lower.contains("historian")
        || role_lower.contains("gateway")
        || role_lower.contains("opc")
        || role_lower.contains("dmz")
    {
        return CriticalityLevel::Medium;
    }

    // Protocol-based fallback: OT protocols suggest at least High
    let has_ot_protocol = protocols.iter().any(|p| {
        let pl = p.to_lowercase();
        pl.contains("modbus")
            || pl.contains("dnp3")
            || pl.contains("s7")
            || pl.contains("enip")
            || pl.contains("bacnet")
            || pl.contains("iec104")
            || pl.contains("profinet")
    });

    if has_ot_protocol {
        return CriticalityLevel::High;
    }

    // Purdue level fallback
    match purdue_level {
        Some(0) | Some(1) => CriticalityLevel::Critical,
        Some(2) => CriticalityLevel::High,
        Some(3) => CriticalityLevel::Medium,
        Some(4) | Some(5) => CriticalityLevel::Low,
        _ => CriticalityLevel::Low,
    }
}

/// Assess all devices in the input and return a criticality list.
pub fn assess_all(assets: &[crate::AssetSnapshot]) -> Vec<CriticalityAssessment> {
    assets
        .iter()
        .map(|a| {
            let level = assess_criticality(&a.device_type, &a.protocols, a.purdue_level);
            let reason = build_reason(&a.device_type, &a.protocols, a.purdue_level, level);
            CriticalityAssessment {
                ip_address: a.ip_address.clone(),
                level,
                reason,
            }
        })
        .collect()
}

fn build_reason(
    role: &str,
    _protocols: &[String],
    purdue_level: Option<u8>,
    level: CriticalityLevel,
) -> String {
    match level {
        CriticalityLevel::Critical => {
            if role.to_lowercase().contains("safety") {
                format!("Safety system ({}) — highest criticality", role)
            } else {
                format!("Control device ({}) — direct process impact", role)
            }
        }
        CriticalityLevel::High => {
            format!("Supervisory device ({}) — operator visibility impact", role)
        }
        CriticalityLevel::Medium => format!("Data/integration layer ({}) — indirect impact", role),
        CriticalityLevel::Low => {
            if let Some(lvl) = purdue_level {
                format!("Purdue Level {} — low criticality", lvl)
            } else {
                "No OT protocols or role classification — assumed low criticality".to_string()
            }
        }
        CriticalityLevel::Unknown => "Insufficient data to classify criticality".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plc_is_critical() {
        assert_eq!(
            assess_criticality("plc", &[], None),
            CriticalityLevel::Critical
        );
    }

    #[test]
    fn test_hmi_is_high() {
        assert_eq!(assess_criticality("hmi", &[], None), CriticalityLevel::High);
    }

    #[test]
    fn test_historian_is_medium() {
        assert_eq!(
            assess_criticality("historian", &[], None),
            CriticalityLevel::Medium
        );
    }

    #[test]
    fn test_purdue_l1_fallback() {
        assert_eq!(
            assess_criticality("unknown", &[], Some(1)),
            CriticalityLevel::Critical
        );
    }

    #[test]
    fn test_purdue_l4_is_low() {
        assert_eq!(
            assess_criticality("it_device", &[], Some(4)),
            CriticalityLevel::Low
        );
    }

    #[test]
    fn test_safety_override() {
        assert_eq!(
            assess_criticality("safety controller", &[], Some(4)),
            CriticalityLevel::Critical
        );
    }

    #[test]
    fn test_ot_protocol_raises_to_high() {
        assert_eq!(
            assess_criticality("unknown", &["modbus".to_string()], None),
            CriticalityLevel::High
        );
    }

    #[test]
    fn test_assess_all_empty() {
        let result = assess_all(&[]);
        assert!(result.is_empty());
    }
}
