//! Device naming suggestions for discovered assets.
//!
//! Generates structured hostname suggestions for devices that lack
//! user-assigned hostnames. Follows ICS naming conventions:
//! role prefix + last two IP octets, e.g., "PLC-01-05" for 10.0.1.5.

use serde::{Deserialize, Serialize};

/// A naming suggestion for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamingSuggestion {
    pub ip_address: String,
    pub suggested_name: String,
    pub reason: String,
}

/// Generate a hostname suggestion for a device.
///
/// Format: `{PREFIX}-{last_two_octets_dashed}`
/// Examples:
///   - 10.0.0.5 + "plc" → "PLC-000-005"
///   - 192.168.1.100 + "hmi" → "HMI-001-100"
pub fn suggest_name(ip: &str, role: &str, protocol: &str) -> String {
    let prefix = role_to_prefix(role, protocol);
    let suffix = ip_suffix(ip);
    format!("{}-{}", prefix, suffix)
}

fn role_to_prefix(role: &str, protocol: &str) -> &'static str {
    let r = role.to_lowercase();
    // Safety must be checked before "controller" since "safety controller" contains both
    if r.contains("safety") || r.contains("sis") {
        return "SIS";
    }
    if r.contains("plc") || r.contains("controller") {
        return "PLC";
    }
    if r.contains("rtu") || r.contains("outstation") {
        return "RTU";
    }
    if r.contains("hmi") {
        return "HMI";
    }
    if r.contains("historian") {
        return "HIST";
    }
    if r.contains("engineering") || r.contains("ews") {
        return "EWS";
    }
    if r.contains("scada") {
        return "SCADA";
    }
    if r.contains("switch") || r.contains("managed") {
        return "SW";
    }
    if r.contains("gateway") || r.contains("proxy") {
        return "GW";
    }
    if r.contains("io") || r.contains("remote i/o") {
        return "IO";
    }
    if r.contains("relay") || r.contains("ied") {
        return "IED";
    }
    if r.contains("dcs") {
        return "DCS";
    }
    // Protocol fallback
    let p = protocol.to_lowercase();
    if p.contains("modbus") {
        return "MOD";
    }
    if p.contains("dnp3") {
        return "DNP";
    }
    if p.contains("s7comm") || p.contains("s7") {
        return "S7";
    }
    if p.contains("bacnet") {
        return "BAC";
    }
    if p.contains("enip") || p.contains("ethernet") {
        return "EIP";
    }
    if p.contains("iec104") {
        return "IEC";
    }
    if p.contains("profinet") {
        return "PN";
    }
    "DEV"
}

fn ip_suffix(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        // Use last two octets, zero-padded to 3 digits each
        format!(
            "{:03}-{:03}",
            parts[2].parse::<u32>().unwrap_or(0),
            parts[3].parse::<u32>().unwrap_or(0)
        )
    } else {
        ip.replace('.', "-")
    }
}

/// Generate naming suggestions for all unnamed devices.
pub fn suggest_all(assets: &[crate::AssetSnapshot]) -> Vec<NamingSuggestion> {
    assets
        .iter()
        .map(|a| {
            let primary_protocol = a.protocols.first().map(|p| p.as_str()).unwrap_or("unknown");
            let name = suggest_name(&a.ip_address, &a.device_type, primary_protocol);
            let reason = format!(
                "Based on role '{}' and protocol '{}'",
                a.device_type, primary_protocol
            );
            NamingSuggestion {
                ip_address: a.ip_address.clone(),
                suggested_name: name,
                reason,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plc_naming() {
        assert_eq!(suggest_name("10.0.0.5", "plc", "modbus"), "PLC-000-005");
    }

    #[test]
    fn test_hmi_naming() {
        assert_eq!(suggest_name("192.168.1.100", "hmi", ""), "HMI-001-100");
    }

    #[test]
    fn test_protocol_fallback_modbus() {
        assert_eq!(suggest_name("10.0.1.20", "unknown", "modbus"), "MOD-001-020");
    }

    #[test]
    fn test_protocol_fallback_s7() {
        assert_eq!(suggest_name("10.0.2.5", "unknown", "s7comm"), "S7-002-005");
    }

    #[test]
    fn test_default_dev() {
        assert_eq!(suggest_name("10.0.0.1", "it_device", "http"), "DEV-000-001");
    }

    #[test]
    fn test_safety_prefix() {
        assert_eq!(suggest_name("10.0.0.10", "safety controller", ""), "SIS-000-010");
    }

    #[test]
    fn test_suggest_all_empty() {
        let result = suggest_all(&[]);
        assert!(result.is_empty());
    }
}
