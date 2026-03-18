//! LLDP (Link Layer Discovery Protocol) parser.
//!
//! Parses LLDP PDUs (IEEE 802.1AB) to extract device identity, capabilities,
//! management addresses, VLAN memberships, and vendor-specific info such as
//! model numbers and firmware versions.
//!
//! LLDP frames use Ethertype 0x88CC. The PDU immediately follows the 14-byte
//! Ethernet header and consists of a series of TLVs.
//!
//! ## TLV Structure
//!
//! Each TLV starts with a 16-bit big-endian header:
//! - Bits [15:9] (7 bits): TLV Type
//! - Bits [8:0]  (9 bits): TLV Length (number of value bytes following)
//!
//! ## TLV Types
//!
//! | Type | Name               |
//! |------|--------------------|
//! | 0    | End of LLDPDU      |
//! | 1    | Chassis ID         |
//! | 2    | Port ID            |
//! | 3    | Time-to-Live       |
//! | 4    | Port Description   |
//! | 5    | System Name        |
//! | 6    | System Description |
//! | 7    | System Capabilities|
//! | 8    | Management Address |
//! | 127  | Org-Specific       |

use serde::{Deserialize, Serialize};

// ─── Capability Flags ─────────────────────────────────────────────────────────

/// LLDP System Capabilities bitmask (IEEE 802.1AB-2009 Table 8-4).
/// Each bit indicates a capability the device supports or has enabled.
pub mod caps {
    pub const OTHER: u16 = 1 << 0;
    pub const REPEATER: u16 = 1 << 1;
    pub const BRIDGE: u16 = 1 << 2;
    pub const WLAN_AP: u16 = 1 << 3;
    pub const ROUTER: u16 = 1 << 4;
    pub const TELEPHONE: u16 = 1 << 5;
    pub const DOCSIS: u16 = 1 << 6;
    pub const STATION: u16 = 1 << 7;
}

// ─── Structs ──────────────────────────────────────────────────────────────────

/// A management address from LLDP Type 8.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LldpMgmtAddress {
    /// Address family: "ipv4", "ipv6", or "other"
    pub addr_type: String,
    /// Human-readable address string
    pub address: String,
}

/// Parsed LLDP PDU information.
///
/// All optional fields reflect TLVs that may or may not be present in a given
/// LLDP frame. Chassis ID and Port ID are always present per the standard;
/// the rest depend on the sender's configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LldpInfo {
    /// Chassis identifier (MAC address, IP address, or local string)
    pub chassis_id: Option<String>,
    /// Port identifier
    pub port_id: Option<String>,
    /// Time-to-live in seconds
    pub ttl: Option<u16>,
    /// Port description string
    pub port_description: Option<String>,
    /// System name (hostname)
    pub system_name: Option<String>,
    /// System description (often includes OS version, model, firmware)
    pub system_description: Option<String>,
    /// System capabilities bitmap (bits per `caps` module)
    pub capabilities: Option<u16>,
    /// Enabled capabilities bitmap
    pub enabled_capabilities: Option<u16>,
    /// Management addresses advertised by the device
    pub management_addresses: Vec<LldpMgmtAddress>,
    /// VLAN IDs from IEEE 802.1 org-specific TLVs
    pub vlan_ids: Vec<u16>,

    // ── Derived / enriched fields ──────────────────────────────────────────
    /// Vendor name inferred from system description or org-specific OUI
    pub vendor: Option<String>,
    /// Device model inferred from system description
    pub model: Option<String>,
    /// Firmware/software version inferred from system description
    pub firmware: Option<String>,

    /// Human-readable capability summary, e.g. "Bridge, Router"
    pub capability_summary: Option<String>,
}

// ─── Parse Function ───────────────────────────────────────────────────────────

/// Parse an LLDP PDU from raw bytes.
///
/// `payload` should be the bytes immediately following the 14-byte Ethernet
/// header (or 18-byte VLAN-tagged header) — i.e. the LLDP TLV stream.
///
/// Returns `None` if the payload is empty or cannot be parsed at all.
/// Individual unrecognised TLVs are silently skipped.
pub fn parse(payload: &[u8]) -> Option<LldpInfo> {
    if payload.is_empty() {
        return None;
    }

    let mut info = LldpInfo::default();
    let mut offset = 0;

    while offset + 2 <= payload.len() {
        // 2-byte TLV header: [type:7][length:9] in big-endian
        let header = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let tlv_type = (header >> 9) as u8;
        let tlv_length = (header & 0x01FF) as usize;
        offset += 2;

        // End-of-LLDPDU TLV
        if tlv_type == 0 {
            break;
        }

        // Guard against out-of-bounds reads
        if offset + tlv_length > payload.len() {
            break;
        }

        let value = &payload[offset..offset + tlv_length];
        offset += tlv_length;

        match tlv_type {
            // Chassis ID: subtype (1 byte) + data
            1 if !value.is_empty() => {
                info.chassis_id = Some(decode_id_tlv(value));
            }
            // Port ID: subtype (1 byte) + data
            2 if !value.is_empty() => {
                info.port_id = Some(decode_id_tlv(value));
            }
            // Time-to-Live: u16 BE
            3 if value.len() >= 2 => {
                info.ttl = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            // Port Description
            4 => {
                info.port_description = Some(String::from_utf8_lossy(value).into_owned());
            }
            // System Name
            5 => {
                info.system_name = Some(String::from_utf8_lossy(value).trim().to_string());
            }
            // System Description
            6 => {
                let desc = String::from_utf8_lossy(value).trim().to_string();
                enrich_from_description(&mut info, &desc);
                info.system_description = Some(desc);
            }
            // System Capabilities: capabilities(2 BE) + enabled(2 BE)
            7 if value.len() >= 4 => {
                let cap = u16::from_be_bytes([value[0], value[1]]);
                let en = u16::from_be_bytes([value[2], value[3]]);
                info.capabilities = Some(cap);
                info.enabled_capabilities = Some(en);
                info.capability_summary = Some(capability_summary(cap, en));
            }
            // Management Address
            8 if value.len() >= 2 => {
                // value[0] = addr string length (includes the subtype byte)
                let addr_str_len = value[0] as usize;
                if addr_str_len >= 1 && value.len() > addr_str_len {
                    let subtype = value[1];
                    let addr_bytes = &value[2..1 + addr_str_len];
                    let (addr_type, address) = decode_management_address(subtype, addr_bytes);
                    info.management_addresses
                        .push(LldpMgmtAddress { addr_type, address });
                }
            }
            // Org-Specific (type 127): OUI (3) + subtype (1) + data
            127 if value.len() >= 4 => {
                handle_org_specific(&mut info, &value[0..3], value[3], &value[4..]);
            }
            // Unknown TLV — skip
            _ => {}
        }
    }

    // Return None only if we got nothing useful at all
    if info.chassis_id.is_none() && info.system_name.is_none() && info.port_id.is_none() {
        return None;
    }

    Some(info)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Decode a Chassis ID or Port ID TLV value.
///
/// The first byte is the subtype; the remaining bytes are the ID data.
fn decode_id_tlv(value: &[u8]) -> String {
    if value.is_empty() {
        return String::new();
    }
    let subtype = value[0];
    let data = &value[1..];

    match subtype {
        // MAC address
        4 if data.len() >= 6 => format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            data[0], data[1], data[2], data[3], data[4], data[5]
        ),
        // IPv4 network address
        5 if data.len() >= 5 && data[0] == 1 => {
            format!("{}.{}.{}.{}", data[1], data[2], data[3], data[4])
        }
        // Interface name / locally assigned / interface alias — treat as UTF-8 string
        _ => String::from_utf8_lossy(data).trim_matches('\0').to_string(),
    }
}

/// Decode a management address from subtype + raw bytes.
fn decode_management_address(subtype: u8, data: &[u8]) -> (String, String) {
    match subtype {
        // IPv4
        1 if data.len() >= 4 => (
            "ipv4".to_string(),
            format!("{}.{}.{}.{}", data[0], data[1], data[2], data[3]),
        ),
        // IPv6
        2 if data.len() >= 16 => {
            let segs: Vec<String> = (0..8)
                .map(|i| format!("{:x}", u16::from_be_bytes([data[i * 2], data[i * 2 + 1]])))
                .collect();
            ("ipv6".to_string(), segs.join(":"))
        }
        _ => ("other".to_string(), format!("{:02x?}", data)),
    }
}

/// Handle an Org-Specific (type 127) TLV.
fn handle_org_specific(info: &mut LldpInfo, oui: &[u8], subtype: u8, data: &[u8]) {
    match (oui, subtype) {
        // IEEE 802.1 OUI: 00-80-C2
        // Subtype 1: Port VLAN ID (2 bytes)
        ([0x00, 0x80, 0xC2], 1) if data.len() >= 2 => {
            let vlan_id = u16::from_be_bytes([data[0], data[1]]);
            if vlan_id != 0 && !info.vlan_ids.contains(&vlan_id) {
                info.vlan_ids.push(vlan_id);
            }
        }
        // Subtype 3: VLAN Name — first 2 bytes = VLAN ID
        ([0x00, 0x80, 0xC2], 3) if data.len() >= 2 => {
            let vlan_id = u16::from_be_bytes([data[0], data[1]]);
            if vlan_id != 0 && !info.vlan_ids.contains(&vlan_id) {
                info.vlan_ids.push(vlan_id);
            }
        }
        // Hirschmann OUI variants: 00-06-2E and 00-80-63
        // These use subtype 1 for device name and firmware
        ([0x00, 0x06, 0x2E] | [0x00, 0x80, 0x63], 1) if !data.is_empty() => {
            if info.vendor.is_none() {
                info.vendor = Some("Hirschmann".to_string());
            }
            // data is ASCII: e.g. "MACH 4002-24G\0FW 09.3.00"
            let text = String::from_utf8_lossy(data);
            enrich_from_description(info, text.trim());
        }
        // Moxa OUI: 00-90-E8 (subtype varies, try all)
        ([0x00, 0x90, 0xE8], _) if !data.is_empty() => {
            if info.vendor.is_none() {
                info.vendor = Some("Moxa".to_string());
            }
            let text = String::from_utf8_lossy(data);
            enrich_from_description(info, text.trim());
        }
        // PROFINET OUI: 00-0E-CF (Siemens and third-party PROFINET devices)
        ([0x00, 0x0E, 0xCF], _) => {
            if info.vendor.is_none() {
                info.vendor = Some("PROFINET Device".to_string());
            }
        }
        _ => {}
    }
}

/// Infer vendor, model, and firmware from the System Description field.
///
/// The description format varies widely across vendors; we use heuristics based
/// on common patterns seen in real ICS captures.
fn enrich_from_description(info: &mut LldpInfo, desc: &str) {
    let desc_lower = desc.to_lowercase();

    // Vendor detection
    if info.vendor.is_none() {
        if desc_lower.contains("hirschmann") {
            info.vendor = Some("Hirschmann".to_string());
        } else if desc_lower.contains("siemens") || desc_lower.contains("scalance") {
            info.vendor = Some("Siemens".to_string());
        } else if desc_lower.contains("moxa") {
            info.vendor = Some("Moxa".to_string());
        } else if desc_lower.contains("cisco") {
            info.vendor = Some("Cisco".to_string());
        } else if desc_lower.contains("aruba") {
            info.vendor = Some("Aruba".to_string());
        } else if desc_lower.contains("juniper") || desc_lower.contains("junos") {
            info.vendor = Some("Juniper".to_string());
        } else if desc_lower.contains("phoenix contact") || desc_lower.contains("fl switch") {
            info.vendor = Some("Phoenix Contact".to_string());
        } else if desc_lower.contains("belden") || desc_lower.contains("ruggedcom") {
            info.vendor = Some("Belden/RuggedCom".to_string());
        } else if desc_lower.contains("westermo") {
            info.vendor = Some("Westermo".to_string());
        } else if desc_lower.contains("eaton") {
            info.vendor = Some("Eaton".to_string());
        }
    }

    // Model detection — look for known product family names
    if info.model.is_none() {
        for keyword in &[
            "MACH",
            "OCTOPUS",
            "SPIDER",
            "MICE",
            "EAGLE", // Hirschmann
            "SCALANCE",
            "S7-",
            "S7 ", // Siemens
            "EDS-",
            "ICS-",
            "PT-",
            "AWK-",
            "TAP-", // Moxa
            "IE-",
            "IE ", // Cisco Industrial
            "FL SWITCH",
            "FL COMSERVER", // Phoenix Contact
            "PowerConnect",
            "OpEdge",
            "WS-C", // Dell/Cisco
        ] {
            if let Some(idx) = desc.to_uppercase().find(&keyword.to_uppercase()) {
                // Grab up to ~30 chars after the keyword as the model string
                let model_start = idx;
                let model_end = (model_start + 32).min(desc.len());
                let model_raw = desc[model_start..model_end].trim();
                // Trim at first newline or null
                let model_clean = model_raw
                    .split(['\n', '\r', '\0'])
                    .next()
                    .unwrap_or(model_raw)
                    .trim();
                if !model_clean.is_empty() {
                    info.model = Some(model_clean.to_string());
                }
                break;
            }
        }
    }

    // Firmware version detection
    // Common patterns: "SW: 09.3.00", "FW: 4.2", "Version 12.1(4)",
    //                  "IOS Software", "Rel 05.3.00", "Version 6.0"
    if info.firmware.is_none() {
        for prefix in &[
            "SW:", "FW:", "Fw:", "fw:", "sw:", "Version", "version", "Rel ", "Release",
        ] {
            if let Some(idx) = desc.find(prefix) {
                let after = desc[idx + prefix.len()..].trim_start();
                // Take up to end of version token (space, comma, newline)
                let version = after
                    .split(['\n', '\r', ','])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_start_matches('v')
                    .trim_start_matches('V');
                if !version.is_empty() && version.len() <= 40 {
                    info.firmware = Some(version.to_string());
                    break;
                }
            }
        }
    }
}

/// Build a human-readable capability summary string.
///
/// Reports enabled capabilities (e.g. "Bridge, Router"); falls back to
/// listing all supported capabilities if enabled is zero.
fn capability_summary(capabilities: u16, enabled: u16) -> String {
    let mask = if enabled != 0 { enabled } else { capabilities };
    let mut parts = Vec::new();
    if mask & caps::REPEATER != 0 {
        parts.push("Repeater");
    }
    if mask & caps::BRIDGE != 0 {
        parts.push("Bridge");
    }
    if mask & caps::WLAN_AP != 0 {
        parts.push("WLAN AP");
    }
    if mask & caps::ROUTER != 0 {
        parts.push("Router");
    }
    if mask & caps::TELEPHONE != 0 {
        parts.push("Telephone");
    }
    if mask & caps::DOCSIS != 0 {
        parts.push("DOCSIS");
    }
    if mask & caps::STATION != 0 {
        parts.push("Station");
    }
    if mask & caps::OTHER != 0 {
        parts.push("Other");
    }
    if parts.is_empty() {
        "Unknown".to_string()
    } else {
        parts.join(", ")
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid LLDP PDU with Chassis ID, Port ID, TTL.
    fn build_minimal(chassis: &[u8], port: &[u8]) -> Vec<u8> {
        let mut pdu = Vec::new();
        // Chassis ID TLV (type=1): subtype 4 (MAC), then MAC bytes
        push_tlv(&mut pdu, 1, chassis);
        // Port ID TLV (type=2): subtype 5 (locally assigned)
        push_tlv(&mut pdu, 2, port);
        // TTL TLV (type=3): 120 seconds
        push_tlv(&mut pdu, 3, &[0x00, 0x78]);
        // End of LLDPDU (type=0, length=0)
        pdu.extend_from_slice(&[0x00, 0x00]);
        pdu
    }

    /// Append a TLV to a buffer.
    fn push_tlv(buf: &mut Vec<u8>, tlv_type: u8, value: &[u8]) {
        let header = ((tlv_type as u16) << 9) | (value.len() as u16 & 0x01FF);
        buf.extend_from_slice(&header.to_be_bytes());
        buf.extend_from_slice(value);
    }

    #[test]
    fn test_minimal_lldp() {
        // Chassis: subtype 4 (MAC) + 6 bytes
        let chassis = [4u8, 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33];
        // Port: subtype 7 (locally assigned) + string
        let port = [7u8, b'E', b't', b'h', b'0'];
        let pdu = build_minimal(&chassis, &port);

        let info = parse(&pdu).expect("should parse minimal LLDP");
        assert_eq!(info.chassis_id.as_deref(), Some("aa:bb:cc:11:22:33"));
        assert_eq!(info.port_id.as_deref(), Some("Eth0"));
        assert_eq!(info.ttl, Some(120));
    }

    #[test]
    fn test_system_name_and_description() {
        let mut pdu = Vec::new();
        // Chassis
        push_tlv(&mut pdu, 1, &[4, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
        // Port
        push_tlv(&mut pdu, 2, &[7, b'G', b'i', b'1']);
        // TTL
        push_tlv(&mut pdu, 3, &[0x00, 0x3C]);
        // System Name: "switch-01"
        push_tlv(&mut pdu, 5, b"switch-01");
        // System Description: "Hirschmann MACH 4002 SW: 09.3.00"
        push_tlv(&mut pdu, 6, b"Hirschmann MACH 4002 SW: 09.3.00");
        pdu.extend_from_slice(&[0x00, 0x00]); // End

        let info = parse(&pdu).expect("should parse system name PDU");
        assert_eq!(info.system_name.as_deref(), Some("switch-01"));
        assert_eq!(info.vendor.as_deref(), Some("Hirschmann"));
        assert!(info
            .model
            .as_deref()
            .map(|m| m.contains("MACH 4002"))
            .unwrap_or(false));
        assert_eq!(info.firmware.as_deref(), Some("09.3.00"));
    }

    #[test]
    fn test_capabilities() {
        let mut pdu = Vec::new();
        push_tlv(&mut pdu, 1, &[4, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        push_tlv(&mut pdu, 2, &[7, b'P', b'1']);
        push_tlv(&mut pdu, 3, &[0x00, 0x78]);
        // Capabilities: supported = Bridge(0x04) | Router(0x10), enabled = Bridge(0x04)
        push_tlv(&mut pdu, 7, &[0x00, 0x14, 0x00, 0x04]);
        pdu.extend_from_slice(&[0x00, 0x00]);

        let info = parse(&pdu).expect("should parse capabilities");
        assert_eq!(info.capabilities, Some(0x0014));
        assert_eq!(info.enabled_capabilities, Some(0x0004));
        // capability_summary should mention Bridge (enabled)
        assert!(info
            .capability_summary
            .as_deref()
            .unwrap_or("")
            .contains("Bridge"));
    }

    #[test]
    fn test_management_address_ipv4() {
        let mut pdu = Vec::new();
        push_tlv(&mut pdu, 1, &[4, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        push_tlv(&mut pdu, 2, &[7, b'P', b'2']);
        push_tlv(&mut pdu, 3, &[0x00, 0x78]);
        // Management Address: length=5 (subtype + 4 IPv4 bytes), subtype=1 (IPv4), 10.0.0.1
        push_tlv(&mut pdu, 8, &[5, 1, 10, 0, 0, 1, 1, 0, 0, 0, 0, 0]);
        pdu.extend_from_slice(&[0x00, 0x00]);

        let info = parse(&pdu).expect("should parse management address");
        assert!(!info.management_addresses.is_empty());
        assert_eq!(info.management_addresses[0].addr_type, "ipv4");
        assert_eq!(info.management_addresses[0].address, "10.0.0.1");
    }

    #[test]
    fn test_vlan_id_from_org_specific() {
        let mut pdu = Vec::new();
        push_tlv(&mut pdu, 1, &[4, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        push_tlv(&mut pdu, 2, &[7, b'P', b'3']);
        push_tlv(&mut pdu, 3, &[0x00, 0x78]);
        // Org-Specific: OUI=00-80-C2, subtype=1 (Port VLAN ID), VLAN=100
        let org: &[u8] = &[0x00, 0x80, 0xC2, 0x01, 0x00, 0x64];
        push_tlv(&mut pdu, 127, org);
        pdu.extend_from_slice(&[0x00, 0x00]);

        let info = parse(&pdu).expect("should parse org-specific VLAN");
        assert!(info.vlan_ids.contains(&100));
    }

    #[test]
    fn test_siemens_scalance_description() {
        let mut pdu = Vec::new();
        push_tlv(&mut pdu, 1, &[4, 0x00, 0x1B, 0x1B, 0xAA, 0xBB, 0xCC]);
        push_tlv(&mut pdu, 2, &[7, b'P', b'1']);
        push_tlv(&mut pdu, 3, &[0x00, 0x78]);
        push_tlv(&mut pdu, 5, b"scalance-xm408");
        push_tlv(&mut pdu, 6, b"Siemens SCALANCE XM408-8C Version 6.4.1");
        pdu.extend_from_slice(&[0x00, 0x00]);

        let info = parse(&pdu).expect("should parse Siemens description");
        assert_eq!(info.vendor.as_deref(), Some("Siemens"));
        assert!(info
            .model
            .as_deref()
            .map(|m| m.contains("SCALANCE"))
            .unwrap_or(false));
        assert_eq!(info.firmware.as_deref(), Some("6.4.1"));
    }

    #[test]
    fn test_moxa_switch_description() {
        let mut pdu = Vec::new();
        push_tlv(&mut pdu, 1, &[4, 0x00, 0x90, 0xE8, 0x01, 0x02, 0x03]);
        push_tlv(&mut pdu, 2, &[7, b'P', b'1']);
        push_tlv(&mut pdu, 3, &[0x00, 0x78]);
        push_tlv(&mut pdu, 6, b"Moxa EDS-516A-MM-SC FW: 4.2 Build 16042218");
        pdu.extend_from_slice(&[0x00, 0x00]);

        let info = parse(&pdu).expect("should parse Moxa description");
        assert_eq!(info.vendor.as_deref(), Some("Moxa"));
        assert!(info
            .model
            .as_deref()
            .map(|m| m.contains("EDS-"))
            .unwrap_or(false));
        assert_eq!(info.firmware.as_deref(), Some("4.2 Build 16042218"));
    }

    #[test]
    fn test_empty_payload_returns_none() {
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn test_truncated_tlv_does_not_panic() {
        // Starts a TLV header claiming 50 bytes but only 2 bytes follow — should not panic
        let data: &[u8] = &[0x0A, 0x32, 0xFF, 0xFF];
        // May return None or a partial result — must not panic
        let _ = parse(data);
    }
}
