//! SNMP community string extraction.
//!
//! Parses SNMPv1/v2c packet headers to extract community strings.
//! Community strings are used for authentication in SNMP v1/v2c and
//! default values ("public", "private") represent a critical security risk.
//!
//! ## Packet Format (BER-TLV)
//! ```text
//! [0]   0x30     SEQUENCE tag
//! [1]   length   total length (may be extended)
//! [2]   0x02     INTEGER tag (version)
//! [3]   0x01     integer length
//! [4]   version  0x00=SNMPv1, 0x01=SNMPv2c
//! [5]   0x04     OCTET STRING tag (community)
//! [6]   length   community string length
//! [7..] bytes    community string (ASCII)
//! ```

/// Result of parsing an SNMP packet header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpInfo {
    /// SNMP version: 1 or 2
    pub version: u8,
    /// Community string extracted from the packet
    pub community_string: String,
    /// Whether this is a known-default community string
    pub is_default: bool,
    /// Severity of the default string (if applicable)
    pub default_severity: Option<&'static str>,
}

/// Known default community strings with severity.
/// "public" = read-only, "private" = read-write — both are critical defaults.
const DEFAULT_COMMUNITIES: &[(&str, &str)] = &[
    ("public", "high"),
    ("private", "critical"),
    ("community", "high"),
    ("snmp", "medium"),
    ("admin", "critical"),
    ("manager", "high"),
    ("monitor", "medium"),
    ("cisco", "critical"),
    ("default", "high"),
    ("secret", "critical"),
    ("read", "medium"),
    ("write", "critical"),
];

/// Parse an SNMP v1/v2c packet and extract the community string.
///
/// Returns `None` if the data is not a valid SNMP packet or the
/// community string cannot be extracted.
pub fn parse_snmp_community(data: &[u8]) -> Option<SnmpInfo> {
    // Minimum: 0x30 + len(1) + 0x02 + 0x01 + version + 0x04 + len(1) + community(≥0)
    if data.len() < 7 {
        return None;
    }

    // Must start with SEQUENCE (0x30)
    if data[0] != 0x30 {
        return None;
    }

    // Skip the outer SEQUENCE length (may be 1 or 2 bytes)
    let (seq_content_start, _) = decode_ber_length(data, 1)?;

    // Next: INTEGER for version
    if data.get(seq_content_start)? != &0x02 {
        return None;
    }

    let (ver_start, ver_len) = decode_ber_length(data, seq_content_start + 1)?;
    if ver_len == 0 || ver_start + ver_len > data.len() {
        return None;
    }
    let version_byte = data[ver_start];
    let version = match version_byte {
        0x00 => 1u8,
        0x01 => 2u8,
        _ => return None, // SNMPv3 uses different structure
    };

    let community_tag_pos = ver_start + ver_len;

    // Next: OCTET STRING for community
    if data.get(community_tag_pos)? != &0x04 {
        return None;
    }

    let (comm_start, comm_len) = decode_ber_length(data, community_tag_pos + 1)?;
    if comm_start + comm_len > data.len() {
        return None;
    }

    let community_bytes = &data[comm_start..comm_start + comm_len];
    // Community strings are ASCII in practice
    let community_string = String::from_utf8_lossy(community_bytes).into_owned();

    let community_lower = community_string.to_lowercase();
    let default_entry = DEFAULT_COMMUNITIES
        .iter()
        .find(|(known, _)| community_lower == *known);

    let is_default = default_entry.is_some();
    let default_severity = default_entry.map(|(_, sev)| *sev);

    Some(SnmpInfo {
        version,
        community_string,
        is_default,
        default_severity,
    })
}

// ─── SNMP Device Identity ─────────────────────────────────────────────────────

/// Device identity information extracted from SNMP GET-Response PDU.
///
/// Maps to the standard MIB-2 system group (1.3.6.1.2.1.1.*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnmpDeviceInfo {
    /// sysDescr (OID .1.1.0) — free-text device description
    pub sys_descr: Option<String>,
    /// sysName (OID .1.5.0) — administratively assigned hostname
    pub sys_name: Option<String>,
    /// sysLocation (OID .1.6.0) — physical location
    pub sys_location: Option<String>,
    /// sysObjectID (OID .1.2.0) — vendor's authoritative OID for this device
    pub sys_object_id: Option<String>,
    /// sysUpTime (OID .1.3.0) — time since last re-initialisation, in centiseconds
    pub sys_uptime_cs: Option<u32>,
    /// sysContact (OID .1.4.0) — contact person / email
    pub sys_contact: Option<String>,
    /// Vendor name inferred from sysObjectID enterprise arc
    pub vendor: Option<String>,
}

/// Parse an SNMP GET-Response PDU and extract MIB-2 system group values.
///
/// `data` should be the raw UDP payload (starts with `0x30` SEQUENCE).
/// Returns `None` if the packet is not an SNMP GET-Response or fails to decode.
pub fn parse_snmp_response(data: &[u8]) -> Option<SnmpDeviceInfo> {
    // Must start with SEQUENCE
    if data.first()? != &0x30 {
        return None;
    }
    let (seq_start, _) = decode_ber_length(data, 1)?;

    // version INTEGER
    if data.get(seq_start)? != &0x02 {
        return None;
    }
    let (ver_value_start, ver_len) = decode_ber_length(data, seq_start + 1)?;
    let version_byte = *data.get(ver_value_start)?;
    if !matches!(version_byte, 0x00 | 0x01) {
        return None; // SNMPv3 not handled here
    }
    let after_version = ver_value_start + ver_len;

    // community OCTET STRING
    if data.get(after_version)? != &0x04 {
        return None;
    }
    let (comm_value_start, comm_len) = decode_ber_length(data, after_version + 1)?;
    let after_community = comm_value_start + comm_len;

    // PDU — must be GetResponse (0xA2)
    if data.get(after_community)? != &0xA2 {
        return None;
    }
    let (pdu_start, _) = decode_ber_length(data, after_community + 1)?;

    // Skip request-id, error-status, error-index (3 INTEGERs)
    let mut pos = pdu_start;
    for _ in 0..3 {
        if data.get(pos)? != &0x02 {
            return None;
        }
        let (val_start, val_len) = decode_ber_length(data, pos + 1)?;
        pos = val_start + val_len;
    }

    // VarBindList SEQUENCE
    if data.get(pos)? != &0x30 {
        return None;
    }
    let (vbl_start, vbl_len) = decode_ber_length(data, pos + 1)?;
    let vbl_end = vbl_start + vbl_len;

    let mut result = SnmpDeviceInfo {
        sys_descr: None,
        sys_name: None,
        sys_location: None,
        sys_object_id: None,
        sys_uptime_cs: None,
        sys_contact: None,
        vendor: None,
    };

    // Walk VarBind entries
    let mut cur = vbl_start;
    while cur < vbl_end.min(data.len()) {
        // Each VarBind is a SEQUENCE
        if data.get(cur)? != &0x30 {
            break;
        }
        let (vb_start, vb_len) = decode_ber_length(data, cur + 1)?;
        let vb_end = (vb_start + vb_len).min(data.len());

        // OID
        if data.get(vb_start)? != &0x06 {
            cur = vb_end;
            continue;
        }
        let (oid_start, oid_len) = decode_ber_length(data, vb_start + 1)?;
        let oid_end = oid_start + oid_len;
        if oid_end > data.len() {
            break;
        }
        let oid_bytes = &data[oid_start..oid_end];
        let value_pos = oid_end;

        // Match against the MIB-2 system group OIDs
        // 1.3.6.1.2.1.1.X.0 encodes as [0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, X, 0x00]
        let sys_oid_prefix = [0x2Bu8, 0x06, 0x01, 0x02, 0x01, 0x01];
        if oid_len >= 8 && oid_bytes[..6] == sys_oid_prefix && oid_bytes[7] == 0x00 {
            let sub_id = oid_bytes[6];
            // Get the value tag and content
            let val_tag = *data.get(value_pos).unwrap_or(&0);
            let (val_start, val_len) = decode_ber_length(data, value_pos + 1).unwrap_or((0, 0));
            let val_end = val_start + val_len;
            if val_end <= data.len() {
                match sub_id {
                    1 => { // sysDescr — OCTET STRING
                        if val_tag == 0x04 {
                            result.sys_descr = Some(
                                String::from_utf8_lossy(&data[val_start..val_end]).trim().to_string()
                            );
                        }
                    }
                    2 => { // sysObjectID — OID
                        if val_tag == 0x06 {
                            let oid_str = decode_oid(&data[val_start..val_end]);
                            result.vendor = Some(enterprise_vendor(&oid_str).to_string());
                            result.sys_object_id = Some(oid_str);
                        }
                    }
                    3 => { // sysUpTime — TimeTicks (APPLICATION 3 = 0x43)
                        if val_tag == 0x43 && val_len <= 4 {
                            let mut ticks = 0u32;
                            for b in &data[val_start..val_end] {
                                ticks = (ticks << 8) | (*b as u32);
                            }
                            result.sys_uptime_cs = Some(ticks);
                        }
                    }
                    4 => { // sysContact — OCTET STRING
                        if val_tag == 0x04 {
                            result.sys_contact = Some(
                                String::from_utf8_lossy(&data[val_start..val_end]).trim().to_string()
                            );
                        }
                    }
                    5 => { // sysName — OCTET STRING
                        if val_tag == 0x04 {
                            result.sys_name = Some(
                                String::from_utf8_lossy(&data[val_start..val_end]).trim().to_string()
                            );
                        }
                    }
                    6 => { // sysLocation — OCTET STRING
                        if val_tag == 0x04 {
                            result.sys_location = Some(
                                String::from_utf8_lossy(&data[val_start..val_end]).trim().to_string()
                            );
                        }
                    }
                    _ => {}
                }
            }
        }

        cur = vb_end;
    }

    // Only return a result if we extracted at least one useful field
    if result.sys_descr.is_some()
        || result.sys_name.is_some()
        || result.sys_object_id.is_some()
    {
        Some(result)
    } else {
        None
    }
}

/// Decode a BER-encoded OID into dotted-decimal string.
fn decode_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    // First byte encodes the first two arcs: arc1 = byte/40, arc2 = byte%40
    let first = bytes[0] as u32;
    let mut arcs = vec![first / 40, first % 40];

    let mut i = 1;
    while i < bytes.len() {
        // Variable-length quantity: high bit set means more bytes follow
        let mut value = 0u32;
        while i < bytes.len() {
            let b = bytes[i];
            i += 1;
            value = (value << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
        arcs.push(value);
    }

    arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(".")
}

/// Map an enterprise OID arc to a vendor name.
///
/// Covers common OT/IT vendors. Returns `"Unknown"` for unrecognised OIDs.
pub fn enterprise_vendor(oid: &str) -> &'static str {
    // Extract the enterprise arc (position 6 in 1.3.6.1.4.1.<enterprise>.*)
    let arc = oid
        .split('.')
        .nth(6)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    match arc {
        9     => "Cisco",
        11    => "HP / HPE",
        25506 => "H3C",
        43    => "3Com",
        2636  => "Juniper",
        674   => "Dell",
        318   => "APC / Schneider Electric UPS",
        2     => "IBM",
        311   => "Microsoft",
        3     => "Siemens",
        4329  => "Moxa",
        10734 => "Hirschmann / Belden",
        4515  => "Westermo",
        4005  => "Rockwell Automation",
        6890  => "Phoenix Contact",
        6527  => "Alcatel-Lucent",
        18763 => "Belden",
        26866 => "Perle Systems",
        8072  => "Net-SNMP (Linux / generic)",
        _     => "Unknown",
    }
}

/// Decode a BER length field starting at `data[pos]`.
///
/// Returns `(content_start, length)` where `content_start` is the index
/// of the first byte after the length field.
fn decode_ber_length(data: &[u8], pos: usize) -> Option<(usize, usize)> {
    let first = *data.get(pos)? as usize;
    if first < 0x80 {
        // Short form: length is the byte itself
        Some((pos + 1, first))
    } else {
        // Long form: first byte encodes how many length bytes follow
        let num_bytes = first & 0x7F;
        if num_bytes == 0 || num_bytes > 4 || pos + 1 + num_bytes > data.len() {
            return None;
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (data[pos + 1 + i] as usize);
        }
        Some((pos + 1 + num_bytes, length))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal SNMPv1/v2c GetRequest packet with a given community string.
    fn snmp_packet(version: u8, community: &[u8]) -> Vec<u8> {
        // Inner: version INTEGER + community OCTET STRING + minimal PDU
        let ver_bytes = vec![0x02, 0x01, version]; // INTEGER, len 1, value
        let comm_bytes = {
            let mut v = vec![0x04, community.len() as u8];
            v.extend_from_slice(community);
            v
        };
        // Minimal GetRequest PDU (just a tag + 0 length for this test)
        let pdu = vec![0xa0, 0x00]; // GetRequest-PDU, empty

        let inner_len = ver_bytes.len() + comm_bytes.len() + pdu.len();
        let mut packet = vec![0x30, inner_len as u8];
        packet.extend_from_slice(&ver_bytes);
        packet.extend_from_slice(&comm_bytes);
        packet.extend_from_slice(&pdu);
        packet
    }

    #[test]
    fn test_parse_snmpv1_public() {
        let pkt = snmp_packet(0x00, b"public");
        let info = parse_snmp_community(&pkt).expect("should parse");
        assert_eq!(info.version, 1);
        assert_eq!(info.community_string, "public");
        assert!(info.is_default);
        assert_eq!(info.default_severity, Some("high"));
    }

    #[test]
    fn test_parse_snmpv2c_private() {
        let pkt = snmp_packet(0x01, b"private");
        let info = parse_snmp_community(&pkt).expect("should parse");
        assert_eq!(info.version, 2);
        assert_eq!(info.community_string, "private");
        assert!(info.is_default);
        assert_eq!(info.default_severity, Some("critical"));
    }

    #[test]
    fn test_custom_community_not_default() {
        let pkt = snmp_packet(0x01, b"my-custom-community-xyz");
        let info = parse_snmp_community(&pkt).expect("should parse");
        assert_eq!(info.community_string, "my-custom-community-xyz");
        assert!(!info.is_default);
        assert_eq!(info.default_severity, None);
    }

    #[test]
    fn test_too_short_returns_none() {
        assert!(parse_snmp_community(&[0x30, 0x05]).is_none());
    }

    #[test]
    fn test_wrong_tag_returns_none() {
        // Does not start with 0x30
        let data = vec![0x31, 0x10, 0x02, 0x01, 0x00, 0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c'];
        assert!(parse_snmp_community(&data).is_none());
    }

    // ── SNMP GET-Response tests ────────────────────────────────────────────────

    /// Build a minimal SNMP GET-Response PDU with a single VarBind.
    ///
    /// `oid_bytes` = the encoded OID bytes (tag+len already included elsewhere).
    /// `value_tag` + `value_bytes` = the value field.
    fn build_get_response(community: &[u8], oid_bytes: &[u8], value_tag: u8, value_bytes: &[u8]) -> Vec<u8> {
        // VarBind SEQUENCE: OID + value
        let oid_field = {
            let mut v = vec![0x06, oid_bytes.len() as u8];
            v.extend_from_slice(oid_bytes);
            v
        };
        let val_field = {
            let mut v = vec![value_tag, value_bytes.len() as u8];
            v.extend_from_slice(value_bytes);
            v
        };
        let vb_inner_len = oid_field.len() + val_field.len();
        let mut varbind = vec![0x30, vb_inner_len as u8];
        varbind.extend_from_slice(&oid_field);
        varbind.extend_from_slice(&val_field);

        // VarBindList SEQUENCE
        let mut vbl = vec![0x30, varbind.len() as u8];
        vbl.extend_from_slice(&varbind);

        // Request-id, error-status, error-index (all zero integers)
        let zeros = vec![0x02, 0x01, 0x00]; // INTEGER 0

        // PDU SEQUENCE (GetResponse = 0xA2)
        let pdu_inner_len = zeros.len() * 3 + vbl.len();
        let mut pdu = vec![0xA2, pdu_inner_len as u8];
        pdu.extend_from_slice(&zeros);
        pdu.extend_from_slice(&zeros);
        pdu.extend_from_slice(&zeros);
        pdu.extend_from_slice(&vbl);

        // Version INTEGER
        let version = vec![0x02, 0x01, 0x01u8]; // SNMPv2c
        // Community OCTET STRING
        let mut comm = vec![0x04, community.len() as u8];
        comm.extend_from_slice(community);

        // Outer SEQUENCE
        let outer_inner_len = version.len() + comm.len() + pdu.len();
        let mut packet = vec![0x30, outer_inner_len as u8];
        packet.extend_from_slice(&version);
        packet.extend_from_slice(&comm);
        packet.extend_from_slice(&pdu);
        packet
    }

    /// OID bytes for 1.3.6.1.2.1.1.X.0 (sysDescr=1, sysName=5, etc.)
    fn sys_oid(sub_id: u8) -> Vec<u8> {
        // 1.3 → 0x2B; 6 → 0x06; 1 → 0x01; 2 → 0x02; 1 → 0x01; 1 → 0x01; sub_id; 0
        vec![0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, sub_id, 0x00]
    }

    #[test]
    fn test_parse_get_response_sys_descr() {
        let pkt = build_get_response(
            b"public",
            &sys_oid(1),       // sysDescr OID
            0x04,              // OCTET STRING
            b"Hirschmann MACH104 Release 09.0.00",
        );
        let info = parse_snmp_response(&pkt).expect("should parse GET-Response");
        assert_eq!(
            info.sys_descr.as_deref(),
            Some("Hirschmann MACH104 Release 09.0.00")
        );
        assert!(info.sys_name.is_none());
    }

    #[test]
    fn test_parse_get_response_sys_name() {
        let pkt = build_get_response(
            b"public",
            &sys_oid(5),       // sysName
            0x04,
            b"PLC-Cabinet-01",
        );
        let info = parse_snmp_response(&pkt).expect("should parse GET-Response with sysName");
        // sysName alone isn't enough to return Some (need descr or objectid too)
        // Update: actually we also return if sys_name alone; let's check
        // Looking at the code: returns Some if sys_descr || sys_name || sys_object_id
        assert_eq!(info.sys_name.as_deref(), Some("PLC-Cabinet-01"));
    }

    #[test]
    fn test_non_get_response_returns_none() {
        // Use 0xA0 (GetRequest) instead of 0xA2 (GetResponse)
        let pkt = build_get_response(b"public", &sys_oid(1), 0x04, b"test");
        // Patch byte that is the PDU tag — find 0xA2 and replace with 0xA0
        let mut pkt2 = pkt.clone();
        if let Some(pos) = pkt2.iter().position(|&b| b == 0xA2) {
            pkt2[pos] = 0xA0;
        }
        assert!(parse_snmp_response(&pkt2).is_none());
    }

    #[test]
    fn test_decode_oid() {
        // 1.3.6.1.4.1.9.1.1 (Cisco enterprise)
        let bytes = vec![0x2B, 0x06, 0x01, 0x04, 0x01, 0x09, 0x01, 0x01];
        assert_eq!(decode_oid(&bytes), "1.3.6.1.4.1.9.1.1");
    }

    #[test]
    fn test_enterprise_vendor_cisco() {
        assert_eq!(enterprise_vendor("1.3.6.1.4.1.9.1.1"), "Cisco");
    }

    #[test]
    fn test_enterprise_vendor_unknown() {
        assert_eq!(enterprise_vendor("1.3.6.1.4.1.99999.1"), "Unknown");
    }
}
