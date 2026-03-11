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
}
