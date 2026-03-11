//! Shared packet parsing utilities.
//!
//! These functions are used by both the PCAP file reader and live capture
//! to extract structured packet information from raw Ethernet frames.

use chrono::{DateTime, Utc};
use etherparse::{SlicedPacket, NetSlice, TransportSlice};

use crate::packet::{ParsedPacket, TransportProtocol};

/// Extract structured packet info from an etherparse SlicedPacket.
///
/// Returns None for non-IP packets (ARP, etc.), which are silently skipped.
pub(crate) fn extract_packet_info(
    parsed: &SlicedPacket,
    raw_data: &[u8],
    timestamp: DateTime<Utc>,
    origin_file: &str,
) -> Option<ParsedPacket> {
    // Extract MAC addresses from Ethernet header
    let (src_mac, dst_mac) = if raw_data.len() >= 14 {
        let dst: [u8; 6] = raw_data[0..6].try_into().ok()?;
        let src: [u8; 6] = raw_data[6..12].try_into().ok()?;
        (
            Some(ParsedPacket::format_mac(&src)),
            Some(ParsedPacket::format_mac(&dst)),
        )
    } else {
        (None, None)
    };

    // Extract IP addresses from network layer
    let (src_ip, dst_ip) = match &parsed.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let header = ipv4.header();
            (
                format_ipv4(header.source()),
                format_ipv4(header.destination()),
            )
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let header = ipv6.header();
            (
                format_ipv6(header.source()),
                format_ipv6(header.destination()),
            )
        }
        _ => return None, // Skip non-IP packets (ARP, etc.)
    };

    // Extract transport layer info (ports + protocol)
    let (transport, src_port, dst_port) = match &parsed.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            (TransportProtocol::Tcp, tcp.source_port(), tcp.destination_port())
        }
        Some(TransportSlice::Udp(udp)) => {
            (TransportProtocol::Udp, udp.source_port(), udp.destination_port())
        }
        _ => (TransportProtocol::Other, 0, 0),
    };

    // Extract application-layer payload from the transport layer
    let payload = match &parsed.transport {
        Some(TransportSlice::Tcp(tcp)) => tcp.payload().to_vec(),
        Some(TransportSlice::Udp(udp)) => udp.payload().to_vec(),
        _ => Vec::new(),
    };

    Some(ParsedPacket {
        timestamp,
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        transport,
        src_port,
        dst_port,
        length: raw_data.len(),
        payload,
        origin_file: origin_file.to_string(),
    })
}

/// Try to extract an LLDP frame from raw Ethernet data.
///
/// LLDP uses Ethertype 0x88CC and is a Layer-2-only protocol — it has no IP
/// header. Returns a synthetic `ParsedPacket` with:
/// - `src_ip` = `"lldp:<mac>"` (the sending device's MAC)
/// - `dst_ip` = `"lldp:broadcast"`
/// - `payload` = the LLDP PDU (everything after the 14-byte Ethernet header)
///
/// Returns None if the frame is not LLDP or is too short.
pub(crate) fn try_extract_lldp_packet(
    raw_data: &[u8],
    timestamp: chrono::DateTime<chrono::Utc>,
    origin_file: &str,
) -> Option<ParsedPacket> {
    // Need at least 14 bytes for Ethernet header
    if raw_data.len() < 14 {
        return None;
    }
    // Check Ethertype at bytes 12-13 (skip VLAN tag 0x8100 if present)
    let (ethertype_offset, payload_start) = if raw_data[12] == 0x81 && raw_data[13] == 0x00 && raw_data.len() >= 18 {
        (14, 18) // 802.1Q VLAN tag
    } else {
        (12, 14)
    };
    if raw_data[ethertype_offset] != 0x88 || raw_data[ethertype_offset + 1] != 0xCC {
        return None;
    }

    let dst_mac: [u8; 6] = raw_data[0..6].try_into().ok()?;
    let src_mac: [u8; 6] = raw_data[6..12].try_into().ok()?;

    let src_mac_str = ParsedPacket::format_mac(&src_mac);
    let dst_mac_str = ParsedPacket::format_mac(&dst_mac);

    Some(ParsedPacket {
        timestamp,
        src_mac: Some(src_mac_str.clone()),
        dst_mac: Some(dst_mac_str),
        // Use a sentinel prefix so the processor can identify LLDP packets
        src_ip: format!("lldp:{}", src_mac_str),
        dst_ip: "lldp:broadcast".to_string(),
        transport: crate::packet::TransportProtocol::Other,
        src_port: 0,
        dst_port: 0,
        length: raw_data.len(),
        payload: raw_data[payload_start..].to_vec(),
        origin_file: origin_file.to_string(),
    })
}

/// Try to extract a Layer-2 redundancy protocol frame from raw Ethernet data.
///
/// Handles MRP, RSTP, HSR, PRP, and DLR frames — all of which lack an IP
/// header and are identified by dst MAC or Ethertype.
///
/// Returns a synthetic `ParsedPacket` with:
/// - `src_ip` = `"redundancy:<proto>"` (e.g. "redundancy:mrp", "redundancy:rstp")
/// - `dst_ip` = `"redundancy:multicast"`
/// - `payload` = frame bytes after the 14-byte Ethernet header
///
/// Returns None if the frame is not a known redundancy protocol or is too short.
///
/// NOTE: Detection logic is inlined here (not delegated to gm-parsers) to avoid
/// a circular dependency: gm-parsers → gm-capture → gm-parsers.
pub(crate) fn try_extract_redundancy_packet(
    raw_data: &[u8],
    timestamp: chrono::DateTime<chrono::Utc>,
    origin_file: &str,
) -> Option<ParsedPacket> {
    if raw_data.len() < 14 {
        return None;
    }
    let dst = &raw_data[0..6];
    let ethertype = u16::from_be_bytes([raw_data[12], raw_data[13]]);

    // RSTP/STP: dst 01:80:C2:00:00:00, length < 1500, LLC DSAP=0x42
    let proto_hint = if dst == [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]
        && ethertype < 1500
        && raw_data.len() >= 17
        && raw_data[14] == 0x42
        && raw_data[15] == 0x42
    {
        "rstp"
    } else if ethertype == 0x88E3
        || (dst[0..5] == [0x01, 0x15, 0x4E, 0x00, 0x01] && (dst[5] == 0x01 || dst[5] == 0x02))
    {
        "mrp"
    } else if ethertype == 0x892F
        || (dst[0..5] == [0x01, 0x15, 0x4E, 0x00, 0x01] && (0x20..=0x2F).contains(&dst[5]))
    {
        "hsr"
    } else if ethertype == 0x88FB || dst == [0x01, 0x15, 0x4E, 0x00, 0x01, 0x00] {
        "prp"
    } else if ethertype == 0x80E1 || dst == [0x01, 0x21, 0x6C, 0x00, 0x00, 0x01] {
        "dlr"
    } else {
        return None;
    };

    let src_mac: [u8; 6] = raw_data[6..12].try_into().ok()?;
    let dst_mac: [u8; 6] = raw_data[0..6].try_into().ok()?;

    let src_mac_str = ParsedPacket::format_mac(&src_mac);
    let dst_mac_str = ParsedPacket::format_mac(&dst_mac);

    Some(ParsedPacket {
        timestamp,
        src_mac: Some(src_mac_str.clone()),
        dst_mac: Some(dst_mac_str),
        // Encode the protocol hint in src_ip so the processor can route it
        src_ip: format!("redundancy:{proto_hint}"),
        dst_ip: "redundancy:multicast".to_string(),
        transport: crate::packet::TransportProtocol::Other,
        src_port: 0,
        dst_port: 0,
        length: raw_data.len(),
        // Payload = everything after the 14-byte Ethernet header
        payload: raw_data[14..].to_vec(),
        origin_file: origin_file.to_string(),
    })
}

/// Convert pcap packet header timestamp to chrono DateTime.
///
/// Casts are required for cross-platform compatibility: the pcap crate's
/// `PacketHeader` wraps C's `struct timeval`, where `tv_sec` and `tv_usec`
/// are `long`. On Linux/macOS (LP64), `long` is 64-bit so these are `i64`.
/// On Windows (LLP64), `long` is 32-bit so these are `i32`.
/// `DateTime::from_timestamp` expects `(i64, u32)`, so we cast explicitly
/// to compile on all platforms.
#[allow(clippy::unnecessary_cast)] // Casts ARE necessary on Windows (i32→i64), but redundant on Linux (i64→i64)
pub(crate) fn timestamp_from_pcap(header: pcap::PacketHeader) -> DateTime<Utc> {
    DateTime::from_timestamp(
        header.ts.tv_sec as i64,
        header.ts.tv_usec as u32 * 1000, // microseconds → nanoseconds
    )
    .unwrap_or_else(Utc::now)
}

pub(crate) fn format_ipv4(bytes: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

pub(crate) fn format_ipv6(bytes: [u8; 16]) -> String {
    let segments: Vec<String> = (0..8)
        .map(|i| {
            let high = bytes[i * 2] as u16;
            let low = bytes[i * 2 + 1] as u16;
            format!("{:x}", (high << 8) | low)
        })
        .collect();
    segments.join(":")
}
