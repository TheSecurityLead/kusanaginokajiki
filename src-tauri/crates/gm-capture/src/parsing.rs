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
