use std::path::Path;
use chrono::{DateTime, Utc};
use etherparse::{SlicedPacket, NetSlice, TransportSlice};
use log::{debug, warn};

use crate::error::CaptureError;
use crate::packet::{ParsedPacket, TransportProtocol};

/// Reads and parses packets from a PCAP/PCAPNG file.
///
/// # Usage
/// ```no_run
/// use gm_capture::PcapReader;
///
/// let reader = PcapReader::new();
/// let packets = reader.read_file("capture.pcap").unwrap();
/// println!("Parsed {} packets", packets.len());
/// ```
pub struct PcapReader;

impl PcapReader {
    pub fn new() -> Self {
        PcapReader
    }

    /// Read all packets from a PCAP or PCAPNG file.
    ///
    /// Returns a Vec of parsed packets with Layer 2-4 information extracted.
    /// Packets that fail to parse are silently skipped (logged at debug level).
    pub fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ParsedPacket>, CaptureError> {
        let path = path.as_ref();

        let mut capture = pcap::Capture::from_file(path)
            .map_err(|e| CaptureError::FileOpen(format!("{}: {}", path.display(), e)))?;

        let mut packets = Vec::new();
        let mut skipped = 0u64;

        while let Ok(raw_packet) = capture.next_packet() {
            // Extract timestamp from pcap header
            let timestamp = timestamp_from_pcap(&raw_packet.header);

            // Parse with etherparse — zero-copy slicing of packet headers
            match SlicedPacket::from_ethernet(raw_packet.data) {
                Ok(parsed) => {
                    if let Some(packet) = extract_packet_info(&parsed, raw_packet.data, timestamp) {
                        packets.push(packet);
                    } else {
                        skipped += 1;
                        debug!("Skipped non-IP packet");
                    }
                }
                Err(e) => {
                    skipped += 1;
                    debug!("Failed to parse packet: {}", e);
                }
            }
        }

        if skipped > 0 {
            warn!("Skipped {} unparseable packets out of {}", skipped, packets.len() + skipped as usize);
        }

        log::info!(
            "Parsed {} packets from {}",
            packets.len(),
            path.display()
        );

        Ok(packets)
    }
}

/// Extract structured packet info from an etherparse SlicedPacket.
fn extract_packet_info(
    parsed: &SlicedPacket,
    raw_data: &[u8],
    timestamp: DateTime<Utc>,
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

    // Extract application-layer payload
    let payload = parsed.payload.to_vec();

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
    })
}

/// Convert pcap packet header timestamp to chrono DateTime.
fn timestamp_from_pcap(header: &pcap::PacketHeader) -> DateTime<Utc> {
    DateTime::from_timestamp(
        header.ts.tv_sec as i64,
        (header.ts.tv_usec as u32) * 1000, // microseconds → nanoseconds
    )
    .unwrap_or_else(|| Utc::now())
}

fn format_ipv4(bytes: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

fn format_ipv6(bytes: [u8; 16]) -> String {
    // Simplified — full IPv6 formatting
    let segments: Vec<String> = (0..8)
        .map(|i| {
            let high = bytes[i * 2] as u16;
            let low = bytes[i * 2 + 1] as u16;
            format!("{:x}", (high << 8) | low)
        })
        .collect();
    segments.join(":")
}

impl Default for PcapReader {
    fn default() -> Self {
        Self::new()
    }
}
