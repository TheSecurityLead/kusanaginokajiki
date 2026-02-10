use chrono::{DateTime, Utc};
use serde::Serialize;

/// Transport layer protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Other,
}

/// A packet parsed down to Layer 4 (transport).
///
/// This struct contains everything extracted from the Ethernet/IP/TCP|UDP
/// headers. The raw payload bytes are included for downstream protocol
/// parsers (Modbus, DNP3, etc.) to inspect.
#[derive(Debug, Clone, Serialize)]
pub struct ParsedPacket {
    /// Timestamp from the PCAP file or live capture
    pub timestamp: DateTime<Utc>,

    /// Source MAC address (hex string, e.g. "aa:bb:cc:dd:ee:ff")
    pub src_mac: Option<String>,

    /// Destination MAC address
    pub dst_mac: Option<String>,

    /// Source IP address
    pub src_ip: String,

    /// Destination IP address
    pub dst_ip: String,

    /// Transport protocol (TCP, UDP, or Other)
    pub transport: TransportProtocol,

    /// Source port (0 if not TCP/UDP)
    pub src_port: u16,

    /// Destination port (0 if not TCP/UDP)
    pub dst_port: u16,

    /// Total packet length in bytes
    pub length: usize,

    /// Raw application-layer payload for protocol parsers
    #[serde(skip)]
    pub payload: Vec<u8>,
}

impl ParsedPacket {
    /// Format MAC bytes as a colon-separated hex string.
    pub fn format_mac(bytes: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}
