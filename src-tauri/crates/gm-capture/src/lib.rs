//! # gm-capture
//!
//! Packet capture engine for Kusanagi Kajiki.
//! Handles both PCAP file import and live network capture.
//!
//! This crate extracts Layer 2-4 information (MAC, IP, ports, transport)
//! and passes raw payload bytes to gm-parsers for protocol identification.

mod error;
mod interface;
pub mod live;
mod packet;
pub(crate) mod parsing;
mod pcap_reader;

pub use error::CaptureError;
pub use interface::{list_interfaces, NetworkInterface, InterfaceAddress, InterfaceFlags};
pub use live::{LiveCaptureHandle, LiveCaptureConfig, CaptureStats};
pub use packet::{ParsedPacket, TransportProtocol};
pub use pcap_reader::PcapReader;
