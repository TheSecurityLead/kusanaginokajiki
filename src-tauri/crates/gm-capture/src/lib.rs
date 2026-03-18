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
mod pcap_filter;
mod pcap_reader;

pub use error::CaptureError;
pub use interface::{list_interfaces, InterfaceAddress, InterfaceFlags, NetworkInterface};
pub use live::{CaptureStats, LiveCaptureConfig, LiveCaptureHandle};
pub use packet::{ParsedPacket, TransportProtocol};
pub use pcap_filter::filter_export_pcap;
pub use pcap_reader::{FileProcessStats, PcapReader, ProgressUpdate};
