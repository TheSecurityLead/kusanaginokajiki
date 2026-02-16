//! External tool log parsers for Kusanagi Kajiki.
//!
//! Parses output from:
//! - **Zeek** (formerly Bro): TSV logs (conn.log, modbus.log, dnp3.log, s7comm.log)
//! - **Suricata**: eve.json (line-delimited JSON with flow/alert/protocol metadata)
//! - **Nmap**: XML output (-oX format, host/port/service/OS detection)
//! - **Masscan**: JSON list format (IP/port/service results)
//!
//! Each parser produces [`IngestResult`] containing assets and connections
//! compatible with the existing pipeline.

pub mod error;
pub mod zeek;
pub mod suricata;
pub mod nmap;
pub mod masscan;

pub use error::IngestError;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Identifies the source of ingested data.
///
/// Used to tag assets and connections so the UI can distinguish
/// active scan results from passive observations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngestSource {
    /// Zeek (Bro) IDS logs — passive observation
    Zeek,
    /// Suricata IDS/IPS — passive observation + alerts
    Suricata,
    /// Nmap scan results — ACTIVE scan (imported only, never run)
    Nmap,
    /// Masscan scan results — ACTIVE scan (imported only, never run)
    Masscan,
}

impl IngestSource {
    /// Whether this source represents an active scan (vs passive observation).
    pub fn is_active_scan(&self) -> bool {
        matches!(self, IngestSource::Nmap | IngestSource::Masscan)
    }

    /// Display name for the source.
    pub fn display_name(&self) -> &'static str {
        match self {
            IngestSource::Zeek => "Zeek",
            IngestSource::Suricata => "Suricata",
            IngestSource::Nmap => "Nmap",
            IngestSource::Masscan => "Masscan",
        }
    }
}

/// An ingested asset from external tool output.
///
/// Lighter than the full AssetInfo — the command layer merges these
/// into existing assets or creates new ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedAsset {
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub device_type: Option<String>,
    pub vendor: Option<String>,
    pub protocols: Vec<String>,
    pub open_ports: Vec<PortService>,
    pub os_info: Option<String>,
    pub source: IngestSource,
    /// Whether this data came from an active scan
    pub is_active: bool,
}

/// An open port with optional service identification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortService {
    pub port: u16,
    pub protocol: String,
    pub service_name: Option<String>,
    pub service_version: Option<String>,
    pub product: Option<String>,
}

/// An ingested connection/flow from external tool logs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedConnection {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub transport: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: Option<DateTime<Utc>>,
    pub last_seen: Option<DateTime<Utc>>,
    pub source: IngestSource,
}

/// An alert/finding from Suricata or similar IDS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedAlert {
    pub timestamp: DateTime<Utc>,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub signature_id: u64,
    pub signature: String,
    pub category: String,
    pub severity: u8,
    pub source: IngestSource,
}

/// Result of ingesting external tool data.
#[derive(Debug, Clone, Default, Serialize)]
pub struct IngestResult {
    pub source: Option<IngestSource>,
    pub assets: Vec<IngestedAsset>,
    pub connections: Vec<IngestedConnection>,
    pub alerts: Vec<IngestedAlert>,
    pub files_processed: usize,
    pub errors: Vec<String>,
}
