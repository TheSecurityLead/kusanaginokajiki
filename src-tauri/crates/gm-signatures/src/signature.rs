//! Signature data model — defines the YAML schema for fingerprints.

use serde::{Deserialize, Serialize};

/// A single device/protocol signature loaded from YAML.
///
/// Each signature has filters (which packets to match) and optional
/// payload extractors (what to pull from matching packets).
/// Confidence is assigned by the signature author based on how specific
/// the match criteria are.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Unique name for this signature (e.g., "schneider_modbus_m340")
    pub name: String,

    /// Human-readable description
    #[serde(default)]
    pub description: String,

    /// Vendor name (e.g., "Schneider Electric")
    #[serde(default)]
    pub vendor: Option<String>,

    /// Product family (e.g., "Modicon M340")
    #[serde(default)]
    pub product_family: Option<String>,

    /// Protocol this signature applies to (matches IcsProtocol variant names)
    #[serde(default)]
    pub protocol: Option<String>,

    /// Filters that must ALL match for this signature to fire
    pub filters: Vec<SignatureFilter>,

    /// Optional payload extraction rules
    #[serde(default)]
    pub payloads: Vec<PayloadExtractor>,

    /// Confidence level (1-5) assigned by the signature author
    /// 1=port only, 2=port+pattern, 3=MAC OUI, 4=payload match, 5=deep parse
    pub confidence: u8,

    /// Device role: "master", "slave", "client", "server", "both"
    #[serde(default)]
    pub role: Option<String>,

    /// Device type: "plc", "rtu", "hmi", "historian", "scada_server", etc.
    #[serde(default)]
    pub device_type: Option<String>,
}

/// A filter condition that a packet must satisfy.
///
/// Filters are AND-combined: all filters in a signature must match
/// for the signature to fire on a given packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureFilter {
    /// The field to check (e.g., "tcp.dst_port", "udp.src_port", "payload", "mac.src_oui")
    pub field: String,

    /// Exact value match (for port numbers, protocol names, etc.)
    #[serde(default)]
    pub value: Option<serde_yaml::Value>,

    /// Hex byte pattern to match in payload (e.g., "\\x00\\x00" or "536368")
    #[serde(default)]
    pub pattern: Option<String>,

    /// Minimum payload length required
    #[serde(default)]
    pub min_length: Option<usize>,

    /// Match payload bytes at a specific offset
    #[serde(default)]
    pub offset: Option<usize>,
}

/// A rule for extracting information from a matching packet's payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadExtractor {
    /// What to extract (e.g., "modbus.device_id.vendor_name")
    pub extract: String,

    /// Display label in the UI
    #[serde(default)]
    pub display: Option<String>,

    /// Byte offset in payload to start extraction
    #[serde(default)]
    pub offset: Option<usize>,

    /// Number of bytes to extract
    #[serde(default)]
    pub length: Option<usize>,

    /// Interpret extracted bytes as: "ascii", "hex", "uint16_be", "uint16_le"
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "ascii".to_string()
}

/// Result of matching a signature against a packet/connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureMatch {
    /// Name of the signature that matched
    pub signature_name: String,

    /// Confidence score (1-5)
    pub confidence: u8,

    /// Vendor identified by the signature
    pub vendor: Option<String>,

    /// Product family identified
    pub product_family: Option<String>,

    /// Device type from signature
    pub device_type: Option<String>,

    /// Device role from signature
    pub role: Option<String>,

    /// Extracted payload values (display_label → value)
    pub extracted_values: Vec<ExtractedValue>,
}

/// A value extracted from a packet payload by a signature's payload extractor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedValue {
    pub label: String,
    pub value: String,
}
