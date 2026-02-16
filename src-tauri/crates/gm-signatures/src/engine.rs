//! Signature matching engine.
//!
//! Loads YAML signatures from a directory, matches them against
//! pre-parsed packet data, and returns confidence-scored results.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::SignatureError;
use crate::signature::{
    ExtractedValue, PayloadExtractor, Signature, SignatureFilter, SignatureMatch,
};

/// Pre-parsed packet data passed to the signature engine for matching.
///
/// This struct is intentionally decoupled from gm-capture's ParsedPacket
/// so the signature crate doesn't depend on the capture crate.
#[derive(Debug, Clone)]
pub struct PacketData {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub transport: String, // "tcp" or "udp"
    pub protocol: String,  // IcsProtocol variant name (lowercase)
    pub payload: Vec<u8>,
    pub length: usize,
}

/// The signature matching engine.
///
/// Holds all loaded signatures and provides methods to match
/// them against packet data.
pub struct SignatureEngine {
    signatures: Vec<Signature>,
    /// Compiled hex patterns for payload matching (signature index → bytes)
    compiled_patterns: HashMap<usize, Vec<CompiledFilter>>,
    /// Directory being watched for signatures
    signature_dir: Option<PathBuf>,
}

/// A pre-compiled filter for faster matching.
#[derive(Debug, Clone)]
enum CompiledFilter {
    /// Match port number: (field_name, port_value)
    Port(String, u16),
    /// Match protocol name
    Protocol(String),
    /// Match payload hex bytes at optional offset
    PayloadBytes {
        bytes: Vec<u8>,
        offset: Option<usize>,
    },
    /// Match minimum payload length
    MinLength(usize),
    /// Match MAC OUI prefix (first 3 bytes of MAC, as "xx:xx:xx")
    MacOui(String, String),
}

impl SignatureEngine {
    /// Create a new empty engine.
    pub fn new() -> Self {
        SignatureEngine {
            signatures: Vec::new(),
            compiled_patterns: HashMap::new(),
            signature_dir: None,
        }
    }

    /// Load all .yaml and .yml files from a directory.
    pub fn load_directory(&mut self, dir: &Path) -> Result<usize, SignatureError> {
        self.signature_dir = Some(dir.to_path_buf());
        let mut count = 0;

        if !dir.exists() {
            log::warn!("Signature directory does not exist: {}", dir.display());
            return Ok(0);
        }

        let entries = std::fs::read_dir(dir).map_err(|e| {
            SignatureError::IoError(format!("Failed to read directory {}: {}", dir.display(), e))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                SignatureError::IoError(format!("Failed to read directory entry: {}", e))
            })?;
            let path = entry.path();

            if let Some(ext) = path.extension() {
                if ext == "yaml" || ext == "yml" {
                    match self.load_file(&path) {
                        Ok(()) => count += 1,
                        Err(e) => {
                            log::warn!("Failed to load signature {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        log::info!("Loaded {} signatures from {}", count, dir.display());
        Ok(count)
    }

    /// Load a single signature YAML file.
    pub fn load_file(&mut self, path: &Path) -> Result<(), SignatureError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            SignatureError::IoError(format!("Failed to read {}: {}", path.display(), e))
        })?;

        self.load_yaml(&content)
    }

    /// Parse and register a signature from a YAML string.
    pub fn load_yaml(&mut self, yaml: &str) -> Result<(), SignatureError> {
        let sig: Signature = serde_yaml::from_str(yaml).map_err(|e| {
            SignatureError::ParseError(format!("Invalid YAML: {}", e))
        })?;

        // Validate confidence range
        if sig.confidence < 1 || sig.confidence > 5 {
            return Err(SignatureError::ValidationError(format!(
                "Signature '{}': confidence must be 1-5, got {}",
                sig.name, sig.confidence
            )));
        }

        // Compile filters for fast matching
        let idx = self.signatures.len();
        let compiled = compile_filters(&sig.filters)?;
        self.compiled_patterns.insert(idx, compiled);
        self.signatures.push(sig);

        Ok(())
    }

    /// Reload all signatures from the configured directory.
    pub fn reload(&mut self) -> Result<usize, SignatureError> {
        let dir = self
            .signature_dir
            .clone()
            .ok_or_else(|| SignatureError::IoError("No signature directory configured".into()))?;

        self.signatures.clear();
        self.compiled_patterns.clear();
        self.load_directory(&dir)
    }

    /// Get all loaded signatures.
    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    /// Get loaded signature count.
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Match all signatures against a single packet.
    /// Returns all matching signatures sorted by confidence (highest first).
    pub fn match_packet(&self, packet: &PacketData) -> Vec<SignatureMatch> {
        let mut matches = Vec::new();

        for (idx, sig) in self.signatures.iter().enumerate() {
            if let Some(compiled) = self.compiled_patterns.get(&idx) {
                if all_filters_match(compiled, packet) {
                    let extracted = extract_payload_values(&sig.payloads, &packet.payload);
                    matches.push(SignatureMatch {
                        signature_name: sig.name.clone(),
                        confidence: sig.confidence,
                        vendor: sig.vendor.clone(),
                        product_family: sig.product_family.clone(),
                        device_type: sig.device_type.clone(),
                        role: sig.role.clone(),
                        extracted_values: extracted,
                    });
                }
            }
        }

        // Sort by confidence descending — highest confidence match first
        matches.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        matches
    }

    /// Match all signatures against a batch of packets for a device.
    /// Returns the best (highest confidence) matches, deduplicated by signature name.
    pub fn match_device_packets(&self, packets: &[PacketData]) -> Vec<SignatureMatch> {
        let mut best_matches: HashMap<String, SignatureMatch> = HashMap::new();

        for packet in packets {
            for m in self.match_packet(packet) {
                // Keep the highest-confidence match for each signature
                if best_matches.get(&m.signature_name).is_none_or(|e| e.confidence < m.confidence) {
                    best_matches.insert(m.signature_name.clone(), m);
                }
            }
        }

        let mut results: Vec<SignatureMatch> = best_matches.into_values().collect();
        results.sort_by(|a, b| b.confidence.cmp(&a.confidence));
        results
    }

    /// Test a single YAML signature against packets, returning all matches.
    /// Used by the signature editor "Test" feature.
    pub fn test_signature(
        &self,
        yaml: &str,
        packets: &[PacketData],
    ) -> Result<Vec<TestResult>, SignatureError> {
        let sig: Signature = serde_yaml::from_str(yaml).map_err(|e| {
            SignatureError::ParseError(format!("Invalid YAML: {}", e))
        })?;

        let compiled = compile_filters(&sig.filters)?;
        let mut results = Vec::new();

        for (i, packet) in packets.iter().enumerate() {
            if all_filters_match(&compiled, packet) {
                let extracted = extract_payload_values(&sig.payloads, &packet.payload);
                results.push(TestResult {
                    packet_index: i,
                    src_ip: packet.src_ip.clone(),
                    dst_ip: packet.dst_ip.clone(),
                    src_port: packet.src_port,
                    dst_port: packet.dst_port,
                    confidence: sig.confidence,
                    extracted_values: extracted,
                });
            }
        }

        Ok(results)
    }
}

/// Result of testing a signature against a packet.
#[derive(Debug, Clone, Serialize)]
pub struct TestResult {
    pub packet_index: usize,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub confidence: u8,
    pub extracted_values: Vec<ExtractedValue>,
}

use serde::Serialize;

impl Default for SignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ── Filter compilation ──────────────────────────────────────────────

/// Compile YAML filter definitions into efficient match operations.
fn compile_filters(filters: &[SignatureFilter]) -> Result<Vec<CompiledFilter>, SignatureError> {
    let mut compiled = Vec::new();

    for filter in filters {
        match filter.field.as_str() {
            "tcp.dst_port" | "tcp.src_port" | "udp.dst_port" | "udp.src_port" | "dst_port"
            | "src_port" => {
                if let Some(ref val) = filter.value {
                    let port = yaml_value_to_u16(val).ok_or_else(|| {
                        SignatureError::ValidationError(format!(
                            "Filter field '{}': expected numeric port value",
                            filter.field
                        ))
                    })?;
                    compiled.push(CompiledFilter::Port(filter.field.clone(), port));
                }
            }

            "protocol" => {
                if let Some(ref val) = filter.value {
                    let proto = yaml_value_to_string(val);
                    compiled.push(CompiledFilter::Protocol(proto.to_lowercase()));
                }
            }

            "payload" => {
                if let Some(ref pattern) = filter.pattern {
                    let bytes = parse_hex_pattern(pattern)?;
                    compiled.push(CompiledFilter::PayloadBytes {
                        bytes,
                        offset: filter.offset,
                    });
                }
                if let Some(min_len) = filter.min_length {
                    compiled.push(CompiledFilter::MinLength(min_len));
                }
            }

            "mac.src_oui" | "mac.dst_oui" => {
                if let Some(ref val) = filter.value {
                    let oui = yaml_value_to_string(val).to_lowercase();
                    compiled.push(CompiledFilter::MacOui(filter.field.clone(), oui));
                }
            }

            other => {
                // For unrecognized fields, check if they have payload pattern
                if let Some(ref pattern) = filter.pattern {
                    let bytes = parse_hex_pattern(pattern)?;
                    compiled.push(CompiledFilter::PayloadBytes {
                        bytes,
                        offset: filter.offset,
                    });
                } else {
                    log::debug!("Ignoring unknown filter field: {}", other);
                }
            }
        }
    }

    Ok(compiled)
}

/// Check if ALL compiled filters match a packet.
fn all_filters_match(filters: &[CompiledFilter], packet: &PacketData) -> bool {
    for filter in filters {
        if !filter_matches(filter, packet) {
            return false;
        }
    }
    true
}

/// Check if a single compiled filter matches.
fn filter_matches(filter: &CompiledFilter, packet: &PacketData) -> bool {
    match filter {
        CompiledFilter::Port(field, port) => match field.as_str() {
            "tcp.dst_port" | "dst_port" => {
                packet.transport == "tcp" && packet.dst_port == *port
            }
            "tcp.src_port" | "src_port" => {
                packet.transport == "tcp" && packet.src_port == *port
            }
            "udp.dst_port" => packet.transport == "udp" && packet.dst_port == *port,
            "udp.src_port" => packet.transport == "udp" && packet.src_port == *port,
            _ => false,
        },

        CompiledFilter::Protocol(proto) => packet.protocol == *proto,

        CompiledFilter::PayloadBytes { bytes, offset } => {
            if packet.payload.is_empty() {
                return false;
            }
            match offset {
                Some(off) => {
                    // Match at specific offset
                    if *off + bytes.len() > packet.payload.len() {
                        return false;
                    }
                    packet.payload[*off..*off + bytes.len()] == *bytes
                }
                None => {
                    // Search anywhere in payload
                    payload_contains(&packet.payload, bytes)
                }
            }
        }

        CompiledFilter::MinLength(min) => packet.payload.len() >= *min,

        CompiledFilter::MacOui(field, oui) => {
            let mac = if field.contains("src") {
                &packet.src_mac
            } else {
                &packet.dst_mac
            };
            match mac {
                Some(m) => {
                    // MAC format: "aa:bb:cc:dd:ee:ff", OUI is first 8 chars "aa:bb:cc"
                    let mac_oui = if m.len() >= 8 { &m[..8] } else { m };
                    mac_oui.to_lowercase() == *oui
                }
                None => false,
            }
        }
    }
}

/// Search for a byte pattern anywhere in a payload (naive substring search).
fn payload_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

// ── Payload extraction ──────────────────────────────────────────────

/// Extract values from a packet payload using extractor rules.
fn extract_payload_values(extractors: &[PayloadExtractor], payload: &[u8]) -> Vec<ExtractedValue> {
    let mut values = Vec::new();

    for ext in extractors {
        let offset = ext.offset.unwrap_or(0);
        let length = ext.length.unwrap_or(0);

        if offset >= payload.len() {
            continue;
        }

        let end = if length > 0 {
            (offset + length).min(payload.len())
        } else {
            payload.len()
        };

        let slice = &payload[offset..end];

        let value = match ext.format.as_str() {
            "ascii" => {
                // Extract printable ASCII, stop at null byte
                let ascii: String = slice
                    .iter()
                    .take_while(|&&b| b != 0)
                    .filter(|&&b| (0x20..=0x7e).contains(&b))
                    .map(|&b| b as char)
                    .collect();
                if ascii.is_empty() {
                    continue;
                }
                ascii
            }
            "hex" => {
                slice.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
            }
            "uint16_be" => {
                if slice.len() >= 2 {
                    let val = u16::from_be_bytes([slice[0], slice[1]]);
                    val.to_string()
                } else {
                    continue;
                }
            }
            "uint16_le" => {
                if slice.len() >= 2 {
                    let val = u16::from_le_bytes([slice[0], slice[1]]);
                    val.to_string()
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        values.push(ExtractedValue {
            label: ext.display.clone().unwrap_or_else(|| ext.extract.clone()),
            value,
        });
    }

    values
}

// ── Helpers ─────────────────────────────────────────────────────────

/// Parse a hex pattern string like "\\x53\\x63\\x68" or "536368" into bytes.
fn parse_hex_pattern(pattern: &str) -> Result<Vec<u8>, SignatureError> {
    let mut bytes = Vec::new();
    let s = pattern.trim();

    if s.contains("\\x") {
        // Parse \x-escaped format: "\x53\x63\x68..."
        let parts: Vec<&str> = s.split("\\x").collect();
        for part in parts {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            // Take first 2 hex chars
            let hex = if trimmed.len() >= 2 {
                &trimmed[..2]
            } else {
                trimmed
            };
            let byte = u8::from_str_radix(hex, 16).map_err(|_| {
                SignatureError::ParseError(format!("Invalid hex byte: '{}' in pattern '{}'", hex, pattern))
            })?;
            bytes.push(byte);
        }
    } else {
        // Parse plain hex string: "536368..."
        let hex_str: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if !hex_str.len().is_multiple_of(2) {
            return Err(SignatureError::ParseError(format!(
                "Odd-length hex pattern: '{}'",
                pattern
            )));
        }
        for i in (0..hex_str.len()).step_by(2) {
            let byte = u8::from_str_radix(&hex_str[i..i + 2], 16).map_err(|_| {
                SignatureError::ParseError(format!("Invalid hex in pattern: '{}'", pattern))
            })?;
            bytes.push(byte);
        }
    }

    if bytes.is_empty() {
        return Err(SignatureError::ParseError(format!(
            "Empty hex pattern: '{}'",
            pattern
        )));
    }

    Ok(bytes)
}

/// Convert a serde_yaml::Value to a u16 (port number).
fn yaml_value_to_u16(val: &serde_yaml::Value) -> Option<u16> {
    match val {
        serde_yaml::Value::Number(n) => n.as_u64().and_then(|v| u16::try_from(v).ok()),
        serde_yaml::Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Convert a serde_yaml::Value to a String.
fn yaml_value_to_string(val: &serde_yaml::Value) -> String {
    match val {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        _ => format!("{:?}", val),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_pattern_escaped() {
        let bytes = parse_hex_pattern("\\x53\\x63\\x68").unwrap();
        assert_eq!(bytes, vec![0x53, 0x63, 0x68]);
    }

    #[test]
    fn test_parse_hex_pattern_plain() {
        let bytes = parse_hex_pattern("536368").unwrap();
        assert_eq!(bytes, vec![0x53, 0x63, 0x68]);
    }

    #[test]
    fn test_payload_contains() {
        let haystack = vec![0x00, 0x53, 0x63, 0x68, 0x00];
        assert!(payload_contains(&haystack, &[0x53, 0x63, 0x68]));
        assert!(!payload_contains(&haystack, &[0x53, 0x64]));
    }

    #[test]
    fn test_port_filter_match() {
        let filter = CompiledFilter::Port("tcp.dst_port".to_string(), 502);
        let packet = PacketData {
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            src_port: 49152,
            dst_port: 502,
            src_mac: None,
            dst_mac: None,
            transport: "tcp".to_string(),
            protocol: "modbus".to_string(),
            payload: vec![],
            length: 64,
        };
        assert!(filter_matches(&filter, &packet));
    }

    #[test]
    fn test_signature_load_and_match() {
        let yaml = r#"
name: "test_modbus"
description: "Test Modbus signature"
vendor: "Test Vendor"
product_family: "Test PLC"
protocol: modbus
filters:
  - field: tcp.dst_port
    value: 502
confidence: 1
role: slave
device_type: plc
"#;
        let mut engine = SignatureEngine::new();
        engine.load_yaml(yaml).unwrap();
        assert_eq!(engine.signature_count(), 1);

        let packet = PacketData {
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            src_port: 49152,
            dst_port: 502,
            src_mac: None,
            dst_mac: None,
            transport: "tcp".to_string(),
            protocol: "modbus".to_string(),
            payload: vec![],
            length: 64,
        };

        let matches = engine.match_packet(&packet);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].signature_name, "test_modbus");
        assert_eq!(matches[0].confidence, 1);
        assert_eq!(matches[0].vendor, Some("Test Vendor".to_string()));
    }

    #[test]
    fn test_payload_pattern_match() {
        let yaml = r#"
name: "schneider_modbus"
description: "Schneider Electric Modbus device"
vendor: "Schneider Electric"
product_family: "Modicon M340"
protocol: modbus
filters:
  - field: tcp.dst_port
    value: 502
  - field: payload
    pattern: "\\x53\\x63\\x68\\x6e\\x65\\x69\\x64\\x65\\x72"
confidence: 4
role: slave
device_type: plc
"#;
        let mut engine = SignatureEngine::new();
        engine.load_yaml(yaml).unwrap();

        // Packet WITH the "Schneider" byte pattern (request to port 502)
        let matching_packet = PacketData {
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            src_port: 49152,
            dst_port: 502,
            src_mac: None,
            dst_mac: None,
            transport: "tcp".to_string(),
            protocol: "modbus".to_string(),
            payload: b"\x00\x00\x00\x00\x53\x63\x68\x6e\x65\x69\x64\x65\x72".to_vec(),
            length: 13,
        };

        let matches = engine.match_packet(&matching_packet);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].confidence, 4);

        // Packet WITHOUT the pattern — should not match
        let non_matching = PacketData {
            src_ip: "192.168.1.10".to_string(),
            dst_ip: "192.168.1.100".to_string(),
            src_port: 49152,
            dst_port: 502,
            src_mac: None,
            dst_mac: None,
            transport: "tcp".to_string(),
            protocol: "modbus".to_string(),
            payload: b"\x00\x00\x00\x00\x00\x00".to_vec(),
            length: 6,
        };
        assert!(engine.match_packet(&non_matching).is_empty());
    }

    #[test]
    fn test_load_signature_directory() {
        // Load the shipped signatures from the project's signatures/ directory
        let sig_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("signatures");
        if sig_dir.exists() {
            let mut engine = SignatureEngine::new();
            let count = engine.load_directory(&sig_dir).unwrap();
            assert!(
                count >= 20,
                "Expected at least 20 signatures, loaded {}",
                count
            );
        }
    }

    #[test]
    fn test_mac_oui_filter() {
        let yaml = r#"
name: "siemens_mac"
description: "Siemens device by MAC OUI"
vendor: "Siemens"
filters:
  - field: mac.src_oui
    value: "00:0e:8c"
confidence: 3
device_type: plc
"#;
        let mut engine = SignatureEngine::new();
        engine.load_yaml(yaml).unwrap();

        let packet = PacketData {
            src_ip: "192.168.1.100".to_string(),
            dst_ip: "192.168.1.10".to_string(),
            src_port: 102,
            dst_port: 49152,
            src_mac: Some("00:0e:8c:12:34:56".to_string()),
            dst_mac: None,
            transport: "tcp".to_string(),
            protocol: "s7comm".to_string(),
            payload: vec![],
            length: 64,
        };

        let matches = engine.match_packet(&packet);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].vendor, Some("Siemens".to_string()));
    }
}
