//! # gm-signatures
//!
//! YAML fingerprint engine for ICS/SCADA device identification.
//!
//! ## Architecture
//!
//! Signatures are human-readable YAML files that describe how to identify
//! specific devices and vendors from network traffic. Each signature has:
//!
//! - **Filters**: conditions that must all match (port, protocol, payload bytes, MAC OUI)
//! - **Payloads**: optional extraction rules to pull vendor/product info from packet data
//! - **Confidence**: 1-5 score indicating how specific the identification is
//!
//! ## Confidence Levels
//!
//! 1. Port number only (e.g., port 502 = "probably Modbus")
//! 2. Port + traffic pattern (client/server behavior)
//! 3. MAC OUI vendor match (e.g., 00:0E:8C = Siemens)
//! 4. Payload byte pattern match (e.g., "Schneider" string in Modbus response)
//! 5. Deep protocol parse confirmation (e.g., Modbus FC 43 Device ID response)

mod error;
mod engine;
mod signature;

pub use error::SignatureError;
pub use engine::{SignatureEngine, PacketData, TestResult};
pub use signature::{Signature, SignatureFilter, SignatureMatch, ExtractedValue, PayloadExtractor};
