//! # gm-parsers
//!
//! ICS/SCADA protocol identification and deep parsing.
//!
//! ## Architecture
//!
//! Protocol identification happens in two passes:
//!
//! 1. **Port-based detection** (fast, works on every packet):
//!    Maps well-known ports to likely protocols. This gives us an initial
//!    classification that's correct ~95% of the time for standard deployments.
//!
//! 2. **Deep parsing** (Phase 4, per-protocol inspection):
//!    Extracts application-layer details: function codes, device IDs,
//!    master/slave roles, register ranges, polling patterns.
//!
//! ## Adding a New Protocol
//!
//! 1. Add a variant to `IcsProtocol`
//! 2. Add port mappings in `identify_by_port()`
//! 3. Add a parser module (e.g., `modbus.rs`, `dnp3.rs`)

mod protocol;
pub mod modbus;
pub mod dnp3;

pub use protocol::{IcsProtocol, identify_protocol, identify_by_port};
pub use modbus::{
    parse_modbus, ModbusInfo, ModbusRole, ModbusDeviceId,
    RegisterRange, RegisterType,
    function_code_name as modbus_function_code_name,
};
pub use dnp3::{
    parse_dnp3, Dnp3Info, Dnp3Role,
    function_code_name as dnp3_function_code_name,
};

use gm_capture::ParsedPacket;
use serde::Serialize;

/// Unified result from deep protocol parsing.
///
/// After port-based protocol identification, packets identified as
/// Modbus or DNP3 are run through the deep parser to extract
/// application-layer details.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "protocol_type")]
pub enum DeepParseResult {
    /// Modbus TCP deep parse result
    Modbus(ModbusInfo),
    /// DNP3 deep parse result
    Dnp3(Dnp3Info),
}

/// Attempt to deep-parse a packet based on its identified protocol.
///
/// Returns None if:
/// - The protocol doesn't have a deep parser (only Modbus and DNP3 for now)
/// - The payload is invalid or too short for the protocol
///
/// # Arguments
/// * `packet` - The parsed packet with payload bytes
/// * `protocol` - The protocol identified by port-based detection
pub fn deep_parse(packet: &ParsedPacket, protocol: IcsProtocol) -> Option<DeepParseResult> {
    match protocol {
        IcsProtocol::Modbus => {
            parse_modbus(&packet.payload, packet.src_port, packet.dst_port)
                .map(DeepParseResult::Modbus)
        }
        IcsProtocol::Dnp3 => {
            parse_dnp3(&packet.payload, packet.src_port, packet.dst_port)
                .map(DeepParseResult::Dnp3)
        }
        _ => None,
    }
}
