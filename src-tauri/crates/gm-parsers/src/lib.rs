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

pub mod bacnet;
pub mod dnp3;
pub mod enip;
pub mod iec104;
pub mod lldp;
pub mod modbus;
pub mod profinet_dcp;
pub mod profinet_io;
mod protocol;
pub mod redundancy;
pub mod s7comm;
pub mod s7comm_plus;
pub mod snmp;
pub mod vendor_tables;

pub use bacnet::{
    parse as parse_bacnet, BacnetIAm, BacnetInfo, BacnetObjectType, BacnetPduType, BacnetRole,
    BacnetService, BvlcFunction,
};
pub use dnp3::{function_code_name as dnp3_function_code_name, parse_dnp3, Dnp3Info, Dnp3Role};
pub use enip::{
    parse as parse_enip, CipClass, CipService, EnipCommand, EnipIdentity, EnipInfo, EnipRole,
};
pub use iec104::{
    parse as parse_iec104, AsduTypeId, CauseOfTransmission, Iec104FrameType, Iec104Info,
    Iec104Role, UFrameFunction,
};
pub use lldp::{parse as parse_lldp, LldpInfo, LldpMgmtAddress};
pub use modbus::{
    function_code_name as modbus_function_code_name, parse_modbus, ModbusDeviceId, ModbusInfo,
    ModbusRole, RegisterRange, RegisterType,
};
pub use profinet_dcp::{
    parse as parse_profinet_dcp, DcpDeviceInfo, DcpServiceId, DcpServiceType, ProfinetDcpInfo,
    ProfinetRole,
};
pub use profinet_io::{
    parse as parse_profinet_io, ProfinetIoAlarmInfo, ProfinetIoDataStatus, ProfinetIoFrameType,
    ProfinetIoInfo, ProfinetIoRole,
};
pub use protocol::{identify_by_port, identify_protocol, IcsProtocol};
pub use redundancy::{
    detect_protocol as detect_redundancy_protocol, parse as parse_redundancy, RedundancyInfo,
    RedundancyProtocol,
};
pub use s7comm::{
    function_code_name as s7_function_code_name, parse as parse_s7, CotpParams, CotpPduType,
    S7Function, S7Info, S7PduType, S7Role,
};
pub use s7comm_plus::{
    function_code_name as s7plus_function_code_name, parse as parse_s7plus, S7PlusFunction,
    S7PlusInfo, S7PlusOpcode, S7PlusRole, S7PlusVersion,
};
pub use snmp::{parse_snmp_community, parse_snmp_response, SnmpDeviceInfo, SnmpInfo};

use gm_capture::ParsedPacket;
use serde::Serialize;

/// Unified result from deep protocol parsing.
///
/// After port-based protocol identification, packets identified as
/// Modbus, DNP3, EtherNet/IP, S7comm, or BACnet are run through the deep
/// parser to extract application-layer details.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "protocol_type")]
pub enum DeepParseResult {
    /// Modbus TCP deep parse result
    Modbus(ModbusInfo),
    /// DNP3 deep parse result
    Dnp3(Dnp3Info),
    /// EtherNet/IP + CIP deep parse result
    Enip(EnipInfo),
    /// S7comm (TPKT/COTP/S7) deep parse result
    S7(S7Info),
    /// S7comm+ (TPKT/COTP/S7+ protocol ID 0x72) deep parse result
    S7Plus(S7PlusInfo),
    /// BACnet/IP (BVLCI/NPDU/APDU) deep parse result
    Bacnet(BacnetInfo),
    /// IEC 60870-5-104 deep parse result
    Iec104(Iec104Info),
    /// PROFINET DCP deep parse result
    ProfinetDcp(ProfinetDcpInfo),
    /// PROFINET IO RT cyclic/alarm frame parse result
    ProfinetIo(ProfinetIoInfo),
    /// LLDP (Link Layer Discovery Protocol) parse result
    Lldp(LldpInfo),
}

/// Attempt to deep-parse a packet based on its identified protocol.
///
/// Returns None if:
/// - The protocol doesn't have a deep parser yet
/// - The payload is invalid or too short for the protocol
///
/// # Arguments
/// * `packet` - The parsed packet with payload bytes
/// * `protocol` - The protocol identified by port-based detection
pub fn deep_parse(packet: &ParsedPacket, protocol: IcsProtocol) -> Option<DeepParseResult> {
    match protocol {
        IcsProtocol::Modbus => parse_modbus(&packet.payload, packet.src_port, packet.dst_port)
            .map(DeepParseResult::Modbus),
        IcsProtocol::Dnp3 => {
            parse_dnp3(&packet.payload, packet.src_port, packet.dst_port).map(DeepParseResult::Dnp3)
        }
        IcsProtocol::EthernetIp => enip::parse(&packet.payload).map(DeepParseResult::Enip),
        IcsProtocol::S7comm => {
            // S7comm+ uses protocol ID 0x72; classic S7comm uses 0x32.
            // Try S7comm+ first; fall back to classic S7comm.
            s7comm_plus::parse(&packet.payload)
                .map(DeepParseResult::S7Plus)
                .or_else(|| s7comm::parse(&packet.payload).map(DeepParseResult::S7))
        }
        IcsProtocol::Bacnet => bacnet::parse(&packet.payload).map(DeepParseResult::Bacnet),
        IcsProtocol::Iec104 => iec104::parse(&packet.payload).map(DeepParseResult::Iec104),
        IcsProtocol::Profinet => {
            // Both parsers validate the Frame ID from bytes 0–1 of the payload.
            // IO RT parser accepts 0x8000–0xFBFF and alarm ranges; DCP parser
            // accepts only 0xFEFC–0xFEFF. Try IO RT first so cyclic/alarm frames
            // are never incorrectly absorbed by the DCP parser.
            profinet_io::parse(&packet.payload, packet.src_port, packet.dst_port)
                .map(DeepParseResult::ProfinetIo)
                .or_else(|| profinet_dcp::parse(&packet.payload).map(DeepParseResult::ProfinetDcp))
        }
        _ => None,
    }
}
