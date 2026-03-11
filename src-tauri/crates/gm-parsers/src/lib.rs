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
pub mod enip;
pub mod s7comm;
pub mod bacnet;
pub mod vendor_tables;
pub mod iec104;
pub mod profinet_dcp;
pub mod snmp;
pub mod lldp;
pub mod redundancy;

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
pub use enip::{parse as parse_enip, EnipInfo, EnipCommand, EnipIdentity, CipService, CipClass, EnipRole};
pub use s7comm::{parse as parse_s7, S7Info, CotpPduType, CotpParams, S7PduType, S7Function, S7Role, function_code_name as s7_function_code_name};
pub use bacnet::{parse as parse_bacnet, BacnetInfo, BvlcFunction, BacnetPduType, BacnetService, BacnetObjectType, BacnetIAm, BacnetRole};
pub use iec104::{parse as parse_iec104, Iec104Info, Iec104FrameType, Iec104Role, UFrameFunction, AsduTypeId, CauseOfTransmission};
pub use profinet_dcp::{parse as parse_profinet_dcp, ProfinetDcpInfo, DcpServiceId, DcpServiceType, DcpDeviceInfo, ProfinetRole};
pub use lldp::{parse as parse_lldp, LldpInfo, LldpMgmtAddress};
pub use snmp::{parse_snmp_community, SnmpInfo, parse_snmp_response, SnmpDeviceInfo};
pub use redundancy::{
    parse as parse_redundancy,
    detect_protocol as detect_redundancy_protocol,
    RedundancyProtocol, RedundancyInfo,
};

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
    /// BACnet/IP (BVLCI/NPDU/APDU) deep parse result
    Bacnet(BacnetInfo),
    /// IEC 60870-5-104 deep parse result
    Iec104(Iec104Info),
    /// PROFINET DCP deep parse result
    ProfinetDcp(ProfinetDcpInfo),
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
        IcsProtocol::Modbus => {
            parse_modbus(&packet.payload, packet.src_port, packet.dst_port)
                .map(DeepParseResult::Modbus)
        }
        IcsProtocol::Dnp3 => {
            parse_dnp3(&packet.payload, packet.src_port, packet.dst_port)
                .map(DeepParseResult::Dnp3)
        }
        IcsProtocol::EthernetIp => {
            enip::parse(&packet.payload).map(DeepParseResult::Enip)
        }
        IcsProtocol::S7comm => {
            s7comm::parse(&packet.payload).map(DeepParseResult::S7)
        }
        IcsProtocol::Bacnet => {
            bacnet::parse(&packet.payload).map(DeepParseResult::Bacnet)
        }
        IcsProtocol::Iec104 => {
            iec104::parse(&packet.payload).map(DeepParseResult::Iec104)
        }
        IcsProtocol::Profinet => {
            profinet_dcp::parse(&packet.payload).map(DeepParseResult::ProfinetDcp)
        }
        _ => None,
    }
}
