//! BACnet/IP (ASHRAE 135 Annex J) deep protocol parser.
//!
//! Parses BVLCI → NPDU → APDU protocol layers for BACnet over UDP.
//! Extracts device identity from I-Am broadcasts, classifies services,
//! and detects client/server roles.
//!
//! Reference: ASHRAE 135-2016, BACnet/IP (Annex J)
//! Port: 47808 UDP (0xBAC0)

use serde::{Deserialize, Serialize};

/// BVLCI (BACnet Virtual Link Control) function code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BvlcFunction {
    /// 0x00 — BVLC-Result
    BvlcResult,
    /// 0x04 — Forwarded-NPDU (via BBMD)
    ForwardedNpdu,
    /// 0x0A — Original-Unicast-NPDU
    OriginalUnicast,
    /// 0x0B — Original-Broadcast-NPDU
    OriginalBroadcast,
    /// Unknown function code
    Unknown(u8),
}

impl BvlcFunction {
    fn from_byte(b: u8) -> Self {
        match b {
            0x00 => BvlcFunction::BvlcResult,
            0x04 => BvlcFunction::ForwardedNpdu,
            0x0A => BvlcFunction::OriginalUnicast,
            0x0B => BvlcFunction::OriginalBroadcast,
            _ => BvlcFunction::Unknown(b),
        }
    }
}

/// BACnet APDU PDU type (high nibble of the first APDU byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BacnetPduType {
    /// 0x0 — Confirmed-Request (client request requiring a response)
    ConfirmedRequest,
    /// 0x1 — Unconfirmed-Request (no response expected)
    UnconfirmedRequest,
    /// 0x2 — SimpleAck (success, no data)
    SimpleAck,
    /// 0x3 — ComplexAck (success with data)
    ComplexAck,
    /// 0x5 — Error
    Error,
    /// 0x6 — Reject
    Reject,
    /// 0x7 — Abort
    Abort,
    /// Unknown PDU type
    Unknown(u8),
}

impl BacnetPduType {
    fn from_nibble(n: u8) -> Self {
        match n {
            0x0 => BacnetPduType::ConfirmedRequest,
            0x1 => BacnetPduType::UnconfirmedRequest,
            0x2 => BacnetPduType::SimpleAck,
            0x3 => BacnetPduType::ComplexAck,
            0x5 => BacnetPduType::Error,
            0x6 => BacnetPduType::Reject,
            0x7 => BacnetPduType::Abort,
            _ => BacnetPduType::Unknown(n),
        }
    }
}

/// BACnet service (confirmed or unconfirmed, unified).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BacnetService {
    // ── Confirmed services ───────────────────────────────────────────
    /// Read a single property (0x0C)
    ReadProperty,
    /// Read multiple properties (0x0E)
    ReadPropertyMultiple,
    /// Write a single property — ATT&CK T0855 (0x0F)
    WriteProperty,
    /// Write multiple properties (0x10)
    WritePropertyMultiple,
    /// Read a portion of a file (0x06)
    AtomicReadFile,
    /// Write a portion of a file (0x07)
    AtomicWriteFile,
    /// Subscribe to change-of-value (0x05)
    SubscribeCov,
    /// Reinitialize the device — ATT&CK T0816 (0x14)
    ReinitializeDevice,
    /// Disable/enable communications — ATT&CK T0811 (0x11)
    DeviceCommunicationControl,
    // ── Unconfirmed services ─────────────────────────────────────────
    /// Broadcast device identity in response to Who-Is (0x00)
    IAm,
    /// Broadcast object presence in response to Who-Has (0x01)
    IHave,
    /// Query for objects with a specific name or instance (0x07)
    WhoHas,
    /// Discover all devices on the network (0x08)
    WhoIs,
    /// Unknown service code
    Unknown(u8),
}

/// BACnet object type (upper 10 bits of Object Identifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BacnetObjectType {
    AnalogInput,
    AnalogOutput,
    AnalogValue,
    BinaryInput,
    BinaryOutput,
    BinaryValue,
    Device,
    File,
    NotificationClass,
    Schedule,
    TrendLog,
    Unknown(u16),
}

impl BacnetObjectType {
    fn from_code(code: u16) -> Self {
        match code {
            0 => BacnetObjectType::AnalogInput,
            1 => BacnetObjectType::AnalogOutput,
            2 => BacnetObjectType::AnalogValue,
            3 => BacnetObjectType::BinaryInput,
            4 => BacnetObjectType::BinaryOutput,
            5 => BacnetObjectType::BinaryValue,
            8 => BacnetObjectType::Device,
            10 => BacnetObjectType::File,
            15 => BacnetObjectType::NotificationClass,
            17 => BacnetObjectType::Schedule,
            20 => BacnetObjectType::TrendLog,
            _ => BacnetObjectType::Unknown(code),
        }
    }
}

/// Client/server role for a BACnet device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BacnetRole {
    /// Device is sending requests (BACnet client / workstation)
    Client,
    /// Device is responding or broadcasting (BACnet server / device)
    Server,
    /// Cannot determine role from this packet
    Unknown,
}

/// Device identity from an I-Am broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacnetIAm {
    /// BACnet device instance number (21-bit)
    pub device_instance: u32,
    /// Maximum APDU length this device supports
    pub max_apdu_length: u32,
    /// Segmentation supported flag
    pub segmentation_supported: u8,
    /// ASHRAE/vendor ID number
    pub vendor_id: u16,
}

/// Parsed BACnet/IP packet information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacnetInfo {
    /// BVLCI function code
    pub bvlc_function: BvlcFunction,
    /// NPDU version (always 1 for conforming devices)
    pub npdu_version: u8,
    /// True if this is a network-layer message (no APDU)
    pub is_network_message: bool,
    /// APDU PDU type
    pub pdu_type: Option<BacnetPduType>,
    /// Service being requested or responded to
    pub service: Option<BacnetService>,
    /// I-Am device identity (present only for I-Am broadcasts)
    pub iam: Option<BacnetIAm>,
    /// Object type from object identifier (if extractable)
    pub object_type: Option<BacnetObjectType>,
    /// Object instance number (if extractable)
    pub object_instance: Option<u32>,
    /// Property ID being accessed (if extractable)
    pub property_id: Option<u32>,
    /// Detected role
    pub role: BacnetRole,
}

/// Read a single BACnet tag from `data` at `offset`.
///
/// Returns `(tag_number, tag_class, value_bytes, next_offset)`:
/// - `tag_number` — upper 4 bits of tag byte
/// - `tag_class` — bit 3: `0`=application, `1`=context
/// - `value_bytes` — slice of the tag value
/// - `next_offset` — absolute offset just past this tag
///
/// Returns `None` if the data is too short.
fn read_tag(data: &[u8], offset: usize) -> Option<(u8, u8, &[u8], usize)> {
    let tag_byte = *data.get(offset)?;
    let tag_number = (tag_byte >> 4) & 0x0F;
    let tag_class = (tag_byte >> 3) & 0x01; // 0=application, 1=context
    let length_field = tag_byte & 0x07;

    let (value_len, value_start) = match length_field {
        // Extended length: next byte holds actual count
        5 => {
            let ext = *data.get(offset + 1)? as usize;
            (ext, offset + 2)
        }
        // Opening (6) or closing (7) tag: no value bytes
        6 | 7 => (0, offset + 1),
        // 0-4: literal length
        n => (n as usize, offset + 1),
    };

    let value = data.get(value_start..value_start + value_len)?;
    Some((tag_number, tag_class, value, value_start + value_len))
}

/// Read a big-endian unsigned integer from `bytes` (up to 4 bytes).
fn read_uint_be(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for &b in bytes.iter().take(4) {
        result = (result << 8) | u32::from(b);
    }
    result
}

/// Map a confirmed-service choice byte to `BacnetService`.
fn map_confirmed_service(b: u8) -> BacnetService {
    match b {
        0x05 => BacnetService::SubscribeCov,
        0x06 => BacnetService::AtomicReadFile,
        0x07 => BacnetService::AtomicWriteFile,
        0x0C => BacnetService::ReadProperty,
        0x0E => BacnetService::ReadPropertyMultiple,
        0x0F => BacnetService::WriteProperty,
        0x10 => BacnetService::WritePropertyMultiple,
        0x11 => BacnetService::DeviceCommunicationControl,
        0x14 => BacnetService::ReinitializeDevice,
        _ => BacnetService::Unknown(b),
    }
}

/// Map an unconfirmed-service choice byte to `BacnetService`.
fn map_unconfirmed_service(b: u8) -> BacnetService {
    match b {
        0x00 => BacnetService::IAm,
        0x01 => BacnetService::IHave,
        0x07 => BacnetService::WhoHas,
        0x08 => BacnetService::WhoIs,
        _ => BacnetService::Unknown(b),
    }
}

/// Parse I-Am tagged values starting at `offset` in `payload`.
///
/// I-Am encoding (all application-tagged, in order):
/// 1. Object Identifier (tag 12, 4 bytes) → device_instance + object_type
/// 2. Max APDU Length (tag 2, unsigned)
/// 3. Segmentation Supported (tag 9, enumerated, 1 byte)
/// 4. Vendor ID (tag 2, unsigned, 1 or 2 bytes)
///
/// Returns `(BacnetIAm, Option<BacnetObjectType>, Option<u32>)` or `None`
/// if any required tag is missing or malformed.
fn parse_iam(
    payload: &[u8],
    offset: usize,
) -> Option<(BacnetIAm, Option<BacnetObjectType>, Option<u32>)> {
    // 1. Object Identifier: application tag 12, 4 bytes
    let (tag_num, _, value, next) = read_tag(payload, offset)?;
    if tag_num != 12 || value.len() != 4 {
        return None;
    }
    let oid = read_uint_be(value);
    let obj_type_code = ((oid >> 22) & 0x3FF) as u16;
    let device_instance = oid & 0x3F_FFFF; // bits 21-0
    let object_type = Some(BacnetObjectType::from_code(obj_type_code));
    let offset = next;

    // 2. Max APDU Length: application tag 2, 2 bytes (unsigned16)
    let (tag_num, _, value, next) = read_tag(payload, offset)?;
    if tag_num != 2 {
        return None;
    }
    let max_apdu_length = read_uint_be(value);
    let offset = next;

    // 3. Segmentation Supported: application tag 9, 1 byte (enumerated)
    let (tag_num, _, value, next) = read_tag(payload, offset)?;
    if tag_num != 9 || value.is_empty() {
        return None;
    }
    let segmentation_supported = value[0];
    let offset = next;

    // 4. Vendor ID: application tag 2, 1 or 2 bytes (unsigned)
    let (tag_num, _, value, _) = read_tag(payload, offset)?;
    if tag_num != 2 || value.is_empty() {
        return None;
    }
    let vendor_id = read_uint_be(value) as u16;

    Some((
        BacnetIAm {
            device_instance,
            max_apdu_length,
            segmentation_supported,
            vendor_id,
        },
        object_type,
        Some(device_instance),
    ))
}

/// Extract object type, instance, and property ID from a ConfirmedRequest body.
///
/// Reads context tag 0 (Object Identifier, 4 bytes) and context tag 1 (Property ID).
/// Returns `(object_type, object_instance, property_id)`, each `None` if absent.
fn parse_confirmed_object_property(
    payload: &[u8],
    offset: usize,
) -> (Option<BacnetObjectType>, Option<u32>, Option<u32>) {
    let mut object_type = None;
    let mut object_instance = None;
    let mut property_id = None;

    // Context tag 0: Object Identifier (4 bytes)
    if let Some((tag_num, tag_class, value, next)) = read_tag(payload, offset) {
        if tag_class == 1 && tag_num == 0 && value.len() == 4 {
            let oid = read_uint_be(value);
            let type_code = ((oid >> 22) & 0x3FF) as u16;
            object_type = Some(BacnetObjectType::from_code(type_code));
            object_instance = Some(oid & 0x3F_FFFF);

            // Context tag 1: Property Identifier
            if let Some((tag_num2, tag_class2, value2, _)) = read_tag(payload, next) {
                if tag_class2 == 1 && tag_num2 == 1 && !value2.is_empty() {
                    property_id = Some(read_uint_be(value2));
                }
            }
        }
    }

    (object_type, object_instance, property_id)
}

/// Attempt to parse a BACnet/IP UDP payload (BVLCI + NPDU + APDU).
///
/// Returns `None` if the payload is too short (< 6 bytes) or the BVLCI
/// type byte is not `0x81`.
///
/// # Arguments
/// * `payload` - Raw UDP payload bytes (starting from BVLCI header)
pub fn parse(payload: &[u8]) -> Option<BacnetInfo> {
    // Minimum: BVLCI(4) + NPDU version(1) + NPDU control(1) = 6 bytes
    if payload.len() < 6 {
        return None;
    }

    // BVLCI type byte MUST be 0x81 (BACnet/IP)
    if payload[0] != 0x81 {
        return None;
    }

    let bvlc_function = BvlcFunction::from_byte(payload[1]);
    // payload[2..4] = total length (informational, not validated here)

    // NPDU starts at offset 4 (immediately after the 4-byte BVLCI header)
    let npdu_start = 4;
    let npdu_version = payload[npdu_start];
    let npdu_control = payload[npdu_start + 1];

    let is_network_message = (npdu_control & 0x80) != 0;
    let has_dst = (npdu_control & 0x20) != 0; // DNET/DADR/Hop present
    let has_src = (npdu_control & 0x08) != 0; // SNET/SADR present

    // Walk NPDU optional fields to find where APDU begins.
    // Start after version(1) + control(1) = offset 2 within NPDU.
    let mut npdu_offset: usize = 2;

    if has_dst {
        // DNET (2 bytes) + DLEN (1 byte) + DADR (DLEN bytes)
        let dlen_pos = npdu_start + npdu_offset + 2; // +2 to skip DNET
        let dlen = *payload.get(dlen_pos)? as usize;
        npdu_offset += 2 + 1 + dlen; // DNET + DLEN + DADR
    }

    if has_src {
        // SNET (2 bytes) + SLEN (1 byte) + SADR (SLEN bytes)
        let slen_pos = npdu_start + npdu_offset + 2; // +2 to skip SNET
        let slen = *payload.get(slen_pos)? as usize;
        npdu_offset += 2 + 1 + slen; // SNET + SLEN + SADR
    }

    if has_dst {
        npdu_offset += 1; // Hop Count (present when DNET is present, always last)
    }

    let apdu_start = npdu_start + npdu_offset;

    // Network-layer messages have no APDU
    if is_network_message {
        return Some(BacnetInfo {
            bvlc_function,
            npdu_version,
            is_network_message: true,
            pdu_type: None,
            service: None,
            iam: None,
            object_type: None,
            object_instance: None,
            property_id: None,
            role: BacnetRole::Unknown,
        });
    }

    // Parse APDU — first byte encodes PDU type in the high nibble
    let apdu_first = *payload.get(apdu_start)?;
    let pdu_type = BacnetPduType::from_nibble((apdu_first >> 4) & 0x0F);

    let (service, iam, object_type, object_instance, property_id, role) = match pdu_type {
        BacnetPduType::UnconfirmedRequest => {
            // [apdu_start+0]: PDU type nibble + flags
            // [apdu_start+1]: service choice
            let service_byte = *payload.get(apdu_start + 1)?;
            let svc = map_unconfirmed_service(service_byte);

            // Parse I-Am device identity
            let (iam_data, obj_type, obj_inst) = if matches!(svc, BacnetService::IAm) {
                match parse_iam(payload, apdu_start + 2) {
                    Some((i, ot, oi)) => (Some(i), ot, oi),
                    None => (None, None, None),
                }
            } else {
                (None, None, None)
            };

            // Role: I-Am/I-Have come from devices (servers); Who-Is/Who-Has from clients
            let role = match svc {
                BacnetService::IAm | BacnetService::IHave => BacnetRole::Server,
                BacnetService::WhoIs | BacnetService::WhoHas => BacnetRole::Client,
                _ => BacnetRole::Unknown,
            };

            (Some(svc), iam_data, obj_type, obj_inst, None, role)
        }

        BacnetPduType::ConfirmedRequest => {
            // [apdu_start+0]: PDU type nibble + seg/more-follows flags
            // [apdu_start+1]: max-segments / max-APDU encoding
            // [apdu_start+2]: invoke-id
            // [apdu_start+3]: service choice
            let service_byte = *payload.get(apdu_start + 3)?;
            let svc = map_confirmed_service(service_byte);

            // Extract object/property for Read/WriteProperty requests
            let (obj_type, obj_inst, prop_id) = if matches!(
                svc,
                BacnetService::ReadProperty | BacnetService::WriteProperty
            ) {
                parse_confirmed_object_property(payload, apdu_start + 4)
            } else {
                (None, None, None)
            };

            (
                Some(svc),
                None,
                obj_type,
                obj_inst,
                prop_id,
                BacnetRole::Client,
            )
        }

        // Responses (Ack, Error, Reject, Abort) originate from the server
        BacnetPduType::SimpleAck
        | BacnetPduType::ComplexAck
        | BacnetPduType::Error
        | BacnetPduType::Reject
        | BacnetPduType::Abort => (None, None, None, None, None, BacnetRole::Server),

        _ => (None, None, None, None, None, BacnetRole::Unknown),
    };

    Some(BacnetInfo {
        bvlc_function,
        npdu_version,
        is_network_message: false,
        pdu_type: Some(pdu_type),
        service,
        iam,
        object_type,
        object_instance,
        property_id,
        role,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_who_is() {
        // Who-Is broadcast — from docs/PROTOCOL-DEEP-PARSE.md
        // Routing: broadcast DNET=0xFFFF, DLEN=0, Hop=255
        let payload: Vec<u8> = vec![
            0x81, 0x0B, 0x00, 0x0C, // BVLCI: BACnet, OriginalBroadcast, total=12
            0x01, 0x20, // NPDU: version=1, control=0x20 (has_dst)
            0xFF, 0xFF, // DNET = 65535 (global broadcast)
            0x00, // DLEN = 0 (no DADR)
            0xFF, // Hop Count = 255
            0x10, // APDU: UnconfirmedRequest (type=1, flags=0)
            0x08, // Service: WhoIs
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(
            info.bvlc_function,
            BvlcFunction::OriginalBroadcast
        ));
        assert!(!info.is_network_message);
        assert!(matches!(
            info.pdu_type,
            Some(BacnetPduType::UnconfirmedRequest)
        ));
        assert!(matches!(info.service, Some(BacnetService::WhoIs)));
        assert!(matches!(info.role, BacnetRole::Client));
        assert!(info.iam.is_none());
    }

    #[test]
    fn test_i_am() {
        // I-Am broadcast — from docs/PROTOCOL-DEEP-PARSE.md
        // Device #1001, Max APDU=480, Segmentation=0, Vendor=3
        let payload: Vec<u8> = vec![
            0x81, 0x0B, 0x00, 0x19, // BVLCI: BACnet, OriginalBroadcast
            0x01, 0x20, // NPDU: version=1, control=0x20 (has_dst)
            0xFF, 0xFF, // DNET
            0x00, // DLEN = 0
            0xFF, // Hop Count
            0x10, // APDU: UnconfirmedRequest
            0x00, // Service: IAm
            // I-Am data:
            0xC4, // App tag 12 (Object Identifier), length=4
            0x02, 0x00, 0x03, 0xE9, // Object ID: Device(8), instance=1001
            0x22, // App tag 2 (Unsigned16), length=2
            0x01, 0xE0, // Max APDU Length = 480
            0x91, // App tag 9 (Enumerated), length=1
            0x00, // Segmentation supported = 0
            0x21, // App tag 2 (Unsigned8), length=1
            0x03, // Vendor ID = 3
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(
            info.pdu_type,
            Some(BacnetPduType::UnconfirmedRequest)
        ));
        assert!(matches!(info.service, Some(BacnetService::IAm)));
        assert!(matches!(info.role, BacnetRole::Server));

        let iam = info.iam.unwrap();
        assert_eq!(iam.device_instance, 1001);
        assert_eq!(iam.max_apdu_length, 480);
        assert_eq!(iam.segmentation_supported, 0);
        assert_eq!(iam.vendor_id, 3);

        assert!(matches!(info.object_type, Some(BacnetObjectType::Device)));
        assert_eq!(info.object_instance, Some(1001));
    }

    #[test]
    fn test_read_property() {
        // Confirmed ReadProperty — unicast, no routing
        // Target: Device(8) instance 1001, Property: Present-Value (85)
        let payload: Vec<u8> = vec![
            0x81, 0x0A, 0x00, 0x11, // BVLCI: OriginalUnicast, total=17
            0x01, 0x04, // NPDU: version=1, control=0x04 (expect reply)
            // APDU ConfirmedRequest:
            0x00, // PDU type=0 (ConfirmedRequest), no seg
            0x04, // max-segs=0, max-APDU size=1024
            0x01, // invoke_id = 1
            0x0C, // Service: ReadProperty
            // Context tag 0: Object Identifier (4 bytes)
            0x0C, 0x02, 0x00, 0x03, 0xE9, // Device(8), instance=1001
            // Context tag 1: Property Identifier (1 byte)
            0x19, 0x55, // Property 85 = Present-Value
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(
            info.pdu_type,
            Some(BacnetPduType::ConfirmedRequest)
        ));
        assert!(matches!(info.service, Some(BacnetService::ReadProperty)));
        assert!(matches!(info.role, BacnetRole::Client));
        assert!(matches!(info.object_type, Some(BacnetObjectType::Device)));
        assert_eq!(info.object_instance, Some(1001));
        assert_eq!(info.property_id, Some(85));
    }

    #[test]
    fn test_write_property() {
        // Confirmed WriteProperty — unicast, no routing (ATT&CK T0855)
        // Target: AnalogValue(2) instance 1, Property: Present-Value (85)
        let payload: Vec<u8> = vec![
            0x81, 0x0A, 0x00, 0x11, // BVLCI: OriginalUnicast, total=17
            0x01, 0x04, // NPDU: version=1, control=0x04 (expect reply)
            // APDU ConfirmedRequest:
            0x00, // PDU type=0, no seg
            0x04, // max-segs/max-APDU
            0x02, // invoke_id = 2
            0x0F, // Service: WriteProperty
            // Context tag 0: Object Identifier (4 bytes)
            // AnalogValue(2): (2 << 22) | 1 = 0x00800001
            0x0C, 0x00, 0x80, 0x00, 0x01, // AnalogValue(2), instance=1
            // Context tag 1: Property Identifier (1 byte)
            0x19, 0x55, // Property 85 = Present-Value
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(info.service, Some(BacnetService::WriteProperty)));
        assert!(matches!(info.role, BacnetRole::Client));
        assert!(matches!(
            info.object_type,
            Some(BacnetObjectType::AnalogValue)
        ));
        assert_eq!(info.object_instance, Some(1));
        assert_eq!(info.property_id, Some(85));
    }

    #[test]
    fn test_reinitialize_device() {
        // Confirmed ReinitializeDevice — ATT&CK T0816
        let payload: Vec<u8> = vec![
            0x81, 0x0A, 0x00, 0x0C, // BVLCI: OriginalUnicast, total=12
            0x01, 0x04, // NPDU: unicast, expect reply
            // APDU ConfirmedRequest:
            0x00, // PDU type=0, no seg
            0x04, // max-segs/max-APDU
            0x03, // invoke_id = 3
            0x14, // Service: ReinitializeDevice (0x14)
            // Parameters (reinitialized-state-of-device):
            0x09, 0x00, // Context tag 0: cold-start
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(
            info.pdu_type,
            Some(BacnetPduType::ConfirmedRequest)
        ));
        assert!(matches!(
            info.service,
            Some(BacnetService::ReinitializeDevice)
        ));
        assert!(matches!(info.role, BacnetRole::Client));
    }

    #[test]
    fn test_device_communication_control() {
        // Confirmed DeviceCommunicationControl — ATT&CK T0811
        let payload: Vec<u8> = vec![
            0x81, 0x0A, 0x00, 0x0A, // BVLCI: OriginalUnicast, total=10
            0x01, 0x04, // NPDU: unicast, expect reply
            0x00, // ConfirmedRequest, no seg
            0x04, // max-segs/max-APDU
            0x04, // invoke_id = 4
            0x11, // Service: DeviceCommunicationControl
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(
            info.service,
            Some(BacnetService::DeviceCommunicationControl)
        ));
        assert!(matches!(info.role, BacnetRole::Client));
    }

    #[test]
    fn test_truncated() {
        // Too short to parse
        let payload: Vec<u8> = vec![0x81, 0x0B, 0x00];
        assert!(parse(&payload).is_none());
    }

    #[test]
    fn test_invalid_bvlci() {
        // First byte is not 0x81
        let payload: Vec<u8> = vec![
            0x82, 0x0B, 0x00, 0x0C, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08,
        ];
        assert!(parse(&payload).is_none());
    }
}
