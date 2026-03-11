//! EtherNet/IP (ENIP) + CIP deep protocol parser.
//!
//! Parses EtherNet/IP encapsulation headers and Common Industrial Protocol (CIP)
//! messages. Extracts device identity from ListIdentity responses and classifies
//! CIP services by type, target class, and instance.
//!
//! Reference: ODVA EtherNet/IP Specification, CIP Vol. 2
//!
//! Encapsulation Header (24 bytes, ALL LITTLE-ENDIAN):
//! [Command: 2][Length: 2][Session Handle: 4][Status: 4][Sender Context: 8][Options: 4]
//!
//! ## Ports
//! - 44818 TCP/UDP — explicit messaging (command/response)
//! - 2222  UDP     — implicit I/O (cyclic data)

use serde::{Deserialize, Serialize};

/// Minimum EtherNet/IP encapsulation header size (always 24 bytes).
const ENIP_HEADER_SIZE: usize = 24;

// ─── Enums ────────────────────────────────────────────────────────────────────

/// EtherNet/IP encapsulation command codes (16-bit, little-endian).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnipCommand {
    /// No operation (0x0000)
    Nop,
    /// Query available services (0x0004)
    ListServices,
    /// Query device identity — broadcast discoverable (0x0063)
    ListIdentity,
    /// List available network interfaces (0x0064)
    ListInterfaces,
    /// Open a TCP session (0x0065)
    RegisterSession,
    /// Close a TCP session (0x0066)
    UnregisterSession,
    /// Send request + await response, unconnected (0x006F)
    SendRRData,
    /// Send connected I/O data (0x0070)
    SendUnitData,
    /// Unrecognised command
    Unknown(u16),
}

/// CIP service codes extracted from the CIP message router request/response.
///
/// Bit 7 of the wire byte distinguishes response (set) from request (clear).
/// The actual service is always `raw_byte & 0x7F`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipService {
    /// Get all attributes of an object (0x01)
    GetAttributeAll,
    /// Get a single attribute (0x0E)
    GetAttributeSingle,
    /// Set a single attribute (0x10) — may trigger T0855
    SetAttributeSingle,
    /// Reset an object to default state (0x05) — may trigger T0816
    Reset,
    /// ControlLogix tag read (0x4C)
    Read,
    /// ControlLogix tag write (0x4D) — triggers T0855
    Write,
    /// Read-modify-write tag (0x4E)
    ReadModifyWrite,
    /// Send request without a pre-established connection (0x52)
    UnconnectedSend,
    /// Open a CIP I/O connection — Scanner behaviour (0x54)
    ForwardOpen,
    /// Close a CIP I/O connection (0x55)
    ForwardClose,
    /// Unrecognised service
    Unknown(u8),
}

/// CIP object class IDs from EPATH class segments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CipClass {
    /// Identity object (0x01) — vendor, device type, serial, product name
    Identity,
    /// Message Router (0x02)
    MessageRouter,
    /// Assembly object (0x04) — I/O data
    Assembly,
    /// Connection object (0x05)
    Connection,
    /// Connection Manager (0x06)
    ConnectionManager,
    /// File object (0x37)
    File,
    /// TCP/IP Interface object (0xF5)
    TcpIp,
    /// Ethernet Link object (0xF6)
    EthernetLink,
    /// Unrecognised class
    Unknown(u16),
}

/// EtherNet/IP device role inferred from packet direction and CIP service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnipRole {
    /// Scanner: initiates connections, sends ForwardOpen / Write requests
    /// (typically a PLC, HMI, or SCADA system)
    Scanner,
    /// Adapter: responds to requests, exposes I/O data
    /// (typically a drive, sensor, or remote I/O block)
    Adapter,
    /// Role cannot be determined from this packet alone
    Unknown,
}

// ─── Structs ──────────────────────────────────────────────────────────────────

/// Device identity extracted from a ListIdentity CPF response.
///
/// Populated when an EtherNet/IP adapter responds to a broadcast ListIdentity
/// query. Provides vendor, product, firmware, and serial number fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnipIdentity {
    /// ODVA Vendor ID (see `cip_vendor_name()`)
    pub vendor_id: u16,
    /// CIP Device Type code (e.g., 0x000E = PLC/SLC-5xx, 0x000C = Comms Adapter)
    pub device_type: u16,
    /// Vendor-assigned product code
    pub product_code: u16,
    /// Major firmware revision number
    pub major_revision: u8,
    /// Minor firmware revision number
    pub minor_revision: u8,
    /// Unique 32-bit device serial number
    pub serial_number: u32,
    /// Human-readable product name string
    pub product_name: String,
    /// Device status word (bit-encoded)
    pub status: u16,
    /// Device state (0=exists, 3=operational, 5=major fault)
    pub state: u8,
}

/// Parsed EtherNet/IP + CIP packet.
///
/// Produced by [`parse()`] for every payload identified as EtherNet/IP.
/// Contains the encapsulation-layer fields plus any CIP message details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnipInfo {
    /// Encapsulation command code
    pub command: EnipCommand,
    /// Session handle (0 for broadcasts; non-zero for established TCP sessions)
    pub session_handle: u32,
    /// Encapsulation status (0 = success)
    pub status: u32,
    /// Device identity populated from ListIdentity responses
    pub identity: Option<EnipIdentity>,
    /// CIP service code from the embedded CIP message
    pub cip_service: Option<CipService>,
    /// CIP object class targeted by the embedded CIP message
    pub cip_class: Option<CipClass>,
    /// CIP object instance
    pub cip_instance: Option<u32>,
    /// CIP attribute (if a single-attribute operation)
    pub cip_attribute: Option<u16>,
    /// True when bit 7 of the CIP service byte is set (response direction)
    pub is_response: bool,
    /// True when the CIP response general-status byte is non-zero (error)
    pub cip_error: bool,
    /// Inferred Scanner / Adapter role for the sending device
    pub role: EnipRole,
}

// ─── Private parse-result ─────────────────────────────────────────────────────

/// Internal result from CIP message parsing (not exposed publicly).
struct CipResult {
    service: CipService,
    class: Option<CipClass>,
    instance: Option<u32>,
    attribute: Option<u16>,
    is_response: bool,
    is_error: bool,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Read a `u16` from `data` at `offset` using little-endian byte order.
///
/// Returns `None` if fewer than 2 bytes remain starting at `offset`.
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Read a `u32` from `data` at `offset` using little-endian byte order.
///
/// Returns `None` if fewer than 4 bytes remain starting at `offset`.
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

// ─── Mapping functions ────────────────────────────────────────────────────────

fn map_command(code: u16) -> EnipCommand {
    match code {
        0x0000 => EnipCommand::Nop,
        0x0004 => EnipCommand::ListServices,
        0x0063 => EnipCommand::ListIdentity,
        0x0064 => EnipCommand::ListInterfaces,
        0x0065 => EnipCommand::RegisterSession,
        0x0066 => EnipCommand::UnregisterSession,
        0x006F => EnipCommand::SendRRData,
        0x0070 => EnipCommand::SendUnitData,
        other => EnipCommand::Unknown(other),
    }
}

fn map_service(code: u8) -> CipService {
    match code {
        0x01 => CipService::GetAttributeAll,
        0x05 => CipService::Reset,
        0x0E => CipService::GetAttributeSingle,
        0x10 => CipService::SetAttributeSingle,
        0x4C => CipService::Read,
        0x4D => CipService::Write,
        0x4E => CipService::ReadModifyWrite,
        0x52 => CipService::UnconnectedSend,
        0x54 => CipService::ForwardOpen,
        0x55 => CipService::ForwardClose,
        other => CipService::Unknown(other),
    }
}

fn map_class(code: u16) -> CipClass {
    match code {
        0x01 => CipClass::Identity,
        0x02 => CipClass::MessageRouter,
        0x04 => CipClass::Assembly,
        0x05 => CipClass::Connection,
        0x06 => CipClass::ConnectionManager,
        0x37 => CipClass::File,
        0xF5 => CipClass::TcpIp,
        0xF6 => CipClass::EthernetLink,
        other => CipClass::Unknown(other),
    }
}

// ─── EPATH parser ─────────────────────────────────────────────────────────────

/// Parse EPATH (encoded path) segments and extract class, instance, attribute.
///
/// EPATH uses a compact TLV-like encoding where the segment type byte determines
/// the number of bytes that follow:
///   - `0x20 cc`         — 8-bit class ID
///   - `0x21 00 lo hi`   — 16-bit class ID (padded to word boundary)
///   - `0x24 ii`         — 8-bit instance ID
///   - `0x25 00 lo hi`   — 16-bit instance ID
///   - `0x30 aa`         — 8-bit attribute ID
///   - `0x31 00 lo hi`   — 16-bit attribute ID
fn parse_epath(path: &[u8]) -> (Option<CipClass>, Option<u32>, Option<u16>) {
    let mut class: Option<CipClass> = None;
    let mut instance: Option<u32> = None;
    let mut attribute: Option<u16> = None;
    let mut i = 0usize;

    while i < path.len() {
        let segment = match path.get(i) {
            Some(&b) => b,
            None => break,
        };
        i += 1;

        match segment {
            0x20 => {
                // 8-bit class segment: [0x20][class_u8]
                if let Some(&class_id) = path.get(i) {
                    class = Some(map_class(class_id as u16));
                    i += 1;
                }
            }
            0x21 => {
                // 16-bit class segment: [0x21][pad=0x00][lo][hi]
                i += 1; // skip pad byte
                if let Some(class_id) = read_u16_le(path, i) {
                    class = Some(map_class(class_id));
                    i += 2;
                }
            }
            0x24 => {
                // 8-bit instance segment: [0x24][inst_u8]
                if let Some(&inst_id) = path.get(i) {
                    instance = Some(inst_id as u32);
                    i += 1;
                }
            }
            0x25 => {
                // 16-bit instance segment: [0x25][pad=0x00][lo][hi]
                i += 1; // skip pad byte
                if let Some(inst_id) = read_u16_le(path, i) {
                    instance = Some(inst_id as u32);
                    i += 2;
                }
            }
            0x30 => {
                // 8-bit attribute segment: [0x30][attr_u8]
                if let Some(&attr_id) = path.get(i) {
                    attribute = Some(attr_id as u16);
                    i += 1;
                }
            }
            0x31 => {
                // 16-bit attribute segment: [0x31][pad=0x00][lo][hi]
                i += 1; // skip pad byte
                if let Some(attr_id) = read_u16_le(path, i) {
                    attribute = Some(attr_id);
                    i += 2;
                }
            }
            _ => {
                // Unknown segment type — cannot safely advance, stop parsing.
                // Do not panic; just return whatever we extracted so far.
                break;
            }
        }
    }

    (class, instance, attribute)
}

// ─── CIP message parser ───────────────────────────────────────────────────────

/// Parse a raw CIP message byte slice.
///
/// Request layout:  `[service][path_size_words][epath...][data...]`
/// Response layout: `[service|0x80][reserved=0x00][general_status][additional_status_size][data...]`
fn parse_cip(cip_data: &[u8]) -> Option<CipResult> {
    if cip_data.is_empty() {
        return None;
    }

    let raw_service = cip_data.first().copied()?;
    let is_response = (raw_service & 0x80) != 0;
    let service_code = raw_service & 0x7F;
    let service = map_service(service_code);

    // General status byte is at offset 2 in a response.
    // Non-zero means an error occurred.
    let is_error = if is_response {
        cip_data.get(2).copied().unwrap_or(0) != 0
    } else {
        false
    };

    // EPATH is only present in request messages (requests carry the target path).
    let (class, instance, attribute) = if !is_response {
        // byte[1] = path size in 16-bit words; path data starts at byte[2]
        let path_size_words = cip_data.get(1).copied().unwrap_or(0) as usize;
        let path_bytes = path_size_words * 2;
        let path_end = (2 + path_bytes).min(cip_data.len());
        // get(2..path_end) returns None if path_end < 2; unwrap_or gives empty slice
        let path = cip_data.get(2..path_end).unwrap_or(&[]);
        parse_epath(path)
    } else {
        (None, None, None)
    };

    Some(CipResult {
        service,
        class,
        instance,
        attribute,
        is_response,
        is_error,
    })
}

// ─── ListIdentity response parser ─────────────────────────────────────────────

/// Parse CPF items from the data section of a ListIdentity response.
///
/// Searches for a CIP Identity item (type `0x000C`) and extracts the device
/// identity fields. Returns `None` if no identity item is found or the data
/// is too short to parse.
///
/// `data` is the payload after the 24-byte encapsulation header.
fn parse_list_identity(data: &[u8]) -> Option<EnipIdentity> {
    // First 2 bytes are item count — used as a minimum length guard
    let _item_count = read_u16_le(data, 0)?;
    let mut offset = 2usize;

    // Walk the CPF item list until we find type 0x000C (CIP Identity)
    while offset + 4 <= data.len() {
        let item_type = read_u16_le(data, offset)?;
        let item_length = read_u16_le(data, offset + 2)? as usize;
        let item_data_start = offset + 4;

        if item_type == 0x000C {
            // CIP Identity item found.
            //
            // Identity item data layout (offsets relative to item_data_start):
            //   [0..1]   u16 LE  Encap Protocol Version
            //   [2..3]   u16 LE  Socket Address Family (AF_INET = 2)
            //   [4..5]   u16 BE  Socket Port (not used)
            //   [6..9]   u32 BE  Socket IP Address (not used)
            //   [10..17] [u8;8]  Socket Zeros
            //   [18..19] u16 LE  Vendor ID          ← key field
            //   [20..21] u16 LE  Device Type        ← key field
            //   [22..23] u16 LE  Product Code       ← key field
            //   [24]     u8      Major Revision     ← firmware
            //   [25]     u8      Minor Revision     ← firmware
            //   [26..27] u16 LE  Status
            //   [28..31] u32 LE  Serial Number      ← unique ID
            //   [32]     u8      Product Name Length
            //   [33..n]  String  Product Name       ← key field
            //   [n+1]    u8      State

            // Use an unbounded slice from item_data_start so truncated packets
            // (where item_length in the header may exceed actual remaining bytes)
            // are still handled gracefully.
            let item_data = data.get(item_data_start..)?;

            // 33 bytes minimum: 18 (socket) + 14 (fixed identity fields) + 1 (name_len)
            if item_data.len() < 33 {
                return None;
            }

            let vendor_id = read_u16_le(item_data, 18)?;
            let device_type = read_u16_le(item_data, 20)?;
            let product_code = read_u16_le(item_data, 22)?;
            let major_revision = item_data.get(24).copied()?;
            let minor_revision = item_data.get(25).copied()?;
            let status = read_u16_le(item_data, 26)?;
            let serial_number = read_u32_le(item_data, 28)?;

            // Product name: length-prefixed string, may contain a trailing NUL
            let name_len = item_data.get(32).copied()? as usize;
            let name_end = (33 + name_len).min(item_data.len());
            let name_bytes = &item_data[33..name_end];
            let product_name = String::from_utf8_lossy(name_bytes)
                .trim_end_matches('\0')
                .to_string();

            // State byte follows the product name (best-effort; 0 if missing)
            let state = item_data.get(33 + name_len).copied().unwrap_or(0);

            return Some(EnipIdentity {
                vendor_id,
                device_type,
                product_code,
                major_revision,
                minor_revision,
                serial_number,
                product_name,
                status,
                state,
            });
        }

        // Not the item we need — advance past this item's data.
        let next = match item_data_start.checked_add(item_length) {
            Some(n) => n,
            None => break,
        };
        if next >= data.len() {
            break;
        }
        offset = next;
    }

    None
}

// ─── SendRRData / SendUnitData parser ─────────────────────────────────────────

/// Parse a CIP message from the data section of SendRRData or SendUnitData.
///
/// Skips the interface-handle (4 bytes) and timeout (2 bytes) fields, then
/// iterates CPF items looking for a data item of type `0x00B2` (Unconnected
/// Data) or `0x00B1` (Connected Data) and calls [`parse_cip()`] on its payload.
///
/// `data` is the payload after the 24-byte encapsulation header.
fn parse_send_data(data: &[u8]) -> Option<CipResult> {
    // Layout: [interface_handle: 4][timeout: 2][item_count: 2][items...]
    let item_count = read_u16_le(data, 6)? as usize;
    let mut offset = 8usize;

    for _ in 0..item_count {
        let item_type = read_u16_le(data, offset)?;
        let item_length = read_u16_le(data, offset + 2)? as usize;
        let item_data_start = offset + 4;

        match item_type {
            // Unconnected Data (0x00B2) or Connected Data (0x00B1) — CIP payload
            0x00B2 | 0x00B1 => {
                let cip_data = data.get(item_data_start..item_data_start + item_length)?;
                return parse_cip(cip_data);
            }
            // Skip: Null Address (0x0000), Connected Address (0x00A1), etc.
            _ => {
                let next = item_data_start.checked_add(item_length)?;
                if next > data.len() {
                    return None;
                }
                offset = next;
            }
        }
    }

    None
}

// ─── Main entry point ─────────────────────────────────────────────────────────

/// Parse an EtherNet/IP encapsulated payload.
///
/// Returns `None` if:
/// - The payload is shorter than the 24-byte encapsulation header
/// - The header fields cannot be read (truncated packet)
///
/// All other conditions (unknown commands, empty CIP data, truncated CIP
/// messages) produce a valid `EnipInfo` with the missing fields left as `None`.
///
/// # Arguments
/// * `payload` - Raw TCP or UDP application-layer bytes
pub fn parse(payload: &[u8]) -> Option<EnipInfo> {
    if payload.len() < ENIP_HEADER_SIZE {
        return None;
    }

    let command_code = read_u16_le(payload, 0)?;
    let length = read_u16_le(payload, 2)? as usize;
    let session_handle = read_u32_le(payload, 4)?;
    let status = read_u32_le(payload, 8)?;
    // bytes[12..20]: sender context (8 bytes, not used)
    // bytes[20..24]: options (4 bytes, not used)

    let command = map_command(command_code);

    // Data section follows the fixed 24-byte header
    let data = payload.get(ENIP_HEADER_SIZE..).unwrap_or(&[]);

    let mut identity: Option<EnipIdentity> = None;
    let mut cip_result: Option<CipResult> = None;

    match &command {
        EnipCommand::ListIdentity => {
            // Non-zero length field means this is a response carrying identity data.
            // Zero length is a broadcast request (no data to parse).
            if length > 0 {
                identity = parse_list_identity(data);
            }
        }
        EnipCommand::SendRRData | EnipCommand::SendUnitData => {
            cip_result = parse_send_data(data);
        }
        _ => {}
    }

    // Infer the device role from the command and CIP message direction/service.
    let role = match &command {
        EnipCommand::ListIdentity => {
            // Device that responded to a ListIdentity query is an Adapter.
            // Device that sent the query (length == 0) cannot be determined.
            if identity.is_some() {
                EnipRole::Adapter
            } else {
                EnipRole::Unknown
            }
        }
        // A device that initiates a TCP session is a Scanner.
        EnipCommand::RegisterSession => EnipRole::Scanner,
        EnipCommand::SendRRData | EnipCommand::SendUnitData => match cip_result.as_ref() {
            Some(cip) if cip.is_response => EnipRole::Adapter,
            Some(cip) => match &cip.service {
                // ForwardOpen opens a connection — Scanner behaviour.
                // Write sends data to an adapter — Scanner behaviour.
                CipService::ForwardOpen | CipService::Write => EnipRole::Scanner,
                _ => EnipRole::Unknown,
            },
            None => EnipRole::Unknown,
        },
        _ => EnipRole::Unknown,
    };

    // Extract CIP fields, cloning where necessary since cip_result is consumed below.
    let is_response = cip_result.as_ref().map(|r| r.is_response).unwrap_or(false);
    let cip_error = cip_result.as_ref().map(|r| r.is_error).unwrap_or(false);
    let cip_service = cip_result.as_ref().map(|r| r.service.clone());
    let cip_class = cip_result.as_ref().and_then(|r| r.class.clone());
    let cip_instance = cip_result.as_ref().and_then(|r| r.instance);
    let cip_attribute = cip_result.as_ref().and_then(|r| r.attribute);

    Some(EnipInfo {
        command,
        session_handle,
        status,
        identity,
        cip_service,
        cip_class,
        cip_instance,
        cip_attribute,
        is_response,
        cip_error,
        role,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A ListIdentity request is a 24-byte header with command 0x0063 and
    /// length 0 (no data section). The parser should recognise the command
    /// but return no identity, since there is nothing to parse.
    #[test]
    fn test_parse_list_identity_request() {
        let data: &[u8] = &[
            0x63, 0x00, // Command: ListIdentity (0x0063)
            0x00, 0x00, // Length: 0 (request — no data follows)
            0x00, 0x00, 0x00, 0x00, // Session Handle: 0
            0x00, 0x00, 0x00, 0x00, // Status: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender Context
            0x00, 0x00, 0x00, 0x00, // Options
        ];

        let result = parse(data).expect("24-byte header should parse");
        assert!(
            matches!(result.command, EnipCommand::ListIdentity),
            "command should be ListIdentity"
        );
        assert!(
            result.identity.is_none(),
            "request carries no identity data"
        );
        assert_eq!(result.session_handle, 0);
        assert_eq!(result.status, 0);
    }

    /// A ListIdentity response from a Rockwell Automation 1756-L71 ControlLogix
    /// PLC. The packet is taken directly from docs/PROTOCOL-DEEP-PARSE.md.
    ///
    /// Expected identity fields:
    /// - vendor_id  = 1  (Rockwell Automation/Allen-Bradley)
    /// - device_type = 14 (0x0E)
    /// - product_code = 54 (0x36)
    /// - major_revision = 20 (0x14), minor_revision = 3
    /// - serial_number = 0x12345678
    /// - product_name = "1756-L71/B V20"
    /// - state = 3 (operational)
    #[test]
    fn test_parse_list_identity_response() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            // Encapsulation header (24 bytes)
            0x63, 0x00,                                     // Command: ListIdentity
            0x3B, 0x00,                                     // Length: 59
            0x00, 0x00, 0x00, 0x00,                         // Session Handle: 0
            0x00, 0x00, 0x00, 0x00,                         // Status: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// Sender Context
            0x00, 0x00, 0x00, 0x00,                         // Options
            // CPF
            0x01, 0x00,                                     // Item Count: 1
            0x0C, 0x00,                                     // Item Type: 0x000C (CIP Identity)
            0x33, 0x00,                                     // Item Length: 51
            // Identity item data
            0x01, 0x00,                                     // Encap Protocol Version: 1
            0x00, 0x02,                                     // Socket Family: 2 (AF_INET)
            0xAF, 0x12,                                     // Socket Port: 44818
            0xC0, 0xA8, 0x01, 0x0A,                         // Socket IP: 192.168.1.10
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// Socket Zeros
            0x01, 0x00,                                     // Vendor ID: 1
            0x0E, 0x00,                                     // Device Type: 14
            0x36, 0x00,                                     // Product Code: 54
            0x14,                                           // Major Revision: 20
            0x03,                                           // Minor Revision: 3
            0x00, 0x00,                                     // Status: 0
            0x78, 0x56, 0x34, 0x12,                         // Serial Number: 0x12345678
            0x0F,                                           // Product Name Length: 15
            b'1', b'7', b'5', b'6', b'-', b'L', b'7', b'1', b'/',
            b'B', b' ', b'V', b'2', b'0', 0x00,             // "1756-L71/B V20\0"
            0x03,                                           // State: 3
        ];

        let result = parse(data).expect("response should parse");
        assert!(matches!(result.command, EnipCommand::ListIdentity));

        let id = result.identity.expect("identity should be present");
        assert_eq!(id.vendor_id, 1, "Rockwell Automation vendor ID");
        assert_eq!(id.device_type, 14);
        assert_eq!(id.product_code, 54);
        assert_eq!(id.major_revision, 20);
        assert_eq!(id.minor_revision, 3);
        assert_eq!(id.serial_number, 0x12345678);
        assert_eq!(id.product_name, "1756-L71/B V20");
        assert_eq!(id.state, 3);

        assert!(matches!(result.role, EnipRole::Adapter));
    }

    /// A RegisterSession request is sent by a Scanner to open a TCP session.
    /// The session handle is 0 on the request (assigned by the Adapter in the
    /// response).
    #[test]
    fn test_parse_register_session() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            0x65, 0x00,                                     // Command: RegisterSession
            0x04, 0x00,                                     // Length: 4
            0x00, 0x00, 0x00, 0x00,                         // Session Handle: 0 (not yet assigned)
            0x00, 0x00, 0x00, 0x00,                         // Status: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// Sender Context
            0x00, 0x00, 0x00, 0x00,                         // Options
            0x01, 0x00,                                     // Encap Protocol Version: 1
            0x00, 0x00,                                     // Options: 0
        ];

        let result = parse(data).expect("RegisterSession should parse");
        assert!(matches!(result.command, EnipCommand::RegisterSession));
        assert!(matches!(result.role, EnipRole::Scanner));
        assert!(result.identity.is_none());
        assert!(result.cip_service.is_none());
    }

    /// SendRRData carrying a CIP GetAttributeAll request to the Identity object
    /// (class 0x01, instance 1). This is the payload from docs/PROTOCOL-DEEP-PARSE.md.
    #[test]
    fn test_parse_cip_get_attribute_all() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            // Encapsulation header (24 bytes)
            0x6F, 0x00,                                     // Command: SendRRData
            0x16, 0x00,                                     // Length: 22
            0x01, 0x00, 0x00, 0x00,                         // Session Handle: 1
            0x00, 0x00, 0x00, 0x00,                         // Status: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// Sender Context
            0x00, 0x00, 0x00, 0x00,                         // Options
            // Data section (22 bytes)
            0x00, 0x00, 0x00, 0x00,                         // Interface Handle: 0
            0x00, 0x00,                                     // Timeout: 0
            0x02, 0x00,                                     // Item Count: 2
            0x00, 0x00, 0x00, 0x00,                         // Null Address (type=0, len=0)
            0xB2, 0x00, 0x06, 0x00,                         // Unconn Data (type=0x00B2, len=6)
            // CIP message (6 bytes)
            0x01,                                           // Service: GetAttributeAll (0x01)
            0x02,                                           // Path size: 2 words (4 bytes)
            0x20, 0x01,                                     // Class segment: Identity (0x01)
            0x24, 0x01,                                     // Instance segment: 1
        ];

        let result = parse(data).expect("SendRRData should parse");
        assert!(matches!(result.command, EnipCommand::SendRRData));
        assert_eq!(result.session_handle, 1);
        assert!(!result.is_response);
        assert!(!result.cip_error);

        assert!(
            matches!(result.cip_service, Some(CipService::GetAttributeAll)),
            "service should be GetAttributeAll"
        );
        assert!(
            matches!(result.cip_class, Some(CipClass::Identity)),
            "class should be Identity"
        );
        assert_eq!(result.cip_instance, Some(1));
        assert!(result.cip_attribute.is_none());
    }

    /// SendRRData carrying a CIP Write request to the Assembly object (class 0x04).
    /// This traffic pattern corresponds to MITRE ATT&CK T0855 — Unauthorized
    /// Command Message. The sender should be classified as a Scanner.
    #[test]
    fn test_parse_cip_write_to_assembly() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            // Encapsulation header (24 bytes)
            0x6F, 0x00,                                     // Command: SendRRData
            0x16, 0x00,                                     // Length: 22
            0x01, 0x00, 0x00, 0x00,                         // Session Handle: 1
            0x00, 0x00, 0x00, 0x00,                         // Status: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// Sender Context
            0x00, 0x00, 0x00, 0x00,                         // Options
            // Data section (22 bytes)
            0x00, 0x00, 0x00, 0x00,                         // Interface Handle: 0
            0x00, 0x00,                                     // Timeout: 0
            0x02, 0x00,                                     // Item Count: 2
            0x00, 0x00, 0x00, 0x00,                         // Null Address (type=0, len=0)
            0xB2, 0x00, 0x06, 0x00,                         // Unconn Data (type=0x00B2, len=6)
            // CIP message (6 bytes)
            0x4D,                                           // Service: Write (0x4D)
            0x02,                                           // Path size: 2 words (4 bytes)
            0x20, 0x04,                                     // Class segment: Assembly (0x04)
            0x24, 0x01,                                     // Instance segment: 1
        ];

        let result = parse(data).expect("CIP Write should parse");
        assert!(matches!(result.cip_service, Some(CipService::Write)));
        assert!(
            matches!(result.cip_class, Some(CipClass::Assembly)),
            "target class should be Assembly"
        );
        assert_eq!(result.cip_instance, Some(1));
        assert!(!result.is_response);
        assert!(
            matches!(result.role, EnipRole::Scanner),
            "Write sender should be classified as Scanner"
        );
    }

    /// ForwardOpen is sent by a Scanner to open a CIP I/O connection.
    /// The sender should be classified as a Scanner.
    #[test]
    fn test_parse_cip_forward_open() {
        #[rustfmt::skip]
        let data: &[u8] = &[
            // Encapsulation header (24 bytes)
            0x6F, 0x00,                                     // Command: SendRRData
            0x16, 0x00,                                     // Length: 22
            0x02, 0x00, 0x00, 0x00,                         // Session Handle: 2
            0x00, 0x00, 0x00, 0x00,                         // Status: 0
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,// Sender Context
            0x00, 0x00, 0x00, 0x00,                         // Options
            // Data section (22 bytes)
            0x00, 0x00, 0x00, 0x00,                         // Interface Handle: 0
            0x00, 0x00,                                     // Timeout: 0
            0x02, 0x00,                                     // Item Count: 2
            0x00, 0x00, 0x00, 0x00,                         // Null Address
            0xB2, 0x00, 0x06, 0x00,                         // Unconn Data (len=6)
            // CIP message
            0x54,                                           // Service: ForwardOpen (0x54)
            0x02,                                           // Path size: 2 words
            0x20, 0x06,                                     // Class: Connection Manager (0x06)
            0x24, 0x01,                                     // Instance: 1
        ];

        let result = parse(data).expect("ForwardOpen should parse");
        assert!(matches!(result.cip_service, Some(CipService::ForwardOpen)));
        assert!(matches!(result.cip_class, Some(CipClass::ConnectionManager)));
        assert!(matches!(result.role, EnipRole::Scanner));
    }

    /// A payload of only 2 bytes is far shorter than the 24-byte encapsulation
    /// header; parse() must return None without panicking.
    #[test]
    fn test_truncated_header() {
        assert!(parse(&[0x63, 0x00]).is_none());
    }

    /// An empty payload must return None without panicking.
    #[test]
    fn test_empty_payload() {
        assert!(parse(&[]).is_none());
    }
}
