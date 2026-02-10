//! Modbus TCP deep protocol parser.
//!
//! Extracts application-layer details from Modbus TCP payloads:
//! - MBAP header (transaction ID, protocol ID, length, unit ID)
//! - Function codes and response/request classification
//! - FC 43/14 Read Device Identification (vendor, product, revision)
//! - Master/slave role detection
//! - Register range tracking (read/write operations)
//!
//! Reference: Modbus Application Protocol Specification V1.1b3
//! MBAP Header: [Transaction ID: 2][Protocol ID: 2][Length: 2][Unit ID: 1]
//! PDU:         [Function Code: 1][Data: variable]

use serde::Serialize;

/// Minimum MBAP header size: 7 bytes (transaction_id=2 + protocol_id=2 + length=2 + unit_id=1)
const MBAP_HEADER_SIZE: usize = 7;

/// Modbus TCP protocol identifier (always 0x0000 for Modbus)
const MODBUS_PROTOCOL_ID: u16 = 0x0000;

/// Parsed Modbus TCP packet information.
#[derive(Debug, Clone, Serialize)]
pub struct ModbusInfo {
    /// Transaction ID from MBAP header (correlates requests/responses)
    pub transaction_id: u16,
    /// Unit ID (slave address, 0-247; 0 = broadcast, 255 = no specific slave)
    pub unit_id: u8,
    /// Function code (1-127 for requests, 128+ for exception responses)
    pub function_code: u8,
    /// Whether this is an exception response (FC >= 0x80)
    pub is_exception: bool,
    /// Exception code if this is an exception response
    pub exception_code: Option<u8>,
    /// Whether this packet appears to be from a master (request) or slave (response)
    pub role: ModbusRole,
    /// Register range being accessed (if applicable)
    pub register_range: Option<RegisterRange>,
    /// Device identification from FC 43/14 response
    pub device_id: Option<ModbusDeviceId>,
    /// Diagnostic sub-function (for FC 8)
    pub diagnostic_subfunction: Option<u16>,
}

/// Master/slave role classification for a Modbus device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModbusRole {
    /// Device is sending requests (master/client)
    Master,
    /// Device is responding (slave/server)
    Slave,
    /// Cannot determine role from this packet
    Unknown,
}

/// A range of Modbus registers being accessed.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterRange {
    /// Starting register address
    pub start: u16,
    /// Number of registers
    pub count: u16,
    /// Type of register access
    pub register_type: RegisterType,
}

/// Type of Modbus register being accessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RegisterType {
    Coil,
    DiscreteInput,
    HoldingRegister,
    InputRegister,
}

/// Device identification extracted from FC 43/14 (Read Device Identification).
#[derive(Debug, Clone, Serialize)]
pub struct ModbusDeviceId {
    /// Vendor name (Object ID 0x00)
    pub vendor_name: Option<String>,
    /// Product code (Object ID 0x01)
    pub product_code: Option<String>,
    /// Major/minor revision (Object ID 0x02)
    pub revision: Option<String>,
    /// Vendor URL (Object ID 0x03)
    pub vendor_url: Option<String>,
    /// Product name (Object ID 0x04)
    pub product_name: Option<String>,
    /// Model name (Object ID 0x05)
    pub model_name: Option<String>,
    /// User application name (Object ID 0x06)
    pub user_app_name: Option<String>,
}

/// Attempt to parse a Modbus TCP payload.
///
/// The payload should be the TCP application-layer data (after the TCP header).
/// Returns None if the payload is too short or has an invalid Modbus protocol ID.
///
/// # Arguments
/// * `payload` - Raw TCP payload bytes
/// * `src_port` - Source port (used for master/slave detection)
/// * `dst_port` - Destination port (used for master/slave detection)
pub fn parse_modbus(payload: &[u8], src_port: u16, dst_port: u16) -> Option<ModbusInfo> {
    // Need at least MBAP header (7 bytes) + function code (1 byte) = 8 bytes
    if payload.len() < MBAP_HEADER_SIZE + 1 {
        return None;
    }

    // Parse MBAP header
    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let protocol_id = u16::from_be_bytes([payload[2], payload[3]]);
    let _length = u16::from_be_bytes([payload[4], payload[5]]);
    let unit_id = payload[6];

    // Validate: Modbus protocol ID must be 0x0000
    if protocol_id != MODBUS_PROTOCOL_ID {
        return None;
    }

    let function_code = payload[7];
    let is_exception = function_code >= 0x80;
    let actual_fc = if is_exception {
        function_code & 0x7F
    } else {
        function_code
    };

    // Determine role based on port numbers:
    // - Requests go TO port 502 (dst_port=502 → this device is master)
    // - Responses come FROM port 502 (src_port=502 → this device is slave)
    let role = if dst_port == 502 {
        ModbusRole::Master
    } else if src_port == 502 {
        ModbusRole::Slave
    } else {
        ModbusRole::Unknown
    };

    // Parse exception code
    let exception_code = if is_exception && payload.len() >= 9 {
        Some(payload[8])
    } else {
        None
    };

    // PDU data starts at offset 8 (after MBAP header + FC)
    let pdu_data = &payload[8..];

    // Extract register range for read/write function codes
    let register_range = parse_register_range(actual_fc, pdu_data, &role);

    // Extract device identification from FC 43/14 responses
    let device_id = if actual_fc == 43 && !is_exception {
        parse_device_id(pdu_data, &role)
    } else {
        None
    };

    // Extract diagnostic sub-function for FC 8
    let diagnostic_subfunction = if actual_fc == 8 && pdu_data.len() >= 2 {
        Some(u16::from_be_bytes([pdu_data[0], pdu_data[1]]))
    } else {
        None
    };

    Some(ModbusInfo {
        transaction_id,
        unit_id,
        function_code: actual_fc,
        is_exception,
        exception_code,
        role,
        register_range,
        device_id,
        diagnostic_subfunction,
    })
}

/// Extract register range from Modbus request PDU data.
///
/// For read requests (FC 1-4): [start_address: 2][quantity: 2]
/// For write single (FC 5, 6): [register_address: 2][value: 2]
/// For write multiple (FC 15, 16): [start_address: 2][quantity: 2][byte_count: 1][data...]
fn parse_register_range(fc: u8, pdu_data: &[u8], role: &ModbusRole) -> Option<RegisterRange> {
    // Register range is in the request, not the response (except for FC 5/6 echo)
    // For responses, FC 1-4 don't include the range, only the data
    let register_type = match fc {
        1 | 5 | 15 => RegisterType::Coil,
        2 => RegisterType::DiscreteInput,
        3 | 6 | 16 | 23 => RegisterType::HoldingRegister,
        4 => RegisterType::InputRegister,
        _ => return None,
    };

    // Requests carry the register range in their PDU
    if *role == ModbusRole::Master && pdu_data.len() >= 4 {
        let start = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
        let count = match fc {
            5 | 6 => 1, // Write single — always 1 register
            _ => u16::from_be_bytes([pdu_data[2], pdu_data[3]]),
        };
        return Some(RegisterRange {
            start,
            count,
            register_type,
        });
    }

    // Response to FC 15/16 echoes the range back
    if *role == ModbusRole::Slave && matches!(fc, 15 | 16) && pdu_data.len() >= 4 {
        let start = u16::from_be_bytes([pdu_data[0], pdu_data[1]]);
        let count = u16::from_be_bytes([pdu_data[2], pdu_data[3]]);
        return Some(RegisterRange {
            start,
            count,
            register_type,
        });
    }

    None
}

/// Parse FC 43/14 (Read Device Identification) response.
///
/// MEI Type: 0x0E (14) — Read Device Identification
/// Response format after FC byte:
/// [MEI Type: 1][Read Device ID Code: 1][Conformity Level: 1]
/// [More Follows: 1][Next Object ID: 1][Number of Objects: 1]
/// [Object ID: 1][Object Length: 1][Object Value: N]...
fn parse_device_id(pdu_data: &[u8], role: &ModbusRole) -> Option<ModbusDeviceId> {
    // FC 43 responses only come from slaves
    if *role != ModbusRole::Slave {
        return None;
    }

    // Need at least: MEI type (1) + Read Device ID Code (1) + Conformity (1)
    // + More Follows (1) + Next Object ID (1) + Num Objects (1) = 6 bytes
    if pdu_data.len() < 6 {
        return None;
    }

    let mei_type = pdu_data[0];
    if mei_type != 0x0E {
        return None;
    }

    let num_objects = pdu_data[5] as usize;
    let mut offset = 6;

    let mut device_id = ModbusDeviceId {
        vendor_name: None,
        product_code: None,
        revision: None,
        vendor_url: None,
        product_name: None,
        model_name: None,
        user_app_name: None,
    };

    // Parse each object: [Object ID: 1][Object Length: 1][Object Value: N]
    for _ in 0..num_objects {
        if offset + 2 > pdu_data.len() {
            break;
        }

        let object_id = pdu_data[offset];
        let object_len = pdu_data[offset + 1] as usize;
        offset += 2;

        if offset + object_len > pdu_data.len() {
            break;
        }

        // Extract ASCII string from object value
        let value: String = pdu_data[offset..offset + object_len]
            .iter()
            .filter(|&&b| (0x20..=0x7e).contains(&b))
            .map(|&b| b as char)
            .collect();

        if !value.is_empty() {
            match object_id {
                0x00 => device_id.vendor_name = Some(value),
                0x01 => device_id.product_code = Some(value),
                0x02 => device_id.revision = Some(value),
                0x03 => device_id.vendor_url = Some(value),
                0x04 => device_id.product_name = Some(value),
                0x05 => device_id.model_name = Some(value),
                0x06 => device_id.user_app_name = Some(value),
                _ => {} // Unknown object IDs are ignored
            }
        }

        offset += object_len;
    }

    // Only return if we extracted at least one useful field
    if device_id.vendor_name.is_some()
        || device_id.product_code.is_some()
        || device_id.revision.is_some()
    {
        Some(device_id)
    } else {
        None
    }
}

/// Human-readable name for a Modbus function code.
pub fn function_code_name(fc: u8) -> &'static str {
    match fc {
        1 => "Read Coils",
        2 => "Read Discrete Inputs",
        3 => "Read Holding Registers",
        4 => "Read Input Registers",
        5 => "Write Single Coil",
        6 => "Write Single Register",
        7 => "Read Exception Status",
        8 => "Diagnostics",
        11 => "Get Comm Event Counter",
        12 => "Get Comm Event Log",
        15 => "Write Multiple Coils",
        16 => "Write Multiple Registers",
        17 => "Report Server ID",
        20 => "Read File Record",
        21 => "Write File Record",
        22 => "Mask Write Register",
        23 => "Read/Write Multiple Registers",
        24 => "Read FIFO Queue",
        43 => "Read Device Identification",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_modbus_read_holding_registers_request() {
        // MBAP header + FC 3 (Read Holding Registers) request
        // Transaction ID: 0x0001, Protocol ID: 0x0000, Length: 0x0006, Unit ID: 1
        // FC: 3, Start: 0x0000, Quantity: 0x000A (10 registers)
        let payload: Vec<u8> = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID (Modbus)
            0x00, 0x06, // Length
            0x01, // Unit ID
            0x03, // FC 3: Read Holding Registers
            0x00, 0x00, // Starting address: 0
            0x00, 0x0A, // Quantity: 10
        ];

        let info = parse_modbus(&payload, 49152, 502).unwrap();
        assert_eq!(info.transaction_id, 1);
        assert_eq!(info.unit_id, 1);
        assert_eq!(info.function_code, 3);
        assert!(!info.is_exception);
        assert_eq!(info.role, ModbusRole::Master);

        let range = info.register_range.unwrap();
        assert_eq!(range.start, 0);
        assert_eq!(range.count, 10);
        assert_eq!(range.register_type, RegisterType::HoldingRegister);
    }

    #[test]
    fn test_parse_modbus_response() {
        // FC 3 response from slave
        let payload: Vec<u8> = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID
            0x00, 0x17, // Length (23)
            0x01, // Unit ID
            0x03, // FC 3
            0x14, // Byte count: 20 (10 registers * 2 bytes)
            0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07,
            0x00, 0x08, 0x00, 0x09, 0x00, 0x0A,
        ];

        let info = parse_modbus(&payload, 502, 49152).unwrap();
        assert_eq!(info.function_code, 3);
        assert_eq!(info.role, ModbusRole::Slave);
        assert!(!info.is_exception);
    }

    #[test]
    fn test_parse_modbus_exception() {
        // Exception response: FC 0x83 (FC 3 + 0x80), exception code 2 (illegal data address)
        let payload: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x83, 0x02,
        ];

        let info = parse_modbus(&payload, 502, 49152).unwrap();
        assert_eq!(info.function_code, 3);
        assert!(info.is_exception);
        assert_eq!(info.exception_code, Some(2));
        assert_eq!(info.role, ModbusRole::Slave);
    }

    #[test]
    fn test_parse_modbus_invalid_protocol_id() {
        // Wrong protocol ID (not 0x0000)
        let payload: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x01, // Protocol ID: 1 (not Modbus)
            0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A,
        ];

        assert!(parse_modbus(&payload, 49152, 502).is_none());
    }

    #[test]
    fn test_parse_modbus_too_short() {
        let payload: Vec<u8> = vec![0x00, 0x01, 0x00, 0x00];
        assert!(parse_modbus(&payload, 49152, 502).is_none());
    }

    #[test]
    fn test_parse_fc43_device_identification() {
        // FC 43 response with vendor name "Schneider" and product code "M340"
        let payload: Vec<u8> = vec![
            0x00, 0x01, // Transaction ID
            0x00, 0x00, // Protocol ID
            0x00, 0x1C, // Length
            0x01, // Unit ID
            0x2B, // FC 43
            0x0E, // MEI Type: 14 (Read Device Identification)
            0x01, // Read Device ID Code: 1 (basic)
            0x01, // Conformity Level
            0x00, // More Follows: 0
            0x00, // Next Object ID
            0x03, // Number of Objects: 3
            // Object 0: Vendor Name
            0x00, // Object ID
            0x09, // Length: 9
            b'S', b'c', b'h', b'n', b'e', b'i', b'd', b'e', b'r',
            // Object 1: Product Code
            0x01, // Object ID
            0x04, // Length: 4
            b'M', b'3', b'4', b'0',
            // Object 2: Revision
            0x02, // Object ID
            0x03, // Length: 3
            b'2', b'.', b'1',
        ];

        let info = parse_modbus(&payload, 502, 49152).unwrap();
        assert_eq!(info.function_code, 43);
        assert_eq!(info.role, ModbusRole::Slave);

        let dev_id = info.device_id.unwrap();
        assert_eq!(dev_id.vendor_name, Some("Schneider".to_string()));
        assert_eq!(dev_id.product_code, Some("M340".to_string()));
        assert_eq!(dev_id.revision, Some("2.1".to_string()));
    }

    #[test]
    fn test_parse_modbus_diagnostics_fc8() {
        // FC 8 Diagnostics request, sub-function 0x0000 (Return Query Data)
        let payload: Vec<u8> = vec![
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x08, 0x00, 0x00, 0xAB, 0xCD,
        ];

        let info = parse_modbus(&payload, 49152, 502).unwrap();
        assert_eq!(info.function_code, 8);
        assert_eq!(info.diagnostic_subfunction, Some(0x0000));
        assert_eq!(info.role, ModbusRole::Master);
    }

    #[test]
    fn test_function_code_name() {
        assert_eq!(function_code_name(1), "Read Coils");
        assert_eq!(function_code_name(3), "Read Holding Registers");
        assert_eq!(function_code_name(16), "Write Multiple Registers");
        assert_eq!(function_code_name(43), "Read Device Identification");
        assert_eq!(function_code_name(99), "Unknown");
    }
}
