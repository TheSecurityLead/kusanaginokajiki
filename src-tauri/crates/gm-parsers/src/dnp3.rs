//! DNP3 deep protocol parser.
//!
//! Extracts application-layer details from DNP3 payloads:
//! - Data link layer: start bytes (0x05 0x64), length, control, source/destination addresses
//! - Transport layer: FIN/FIR bits, sequence number
//! - Application layer: function codes, object headers
//! - Master/outstation role detection
//! - Unsolicited response detection (FC 130)
//!
//! Reference: IEEE 1815-2012 (DNP3)
//!
//! Data Link Frame:
//! [Start: 0x05 0x64][Length: 1][Control: 1][Destination: 2 LE][Source: 2 LE][CRC: 2]
//!
//! The Control byte's DIR bit (bit 7) indicates direction:
//!   1 = from master, 0 = from outstation

use serde::Serialize;

/// DNP3 start bytes — every DNP3 data link frame begins with these
const DNP3_START_1: u8 = 0x05;
const DNP3_START_2: u8 = 0x64;

/// Minimum DNP3 data link header size: start(2) + length(1) + control(1) + dst(2) + src(2) + crc(2) = 10
const DNP3_LINK_HEADER_SIZE: usize = 10;

/// Parsed DNP3 packet information.
#[derive(Debug, Clone, Serialize)]
pub struct Dnp3Info {
    /// DNP3 source address (from data link layer, little-endian)
    pub source_address: u16,
    /// DNP3 destination address (from data link layer, little-endian)
    pub destination_address: u16,
    /// Direction bit from control byte (true = from master)
    pub from_master: bool,
    /// Primary bit from control byte
    pub is_primary: bool,
    /// Application layer function code (if present)
    pub function_code: Option<u8>,
    /// Whether this is an unsolicited response (FC 130)
    pub is_unsolicited: bool,
    /// Device role inferred from the packet
    pub role: Dnp3Role,
    /// Transport layer sequence number
    pub transport_seq: Option<u8>,
    /// Transport FIN bit (final fragment)
    pub transport_fin: bool,
    /// Transport FIR bit (first fragment)
    pub transport_fir: bool,
    /// Application sequence number (from application control byte)
    pub app_sequence: Option<u8>,
    /// Application CON bit (confirmation requested)
    pub app_confirm_requested: bool,
    /// Application UNS bit (unsolicited)
    pub app_unsolicited: bool,
}

/// Master/outstation role classification for a DNP3 device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dnp3Role {
    /// Device is a master station (sends requests)
    Master,
    /// Device is an outstation (responds to requests, may send unsolicited)
    Outstation,
    /// Cannot determine role from this packet
    Unknown,
}

/// Attempt to parse a DNP3 payload.
///
/// The payload should be the TCP or UDP application-layer data.
/// Returns None if the payload doesn't start with DNP3 start bytes
/// or is too short to be a valid frame.
///
/// # Arguments
/// * `payload` - Raw application-layer payload bytes
/// * `src_port` - Source port (used as secondary role detection)
/// * `dst_port` - Destination port (used as secondary role detection)
pub fn parse_dnp3(payload: &[u8], src_port: u16, dst_port: u16) -> Option<Dnp3Info> {
    // Validate minimum length and start bytes
    if payload.len() < DNP3_LINK_HEADER_SIZE {
        return None;
    }

    if payload[0] != DNP3_START_1 || payload[1] != DNP3_START_2 {
        return None;
    }

    let _length = payload[2];
    let control = payload[3];

    // DNP3 addresses are little-endian
    let destination_address = u16::from_le_bytes([payload[4], payload[5]]);
    let source_address = u16::from_le_bytes([payload[6], payload[7]]);

    // Control byte bits:
    // Bit 7: DIR (1=from master, 0=from outstation)
    // Bit 6: PRM (1=primary message, 0=secondary message)
    // Bits 5-4: Frame Count Bit / Data Flow Control
    // Bits 3-0: Function Code (data link layer, NOT application layer)
    let from_master = (control & 0x80) != 0;
    let is_primary = (control & 0x40) != 0;

    // Determine role from control byte direction
    let role = if from_master {
        Dnp3Role::Master
    } else {
        // Double-check with port: if src_port=20000, likely outstation responding
        if src_port == 20000 || dst_port != 20000 {
            Dnp3Role::Outstation
        } else {
            Dnp3Role::Unknown
        }
    };

    // Try to extract transport and application layer info
    // After the 10-byte link header, we have data blocks with CRC
    // The transport header is the first byte of the first data block
    let mut transport_seq: Option<u8> = None;
    let mut transport_fin = false;
    let mut transport_fir = false;
    let mut function_code: Option<u8> = None;
    let mut is_unsolicited = false;
    let mut app_sequence: Option<u8> = None;
    let mut app_confirm_requested = false;
    let mut app_unsolicited = false;

    // After the 10-byte link header, the user data starts.
    // In DNP3 over TCP (as used in most modern systems), the CRC bytes
    // may or may not be present. Many implementations strip CRCs for TCP.
    // We attempt to read transport + application layer starting at offset 10.
    if payload.len() > DNP3_LINK_HEADER_SIZE {
        let transport_byte = payload[DNP3_LINK_HEADER_SIZE];
        // Transport header: FIN(bit7) | FIR(bit6) | SEQUENCE(bits 5-0)
        transport_fin = (transport_byte & 0x80) != 0;
        transport_fir = (transport_byte & 0x40) != 0;
        transport_seq = Some(transport_byte & 0x3F);

        // Application layer starts after transport header (offset 11)
        if payload.len() > DNP3_LINK_HEADER_SIZE + 1 {
            let app_offset = DNP3_LINK_HEADER_SIZE + 1;

            // Application control byte
            if payload.len() > app_offset {
                let app_control = payload[app_offset];
                // Application control: FIR(bit7) | FIN(bit6) | CON(bit5) | UNS(bit4) | SEQ(bits 3-0)
                app_confirm_requested = (app_control & 0x20) != 0;
                app_unsolicited = (app_control & 0x10) != 0;
                app_sequence = Some(app_control & 0x0F);
            }

            // Application function code is next byte
            if payload.len() > app_offset + 1 {
                let fc = payload[app_offset + 1];
                function_code = Some(fc);

                // FC 130 (0x82) is Unsolicited Response
                is_unsolicited = fc == 130;
            }
        }
    }

    Some(Dnp3Info {
        source_address,
        destination_address,
        from_master,
        is_primary,
        function_code,
        is_unsolicited,
        role,
        transport_seq,
        transport_fin,
        transport_fir,
        app_sequence,
        app_confirm_requested,
        app_unsolicited,
    })
}

/// Human-readable name for a DNP3 application layer function code.
pub fn function_code_name(fc: u8) -> &'static str {
    match fc {
        0 => "Confirm",
        1 => "Read",
        2 => "Write",
        3 => "Select",
        4 => "Operate",
        5 => "Direct Operate",
        6 => "Direct Operate No Ack",
        7 => "Immediate Freeze",
        8 => "Immediate Freeze No Ack",
        9 => "Freeze and Clear",
        10 => "Freeze and Clear No Ack",
        11 => "Freeze At Time",
        12 => "Freeze At Time No Ack",
        13 => "Cold Restart",
        14 => "Warm Restart",
        15 => "Initialize Data",
        16 => "Initialize Application",
        17 => "Start Application",
        18 => "Stop Application",
        20 => "Enable Unsolicited",
        21 => "Disable Unsolicited",
        22 => "Assign Class",
        23 => "Delay Measurement",
        24 => "Record Current Time",
        25 => "Open File",
        26 => "Close File",
        27 => "Delete File",
        28 => "Get File Info",
        29 => "Authenticate File",
        30 => "Abort File",
        129 => "Response",
        130 => "Unsolicited Response",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dnp3_master_request() {
        // DNP3 frame: start bytes, length, control (DIR=1, PRM=1), dst=1, src=100
        // Then transport header (FIR+FIN) + app control + FC 1 (Read)
        let payload: Vec<u8> = vec![
            0x05, 0x64, // Start bytes
            0x05, // Length
            0xC0, // Control: DIR=1 (from master), PRM=1
            0x01, 0x00, // Destination: 1 (LE)
            0x64, 0x00, // Source: 100 (LE)
            0x00, 0x00, // CRC placeholder
            0xC0, // Transport: FIN=1, FIR=1, SEQ=0
            0xC0, // App control: FIR=1, FIN=1, CON=0, UNS=0, SEQ=0
            0x01, // FC 1: Read
        ];

        let info = parse_dnp3(&payload, 49152, 20000).unwrap();
        assert_eq!(info.source_address, 100);
        assert_eq!(info.destination_address, 1);
        assert!(info.from_master);
        assert!(info.is_primary);
        assert_eq!(info.function_code, Some(1));
        assert!(!info.is_unsolicited);
        assert_eq!(info.role, Dnp3Role::Master);
        assert!(info.transport_fir);
        assert!(info.transport_fin);
    }

    #[test]
    fn test_parse_dnp3_outstation_response() {
        // Response from outstation (DIR=0)
        let payload: Vec<u8> = vec![
            0x05, 0x64, // Start bytes
            0x05, // Length
            0x00, // Control: DIR=0 (from outstation), PRM=0
            0x64, 0x00, // Destination: 100 (LE) — back to master
            0x01, 0x00, // Source: 1 (LE)
            0x00, 0x00, // CRC
            0xC0, // Transport: FIR+FIN
            0xC0, // App control
            0x81, // FC 129: Response
        ];

        let info = parse_dnp3(&payload, 20000, 49152).unwrap();
        assert_eq!(info.source_address, 1);
        assert_eq!(info.destination_address, 100);
        assert!(!info.from_master);
        assert_eq!(info.function_code, Some(129));
        assert!(!info.is_unsolicited);
        assert_eq!(info.role, Dnp3Role::Outstation);
    }

    #[test]
    fn test_parse_dnp3_unsolicited_response() {
        // Unsolicited response (FC 130)
        let payload: Vec<u8> = vec![
            0x05, 0x64, 0x05, 0x00, // Start, length, control (from outstation)
            0x64, 0x00, // Destination
            0x01, 0x00, // Source
            0x00, 0x00, // CRC
            0xC0, // Transport
            0xD0, // App control: FIR=1, FIN=1, CON=0, UNS=1
            0x82, // FC 130: Unsolicited Response
        ];

        let info = parse_dnp3(&payload, 20000, 49152).unwrap();
        assert!(info.is_unsolicited);
        assert_eq!(info.function_code, Some(130));
        assert!(info.app_unsolicited);
        assert_eq!(info.role, Dnp3Role::Outstation);
    }

    #[test]
    fn test_parse_dnp3_invalid_start_bytes() {
        let payload: Vec<u8> = vec![
            0x05, 0x65, // Wrong second start byte
            0x05, 0xC0, 0x01, 0x00, 0x64, 0x00, 0x00, 0x00,
        ];
        assert!(parse_dnp3(&payload, 49152, 20000).is_none());
    }

    #[test]
    fn test_parse_dnp3_too_short() {
        let payload: Vec<u8> = vec![0x05, 0x64, 0x05];
        assert!(parse_dnp3(&payload, 49152, 20000).is_none());
    }

    #[test]
    fn test_dnp3_function_code_names() {
        assert_eq!(function_code_name(1), "Read");
        assert_eq!(function_code_name(2), "Write");
        assert_eq!(function_code_name(129), "Response");
        assert_eq!(function_code_name(130), "Unsolicited Response");
        assert_eq!(function_code_name(200), "Unknown");
    }
}
