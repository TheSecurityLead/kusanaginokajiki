//! S7comm deep protocol parser.
//!
//! Parses the TPKT → COTP → S7 protocol stack used by Siemens S7 PLCs.
//! Extracts function codes, rack/slot from COTP TSAP parameters,
//! and detects client/server roles.
//!
//! Reference: Wireshark S7comm dissector, RFC 1006 (TPKT), ISO 8073 (COTP)
//! Port: 102 TCP (ISO-TSAP)

use serde::{Deserialize, Serialize};

/// Offset of COTP header within payload (immediately after 4-byte TPKT header).
const COTP_OFFSET: usize = 4;

/// S7 protocol identifier (first byte of S7 header).
const S7_PROTOCOL_ID: u8 = 0x32;

/// COTP PDU type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CotpPduType {
    /// Connection Request (0xE0)
    ConnectionRequest,
    /// Connection Confirm (0xD0)
    ConnectionConfirm,
    /// DT Data (0xF0) — carries S7 payload
    DtData,
    /// Disconnect Request (0x80)
    DisconnectRequest,
    /// Unknown PDU type
    Unknown(u8),
}

impl CotpPduType {
    fn from_byte(b: u8) -> Self {
        match b {
            0xE0 => CotpPduType::ConnectionRequest,
            0xD0 => CotpPduType::ConnectionConfirm,
            0xF0 => CotpPduType::DtData,
            0x80 => CotpPduType::DisconnectRequest,
            _ => CotpPduType::Unknown(b),
        }
    }
}

/// COTP connection parameters extracted from CR/CC TLV fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CotpParams {
    /// Destination reference
    pub dst_ref: u16,
    /// Source reference
    pub src_ref: u16,
    /// Source TSAP bytes (0xC1 parameter)
    pub src_tsap: Option<Vec<u8>>,
    /// Destination TSAP bytes (0xC2 parameter)
    pub dst_tsap: Option<Vec<u8>>,
    /// TPDU size code (log2 of max PDU size, from 0xC0 parameter)
    pub tpdu_size: Option<u8>,
    /// PLC rack number (decoded from dst_tsap byte[1], upper 3 bits)
    pub rack: Option<u8>,
    /// PLC slot number (decoded from dst_tsap byte[1], lower 5 bits)
    pub slot: Option<u8>,
}

/// S7 ROSCTR (PDU type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S7PduType {
    /// 0x01 — Job (request from client)
    Job,
    /// 0x02 — Ack (acknowledgement without data)
    Ack,
    /// 0x03 — Ack_Data (response with data)
    AckData,
    /// 0x07 — Userdata (programmed functions, SZL reads)
    Userdata,
    /// Unknown ROSCTR value
    Unknown(u8),
}

/// S7 function code (first byte of S7 parameters block).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S7Function {
    /// 0x04 — Read variable
    ReadVar,
    /// 0x05 — Write variable (ATT&CK T0855)
    WriteVar,
    /// 0xF0 — Setup Communication (negotiate PDU and queue sizes)
    SetupCommunication,
    /// 0x28 — PI Service (start/stop/delete program — T0843/T0816)
    PiService,
    /// 0x29 — PLC Stop (T0816)
    PlcStop,
    /// 0x1A — Upload Start (T0845)
    UploadStart,
    /// 0x1B — Upload
    Upload,
    /// 0x1C — Upload End
    UploadEnd,
    /// 0x1D — Download Start (T0843)
    DownloadStart,
    /// 0x1E — Download
    Download,
    /// 0x1F — Download End
    DownloadEnd,
    /// Unknown function code
    Unknown(u8),
}

impl S7Function {
    fn from_byte(b: u8) -> Self {
        match b {
            0x04 => S7Function::ReadVar,
            0x05 => S7Function::WriteVar,
            0xF0 => S7Function::SetupCommunication,
            0x28 => S7Function::PiService,
            0x29 => S7Function::PlcStop,
            0x1A => S7Function::UploadStart,
            0x1B => S7Function::Upload,
            0x1C => S7Function::UploadEnd,
            0x1D => S7Function::DownloadStart,
            0x1E => S7Function::Download,
            0x1F => S7Function::DownloadEnd,
            _ => S7Function::Unknown(b),
        }
    }
}

/// Client/server role for an S7 device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S7Role {
    /// Device is sending requests (engineering station / HMI)
    Client,
    /// Device is responding (PLC)
    Server,
    /// Cannot determine role from this packet
    Unknown,
}

/// Parsed S7comm packet information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S7Info {
    /// COTP PDU type
    pub cotp_pdu_type: CotpPduType,
    /// COTP connection parameters (CR/CC only)
    pub cotp_params: Option<CotpParams>,
    /// S7 PDU type (ROSCTR)
    pub s7_pdu_type: Option<S7PduType>,
    /// S7 function code
    pub s7_function: Option<S7Function>,
    /// PDU reference (correlates request/response pairs)
    pub pdu_reference: Option<u16>,
    /// Error class (Ack/AckData only)
    pub error_class: Option<u8>,
    /// Error code (Ack/AckData only)
    pub error_code: Option<u8>,
    /// Max outstanding requests from calling side (SetupCommunication)
    pub max_amq_calling: Option<u16>,
    /// Max outstanding requests from called side (SetupCommunication)
    pub max_amq_called: Option<u16>,
    /// Negotiated PDU size in bytes (SetupCommunication)
    pub pdu_length: Option<u16>,
    /// SZL ID for Userdata reads
    pub szl_id: Option<u16>,
    /// Order/part number (from SZL)
    pub order_number: Option<String>,
    /// Firmware version string
    pub firmware_version: Option<String>,
    /// Module type string
    pub module_type: Option<String>,
    /// Serial number string
    pub serial_number: Option<String>,
    /// Detected role
    pub role: S7Role,
}

/// Parse COTP CR/CC TLV parameters and return a `CotpParams`.
///
/// Reads dst_ref and src_ref from fixed offsets, then walks the TLV block
/// (starting at COTP[7]) to extract TPDU size, src/dst TSAP, and rack/slot.
fn parse_cotp_params(payload: &[u8], cotp_length: usize) -> CotpParams {
    // dst_ref at COTP[2..4], src_ref at COTP[4..6] — big-endian
    let dst_ref = payload
        .get(COTP_OFFSET + 2..COTP_OFFSET + 4)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .unwrap_or(0);
    let src_ref = payload
        .get(COTP_OFFSET + 4..COTP_OFFSET + 6)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .unwrap_or(0);

    let mut params = CotpParams {
        dst_ref,
        src_ref,
        ..CotpParams::default()
    };

    // TLV params occupy payload[tlv_start..tlv_end]
    // COTP header: [length(1)][pdu_type(1)][dst_ref(2)][src_ref(2)][class(1)][TLV...]
    let tlv_start = COTP_OFFSET + 7;
    let tlv_end = COTP_OFFSET + 1 + cotp_length;

    if tlv_start >= tlv_end || tlv_end > payload.len() {
        return params;
    }

    // Walk TLV: [type(1)][length(1)][value(length bytes)]
    let mut offset = tlv_start;
    while offset + 2 <= tlv_end {
        // Safe: loop guard ensures offset+1 < tlv_end <= payload.len()
        let param_type = payload[offset];
        let param_len = payload[offset + 1] as usize;
        let value_start = offset + 2;
        let value_end = value_start + param_len;

        if value_end > payload.len() || value_end > tlv_end {
            break;
        }

        let value = &payload[value_start..value_end];
        match param_type {
            // 0xC0: TPDU size — single byte, log2 of max PDU size
            0xC0 => {
                if let Some(&b) = value.first() {
                    params.tpdu_size = Some(b);
                }
            }
            // 0xC1: Source TSAP
            0xC1 => {
                params.src_tsap = Some(value.to_vec());
            }
            // 0xC2: Destination TSAP — byte[1] encodes rack (bits 7-5) and slot (bits 4-0)
            0xC2 => {
                params.dst_tsap = Some(value.to_vec());
                if let Some(&tsap1) = value.get(1) {
                    params.rack = Some((tsap1 >> 5) & 0x07);
                    params.slot = Some(tsap1 & 0x1F);
                }
            }
            _ => {}
        }

        offset = value_end;
    }

    params
}

/// Build an S7Info for COTP-only packets (no S7 layer present).
fn make_cotp_only_info(cotp_pdu_type: CotpPduType, cotp_params: Option<CotpParams>) -> S7Info {
    S7Info {
        cotp_pdu_type,
        cotp_params,
        s7_pdu_type: None,
        s7_function: None,
        pdu_reference: None,
        error_class: None,
        error_code: None,
        max_amq_calling: None,
        max_amq_called: None,
        pdu_length: None,
        szl_id: None,
        order_number: None,
        firmware_version: None,
        module_type: None,
        serial_number: None,
        role: S7Role::Unknown,
    }
}

/// Attempt to parse an S7comm TCP payload (TPKT + COTP + S7).
///
/// Returns `None` if:
/// - The payload is too short (< 6 bytes)
/// - TPKT version byte is not 0x03
///
/// Returns `Some(S7Info)` for all valid TPKT packets, even if no S7 layer
/// is present (e.g., COTP CR/CC connection setup).
///
/// # Arguments
/// * `payload` - Raw TCP payload bytes (starting from TPKT header)
pub fn parse(payload: &[u8]) -> Option<S7Info> {
    // Minimum: TPKT(4) + COTP length byte(1) + COTP PDU type byte(1) = 6 bytes
    if payload.len() < 6 {
        return None;
    }

    // TPKT version MUST be 0x03
    if payload[0] != 0x03 {
        return None;
    }

    // COTP length byte: how many bytes follow the length byte in the COTP header
    let cotp_length = payload[COTP_OFFSET] as usize;
    let pdu_type_byte = payload[COTP_OFFSET + 1];
    let cotp_pdu_type = CotpPduType::from_byte(pdu_type_byte);

    match pdu_type_byte {
        // Connection Request / Confirm: parse TLV params for rack/slot
        0xE0 | 0xD0 => {
            let cotp_params = parse_cotp_params(payload, cotp_length);
            Some(make_cotp_only_info(cotp_pdu_type, Some(cotp_params)))
        }

        // DT Data: S7 application layer follows the COTP header
        0xF0 => {
            // S7 starts at: TPKT(4) + COTP_length_byte(1) + cotp_length bytes
            let s7_start = COTP_OFFSET + 1 + cotp_length;

            // Need at least 10 bytes for Job/Userdata S7 header
            if payload.len() < s7_start + 10 {
                return Some(make_cotp_only_info(CotpPduType::DtData, None));
            }

            // S7 protocol ID must be 0x32
            if payload[s7_start] != S7_PROTOCOL_ID {
                return Some(make_cotp_only_info(CotpPduType::DtData, None));
            }

            let rosctr = payload[s7_start + 1];
            let pdu_reference = Some(u16::from_be_bytes([
                payload[s7_start + 4],
                payload[s7_start + 5],
            ]));
            let param_length =
                u16::from_be_bytes([payload[s7_start + 6], payload[s7_start + 7]]) as usize;

            let s7_pdu_type = Some(match rosctr {
                0x01 => S7PduType::Job,
                0x02 => S7PduType::Ack,
                0x03 => S7PduType::AckData,
                0x07 => S7PduType::Userdata,
                _ => S7PduType::Unknown(rosctr),
            });

            // Ack (0x02) and AckData (0x03) have 12-byte headers with error fields
            let (error_class, error_code, params_start) = if rosctr == 0x02 || rosctr == 0x03 {
                if payload.len() < s7_start + 12 {
                    (None, None, s7_start + 12)
                } else {
                    (
                        Some(payload[s7_start + 10]),
                        Some(payload[s7_start + 11]),
                        s7_start + 12,
                    )
                }
            } else {
                // Job (0x01) and Userdata (0x07): 10-byte header
                (None, None, s7_start + 10)
            };

            // Role: request senders (Job/Userdata) are Clients; responders are Servers
            let role = match rosctr {
                0x01 | 0x07 => S7Role::Client,
                0x02 | 0x03 => S7Role::Server,
                _ => S7Role::Unknown,
            };

            // Extract function code from first byte of the parameters block
            let s7_function = if param_length > 0 {
                payload.get(params_start).map(|&b| S7Function::from_byte(b))
            } else {
                None
            };

            // SetupCommunication carries negotiation params after the FC byte:
            // [FC(1)][reserved(1)][max_amq_calling(2 BE)][max_amq_called(2 BE)][pdu_len(2 BE)]
            let is_setup_comm = matches!(s7_function, Some(S7Function::SetupCommunication));
            let (max_amq_calling, max_amq_called, pdu_length) =
                if is_setup_comm && param_length >= 8 {
                    let calling = payload
                        .get(params_start + 2..params_start + 4)
                        .map(|b| u16::from_be_bytes([b[0], b[1]]));
                    let called = payload
                        .get(params_start + 4..params_start + 6)
                        .map(|b| u16::from_be_bytes([b[0], b[1]]));
                    let pdusz = payload
                        .get(params_start + 6..params_start + 8)
                        .map(|b| u16::from_be_bytes([b[0], b[1]]));
                    (calling, called, pdusz)
                } else {
                    (None, None, None)
                };

            Some(S7Info {
                cotp_pdu_type: CotpPduType::DtData,
                cotp_params: None,
                s7_pdu_type,
                s7_function,
                pdu_reference,
                error_class,
                error_code,
                max_amq_calling,
                max_amq_called,
                pdu_length,
                szl_id: None,
                order_number: None,
                firmware_version: None,
                module_type: None,
                serial_number: None,
                role,
            })
        }

        // Disconnect Request or unknown: return with COTP type, no S7
        _ => Some(make_cotp_only_info(cotp_pdu_type, None)),
    }
}

/// Human-readable name for an S7 function code byte.
pub fn function_code_name(fc: u8) -> &'static str {
    match fc {
        0x04 => "Read Var",
        0x05 => "Write Var",
        0xF0 => "Setup Communication",
        0x28 => "PI Service",
        0x29 => "PLC Stop",
        0x1A => "Upload Start",
        0x1B => "Upload",
        0x1C => "Upload End",
        0x1D => "Download Start",
        0x1E => "Download",
        0x1F => "Download End",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cotp_connection_request() {
        // COTP CR (rack 0, slot 2) — from docs/PROTOCOL-DEEP-PARSE.md
        let payload: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x16, // TPKT: version=3, total=22
            0x11, 0xE0, // COTP: length=17, PDU type=CR (0xE0)
            0x00, 0x00, // dst_ref = 0
            0x00, 0x01, // src_ref = 1
            0x00, // class/option
            0xC0, 0x01, 0x0A, // TPDU size: log2=10 → 1024 bytes max
            0xC1, 0x02, 0x01, 0x00, // Src TSAP: [0x01, 0x00]
            0xC2, 0x02, 0x01, 0x02, // Dst TSAP: [0x01, 0x02] → rack=0, slot=2
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(info.cotp_pdu_type, CotpPduType::ConnectionRequest));
        assert!(info.s7_pdu_type.is_none());
        assert!(matches!(info.role, S7Role::Unknown));

        let params = info.cotp_params.unwrap();
        assert_eq!(params.dst_ref, 0);
        assert_eq!(params.src_ref, 1);
        assert_eq!(params.tpdu_size, Some(0x0A));
        assert_eq!(params.rack, Some(0));
        assert_eq!(params.slot, Some(2));
    }

    #[test]
    fn test_setup_communication() {
        // S7 Setup Communication Job — from docs/PROTOCOL-DEEP-PARSE.md
        let payload: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x19, // TPKT: total=25
            0x02, 0xF0, 0x80, // COTP DT Data: length=2, PDU=0xF0, TPDU=0x80
            0x32, 0x01, // S7: protocol_id=0x32, ROSCTR=Job(0x01)
            0x00, 0x00, // reserved
            0x00, 0x01, // PDU reference = 1
            0x00, 0x08, // parameter length = 8
            0x00, 0x00, // data length = 0
            // SetupCommunication params:
            0xF0, 0x00, // FC=0xF0, reserved=0
            0x00, 0x01, // max_amq_calling = 1
            0x00, 0x01, // max_amq_called = 1
            0x01, 0xE0, // pdu_length = 480
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(info.cotp_pdu_type, CotpPduType::DtData));
        assert!(matches!(info.s7_pdu_type, Some(S7PduType::Job)));
        assert!(matches!(
            info.s7_function,
            Some(S7Function::SetupCommunication)
        ));
        assert_eq!(info.pdu_reference, Some(1));
        assert_eq!(info.max_amq_calling, Some(1));
        assert_eq!(info.max_amq_called, Some(1));
        assert_eq!(info.pdu_length, Some(480));
        assert!(matches!(info.role, S7Role::Client));
    }

    #[test]
    fn test_read_var() {
        // S7 Read Var Job (FC 0x04)
        let payload: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x1F, // TPKT: total=31
            0x02, 0xF0, 0x80, // COTP DT Data
            0x32, 0x01, // S7 Job
            0x00, 0x00, // reserved
            0x00, 0x02, // PDU ref = 2
            0x00, 0x0E, // param length = 14
            0x00, 0x00, // data length = 0
            0x04, // FC = Read Var
            0x01, // variable count = 1
            // Variable specification (DB1.DBW0):
            0x12, 0x0A, 0x10, 0x02, 0x00, 0x01, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00,
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(info.s7_pdu_type, Some(S7PduType::Job)));
        assert!(matches!(info.s7_function, Some(S7Function::ReadVar)));
        assert!(matches!(info.role, S7Role::Client));
    }

    #[test]
    fn test_write_var() {
        // S7 Write Var Job (FC 0x05 — ATT&CK T0855)
        let payload: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x1F, // TPKT: total=31
            0x02, 0xF0, 0x80, // COTP DT Data
            0x32, 0x01, // S7 Job
            0x00, 0x00, // reserved
            0x00, 0x03, // PDU ref = 3
            0x00, 0x0E, // param length = 14
            0x00, 0x00, // data length = 0
            0x05, // FC = Write Var
            0x01, // variable count = 1
            // Variable address
            0x12, 0x0A, 0x10, 0x02, 0x00, 0x01, 0x00, 0x01, 0x84, 0x00, 0x00, 0x00,
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(info.s7_function, Some(S7Function::WriteVar)));
        assert!(matches!(info.role, S7Role::Client));
    }

    #[test]
    fn test_plc_stop() {
        // S7 PLC Stop Job — from docs/PROTOCOL-DEEP-PARSE.md (ATT&CK T0816)
        let payload: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x15, // TPKT: total=21
            0x02, 0xF0, 0x80, // COTP DT Data
            0x32, 0x01, // S7 Job
            0x00, 0x00, // reserved
            0x00, 0x04, // PDU ref = 4
            0x00, 0x04, // param length = 4
            0x00, 0x00, // data length = 0
            0x29, 0x00, 0x00, 0x00, // FC = PLC Stop (0x29) + padding
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(info.s7_function, Some(S7Function::PlcStop)));
        assert!(matches!(info.role, S7Role::Client));
        assert_eq!(info.pdu_reference, Some(4));
    }

    #[test]
    fn test_download_start() {
        // S7 Download Start Job — from docs/PROTOCOL-DEEP-PARSE.md (ATT&CK T0843)
        let payload: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x13, // TPKT: total=19
            0x02, 0xF0, 0x80, // COTP DT Data
            0x32, 0x01, // S7 Job
            0x00, 0x00, // reserved
            0x00, 0x03, // PDU ref = 3
            0x00, 0x02, // param length = 2
            0x00, 0x00, // data length = 0
            0x1D, 0x00, // FC = Download Start (0x1D)
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(info.s7_function, Some(S7Function::DownloadStart)));
        assert!(matches!(info.role, S7Role::Client));
    }

    #[test]
    fn test_ack_data_response() {
        // S7 AckData SetupCommunication response (Server role, error fields present)
        let payload: Vec<u8> = vec![
            0x03, 0x00, 0x00, 0x1B, // TPKT: total=27
            0x02, 0xF0, 0x80, // COTP DT Data
            0x32, 0x03, // S7 AckData (ROSCTR=0x03)
            0x00, 0x00, // reserved
            0x00, 0x01, // PDU ref = 1
            0x00, 0x08, // param length = 8
            0x00, 0x00, // data length = 0
            0x00, 0x00, // error_class=0, error_code=0 (no error)
            // SetupCommunication response params:
            0xF0, 0x00, // FC=0xF0, reserved
            0x00, 0x01, // max_amq_calling = 1
            0x00, 0x01, // max_amq_called = 1
            0x01, 0xE0, // pdu_length = 480
        ];

        let info = parse(&payload).unwrap();
        assert!(matches!(info.s7_pdu_type, Some(S7PduType::AckData)));
        assert!(matches!(info.role, S7Role::Server));
        assert_eq!(info.error_class, Some(0x00));
        assert_eq!(info.error_code, Some(0x00));
        assert!(matches!(
            info.s7_function,
            Some(S7Function::SetupCommunication)
        ));
        assert_eq!(info.pdu_length, Some(480));
    }

    #[test]
    fn test_truncated_tpkt() {
        // Too short to contain TPKT + COTP type byte
        let payload: Vec<u8> = vec![0x03, 0x00];
        assert!(parse(&payload).is_none());
    }

    #[test]
    fn test_invalid_tpkt_version() {
        // TPKT version byte is 0x04, not 0x03 → reject
        let payload: Vec<u8> = vec![
            0x04, 0x00, 0x00, 0x19, 0x02, 0xF0, 0x80, 0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x08, 0x00, 0x00, 0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0,
        ];
        assert!(parse(&payload).is_none());
    }
}
