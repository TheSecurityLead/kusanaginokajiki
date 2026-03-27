//! S7comm+ (S7CommPlus) protocol parser.
//!
//! S7comm+ is Siemens' successor protocol to classic S7comm, used by
//! S7-1200 (FW ≥ 4.x) and S7-1500 PLCs. It runs over the same
//! TPKT → COTP DT Data transport stack on port 102/TCP but uses
//! protocol identifier byte `0x72` instead of `0x32`.
//!
//! The protocol is partially proprietary; this parser targets the fields
//! that are publicly documented via the Wireshark S7comm+ dissector and
//! security research (Klick et al., "Industrial Control System Security",
//! USENIX 2015).
//!
//! ## Frame Layout (after COTP DT Data)
//!
//! ```text
//! [0]    Protocol ID  0x72
//! [1]    Version      0x01 (V1), 0x02 (V2), 0x03 (V3)
//! [2-3]  Data length  (u16 BE) — bytes remaining after this field
//! [4]    Opcode:
//!          0x31 = Request
//!          0x32 = Response
//!          0x33 = Notification
//!          0x02 = IntegrityPart (connect/integrity exchange)
//! [5-8]  Reserved / padding (4 bytes)
//! [9-12] Session ID   (u32 LE) — correlates request/response pairs
//! [13-16] Function    (u32 LE) — see S7PlusFunction
//! [17-20] Return value (Response only, u32 LE; 0x00000000 = OK)
//! ```
//!
//! ## Known Function Codes
//!
//! ```text
//! 0x0000_0016  Explore       (device/tag discovery — T0846)
//! 0x0000_0045  CreateObject  (upload/create logic object — T0843)
//! 0x0000_0046  DeleteObject  (delete logic object)
//! 0x0000_04BB  GetVarSubStruc
//! 0x0000_04CA  ReadValue     (read process variable — T0801)
//! 0x0000_04D4  WriteValue    (write process variable — T0855)
//! 0x0000_04F2  GetMultiVariables
//! 0x0000_04FC  SetMultiVariables (multi-write — T0855)
//! ```
//!
//! ## Security Relevance
//!
//! - `WriteValue` / `SetMultiVariables`: direct PLC memory writes (T0855)
//! - `CreateObject` / `DeleteObject`: program upload/manipulation (T0843)
//! - `Explore`: asset discovery / reconnaissance (T0846)

use serde::{Deserialize, Serialize};

/// Offset into the raw TCP payload where COTP begins (after 4-byte TPKT header).
const COTP_OFFSET: usize = 4;

/// S7comm+ protocol identifier byte.
const S7PLUS_PROTOCOL_ID: u8 = 0x72;

// ─── Version ──────────────────────────────────────────────────────────────────

/// S7comm+ protocol version.
///
/// Corresponds to the version byte at payload[s7plus_start + 1].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S7PlusVersion {
    /// Version 1 — early S7-1200 firmware
    V1,
    /// Version 2 — S7-1200 FW 4+ and most S7-1500 firmware
    V2,
    /// Version 3 — newer S7-1500 firmware
    V3,
    /// Unknown version byte
    Unknown(u8),
}

impl S7PlusVersion {
    fn from_byte(b: u8) -> Self {
        match b {
            0x01 => S7PlusVersion::V1,
            0x02 => S7PlusVersion::V2,
            0x03 => S7PlusVersion::V3,
            other => S7PlusVersion::Unknown(other),
        }
    }
}

// ─── Opcode ───────────────────────────────────────────────────────────────────

/// S7comm+ opcode type — determines the PDU direction and kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S7PlusOpcode {
    /// 0x02 — IntegrityPart: connection/integrity exchange
    IntegrityPart,
    /// 0x31 — Request from engineering station / HMI to PLC
    Request,
    /// 0x32 — Response from PLC to engineering station / HMI
    Response,
    /// 0x33 — Notification/push from PLC (unsolicited data)
    Notification,
    /// Unknown opcode byte
    Unknown(u8),
}

impl S7PlusOpcode {
    fn from_byte(b: u8) -> Self {
        match b {
            0x02 => S7PlusOpcode::IntegrityPart,
            0x31 => S7PlusOpcode::Request,
            0x32 => S7PlusOpcode::Response,
            0x33 => S7PlusOpcode::Notification,
            other => S7PlusOpcode::Unknown(other),
        }
    }
}

// ─── Function ─────────────────────────────────────────────────────────────────

/// S7comm+ function code (32-bit LE value following the session ID).
///
/// Security relevance: WriteValue and SetMultiVariables perform direct
/// PLC memory writes (MITRE ATT&CK for ICS T0855). CreateObject and
/// DeleteObject manipulate PLC program objects (T0843). Explore is used
/// for reconnaissance (T0846).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S7PlusFunction {
    /// 0x0016 — Explore / GetTypeInfo (device and tag discovery — T0846)
    Explore,
    /// 0x0045 — CreateObject (upload/create program block — T0843)
    CreateObject,
    /// 0x0046 — DeleteObject (delete program block)
    DeleteObject,
    /// 0x04BB — GetVarSubStruc (read variable sub-structure)
    GetVarSubStruc,
    /// 0x04CA — ReadValue (read process variable — T0801)
    ReadValue,
    /// 0x04D4 — WriteValue (write process variable — T0855)
    WriteValue,
    /// 0x04F2 — GetMultiVariables (bulk read)
    GetMultiVariables,
    /// 0x04FC — SetMultiVariables (bulk write — T0855)
    SetMultiVariables,
    /// Unknown or undocumented function code
    Unknown(u32),
}

impl S7PlusFunction {
    fn from_u32(v: u32) -> Self {
        match v {
            0x0016 => S7PlusFunction::Explore,
            0x0045 => S7PlusFunction::CreateObject,
            0x0046 => S7PlusFunction::DeleteObject,
            0x04BB => S7PlusFunction::GetVarSubStruc,
            0x04CA => S7PlusFunction::ReadValue,
            0x04D4 => S7PlusFunction::WriteValue,
            0x04F2 => S7PlusFunction::GetMultiVariables,
            0x04FC => S7PlusFunction::SetMultiVariables,
            other => S7PlusFunction::Unknown(other),
        }
    }

    /// Human-readable name for this function.
    pub fn name(&self) -> &'static str {
        match self {
            S7PlusFunction::Explore => "Explore",
            S7PlusFunction::CreateObject => "CreateObject",
            S7PlusFunction::DeleteObject => "DeleteObject",
            S7PlusFunction::GetVarSubStruc => "GetVarSubStruc",
            S7PlusFunction::ReadValue => "ReadValue",
            S7PlusFunction::WriteValue => "WriteValue",
            S7PlusFunction::GetMultiVariables => "GetMultiVariables",
            S7PlusFunction::SetMultiVariables => "SetMultiVariables",
            S7PlusFunction::Unknown(_) => "Unknown",
        }
    }

    /// True for functions that write process data or program objects.
    ///
    /// Security relevance: writing to a PLC represents potential process
    /// manipulation (ATT&CK T0855 / T0843).
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            S7PlusFunction::WriteValue
                | S7PlusFunction::SetMultiVariables
                | S7PlusFunction::CreateObject
                | S7PlusFunction::DeleteObject
        )
    }
}

// ─── Role ─────────────────────────────────────────────────────────────────────

/// Sender role inferred from the S7comm+ opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum S7PlusRole {
    /// Engineering station, HMI, or SCADA system sending requests
    Client,
    /// PLC responding to requests or sending notifications
    Server,
    /// Role cannot be determined (IntegrityPart or unknown opcode)
    Unknown,
}

// ─── Main Result ──────────────────────────────────────────────────────────────

/// Parsed S7comm+ packet information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S7PlusInfo {
    /// Protocol version (V1/V2/V3)
    pub version: S7PlusVersion,
    /// Opcode type (Request / Response / Notification / IntegrityPart)
    pub opcode: S7PlusOpcode,
    /// Application-layer data length (bytes after the length field)
    pub data_length: u16,
    /// Session ID correlating a request/response pair (LE u32)
    pub session_id: Option<u32>,
    /// Function code identifying the operation
    pub function: Option<S7PlusFunction>,
    /// Return value from a Response PDU (0 = OK, non-zero = error)
    pub return_value: Option<u32>,
    /// Inferred role of the sender
    pub role: S7PlusRole,
}

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Parse an S7comm+ TCP payload (TPKT → COTP DT Data → S7comm+).
///
/// Returns `None` if:
/// - Payload is shorter than the TPKT + COTP + S7+ common header
/// - TPKT version byte is not 0x03
/// - S7+ protocol ID byte is not 0x72 (classic S7comm should use `s7comm::parse`)
///
/// # Arguments
/// * `payload` — Raw TCP payload bytes starting from the TPKT header
pub fn parse(payload: &[u8]) -> Option<S7PlusInfo> {
    // Minimum: TPKT(4) + COTP_len(1) + COTP_PDU_type(1) = 6 for outer validation
    if payload.len() < 6 {
        return None;
    }

    // TPKT version must be 0x03 (RFC 1006)
    if payload[0] != 0x03 {
        return None;
    }

    // Only handle COTP DT Data (0xF0) — CR/CC setup frames carry no S7+ payload
    let pdu_type_byte = payload[COTP_OFFSET + 1];
    if pdu_type_byte != 0xF0 {
        return None;
    }

    // COTP length byte: how many bytes follow it in the COTP header
    let cotp_length = payload[COTP_OFFSET] as usize;

    // S7+ starts immediately after the COTP header
    let s7p_start = COTP_OFFSET + 1 + cotp_length;

    // Minimum S7+ common header: protocol_id(1) + version(1) + data_len(2) + opcode(1) = 5
    if payload.len() < s7p_start + 5 {
        return None;
    }

    // Protocol ID must be 0x72
    if payload[s7p_start] != S7PLUS_PROTOCOL_ID {
        return None;
    }

    let version = S7PlusVersion::from_byte(payload[s7p_start + 1]);
    let data_length = u16::from_be_bytes([payload[s7p_start + 2], payload[s7p_start + 3]]);
    let opcode = S7PlusOpcode::from_byte(payload[s7p_start + 4]);

    let role = match opcode {
        S7PlusOpcode::Request => S7PlusRole::Client,
        S7PlusOpcode::Response | S7PlusOpcode::Notification => S7PlusRole::Server,
        _ => S7PlusRole::Unknown,
    };

    // Extended fields: reserved(4) + session_id(4) + function(4) = 12 bytes after opcode
    // Byte offsets relative to s7p_start:
    //   [5-8]  reserved
    //   [9-12] session_id (u32 LE)
    //   [13-16] function (u32 LE)
    let (session_id, function, return_value) =
        if payload.len() >= s7p_start + 17 {
            let sess = u32::from_le_bytes([
                payload[s7p_start + 9],
                payload[s7p_start + 10],
                payload[s7p_start + 11],
                payload[s7p_start + 12],
            ]);
            let func_raw = u32::from_le_bytes([
                payload[s7p_start + 13],
                payload[s7p_start + 14],
                payload[s7p_start + 15],
                payload[s7p_start + 16],
            ]);
            let func = S7PlusFunction::from_u32(func_raw);

            // Response PDUs carry a return value at [17-20]
            let ret = if matches!(opcode, S7PlusOpcode::Response)
                && payload.len() >= s7p_start + 21
            {
                Some(u32::from_le_bytes([
                    payload[s7p_start + 17],
                    payload[s7p_start + 18],
                    payload[s7p_start + 19],
                    payload[s7p_start + 20],
                ]))
            } else {
                None
            };

            (Some(sess), Some(func), ret)
        } else {
            (None, None, None)
        };

    Some(S7PlusInfo {
        version,
        opcode,
        data_length,
        session_id,
        function,
        return_value,
        role,
    })
}

/// Human-readable name for an S7comm+ function code (u32 LE value).
pub fn function_code_name(code: u32) -> &'static str {
    S7PlusFunction::from_u32(code).name()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal S7comm+ packet with a given opcode and optional function.
    fn build_packet(version: u8, opcode: u8, session_id: u32, function: u32) -> Vec<u8> {
        // TPKT header
        let mut pkt = vec![0x03, 0x00, 0x00, 0x00];
        // COTP DT Data: length=2, PDU=0xF0, TPDU=0x80
        pkt.extend_from_slice(&[0x02, 0xF0, 0x80]);
        // S7comm+ header
        pkt.push(0x72); // protocol ID
        pkt.push(version);
        pkt.extend_from_slice(&[0x00, 0x10]); // data_length = 16
        pkt.push(opcode);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
        pkt.extend_from_slice(&session_id.to_le_bytes()); // session_id LE
        pkt.extend_from_slice(&function.to_le_bytes()); // function LE
        pkt
    }

    #[test]
    fn test_read_value_request() {
        let pkt = build_packet(0x02, 0x31, 0x0000_0001, 0x0000_04CA);
        let info = parse(&pkt).expect("should parse ReadValue request");
        assert!(matches!(info.version, S7PlusVersion::V2));
        assert!(matches!(info.opcode, S7PlusOpcode::Request));
        assert!(matches!(info.role, S7PlusRole::Client));
        assert_eq!(info.session_id, Some(1));
        let f = info.function.unwrap();
        assert!(matches!(f, S7PlusFunction::ReadValue));
        assert!(!f.is_write());
    }

    #[test]
    fn test_write_value_request() {
        let pkt = build_packet(0x02, 0x31, 0x0000_0002, 0x0000_04D4);
        let info = parse(&pkt).expect("should parse WriteValue request");
        assert!(matches!(info.opcode, S7PlusOpcode::Request));
        assert!(matches!(info.role, S7PlusRole::Client));
        let f = info.function.unwrap();
        assert!(matches!(f, S7PlusFunction::WriteValue));
        assert!(f.is_write());
    }

    #[test]
    fn test_response_opcode() {
        let pkt = build_packet(0x02, 0x32, 0x0000_0001, 0x0000_04CA);
        let info = parse(&pkt).expect("should parse response");
        assert!(matches!(info.opcode, S7PlusOpcode::Response));
        assert!(matches!(info.role, S7PlusRole::Server));
    }

    #[test]
    fn test_explore_function() {
        let pkt = build_packet(0x01, 0x31, 0xDEAD, 0x0016);
        let info = parse(&pkt).expect("should parse Explore");
        assert!(matches!(info.version, S7PlusVersion::V1));
        assert!(matches!(info.function, Some(S7PlusFunction::Explore)));
    }

    #[test]
    fn test_create_object_is_write() {
        let pkt = build_packet(0x03, 0x31, 1, 0x0045);
        let info = parse(&pkt).expect("should parse CreateObject");
        assert!(matches!(info.version, S7PlusVersion::V3));
        let f = info.function.unwrap();
        assert!(matches!(f, S7PlusFunction::CreateObject));
        assert!(f.is_write());
    }

    #[test]
    fn test_wrong_protocol_id_rejected() {
        // Protocol ID 0x32 = classic S7comm — should not parse as S7comm+
        let mut pkt = build_packet(0x02, 0x31, 1, 0x04CA);
        // Overwrite protocol ID byte (at offset 7)
        pkt[7] = 0x32;
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn test_cotp_cr_rejected() {
        // COTP CR (0xE0) frames carry no S7+ payload — should return None
        let pkt = vec![
            0x03, 0x00, 0x00, 0x16, // TPKT
            0x11, 0xE0, // COTP CR
            0x00, 0x00, 0x00, 0x01, 0x00, // COTP fields
            0xC0, 0x01, 0x0A, 0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02,
        ];
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn test_too_short_rejected() {
        assert!(parse(&[0x03, 0x00]).is_none());
    }

    #[test]
    fn test_invalid_tpkt_version_rejected() {
        let mut pkt = build_packet(0x02, 0x31, 1, 0x04CA);
        pkt[0] = 0x04; // wrong TPKT version
        assert!(parse(&pkt).is_none());
    }

    #[test]
    fn test_function_code_name() {
        assert_eq!(function_code_name(0x04CA), "ReadValue");
        assert_eq!(function_code_name(0x04D4), "WriteValue");
        assert_eq!(function_code_name(0x0016), "Explore");
        assert_eq!(function_code_name(0x0045), "CreateObject");
        assert_eq!(function_code_name(0x04FC), "SetMultiVariables");
        assert_eq!(function_code_name(0xFFFF), "Unknown");
    }

    #[test]
    fn test_short_payload_yields_none_function() {
        // Packet too short to reach the function field — opcode present but no session/function
        let pkt = vec![
            0x03, 0x00, 0x00, 0x0C, // TPKT
            0x02, 0xF0, 0x80,       // COTP DT Data
            0x72, 0x02,             // protocol_id, version
            0x00, 0x04,             // data_length = 4
            0x31,                   // opcode = Request
            // only 4 bytes of reserved — NOT enough to reach session_id + function
            0x00, 0x00, 0x00, 0x00,
        ];
        let info = parse(&pkt).expect("should parse common header");
        assert!(matches!(info.opcode, S7PlusOpcode::Request));
        assert!(info.session_id.is_none());
        assert!(info.function.is_none());
    }
}
