//! IEC 60870-5-104 deep protocol parser.
//!
//! Parses the APCI → ASDU protocol stack used for telecontrol over TCP.
//! Extracts frame type, sequence numbers, ASDU type ID, cause of transmission,
//! and detects master/outstation roles.
//!
//! Reference: IEC 60870-5-104:2006, IEC 60870-5-101 (ASDU structure)
//! Port: 2404 TCP
//!
//! APCI (6 bytes, always present):
//!   [0]    Start byte (MUST be 0x68)
//!   [1]    APDU Length (bytes following, excluding start+length bytes)
//!   [2..5] Control fields (frame type encoded in byte[2] bits 0-1)
//!
//! Frame type detection (from byte[2]):
//!   bit 0 == 0:      I-frame (Information) — carries ASDU data
//!   bits 1:0 == 01:  S-frame (Supervisory) — acknowledgement only
//!   bits 1:0 == 11:  U-frame (Unnumbered) — control functions (STARTDT/STOPDT/TESTFR)

use serde::{Deserialize, Serialize};

/// IEC 104 start byte — every APCI frame begins with this value.
const APCI_START: u8 = 0x68;

/// Fixed APCI header size (always 6 bytes).
const APCI_SIZE: usize = 6;

// ─── Enums ────────────────────────────────────────────────────────────────────

/// IEC 104 APCI frame type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Iec104FrameType {
    /// Information frame — carries an ASDU payload
    I,
    /// Supervisory frame — acknowledgement only, no ASDU
    S,
    /// Unnumbered frame — control functions (STARTDT, STOPDT, TESTFR)
    U,
}

/// U-frame control function codes (encoded in control byte[2]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UFrameFunction {
    /// 0x07 — STARTDT act: request to start data transfer
    StartDtAct,
    /// 0x0B — STARTDT con: confirm data transfer started
    StartDtCon,
    /// 0x13 — STOPDT act: request to stop data transfer
    StopDtAct,
    /// 0x17 — STOPDT con: confirm data transfer stopped
    StopDtCon,
    /// 0x43 — TESTFR act: test frame request (keep-alive)
    TestFrAct,
    /// 0x83 — TESTFR con: test frame confirm
    TestFrCon,
    /// Unrecognised U-frame function
    Unknown(u8),
}

impl UFrameFunction {
    fn from_byte(b: u8) -> Self {
        match b {
            0x07 => UFrameFunction::StartDtAct,
            0x0B => UFrameFunction::StartDtCon,
            0x13 => UFrameFunction::StopDtAct,
            0x17 => UFrameFunction::StopDtCon,
            0x43 => UFrameFunction::TestFrAct,
            0x83 => UFrameFunction::TestFrCon,
            _ => UFrameFunction::Unknown(b),
        }
    }
}

/// ASDU Type ID — identifies the data or command type carried by the ASDU.
///
/// Monitoring types (1–44) flow from outstation to master.
/// Command types (45–69) flow from master to outstation.
/// System types (100–107) can flow in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AsduTypeId {
    // ── Monitoring (outstation → master) ────────────────────────────────────
    /// 1 — M_SP_NA_1: Single-point information (no timestamp)
    SinglePoint,
    /// 3 — M_DP_NA_1: Double-point information
    DoublePoint,
    /// 5 — M_ST_NA_1: Step position information
    StepPosition,
    /// 9 — M_ME_NA_1: Measured value, normalized
    MeasuredNormalized,
    /// 11 — M_ME_NB_1: Measured value, scaled
    MeasuredScaled,
    /// 13 — M_ME_NC_1: Measured value, short floating-point
    MeasuredShortFloat,
    /// 15 — M_IT_NA_1: Integrated totals
    IntegratedTotals,
    /// 30 — M_SP_TB_1: Single-point with time tag CP56Time2a
    SinglePointWithTime,
    /// 31 — M_DP_TB_1: Double-point with time tag
    DoublePointWithTime,
    /// 36 — M_ME_TF_1: Measured float with time tag
    MeasuredFloatWithTime,
    // ── Commands (master → outstation) ──────────────────────────────────────
    /// 45 — C_SC_NA_1: Single command (ATT&CK T0855)
    SingleCommand,
    /// 46 — C_DC_NA_1: Double command (ATT&CK T0855)
    DoubleCommand,
    /// 47 — C_RC_NA_1: Regulating step command
    RegulatingStep,
    /// 48 — C_SE_NA_1: Set-point command, normalized (ATT&CK T0855)
    SetpointNormalized,
    /// 49 — C_SE_NB_1: Set-point command, scaled (ATT&CK T0855)
    SetpointScaled,
    /// 50 — C_SE_NC_1: Set-point command, short floating-point (ATT&CK T0855)
    SetpointShortFloat,
    /// 58 — C_SC_TA_1: Single command with time tag
    SingleCommandWithTime,
    /// 59 — C_DC_TA_1: Double command with time tag
    DoubleCommandWithTime,
    /// 63 — C_SE_TC_1: Set-point float command with time tag
    SetpointFloatWithTime,
    // ── System (both directions) ─────────────────────────────────────────────
    /// 100 — C_IC_NA_1: General interrogation command
    Interrogation,
    /// 101 — C_CI_NA_1: Counter interrogation command
    CounterInterrogation,
    /// 102 — C_RD_NA_1: Read command
    ReadCommand,
    /// 103 — C_CS_NA_1: Clock synchronisation command
    ClockSync,
    /// 105 — C_RP_NA_1: Reset process command (ATT&CK T0816)
    ResetProcess,
    /// Unrecognised type ID
    Unknown(u8),
}

impl AsduTypeId {
    fn from_byte(b: u8) -> Self {
        match b {
            1 => AsduTypeId::SinglePoint,
            3 => AsduTypeId::DoublePoint,
            5 => AsduTypeId::StepPosition,
            9 => AsduTypeId::MeasuredNormalized,
            11 => AsduTypeId::MeasuredScaled,
            13 => AsduTypeId::MeasuredShortFloat,
            15 => AsduTypeId::IntegratedTotals,
            30 => AsduTypeId::SinglePointWithTime,
            31 => AsduTypeId::DoublePointWithTime,
            36 => AsduTypeId::MeasuredFloatWithTime,
            45 => AsduTypeId::SingleCommand,
            46 => AsduTypeId::DoubleCommand,
            47 => AsduTypeId::RegulatingStep,
            48 => AsduTypeId::SetpointNormalized,
            49 => AsduTypeId::SetpointScaled,
            50 => AsduTypeId::SetpointShortFloat,
            58 => AsduTypeId::SingleCommandWithTime,
            59 => AsduTypeId::DoubleCommandWithTime,
            63 => AsduTypeId::SetpointFloatWithTime,
            100 => AsduTypeId::Interrogation,
            101 => AsduTypeId::CounterInterrogation,
            102 => AsduTypeId::ReadCommand,
            103 => AsduTypeId::ClockSync,
            105 => AsduTypeId::ResetProcess,
            _ => AsduTypeId::Unknown(b),
        }
    }
}

/// Cause of transmission — encoded in the low 6 bits of the COT byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CauseOfTransmission {
    /// 1 — Periodic, cyclic
    Periodic,
    /// 2 — Background scan
    Background,
    /// 3 — Spontaneous
    Spontaneous,
    /// 4 — Initialized
    Initialized,
    /// 5 — Requested
    Requested,
    /// 6 — Activation
    Activation,
    /// 7 — Activation confirmation
    ActivationCon,
    /// 8 — Deactivation
    Deactivation,
    /// 9 — Deactivation confirmation
    DeactivationCon,
    /// 10 — Activation termination
    ActivationTerm,
    /// 20 — Interrogated by general interrogation
    Interrogated,
    /// Unrecognised cause code
    Unknown(u8),
}

impl CauseOfTransmission {
    /// Parse from the low 6 bits of the COT byte.
    fn from_byte(b: u8) -> Self {
        match b & 0x3F {
            1 => CauseOfTransmission::Periodic,
            2 => CauseOfTransmission::Background,
            3 => CauseOfTransmission::Spontaneous,
            4 => CauseOfTransmission::Initialized,
            5 => CauseOfTransmission::Requested,
            6 => CauseOfTransmission::Activation,
            7 => CauseOfTransmission::ActivationCon,
            8 => CauseOfTransmission::Deactivation,
            9 => CauseOfTransmission::DeactivationCon,
            10 => CauseOfTransmission::ActivationTerm,
            20 => CauseOfTransmission::Interrogated,
            v => CauseOfTransmission::Unknown(v),
        }
    }
}

/// Master/outstation role for an IEC 104 device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Iec104Role {
    /// Device is sending commands (master / control centre)
    Master,
    /// Device is sending monitoring data (outstation / RTU)
    Outstation,
    /// Cannot determine role from this packet alone
    Unknown,
}

// ─── Struct ───────────────────────────────────────────────────────────────────

/// Parsed IEC 60870-5-104 packet information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iec104Info {
    /// APCI frame type (I, S, or U)
    pub frame_type: Iec104FrameType,
    /// U-frame control function (present only for U-frames)
    pub u_function: Option<UFrameFunction>,
    /// I-frame send sequence number N(S) (present for I-frames)
    pub send_seq: Option<u16>,
    /// S/I-frame receive sequence number N(R) (present for I- and S-frames)
    pub recv_seq: Option<u16>,
    /// ASDU Type ID (present for I-frames with an ASDU)
    pub type_id: Option<AsduTypeId>,
    /// Number of information objects in the ASDU
    pub num_objects: Option<u8>,
    /// True when the SQ bit is set (objects addressed as a sequence)
    pub is_sequence: bool,
    /// Cause of transmission
    pub cause: Option<CauseOfTransmission>,
    /// True when the P/N (negative confirm) bit is set in COT byte
    pub is_negative: bool,
    /// True when the T (test) bit is set in COT byte
    pub is_test: bool,
    /// Originator address from COT high byte (0 if not used)
    pub originator_address: Option<u8>,
    /// Common ASDU address (identifies the station/RTU)
    pub common_address: Option<u16>,
    /// First Information Object Address in the ASDU (3-byte LE)
    pub first_ioa: Option<u32>,
    /// True when this packet contains a command (types 45–69 or 100–107)
    pub is_command: bool,
    /// True when this packet contains monitoring data (types 1–44)
    pub is_monitor: bool,
    /// Detected role of the sending device
    pub role: Iec104Role,
}

// ─── Parse Function ───────────────────────────────────────────────────────────

/// Attempt to parse an IEC 60870-5-104 payload.
///
/// The payload should be TCP application-layer data starting with the
/// APCI start byte (0x68). Returns None if the start byte is missing or
/// the payload is shorter than the 6-byte APCI header.
pub fn parse(payload: &[u8]) -> Option<Iec104Info> {
    if payload.len() < APCI_SIZE {
        return None;
    }
    if payload[0] != APCI_START {
        return None;
    }

    let _apdu_length = payload[1];
    let ctrl = payload[2];

    // Classify frame type from the low two bits of control byte[2]
    let frame_type = if ctrl & 0x01 == 0 {
        Iec104FrameType::I
    } else if ctrl & 0x03 == 0x01 {
        Iec104FrameType::S
    } else {
        Iec104FrameType::U
    };

    match frame_type {
        Iec104FrameType::U => {
            // The function code IS the full control byte[2] (always has bits[1:0] = 11)
            let u_function = UFrameFunction::from_byte(ctrl);
            Some(Iec104Info {
                frame_type,
                u_function: Some(u_function),
                send_seq: None,
                recv_seq: None,
                type_id: None,
                num_objects: None,
                is_sequence: false,
                cause: None,
                is_negative: false,
                is_test: false,
                originator_address: None,
                common_address: None,
                first_ioa: None,
                is_command: false,
                is_monitor: false,
                role: Iec104Role::Unknown,
            })
        }

        Iec104FrameType::S => {
            // S-frame only carries N(R); bytes[2..4] are reserved
            let recv_seq = u16::from_le_bytes([payload[4], payload[5]]) >> 1;
            Some(Iec104Info {
                frame_type,
                u_function: None,
                send_seq: None,
                recv_seq: Some(recv_seq),
                type_id: None,
                num_objects: None,
                is_sequence: false,
                cause: None,
                is_negative: false,
                is_test: false,
                originator_address: None,
                common_address: None,
                first_ioa: None,
                is_command: false,
                is_monitor: false,
                role: Iec104Role::Unknown,
            })
        }

        Iec104FrameType::I => {
            // N(S) = bits[15:1] of bytes[2..4]; N(R) = bits[15:1] of bytes[4..6]
            let send_seq = u16::from_le_bytes([payload[2], payload[3]]) >> 1;
            let recv_seq = u16::from_le_bytes([payload[4], payload[5]]) >> 1;

            // I-frame may carry no ASDU if the payload ends at the APCI header
            if payload.len() <= APCI_SIZE {
                return Some(Iec104Info {
                    frame_type,
                    u_function: None,
                    send_seq: Some(send_seq),
                    recv_seq: Some(recv_seq),
                    type_id: None,
                    num_objects: None,
                    is_sequence: false,
                    cause: None,
                    is_negative: false,
                    is_test: false,
                    originator_address: None,
                    common_address: None,
                    first_ioa: None,
                    is_command: false,
                    is_monitor: false,
                    role: Iec104Role::Unknown,
                });
            }

            // ASDU begins immediately after the 6-byte APCI header
            let asdu = &payload[APCI_SIZE..];

            // ASDU[0]: Type ID
            let type_id_byte = asdu[0];
            let type_id = AsduTypeId::from_byte(type_id_byte);

            // ASDU[1]: VSQ — bit7=SQ (sequence flag), bits[6:0]=number of objects
            let vsq = asdu.get(1).copied().unwrap_or(0);
            let is_sequence = (vsq & 0x80) != 0;
            let num_objects = vsq & 0x7F;

            // ASDU[2]: COT low byte — bits[5:0]=cause, bit6=P/N, bit7=T(test)
            let cot_low = asdu.get(2).copied().unwrap_or(0);
            let cause = CauseOfTransmission::from_byte(cot_low);
            let is_negative = (cot_low & 0x40) != 0;
            let is_test = (cot_low & 0x80) != 0;

            // ASDU[3]: Originator address (COT high byte)
            let originator_address = asdu.get(3).copied();

            // ASDU[4..6]: Common ASDU Address (LE u16)
            let common_address = if asdu.len() >= 6 {
                Some(u16::from_le_bytes([asdu[4], asdu[5]]))
            } else {
                None
            };

            // ASDU[6..9]: First IOA — 3-byte little-endian address
            let first_ioa = if asdu.len() >= 9 {
                Some(
                    asdu[6] as u32
                        | (asdu[7] as u32) << 8
                        | (asdu[8] as u32) << 16,
                )
            } else {
                None
            };

            // Classify as command (master→outstation) or monitoring (outstation→master)
            let is_command = (45..=69).contains(&type_id_byte)
                || (100..=107).contains(&type_id_byte);
            let is_monitor = (1..=44).contains(&type_id_byte);

            let role = if is_command {
                Iec104Role::Master
            } else if is_monitor {
                Iec104Role::Outstation
            } else {
                Iec104Role::Unknown
            };

            Some(Iec104Info {
                frame_type,
                u_function: None,
                send_seq: Some(send_seq),
                recv_seq: Some(recv_seq),
                type_id: Some(type_id),
                num_objects: Some(num_objects),
                is_sequence,
                cause: Some(cause),
                is_negative,
                is_test,
                originator_address,
                common_address,
                first_ioa,
                is_command,
                is_monitor,
                role,
            })
        }
    }
}

/// Human-readable name for an IEC 104 ASDU type ID.
pub fn type_id_name(type_id: u8) -> &'static str {
    match type_id {
        1 => "M_SP_NA_1 (Single-point)",
        3 => "M_DP_NA_1 (Double-point)",
        5 => "M_ST_NA_1 (Step position)",
        9 => "M_ME_NA_1 (Measured normalized)",
        11 => "M_ME_NB_1 (Measured scaled)",
        13 => "M_ME_NC_1 (Measured float)",
        15 => "M_IT_NA_1 (Integrated totals)",
        30 => "M_SP_TB_1 (Single-point with time)",
        31 => "M_DP_TB_1 (Double-point with time)",
        36 => "M_ME_TF_1 (Measured float with time)",
        45 => "C_SC_NA_1 (Single command)",
        46 => "C_DC_NA_1 (Double command)",
        47 => "C_RC_NA_1 (Regulating step)",
        48 => "C_SE_NA_1 (Setpoint normalized)",
        49 => "C_SE_NB_1 (Setpoint scaled)",
        50 => "C_SE_NC_1 (Setpoint float)",
        58 => "C_SC_TA_1 (Single command with time)",
        59 => "C_DC_TA_1 (Double command with time)",
        63 => "C_SE_TC_1 (Setpoint float with time)",
        100 => "C_IC_NA_1 (Interrogation)",
        101 => "C_CI_NA_1 (Counter interrogation)",
        102 => "C_RD_NA_1 (Read command)",
        103 => "C_CS_NA_1 (Clock sync)",
        105 => "C_RP_NA_1 (Reset process)",
        _ => "Unknown",
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_startdt_act() {
        // U-frame STARTDT act — doc payload: 68 04 07 00 00 00
        let payload: &[u8] = &[0x68, 0x04, 0x07, 0x00, 0x00, 0x00];
        let info = parse(payload).unwrap();
        assert_eq!(info.frame_type, Iec104FrameType::U);
        assert_eq!(info.u_function, Some(UFrameFunction::StartDtAct));
        assert!(info.send_seq.is_none());
        assert!(info.recv_seq.is_none());
        assert!(!info.is_command);
        assert!(!info.is_monitor);
        assert_eq!(info.role, Iec104Role::Unknown);
    }

    #[test]
    fn test_startdt_con() {
        // U-frame STARTDT con
        let payload: &[u8] = &[0x68, 0x04, 0x0B, 0x00, 0x00, 0x00];
        let info = parse(payload).unwrap();
        assert_eq!(info.frame_type, Iec104FrameType::U);
        assert_eq!(info.u_function, Some(UFrameFunction::StartDtCon));
        assert_eq!(info.role, Iec104Role::Unknown);
    }

    #[test]
    fn test_s_frame() {
        // S-frame with recv_seq = 2 (encoded as 4 in LE u16, then >> 1)
        let payload: &[u8] = &[0x68, 0x04, 0x01, 0x00, 0x04, 0x00];
        let info = parse(payload).unwrap();
        assert_eq!(info.frame_type, Iec104FrameType::S);
        assert_eq!(info.recv_seq, Some(2));
        assert!(info.send_seq.is_none());
        assert!(info.u_function.is_none());
        assert!(!info.is_command);
        assert!(!info.is_monitor);
    }

    #[test]
    fn test_interrogation_command() {
        // I-frame: Type 100 (Interrogation), COT 6 (Activation), station 1
        // Doc payload: 68 0E 00 00 00 00 64 01 06 00 01 00 00 00 00 14
        let payload: &[u8] = &[
            0x68, 0x0E, 0x00, 0x00, 0x00, 0x00, // APCI: send_seq=0, recv_seq=0
            0x64, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14, // ASDU
        ];
        let info = parse(payload).unwrap();
        assert_eq!(info.frame_type, Iec104FrameType::I);
        assert_eq!(info.send_seq, Some(0));
        assert_eq!(info.recv_seq, Some(0));
        assert_eq!(info.type_id, Some(AsduTypeId::Interrogation));
        assert_eq!(info.num_objects, Some(1));
        assert_eq!(info.cause, Some(CauseOfTransmission::Activation));
        assert!(!info.is_negative);
        assert!(!info.is_test);
        assert_eq!(info.common_address, Some(1));
        assert_eq!(info.first_ioa, Some(0));
        assert!(info.is_command);
        assert!(!info.is_monitor);
        assert_eq!(info.role, Iec104Role::Master);
    }

    #[test]
    fn test_single_command() {
        // I-frame: Type 45 (SingleCommand), send_seq=1, station 1, IOA=1
        // Doc payload: 68 0E 02 00 00 00 2D 01 06 00 01 00 01 00 00 01
        let payload: &[u8] = &[
            0x68, 0x0E, 0x02, 0x00, 0x00, 0x00, // APCI: send_seq = 2>>1 = 1
            0x2D, 0x01, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, // ASDU
        ];
        let info = parse(payload).unwrap();
        assert_eq!(info.frame_type, Iec104FrameType::I);
        assert_eq!(info.send_seq, Some(1));
        assert_eq!(info.type_id, Some(AsduTypeId::SingleCommand));
        assert_eq!(info.cause, Some(CauseOfTransmission::Activation));
        assert_eq!(info.common_address, Some(1));
        assert_eq!(info.first_ioa, Some(1));
        assert!(info.is_command);
        assert!(!info.is_monitor);
        assert_eq!(info.role, Iec104Role::Master);
    }

    #[test]
    fn test_measured_float() {
        // I-frame: Type 13 (MeasuredShortFloat), COT 3 (Spontaneous), IOA=10
        // Doc payload: 68 12 04 00 02 00 0D 01 03 00 01 00 0A 00 00 00 00 C8 42 00
        let payload: &[u8] = &[
            0x68, 0x12, 0x04, 0x00, 0x02, 0x00, // APCI: send_seq=2, recv_seq=1
            0x0D, 0x01, 0x03, 0x00, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00, 0xC8, 0x42, 0x00,
        ];
        let info = parse(payload).unwrap();
        assert_eq!(info.frame_type, Iec104FrameType::I);
        assert_eq!(info.send_seq, Some(2));
        assert_eq!(info.recv_seq, Some(1));
        assert_eq!(info.type_id, Some(AsduTypeId::MeasuredShortFloat));
        assert_eq!(info.cause, Some(CauseOfTransmission::Spontaneous));
        assert_eq!(info.common_address, Some(1));
        assert_eq!(info.first_ioa, Some(10));
        assert!(!info.is_command);
        assert!(info.is_monitor);
        assert_eq!(info.role, Iec104Role::Outstation);
    }

    #[test]
    fn test_invalid_start_byte() {
        // Wrong start byte — must return None
        let payload: &[u8] = &[0x69, 0x04, 0x07, 0x00, 0x00, 0x00];
        assert!(parse(payload).is_none());
    }

    #[test]
    fn test_truncated() {
        // Too short (< 6 bytes) — must return None
        let payload: &[u8] = &[0x68, 0x04, 0x07];
        assert!(parse(payload).is_none());
    }
}
