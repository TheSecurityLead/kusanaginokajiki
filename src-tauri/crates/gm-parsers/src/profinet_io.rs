//! PROFINET IO Real-Time (RT) cyclic data parser.
//!
//! Parses PROFINET IO RT frames transmitted over UDP (RT_CLASS_UDP).
//! These frames carry cyclic process data between IO Controllers (PLCs)
//! and IO Devices (field devices, peripherals).
//!
//! This parser is complementary to `profinet_dcp.rs`:
//!  - DCP handles discovery/configuration frames (Frame IDs 0xFEFC–0xFEFF)
//!  - This module handles cyclic data and alarm frames
//!
//! Reference: IEC 61158-6-10 (PROFINET IO Protocol specification)
//!            IEC 61784-2 (Real-Time Ethernet profiles, Profile 3 = PROFINET)
//!
//! Ports: 34962/UDP, 34963/UDP (cyclic data)
//!        34964/UDP (also used for DCP discovery)
//!
//! ## Frame ID Ranges
//! ```text
//! 0x8000–0xBFFF  RT_CLASS_1 / RT_CLASS_3 cyclic data
//! 0xC000–0xFBFF  RT_CLASS_UDP cyclic data
//! 0xFF20–0xFF3F  RT alarm, low priority
//! 0xFF40–0xFF5F  RT alarm, high priority
//! 0xFEFC–0xFEFF  DCP frames (handled by profinet_dcp parser)
//! ```
//!
//! ## Cyclic Frame Trailer (last 4 bytes)
//! ```text
//! [n-4..n-3]  Cycle Counter  (u16 BE — increments each IO cycle)
//! [n-2]       DataStatus     (provider state bits)
//! [n-1]       TransferStatus (0x00 = OK)
//! ```
//!
//! ## DataStatus Byte Bit Layout
//! ```text
//! bit 0: reserved
//! bit 1: DataState       (1 = run, 0 = stop)
//! bit 2: ProviderState   (1 = primary, 0 = backup)
//! bit 3: Redundancy      (0 = primary, 1 = backup in system redundancy)
//! bit 4: ProblemIndicator (1 = problem detected in data)
//! bit 5: IGNORE          (1 = consumer shall ignore this data)
//! bit 6: DataValid       (1 = data valid)
//! bit 7: Reserved
//! ```

use serde::{Deserialize, Serialize};

// ─── Frame Type ───────────────────────────────────────────────────────────────

/// Classification of the PROFINET IO frame type based on Frame ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfinetIoFrameType {
    /// 0x8000–0xBFFF: RT_CLASS_1 and RT_CLASS_3 cyclic data (high-performance)
    CyclicRtClass1,
    /// 0xC000–0xFBFF: RT_CLASS_UDP cyclic data (software-only RT)
    CyclicRtClassUdp,
    /// 0xFF20–0xFF3F: Alarm, low priority (e.g. process alarms, diagnosis)
    AlarmLow,
    /// 0xFF40–0xFF5F: Alarm, high priority (e.g. hardware faults)
    AlarmHigh,
}

// ─── Role ─────────────────────────────────────────────────────────────────────

/// PROFINET IO role detected from packet direction and port numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfinetIoRole {
    /// IO Controller (PLC/DCS) — sends output data to field devices
    IoController,
    /// IO Device (field device / peripheral) — sends input data to controller
    IoDevice,
    /// Role could not be determined from port direction alone
    Unknown,
}

// ─── DataStatus ───────────────────────────────────────────────────────────────

/// Provider/consumer data status from the cyclic frame trailer.
///
/// Security relevance: `data_valid = false` or `provider_state = stop`
/// indicates the IO Controller PLC has gone into STOP mode, which could
/// mean a plant shutdown command or a safety system activation (T0881).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfinetIoDataStatus {
    /// Data is valid (bit 2 — if false, consumers should discard process data)
    pub data_valid: bool,
    /// Provider is running ("run") or stopped ("stop") — stop = PLC in STOP mode
    pub provider_state: String,
    /// A problem was detected in the data (bit 4 — vendor-specific meaning)
    pub problem_indicator: bool,
    /// Raw DataStatus byte value for full analysis
    pub raw: u8,
}

// ─── Alarm Info ───────────────────────────────────────────────────────────────

/// A single PROFINET IO alarm occurrence observed in the capture.
///
/// Security relevance:
///  - Alarm type 0x0003 (Pull) = a module was physically removed
///  - Alarm type 0x0004 (Plug) = a module was physically inserted
///  - Alarm type 0x0008 (Controlled by Supervisor) = remote takeover of device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfinetIoAlarmInfo {
    /// IEC 61158-6-10 alarm type code
    pub alarm_type_code: u16,
    /// Human-readable alarm type name
    pub name: String,
    /// Slot number of the affected module (0 = device-level)
    pub slot: Option<u16>,
    /// Subslot number of the affected submodule
    pub subslot: Option<u16>,
    /// How many times this alarm type was seen for this device
    pub count: u64,
}

// ─── Main Result ──────────────────────────────────────────────────────────────

/// Parsed PROFINET IO RT frame information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfinetIoInfo {
    /// PROFINET IO Frame ID identifying the communication relationship (AR)
    pub frame_id: u16,
    /// Classification of the frame type
    pub frame_type: ProfinetIoFrameType,
    /// Detected role of the sender
    pub role: ProfinetIoRole,
    /// Cyclic counter from the frame trailer (present on cyclic data frames)
    pub cycle_counter: Option<u16>,
    /// Provider data status (present on cyclic data frames)
    pub data_status: Option<ProfinetIoDataStatus>,
    /// Whether this is an alarm frame
    pub is_alarm: bool,
    /// Alarm type code (only present for alarm frames)
    pub alarm_type_code: Option<u16>,
    /// Alarm type name (only present for alarm frames)
    pub alarm_type_name: Option<String>,
    /// Slot number (only present for alarm frames)
    pub slot_number: Option<u16>,
    /// Subslot number (only present for alarm frames)
    pub subslot_number: Option<u16>,
}

// ─── Parser ───────────────────────────────────────────────────────────────────

/// Parse a PROFINET IO RT frame from a UDP payload.
///
/// Returns `None` if:
/// - Payload is too short (< 4 bytes)
/// - Frame ID is not in a PROFINET IO RT range
/// - Frame is a DCP frame (handled by `profinet_dcp::parse` instead)
/// - Transfer Status is non-zero on a cyclic frame (corrupted/truncated)
pub fn parse(payload: &[u8], src_port: u16, dst_port: u16) -> Option<ProfinetIoInfo> {
    if payload.len() < 4 {
        return None;
    }

    let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
    let frame_type = classify_frame_id(frame_id)?;

    // Determine role from port direction:
    //   dst_port in {34962, 34963} → sender is IO Controller (sending outputs)
    //   src_port in {34962, 34963} → sender is IO Device (sending inputs)
    let role = if dst_port == 34962 || dst_port == 34963 {
        ProfinetIoRole::IoController
    } else if src_port == 34962 || src_port == 34963 {
        ProfinetIoRole::IoDevice
    } else {
        ProfinetIoRole::Unknown
    };

    let is_alarm = matches!(
        frame_type,
        ProfinetIoFrameType::AlarmLow | ProfinetIoFrameType::AlarmHigh
    );

    // For cyclic data frames, parse the 4-byte trailer
    let (cycle_counter, data_status) = if !is_alarm && payload.len() >= 6 {
        let t = payload.len() - 4;
        let cc = u16::from_be_bytes([payload[t], payload[t + 1]]);
        let ds_byte = payload[t + 2];
        let transfer_status = payload[t + 3];

        // TransferStatus != 0x00 means the frame is corrupted or a retransmit
        if transfer_status != 0x00 {
            return None;
        }

        (Some(cc), Some(parse_data_status(ds_byte)))
    } else {
        (None, None)
    };

    // For alarm frames, parse the RTA-PDU alarm notification block
    let (alarm_type_code, alarm_type_name, slot_number, subslot_number) = if is_alarm {
        let (code, slot, subslot) = parse_alarm_info(payload);
        let name = code.map(alarm_type_name);
        (code, name, slot, subslot)
    } else {
        (None, None, None, None)
    };

    Some(ProfinetIoInfo {
        frame_id,
        frame_type,
        role,
        cycle_counter,
        data_status,
        is_alarm,
        alarm_type_code,
        alarm_type_name,
        slot_number,
        subslot_number,
    })
}

// ─── Internal Helpers ─────────────────────────────────────────────────────────

/// Map a Frame ID to a PROFINET IO frame type.
/// Returns `None` for DCP frames and reserved/unknown ranges.
fn classify_frame_id(frame_id: u16) -> Option<ProfinetIoFrameType> {
    match frame_id {
        0x8000..=0xBFFF => Some(ProfinetIoFrameType::CyclicRtClass1),
        0xC000..=0xFBFF => Some(ProfinetIoFrameType::CyclicRtClassUdp),
        0xFF20..=0xFF3F => Some(ProfinetIoFrameType::AlarmLow),
        0xFF40..=0xFF5F => Some(ProfinetIoFrameType::AlarmHigh),
        // DCP frame IDs (0xFEFC–0xFEFF) → handled by profinet_dcp parser
        _ => None,
    }
}

/// Parse the DataStatus byte from a cyclic frame trailer.
fn parse_data_status(ds: u8) -> ProfinetIoDataStatus {
    let data_valid = (ds & 0x04) != 0; // bit 2
    let provider_state = if (ds & 0x02) != 0 { "run" } else { "stop" };
    let problem_indicator = (ds & 0x10) != 0; // bit 4
    ProfinetIoDataStatus {
        data_valid,
        provider_state: provider_state.to_string(),
        problem_indicator,
        raw: ds,
    }
}

/// Extract alarm type code, slot, and subslot from an RTA-PDU alarm frame.
///
/// RTA-PDU layout (bytes after Frame ID at offset 0):
/// ```text
/// [2]    PDU Type    (0x01 = DATA-RTA = carries alarm notification)
/// [3]    Add Flags
/// [4-5]  SendSeqNum  (u16 BE)
/// [6-7]  AckSeqNum   (u16 BE)
/// [8-9]  VarPartLen  (u16 BE)
/// [10+]  AlarmNotification block:
///          [10-11] AlarmType  (u16 BE)
///          [12-13] SlotNumber (u16 BE)
///          [14-15] SubslotNumber (u16 BE)
/// ```
fn parse_alarm_info(payload: &[u8]) -> (Option<u16>, Option<u16>, Option<u16>) {
    // Need Frame ID (2) + PDU header (8) + alarm block header (6) = 16 bytes minimum
    if payload.len() < 16 {
        return (None, None, None);
    }

    // byte 2 = PDU Type; 0x01 = DATA-RTA-PDU (actual alarm data)
    if payload[2] != 0x01 {
        return (None, None, None);
    }

    let alarm_type = u16::from_be_bytes([payload[10], payload[11]]);
    let slot = u16::from_be_bytes([payload[12], payload[13]]);
    let subslot = u16::from_be_bytes([payload[14], payload[15]]);

    (Some(alarm_type), Some(slot), Some(subslot))
}

/// Return a human-readable name for a PROFINET IO alarm type code.
/// Codes from IEC 61158-6-10 Table 487 — AlarmType.
fn alarm_type_name(code: u16) -> String {
    match code {
        0x0001 => "Diagnosis",
        0x0002 => "Process",
        0x0003 => "Pull",
        0x0004 => "Plug",
        0x0005 => "Status",
        0x0006 => "Update",
        0x0007 => "Redundancy",
        0x0008 => "Controlled by Supervisor",
        0x0009 => "Released",
        0x000A => "Plug Wrong Submodule",
        0x000B => "Return of Submodule",
        0x000C => "Diagnosis Disappears",
        0x000D => "Multicast Communication Mismatch",
        0x000E => "Port Data Change Notification",
        0x000F => "Sync Data Changed",
        0x0010 => "Isochronous Mode Problem",
        0x0011 => "Network Component Problem",
        0x0012 => "Time Data Changed",
        0x001E => "External Problem",
        0x001F => "Vendor Specific",
        _ => "Reserved",
    }
    .to_string()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cyclic_rt_class1_frame() {
        // Frame ID 0x8001 (RT_CLASS_1), 2 bytes IO data, 4-byte trailer
        // CC=100, DataStatus=0x35 (valid, run), TransferStatus=0x00
        let payload = vec![
            0x80, 0x01, // Frame ID
            0xDE, 0xAD, // IO data
            0x00, 0x64, // Cycle Counter = 100
            0x06, // DataStatus: bit1=1(run) bit2=1(valid)
            0x00, // TransferStatus = OK
        ];
        let info = parse(&payload, 12345, 34962).expect("should parse RT_CLASS_1");
        assert_eq!(info.frame_id, 0x8001);
        assert!(matches!(
            info.frame_type,
            ProfinetIoFrameType::CyclicRtClass1
        ));
        assert!(matches!(info.role, ProfinetIoRole::IoController));
        assert!(!info.is_alarm);
        assert_eq!(info.cycle_counter, Some(100));
        let ds = info.data_status.unwrap();
        assert!(ds.data_valid);
        assert_eq!(ds.provider_state, "run");
        assert!(!ds.problem_indicator);
    }

    #[test]
    fn test_cyclic_rt_class_udp_frame() {
        // Frame ID 0xC001 (RT_CLASS_UDP)
        let payload = vec![
            0xC0, 0x01, // Frame ID
            0x01, 0x02, 0x03, // IO data
            0x00, 0x0A, // Cycle Counter = 10
            0x06, // DataStatus: bit1=1(run) bit2=1(valid)
            0x00, // TransferStatus = OK
        ];
        let info = parse(&payload, 34963, 22222).expect("should parse RT_CLASS_UDP");
        assert!(matches!(
            info.frame_type,
            ProfinetIoFrameType::CyclicRtClassUdp
        ));
        assert!(matches!(info.role, ProfinetIoRole::IoDevice));
    }

    #[test]
    fn test_provider_stop_detected() {
        // DataStatus = 0x00: bit1=0(stop), bit2=0(invalid)
        let payload = vec![0x80, 0x01, 0xAA, 0xBB, 0x00, 0x01, 0x00, 0x00];
        let info = parse(&payload, 12345, 34962).expect("should parse");
        let ds = info.data_status.unwrap();
        assert!(!ds.data_valid);
        assert_eq!(ds.provider_state, "stop");
    }

    #[test]
    fn test_dcp_frame_rejected() {
        // DCP frame ID 0xFEFF — must be rejected (handled by profinet_dcp parser)
        let payload = vec![0xFE, 0xFF, 0x00, 0x01, 0x00, 0x00];
        assert!(parse(&payload, 12345, 34964).is_none());
    }

    #[test]
    fn test_payload_too_short() {
        assert!(parse(&[0x80, 0x01, 0x00], 12345, 34962).is_none());
    }

    #[test]
    fn test_classify_frame_ids() {
        assert!(classify_frame_id(0x8001).is_some());
        assert!(classify_frame_id(0xBFFF).is_some());
        assert!(classify_frame_id(0xC000).is_some());
        assert!(classify_frame_id(0xFBFF).is_some());
        assert!(classify_frame_id(0xFF21).is_some());
        assert!(classify_frame_id(0xFF41).is_some());
        // DCP / reserved ranges rejected
        assert!(classify_frame_id(0xFEFE).is_none());
        assert!(classify_frame_id(0xFEFF).is_none());
        assert!(classify_frame_id(0x0001).is_none());
    }

    #[test]
    fn test_alarm_type_names() {
        assert_eq!(alarm_type_name(0x0003), "Pull");
        assert_eq!(alarm_type_name(0x0004), "Plug");
        assert_eq!(alarm_type_name(0x0008), "Controlled by Supervisor");
        assert_eq!(alarm_type_name(0x0001), "Diagnosis");
        assert_eq!(alarm_type_name(0xFFFF), "Reserved");
    }
}
