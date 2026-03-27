//! PROFINET DCP (Discovery and Configuration Protocol) deep parser.
//!
//! Parses DCP frames to extract device name, vendor ID, device ID, IP
//! configuration, and role. DCP is the Layer-2 discovery/configuration
//! protocol used by all PROFINET IO devices.
//!
//! In KusanagiNoKajiki the parser receives the UDP payload from port 34964
//! packets — the DCP header starts at byte 0 of that payload.
//!
//! Reference: IEC 61158-6-10 (PROFINET DCP protocol), also covered in
//!   Siemens Application Note "PROFINET Technology and Application".
//!
//! Port: 34964 UDP (DCP multicast port)
//!
//! DCP Header (10 bytes):
//!   [0]     Service ID (0x03=Get, 0x04=Set, 0x05=Identify, 0x06=Hello)
//!   [1]     Service Type (0x00=Request, 0x01=ResponseSuccess, 0x05=ResponseError)
//!   [2..5]  u32 BE  Xid (transaction ID)
//!   [6..7]  u16 BE  Response Delay (ignored)
//!   [8..9]  u16 BE  DCP Data Length
//!
//! Each DCP Block:
//!   [0]     Option
//!   [1]     Suboption
//!   [2..3]  u16 BE  Block Length
//!   [4..5]  u16 BE  Block Info (RESPONSES ONLY — not present in requests)
//!   [6..n]  Data     (responses: starting after BlockInfo; requests: starting at offset+4)
//!
//! Blocks are padded to even byte boundaries.

use serde::{Deserialize, Serialize};

// ─── Enums ────────────────────────────────────────────────────────────────────

/// DCP service identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcpServiceId {
    /// 0x03 — Request current value of a parameter
    Get,
    /// 0x04 — Set a parameter value
    Set,
    /// 0x05 — Identify request/response (device discovery)
    Identify,
    /// 0x06 — Hello announcement (device power-on)
    Hello,
    /// Unrecognised service ID
    Unknown(u8),
}

impl DcpServiceId {
    fn from_byte(b: u8) -> Self {
        match b {
            0x03 => DcpServiceId::Get,
            0x04 => DcpServiceId::Set,
            0x05 => DcpServiceId::Identify,
            0x06 => DcpServiceId::Hello,
            _ => DcpServiceId::Unknown(b),
        }
    }
}

/// DCP service type (direction of the message).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DcpServiceType {
    /// 0x00 — Request from IO-Controller/supervisor
    Request,
    /// 0x01 — Successful response from IO-Device
    ResponseSuccess,
    /// 0x05 — Error response
    ResponseError,
    /// Unrecognised service type
    Unknown(u8),
}

impl DcpServiceType {
    fn from_byte(b: u8) -> Self {
        match b {
            0x00 => DcpServiceType::Request,
            0x01 => DcpServiceType::ResponseSuccess,
            0x05 => DcpServiceType::ResponseError,
            _ => DcpServiceType::Unknown(b),
        }
    }
}

/// Detected PROFINET device role from the DCP Device Role block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfinetRole {
    /// 0x01 — IO-Device (field device / remote I/O)
    IoDevice,
    /// 0x02 — IO-Controller (PLC acting as PROFINET controller)
    IoController,
    /// 0x08 — IO-Supervisor (engineering tool / HMI with supervisor access)
    IoSupervisor,
    /// Role block not present or value not recognised
    Unknown,
}

// ─── Structs ──────────────────────────────────────────────────────────────────

/// Device identification information extracted from DCP TLV blocks.
///
/// All fields are `Option` because they may or may not appear in a
/// given DCP frame (Identify Response typically contains all of them;
/// Identify Request typically contains none).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DcpDeviceInfo {
    /// Station name (option 0x02/0x02) — unique within a PROFINET subnet
    pub name_of_station: Option<String>,
    /// Manufacturer/vendor name (option 0x02/0x01)
    pub vendor_name: Option<String>,
    /// PROFINET vendor ID (option 0x02/0x03, high u16)
    pub vendor_id: Option<u16>,
    /// Device model ID (option 0x02/0x03, low u16)
    pub device_id: Option<u16>,
    /// Raw device role byte from option 0x02/0x04
    pub device_role: Option<u8>,
    /// Configured IP address (option 0x01/0x02, bytes 0-3)
    pub ip_address: Option<[u8; 4]>,
    /// Subnet mask (option 0x01/0x02, bytes 4-7)
    pub subnet_mask: Option<[u8; 4]>,
    /// Default gateway (option 0x01/0x02, bytes 8-11)
    pub gateway: Option<[u8; 4]>,
    /// Device MAC address (option 0x01/0x01)
    pub mac_address: Option<[u8; 6]>,
    /// Alias name (option 0x02/0x06)
    pub alias_name: Option<String>,
}

/// Parsed PROFINET DCP packet information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfinetDcpInfo {
    /// DCP service (Get / Set / Identify / Hello)
    pub service_id: DcpServiceId,
    /// Direction of the message (Request or Response)
    pub service_type: DcpServiceType,
    /// Transaction ID used to match requests with responses
    pub xid: u32,
    /// Device identification data extracted from TLV blocks
    pub device_info: DcpDeviceInfo,
    /// Detected device role (derived from the Device Role block)
    pub role: ProfinetRole,
}

// ─── Parse Function ───────────────────────────────────────────────────────────

/// Attempt to parse a PROFINET DCP payload.
///
/// The payload must be the UDP application-layer data from port 34964,
/// starting at the 2-byte PROFINET Frame ID followed by the 10-byte DCP
/// header. Returns `None` if:
/// - the payload is shorter than 12 bytes (2 Frame ID + 10 DCP header)
/// - the Frame ID is not in the DCP range (0xFEFC–0xFEFF)
pub fn parse(payload: &[u8]) -> Option<ProfinetDcpInfo> {
    // Minimum: 2-byte Frame ID + 10-byte DCP header
    if payload.len() < 12 {
        return None;
    }

    // Validate Frame ID — DCP uses 0xFEFC–0xFEFF only.
    // Any other Frame ID belongs to the IO RT parser.
    let frame_id = u16::from_be_bytes([payload[0], payload[1]]);
    if !(0xFEFC..=0xFEFF).contains(&frame_id) {
        return None;
    }

    // DCP header starts at byte 2 (after the Frame ID).
    let service_id = DcpServiceId::from_byte(payload[2]);
    let service_type = DcpServiceType::from_byte(payload[3]);
    let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    // payload[8..10] = Response Delay — skip
    let dcp_data_length = u16::from_be_bytes([payload[10], payload[11]]) as usize;

    // Responses include a 2-byte BlockInfo field at the start of each block's data.
    // Requests do not have BlockInfo.
    let has_block_info = matches!(service_type, DcpServiceType::ResponseSuccess);

    let mut device_info = DcpDeviceInfo::default();

    let data_end = 12 + dcp_data_length;
    let mut offset = 12;

    while offset + 4 <= data_end && offset + 4 <= payload.len() {
        let option = *payload.get(offset)?;
        let suboption = *payload.get(offset + 1)?;
        let block_length =
            u16::from_be_bytes([*payload.get(offset + 2)?, *payload.get(offset + 3)?]) as usize;

        // Skip past the 4-byte block header; for responses also skip BlockInfo (2 bytes)
        let data_start = if has_block_info {
            offset + 6
        } else {
            offset + 4
        };
        let data_len = if has_block_info {
            block_length.saturating_sub(2)
        } else {
            block_length
        };
        // Safe slice — returns None (ignored by if-let) if out of bounds
        let block_data = payload.get(data_start..data_start + data_len);

        match (option, suboption) {
            // Vendor/Manufacturer Name (ASCII string)
            (0x02, 0x01) => {
                if let Some(data) = block_data {
                    device_info.vendor_name = Some(
                        String::from_utf8_lossy(data)
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
            }
            // Name of Station (ASCII string)
            (0x02, 0x02) => {
                if let Some(data) = block_data {
                    device_info.name_of_station = Some(
                        String::from_utf8_lossy(data)
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
            }
            // Device ID: u16 vendor_id + u16 device_id
            (0x02, 0x03) => {
                if let Some(data) = block_data {
                    if data.len() >= 4 {
                        device_info.vendor_id = Some(u16::from_be_bytes([data[0], data[1]]));
                        device_info.device_id = Some(u16::from_be_bytes([data[2], data[3]]));
                    }
                }
            }
            // Device Role: u16 (only low byte is meaningful for standard roles)
            (0x02, 0x04) => {
                if let Some(data) = block_data {
                    if data.len() >= 2 {
                        device_info.device_role =
                            Some(u16::from_be_bytes([data[0], data[1]]) as u8);
                    }
                }
            }
            // Alias Name (ASCII string)
            (0x02, 0x06) => {
                if let Some(data) = block_data {
                    device_info.alias_name = Some(
                        String::from_utf8_lossy(data)
                            .trim_end_matches('\0')
                            .to_string(),
                    );
                }
            }
            // MAC Address (6 bytes)
            (0x01, 0x01) => {
                if let Some(data) = block_data {
                    if data.len() >= 6 {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&data[..6]);
                        device_info.mac_address = Some(mac);
                    }
                }
            }
            // IP Suite: IP (4) + Subnet Mask (4) + Gateway (4)
            (0x01, 0x02) => {
                if let Some(data) = block_data {
                    if data.len() >= 12 {
                        let mut ip = [0u8; 4];
                        let mut mask = [0u8; 4];
                        let mut gw = [0u8; 4];
                        ip.copy_from_slice(&data[0..4]);
                        mask.copy_from_slice(&data[4..8]);
                        gw.copy_from_slice(&data[8..12]);
                        device_info.ip_address = Some(ip);
                        device_info.subnet_mask = Some(mask);
                        device_info.gateway = Some(gw);
                    }
                }
            }
            // Unknown option/suboption — skip
            _ => {}
        }

        // Advance past this block (4-byte header + block_length bytes),
        // padding to even byte boundary.
        let total_block = 4 + block_length;
        let padded = if total_block % 2 == 1 {
            total_block + 1
        } else {
            total_block
        };
        offset += padded;
    }

    // Derive role from the Device Role block value
    let role = match device_info.device_role {
        Some(0x01) => ProfinetRole::IoDevice,
        Some(0x02) => ProfinetRole::IoController,
        Some(0x08) => ProfinetRole::IoSupervisor,
        _ => ProfinetRole::Unknown,
    };

    Some(ProfinetDcpInfo {
        service_id,
        service_type,
        xid,
        device_info,
        role,
    })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a realistic DCP Identify Response with all common blocks.
    fn build_identify_response() -> Vec<u8> {
        let mut pkt = vec![
            0xFE, 0xFF, // Frame ID = 0xFEFF (Identify)
            0x05, // Service: Identify
            0x01, // Type: Response Success
            0x00, 0x00, 0x12, 0x34, // XID = 0x00001234
            0x00,
            0x00, // Response delay (skipped)
                  // DCP data length placeholder — filled in below
        ];

        let mut blocks: Vec<u8> = Vec::new();

        // Name of Station: "plc-001"
        let name = b"plc-001";
        blocks.extend_from_slice(&[0x02, 0x02]);
        blocks.extend_from_slice(&((name.len() as u16 + 2).to_be_bytes())); // +2 for BlockInfo
        blocks.extend_from_slice(&[0x00, 0x00]); // BlockInfo
        blocks.extend_from_slice(name);
        // Total block = 4 + (7+2) = 13 (odd) → pad by 1
        blocks.push(0x00);

        // Vendor/Manufacturer Name: "Siemens"
        let vendor = b"Siemens";
        blocks.extend_from_slice(&[0x02, 0x01]);
        blocks.extend_from_slice(&((vendor.len() as u16 + 2).to_be_bytes())); // +2 BlockInfo
        blocks.extend_from_slice(&[0x00, 0x00]); // BlockInfo
        blocks.extend_from_slice(vendor);
        // Total block = 4 + (7+2) = 13 (odd) → pad by 1
        blocks.push(0x00);

        // Device ID: vendor 0x002A (Siemens), device 0x0001
        blocks.extend_from_slice(&[0x02, 0x03]);
        blocks.extend_from_slice(&6u16.to_be_bytes()); // 4 data bytes + 2 BlockInfo
        blocks.extend_from_slice(&[0x00, 0x00]); // BlockInfo
        blocks.extend_from_slice(&[0x00, 0x2A, 0x00, 0x01]);
        // Total block = 4 + 6 = 10 (even) → no pad

        // Device Role: 0x01 (IO-Device)
        blocks.extend_from_slice(&[0x02, 0x04]);
        blocks.extend_from_slice(&4u16.to_be_bytes()); // 2 data bytes + 2 BlockInfo
        blocks.extend_from_slice(&[0x00, 0x00]); // BlockInfo
        blocks.extend_from_slice(&[0x00, 0x01]); // role = 1 (IO-Device)
                                                 // Total block = 4 + 4 = 8 (even) → no pad

        // IP Suite: 192.168.1.100, 255.255.255.0, 192.168.1.1
        blocks.extend_from_slice(&[0x01, 0x02]);
        blocks.extend_from_slice(&14u16.to_be_bytes()); // 12 data bytes + 2 BlockInfo
        blocks.extend_from_slice(&[0x00, 0x00]); // BlockInfo
        blocks.extend_from_slice(&[192, 168, 1, 100]);
        blocks.extend_from_slice(&[255, 255, 255, 0]);
        blocks.extend_from_slice(&[192, 168, 1, 1]);
        // Total block = 4 + 14 = 18 (even) → no pad

        // Write DCP data length into header
        let data_len = blocks.len() as u16;
        pkt.extend_from_slice(&data_len.to_be_bytes());
        pkt.extend_from_slice(&blocks);
        pkt
    }

    #[test]
    fn test_identify_response() {
        let data = build_identify_response();
        let result = parse(&data).expect("should parse identify response");
        assert!(matches!(result.service_id, DcpServiceId::Identify));
        assert!(matches!(
            result.service_type,
            DcpServiceType::ResponseSuccess
        ));
        assert_eq!(result.xid, 0x0000_1234);
        assert_eq!(
            result.device_info.name_of_station.as_deref(),
            Some("plc-001")
        );
        assert_eq!(result.device_info.vendor_name.as_deref(), Some("Siemens"));
        assert_eq!(result.device_info.vendor_id, Some(0x002A));
        assert_eq!(result.device_info.device_id, Some(0x0001));
        assert_eq!(result.device_info.ip_address, Some([192, 168, 1, 100]));
        assert_eq!(result.device_info.subnet_mask, Some([255, 255, 255, 0]));
        assert_eq!(result.device_info.gateway, Some([192, 168, 1, 1]));
        assert!(matches!(result.role, ProfinetRole::IoDevice));
    }

    #[test]
    fn test_identify_request() {
        // Identify Request with an "All" wildcard block (option=0x00, suboption=0xFF)
        let data: &[u8] = &[
            0xFE, 0xFF, // Frame ID = 0xFEFF (Identify)
            0x05, 0x00, // Identify Request
            0x00, 0x00, 0x00, 0x01, // XID = 1
            0x00, 0x00, // Response delay
            0x00, 0x04, // DCP data length = 4 bytes
            0x00, 0xFF, 0x00, 0x00, // Unknown block (option=0, sub=255), length=0
        ];
        let result = parse(data).expect("should parse identify request");
        assert!(matches!(result.service_id, DcpServiceId::Identify));
        assert!(matches!(result.service_type, DcpServiceType::Request));
        assert_eq!(result.xid, 1);
        // No device info in a request
        assert!(result.device_info.name_of_station.is_none());
    }

    #[test]
    fn test_io_controller_role() {
        // Response with only a Device Role block set to 0x02 (IO-Controller)
        let mut pkt: Vec<u8> = vec![
            0xFE, 0xFF, // Frame ID = 0xFEFF (Identify)
            0x05, 0x01, // Identify Response
            0x00, 0x00, 0xAB, 0xCD, // XID
            0x00, 0x00, // Response delay placeholder
        ];
        let mut blocks: Vec<u8> = Vec::new();
        blocks.extend_from_slice(&[0x02, 0x04]); // Device Role
        blocks.extend_from_slice(&4u16.to_be_bytes()); // length = 4 (2 data + 2 BlockInfo)
        blocks.extend_from_slice(&[0x00, 0x00]); // BlockInfo
        blocks.extend_from_slice(&[0x00, 0x02]); // role = 2 (IO-Controller)
        let data_len = blocks.len() as u16;
        pkt.extend_from_slice(&data_len.to_be_bytes());
        pkt.extend_from_slice(&blocks);

        let result = parse(&pkt).expect("should parse io-controller response");
        assert!(matches!(result.role, ProfinetRole::IoController));
        assert_eq!(result.xid, 0x0000_ABCD);
    }

    #[test]
    fn test_get_request() {
        // Minimal Get Request — 2-byte Frame ID + 10-byte header, no blocks
        let data: &[u8] = &[
            0xFE, 0xFC, // Frame ID = 0xFEFC (Get)
            0x03, 0x00, // Get Request
            0x00, 0x00, 0x00, 0x02, // XID = 2
            0x00, 0x00, // Response delay
            0x00, 0x00, // DCP data length = 0
        ];
        let result = parse(data).expect("should parse get request");
        assert!(matches!(result.service_id, DcpServiceId::Get));
        assert!(matches!(result.service_type, DcpServiceType::Request));
        assert_eq!(result.xid, 2);
    }

    #[test]
    fn test_truncated() {
        // Less than 12 bytes (2 Frame ID + 10 DCP header) — should return None
        let data: &[u8] = &[
            0xFE, 0xFF, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        assert!(parse(data).is_none());
    }

    #[test]
    fn test_io_rt_frame_rejected() {
        // IO RT cyclic frame (Frame ID 0x8001) must not be accepted by DCP parser
        let data: &[u8] = &[
            0x80, 0x01, // Frame ID = 0x8001 (RT_CLASS_1 cyclic)
            0x05, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse(data).is_none());
    }

    #[test]
    fn test_wrong_frame_id_rejected() {
        // Frame ID outside DCP range — should return None
        let data: &[u8] = &[
            0xC0, 0x00, // Frame ID = 0xC000 (RT_CLASS_UDP cyclic)
            0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        assert!(parse(data).is_none());
    }

    #[test]
    fn test_empty() {
        assert!(parse(&[]).is_none());
    }
}
