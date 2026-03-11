//! OT Ring Redundancy Protocol detection and parsing.
//!
//! Detects and parses Layer-2 redundancy protocols used in industrial Ethernet
//! networks. These frames are Layer-2-only (no IP header) and are forwarded at
//! wire-speed by managed switches to maintain ring topology.
//!
//! ## Supported Protocols
//!
//! | Protocol | Standard | Ethertype / Dst MAC | Role |
//! |----------|----------|---------------------|------|
//! | MRP  | IEC 62439-2    | 0x88E3 / 01:15:4E:00:01:0X | Ring Manager / Client |
//! | RSTP | IEEE 802.1w    | Dst 01:80:C2:00:00:00      | Root Bridge / Designated |
//! | HSR  | IEC 62439-3    | 0x892F / 01:15:4E:00:01:2X | Node |
//! | PRP  | IEC 62439-3    | 0x88FB / 01:15:4E:00:01:00 | Node |
//! | DLR  | EtherNet/IP    | 0x80E1 / 01:21:6C:00:00:01 | Supervisor / Node |
//!
//! ## Integration Note
//!
//! Raw Ethernet frames are intercepted in `gm-capture::parsing` (same pattern
//! as LLDP). The protocol is encoded into the synthetic `src_ip` field as
//! `"redundancy:<proto>"` so `PacketProcessor` can route correctly.

use serde::{Deserialize, Serialize};

// ─── Protocol and Role Enums ──────────────────────────────────────────────────

/// Redundancy protocol family detected from the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedundancyProtocol {
    /// Media Redundancy Protocol (IEC 62439-2), used by PROFINET devices.
    Mrp,
    /// Rapid Spanning Tree Protocol (IEEE 802.1w), common IT/OT hybrid networks.
    Rstp,
    /// High-availability Seamless Redundancy (IEC 62439-3).
    Hsr,
    /// Parallel Redundancy Protocol (IEC 62439-3).
    Prp,
    /// Device Level Ring (EtherNet/IP / CIP).
    Dlr,
}

impl RedundancyProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mrp  => "MRP",
            Self::Rstp => "RSTP",
            Self::Hsr  => "HSR",
            Self::Prp  => "PRP",
            Self::Dlr  => "DLR",
        }
    }
    /// Protocol hint string used in the synthetic src_ip field.
    pub fn hint(self) -> &'static str {
        match self {
            Self::Mrp  => "mrp",
            Self::Rstp => "rstp",
            Self::Hsr  => "hsr",
            Self::Prp  => "prp",
            Self::Dlr  => "dlr",
        }
    }
}

// ─── Result Struct ────────────────────────────────────────────────────────────

/// Information extracted from a redundancy protocol frame.
///
/// All fields are extracted from the wire; absent fields are `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedundancyInfo {
    /// Which redundancy protocol this frame belongs to
    pub protocol: RedundancyProtocol,
    /// Device role in the redundancy topology (e.g., "ring-manager", "root-bridge")
    pub role: Option<String>,
    /// Ring / domain identifier (MRP domain, DLR ring state, VLAN for PVST+)
    pub ring_id: Option<u16>,
    /// Bridge / supervisor / manager priority (lower = more preferred)
    pub priority: Option<u16>,
    /// Source MAC address of the sending device
    pub source_mac: String,
    /// Human-readable summary of the frame
    pub details: String,
    /// True if this device is the ring manager / root bridge / supervisor
    pub is_manager: bool,
    /// True if this frame indicates a topology change event
    pub topology_change: bool,
}

// ─── Frame Detection (from raw Ethernet) ─────────────────────────────────────

/// Detect whether a raw Ethernet frame is a redundancy protocol frame.
///
/// Returns `Some((protocol, ethertype_or_zero))` if the frame belongs to a
/// known redundancy protocol, or `None` otherwise.
///
/// `raw_data` is the full Ethernet frame including the 14-byte header.
pub fn detect_protocol(raw_data: &[u8]) -> Option<RedundancyProtocol> {
    if raw_data.len() < 14 {
        return None;
    }
    let dst = &raw_data[0..6];
    let ethertype = u16::from_be_bytes([raw_data[12], raw_data[13]]);
    let length = ethertype; // Same field, used as length when < 1500

    // RSTP / STP: dst = 01:80:C2:00:00:00, "ethertype" < 1500 (it's a length),
    // LLC header: DSAP=0x42, SSAP=0x42, Ctrl=0x03
    if dst == [0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]
        && length < 1500
        && raw_data.len() >= 17
        && raw_data[14] == 0x42
        && raw_data[15] == 0x42
    {
        return Some(RedundancyProtocol::Rstp);
    }

    // MRP: Ethertype 0x88E3
    if ethertype == 0x88E3 {
        return Some(RedundancyProtocol::Mrp);
    }
    // MRP: dst MAC 01:15:4E:00:01:01 (MRP_Test) or 01:15:4E:00:01:02 (TopologyChange)
    if dst[0..5] == [0x01, 0x15, 0x4E, 0x00, 0x01] && (dst[5] == 0x01 || dst[5] == 0x02) {
        return Some(RedundancyProtocol::Mrp);
    }

    // HSR: Ethertype 0x892F
    if ethertype == 0x892F {
        return Some(RedundancyProtocol::Hsr);
    }
    // HSR: supervision multicast 01:15:4E:00:01:20..2F
    if dst[0..5] == [0x01, 0x15, 0x4E, 0x00, 0x01] && (0x20..=0x2F).contains(&dst[5]) {
        return Some(RedundancyProtocol::Hsr);
    }

    // PRP: Ethertype 0x88FB (supervision)
    if ethertype == 0x88FB {
        return Some(RedundancyProtocol::Prp);
    }
    // PRP: supervision dst 01:15:4E:00:01:00
    if dst == [0x01, 0x15, 0x4E, 0x00, 0x01, 0x00] {
        return Some(RedundancyProtocol::Prp);
    }

    // DLR: Ethertype 0x80E1
    if ethertype == 0x80E1 {
        return Some(RedundancyProtocol::Dlr);
    }
    // DLR: dst 01:21:6C:00:00:01
    if dst == [0x01, 0x21, 0x6C, 0x00, 0x00, 0x01] {
        return Some(RedundancyProtocol::Dlr);
    }

    None
}

// ─── Deep Parse ───────────────────────────────────────────────────────────────

/// Parse a redundancy frame payload (bytes after the 14-byte Ethernet header).
///
/// `proto_hint` must be one of "mrp", "rstp", "hsr", "prp", "dlr".
/// `source_mac` is the MAC address of the sending device.
pub fn parse(payload: &[u8], proto_hint: &str, source_mac: &str) -> Option<RedundancyInfo> {
    match proto_hint {
        "rstp" => parse_rstp(payload, source_mac),
        "mrp"  => parse_mrp(payload, source_mac),
        "hsr"  => parse_hsr(payload, source_mac),
        "prp"  => parse_prp(payload, source_mac),
        "dlr"  => parse_dlr(payload, source_mac),
        _ => None,
    }
}

// ─── RSTP ─────────────────────────────────────────────────────────────────────

/// Parse RSTP/STP BPDU.
///
/// Payload layout (after Ethernet header):
/// ```text
/// [0]   DSAP=0x42
/// [1]   SSAP=0x42
/// [2]   Ctrl=0x03
/// [3]   Protocol ID high (0x00)
/// [4]   Protocol ID low  (0x00)
/// [5]   Protocol version (0x00=STP, 0x02=RSTP)
/// [6]   BPDU type (0x00=Config, 0x80=TCN, 0x02=RST)
/// [7]   Flags
/// [8..9]  Root Bridge Priority
/// [10..15] Root Bridge MAC
/// [16..19] Root Path Cost
/// [20..21] Bridge Priority (this device)
/// [22..27] Bridge MAC (this device)
/// [28..29] Port ID
/// ```
fn parse_rstp(payload: &[u8], source_mac: &str) -> Option<RedundancyInfo> {
    // Need at least LLC (3) + Protocol (2) + version (1) + type (1) = 7 bytes
    if payload.len() < 7 {
        return None;
    }
    // Verify LLC header and Protocol ID
    if payload[0] != 0x42 || payload[4] != 0x00 {
        return None;
    }

    let version = payload[5];
    let bpdu_type = payload[6];

    // Topology Change Notification — no extra fields
    let topology_change_only = bpdu_type == 0x80;
    if topology_change_only {
        return Some(RedundancyInfo {
            protocol: RedundancyProtocol::Rstp,
            role: Some("bridge".to_string()),
            ring_id: None,
            priority: None,
            source_mac: source_mac.to_string(),
            details: "RSTP Topology Change Notification (TCN) — link flap or new device".to_string(),
            is_manager: false,
            topology_change: true,
        });
    }

    // Config / RST BPDU — need at least 38 bytes for full fields
    let flags = payload.get(7).copied().unwrap_or(0);
    let tc_flag = flags & 0x01 != 0;

    // Port role from flags bits [2:3]
    let port_role_bits = (flags >> 2) & 0x03;
    let port_role = match port_role_bits {
        0x01 => "alternate/backup",
        0x02 => "root",
        0x03 => "designated",
        _    => "unknown",
    };

    let (root_priority, root_mac, bridge_priority, is_root) = if payload.len() >= 30 {
        let root_prio = u16::from_be_bytes([payload[8], payload[9]]);
        let root_mac_bytes = &payload[10..16];
        let root_mac_str = format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            root_mac_bytes[0], root_mac_bytes[1], root_mac_bytes[2],
            root_mac_bytes[3], root_mac_bytes[4], root_mac_bytes[5]
        );
        let bridge_prio = u16::from_be_bytes([payload[20], payload[21]]);
        // This device is root if its MAC matches the root bridge MAC
        let is_r = source_mac == root_mac_str;
        (root_prio, root_mac_str, bridge_prio, is_r)
    } else {
        (0, "unknown".to_string(), 0, false)
    };

    let proto_name = if version == 0x02 { "RSTP" } else { "STP" };
    let role = if is_root {
        "root-bridge"
    } else {
        port_role
    };

    let details = format!(
        "{} BPDU: port-role={} root={} root-prio={} bridge-prio={}{}",
        proto_name, port_role, root_mac, root_priority, bridge_priority,
        if tc_flag { " [TC]" } else { "" }
    );

    Some(RedundancyInfo {
        protocol: RedundancyProtocol::Rstp,
        role: Some(role.to_string()),
        ring_id: None,
        priority: Some(bridge_priority),
        source_mac: source_mac.to_string(),
        details,
        is_manager: is_root,
        topology_change: tc_flag,
    })
}

// ─── MRP ──────────────────────────────────────────────────────────────────────

/// Parse MRP (Media Redundancy Protocol) frame.
///
/// MRP PDU layout (after Ethernet header, IEC 62439-2 TLV format):
/// ```text
/// [0..1]  TLV Type (0x0001=Test, 0x0002=TopologyChange, 0x0003=LinkDown, 0x0004=LinkUp)
/// [2..3]  TLV Length
/// For MRP_Test (type 0x0001):
///   [4..5]  Prio (ring manager priority, lower = preferred)
///   [6..11] SA (ring manager MAC address)
///   [12..13] PortRole (0=Primary, 1=Secondary)
///   [14..15] RingState (0=RC_Open=ring broken, 1=RC_Closed=ring healthy)
/// ```
fn parse_mrp(payload: &[u8], source_mac: &str) -> Option<RedundancyInfo> {
    if payload.len() < 4 {
        return None;
    }
    let pdu_type = u16::from_be_bytes([payload[0], payload[1]]);

    match pdu_type {
        0x0001 => {
            // MRP_Test: sent by Ring Manager periodically to verify ring continuity
            let priority = if payload.len() >= 6 {
                Some(u16::from_be_bytes([payload[4], payload[5]]))
            } else {
                None
            };
            let ring_state = if payload.len() >= 16 {
                match u16::from_be_bytes([payload[14], payload[15]]) {
                    0 => "open (ring broken)",
                    1 => "closed (ring healthy)",
                    _ => "unknown",
                }
            } else {
                "unknown"
            };
            let port_role = if payload.len() >= 14 {
                match u16::from_be_bytes([payload[12], payload[13]]) {
                    0 => "primary",
                    1 => "secondary",
                    _ => "unknown",
                }
            } else {
                "unknown"
            };
            Some(RedundancyInfo {
                protocol: RedundancyProtocol::Mrp,
                role: Some("ring-manager".to_string()),
                ring_id: None,
                priority,
                source_mac: source_mac.to_string(),
                details: format!("MRP_Test: ring-state={ring_state} port={port_role}"),
                is_manager: true,
                topology_change: false,
            })
        }
        0x0002 => {
            // MRP_TopologyChange: sent by Ring Manager when ring state changes
            Some(RedundancyInfo {
                protocol: RedundancyProtocol::Mrp,
                role: Some("ring-manager".to_string()),
                ring_id: None,
                priority: None,
                source_mac: source_mac.to_string(),
                details: "MRP_TopologyChange: ring manager signalling topology change".to_string(),
                is_manager: true,
                topology_change: true,
            })
        }
        0x0003 | 0x0004 => {
            // MRP_LinkDown / MRP_LinkUp: sent by Ring Clients (normal switches)
            let event = if pdu_type == 0x0003 { "LinkDown" } else { "LinkUp" };
            Some(RedundancyInfo {
                protocol: RedundancyProtocol::Mrp,
                role: Some("ring-client".to_string()),
                ring_id: None,
                priority: None,
                source_mac: source_mac.to_string(),
                details: format!("MRP_{event}: ring client reporting link state change"),
                is_manager: false,
                topology_change: pdu_type == 0x0003,
            })
        }
        _ => {
            // Unknown MRP PDU type — still recognise as MRP
            Some(RedundancyInfo {
                protocol: RedundancyProtocol::Mrp,
                role: None,
                ring_id: None,
                priority: None,
                source_mac: source_mac.to_string(),
                details: format!("MRP PDU type=0x{pdu_type:04X}"),
                is_manager: false,
                topology_change: false,
            })
        }
    }
}

// ─── HSR ──────────────────────────────────────────────────────────────────────

/// Parse HSR (High-availability Seamless Redundancy) supervision frame.
///
/// HSR header (after Ethernet header, Ethertype 0x892F):
/// ```text
/// [0..1]  Path (0x0000=PortA, 0x0400=PortB)
/// [2..3]  SeqNr (sequence number)
/// [4..5]  Encapsulated Ethertype (the real protocol inside)
/// Then the supervision payload:
///   [0..1]  TLV Type (0x0023 = HSRP supervision)
///   [2..3]  TLV Length
///   [4..9]  Source MAC
/// ```
fn parse_hsr(payload: &[u8], source_mac: &str) -> Option<RedundancyInfo> {
    if payload.len() < 6 {
        return Some(RedundancyInfo {
            protocol: RedundancyProtocol::Hsr,
            role: Some("hsr-node".to_string()),
            ring_id: None,
            priority: None,
            source_mac: source_mac.to_string(),
            details: "HSR frame (insufficient data for detail)".to_string(),
            is_manager: false,
            topology_change: false,
        });
    }
    let path = u16::from_be_bytes([payload[0], payload[1]]);
    let seq_nr = u16::from_be_bytes([payload[2], payload[3]]);
    let port = if path == 0x0400 { "B" } else { "A" };

    Some(RedundancyInfo {
        protocol: RedundancyProtocol::Hsr,
        role: Some("hsr-node".to_string()),
        ring_id: Some(seq_nr),
        priority: None,
        source_mac: source_mac.to_string(),
        details: format!("HSR supervision: port={port} seq={seq_nr}"),
        is_manager: false,
        topology_change: false,
    })
}

// ─── PRP ──────────────────────────────────────────────────────────────────────

/// Parse PRP (Parallel Redundancy Protocol) supervision frame.
///
/// PRP supervision frame (Ethertype 0x88FB or dst 01:15:4E:00:01:00):
/// ```text
/// [0..1]  TLV Type (0x0020 = PRP supervision)
/// [2..3]  TLV Length
/// [4..5]  RedBox MAC address high (or 0x0000 for DANP nodes)
/// [6..9]  RedBox MAC address remaining
/// ```
fn parse_prp(payload: &[u8], source_mac: &str) -> Option<RedundancyInfo> {
    let seq_nr = if payload.len() >= 4 {
        Some(u16::from_be_bytes([payload[2], payload[3]]))
    } else {
        None
    };

    Some(RedundancyInfo {
        protocol: RedundancyProtocol::Prp,
        role: Some("prp-node".to_string()),
        ring_id: seq_nr,
        priority: None,
        source_mac: source_mac.to_string(),
        details: "PRP supervision frame (parallel redundancy active)".to_string(),
        is_manager: false,
        topology_change: false,
    })
}

// ─── DLR ──────────────────────────────────────────────────────────────────────

/// Parse DLR (Device Level Ring) frame.
///
/// DLR frame layout (after Ethernet header, Ethertype 0x80E1):
/// ```text
/// [0]  Frame Type:
///       0x00 = Beacon (from Active Supervisor)
///       0x02 = Announce
///       0x03 = Sign_On
///       0x04 = Advertise (from Active Supervisor)
/// [1]  Frame Sub-Type
/// [2]  Protocol Version
/// [3]  Reserved
/// For Beacon:
///   [4]  Ring State (0x01=Normal, 0x02=Ring_Fault)
///   [5]  Reserved
///   [6..7]  Supervisor Precedence (for supervisor election, higher = preferred)
///   ...
/// ```
fn parse_dlr(payload: &[u8], source_mac: &str) -> Option<RedundancyInfo> {
    if payload.is_empty() {
        return None;
    }
    let frame_type = payload[0];
    match frame_type {
        0x00 => {
            // Beacon — sent by Active Supervisor to detect ring breaks
            let ring_state = payload.get(4).copied().unwrap_or(0);
            let ring_ok = ring_state == 0x01;
            let precedence = if payload.len() >= 8 {
                Some(u16::from_be_bytes([payload[6], payload[7]]))
            } else {
                None
            };
            let ring_state_str = if ring_ok { "normal" } else { "ring-fault" };

            Some(RedundancyInfo {
                protocol: RedundancyProtocol::Dlr,
                role: Some("active-supervisor".to_string()),
                ring_id: None,
                priority: precedence,
                source_mac: source_mac.to_string(),
                details: format!("DLR Beacon: ring-state={ring_state_str}"),
                is_manager: true,
                topology_change: !ring_ok,
            })
        }
        0x04 => {
            // Advertise — supervisor advertising itself
            Some(RedundancyInfo {
                protocol: RedundancyProtocol::Dlr,
                role: Some("active-supervisor".to_string()),
                ring_id: None,
                priority: None,
                source_mac: source_mac.to_string(),
                details: "DLR Advertise: active supervisor announcement".to_string(),
                is_manager: true,
                topology_change: false,
            })
        }
        _ => {
            // Other DLR frame types (Announce, Sign_On, etc.)
            Some(RedundancyInfo {
                protocol: RedundancyProtocol::Dlr,
                role: Some("dlr-node".to_string()),
                ring_id: None,
                priority: None,
                source_mac: source_mac.to_string(),
                details: format!("DLR frame type=0x{frame_type:02X}"),
                is_manager: false,
                topology_change: false,
            })
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a full Ethernet frame for RSTP BPDU (RST Config BPDU).
    fn build_rstp_frame(bpdu_type: u8, flags: u8, is_root: bool) -> Vec<u8> {
        let mut frame = Vec::new();
        // Dst MAC: 01:80:C2:00:00:00 (STP multicast)
        frame.extend_from_slice(&[0x01, 0x80, 0xC2, 0x00, 0x00, 0x00]);
        // Src MAC
        let src = if is_root {
            [0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]
        } else {
            [0x11, 0x22, 0x33, 0x00, 0x00, 0x02]
        };
        frame.extend_from_slice(&src);
        // Length (not Ethertype): 38 bytes of payload
        frame.extend_from_slice(&[0x00, 0x26]);
        // LLC: DSAP=0x42, SSAP=0x42, Ctrl=0x03
        frame.extend_from_slice(&[0x42, 0x42, 0x03]);
        // Protocol ID: 0x0000
        frame.extend_from_slice(&[0x00, 0x00]);
        // Protocol Version: 0x02 (RSTP)
        frame.push(0x02);
        // BPDU Type
        frame.push(bpdu_type);
        // Flags
        frame.push(flags);
        // Root Bridge ID: priority=0x8000, MAC=AA:BB:CC:00:00:01
        frame.extend_from_slice(&[0x80, 0x00]);
        frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]);
        // Root Path Cost: 200000
        frame.extend_from_slice(&[0x00, 0x03, 0x0D, 0x40]);
        // Bridge ID: varies
        if is_root {
            frame.extend_from_slice(&[0x80, 0x00]);
            frame.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]);
        } else {
            frame.extend_from_slice(&[0x80, 0x00]);
            frame.extend_from_slice(&[0x11, 0x22, 0x33, 0x00, 0x00, 0x02]);
        }
        // Port ID
        frame.extend_from_slice(&[0x80, 0x01]);
        frame
    }

    #[test]
    fn test_detect_rstp_frame() {
        let frame = build_rstp_frame(0x02, 0x0C, false); // Designated port
        assert_eq!(detect_protocol(&frame), Some(RedundancyProtocol::Rstp));
    }

    #[test]
    fn test_detect_mrp_ethertype() {
        let mut frame = vec![0u8; 16];
        // Dst = MRP_Test multicast
        frame[0..6].copy_from_slice(&[0x01, 0x15, 0x4E, 0x00, 0x01, 0x01]);
        frame[6..12].copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        // Ethertype = 0x88E3 (MRP)
        frame[12..14].copy_from_slice(&[0x88, 0xE3]);
        assert_eq!(detect_protocol(&frame), Some(RedundancyProtocol::Mrp));
    }

    #[test]
    fn test_detect_dlr_ethertype() {
        let mut frame = vec![0u8; 16];
        frame[0..6].copy_from_slice(&[0x01, 0x21, 0x6C, 0x00, 0x00, 0x01]);
        frame[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]);
        frame[12..14].copy_from_slice(&[0x80, 0xE1]);
        assert_eq!(detect_protocol(&frame), Some(RedundancyProtocol::Dlr));
    }

    #[test]
    fn test_detect_hsr_ethertype() {
        let mut frame = vec![0u8; 20];
        frame[6..12].copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]);
        frame[12..14].copy_from_slice(&[0x89, 0x2F]);
        assert_eq!(detect_protocol(&frame), Some(RedundancyProtocol::Hsr));
    }

    #[test]
    fn test_detect_prp_supervision_mac() {
        let mut frame = vec![0u8; 16];
        // PRP supervision dst MAC
        frame[0..6].copy_from_slice(&[0x01, 0x15, 0x4E, 0x00, 0x01, 0x00]);
        frame[6..12].copy_from_slice(&[0xAA, 0x00, 0x00, 0x00, 0x00, 0x01]);
        frame[12..14].copy_from_slice(&[0x88, 0xFB]);
        assert_eq!(detect_protocol(&frame), Some(RedundancyProtocol::Prp));
    }

    #[test]
    fn test_parse_rstp_root_bridge() {
        let frame = build_rstp_frame(0x02, 0x0C, true); // Root device, designated port
        // Payload = frame[14..]
        let payload = &frame[14..];
        let src_mac = "aa:bb:cc:00:00:01";
        let info = parse_rstp(payload, src_mac).expect("should parse RSTP root bridge");
        assert_eq!(info.protocol, RedundancyProtocol::Rstp);
        assert_eq!(info.role.as_deref(), Some("root-bridge"));
        assert!(info.is_manager);
    }

    #[test]
    fn test_parse_rstp_tcn() {
        // TCN BPDU: version=0, type=0x80
        let mut payload = vec![0x42, 0x42, 0x03, 0x00, 0x00, 0x00, 0x80];
        // Flags byte (0x00) - no TC, no Ack
        payload.push(0x00);
        let info = parse_rstp(&payload, "11:22:33:00:00:02").expect("should parse TCN");
        assert!(info.topology_change);
        assert_eq!(info.role.as_deref(), Some("bridge"));
    }

    #[test]
    fn test_parse_mrp_test() {
        // MRP_Test PDU with priority 0x8000
        let payload: Vec<u8> = vec![
            0x00, 0x01, // PDU type = MRP_Test
            0x00, 0x18, // TLV length = 24
            0x80, 0x00, // Prio = 0x8000
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // SA
            0x00, 0x00, // Port Role = Primary
            0x00, 0x01, // Ring State = RC_Closed (healthy)
            0x00, 0x00, // Transition
            0x00, 0x00, // Timestamp
        ];
        let info = parse_mrp(&payload, "00:01:02:03:04:05").expect("should parse MRP_Test");
        assert_eq!(info.protocol, RedundancyProtocol::Mrp);
        assert_eq!(info.role.as_deref(), Some("ring-manager"));
        assert!(info.is_manager);
        assert_eq!(info.priority, Some(0x8000));
    }

    #[test]
    fn test_parse_mrp_topology_change() {
        let payload: Vec<u8> = vec![
            0x00, 0x02, // PDU type = MRP_TopologyChange
            0x00, 0x04, // length
            0x00, 0x00, 0x00, 0x00,
        ];
        let info = parse_mrp(&payload, "00:01:02:03:04:05").expect("should parse MRP_TC");
        assert!(info.topology_change);
        assert!(info.is_manager);
    }

    #[test]
    fn test_parse_dlr_beacon_ring_fault() {
        let mut payload = vec![0u8; 10];
        payload[0] = 0x00; // Frame type = Beacon
        payload[4] = 0x02; // Ring state = ring-fault
        payload[6] = 0x00;
        payload[7] = 0x64; // Precedence = 100
        let info = parse_dlr(&payload, "aa:bb:cc:00:00:01").expect("should parse DLR beacon");
        assert_eq!(info.protocol, RedundancyProtocol::Dlr);
        assert!(info.is_manager);
        assert!(info.topology_change);
        assert!(info.details.contains("ring-fault"));
    }

    #[test]
    fn test_non_redundancy_frame_returns_none() {
        let mut frame = vec![0u8; 60];
        // Normal unicast ethernet with IP Ethertype
        frame[0..6].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        frame[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
        assert!(detect_protocol(&frame).is_none());
    }
}
