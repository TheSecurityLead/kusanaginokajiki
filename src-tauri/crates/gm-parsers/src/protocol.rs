use serde::{Deserialize, Serialize};
use gm_capture::ParsedPacket;

/// ICS/SCADA and common IT protocols recognized by Kusanagi Kajiki.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IcsProtocol {
    /// Modbus TCP (Modicon, port 502)
    Modbus,
    /// DNP3 / IEEE 1815 (port 20000)
    Dnp3,
    /// EtherNet/IP — CIP over TCP/UDP (port 44818, 2222)
    EthernetIp,
    /// BACnet/IP — building automation (port 47808)
    Bacnet,
    /// S7comm — Siemens (port 102, ISO-TSAP)
    S7comm,
    /// OPC UA — modern ICS standard (port 4840)
    OpcUa,
    /// PROFINET (various ports)
    Profinet,
    /// IEC 60870-5-104 (port 2404)
    Iec104,
    /// MQTT — IoT/IIoT messaging (port 1883, 8883)
    Mqtt,
    /// HART-IP — process instrumentation (port 5094)
    HartIp,
    /// Foundation Fieldbus HSE (ports 1089-1091)
    FoundationFieldbus,
    /// GE SRTP — GE PLCs (ports 18245-18246)
    GeSrtp,
    /// Wonderware SuiteLink (port 5007)
    WonderwareSuitelink,

    // Common IT protocols for context
    Http,
    Https,
    Dns,
    Ssh,
    Rdp,
    Snmp,

    /// Protocol could not be identified
    Unknown,
}

impl IcsProtocol {
    /// Parse a protocol name string back into an IcsProtocol variant.
    ///
    /// Accepts the snake_case serde names (e.g., "modbus", "ethernet_ip")
    /// as well as common display names. Returns Unknown for unrecognized strings.
    pub fn from_name(name: &str) -> Self {
        match name {
            "modbus" => IcsProtocol::Modbus,
            "dnp3" => IcsProtocol::Dnp3,
            "ethernet_ip" => IcsProtocol::EthernetIp,
            "bacnet" => IcsProtocol::Bacnet,
            "s7comm" => IcsProtocol::S7comm,
            "opc_ua" => IcsProtocol::OpcUa,
            "profinet" => IcsProtocol::Profinet,
            "iec104" => IcsProtocol::Iec104,
            "mqtt" => IcsProtocol::Mqtt,
            "hart_ip" => IcsProtocol::HartIp,
            "foundation_fieldbus" => IcsProtocol::FoundationFieldbus,
            "ge_srtp" => IcsProtocol::GeSrtp,
            "wonderware_suitelink" => IcsProtocol::WonderwareSuitelink,
            "http" => IcsProtocol::Http,
            "https" => IcsProtocol::Https,
            "dns" => IcsProtocol::Dns,
            "ssh" => IcsProtocol::Ssh,
            "rdp" => IcsProtocol::Rdp,
            "snmp" => IcsProtocol::Snmp,
            _ => IcsProtocol::Unknown,
        }
    }

    /// Returns true if this is an OT/ICS-specific protocol.
    pub fn is_ot(&self) -> bool {
        matches!(
            self,
            IcsProtocol::Modbus
                | IcsProtocol::Dnp3
                | IcsProtocol::EthernetIp
                | IcsProtocol::Bacnet
                | IcsProtocol::S7comm
                | IcsProtocol::OpcUa
                | IcsProtocol::Profinet
                | IcsProtocol::Iec104
                | IcsProtocol::Mqtt
                | IcsProtocol::HartIp
                | IcsProtocol::FoundationFieldbus
                | IcsProtocol::GeSrtp
                | IcsProtocol::WonderwareSuitelink
        )
    }

    /// Returns a human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            IcsProtocol::Modbus => "Modbus TCP",
            IcsProtocol::Dnp3 => "DNP3",
            IcsProtocol::EthernetIp => "EtherNet/IP",
            IcsProtocol::Bacnet => "BACnet/IP",
            IcsProtocol::S7comm => "S7comm",
            IcsProtocol::OpcUa => "OPC UA",
            IcsProtocol::Profinet => "PROFINET",
            IcsProtocol::Iec104 => "IEC 60870-5-104",
            IcsProtocol::Mqtt => "MQTT",
            IcsProtocol::HartIp => "HART-IP",
            IcsProtocol::FoundationFieldbus => "Foundation Fieldbus HSE",
            IcsProtocol::GeSrtp => "GE SRTP",
            IcsProtocol::WonderwareSuitelink => "Wonderware SuiteLink",
            IcsProtocol::Http => "HTTP",
            IcsProtocol::Https => "HTTPS/TLS",
            IcsProtocol::Dns => "DNS",
            IcsProtocol::Ssh => "SSH",
            IcsProtocol::Rdp => "RDP",
            IcsProtocol::Snmp => "SNMP",
            IcsProtocol::Unknown => "Unknown",
        }
    }
}

/// Identify the application-layer protocol of a parsed packet.
///
/// Currently uses port-based identification (Phase 1).
/// Payload-based deep inspection will be added in Phase 3.
pub fn identify_protocol(packet: &ParsedPacket) -> IcsProtocol {
    // First pass: port-based identification
    let by_port = identify_by_port(packet.src_port, packet.dst_port);

    if by_port != IcsProtocol::Unknown {
        return by_port;
    }

    // TODO Phase 3: Payload-based identification
    // - Check for Modbus MBAP header (transaction ID + protocol ID 0x0000)
    // - Check for DNP3 start bytes (0x0564)
    // - Check for EtherNet/IP encapsulation header
    // - Check for BACnet/IP BVLC header (0x81)

    IcsProtocol::Unknown
}

/// Identify protocol based on well-known port numbers.
///
/// Checks both source and destination ports — a server responding
/// FROM port 502 is still Modbus traffic.
pub fn identify_by_port(src_port: u16, dst_port: u16) -> IcsProtocol {
    // Check destination port first (more likely to match for client→server)
    // then source port (for server→client responses)
    let ports = [dst_port, src_port];

    for &port in &ports {
        match port {
            // ─── ICS/OT Protocols ─────────────────────────
            502 => return IcsProtocol::Modbus,
            20000 => return IcsProtocol::Dnp3,
            44818 | 2222 => return IcsProtocol::EthernetIp,
            47808 => return IcsProtocol::Bacnet,
            102 => return IcsProtocol::S7comm,
            4840 => return IcsProtocol::OpcUa,
            34962..=34964 => return IcsProtocol::Profinet,
            2404 => return IcsProtocol::Iec104,
            1883 | 8883 => return IcsProtocol::Mqtt,
            5094 => return IcsProtocol::HartIp,
            1089..=1091 => return IcsProtocol::FoundationFieldbus,
            18245 | 18246 => return IcsProtocol::GeSrtp,
            5007 => return IcsProtocol::WonderwareSuitelink,

            // ─── Common IT Protocols ──────────────────────
            80 | 8080 | 8443 => return IcsProtocol::Http,
            443 => return IcsProtocol::Https,
            53 => return IcsProtocol::Dns,
            22 => return IcsProtocol::Ssh,
            3389 => return IcsProtocol::Rdp,
            161 | 162 => return IcsProtocol::Snmp,

            _ => continue,
        }
    }

    IcsProtocol::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modbus_port_detection() {
        assert_eq!(identify_by_port(49152, 502), IcsProtocol::Modbus);
        assert_eq!(identify_by_port(502, 49152), IcsProtocol::Modbus);
    }

    #[test]
    fn test_dnp3_port_detection() {
        assert_eq!(identify_by_port(49152, 20000), IcsProtocol::Dnp3);
    }

    #[test]
    fn test_unknown_port() {
        assert_eq!(identify_by_port(12345, 54321), IcsProtocol::Unknown);
    }

    #[test]
    fn test_ot_classification() {
        assert!(IcsProtocol::Modbus.is_ot());
        assert!(IcsProtocol::Dnp3.is_ot());
        assert!(IcsProtocol::EthernetIp.is_ot());
        assert!(IcsProtocol::HartIp.is_ot());
        assert!(IcsProtocol::FoundationFieldbus.is_ot());
        assert!(IcsProtocol::GeSrtp.is_ot());
        assert!(IcsProtocol::WonderwareSuitelink.is_ot());
        assert!(IcsProtocol::Mqtt.is_ot());
        assert!(!IcsProtocol::Http.is_ot());
        assert!(!IcsProtocol::Dns.is_ot());
        assert!(!IcsProtocol::Unknown.is_ot());
    }

    #[test]
    fn test_new_ot_port_detection() {
        assert_eq!(identify_by_port(49152, 5094), IcsProtocol::HartIp);
        assert_eq!(identify_by_port(49152, 1089), IcsProtocol::FoundationFieldbus);
        assert_eq!(identify_by_port(49152, 18245), IcsProtocol::GeSrtp);
        assert_eq!(identify_by_port(49152, 5007), IcsProtocol::WonderwareSuitelink);
        assert_eq!(identify_by_port(49152, 2404), IcsProtocol::Iec104);
        assert_eq!(identify_by_port(49152, 34962), IcsProtocol::Profinet);
    }
}
