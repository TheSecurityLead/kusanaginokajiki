pub mod system;
pub mod capture;
pub mod data;

use std::sync::Mutex;
use gm_topology::TopologyGraph;
use gm_parsers::IcsProtocol;
use serde::Serialize;

/// Shared application state, managed by Tauri.
///
/// This is wrapped in Mutex for thread-safe access from command handlers.
/// Tauri's state management ensures this is available to all commands
/// via the `State<'_, AppState>` parameter.
pub struct AppState {
    pub inner: Mutex<AppStateInner>,
}

pub struct AppStateInner {
    /// The current network topology graph
    pub topology: TopologyGraph,
    /// All discovered assets
    pub assets: Vec<AssetInfo>,
    /// All observed connections
    pub connections: Vec<ConnectionInfo>,
}

/// Asset information stored in application state.
#[derive(Debug, Clone, Serialize)]
pub struct AssetInfo {
    pub id: String,
    pub ip_address: String,
    pub mac_address: Option<String>,
    pub hostname: Option<String>,
    pub device_type: String,
    pub vendor: Option<String>,
    pub protocols: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub notes: String,
    pub purdue_level: Option<u8>,
    pub tags: Vec<String>,
    pub packet_count: u64,
}

/// Connection information stored in application state.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    pub src_ip: String,
    pub src_port: u16,
    pub src_mac: Option<String>,
    pub dst_ip: String,
    pub dst_port: u16,
    pub dst_mac: Option<String>,
    pub protocol: String,
    pub transport: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

/// Protocol statistics.
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolStatInfo {
    pub protocol: String,
    pub packet_count: u64,
    pub byte_count: u64,
    pub connection_count: u64,
    pub unique_devices: u64,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            inner: Mutex::new(AppStateInner {
                topology: TopologyGraph::default(),
                assets: Vec::new(),
                connections: Vec::new(),
            }),
        }
    }
}

/// Infer device type based on which protocols it speaks and its role.
pub fn infer_device_type(protocols: &[IcsProtocol], is_server: bool) -> String {
    // If it responds on OT protocol ports, it's likely an OT device
    let has_modbus = protocols.contains(&IcsProtocol::Modbus);
    let has_dnp3 = protocols.contains(&IcsProtocol::Dnp3);
    let has_ethernet_ip = protocols.contains(&IcsProtocol::EthernetIp);
    let has_s7 = protocols.contains(&IcsProtocol::S7comm);
    let has_bacnet = protocols.contains(&IcsProtocol::Bacnet);
    let has_opc_ua = protocols.contains(&IcsProtocol::OpcUa);

    let ot_protocol_count = [has_modbus, has_dnp3, has_ethernet_ip, has_s7, has_bacnet, has_opc_ua]
        .iter()
        .filter(|&&x| x)
        .count();

    if is_server && ot_protocol_count >= 1 {
        // Server responding on OT ports → likely PLC/RTU
        if has_ethernet_ip {
            "plc".to_string() // Allen-Bradley / Rockwell
        } else if has_s7 {
            "plc".to_string() // Siemens
        } else if has_modbus || has_dnp3 {
            "rtu".to_string()
        } else if has_bacnet {
            "plc".to_string() // BACnet controller
        } else {
            "unknown".to_string()
        }
    } else if ot_protocol_count >= 2 {
        // Client talking multiple OT protocols → likely HMI or SCADA server
        "hmi".to_string()
    } else if has_opc_ua && ot_protocol_count == 1 {
        "historian".to_string()
    } else if ot_protocol_count == 0 {
        "it_device".to_string()
    } else {
        "unknown".to_string()
    }
}
