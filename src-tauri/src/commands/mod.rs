pub mod system;
pub mod capture;
pub mod data;
pub mod processor;
pub mod signatures;
pub mod session;
pub mod projects;
pub mod physical;
pub mod ingest;
pub mod wireshark;
pub mod export;
pub mod analysis;
pub mod baseline;
pub mod patterns;
pub mod correlation;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::thread::JoinHandle;
use gm_capture::LiveCaptureHandle;
use gm_topology::TopologyGraph;
use gm_parsers::IcsProtocol;
use gm_signatures::SignatureEngine;
use gm_db::{Database, OuiLookup, GeoIpLookup};
use gm_physical::{PhysicalTopology, InferredTopology};
use gm_analysis::{Finding, PurdueAssignment, AnomalyScore, ConnectionStats, PatternAnomaly};
use gm_parsers::RedundancyInfo;
use serde::{Serialize, Deserialize};

/// Shared application state, managed by Tauri.
///
/// This is wrapped in Mutex for thread-safe access from command handlers.
/// Tauri's state management ensures this is available to all commands
/// via the `State<'_, AppState>` parameter.
pub struct AppState {
    pub inner: Mutex<AppStateInner>,
    /// Set to true to cancel an in-progress PCAP import. Lives outside the
    /// Mutex so it can be read/written by the import thread and the cancel
    /// command without acquiring the heavy state lock.
    pub import_cancelled: Arc<AtomicBool>,
}

pub struct AppStateInner {
    /// The current network topology graph
    pub topology: TopologyGraph,
    /// All discovered assets
    pub assets: Vec<AssetInfo>,
    /// All observed connections
    pub connections: Vec<ConnectionInfo>,
    /// Packet summaries grouped by connection ID, for the connection tree
    pub packet_summaries: HashMap<String, Vec<PacketSummary>>,
    /// List of imported PCAP files
    pub imported_files: Vec<String>,
    /// Signature engine for device fingerprinting
    pub signature_engine: SignatureEngine,
    /// Deep parse results grouped by IP address
    pub deep_parse_info: HashMap<String, DeepParseInfo>,
    /// Handle to the running live capture (None if not capturing)
    pub live_capture: Option<LiveCaptureHandle>,
    /// Join handle for the live capture processing thread
    pub processing_thread: Option<JoinHandle<()>>,
    /// IEEE OUI vendor lookup table
    pub oui_lookup: OuiLookup,
    /// GeoIP country lookup
    pub geoip_lookup: GeoIpLookup,
    /// SQLite database for persistence
    pub db: Option<Database>,
    /// Currently loaded session ID (None if no session loaded)
    pub current_session_id: Option<String>,
    /// Currently loaded session name
    pub current_session_name: Option<String>,
    /// Active project ID (None if no project selected)
    pub current_project_id: Option<i64>,
    /// Physical topology from Cisco/JunOS/Aruba config/CAM/CDP/ARP imports
    pub physical_topology: PhysicalTopology,
    /// Traffic-inferred topology from packet analysis
    pub inferred_topology: Option<InferredTopology>,
    /// Security findings from the last analysis run
    pub findings: Vec<Finding>,
    /// Purdue level assignments from the last analysis run
    pub purdue_assignments: Vec<PurdueAssignment>,
    /// Anomaly scores from the last analysis run
    pub anomalies: Vec<AnomalyScore>,
    /// Per-connection timing statistics (computed after import / capture)
    pub connection_stats: Vec<ConnectionStats>,
    /// Communication pattern anomalies (computed alongside connection_stats)
    pub pattern_anomalies: Vec<PatternAnomaly>,
    /// Redundancy protocol frames observed (MRP/RSTP/HSR/PRP/DLR)
    pub redundancy_protocols: Vec<RedundancyInfo>,
    /// Alerts imported from external IDS/SIEM tools (Suricata, Wazuh)
    pub imported_alerts: Vec<StoredAlert>,
    /// Per-device Zeek event summaries (rebuilt on each Zeek import)
    pub zeek_device_events: HashMap<String, DeviceZeekEvents>,
}

/// An alert imported from an external IDS/SIEM and stored in AppState.
///
/// Flattened from IngestedAlert for direct serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAlert {
    /// RFC 3339 timestamp of the alert
    pub timestamp: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    /// IDS signature/rule ID (e.g. Suricata SID or Wazuh rule ID)
    pub signature_id: u64,
    /// Human-readable rule description
    pub signature: String,
    /// Alert category (e.g. "Attempted Attack", "ics")
    pub category: String,
    /// Severity: 1 = high, 2 = medium, 3 = low
    pub severity: u8,
    /// Source tool name: "Suricata" or "Wazuh"
    pub source: String,
}

/// A single Zeek-observed event summarised for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeekEventSummary {
    /// RFC 3339 timestamp (connection first_seen)
    pub timestamp: String,
    /// Zeek log type: "conn", "modbus", "dnp3", "s7comm", "dns", "http"
    pub log_type: String,
    /// The remote peer IP address
    pub peer_ip: String,
    /// One-line human-readable summary
    pub summary: String,
}

/// Per-device aggregate of Zeek-observed events.
///
/// Built from connections that have "[Zeek]" in their origin_files.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceZeekEvents {
    pub device_ip: String,
    /// Total conn.log-type entries for this device
    pub conn_log_entries: u32,
    pub modbus_events: u32,
    pub dnp3_events: u32,
    pub dns_queries: u32,
    pub http_requests: u32,
    /// Unique peer IPs this device communicated with in Zeek data
    pub unique_peers: u32,
    /// Number of Suricata/Wazuh alerts correlated with this device
    pub alert_count: u32,
    /// Sample events (capped at 50)
    pub sample_events: Vec<ZeekEventSummary>,
}

/// Asset information stored in application state.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Overall confidence score (1-5), highest from any signature match
    pub confidence: u8,
    /// Vendor-specific product identification from signatures
    pub product_family: Option<String>,
    /// All signature matches for this asset
    pub signature_matches: Vec<AssetSignatureMatch>,
    /// Vendor name from IEEE OUI database (MAC prefix lookup)
    #[serde(default)]
    pub oui_vendor: Option<String>,
    /// ISO 3166-1 alpha-2 country code (public IPs only)
    #[serde(default)]
    pub country: Option<String>,
    /// Whether this IP is a public (routable) address
    #[serde(default)]
    pub is_public_ip: bool,
}

/// A signature match result attached to an asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSignatureMatch {
    pub signature_name: String,
    pub confidence: u8,
    pub vendor: Option<String>,
    pub product_family: Option<String>,
    pub device_type: Option<String>,
    pub role: Option<String>,
}

/// Connection information stored in application state.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Which PCAP files contributed packets to this connection
    pub origin_files: Vec<String>,
}

/// Lightweight packet summary for the connection tree detail view.
/// Full payload is not included — this is for display only.
#[derive(Debug, Clone, Serialize)]
pub struct PacketSummary {
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub origin_file: String,
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

/// Aggregated deep parse information for a single device (IP address).
///
/// Collects all Modbus/DNP3/EtherNet-IP/S7comm/BACnet details observed across
/// every packet for a given IP, including function codes, roles, and
/// security-relevant flags for ATT&CK detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeepParseInfo {
    /// Modbus-specific details (present if device speaks Modbus)
    pub modbus: Option<ModbusDetail>,
    /// DNP3-specific details (present if device speaks DNP3)
    pub dnp3: Option<Dnp3Detail>,
    /// EtherNet/IP details (present if device speaks EtherNet/IP)
    pub enip: Option<EnipDetail>,
    /// S7comm details (present if device speaks S7comm)
    pub s7: Option<S7Detail>,
    /// BACnet details (present if device speaks BACnet)
    pub bacnet: Option<BacnetDetail>,
    /// IEC 60870-5-104 details (present if device speaks IEC 104)
    pub iec104: Option<Iec104Detail>,
    /// PROFINET DCP details (present if device speaks PROFINET DCP)
    pub profinet_dcp: Option<ProfinetDcpDetail>,
    /// LLDP details (present if device advertised itself via LLDP)
    pub lldp: Option<LldpDetail>,
    /// SNMP device identity (present if device responded to SNMP GET)
    pub snmp: Option<SnmpDetail>,
}

/// EtherNet/IP aggregated details for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnipDetail {
    /// Detected role: "scanner" (client) or "adapter" (server)
    pub role: String,
    /// IP sent CIP Write or ReadModifyWrite to an Assembly object
    pub cip_writes_to_assembly: bool,
    /// IP accessed CIP File class (firmware/program operations)
    pub cip_file_access: bool,
    /// IP sent ListIdentity requests (network discovery)
    pub list_identity_requests: bool,
}

/// S7comm aggregated details for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S7Detail {
    /// Detected role: "client" or "server"
    pub role: String,
    /// S7 functions observed from this device (snake_case names, sorted)
    pub functions_seen: Vec<String>,
}

/// BACnet aggregated details for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacnetDetail {
    /// Detected role: "client" or "server"
    pub role: String,
    /// WriteProperty to AnalogOutput or BinaryOutput was seen
    pub write_to_output: bool,
    /// WriteProperty to NotificationClass was seen (alarm suppression)
    pub write_to_notification_class: bool,
    /// ReinitializeDevice service was seen
    pub reinitialize_device: bool,
    /// DeviceCommunicationControl service was seen
    pub device_communication_control: bool,
}

/// PROFINET DCP aggregated details for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfinetDcpDetail {
    /// Detected role: "io_device", "io_controller", "io_supervisor", or "unknown"
    pub role: String,
    /// Station name from DCP Name-of-Station block
    pub device_name: Option<String>,
}

/// LLDP (Link Layer Discovery Protocol) details for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldpDetail {
    /// System name (hostname) from LLDP Type 5
    pub system_name: Option<String>,
    /// System description from LLDP Type 6
    pub system_description: Option<String>,
    /// Chassis identifier (MAC or string)
    pub chassis_id: Option<String>,
    /// Port identifier
    pub port_id: Option<String>,
    /// Capability summary string, e.g. "Bridge, Router"
    pub capability_summary: Option<String>,
    /// Management addresses advertised
    pub management_addresses: Vec<String>,
    /// VLAN IDs from 802.1 org-specific TLVs
    pub vlan_ids: Vec<u16>,
    /// Vendor inferred from description
    pub vendor: Option<String>,
    /// Model inferred from description
    pub model: Option<String>,
    /// Firmware version inferred from description
    pub firmware: Option<String>,
}

/// SNMP device identity extracted from GET-Response packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnmpDetail {
    /// sysDescr — free-text description of the device
    pub sys_descr: Option<String>,
    /// sysName — administratively assigned hostname
    pub sys_name: Option<String>,
    /// sysLocation — physical location string
    pub sys_location: Option<String>,
    /// sysObjectID — vendor's authoritative OID for this device type
    pub sys_object_id: Option<String>,
    /// sysUpTime in centiseconds
    pub sys_uptime_cs: Option<u32>,
    /// sysContact — contact person / email
    pub sys_contact: Option<String>,
    /// Vendor name inferred from enterprise OID
    pub vendor: Option<String>,
}

/// IEC 60870-5-104 aggregated details for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iec104Detail {
    /// Detected role: "master" or "outstation"
    pub role: String,
    /// Device sent control command ASDUs (type IDs 45–69)
    pub has_control_commands: bool,
    /// Device sent Reset Process command (type ID 105)
    pub has_reset_process: bool,
    /// Device sent General Interrogation (type ID 100)
    pub has_interrogation: bool,
}

/// Aggregated Modbus details for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusDetail {
    /// Detected role: "master", "slave", or "both"
    pub role: String,
    /// Unit IDs seen on this device (slave → responds as; master → polls)
    pub unit_ids: Vec<u8>,
    /// Function codes observed (code → count)
    pub function_codes: Vec<FunctionCodeStat>,
    /// Register ranges accessed
    pub register_ranges: Vec<RegisterRangeInfo>,
    /// Device identification from FC 43/14 (if extracted)
    pub device_id: Option<ModbusDeviceIdInfo>,
    /// IPs this device communicates with, with roles
    pub relationships: Vec<ModbusRelationship>,
    /// Polling intervals detected (in milliseconds)
    pub polling_intervals: Vec<PollingInterval>,
}

/// DNP3 aggregated details for a device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dnp3Detail {
    /// Detected role: "master", "outstation", or "both"
    pub role: String,
    /// DNP3 addresses used by this device
    pub addresses: Vec<u16>,
    /// Function codes observed (code → count)
    pub function_codes: Vec<FunctionCodeStat>,
    /// Whether unsolicited responses were detected from this device
    pub has_unsolicited: bool,
    /// IPs this device communicates with
    pub relationships: Vec<Dnp3Relationship>,
}

/// Function code usage statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCodeStat {
    pub code: u8,
    pub name: String,
    pub count: u64,
    /// Whether this is a write/control operation (security-relevant)
    pub is_write: bool,
}

/// Register range accessed by a Modbus device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRangeInfo {
    pub start: u16,
    pub count: u16,
    pub register_type: String,
    /// How many times this range was accessed
    pub access_count: u64,
}

/// Modbus device identification from FC 43/14.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusDeviceIdInfo {
    pub vendor_name: Option<String>,
    pub product_code: Option<String>,
    pub revision: Option<String>,
    pub vendor_url: Option<String>,
    pub product_name: Option<String>,
    pub model_name: Option<String>,
}

/// A relationship between Modbus master/slave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModbusRelationship {
    pub remote_ip: String,
    /// "master" or "slave" — what the REMOTE device is
    pub remote_role: String,
    pub unit_ids: Vec<u8>,
    pub packet_count: u64,
}

/// A relationship between DNP3 master/outstation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dnp3Relationship {
    pub remote_ip: String,
    /// "master" or "outstation"
    pub remote_role: String,
    pub packet_count: u64,
}

/// Detected polling interval for a master→slave relationship.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollingInterval {
    pub remote_ip: String,
    pub unit_id: Option<u8>,
    pub function_code: u8,
    /// Average interval in milliseconds
    pub avg_interval_ms: f64,
    /// Minimum interval observed
    pub min_interval_ms: f64,
    /// Maximum interval observed
    pub max_interval_ms: f64,
    /// Number of samples used to compute the interval
    pub sample_count: u64,
}

impl AppState {
    pub fn new() -> Self {
        let mut engine = SignatureEngine::new();

        // Load default signatures from the bundled signatures/ directory.
        // Try multiple paths: relative to binary (production) and relative to src-tauri/ (dev).
        let signature_dirs = [
            std::path::PathBuf::from("signatures"),
            std::path::PathBuf::from("../src-tauri/signatures"),
            // When running via `cargo tauri dev`, CWD is the project root
            std::path::PathBuf::from("src-tauri/signatures"),
        ];

        for dir in &signature_dirs {
            if dir.exists() {
                match engine.load_directory(dir) {
                    Ok(count) => {
                        log::info!("Loaded {} signatures from {}", count, dir.display());
                        break;
                    }
                    Err(e) => {
                        log::warn!("Failed to load signatures from {}: {}", dir.display(), e);
                    }
                }
            }
        }

        // Load OUI database
        let oui_paths = [
            std::path::PathBuf::from("data/oui.tsv"),
            std::path::PathBuf::from("../src-tauri/data/oui.tsv"),
            std::path::PathBuf::from("src-tauri/data/oui.tsv"),
        ];
        let mut oui_lookup = OuiLookup::empty();
        for path in &oui_paths {
            if path.exists() {
                match OuiLookup::load_from_file(path) {
                    Ok(lookup) => {
                        oui_lookup = lookup;
                        break;
                    }
                    Err(e) => {
                        log::warn!("Failed to load OUI from {}: {}", path.display(), e);
                    }
                }
            }
        }

        // Load GeoIP database
        let geoip_paths = [
            std::path::PathBuf::from("data/dbip-country-lite.mmdb"),
            std::path::PathBuf::from("../src-tauri/data/dbip-country-lite.mmdb"),
            std::path::PathBuf::from("src-tauri/data/dbip-country-lite.mmdb"),
        ];
        let mut geoip_lookup = GeoIpLookup::empty();
        for path in &geoip_paths {
            if path.exists() {
                match GeoIpLookup::load_from_file(path) {
                    Ok(lookup) => {
                        geoip_lookup = lookup;
                        break;
                    }
                    Err(e) => {
                        log::warn!("Failed to load GeoIP from {}: {}", path.display(), e);
                    }
                }
            }
        }

        // Open SQLite database at ~/.kusanaginokajiki/data.db
        let db = match dirs::home_dir() {
            Some(home) => {
                let db_path = home.join(".kusanaginokajiki").join("data.db");
                match Database::open(&db_path) {
                    Ok(db) => Some(db),
                    Err(e) => {
                        log::warn!("Failed to open database at {}: {}", db_path.display(), e);
                        None
                    }
                }
            }
            None => {
                log::warn!("Could not determine home directory for database");
                None
            }
        };

        AppState {
            import_cancelled: Arc::new(AtomicBool::new(false)),
            inner: Mutex::new(AppStateInner {
                topology: TopologyGraph::default(),
                assets: Vec::new(),
                connections: Vec::new(),
                packet_summaries: HashMap::new(),
                imported_files: Vec::new(),
                signature_engine: engine,
                deep_parse_info: HashMap::new(),
                live_capture: None,
                processing_thread: None,
                oui_lookup,
                geoip_lookup,
                db,
                current_session_id: None,
                current_session_name: None,
                current_project_id: None,
                physical_topology: PhysicalTopology::default(),
                inferred_topology: None,
                findings: Vec::new(),
                purdue_assignments: Vec::new(),
                anomalies: Vec::new(),
                connection_stats: Vec::new(),
                pattern_anomalies: Vec::new(),
                redundancy_protocols: Vec::new(),
                imported_alerts: Vec::new(),
                zeek_device_events: HashMap::new(),
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
    let has_ge_srtp = protocols.contains(&IcsProtocol::GeSrtp);
    let has_suitelink = protocols.contains(&IcsProtocol::WonderwareSuitelink);

    let ot_protocol_count = protocols.iter().filter(|p| p.is_ot()).count();

    if is_server && ot_protocol_count >= 1 {
        // Server responding on OT ports → likely PLC/RTU
        if has_ethernet_ip || has_s7 || has_ge_srtp || has_bacnet {
            // Allen-Bradley (EtherNet/IP), Siemens (S7), GE (SRTP), BACnet controller
            "plc".to_string()
        } else if has_modbus || has_dnp3 {
            "rtu".to_string()
        } else {
            "unknown".to_string()
        }
    } else if has_suitelink && is_server {
        "scada_server".to_string() // Wonderware SuiteLink server
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
