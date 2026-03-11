//! Shared packet processing pipeline.
//!
//! `PacketProcessor` encapsulates the full processing pipeline used by both
//! PCAP import and live capture: protocol identification → deep parse →
//! connection tracking → topology building → signature matching.

use std::collections::{HashMap, HashSet};
use uuid::Uuid;

use gm_capture::ParsedPacket;
use gm_parsers::{
    identify_protocol, deep_parse, IcsProtocol, DeepParseResult,
    ModbusRole, ModbusDeviceId, Dnp3Role,
    modbus_function_code_name, dnp3_function_code_name,
    EnipRole, EnipCommand, CipService, CipClass,
    S7Role, S7Function,
    BacnetRole, BacnetService, BacnetObjectType,
    Iec104Role, AsduTypeId,
    ProfinetRole,
    LldpInfo, parse_lldp,
    RedundancyInfo, parse_redundancy,
    SnmpDeviceInfo, parse_snmp_response,
};
use gm_signatures::{PacketData, SignatureEngine};
use gm_topology::TopologyBuilder;
use gm_db::{OuiLookup, GeoIpLookup};
use gm_analysis::{ConnectionStats, PatternAnomaly, PatternAnalyzer};

use super::{
    AssetInfo, AssetSignatureMatch, ConnectionInfo, PacketSummary, infer_device_type,
    DeepParseInfo, ModbusDetail, Dnp3Detail, FunctionCodeStat, RegisterRangeInfo,
    ModbusDeviceIdInfo, ModbusRelationship, Dnp3Relationship, PollingInterval,
    EnipDetail, S7Detail, BacnetDetail, Iec104Detail, ProfinetDcpDetail, LldpDetail,
    SnmpDetail,
};

/// Well-known OT/ICS service ports — if a device listens on one of these,
/// it's considered a "server" (PLC/RTU/etc.) for classification purposes.
fn is_server_port(port: u16) -> bool {
    matches!(
        port,
        102 | 502 | 1089 | 1090 | 1091 | 1883 | 2222 | 2404 | 4840
            | 5007 | 5094 | 8883 | 18245 | 18246 | 20000 | 34962
            | 34963 | 34964 | 44818 | 47808
    )
}

/// Processes packets through the full pipeline:
/// protocol identification → deep parse → connection tracking → topology building.
///
/// Used by both PCAP import and live capture.
pub struct PacketProcessor {
    pub topo_builder: TopologyBuilder,
    connections: HashMap<String, ConnectionInfo>,
    packet_summaries: HashMap<String, Vec<PacketSummary>>,
    asset_protocols: HashMap<String, HashSet<IcsProtocol>>,
    asset_macs: HashMap<String, String>,
    asset_packet_counts: HashMap<String, u64>,
    asset_first_seen: HashMap<String, String>,
    asset_last_seen: HashMap<String, String>,
    server_ips: HashSet<String>,
    all_protocols: HashSet<String>,
    conn_origin_files: HashMap<String, HashSet<String>>,

    // Deep parse accumulators
    modbus_fc_counts: HashMap<String, HashMap<u8, u64>>,
    modbus_unit_ids: HashMap<String, HashSet<u8>>,
    #[allow(clippy::type_complexity)]
    modbus_register_ranges: HashMap<String, HashMap<(u16, u16, String), u64>>,
    modbus_roles: HashMap<String, HashSet<String>>,
    modbus_device_ids: HashMap<String, ModbusDeviceId>,
    #[allow(clippy::type_complexity)]
    modbus_relationships: HashMap<String, HashMap<String, (String, HashSet<u8>, u64)>>,
    modbus_polling_timestamps: HashMap<(String, String, u8, u8), Vec<f64>>,

    dnp3_fc_counts: HashMap<String, HashMap<u8, u64>>,
    dnp3_addresses: HashMap<String, HashSet<u16>>,
    dnp3_roles: HashMap<String, HashSet<String>>,
    dnp3_unsolicited: HashMap<String, bool>,
    dnp3_relationships: HashMap<String, HashMap<String, (String, u64)>>,

    // EtherNet/IP accumulators
    enip_roles: HashMap<String, String>,
    enip_cip_writes_to_assembly: HashSet<String>,
    enip_cip_file_access: HashSet<String>,
    enip_list_identity: HashSet<String>,

    // S7comm accumulators
    s7_roles: HashMap<String, String>,
    s7_functions_seen: HashMap<String, HashSet<String>>,

    // BACnet accumulators
    bacnet_roles: HashMap<String, String>,
    bacnet_write_to_output: HashSet<String>,
    bacnet_write_to_notification_class: HashSet<String>,
    bacnet_reinitialize: HashSet<String>,
    bacnet_device_comm_ctrl: HashSet<String>,

    // IEC 60870-5-104 accumulators
    iec104_roles: HashMap<String, String>,
    iec104_control_commands: HashSet<String>,
    iec104_reset_process: HashSet<String>,
    iec104_interrogation: HashSet<String>,

    // PROFINET DCP accumulators
    profinet_roles: HashMap<String, String>,
    profinet_device_names: HashMap<String, String>,

    // Signature matching data — accumulated per-IP
    ip_packets: HashMap<String, Vec<PacketData>>,

    /// LLDP info keyed by the sender MAC address (e.g. "aa:bb:cc:dd:ee:ff").
    /// Multiple LLDP frames from the same device are merged (last-write-wins).
    lldp_by_mac: HashMap<String, LldpInfo>,

    /// Redundancy protocol frames observed. Keyed by source MAC; last-write-wins
    /// within each MAC so we keep the most recent frame per sender.
    redundancy_by_mac: HashMap<String, RedundancyInfo>,

    /// SNMP device identity extracted from GET-Response packets.
    /// Keyed by the responding device's IP (src_ip when src_port == 161).
    snmp_device_info: HashMap<String, SnmpDeviceInfo>,

    /// Communication pattern analyzer — collects timestamps per connection pair
    pattern_analyzer: PatternAnalyzer,

    pub total_packets: u64,
}

impl PacketProcessor {
    pub fn new() -> Self {
        Self {
            topo_builder: TopologyBuilder::new(),
            connections: HashMap::new(),
            packet_summaries: HashMap::new(),
            asset_protocols: HashMap::new(),
            asset_macs: HashMap::new(),
            asset_packet_counts: HashMap::new(),
            asset_first_seen: HashMap::new(),
            asset_last_seen: HashMap::new(),
            server_ips: HashSet::new(),
            all_protocols: HashSet::new(),
            conn_origin_files: HashMap::new(),
            modbus_fc_counts: HashMap::new(),
            modbus_unit_ids: HashMap::new(),
            modbus_register_ranges: HashMap::new(),
            modbus_roles: HashMap::new(),
            modbus_device_ids: HashMap::new(),
            modbus_relationships: HashMap::new(),
            modbus_polling_timestamps: HashMap::new(),
            dnp3_fc_counts: HashMap::new(),
            dnp3_addresses: HashMap::new(),
            dnp3_roles: HashMap::new(),
            dnp3_unsolicited: HashMap::new(),
            dnp3_relationships: HashMap::new(),
            enip_roles: HashMap::new(),
            enip_cip_writes_to_assembly: HashSet::new(),
            enip_cip_file_access: HashSet::new(),
            enip_list_identity: HashSet::new(),
            s7_roles: HashMap::new(),
            s7_functions_seen: HashMap::new(),
            bacnet_roles: HashMap::new(),
            bacnet_write_to_output: HashSet::new(),
            bacnet_write_to_notification_class: HashSet::new(),
            bacnet_reinitialize: HashSet::new(),
            bacnet_device_comm_ctrl: HashSet::new(),
            iec104_roles: HashMap::new(),
            iec104_control_commands: HashSet::new(),
            iec104_reset_process: HashSet::new(),
            iec104_interrogation: HashSet::new(),
            profinet_roles: HashMap::new(),
            profinet_device_names: HashMap::new(),
            ip_packets: HashMap::new(),
            lldp_by_mac: HashMap::new(),
            redundancy_by_mac: HashMap::new(),
            snmp_device_info: HashMap::new(),
            pattern_analyzer: PatternAnalyzer::new(),
            total_packets: 0,
        }
    }

    /// Process a single packet through the pipeline.
    pub fn process_packet(&mut self, packet: &ParsedPacket) {
        // LLDP packets have a sentinel src_ip of "lldp:<mac>" — handle them
        // separately before the IP-based pipeline since they carry no IP header.
        if packet.src_ip.starts_with("lldp:") {
            if let Some(ref mac) = packet.src_mac {
                if let Some(lldp_info) = parse_lldp(&packet.payload) {
                    self.lldp_by_mac.insert(mac.clone(), lldp_info);
                }
            }
            return;
        }

        // Redundancy protocol packets (MRP/RSTP/HSR/PRP/DLR) use the sentinel
        // prefix "redundancy:<proto>" in src_ip. Parse and store by source MAC.
        if let Some(proto_hint) = packet.src_ip.strip_prefix("redundancy:") {
            if let Some(ref mac) = packet.src_mac {
                if let Some(info) = parse_redundancy(&packet.payload, proto_hint, mac) {
                    self.redundancy_by_mac.insert(mac.clone(), info);
                }
            }
            return;
        }

        let protocol = identify_protocol(packet);
        let proto_str = format!("{:?}", protocol);
        self.all_protocols.insert(proto_str.clone());
        self.total_packets += 1;

        let timestamp = packet.timestamp.to_rfc3339();

        // Track asset protocols
        self.asset_protocols
            .entry(packet.src_ip.clone())
            .or_default()
            .insert(protocol);
        self.asset_protocols
            .entry(packet.dst_ip.clone())
            .or_default()
            .insert(protocol);

        // Track MACs
        if let Some(ref mac) = packet.src_mac {
            self.asset_macs.entry(packet.src_ip.clone()).or_insert_with(|| mac.clone());
        }
        if let Some(ref mac) = packet.dst_mac {
            self.asset_macs.entry(packet.dst_ip.clone()).or_insert_with(|| mac.clone());
        }

        // Track packet counts
        *self.asset_packet_counts.entry(packet.src_ip.clone()).or_insert(0) += 1;
        *self.asset_packet_counts.entry(packet.dst_ip.clone()).or_insert(0) += 1;

        // Track timestamps
        self.asset_first_seen
            .entry(packet.src_ip.clone())
            .or_insert_with(|| timestamp.clone());
        self.asset_last_seen.insert(packet.src_ip.clone(), timestamp.clone());
        self.asset_first_seen
            .entry(packet.dst_ip.clone())
            .or_insert_with(|| timestamp.clone());
        self.asset_last_seen.insert(packet.dst_ip.clone(), timestamp.clone());

        // Detect servers using well-known OT service ports
        if is_server_port(packet.dst_port) {
            self.server_ips.insert(packet.dst_ip.clone());
        }
        if is_server_port(packet.src_port) {
            self.server_ips.insert(packet.src_ip.clone());
        }

        // Build connection key (directional: src→dst on protocol)
        let conn_key = format!(
            "{}:{}->{}:{}:{}",
            packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, proto_str
        );

        let conn = self.connections.entry(conn_key.clone()).or_insert_with(|| {
            ConnectionInfo {
                id: Uuid::new_v4().to_string(),
                src_ip: packet.src_ip.clone(),
                src_port: packet.src_port,
                src_mac: packet.src_mac.clone(),
                dst_ip: packet.dst_ip.clone(),
                dst_port: packet.dst_port,
                dst_mac: packet.dst_mac.clone(),
                protocol: proto_str.clone(),
                transport: format!("{:?}", packet.transport).to_lowercase(),
                packet_count: 0,
                byte_count: 0,
                first_seen: timestamp.clone(),
                last_seen: timestamp.clone(),
                origin_files: Vec::new(),
            }
        });

        conn.packet_count += 1;
        conn.byte_count += packet.length as u64;
        conn.last_seen = timestamp.clone();

        // Track origin files per connection
        self.conn_origin_files
            .entry(conn_key.clone())
            .or_default()
            .insert(packet.origin_file.clone());

        // Store packet summary (cap at 1000 per connection)
        let summaries = self.packet_summaries.entry(conn.id.clone()).or_default();
        if summaries.len() < 1000 {
            summaries.push(PacketSummary {
                timestamp,
                src_ip: packet.src_ip.clone(),
                dst_ip: packet.dst_ip.clone(),
                src_port: packet.src_port,
                dst_port: packet.dst_port,
                protocol: proto_str.clone(),
                length: packet.length,
                origin_file: packet.origin_file.clone(),
            });
        }

        // ── Deep Protocol Parsing ────────────────────────────────
        if let Some(deep_result) = deep_parse(packet, protocol) {
            let ts_epoch = packet.timestamp.timestamp() as f64
                + packet.timestamp.timestamp_subsec_millis() as f64 / 1000.0;

            match deep_result {
                DeepParseResult::Modbus(ref info) => {
                    self.process_modbus(packet, info, ts_epoch);
                }
                DeepParseResult::Dnp3(ref info) => {
                    self.process_dnp3(packet, info);
                }
                DeepParseResult::Enip(ref info) => {
                    self.process_enip(packet, info);
                }
                DeepParseResult::S7(ref info) => {
                    self.process_s7(packet, info);
                }
                DeepParseResult::Bacnet(ref info) => {
                    self.process_bacnet(packet, info);
                }
                DeepParseResult::Iec104(ref info) => {
                    self.process_iec104(packet, info);
                }
                DeepParseResult::ProfinetDcp(ref info) => {
                    self.process_profinet_dcp(packet, info);
                }
                // LLDP is handled by the early-return above; deep_parse()
                // never returns Lldp since it's not an IP-layer protocol.
                DeepParseResult::Lldp(_) => {}
            }
        }

        // SNMP GET-Response: extract device identity from responses (src port 161)
        if packet.src_port == 161 && !packet.payload.is_empty() {
            if let Some(dev_info) = parse_snmp_response(&packet.payload) {
                self.snmp_device_info.insert(packet.src_ip.clone(), dev_info);
            }
        }

        // Feed into topology builder
        self.topo_builder.add_connection(
            &packet.src_ip,
            &packet.dst_ip,
            packet.src_mac.as_deref(),
            packet.dst_mac.as_deref(),
            protocol,
            packet.length as u64,
        );

        // Record packet for communication pattern analysis (O(1))
        let ts_epoch_pattern = packet.timestamp.timestamp() as f64
            + packet.timestamp.timestamp_subsec_nanos() as f64 / 1_000_000_000.0;
        self.pattern_analyzer.record_packet(
            &packet.src_ip,
            &packet.dst_ip,
            packet.dst_port,
            &proto_str,
            ts_epoch_pattern,
            packet.length as u64,
        );

        // Accumulate signature matching data (PacketData per IP)
        let pkt_data = PacketData {
            src_ip: packet.src_ip.clone(),
            dst_ip: packet.dst_ip.clone(),
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            src_mac: packet.src_mac.clone(),
            dst_mac: packet.dst_mac.clone(),
            transport: format!("{:?}", packet.transport).to_lowercase(),
            protocol: format!("{:?}", protocol).to_lowercase(),
            payload: packet.payload.clone(),
            length: packet.length,
        };

        // Cap signature-matching packet storage at 200 per IP.
        // The signature engine only needs a small sample to identify a device;
        // storing all packets would consume gigabytes for large captures.
        const IP_PACKET_CAP: usize = 200;
        let src_entry = self.ip_packets.entry(packet.src_ip.clone()).or_default();
        if src_entry.len() < IP_PACKET_CAP {
            src_entry.push(pkt_data.clone());
        }
        let dst_entry = self.ip_packets.entry(packet.dst_ip.clone()).or_default();
        if dst_entry.len() < IP_PACKET_CAP {
            dst_entry.push(pkt_data);
        }
    }

    /// Process Modbus deep parse result for a packet.
    fn process_modbus(
        &mut self,
        packet: &ParsedPacket,
        info: &gm_parsers::ModbusInfo,
        ts_epoch: f64,
    ) {
        let ip_for_fc = match info.role {
            ModbusRole::Master | ModbusRole::Slave | ModbusRole::Unknown => &packet.src_ip,
        };

        *self.modbus_fc_counts
            .entry(ip_for_fc.clone())
            .or_default()
            .entry(info.function_code)
            .or_insert(0) += 1;

        self.modbus_unit_ids
            .entry(ip_for_fc.clone())
            .or_default()
            .insert(info.unit_id);

        let role_str = match info.role {
            ModbusRole::Master => "master",
            ModbusRole::Slave => "slave",
            ModbusRole::Unknown => "unknown",
        };
        self.modbus_roles
            .entry(ip_for_fc.clone())
            .or_default()
            .insert(role_str.to_string());

        if let Some(ref range) = info.register_range {
            let reg_type = format!("{:?}", range.register_type).to_lowercase();
            *self.modbus_register_ranges
                .entry(ip_for_fc.clone())
                .or_default()
                .entry((range.start, range.count, reg_type))
                .or_insert(0) += 1;
        }

        if let Some(ref dev_id) = info.device_id {
            self.modbus_device_ids.insert(packet.src_ip.clone(), dev_id.clone());
        }

        let (local_ip, remote_ip, remote_role) = match info.role {
            ModbusRole::Master => (&packet.src_ip, &packet.dst_ip, "slave"),
            ModbusRole::Slave => (&packet.src_ip, &packet.dst_ip, "master"),
            ModbusRole::Unknown => (&packet.src_ip, &packet.dst_ip, "unknown"),
        };
        let rel = self.modbus_relationships
            .entry(local_ip.clone())
            .or_default()
            .entry(remote_ip.clone())
            .or_insert_with(|| (remote_role.to_string(), HashSet::new(), 0));
        rel.1.insert(info.unit_id);
        rel.2 += 1;

        if info.role == ModbusRole::Master && !info.is_exception {
            let key = (
                packet.src_ip.clone(),
                packet.dst_ip.clone(),
                info.function_code,
                info.unit_id,
            );
            self.modbus_polling_timestamps
                .entry(key)
                .or_default()
                .push(ts_epoch);
        }
    }

    /// Process DNP3 deep parse result for a packet.
    fn process_dnp3(
        &mut self,
        packet: &ParsedPacket,
        info: &gm_parsers::Dnp3Info,
    ) {
        let ip_for_fc = &packet.src_ip;

        if let Some(fc) = info.function_code {
            *self.dnp3_fc_counts
                .entry(ip_for_fc.clone())
                .or_default()
                .entry(fc)
                .or_insert(0) += 1;
        }

        self.dnp3_addresses
            .entry(ip_for_fc.clone())
            .or_default()
            .insert(info.source_address);

        let role_str = match info.role {
            Dnp3Role::Master => "master",
            Dnp3Role::Outstation => "outstation",
            Dnp3Role::Unknown => "unknown",
        };
        self.dnp3_roles
            .entry(ip_for_fc.clone())
            .or_default()
            .insert(role_str.to_string());

        if info.is_unsolicited {
            self.dnp3_unsolicited.insert(ip_for_fc.clone(), true);
        }

        let remote_role = match info.role {
            Dnp3Role::Master => "outstation",
            Dnp3Role::Outstation => "master",
            Dnp3Role::Unknown => "unknown",
        };
        let rel = self.dnp3_relationships
            .entry(ip_for_fc.clone())
            .or_default()
            .entry(packet.dst_ip.clone())
            .or_insert_with(|| (remote_role.to_string(), 0));
        rel.1 += 1;
    }

    /// Process EtherNet/IP deep parse result for a packet.
    fn process_enip(&mut self, packet: &ParsedPacket, info: &gm_parsers::EnipInfo) {
        let ip = &packet.src_ip;

        let role_str = match info.role {
            EnipRole::Scanner => "scanner",
            EnipRole::Adapter => "adapter",
            EnipRole::Unknown => "unknown",
        };
        self.enip_roles.insert(ip.clone(), role_str.to_string());

        // ListIdentity request (not a response) — network discovery
        if matches!(info.command, EnipCommand::ListIdentity) && !info.is_response {
            self.enip_list_identity.insert(ip.clone());
        }

        // CIP Write or ReadModifyWrite to Assembly object — I/O control
        let is_write = matches!(
            info.cip_service,
            Some(CipService::Write) | Some(CipService::ReadModifyWrite)
        );
        let is_assembly = matches!(info.cip_class, Some(CipClass::Assembly));
        if is_write && is_assembly {
            self.enip_cip_writes_to_assembly.insert(ip.clone());
        }

        // CIP File class access — firmware/program operations
        if matches!(info.cip_class, Some(CipClass::File)) {
            self.enip_cip_file_access.insert(ip.clone());
        }
    }

    /// Process S7comm deep parse result for a packet.
    fn process_s7(&mut self, packet: &ParsedPacket, info: &gm_parsers::S7Info) {
        let ip = &packet.src_ip;

        let role_str = match info.role {
            S7Role::Client => "client",
            S7Role::Server => "server",
            S7Role::Unknown => "unknown",
        };
        self.s7_roles.insert(ip.clone(), role_str.to_string());

        if let Some(ref function) = info.s7_function {
            let fn_name = match function {
                S7Function::SetupCommunication => "setup_communication",
                S7Function::ReadVar => "read_var",
                S7Function::WriteVar => "write_var",
                S7Function::UploadStart => "upload_start",
                S7Function::Upload => "upload",
                S7Function::UploadEnd => "upload_end",
                S7Function::DownloadStart => "download_start",
                S7Function::Download => "download",
                S7Function::DownloadEnd => "download_end",
                S7Function::PlcStop => "plc_stop",
                S7Function::PiService => "pi_service",
                S7Function::Unknown(_) => "unknown",
            };
            self.s7_functions_seen
                .entry(ip.clone())
                .or_default()
                .insert(fn_name.to_string());
        }
    }

    /// Process BACnet deep parse result for a packet.
    fn process_bacnet(&mut self, packet: &ParsedPacket, info: &gm_parsers::BacnetInfo) {
        let ip = &packet.src_ip;

        let role_str = match info.role {
            BacnetRole::Client => "client",
            BacnetRole::Server => "server",
            BacnetRole::Unknown => "unknown",
        };
        self.bacnet_roles.insert(ip.clone(), role_str.to_string());

        match info.service {
            Some(BacnetService::WriteProperty) | Some(BacnetService::WritePropertyMultiple) => {
                match info.object_type {
                    Some(BacnetObjectType::AnalogOutput) | Some(BacnetObjectType::BinaryOutput) => {
                        self.bacnet_write_to_output.insert(ip.clone());
                    }
                    Some(BacnetObjectType::NotificationClass) => {
                        self.bacnet_write_to_notification_class.insert(ip.clone());
                    }
                    _ => {}
                }
            }
            Some(BacnetService::ReinitializeDevice) => {
                self.bacnet_reinitialize.insert(ip.clone());
            }
            Some(BacnetService::DeviceCommunicationControl) => {
                self.bacnet_device_comm_ctrl.insert(ip.clone());
            }
            _ => {}
        }
    }

    /// Process IEC 60870-5-104 deep parse result for a packet.
    fn process_iec104(&mut self, packet: &ParsedPacket, info: &gm_parsers::Iec104Info) {
        let ip = &packet.src_ip;

        let role_str = match info.role {
            Iec104Role::Master => "master",
            Iec104Role::Outstation => "outstation",
            Iec104Role::Unknown => "unknown",
        };
        self.iec104_roles.insert(ip.clone(), role_str.to_string());

        if info.is_command {
            self.iec104_control_commands.insert(ip.clone());
        }
        if matches!(info.type_id, Some(AsduTypeId::ResetProcess)) {
            self.iec104_reset_process.insert(ip.clone());
        }
        if matches!(info.type_id, Some(AsduTypeId::Interrogation)) {
            self.iec104_interrogation.insert(ip.clone());
        }
    }

    /// Process PROFINET DCP deep parse result for a packet.
    fn process_profinet_dcp(
        &mut self,
        packet: &ParsedPacket,
        info: &gm_parsers::ProfinetDcpInfo,
    ) {
        let ip = &packet.src_ip;

        let role_str = match info.role {
            ProfinetRole::IoDevice => "io_device",
            ProfinetRole::IoController => "io_controller",
            ProfinetRole::IoSupervisor => "io_supervisor",
            ProfinetRole::Unknown => "unknown",
        };
        // Only update if we have a meaningful role (responses carry the role block)
        if role_str != "unknown" {
            self.profinet_roles.insert(ip.clone(), role_str.to_string());
        } else {
            // Record the device even without a role so we know it speaks PROFINET
            self.profinet_roles.entry(ip.clone()).or_insert_with(|| "unknown".to_string());
        }

        if let Some(ref name) = info.device_info.name_of_station {
            if !name.is_empty() {
                self.profinet_device_names.insert(ip.clone(), name.clone());
            }
        }
    }

    /// Build deep parse info from accumulated data.
    pub fn build_deep_parse_info(&self) -> HashMap<String, DeepParseInfo> {
        let mut deep_parse_info: HashMap<String, DeepParseInfo> = HashMap::new();

        // Aggregate Modbus data
        let all_modbus_ips: HashSet<String> = self.modbus_fc_counts
            .keys()
            .chain(self.modbus_roles.keys())
            .cloned()
            .collect();

        for ip in &all_modbus_ips {
            let role = self.modbus_roles.get(ip).map(|roles| {
                if roles.contains("master") && roles.contains("slave") {
                    "both".to_string()
                } else if roles.contains("master") {
                    "master".to_string()
                } else if roles.contains("slave") {
                    "slave".to_string()
                } else {
                    "unknown".to_string()
                }
            }).unwrap_or_else(|| "unknown".to_string());

            let mut unit_ids: Vec<u8> = self.modbus_unit_ids
                .get(ip)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();
            unit_ids.sort();

            let function_codes: Vec<FunctionCodeStat> = self.modbus_fc_counts
                .get(ip)
                .map(|fc_map| {
                    let mut fcs: Vec<FunctionCodeStat> = fc_map.iter().map(|(&code, &count)| {
                        FunctionCodeStat {
                            code,
                            name: modbus_function_code_name(code).to_string(),
                            count,
                            is_write: matches!(code, 5 | 6 | 15 | 16 | 22 | 23),
                        }
                    }).collect();
                    fcs.sort_by(|a, b| b.count.cmp(&a.count));
                    fcs
                })
                .unwrap_or_default();

            let register_ranges: Vec<RegisterRangeInfo> = self.modbus_register_ranges
                .get(ip)
                .map(|range_map| {
                    let mut ranges: Vec<RegisterRangeInfo> = range_map.iter().map(|((start, count, reg_type), &access_count)| {
                        RegisterRangeInfo {
                            start: *start,
                            count: *count,
                            register_type: reg_type.clone(),
                            access_count,
                        }
                    }).collect();
                    ranges.sort_by(|a, b| a.start.cmp(&b.start));
                    ranges
                })
                .unwrap_or_default();

            let device_id = self.modbus_device_ids.get(ip).map(|d| ModbusDeviceIdInfo {
                vendor_name: d.vendor_name.clone(),
                product_code: d.product_code.clone(),
                revision: d.revision.clone(),
                vendor_url: d.vendor_url.clone(),
                product_name: d.product_name.clone(),
                model_name: d.model_name.clone(),
            });

            let relationships: Vec<ModbusRelationship> = self.modbus_relationships
                .get(ip)
                .map(|rel_map| {
                    rel_map.iter().map(|(remote_ip, (remote_role, unit_id_set, pkt_count))| {
                        let mut uids: Vec<u8> = unit_id_set.iter().copied().collect();
                        uids.sort();
                        ModbusRelationship {
                            remote_ip: remote_ip.clone(),
                            remote_role: remote_role.clone(),
                            unit_ids: uids,
                            packet_count: *pkt_count,
                        }
                    }).collect()
                })
                .unwrap_or_default();

            // Compute polling intervals from timestamps
            let mut polling_intervals: Vec<PollingInterval> = Vec::new();
            for ((src, dst, fc, uid), timestamps) in &self.modbus_polling_timestamps {
                if src == ip && timestamps.len() >= 3 {
                    let mut sorted_ts = timestamps.clone();
                    sorted_ts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

                    let intervals: Vec<f64> = sorted_ts.windows(2)
                        .map(|w| (w[1] - w[0]) * 1000.0)
                        .filter(|&i| i > 0.0 && i < 60_000.0)
                        .collect();

                    if intervals.len() >= 2 {
                        let sum: f64 = intervals.iter().sum();
                        let avg = sum / intervals.len() as f64;
                        let min = intervals.iter().cloned().fold(f64::MAX, f64::min);
                        let max = intervals.iter().cloned().fold(f64::MIN, f64::max);

                        polling_intervals.push(PollingInterval {
                            remote_ip: dst.clone(),
                            unit_id: Some(*uid),
                            function_code: *fc,
                            avg_interval_ms: (avg * 10.0).round() / 10.0,
                            min_interval_ms: (min * 10.0).round() / 10.0,
                            max_interval_ms: (max * 10.0).round() / 10.0,
                            sample_count: intervals.len() as u64,
                        });
                    }
                }
            }

            let modbus_detail = ModbusDetail {
                role,
                unit_ids,
                function_codes,
                register_ranges,
                device_id,
                relationships,
                polling_intervals,
            };

            deep_parse_info
                .entry(ip.clone())
                .or_default()
                .modbus = Some(modbus_detail);
        }

        // Aggregate DNP3 data
        let all_dnp3_ips: HashSet<String> = self.dnp3_fc_counts
            .keys()
            .chain(self.dnp3_roles.keys())
            .cloned()
            .collect();

        for ip in &all_dnp3_ips {
            let role = self.dnp3_roles.get(ip).map(|roles| {
                if roles.contains("master") && roles.contains("outstation") {
                    "both".to_string()
                } else if roles.contains("master") {
                    "master".to_string()
                } else if roles.contains("outstation") {
                    "outstation".to_string()
                } else {
                    "unknown".to_string()
                }
            }).unwrap_or_else(|| "unknown".to_string());

            let mut addresses: Vec<u16> = self.dnp3_addresses
                .get(ip)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();
            addresses.sort();

            let function_codes: Vec<FunctionCodeStat> = self.dnp3_fc_counts
                .get(ip)
                .map(|fc_map| {
                    let mut fcs: Vec<FunctionCodeStat> = fc_map.iter().map(|(&code, &count)| {
                        FunctionCodeStat {
                            code,
                            name: dnp3_function_code_name(code).to_string(),
                            count,
                            is_write: matches!(code, 2..=6),
                        }
                    }).collect();
                    fcs.sort_by(|a, b| b.count.cmp(&a.count));
                    fcs
                })
                .unwrap_or_default();

            let has_unsolicited = self.dnp3_unsolicited.get(ip).copied().unwrap_or(false);

            let relationships: Vec<Dnp3Relationship> = self.dnp3_relationships
                .get(ip)
                .map(|rel_map| {
                    rel_map.iter().map(|(remote_ip, (remote_role, pkt_count))| {
                        Dnp3Relationship {
                            remote_ip: remote_ip.clone(),
                            remote_role: remote_role.clone(),
                            packet_count: *pkt_count,
                        }
                    }).collect()
                })
                .unwrap_or_default();

            let dnp3_detail = Dnp3Detail {
                role,
                addresses,
                function_codes,
                has_unsolicited,
                relationships,
            };

            deep_parse_info
                .entry(ip.clone())
                .or_default()
                .dnp3 = Some(dnp3_detail);
        }

        // Aggregate EtherNet/IP data
        for ip in self.enip_roles.keys() {
            let role = self.enip_roles.get(ip)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let enip_detail = EnipDetail {
                role,
                cip_writes_to_assembly: self.enip_cip_writes_to_assembly.contains(ip),
                cip_file_access: self.enip_cip_file_access.contains(ip),
                list_identity_requests: self.enip_list_identity.contains(ip),
            };
            deep_parse_info
                .entry(ip.clone())
                .or_default()
                .enip = Some(enip_detail);
        }

        // Aggregate S7comm data
        for ip in self.s7_roles.keys() {
            let role = self.s7_roles.get(ip)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let mut functions_seen: Vec<String> = self.s7_functions_seen
                .get(ip)
                .map(|s| s.iter().cloned().collect())
                .unwrap_or_default();
            functions_seen.sort();
            let s7_detail = S7Detail { role, functions_seen };
            deep_parse_info
                .entry(ip.clone())
                .or_default()
                .s7 = Some(s7_detail);
        }

        // Aggregate BACnet data
        for ip in self.bacnet_roles.keys() {
            let role = self.bacnet_roles.get(ip)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let bacnet_detail = BacnetDetail {
                role,
                write_to_output: self.bacnet_write_to_output.contains(ip),
                write_to_notification_class: self.bacnet_write_to_notification_class.contains(ip),
                reinitialize_device: self.bacnet_reinitialize.contains(ip),
                device_communication_control: self.bacnet_device_comm_ctrl.contains(ip),
            };
            deep_parse_info
                .entry(ip.clone())
                .or_default()
                .bacnet = Some(bacnet_detail);
        }

        // Aggregate PROFINET DCP data
        for ip in self.profinet_roles.keys() {
            let role = self.profinet_roles.get(ip)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let profinet_detail = ProfinetDcpDetail {
                role,
                device_name: self.profinet_device_names.get(ip).cloned(),
            };
            deep_parse_info
                .entry(ip.clone())
                .or_default()
                .profinet_dcp = Some(profinet_detail);
        }

        // Aggregate IEC 104 data
        for ip in self.iec104_roles.keys() {
            let role = self.iec104_roles.get(ip)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let iec104_detail = Iec104Detail {
                role,
                has_control_commands: self.iec104_control_commands.contains(ip),
                has_reset_process: self.iec104_reset_process.contains(ip),
                has_interrogation: self.iec104_interrogation.contains(ip),
            };
            deep_parse_info
                .entry(ip.clone())
                .or_default()
                .iec104 = Some(iec104_detail);
        }

        // Aggregate LLDP data: match by MAC address
        // asset_macs maps IP → MAC; we need the reverse to look up by MAC
        for (ip, mac) in &self.asset_macs {
            if let Some(lldp_info) = self.lldp_by_mac.get(mac) {
                let mgmt_addrs: Vec<String> = lldp_info
                    .management_addresses
                    .iter()
                    .map(|a| format!("{} ({})", a.address, a.addr_type))
                    .collect();
                let lldp_detail = LldpDetail {
                    system_name: lldp_info.system_name.clone(),
                    system_description: lldp_info.system_description.clone(),
                    chassis_id: lldp_info.chassis_id.clone(),
                    port_id: lldp_info.port_id.clone(),
                    capability_summary: lldp_info.capability_summary.clone(),
                    management_addresses: mgmt_addrs,
                    vlan_ids: lldp_info.vlan_ids.clone(),
                    vendor: lldp_info.vendor.clone(),
                    model: lldp_info.model.clone(),
                    firmware: lldp_info.firmware.clone(),
                };
                deep_parse_info
                    .entry(ip.clone())
                    .or_default()
                    .lldp = Some(lldp_detail);
            }
        }

        // Aggregate SNMP device identity (keyed directly by IP)
        for (ip, snmp_info) in &self.snmp_device_info {
            let snmp_detail = SnmpDetail {
                sys_descr: snmp_info.sys_descr.clone(),
                sys_name: snmp_info.sys_name.clone(),
                sys_location: snmp_info.sys_location.clone(),
                sys_object_id: snmp_info.sys_object_id.clone(),
                sys_uptime_cs: snmp_info.sys_uptime_cs,
                sys_contact: snmp_info.sys_contact.clone(),
                vendor: snmp_info.vendor.clone(),
            };
            deep_parse_info
                .entry(ip.clone())
                .or_default()
                .snmp = Some(snmp_detail);
        }

        deep_parse_info
    }

    /// Collect all observed redundancy protocol frames as a flat list.
    ///
    /// Returns one `RedundancyInfo` per unique source MAC (last-frame-wins).
    pub fn build_redundancy_info(&self) -> Vec<RedundancyInfo> {
        self.redundancy_by_mac.values().cloned().collect()
    }

    /// Run signature matching and build the final asset list.
    ///
    /// Requires references to the SignatureEngine, OUI lookup, and GeoIP lookup.
    pub fn build_assets(
        &self,
        engine: &SignatureEngine,
        deep_parse_info: &HashMap<String, DeepParseInfo>,
        oui_lookup: &OuiLookup,
        geoip_lookup: &GeoIpLookup,
    ) -> (Vec<AssetInfo>, HashMap<String, Vec<AssetSignatureMatch>>) {
        // Run signature matching per device
        let mut sig_results: HashMap<String, Vec<AssetSignatureMatch>> = HashMap::new();
        for (ip, packets) in &self.ip_packets {
            let matches = engine.match_device_packets(packets);
            if !matches.is_empty() {
                sig_results.insert(
                    ip.clone(),
                    matches
                        .into_iter()
                        .map(|m| AssetSignatureMatch {
                            signature_name: m.signature_name,
                            confidence: m.confidence,
                            vendor: m.vendor,
                            product_family: m.product_family,
                            device_type: m.device_type,
                            role: m.role,
                        })
                        .collect(),
                );
            }
        }

        // Build assets
        let all_ips: HashSet<String> = self.asset_protocols.keys().cloned().collect();
        let mut assets: Vec<AssetInfo> = Vec::new();

        for ip in &all_ips {
            let protocols: Vec<IcsProtocol> = self.asset_protocols
                .get(ip)
                .map(|s| s.iter().copied().collect())
                .unwrap_or_default();

            let is_server = self.server_ips.contains(ip);
            let mut device_type = infer_device_type(&protocols, is_server);

            let sig_matches = sig_results.get(ip).cloned().unwrap_or_default();
            let best_match = sig_matches.first();

            let mut confidence = best_match.map(|m| m.confidence).unwrap_or(
                if protocols.iter().any(|p| *p != IcsProtocol::Unknown) { 1 } else { 0 },
            );

            let mut vendor = best_match.and_then(|m| m.vendor.clone());
            let mut product_family = best_match.and_then(|m| m.product_family.clone());

            // OUI vendor lookup from MAC address
            let mac = self.asset_macs.get(ip);
            let oui_vendor = mac.and_then(|m| oui_lookup.lookup(m).map(|v| v.to_string()));

            // If no signature vendor but OUI found, use OUI vendor + confidence 3
            if vendor.is_none() {
                if let Some(ref oui_v) = oui_vendor {
                    vendor = Some(oui_v.clone());
                    if confidence < 3 {
                        confidence = 3;
                    }
                }
            }

            // Deep parse Device ID (FC 43/14) overrides with confidence 5
            if let Some(dp_info) = deep_parse_info.get(ip) {
                if let Some(ref modbus) = dp_info.modbus {
                    if let Some(ref dev_id) = modbus.device_id {
                        confidence = 5;
                        if let Some(ref vn) = dev_id.vendor_name {
                            vendor = Some(vn.clone());
                        }
                        let pf_parts: Vec<&str> = [
                            dev_id.product_code.as_deref(),
                            dev_id.product_name.as_deref(),
                            dev_id.model_name.as_deref(),
                        ]
                        .iter()
                        .filter_map(|&x| x)
                        .collect();
                        if !pf_parts.is_empty() {
                            product_family = Some(pf_parts.join(" "));
                        }
                    }
                }
            }

            if let Some(m) = best_match {
                if let Some(ref sig_device_type) = m.device_type {
                    if m.confidence >= 3 {
                        device_type = sig_device_type.clone();
                    }
                }
            }

            // LLDP enrichment (confidence 4 — better than OUI/port, lower than deep parse)
            let mut hostname: Option<String> = None;
            if let Some(mac_addr) = self.asset_macs.get(ip) {
                if let Some(lldp) = self.lldp_by_mac.get(mac_addr) {
                    if let Some(ref sn) = lldp.system_name {
                        hostname = Some(sn.clone());
                    }
                    if vendor.is_none() {
                        if let Some(ref lv) = lldp.vendor {
                            vendor = Some(lv.clone());
                            if confidence < 4 { confidence = 4; }
                        }
                    }
                    if product_family.is_none() {
                        if let Some(ref lm) = lldp.model {
                            product_family = Some(lm.clone());
                        }
                    }
                    // If LLDP capabilities indicate bridge-only, classify as switch
                    if let (Some(cap), Some(en)) = (lldp.capabilities, lldp.enabled_capabilities) {
                        use gm_parsers::lldp::caps;
                        let active = if en != 0 { en } else { cap };
                        let is_bridge = active & caps::BRIDGE != 0;
                        let is_router = active & caps::ROUTER != 0;
                        if is_bridge && !is_router && device_type == "unknown" {
                            device_type = "switch".to_string();
                        }
                        if is_router && device_type == "unknown" {
                            device_type = "router".to_string();
                        }
                    }
                }
            }

            // GeoIP enrichment
            let is_public_ip = GeoIpLookup::is_public_ip(ip);
            let country = geoip_lookup.lookup_country(ip);

            assets.push(AssetInfo {
                id: ip.clone(),
                ip_address: ip.clone(),
                mac_address: self.asset_macs.get(ip).cloned(),
                hostname,
                device_type,
                vendor,
                protocols: protocols.iter().map(|p| format!("{:?}", p).to_lowercase()).collect(),
                first_seen: self.asset_first_seen.get(ip).cloned().unwrap_or_default(),
                last_seen: self.asset_last_seen.get(ip).cloned().unwrap_or_default(),
                notes: String::new(),
                purdue_level: None,
                tags: Vec::new(),
                packet_count: *self.asset_packet_counts.get(ip).unwrap_or(&0),
                confidence,
                product_family,
                signature_matches: sig_matches,
                oui_vendor,
                country,
                is_public_ip,
            });
        }

        // Sort: OT devices first, then by packet count descending
        assets.sort_by(|a, b| {
            let a_ot = a.device_type != "it_device" && a.device_type != "unknown";
            let b_ot = b.device_type != "it_device" && b.device_type != "unknown";
            b_ot.cmp(&a_ot).then(b.packet_count.cmp(&a.packet_count))
        });

        (assets, sig_results)
    }

    /// Finalize connections with origin file tracking.
    pub fn get_connections(&mut self) -> Vec<ConnectionInfo> {
        for (conn_key, conn) in &mut self.connections {
            if let Some(files) = self.conn_origin_files.get(conn_key) {
                conn.origin_files = files.iter().cloned().collect();
                conn.origin_files.sort();
            }
        }
        self.connections.values().cloned().collect()
    }

    /// Get a snapshot of packet summaries.
    pub fn get_packet_summaries(&self) -> HashMap<String, Vec<PacketSummary>> {
        self.packet_summaries.clone()
    }

    /// Get protocols detected so far.
    pub fn get_protocols_detected(&self) -> Vec<String> {
        self.all_protocols.iter().cloned().collect()
    }

    /// Compute per-connection-pair statistics and detect pattern anomalies.
    ///
    /// Returns `(stats, anomalies)` derived from Welford accumulators.
    /// Safe to call multiple times — no mutable state in PatternAnalyzer.
    pub fn build_pattern_results(&mut self) -> (Vec<ConnectionStats>, Vec<PatternAnomaly>) {
        let stats = self.pattern_analyzer.compute_stats();
        let anomalies = PatternAnalyzer::detect_anomalies(&stats);
        (stats, anomalies)
    }

}
