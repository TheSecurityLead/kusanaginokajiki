use std::collections::{HashMap, HashSet};
use std::time::Instant;
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use gm_capture::PcapReader;
use gm_parsers::{
    identify_protocol, deep_parse, IcsProtocol, DeepParseResult,
    ModbusRole, ModbusDeviceId, Dnp3Role,
    modbus_function_code_name, dnp3_function_code_name,
};
use gm_signatures::PacketData;
use gm_topology::TopologyBuilder;

use super::{
    AppState, AssetInfo, AssetSignatureMatch, ConnectionInfo, PacketSummary, infer_device_type,
    DeepParseInfo, ModbusDetail, Dnp3Detail, FunctionCodeStat, RegisterRangeInfo,
    ModbusDeviceIdInfo, ModbusRelationship, Dnp3Relationship, PollingInterval,
};

#[derive(Serialize)]
pub struct ImportResult {
    pub file_count: usize,
    pub packet_count: usize,
    pub connection_count: usize,
    pub asset_count: usize,
    pub protocols_detected: Vec<String>,
    pub duration_ms: u64,
    /// Per-file breakdown for the UI
    pub per_file: Vec<FileImportResult>,
}

#[derive(Serialize)]
pub struct FileImportResult {
    pub filename: String,
    pub packet_count: usize,
    pub status: String,
}

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

/// Import one or more PCAP files and process them through the full pipeline:
/// 1. Read packets from each file (gm-capture), tagged with origin filename
/// 2. Identify protocols (gm-parsers)
/// 3. Build topology graph (gm-topology)
/// 4. Store results in app state, including per-connection packet summaries
///
/// Supports multi-PCAP import: results from all files are merged into
/// a single topology. Each connection and packet tracks which file it came from.
#[tauri::command]
pub async fn import_pcap(
    paths: Vec<String>,
    state: State<'_, AppState>,
) -> Result<ImportResult, String> {
    let start = Instant::now();
    let reader = PcapReader::new();

    // Read packets from all files
    let mut all_packets = Vec::new();
    let mut per_file_results = Vec::new();

    for path in &paths {
        match reader.read_file(path) {
            Ok(packets) => {
                let count = packets.len();
                let filename = std::path::Path::new(path)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                per_file_results.push(FileImportResult {
                    filename,
                    packet_count: count,
                    status: "ok".to_string(),
                });
                all_packets.extend(packets);
            }
            Err(e) => {
                let filename = std::path::Path::new(path)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.clone());
                log::warn!("Failed to read {}: {}", path, e);
                per_file_results.push(FileImportResult {
                    filename,
                    packet_count: 0,
                    status: format!("error: {}", e),
                });
            }
        }
    }

    let total_packet_count = all_packets.len();
    if total_packet_count == 0 {
        return Err("No packets could be parsed from the provided files".to_string());
    }

    // Process all packets through the pipeline
    let mut topo_builder = TopologyBuilder::new();
    let mut connections: HashMap<String, ConnectionInfo> = HashMap::new();
    let mut packet_summaries: HashMap<String, Vec<PacketSummary>> = HashMap::new();
    let mut asset_protocols: HashMap<String, HashSet<IcsProtocol>> = HashMap::new();
    let mut asset_macs: HashMap<String, String> = HashMap::new();
    let mut asset_packet_counts: HashMap<String, u64> = HashMap::new();
    let mut asset_first_seen: HashMap<String, String> = HashMap::new();
    let mut asset_last_seen: HashMap<String, String> = HashMap::new();
    let mut server_ips: HashSet<String> = HashSet::new();
    let mut all_protocols: HashSet<String> = HashSet::new();
    let mut conn_origin_files: HashMap<String, HashSet<String>> = HashMap::new();

    // Accumulators for deep parse results, keyed by IP
    // For each IP, track: function codes, unit IDs, register ranges, roles, timestamps per (remote_ip, fc, unit_id)
    let mut modbus_fc_counts: HashMap<String, HashMap<u8, u64>> = HashMap::new();
    let mut modbus_unit_ids: HashMap<String, HashSet<u8>> = HashMap::new();
    let mut modbus_register_ranges: HashMap<String, HashMap<(u16, u16, String), u64>> = HashMap::new();
    let mut modbus_roles: HashMap<String, HashSet<String>> = HashMap::new();
    let mut modbus_device_ids: HashMap<String, ModbusDeviceId> = HashMap::new();
    // (remote_role, unit_ids, packet_count) per remote_ip per local_ip
    #[allow(clippy::type_complexity)]
    let mut modbus_relationships: HashMap<String, HashMap<String, (String, HashSet<u8>, u64)>> = HashMap::new();
    // For polling interval detection: (src_ip, dst_ip, fc, unit_id) → sorted list of timestamps
    let mut modbus_polling_timestamps: HashMap<(String, String, u8, u8), Vec<f64>> = HashMap::new();

    let mut dnp3_fc_counts: HashMap<String, HashMap<u8, u64>> = HashMap::new();
    let mut dnp3_addresses: HashMap<String, HashSet<u16>> = HashMap::new();
    let mut dnp3_roles: HashMap<String, HashSet<String>> = HashMap::new();
    let mut dnp3_unsolicited: HashMap<String, bool> = HashMap::new();
    let mut dnp3_relationships: HashMap<String, HashMap<String, (String, u64)>> = HashMap::new();

    for packet in &all_packets {
        let protocol = identify_protocol(packet);
        let proto_str = format!("{:?}", protocol);
        all_protocols.insert(proto_str.clone());

        let timestamp = packet.timestamp.to_rfc3339();

        // Track asset protocols
        asset_protocols
            .entry(packet.src_ip.clone())
            .or_default()
            .insert(protocol);
        asset_protocols
            .entry(packet.dst_ip.clone())
            .or_default()
            .insert(protocol);

        // Track MACs
        if let Some(ref mac) = packet.src_mac {
            asset_macs.entry(packet.src_ip.clone()).or_insert_with(|| mac.clone());
        }
        if let Some(ref mac) = packet.dst_mac {
            asset_macs.entry(packet.dst_ip.clone()).or_insert_with(|| mac.clone());
        }

        // Track packet counts
        *asset_packet_counts.entry(packet.src_ip.clone()).or_insert(0) += 1;
        *asset_packet_counts.entry(packet.dst_ip.clone()).or_insert(0) += 1;

        // Track timestamps
        asset_first_seen
            .entry(packet.src_ip.clone())
            .or_insert_with(|| timestamp.clone());
        asset_last_seen.insert(packet.src_ip.clone(), timestamp.clone());
        asset_first_seen
            .entry(packet.dst_ip.clone())
            .or_insert_with(|| timestamp.clone());
        asset_last_seen.insert(packet.dst_ip.clone(), timestamp.clone());

        // Detect servers using well-known OT service ports
        if is_server_port(packet.dst_port) {
            server_ips.insert(packet.dst_ip.clone());
        }
        if is_server_port(packet.src_port) {
            server_ips.insert(packet.src_ip.clone());
        }

        // Build connection key (directional: src→dst on protocol)
        let conn_key = format!(
            "{}:{}->{}:{}:{}",
            packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, proto_str
        );

        let conn = connections.entry(conn_key.clone()).or_insert_with(|| {
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
        conn_origin_files
            .entry(conn_key.clone())
            .or_default()
            .insert(packet.origin_file.clone());

        // Store packet summary for the connection tree
        // Cap at 1000 summaries per connection to avoid memory bloat on large PCAPs
        let summaries = packet_summaries.entry(conn.id.clone()).or_default();
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
        // Run deep parser on Modbus/DNP3 packets to extract function codes,
        // unit IDs, register ranges, device IDs, and master/slave roles.
        if let Some(deep_result) = deep_parse(packet, protocol) {
            let ts_epoch = packet.timestamp.timestamp() as f64
                + packet.timestamp.timestamp_subsec_millis() as f64 / 1000.0;

            match deep_result {
                DeepParseResult::Modbus(ref info) => {
                    // Track function codes for both src and dst
                    let ip_for_fc = match info.role {
                        ModbusRole::Master => &packet.src_ip,
                        ModbusRole::Slave => &packet.src_ip,
                        ModbusRole::Unknown => &packet.src_ip,
                    };
                    *modbus_fc_counts
                        .entry(ip_for_fc.clone())
                        .or_default()
                        .entry(info.function_code)
                        .or_insert(0) += 1;

                    // Track unit IDs
                    modbus_unit_ids
                        .entry(ip_for_fc.clone())
                        .or_default()
                        .insert(info.unit_id);

                    // Track roles
                    let role_str = match info.role {
                        ModbusRole::Master => "master",
                        ModbusRole::Slave => "slave",
                        ModbusRole::Unknown => "unknown",
                    };
                    modbus_roles
                        .entry(ip_for_fc.clone())
                        .or_default()
                        .insert(role_str.to_string());

                    // Track register ranges (from master requests)
                    if let Some(ref range) = info.register_range {
                        let reg_type = format!("{:?}", range.register_type).to_lowercase();
                        *modbus_register_ranges
                            .entry(ip_for_fc.clone())
                            .or_default()
                            .entry((range.start, range.count, reg_type))
                            .or_insert(0) += 1;
                    }

                    // Track device identification from FC 43/14
                    if let Some(ref dev_id) = info.device_id {
                        modbus_device_ids.insert(packet.src_ip.clone(), dev_id.clone());
                    }

                    // Track master↔slave relationships
                    let (local_ip, remote_ip, remote_role) = match info.role {
                        ModbusRole::Master => (&packet.src_ip, &packet.dst_ip, "slave"),
                        ModbusRole::Slave => (&packet.src_ip, &packet.dst_ip, "master"),
                        ModbusRole::Unknown => (&packet.src_ip, &packet.dst_ip, "unknown"),
                    };
                    let rel = modbus_relationships
                        .entry(local_ip.clone())
                        .or_default()
                        .entry(remote_ip.clone())
                        .or_insert_with(|| (remote_role.to_string(), HashSet::new(), 0));
                    rel.1.insert(info.unit_id);
                    rel.2 += 1;

                    // Track polling timestamps for master requests (for interval detection)
                    if info.role == ModbusRole::Master && !info.is_exception {
                        let key = (
                            packet.src_ip.clone(),
                            packet.dst_ip.clone(),
                            info.function_code,
                            info.unit_id,
                        );
                        modbus_polling_timestamps
                            .entry(key)
                            .or_default()
                            .push(ts_epoch);
                    }
                }
                DeepParseResult::Dnp3(ref info) => {
                    let ip_for_fc = &packet.src_ip;

                    // Track function codes
                    if let Some(fc) = info.function_code {
                        *dnp3_fc_counts
                            .entry(ip_for_fc.clone())
                            .or_default()
                            .entry(fc)
                            .or_insert(0) += 1;
                    }

                    // Track DNP3 addresses
                    dnp3_addresses
                        .entry(ip_for_fc.clone())
                        .or_default()
                        .insert(info.source_address);

                    // Track roles
                    let role_str = match info.role {
                        Dnp3Role::Master => "master",
                        Dnp3Role::Outstation => "outstation",
                        Dnp3Role::Unknown => "unknown",
                    };
                    dnp3_roles
                        .entry(ip_for_fc.clone())
                        .or_default()
                        .insert(role_str.to_string());

                    // Track unsolicited responses
                    if info.is_unsolicited {
                        dnp3_unsolicited.insert(ip_for_fc.clone(), true);
                    }

                    // Track relationships
                    let remote_role = match info.role {
                        Dnp3Role::Master => "outstation",
                        Dnp3Role::Outstation => "master",
                        Dnp3Role::Unknown => "unknown",
                    };
                    let rel = dnp3_relationships
                        .entry(ip_for_fc.clone())
                        .or_default()
                        .entry(packet.dst_ip.clone())
                        .or_insert_with(|| (remote_role.to_string(), 0));
                    rel.1 += 1;
                }
            }
        }

        // Feed into topology builder
        topo_builder.add_connection(
            &packet.src_ip,
            &packet.dst_ip,
            packet.src_mac.as_deref(),
            packet.dst_mac.as_deref(),
            protocol,
            packet.length as u64,
        );
    }

    // Finalize origin_files on each connection
    for (conn_key, conn) in &mut connections {
        if let Some(files) = conn_origin_files.get(conn_key) {
            conn.origin_files = files.iter().cloned().collect();
            conn.origin_files.sort();
        }
    }

    // ── Deep Parse Aggregation ──────────────────────────────────────
    // Build per-IP DeepParseInfo from accumulated deep parse data.
    let mut deep_parse_info: HashMap<String, DeepParseInfo> = HashMap::new();

    // Aggregate Modbus data
    let all_modbus_ips: HashSet<String> = modbus_fc_counts
        .keys()
        .chain(modbus_roles.keys())
        .cloned()
        .collect();

    for ip in &all_modbus_ips {
        let role = modbus_roles.get(ip).map(|roles| {
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

        let mut unit_ids: Vec<u8> = modbus_unit_ids
            .get(ip)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        unit_ids.sort();

        let function_codes: Vec<FunctionCodeStat> = modbus_fc_counts
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

        let register_ranges: Vec<RegisterRangeInfo> = modbus_register_ranges
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

        let device_id = modbus_device_ids.get(ip).map(|d| ModbusDeviceIdInfo {
            vendor_name: d.vendor_name.clone(),
            product_code: d.product_code.clone(),
            revision: d.revision.clone(),
            vendor_url: d.vendor_url.clone(),
            product_name: d.product_name.clone(),
            model_name: d.model_name.clone(),
        });

        let relationships: Vec<ModbusRelationship> = modbus_relationships
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
        for ((src, dst, fc, uid), timestamps) in &modbus_polling_timestamps {
            if src == ip && timestamps.len() >= 3 {
                let mut sorted_ts = timestamps.clone();
                sorted_ts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

                // Compute intervals between consecutive timestamps
                let intervals: Vec<f64> = sorted_ts.windows(2)
                    .map(|w| (w[1] - w[0]) * 1000.0) // convert to ms
                    .filter(|&i| i > 0.0 && i < 60_000.0) // filter out gaps > 60s
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
    let all_dnp3_ips: HashSet<String> = dnp3_fc_counts
        .keys()
        .chain(dnp3_roles.keys())
        .cloned()
        .collect();

    for ip in &all_dnp3_ips {
        let role = dnp3_roles.get(ip).map(|roles| {
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

        let mut addresses: Vec<u16> = dnp3_addresses
            .get(ip)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        addresses.sort();

        let function_codes: Vec<FunctionCodeStat> = dnp3_fc_counts
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

        let has_unsolicited = dnp3_unsolicited.get(ip).copied().unwrap_or(false);

        let relationships: Vec<Dnp3Relationship> = dnp3_relationships
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

    // ── Signature Matching ────────────────────────────────────────
    // Convert packets to PacketData for the signature engine and group by IP.
    // We run signature matching per-device: collect all packets where the IP
    // is either source or destination, then match signatures against that set.
    let mut ip_packets: HashMap<String, Vec<PacketData>> = HashMap::new();

    for packet in &all_packets {
        let protocol = identify_protocol(packet);
        let proto_str = format!("{:?}", protocol).to_lowercase();

        let pkt_data = PacketData {
            src_ip: packet.src_ip.clone(),
            dst_ip: packet.dst_ip.clone(),
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            src_mac: packet.src_mac.clone(),
            dst_mac: packet.dst_mac.clone(),
            transport: format!("{:?}", packet.transport).to_lowercase(),
            protocol: proto_str,
            payload: packet.payload.clone(),
            length: packet.length,
        };

        // Associate packet with both src and dst IP for signature matching
        ip_packets
            .entry(packet.src_ip.clone())
            .or_default()
            .push(pkt_data.clone());
        ip_packets
            .entry(packet.dst_ip.clone())
            .or_default()
            .push(pkt_data);
    }

    // We need access to the signature engine from state for matching.
    // Lock state briefly to run matching, then release before the final update.
    let sig_results: HashMap<String, Vec<AssetSignatureMatch>> = {
        let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
        let mut results = HashMap::new();

        for (ip, packets) in &ip_packets {
            let matches = state_inner.signature_engine.match_device_packets(packets);
            if !matches.is_empty() {
                results.insert(
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

        results
    };

    // Build assets from collected data, enriched with signature results
    let all_ips: HashSet<String> = asset_protocols.keys().cloned().collect();
    let mut assets: Vec<AssetInfo> = Vec::new();

    for ip in &all_ips {
        let protocols: Vec<IcsProtocol> = asset_protocols
            .get(ip)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();

        let is_server = server_ips.contains(ip);
        let mut device_type = infer_device_type(&protocols, is_server);

        // Apply signature match data
        let sig_matches = sig_results.get(ip).cloned().unwrap_or_default();
        let best_match = sig_matches.first();

        // Highest confidence from any signature match (0 if no matches)
        let mut confidence = best_match.map(|m| m.confidence).unwrap_or(
            // Default confidence: 1 if we identified a protocol by port, 0 if unknown
            if protocols.iter().any(|p| *p != IcsProtocol::Unknown) {
                1
            } else {
                0
            },
        );

        // Use vendor from highest-confidence signature match
        let mut vendor = best_match.and_then(|m| m.vendor.clone());
        let mut product_family = best_match.and_then(|m| m.product_family.clone());

        // Deep parse Device ID (FC 43/14) overrides with confidence 5
        if let Some(dp_info) = deep_parse_info.get(ip) {
            if let Some(ref modbus) = dp_info.modbus {
                if let Some(ref dev_id) = modbus.device_id {
                    confidence = 5;
                    if let Some(ref vn) = dev_id.vendor_name {
                        vendor = Some(vn.clone());
                    }
                    // Build product family from available fields
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

        // Override device_type if signature provides one with higher confidence
        if let Some(m) = best_match {
            if let Some(ref sig_device_type) = m.device_type {
                if m.confidence >= 3 {
                    device_type = sig_device_type.clone();
                }
            }
        }

        assets.push(AssetInfo {
            id: ip.clone(),
            ip_address: ip.clone(),
            mac_address: asset_macs.get(ip).cloned(),
            hostname: None,
            device_type,
            vendor,
            protocols: protocols.iter().map(|p| format!("{:?}", p).to_lowercase()).collect(),
            first_seen: asset_first_seen.get(ip).cloned().unwrap_or_default(),
            last_seen: asset_last_seen.get(ip).cloned().unwrap_or_default(),
            notes: String::new(),
            purdue_level: None,
            tags: Vec::new(),
            packet_count: *asset_packet_counts.get(ip).unwrap_or(&0),
            confidence,
            product_family,
            signature_matches: sig_matches,
        });
    }

    // Sort assets: OT devices first, then by packet count descending
    assets.sort_by(|a, b| {
        let a_ot = a.device_type != "it_device" && a.device_type != "unknown";
        let b_ot = b.device_type != "it_device" && b.device_type != "unknown";
        b_ot.cmp(&a_ot).then(b.packet_count.cmp(&a.packet_count))
    });

    let mut topology = topo_builder.build();

    // Enrich topology nodes with signature-derived data (vendor, device_type)
    for node in &mut topology.nodes {
        if let Some(sig_matches) = sig_results.get(&node.ip_address) {
            if let Some(best) = sig_matches.first() {
                if let Some(ref v) = best.vendor {
                    node.vendor = Some(v.clone());
                }
                if let Some(ref dt) = best.device_type {
                    if best.confidence >= 3 {
                        node.device_type = dt.clone();
                    }
                }
            }
        }
    }
    let connection_list: Vec<ConnectionInfo> = connections.into_values().collect();
    let asset_count = assets.len();
    let connection_count = connection_list.len();
    let protocols_detected: Vec<String> = all_protocols.into_iter().collect();

    // Collect imported filenames
    let imported_files: Vec<String> = per_file_results
        .iter()
        .filter(|f| f.status == "ok")
        .map(|f| f.filename.clone())
        .collect();

    // Store results in app state
    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    state_inner.topology = topology;
    state_inner.assets = assets;
    state_inner.connections = connection_list;
    state_inner.packet_summaries = packet_summaries;
    state_inner.deep_parse_info = deep_parse_info;
    state_inner.imported_files.extend(imported_files);
    state_inner.imported_files.sort();
    state_inner.imported_files.dedup();

    let duration_ms = start.elapsed().as_millis() as u64;

    log::info!(
        "Imported {} files, {} packets → {} assets, {} connections in {}ms",
        paths.len(), total_packet_count, asset_count, connection_count, duration_ms
    );

    Ok(ImportResult {
        file_count: paths.len(),
        packet_count: total_packet_count,
        connection_count,
        asset_count,
        protocols_detected,
        duration_ms,
        per_file: per_file_results,
    })
}
