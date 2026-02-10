use std::collections::{HashMap, HashSet};
use std::time::Instant;
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use gm_capture::PcapReader;
use gm_parsers::{identify_protocol, IcsProtocol};
use gm_topology::TopologyBuilder;

use super::{AppState, AssetInfo, ConnectionInfo, PacketSummary, infer_device_type};

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

    // Build assets from collected data
    let all_ips: HashSet<String> = asset_protocols.keys().cloned().collect();
    let mut assets: Vec<AssetInfo> = Vec::new();

    for ip in &all_ips {
        let protocols: Vec<IcsProtocol> = asset_protocols
            .get(ip)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();

        let is_server = server_ips.contains(ip);
        let device_type = infer_device_type(&protocols, is_server);

        assets.push(AssetInfo {
            id: ip.clone(),
            ip_address: ip.clone(),
            mac_address: asset_macs.get(ip).cloned(),
            hostname: None,
            device_type,
            vendor: None,
            protocols: protocols.iter().map(|p| format!("{:?}", p).to_lowercase()).collect(),
            first_seen: asset_first_seen.get(ip).cloned().unwrap_or_default(),
            last_seen: asset_last_seen.get(ip).cloned().unwrap_or_default(),
            notes: String::new(),
            purdue_level: None,
            tags: Vec::new(),
            packet_count: *asset_packet_counts.get(ip).unwrap_or(&0),
        });
    }

    // Sort assets: OT devices first, then by packet count descending
    assets.sort_by(|a, b| {
        let a_ot = a.device_type != "it_device" && a.device_type != "unknown";
        let b_ot = b.device_type != "it_device" && b.device_type != "unknown";
        b_ot.cmp(&a_ot).then(b.packet_count.cmp(&a.packet_count))
    });

    let topology = topo_builder.build();
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
