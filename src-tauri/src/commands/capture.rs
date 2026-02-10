use std::collections::{HashMap, HashSet};
use std::time::Instant;
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use gm_capture::PcapReader;
use gm_parsers::{identify_protocol, IcsProtocol};
use gm_topology::TopologyBuilder;

use super::{AppState, AssetInfo, ConnectionInfo, infer_device_type};

#[derive(Serialize)]
pub struct ImportResult {
    packet_count: usize,
    connection_count: usize,
    asset_count: usize,
    protocols_detected: Vec<String>,
    duration_ms: u64,
}

/// Import a PCAP file and process it through the full pipeline:
/// 1. Read packets (gm-capture)
/// 2. Identify protocols (gm-parsers)
/// 3. Build topology graph (gm-topology)
/// 4. Store results in app state
///
/// This is the core import workflow that drives the entire application.
#[tauri::command]
pub async fn import_pcap(
    file_path: String,
    state: State<'_, AppState>,
) -> Result<ImportResult, String> {
    let start = Instant::now();

    // Step 1: Read packets from PCAP file
    let reader = PcapReader::new();
    let packets = reader
        .read_file(&file_path)
        .map_err(|e| format!("Failed to read PCAP: {}", e))?;

    let packet_count = packets.len();

    // Step 2: Identify protocols and build connection map
    let mut topo_builder = TopologyBuilder::new();
    let mut connections: HashMap<String, ConnectionInfo> = HashMap::new();
    let mut asset_protocols: HashMap<String, HashSet<IcsProtocol>> = HashMap::new();
    let mut asset_macs: HashMap<String, String> = HashMap::new();
    let mut asset_packet_counts: HashMap<String, u64> = HashMap::new();
    let mut asset_first_seen: HashMap<String, String> = HashMap::new();
    let mut asset_last_seen: HashMap<String, String> = HashMap::new();
    // Track which IPs are servers (receive connections on well-known ports)
    let mut server_ips: HashSet<String> = HashSet::new();
    let mut all_protocols: HashSet<String> = HashSet::new();

    for packet in &packets {
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

        // Detect servers (respond on well-known OT ports)
        if protocol.is_ot() && packet.src_port <= 1024 {
            server_ips.insert(packet.src_ip.clone());
        }
        if protocol.is_ot() && packet.dst_port <= 1024 {
            server_ips.insert(packet.dst_ip.clone());
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
            }
        });

        conn.packet_count += 1;
        conn.byte_count += packet.length as u64;
        conn.last_seen = timestamp;

        // Step 3: Feed into topology builder
        topo_builder.add_connection(
            &packet.src_ip,
            &packet.dst_ip,
            packet.src_mac.as_deref(),
            packet.dst_mac.as_deref(),
            protocol,
            packet.length as u64,
        );
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
            id: ip.clone(), // Use IP as ID for now; UUID in Phase 5
            ip_address: ip.clone(),
            mac_address: asset_macs.get(ip).cloned(),
            hostname: None, // DNS reverse lookup in future phase
            device_type,
            vendor: None, // MAC OUI lookup in Phase 5
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

    // Step 4: Store results in app state
    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    state_inner.topology = topology;
    state_inner.assets = assets;
    state_inner.connections = connection_list;

    let duration_ms = start.elapsed().as_millis() as u64;

    log::info!(
        "Imported {} packets → {} assets, {} connections in {}ms",
        packet_count, asset_count, connection_count, duration_ms
    );

    Ok(ImportResult {
        packet_count,
        connection_count,
        asset_count,
        protocols_detected,
        duration_ms,
    })
}
