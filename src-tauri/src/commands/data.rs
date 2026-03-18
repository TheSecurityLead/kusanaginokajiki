use serde::Serialize;
use std::collections::{HashMap, HashSet};
use tauri::State;

use super::{
    AppState, AssetInfo, ConnectionInfo, DeepParseInfo, FunctionCodeStat, PacketSummary,
    ProtocolStatInfo,
};
use gm_topology::TopologyGraph;

/// Maximum nodes returned by get_topology. Excess nodes (by packet count) are
/// dropped to prevent the webview from being asked to render a massive graph.
const MAX_TOPOLOGY_NODES: usize = 5_000;
/// Maximum edges returned by get_topology.
const MAX_TOPOLOGY_EDGES: usize = 20_000;

/// Get the current network topology graph for visualization.
///
/// Nodes are capped at MAX_TOPOLOGY_NODES (5 000) by packet_count descending.
/// Edges are then filtered to only include connections between remaining nodes
/// and capped at MAX_TOPOLOGY_EDGES (20 000) by packet_count descending.
/// For smaller datasets the full graph is returned unchanged.
#[tauri::command]
pub fn get_topology(state: State<'_, AppState>) -> Result<TopologyGraph, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    let topo = &state_inner.topology;

    if topo.nodes.len() <= MAX_TOPOLOGY_NODES && topo.edges.len() <= MAX_TOPOLOGY_EDGES {
        return Ok(topo.clone());
    }

    // Cap nodes: keep the highest-traffic devices.
    let mut nodes = topo.nodes.clone();
    nodes.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    nodes.truncate(MAX_TOPOLOGY_NODES);

    // Build a set of the retained node IDs so we can filter edges cheaply.
    let retained: HashSet<&str> = nodes.iter().map(|n| n.id.as_str()).collect();

    // Filter edges to connections between retained nodes, then cap.
    let mut edges: Vec<_> = topo
        .edges
        .iter()
        .filter(|e| retained.contains(e.source.as_str()) && retained.contains(e.target.as_str()))
        .cloned()
        .collect();
    edges.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    edges.truncate(MAX_TOPOLOGY_EDGES);

    Ok(TopologyGraph { nodes, edges })
}

// ─── Paginated data responses ──────────────────────────────────

/// A page of assets returned by `get_assets`.
#[derive(Serialize, Clone)]
pub struct AssetPage {
    pub assets: Vec<AssetInfo>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub has_more: bool,
}

/// A page of connections returned by `get_connections`.
#[derive(Serialize, Clone)]
pub struct ConnectionPage {
    pub connections: Vec<ConnectionInfo>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub has_more: bool,
}

/// Lightweight counts for the sidebar (no payload).
#[derive(Serialize, Clone)]
pub struct DataCounts {
    pub asset_count: usize,
    pub connection_count: usize,
}

/// Get discovered assets, paginated.
///
/// Parameters:
/// - `page`: zero-based page index (default 0)
/// - `page_size`: items per page (default 200)
/// - `sort_by`: optional sort key — "ip", "packets", "protocol", "connections"
#[tauri::command]
pub fn get_assets(
    state: State<'_, AppState>,
    page: Option<usize>,
    page_size: Option<usize>,
    sort_by: Option<String>,
) -> Result<AssetPage, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let page = page.unwrap_or(0);
    let page_size = page_size.unwrap_or(200);

    let mut all_assets = state_inner.assets.clone();
    let total = all_assets.len();

    // Sort
    match sort_by.as_deref() {
        Some("ip") => all_assets.sort_by(|a, b| a.ip_address.cmp(&b.ip_address)),
        Some("packets") => all_assets.sort_by(|a, b| b.packet_count.cmp(&a.packet_count)),
        Some("protocol") => {
            all_assets.sort_by(|a, b| {
                let ap = a.protocols.first().map(|s| s.as_str()).unwrap_or("");
                let bp = b.protocols.first().map(|s| s.as_str()).unwrap_or("");
                ap.cmp(bp)
            });
        }
        _ => {} // default insertion order
    }

    // Paginate
    let start = page * page_size;
    let assets = if start < total {
        all_assets.into_iter().skip(start).take(page_size).collect()
    } else {
        Vec::new()
    };
    let has_more = start + page_size < total;

    Ok(AssetPage {
        assets,
        total,
        page,
        page_size,
        has_more,
    })
}

/// Get observed connections, paginated.
///
/// Parameters:
/// - `page`: zero-based page index (default 0)
/// - `page_size`: items per page (default 500)
/// - `sort_by`: optional sort key — "packets", "bytes"
#[tauri::command]
pub fn get_connections(
    state: State<'_, AppState>,
    page: Option<usize>,
    page_size: Option<usize>,
    sort_by: Option<String>,
) -> Result<ConnectionPage, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let page = page.unwrap_or(0);
    let page_size = page_size.unwrap_or(500);

    let mut all_connections = state_inner.connections.clone();
    let total = all_connections.len();

    match sort_by.as_deref() {
        Some("packets") => {
            all_connections.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
        }
        Some("bytes") => {
            all_connections.sort_by(|a, b| b.byte_count.cmp(&a.byte_count));
        }
        _ => {}
    }

    let start = page * page_size;
    let connections = if start < total {
        all_connections
            .into_iter()
            .skip(start)
            .take(page_size)
            .collect()
    } else {
        Vec::new()
    };
    let has_more = start + page_size < total;

    Ok(ConnectionPage {
        connections,
        total,
        page,
        page_size,
        has_more,
    })
}

/// Get lightweight asset/connection counts for the sidebar.
///
/// This avoids serializing the full dataset just to show totals.
#[tauri::command]
pub fn get_data_counts(state: State<'_, AppState>) -> Result<DataCounts, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(DataCounts {
        asset_count: state_inner.assets.len(),
        connection_count: state_inner.connections.len(),
    })
}

/// Compute protocol breakdown statistics from current connections.
///
/// Single-pass O(n_connections): accumulates stats and unique-device sets for
/// all protocols in one loop, avoiding the previous O(protocols × connections)
/// double-loop.
#[tauri::command]
pub fn get_protocol_stats(state: State<'_, AppState>) -> Result<Vec<ProtocolStatInfo>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let mut stats: HashMap<String, ProtocolStatInfo> = HashMap::new();
    // Track unique devices per protocol in the same pass.
    let mut devices_per_proto: HashMap<String, HashSet<String>> = HashMap::new();

    for conn in &state_inner.connections {
        let entry = stats
            .entry(conn.protocol.clone())
            .or_insert_with(|| ProtocolStatInfo {
                protocol: conn.protocol.clone(),
                packet_count: 0,
                byte_count: 0,
                connection_count: 0,
                unique_devices: 0,
            });
        entry.packet_count += conn.packet_count;
        entry.byte_count += conn.byte_count;
        entry.connection_count += 1;

        let dev = devices_per_proto.entry(conn.protocol.clone()).or_default();
        dev.insert(conn.src_ip.clone());
        dev.insert(conn.dst_ip.clone());
    }

    // Merge unique device counts into stats.
    for (proto, dev_set) in &devices_per_proto {
        if let Some(stat) = stats.get_mut(proto) {
            stat.unique_devices = dev_set.len() as u64;
        }
    }

    let mut result: Vec<ProtocolStatInfo> = stats.into_values().collect();
    result.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));

    Ok(result)
}

/// Get packet summaries for a specific connection (for the connection tree detail view).
///
/// Already capped at 1000 per connection during ingestion (see processor.rs).
#[tauri::command]
pub fn get_connection_packets(
    connection_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<PacketSummary>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner
        .packet_summaries
        .get(&connection_id)
        .cloned()
        .unwrap_or_default())
}

/// Get deep parse information for a specific device by IP address.
///
/// Returns Modbus/DNP3 details including function codes, unit IDs,
/// register ranges, device identification, and polling intervals.
#[tauri::command]
pub fn get_deep_parse_info(
    ip_address: String,
    state: State<'_, AppState>,
) -> Result<Option<DeepParseInfo>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.deep_parse_info.get(&ip_address).cloned())
}

/// Get function code distribution across all protocols.
///
/// Returns aggregated function code stats for the protocol stats view,
/// showing which function codes are most used across the network.
#[tauri::command]
pub fn get_function_code_stats(
    state: State<'_, AppState>,
) -> Result<HashMap<String, Vec<FunctionCodeStat>>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let mut modbus_fcs: HashMap<u8, u64> = HashMap::new();
    let mut dnp3_fcs: HashMap<u8, u64> = HashMap::new();

    for info in state_inner.deep_parse_info.values() {
        if let Some(ref modbus) = info.modbus {
            for fc in &modbus.function_codes {
                *modbus_fcs.entry(fc.code).or_insert(0) += fc.count;
            }
        }
        if let Some(ref dnp3) = info.dnp3 {
            for fc in &dnp3.function_codes {
                *dnp3_fcs.entry(fc.code).or_insert(0) += fc.count;
            }
        }
    }

    let mut result: HashMap<String, Vec<FunctionCodeStat>> = HashMap::new();

    if !modbus_fcs.is_empty() {
        let mut fcs: Vec<FunctionCodeStat> = modbus_fcs
            .into_iter()
            .map(|(code, count)| FunctionCodeStat {
                code,
                name: gm_parsers::modbus_function_code_name(code).to_string(),
                count,
                is_write: matches!(code, 5 | 6 | 15 | 16 | 22 | 23),
            })
            .collect();
        fcs.sort_by(|a, b| b.count.cmp(&a.count));
        result.insert("modbus".to_string(), fcs);
    }

    if !dnp3_fcs.is_empty() {
        let mut fcs: Vec<FunctionCodeStat> = dnp3_fcs
            .into_iter()
            .map(|(code, count)| FunctionCodeStat {
                code,
                name: gm_parsers::dnp3_function_code_name(code).to_string(),
                count,
                is_write: matches!(code, 2..=6),
            })
            .collect();
        fcs.sort_by(|a, b| b.count.cmp(&a.count));
        result.insert("dnp3".to_string(), fcs);
    }

    Ok(result)
}

// ─── Timeline (Phase 11) ────────────────────────────────────

/// Timeline range: earliest and latest timestamps across all connections.
#[derive(Debug, Clone, Serialize)]
pub struct TimelineRange {
    pub earliest: Option<String>,
    pub latest: Option<String>,
    /// Total number of connections with timestamps
    pub connection_count: usize,
}

/// Get the time range of the current dataset.
///
/// Returns the earliest and latest timestamps from all connections,
/// used by the timeline scrubber to set slider bounds.
/// Scans all connections (not capped) to ensure accurate bounds.
#[tauri::command]
pub fn get_timeline_range(state: State<'_, AppState>) -> Result<TimelineRange, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let mut earliest: Option<&str> = None;
    let mut latest: Option<&str> = None;

    for conn in &state_inner.connections {
        let fs = conn.first_seen.as_str();
        let ls = conn.last_seen.as_str();

        match earliest {
            None => earliest = Some(fs),
            Some(e) if fs < e => earliest = Some(fs),
            _ => {}
        }
        match latest {
            None => latest = Some(ls),
            Some(l) if ls > l => latest = Some(ls),
            _ => {}
        }
    }

    Ok(TimelineRange {
        earliest: earliest.map(|s| s.to_string()),
        latest: latest.map(|s| s.to_string()),
        connection_count: state_inner.connections.len(),
    })
}
