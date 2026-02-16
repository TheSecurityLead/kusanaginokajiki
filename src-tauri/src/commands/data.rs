use std::collections::{HashMap, HashSet};
use serde::Serialize;
use tauri::State;

use gm_topology::TopologyGraph;
use super::{
    AppState, AssetInfo, ConnectionInfo, PacketSummary, ProtocolStatInfo,
    DeepParseInfo, FunctionCodeStat,
};

/// Get the current network topology graph for visualization.
#[tauri::command]
pub fn get_topology(state: State<'_, AppState>) -> Result<TopologyGraph, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.topology.clone())
}

/// Get all discovered assets.
#[tauri::command]
pub fn get_assets(state: State<'_, AppState>) -> Result<Vec<AssetInfo>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.assets.clone())
}

/// Get all observed connections.
#[tauri::command]
pub fn get_connections(state: State<'_, AppState>) -> Result<Vec<ConnectionInfo>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.connections.clone())
}

/// Compute protocol breakdown statistics from current connections.
#[tauri::command]
pub fn get_protocol_stats(state: State<'_, AppState>) -> Result<Vec<ProtocolStatInfo>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let mut stats: HashMap<String, ProtocolStatInfo> = HashMap::new();

    for conn in &state_inner.connections {
        let entry = stats.entry(conn.protocol.clone()).or_insert_with(|| {
            ProtocolStatInfo {
                protocol: conn.protocol.clone(),
                packet_count: 0,
                byte_count: 0,
                connection_count: 0,
                unique_devices: 0,
            }
        });

        entry.packet_count += conn.packet_count;
        entry.byte_count += conn.byte_count;
        entry.connection_count += 1;
    }

    // Count unique devices per protocol
    for (proto, stat) in &mut stats {
        let mut devices: HashSet<String> = HashSet::new();
        for conn in &state_inner.connections {
            if &conn.protocol == proto {
                devices.insert(conn.src_ip.clone());
                devices.insert(conn.dst_ip.clone());
            }
        }
        stat.unique_devices = devices.len() as u64;
    }

    let mut result: Vec<ProtocolStatInfo> = stats.into_values().collect();
    result.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));

    Ok(result)
}

/// Get packet summaries for a specific connection (for the connection tree detail view).
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
        let mut fcs: Vec<FunctionCodeStat> = modbus_fcs.into_iter().map(|(code, count)| {
            FunctionCodeStat {
                code,
                name: gm_parsers::modbus_function_code_name(code).to_string(),
                count,
                is_write: matches!(code, 5 | 6 | 15 | 16 | 22 | 23),
            }
        }).collect();
        fcs.sort_by(|a, b| b.count.cmp(&a.count));
        result.insert("modbus".to_string(), fcs);
    }

    if !dnp3_fcs.is_empty() {
        let mut fcs: Vec<FunctionCodeStat> = dnp3_fcs.into_iter().map(|(code, count)| {
            FunctionCodeStat {
                code,
                name: gm_parsers::dnp3_function_code_name(code).to_string(),
                count,
                is_write: matches!(code, 2..=6),
            }
        }).collect();
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
