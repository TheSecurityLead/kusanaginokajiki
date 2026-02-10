use std::collections::{HashMap, HashSet};
use tauri::State;

use gm_topology::TopologyGraph;
use super::{AppState, AssetInfo, ConnectionInfo, ProtocolStatInfo};

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
