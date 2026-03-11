//! Communication pattern analysis commands.
//!
//! Returns pre-computed `ConnectionStats` and `PatternAnomaly` values that
//! were populated by `PacketProcessor::build_pattern_results()` during
//! PCAP import or live capture.

use tauri::State;
use gm_analysis::{ConnectionStats, PatternAnomaly};
use super::AppState;

/// Get per-connection timing statistics for the current dataset.
#[tauri::command]
pub fn get_connection_stats(state: State<'_, AppState>) -> Result<Vec<ConnectionStats>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(inner.connection_stats.clone())
}

/// Get detected communication pattern anomalies for the current dataset.
#[tauri::command]
pub fn get_pattern_anomalies(state: State<'_, AppState>) -> Result<Vec<PatternAnomaly>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(inner.pattern_anomalies.clone())
}
