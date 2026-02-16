//! Tauri commands for physical topology operations.
//!
//! Supports importing Cisco IOS configs, MAC address tables,
//! CDP neighbor output, and ARP tables.

use std::path::Path;
use tauri::State;

use gm_physical::{PhysicalTopology, cisco};

use super::AppState;

/// Import a Cisco IOS running-config file.
///
/// Parses the config for hostname, interfaces, VLANs, and IPs,
/// then adds the switch to the physical topology.
#[tauri::command]
pub fn import_cisco_config(
    path: String,
    state: State<'_, AppState>,
) -> Result<PhysicalTopology, String> {
    let file_path = Path::new(&path);
    let switch = cisco::parse_running_config_file(file_path)
        .map_err(|e| e.to_string())?;

    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    // Check if a switch with this hostname already exists; if so, replace it
    let hostname = switch.hostname.clone();
    state_inner.physical_topology.switches.retain(|s| s.hostname != hostname);
    state_inner.physical_topology.switches.push(switch);

    // Rebuild links from CDP data
    state_inner.physical_topology.build_links();
    // Re-correlate ARP→port mappings
    state_inner.physical_topology.correlate_arp_to_ports();

    log::info!("Imported Cisco config for switch '{}' from {}", hostname, path);

    Ok(state_inner.physical_topology.clone())
}

/// Import a `show mac address-table` output file.
///
/// Associates MAC addresses with switch ports. Requires a switch
/// hostname to know which switch this data belongs to.
#[tauri::command]
pub fn import_mac_table(
    path: String,
    switch_hostname: String,
    state: State<'_, AppState>,
) -> Result<PhysicalTopology, String> {
    let file_path = Path::new(&path);
    let entries = cisco::parse_mac_table_file(file_path)
        .map_err(|e| e.to_string())?;

    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    // Check the switch exists
    if !state_inner.physical_topology.switches.iter().any(|s| s.hostname == switch_hostname) {
        return Err(format!(
            "Switch '{}' not found. Import its running-config first.", switch_hostname
        ));
    }

    let count = entries.len();
    state_inner.physical_topology.apply_mac_table(&switch_hostname, &entries);

    // Re-correlate since we have new MAC→port mappings
    state_inner.physical_topology.correlate_arp_to_ports();

    log::info!("Imported {} MAC table entries for switch '{}'", count, switch_hostname);

    Ok(state_inner.physical_topology.clone())
}

/// Import a `show cdp neighbors detail` output file.
///
/// Discovers physical adjacencies between switches.
#[tauri::command]
pub fn import_cdp_neighbors(
    path: String,
    switch_hostname: String,
    state: State<'_, AppState>,
) -> Result<PhysicalTopology, String> {
    let file_path = Path::new(&path);
    let neighbors = cisco::parse_cdp_neighbors_file(file_path)
        .map_err(|e| e.to_string())?;

    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    if !state_inner.physical_topology.switches.iter().any(|s| s.hostname == switch_hostname) {
        return Err(format!(
            "Switch '{}' not found. Import its running-config first.", switch_hostname
        ));
    }

    let count = neighbors.len();
    state_inner.physical_topology.apply_cdp_neighbors(&switch_hostname, &neighbors);

    // Rebuild inter-switch links from the updated CDP data
    state_inner.physical_topology.build_links();

    log::info!("Imported {} CDP neighbors for switch '{}'", count, switch_hostname);

    Ok(state_inner.physical_topology.clone())
}

/// Import a `show arp` / `show ip arp` output file.
///
/// Correlates IP addresses with MAC addresses and maps them to
/// switch ports via the MAC address table.
#[tauri::command]
pub fn import_arp_table(
    path: String,
    state: State<'_, AppState>,
) -> Result<PhysicalTopology, String> {
    let file_path = Path::new(&path);
    let entries = cisco::parse_arp_table_file(file_path)
        .map_err(|e| e.to_string())?;

    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let count = entries.len();
    state_inner.physical_topology.apply_arp_entries(&entries);

    // Correlate with existing MAC table data
    state_inner.physical_topology.correlate_arp_to_ports();

    log::info!("Imported {} ARP entries", count);

    Ok(state_inner.physical_topology.clone())
}

/// Get the current physical topology.
#[tauri::command]
pub fn get_physical_topology(
    state: State<'_, AppState>,
) -> Result<PhysicalTopology, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.physical_topology.clone())
}

/// Clear all physical topology data.
#[tauri::command]
pub fn clear_physical_topology(
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    state_inner.physical_topology = PhysicalTopology::default();
    log::info!("Cleared physical topology");
    Ok(())
}
