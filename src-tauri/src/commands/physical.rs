//! Tauri commands for physical topology operations.
//!
//! Supports importing Cisco IOS, Juniper JunOS, and HP/Aruba ProCurve
//! configs, MAC address tables, LLDP/CDP neighbors, and ARP tables.
//! Also supports traffic-inferred topology from observed packet flows.

use std::path::Path;
use tauri::State;

use gm_physical::{PhysicalTopology, InferredTopology, cisco, juniper, aruba, inference};
use gm_physical::inference::{InferenceInput, AssetSnapshot as InfAssetSnapshot, ConnSnapshot};

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

// ─── Multi-Vendor Commands ────────────────────────────────────────

/// Import a network device config with automatic vendor detection.
///
/// Detects Cisco IOS, Juniper JunOS, or HP/Aruba ProCurve by content
/// signatures and dispatches to the appropriate parser.
#[tauri::command]
pub fn import_network_config(
    path: String,
    state: State<'_, AppState>,
) -> Result<PhysicalTopology, String> {
    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let file_path = Path::new(&path);

    // Auto-detect vendor by content keywords
    let switch = if content.contains("set system host-name") || content.contains("set interfaces ge-") || content.contains("set interfaces xe-") {
        // Juniper JunOS set-format
        juniper::parse_junos_config(&content).map_err(|e| e.to_string())?
    } else if content.contains("hostname \"") && content.contains("untagged") {
        // HP/Aruba ProCurve
        aruba::parse_aruba_config(&content).map_err(|e| e.to_string())?
    } else {
        // Default to Cisco IOS
        cisco::parse_running_config_file(file_path).map_err(|e| e.to_string())?
    };

    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    let hostname = switch.hostname.clone();
    state_inner.physical_topology.switches.retain(|s| s.hostname != hostname);
    state_inner.physical_topology.switches.push(switch);
    state_inner.physical_topology.build_links();
    state_inner.physical_topology.correlate_arp_to_ports();

    log::info!("Auto-imported network config for switch '{}' from {}", hostname, path);
    Ok(state_inner.physical_topology.clone())
}

/// Import a MAC address table with automatic vendor detection.
///
/// The switch must already be imported (via import_network_config or
/// import_cisco_config) before calling this command.
#[tauri::command]
pub fn import_mac_table_auto(
    path: String,
    switch_hostname: String,
    state: State<'_, AppState>,
) -> Result<PhysicalTopology, String> {
    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let file_path = Path::new(&path);

    // Auto-detect vendor by content keywords
    let entries = if content.contains("ethernet-switching") || content.contains("Ethernet switching") {
        // Juniper JunOS ethernet-switching table
        juniper::parse_ethernet_switching_table(&content, &switch_hostname)
    } else if content.to_lowercase().contains("mac address") && content.contains('-') {
        // HP/Aruba format (aabbcc-ddeeff MAC style)
        aruba::parse_aruba_mac_table(&content)
    } else {
        // Default to Cisco IOS
        cisco::parse_mac_table_file(file_path).map_err(|e| e.to_string())?
    };

    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    if !state_inner.physical_topology.switches.iter().any(|s| s.hostname == switch_hostname) {
        return Err(format!(
            "Switch '{}' not found. Import its config first.", switch_hostname
        ));
    }

    let count = entries.len();
    state_inner.physical_topology.apply_mac_table(&switch_hostname, &entries);
    state_inner.physical_topology.correlate_arp_to_ports();

    log::info!("Auto-imported {} MAC table entries for switch '{}'", count, switch_hostname);
    Ok(state_inner.physical_topology.clone())
}

/// Import an LLDP/CDP neighbor table with automatic vendor detection.
///
/// The switch must already be imported before calling this command.
#[tauri::command]
pub fn import_neighbor_table(
    path: String,
    switch_hostname: String,
    state: State<'_, AppState>,
) -> Result<PhysicalTopology, String> {
    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let file_path = Path::new(&path);

    // Auto-detect: JunOS LLDP has "ge-"/"xe-" interface names
    // HP/Aruba LLDP has "|" pipe separators or "LocalPort" header
    // Cisco CDP has "Device ID:" entries
    let neighbors = if content.contains("ge-") || content.contains("xe-") || content.contains("et-") {
        // Juniper JunOS LLDP
        juniper::parse_lldp_neighbors(&content)
    } else if content.contains("ChassisId") || content.contains("LocalPort") {
        // HP/Aruba LLDP
        aruba::parse_aruba_lldp_neighbors(&content)
    } else {
        // Cisco CDP
        cisco::parse_cdp_neighbors_file(file_path).map_err(|e| e.to_string())?
    };

    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    if !state_inner.physical_topology.switches.iter().any(|s| s.hostname == switch_hostname) {
        return Err(format!(
            "Switch '{}' not found. Import its config first.", switch_hostname
        ));
    }

    let count = neighbors.len();
    state_inner.physical_topology.apply_cdp_neighbors(&switch_hostname, &neighbors);
    state_inner.physical_topology.build_links();

    log::info!("Auto-imported {} neighbor entries for switch '{}'", count, switch_hostname);
    Ok(state_inner.physical_topology.clone())
}

/// Run traffic-inferred topology analysis from the current dataset.
///
/// Derives subnet structure, gateway candidates, switch candidates, and
/// broadcast domains purely from observed packet flows — no switch config
/// files required.
#[tauri::command]
pub fn run_topology_inference(
    state: State<'_, AppState>,
) -> Result<InferredTopology, String> {
    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let input = InferenceInput {
        assets: state_inner.assets.iter().map(|a| InfAssetSnapshot {
            ip_address: a.ip_address.clone(),
            mac_address: a.mac_address.clone(),
        }).collect(),
        connections: state_inner.connections.iter().map(|c| ConnSnapshot {
            src_ip: c.src_ip.clone(),
            dst_ip: c.dst_ip.clone(),
            src_mac: c.src_mac.clone(),
            dst_mac: c.dst_mac.clone(),
            packet_count: c.packet_count,
        }).collect(),
    };

    let result = inference::infer_topology(&input);

    log::info!(
        "Inferred topology: {} subnets, {} gateways, {} switch candidates",
        result.subnets.len(),
        result.gateways.len(),
        result.switch_candidates.len()
    );

    state_inner.inferred_topology = Some(result.clone());
    Ok(result)
}

/// Get the last computed inferred topology (or None if not yet run).
#[tauri::command]
pub fn get_inferred_topology(
    state: State<'_, AppState>,
) -> Result<Option<InferredTopology>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.inferred_topology.clone())
}
