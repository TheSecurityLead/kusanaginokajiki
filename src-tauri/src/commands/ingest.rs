//! Tauri commands for importing external tool data.
//!
//! Imports Zeek logs, Suricata eve.json, Nmap XML, and Masscan JSON.
//! Ingested data is merged into the existing pipeline alongside PCAP data.

use std::path::Path;
use std::time::Instant;
use serde::Serialize;
use tauri::State;

use gm_ingest::{IngestResult, IngestedAsset};
use gm_parsers::IcsProtocol;

use super::{AppState, AssetInfo, ConnectionInfo};

/// Result returned to the frontend from an ingest operation.
#[derive(Serialize)]
pub struct IngestImportResult {
    pub source: String,
    pub files_processed: usize,
    pub asset_count: usize,
    pub connection_count: usize,
    pub alert_count: usize,
    pub new_assets: usize,
    pub updated_assets: usize,
    pub duration_ms: u64,
    pub errors: Vec<String>,
}

/// Import Zeek TSV log files (conn.log, modbus.log, dnp3.log, s7comm.log).
#[tauri::command]
pub async fn import_zeek_logs(
    paths: Vec<String>,
    state: State<'_, AppState>,
) -> Result<IngestImportResult, String> {
    let start = Instant::now();

    let path_refs: Vec<&Path> = paths.iter().map(|p| Path::new(p.as_str())).collect();
    let ingest_result = gm_ingest::zeek::parse_zeek_logs(&path_refs)
        .map_err(|e| e.to_string())?;

    let import_result = merge_ingest_result(ingest_result, &state, start)?;

    log::info!(
        "Zeek import: {} files → {} assets ({} new), {} connections, {}ms",
        import_result.files_processed, import_result.asset_count,
        import_result.new_assets, import_result.connection_count,
        import_result.duration_ms
    );

    Ok(import_result)
}

/// Import a Suricata eve.json file.
#[tauri::command]
pub async fn import_suricata_eve(
    path: String,
    state: State<'_, AppState>,
) -> Result<IngestImportResult, String> {
    let start = Instant::now();

    let ingest_result = gm_ingest::suricata::parse_eve_json(Path::new(&path))
        .map_err(|e| e.to_string())?;

    let import_result = merge_ingest_result(ingest_result, &state, start)?;

    log::info!(
        "Suricata import: {} assets ({} new), {} connections, {} alerts, {}ms",
        import_result.asset_count, import_result.new_assets,
        import_result.connection_count, import_result.alert_count,
        import_result.duration_ms
    );

    Ok(import_result)
}

/// Import an Nmap XML file (-oX output).
///
/// **WARNING:** This imports results from an ACTIVE SCAN performed externally.
/// Kusanagi Kajiki NEVER performs active scans itself.
#[tauri::command]
pub async fn import_nmap_xml(
    path: String,
    state: State<'_, AppState>,
) -> Result<IngestImportResult, String> {
    let start = Instant::now();

    let ingest_result = gm_ingest::nmap::parse_nmap_xml(Path::new(&path))
        .map_err(|e| e.to_string())?;

    let import_result = merge_ingest_result(ingest_result, &state, start)?;

    log::info!(
        "Nmap import: {} assets ({} new), {}ms [ACTIVE SCAN DATA]",
        import_result.asset_count, import_result.new_assets,
        import_result.duration_ms
    );

    Ok(import_result)
}

/// Import a Masscan JSON file (-oJ output).
///
/// **WARNING:** This imports results from an ACTIVE SCAN performed externally.
/// Kusanagi Kajiki NEVER performs active scans itself.
#[tauri::command]
pub async fn import_masscan_json(
    path: String,
    state: State<'_, AppState>,
) -> Result<IngestImportResult, String> {
    let start = Instant::now();

    let ingest_result = gm_ingest::masscan::parse_masscan_json(Path::new(&path))
        .map_err(|e| e.to_string())?;

    let import_result = merge_ingest_result(ingest_result, &state, start)?;

    log::info!(
        "Masscan import: {} assets ({} new), {}ms [ACTIVE SCAN DATA]",
        import_result.asset_count, import_result.new_assets,
        import_result.duration_ms
    );

    Ok(import_result)
}

/// Merge ingested data into application state.
///
/// Assets are merged by IP address — if an asset already exists from PCAP data,
/// the ingested data enriches it (hostname, OS, open ports) without overwriting.
/// New assets are created for IPs not yet seen.
/// Connections are appended with the ingest source tagged.
fn merge_ingest_result(
    ingest: IngestResult,
    state: &AppState,
    start: Instant,
) -> Result<IngestImportResult, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

    let source_name = ingest.source
        .map(|s| s.display_name().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let is_active = ingest.source.map(|s| s.is_active_scan()).unwrap_or(false);
    let ingest_source = ingest.source;

    let total_assets = ingest.assets.len();
    let total_connections = ingest.connections.len();
    let total_alerts = ingest.alerts.len();

    // Merge assets
    let mut new_count = 0;
    let mut updated_count = 0;

    for ingested_asset in &ingest.assets {
        if let Some(existing) = inner.assets.iter_mut().find(|a| a.ip_address == ingested_asset.ip_address) {
            // Enrich existing asset
            enrich_asset(existing, ingested_asset, is_active);
            updated_count += 1;
        } else {
            // Create new asset
            let asset = create_asset_from_ingested(ingested_asset, is_active);
            inner.assets.push(asset);
            new_count += 1;
        }
    }

    // Merge connections — tag with ingest source in origin_files
    for ingested_conn in &ingest.connections {
        let origin = format!("[{}]", source_name);

        // Check if this connection already exists
        if let Some(existing) = inner.connections.iter_mut().find(|c| {
            c.src_ip == ingested_conn.src_ip
                && c.dst_ip == ingested_conn.dst_ip
                && c.src_port == ingested_conn.src_port
                && c.dst_port == ingested_conn.dst_port
        }) {
            // Update counts
            existing.packet_count += ingested_conn.packet_count;
            existing.byte_count += ingested_conn.byte_count;
            if !existing.origin_files.contains(&origin) {
                existing.origin_files.push(origin);
            }
        } else {
            // New connection
            let conn = ConnectionInfo {
                id: uuid::Uuid::new_v4().to_string(),
                src_ip: ingested_conn.src_ip.clone(),
                src_port: ingested_conn.src_port,
                src_mac: None,
                dst_ip: ingested_conn.dst_ip.clone(),
                dst_port: ingested_conn.dst_port,
                dst_mac: None,
                protocol: ingested_conn.protocol.clone(),
                transport: ingested_conn.transport.clone(),
                packet_count: ingested_conn.packet_count,
                byte_count: ingested_conn.byte_count,
                first_seen: ingested_conn.first_seen
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
                last_seen: ingested_conn.last_seen
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
                origin_files: vec![origin],
            };
            inner.connections.push(conn);
        }
    }

    // Store ingest source for tracking
    if let Some(source) = ingest_source {
        let source_tag = format!("[{}]", source.display_name());
        if !inner.imported_files.contains(&source_tag) {
            inner.imported_files.push(source_tag);
        }
    }

    // Rebuild topology from updated connections
    // The topology builder needs to be re-run with new data
    let mut topo = gm_topology::TopologyBuilder::new();
    for conn in &inner.connections {
        let protocol = IcsProtocol::from_name(&conn.protocol);
        topo.add_connection(
            &conn.src_ip,
            &conn.dst_ip,
            None, // MAC not always available from ingest
            None,
            protocol,
            conn.byte_count,
        );
    }
    inner.topology = topo.snapshot();

    // Enrich topology nodes with asset data
    // Collect asset lookup first to avoid borrow conflict
    let asset_lookup: std::collections::HashMap<String, (Option<String>, String, u8)> = inner.assets.iter()
        .map(|a| (a.ip_address.clone(), (a.vendor.clone(), a.device_type.clone(), a.confidence)))
        .collect();

    for node in &mut inner.topology.nodes {
        if let Some((vendor, device_type, confidence)) = asset_lookup.get(&node.ip_address) {
            if let Some(ref v) = vendor {
                node.vendor = Some(v.clone());
            }
            if *confidence >= 3 {
                node.device_type = device_type.clone();
            }
        }
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(IngestImportResult {
        source: source_name,
        files_processed: ingest.files_processed,
        asset_count: total_assets,
        connection_count: total_connections,
        alert_count: total_alerts,
        new_assets: new_count,
        updated_assets: updated_count,
        duration_ms,
        errors: ingest.errors,
    })
}

/// Enrich an existing asset with data from an ingested asset.
fn enrich_asset(existing: &mut AssetInfo, ingested: &IngestedAsset, is_active: bool) {
    // Add new protocols
    for proto in &ingested.protocols {
        if !existing.protocols.contains(proto) {
            existing.protocols.push(proto.clone());
        }
    }

    // Hostname — prefer existing, fill if missing
    if existing.hostname.is_none() && ingested.hostname.is_some() {
        existing.hostname = ingested.hostname.clone();
    }

    // Vendor — prefer existing (from signatures/OUI), fill if missing
    if existing.vendor.is_none() && ingested.vendor.is_some() {
        existing.vendor = ingested.vendor.clone();
    }

    // OS info goes in notes if available and not already noted
    if let Some(ref os) = ingested.os_info {
        let os_note = format!("[{}] OS: {}", if is_active { "scan" } else { "passive" }, os);
        if !existing.notes.contains(&os_note) {
            if !existing.notes.is_empty() {
                existing.notes.push_str("; ");
            }
            existing.notes.push_str(&os_note);
        }
    }

    // Tag with source type
    let source_tag = format!("[{}]", ingested.source.display_name());
    if !existing.tags.contains(&source_tag) {
        existing.tags.push(source_tag);
    }

    // Active scan tag
    if is_active && !existing.tags.contains(&"[active-scan]".to_string()) {
        existing.tags.push("[active-scan]".to_string());
    }
}

/// Create a new AssetInfo from ingested data.
fn create_asset_from_ingested(ingested: &IngestedAsset, is_active: bool) -> AssetInfo {
    let mut tags = vec![format!("[{}]", ingested.source.display_name())];
    if is_active {
        tags.push("[active-scan]".to_string());
    }

    let mut notes = String::new();
    if let Some(ref os) = ingested.os_info {
        notes = format!("[{}] OS: {}", if is_active { "scan" } else { "passive" }, os);
    }

    // Infer device type from protocols
    let protocols_as_ics: Vec<IcsProtocol> = ingested.protocols.iter()
        .map(|p| IcsProtocol::from_name(p))
        .collect();
    let has_server_ports = ingested.open_ports.iter().any(|p| {
        matches!(p.port, 102 | 502 | 1089..=1091 | 1883 | 2222 | 2404 | 4840
            | 5007 | 5094 | 8883 | 18245 | 18246 | 20000 | 34962..=34964 | 44818 | 47808)
    });
    let device_type = super::infer_device_type(&protocols_as_ics, has_server_ports);

    AssetInfo {
        id: ingested.ip_address.clone(),
        ip_address: ingested.ip_address.clone(),
        mac_address: ingested.mac_address.clone(),
        hostname: ingested.hostname.clone(),
        device_type,
        vendor: ingested.vendor.clone(),
        protocols: ingested.protocols.clone(),
        first_seen: String::new(),
        last_seen: String::new(),
        notes,
        purdue_level: None,
        tags,
        packet_count: 0,
        confidence: if ingested.vendor.is_some() { 2 } else { 1 },
        product_family: None,
        signature_matches: Vec::new(),
        oui_vendor: None,
        country: None,
        is_public_ip: gm_db::GeoIpLookup::is_public_ip(&ingested.ip_address),
    }
}
