//! Tauri commands for importing external tool data.
//!
//! Imports Zeek logs, Suricata eve.json, Nmap XML, and Masscan JSON.
//! Ingested data is merged into the existing pipeline alongside PCAP data.

use std::path::Path;
use std::time::Instant;
use serde::Serialize;
use tauri::State;

use std::collections::HashMap;

use gm_ingest::{IngestResult, IngestedAlert, IngestedAsset, IngestSource};
use gm_parsers::IcsProtocol;

use super::{AppState, AppStateInner, AssetInfo, ConnectionInfo, DeviceZeekEvents, StoredAlert, ZeekEventSummary};

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

/// Import a Wazuh HIDS/SIEM alert export file.
///
/// Accepts both line-delimited JSON and JSON array formats.
/// Alerts are stored for correlation with the device inventory.
#[tauri::command]
pub async fn import_wazuh_alerts(
    path: String,
    state: State<'_, AppState>,
) -> Result<IngestImportResult, String> {
    let start = Instant::now();

    let ingest_result = gm_ingest::wazuh::parse_wazuh_alerts(Path::new(&path))
        .map_err(|e| e.to_string())?;

    let import_result = merge_ingest_result(ingest_result, &state, start)?;

    log::info!(
        "Wazuh import: {} alerts, {}ms",
        import_result.alert_count, import_result.duration_ms
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

    // Store alerts for correlation
    for alert in &ingest.alerts {
        inner.imported_alerts.push(ingested_alert_to_stored(alert));
    }

    // Rebuild per-device Zeek event summaries after any Zeek import
    if ingest_source == Some(IngestSource::Zeek) {
        rebuild_zeek_device_events(&mut inner);
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

/// Convert an IngestedAlert to the StoredAlert type used in AppState.
fn ingested_alert_to_stored(alert: &IngestedAlert) -> StoredAlert {
    StoredAlert {
        timestamp: alert.timestamp.to_rfc3339(),
        src_ip: alert.src_ip.clone(),
        src_port: alert.src_port,
        dst_ip: alert.dst_ip.clone(),
        dst_port: alert.dst_port,
        signature_id: alert.signature_id,
        signature: alert.signature.clone(),
        category: alert.category.clone(),
        severity: alert.severity,
        source: alert.source.display_name().to_string(),
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

    // Prefer explicit device type from ingest source; fall back to protocol inference
    let protocols_as_ics: Vec<IcsProtocol> = ingested.protocols.iter()
        .map(|p| IcsProtocol::from_name(p))
        .collect();
    let has_server_ports = ingested.open_ports.iter().any(|p| {
        matches!(p.port, 102 | 502 | 1089..=1091 | 1883 | 2222 | 2404 | 4840
            | 5007 | 5094 | 8883 | 18245 | 18246 | 20000 | 34962..=34964 | 44818 | 47808)
    });
    let device_type = ingested.device_type.clone()
        .unwrap_or_else(|| super::infer_device_type(&protocols_as_ics, has_server_ports));

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

/// Rebuild per-device Zeek event summaries from all connections tagged with [Zeek].
///
/// Called after each Zeek import. Replaces the previous zeek_device_events map.
fn rebuild_zeek_device_events(inner: &mut AppStateInner) {
    // Accumulate counts and sample events per device IP
    let mut map: HashMap<String, (DeviceZeekEvents, std::collections::HashSet<String>)> =
        HashMap::new();

    for conn in &inner.connections {
        if !conn.origin_files.iter().any(|f| f.contains("Zeek")) {
            continue;
        }

        let log_type = classify_zeek_log_type(&conn.protocol, conn.dst_port);
        let timestamp = conn.first_seen.clone();

        // Add event entry for src device (peer = dst)
        for (device_ip, peer_ip) in [
            (conn.src_ip.clone(), conn.dst_ip.clone()),
            (conn.dst_ip.clone(), conn.src_ip.clone()),
        ] {
            let (events, peers) = map.entry(device_ip.clone()).or_insert_with(|| {
                (
                    DeviceZeekEvents {
                        device_ip: device_ip.clone(),
                        ..Default::default()
                    },
                    std::collections::HashSet::new(),
                )
            });

            // Increment the appropriate counter
            match log_type.as_str() {
                "modbus" => events.modbus_events += 1,
                "dnp3" => events.dnp3_events += 1,
                "dns" => events.dns_queries += 1,
                "http" => events.http_requests += 1,
                _ => events.conn_log_entries += 1,
            }

            peers.insert(peer_ip.clone());

            // Add sample event (capped at 50)
            if events.sample_events.len() < 50 {
                events.sample_events.push(ZeekEventSummary {
                    timestamp: timestamp.clone(),
                    log_type: log_type.clone(),
                    peer_ip: peer_ip.clone(),
                    summary: format!(
                        "{} {}:{} → {}:{} ({} pkts)",
                        conn.transport.to_uppercase(),
                        conn.src_ip, conn.src_port,
                        conn.dst_ip, conn.dst_port,
                        conn.packet_count
                    ),
                });
            }
        }
    }

    // Finalize unique_peers counts and correlate alerts
    let alert_map: HashMap<String, u32> = {
        let mut m: HashMap<String, u32> = HashMap::new();
        for alert in &inner.imported_alerts {
            *m.entry(alert.src_ip.clone()).or_insert(0) += 1;
            *m.entry(alert.dst_ip.clone()).or_insert(0) += 1;
        }
        m
    };

    inner.zeek_device_events = map
        .into_iter()
        .map(|(ip, (mut events, peers))| {
            events.unique_peers = peers.len() as u32;
            events.alert_count = alert_map.get(&ip).copied().unwrap_or(0);
            (ip, events)
        })
        .collect();
}

/// Map a connection protocol string to a Zeek log type label.
fn classify_zeek_log_type(protocol: &str, dst_port: u16) -> String {
    match protocol.to_lowercase().as_str() {
        "modbus" => "modbus".to_string(),
        "dnp3" => "dnp3".to_string(),
        "s7comm" => "s7comm".to_string(),
        _ => match dst_port {
            53 => "dns".to_string(),
            80 | 443 | 8080 | 8443 => "http".to_string(),
            _ => "conn".to_string(),
        },
    }
}

/// Get Zeek-observed event statistics for a specific device IP.
#[tauri::command]
pub async fn get_device_zeek_events(
    device_ip: String,
    state: State<'_, AppState>,
) -> Result<DeviceZeekEvents, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(inner
        .zeek_device_events
        .get(&device_ip)
        .cloned()
        .unwrap_or_else(|| DeviceZeekEvents {
            device_ip: device_ip.clone(),
            ..Default::default()
        }))
}

/// Import a SINEMA Server CSV device inventory export.
///
/// SINEMA Server exports device lists with IP, MAC, model, firmware, and location.
/// Data is merged with existing passively-discovered assets.
#[tauri::command]
pub async fn import_sinema_csv(
    path: String,
    state: State<'_, AppState>,
) -> Result<IngestImportResult, String> {
    let start = Instant::now();

    let ingest_result = gm_ingest::sinema::import_sinema_csv(Path::new(&path))
        .map_err(|e| e.to_string())?;

    let import_result = merge_ingest_result(ingest_result, &state, start)?;

    log::info!(
        "SINEMA CSV import: {} assets ({} new), {}ms",
        import_result.asset_count,
        import_result.new_assets,
        import_result.duration_ms
    );

    Ok(import_result)
}

/// Import a TIA Portal network configuration XML export.
///
/// Extracts device names, IP addresses, hardware models, and firmware versions
/// from TIA Portal V15+ XML exports.
#[tauri::command]
pub async fn import_tia_xml(
    path: String,
    state: State<'_, AppState>,
) -> Result<IngestImportResult, String> {
    let start = Instant::now();

    let ingest_result = gm_ingest::sinema::import_tia_xml(Path::new(&path))
        .map_err(|e| e.to_string())?;

    let import_result = merge_ingest_result(ingest_result, &state, start)?;

    log::info!(
        "TIA Portal XML import: {} assets ({} new), {}ms",
        import_result.asset_count,
        import_result.new_assets,
        import_result.duration_ms
    );

    Ok(import_result)
}
