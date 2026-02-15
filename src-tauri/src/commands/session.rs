//! Session management commands: save, load, list, delete sessions,
//! update and bulk update assets, export/import ZIP archives.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use tauri::State;

use gm_db::{AssetRow, ConnectionRow};
use gm_topology::TopologyBuilder;

use super::{
    AppState, AssetInfo, ConnectionInfo, DeepParseInfo,
};

// ─── Types ──────────────────────────────────────────────────

/// Session info returned to the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub updated_at: String,
    pub asset_count: i64,
    pub connection_count: i64,
}

/// Partial updates for an asset (from the frontend edit form).
#[derive(Debug, Clone, Deserialize)]
pub struct AssetUpdate {
    pub device_type: Option<String>,
    pub hostname: Option<String>,
    pub notes: Option<String>,
    pub purdue_level: Option<u8>,
    pub tags: Option<Vec<String>>,
}

/// Session metadata stored as JSON in the database.
#[derive(Debug, Serialize, Deserialize)]
struct SessionMetadata {
    deep_parse_info: HashMap<String, DeepParseInfo>,
    imported_files: Vec<String>,
}

// ─── Session Commands ───────────────────────────────────────

/// Save the current state as a named session.
#[tauri::command]
pub async fn save_session(
    name: String,
    description: Option<String>,
    state: State<'_, AppState>,
) -> Result<SessionInfo, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;

    let db = inner.db.as_ref().ok_or("Database not available")?;
    let session_id = uuid::Uuid::new_v4().to_string();
    let desc = description.unwrap_or_default();

    // Serialize metadata (deep parse info + imported files)
    let metadata = SessionMetadata {
        deep_parse_info: inner.deep_parse_info.clone(),
        imported_files: inner.imported_files.clone(),
    };
    let metadata_json = serde_json::to_string(&metadata).map_err(|e| e.to_string())?;

    // Create session record
    let session_row = db
        .create_session(&session_id, &name, &desc, &metadata_json)
        .map_err(|e| e.to_string())?;

    // Insert all assets
    for asset in &inner.assets {
        let row = asset_info_to_row(asset, &session_id);
        db.insert_asset(&row).map_err(|e| e.to_string())?;
    }

    // Insert all connections
    for conn in &inner.connections {
        let row = connection_info_to_row(conn, &session_id);
        db.insert_connection(&row).map_err(|e| e.to_string())?;
    }

    // Update counts
    db.update_session_counts(
        &session_id,
        inner.assets.len() as i64,
        inner.connections.len() as i64,
    )
    .map_err(|e| e.to_string())?;

    log::info!("Saved session '{}' ({}) with {} assets, {} connections",
        name, session_id, inner.assets.len(), inner.connections.len());

    Ok(SessionInfo {
        id: session_row.id,
        name: session_row.name,
        description: session_row.description,
        created_at: session_row.created_at,
        updated_at: session_row.updated_at,
        asset_count: inner.assets.len() as i64,
        connection_count: inner.connections.len() as i64,
    })
}

/// Load a session by ID, replacing the current state.
#[tauri::command]
pub async fn load_session(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<SessionInfo, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

    let db = inner.db.as_ref().ok_or("Database not available")?;

    // Load session record
    let session_row = db.get_session(&session_id).map_err(|e| e.to_string())?;

    // Parse metadata
    let metadata: SessionMetadata = serde_json::from_str(&session_row.metadata)
        .unwrap_or(SessionMetadata {
            deep_parse_info: HashMap::new(),
            imported_files: Vec::new(),
        });

    // Load assets from DB
    let asset_rows = db.list_assets(&session_id).map_err(|e| e.to_string())?;
    let assets: Vec<AssetInfo> = asset_rows.into_iter().map(row_to_asset_info).collect();

    // Load connections from DB
    let conn_rows = db.list_connections(&session_id).map_err(|e| e.to_string())?;
    let connections: Vec<ConnectionInfo> = conn_rows.into_iter().map(row_to_connection_info).collect();

    // Rebuild topology from loaded connections
    let mut topo_builder = TopologyBuilder::new();
    for conn in &connections {
        let protocol = gm_parsers::IcsProtocol::from_name(&conn.protocol);
        topo_builder.add_connection(
            &conn.src_ip,
            &conn.dst_ip,
            conn.src_mac.as_deref(),
            conn.dst_mac.as_deref(),
            protocol,
            conn.byte_count,
        );
    }
    let topology = topo_builder.snapshot();

    // Replace state (preserve signature_engine, oui_lookup, geoip_lookup, db)
    inner.topology = topology;
    inner.assets = assets;
    inner.connections = connections;
    inner.packet_summaries = HashMap::new(); // Not persisted (too large)
    inner.imported_files = metadata.imported_files;
    inner.deep_parse_info = metadata.deep_parse_info;
    inner.current_session_id = Some(session_id.clone());
    inner.current_session_name = Some(session_row.name.clone());

    log::info!("Loaded session '{}' ({})", session_row.name, session_id);

    Ok(SessionInfo {
        id: session_row.id,
        name: session_row.name,
        description: session_row.description,
        created_at: session_row.created_at,
        updated_at: session_row.updated_at,
        asset_count: session_row.asset_count,
        connection_count: session_row.connection_count,
    })
}

/// List all saved sessions.
#[tauri::command]
pub async fn list_sessions(
    state: State<'_, AppState>,
) -> Result<Vec<SessionInfo>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;

    let rows = db.list_sessions().map_err(|e| e.to_string())?;
    Ok(rows
        .into_iter()
        .map(|r| SessionInfo {
            id: r.id,
            name: r.name,
            description: r.description,
            created_at: r.created_at,
            updated_at: r.updated_at,
            asset_count: r.asset_count,
            connection_count: r.connection_count,
        })
        .collect())
}

/// Delete a session by ID.
#[tauri::command]
pub async fn delete_session(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;
    db.delete_session(&session_id).map_err(|e| e.to_string())?;
    log::info!("Deleted session {}", session_id);
    Ok(())
}

// ─── Asset Update Commands ──────────────────────────────────

/// Update a single asset's editable fields.
#[tauri::command]
pub async fn update_asset(
    asset_id: String,
    updates: AssetUpdate,
    state: State<'_, AppState>,
) -> Result<AssetInfo, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

    // Find and update the asset in memory
    let asset = inner
        .assets
        .iter_mut()
        .find(|a| a.id == asset_id)
        .ok_or_else(|| format!("Asset {} not found", asset_id))?;

    if let Some(ref dt) = updates.device_type {
        asset.device_type = dt.clone();
    }
    if let Some(ref hostname) = updates.hostname {
        asset.hostname = if hostname.is_empty() { None } else { Some(hostname.clone()) };
    }
    if let Some(ref notes) = updates.notes {
        asset.notes = notes.clone();
    }
    if let Some(level) = updates.purdue_level {
        asset.purdue_level = if level > 5 { None } else { Some(level) };
    }
    if let Some(ref tags) = updates.tags {
        asset.tags = tags.clone();
    }

    let updated = asset.clone();

    // Persist to DB if a session is loaded
    if let (Some(ref db), Some(ref _session_id)) = (&inner.db, &inner.current_session_id) {
        if let Some(ref dt) = updates.device_type {
            let _ = db.update_asset_field(&asset_id, "device_type", dt);
        }
        if let Some(ref hostname) = updates.hostname {
            let _ = db.update_asset_field(&asset_id, "hostname", hostname);
        }
        if let Some(ref notes) = updates.notes {
            let _ = db.update_asset_field(&asset_id, "notes", notes);
        }
        if let Some(level) = updates.purdue_level {
            let _ = db.update_asset_field(&asset_id, "purdue_level", &level.to_string());
        }
        if let Some(ref tags) = updates.tags {
            let tags_json = serde_json::to_string(tags).unwrap_or_else(|_| "[]".to_string());
            let _ = db.update_asset_field(&asset_id, "tags", &tags_json);
        }
    }

    Ok(updated)
}

/// Bulk update assets (same field on multiple assets).
#[tauri::command]
pub async fn bulk_update_assets(
    asset_ids: Vec<String>,
    updates: AssetUpdate,
    state: State<'_, AppState>,
) -> Result<usize, String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

    let mut count = 0;
    for asset in &mut inner.assets {
        if asset_ids.contains(&asset.id) {
            if let Some(ref dt) = updates.device_type {
                asset.device_type = dt.clone();
            }
            if let Some(ref hostname) = updates.hostname {
                asset.hostname = if hostname.is_empty() { None } else { Some(hostname.clone()) };
            }
            if let Some(ref notes) = updates.notes {
                asset.notes = notes.clone();
            }
            if let Some(level) = updates.purdue_level {
                asset.purdue_level = if level > 5 { None } else { Some(level) };
            }
            if let Some(ref tags) = updates.tags {
                asset.tags = tags.clone();
            }
            count += 1;
        }
    }

    // Persist to DB if session is loaded
    if let (Some(ref db), Some(ref _session_id)) = (&inner.db, &inner.current_session_id) {
        if let Some(ref dt) = updates.device_type {
            let _ = db.bulk_update_asset_field(&asset_ids, "device_type", dt);
        }
        if let Some(ref notes) = updates.notes {
            let _ = db.bulk_update_asset_field(&asset_ids, "notes", notes);
        }
    }

    Ok(count)
}

// ─── Session Archive (ZIP) ──────────────────────────────────

/// Export a session to a .kkj ZIP archive.
#[tauri::command]
pub async fn export_session_archive(
    session_id: String,
    output_path: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;

    // Load session data from DB
    let session = db.get_session(&session_id).map_err(|e| e.to_string())?;
    let assets = db.list_assets(&session_id).map_err(|e| e.to_string())?;
    let connections = db.list_connections(&session_id).map_err(|e| e.to_string())?;

    // Build the session data JSON
    let session_data = serde_json::json!({
        "session": {
            "id": session.id,
            "name": session.name,
            "description": session.description,
            "created_at": session.created_at,
            "updated_at": session.updated_at,
        },
        "metadata": session.metadata,
        "assets": assets,
        "connections": connections,
    });

    let manifest = serde_json::json!({
        "version": "1.0",
        "app_version": env!("CARGO_PKG_VERSION"),
        "created_at": chrono::Utc::now().to_rfc3339(),
        "asset_count": assets.len(),
        "connection_count": connections.len(),
    });

    // Create ZIP file
    let file = std::fs::File::create(&output_path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // Write manifest.json
    zip.start_file("manifest.json", options).map_err(|e| e.to_string())?;
    std::io::Write::write_all(
        &mut zip,
        serde_json::to_string_pretty(&manifest).map_err(|e| e.to_string())?.as_bytes(),
    ).map_err(|e| e.to_string())?;

    // Write session.json
    zip.start_file("session.json", options).map_err(|e| e.to_string())?;
    std::io::Write::write_all(
        &mut zip,
        serde_json::to_string_pretty(&session_data).map_err(|e| e.to_string())?.as_bytes(),
    ).map_err(|e| e.to_string())?;

    zip.finish().map_err(|e| e.to_string())?;

    log::info!("Exported session archive to {}", output_path);
    Ok(output_path)
}

/// Import a session from a .kkj ZIP archive.
#[tauri::command]
pub async fn import_session_archive(
    archive_path: String,
    state: State<'_, AppState>,
) -> Result<SessionInfo, String> {
    // Read the ZIP file
    let file = std::fs::File::open(&archive_path).map_err(|e| e.to_string())?;
    let mut archive = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;

    // Read session.json
    let session_json: serde_json::Value = {
        let entry = archive.by_name("session.json").map_err(|e| e.to_string())?;
        serde_json::from_reader(entry).map_err(|e| e.to_string())?
    };

    // Parse session data
    let session_name = session_json["session"]["name"]
        .as_str()
        .unwrap_or("Imported Session")
        .to_string();
    let session_desc = session_json["session"]["description"]
        .as_str()
        .unwrap_or("")
        .to_string();
    let metadata_str = session_json.get("metadata")
        .map(|m| m.to_string())
        .unwrap_or_else(|| "{}".to_string());

    let assets: Vec<AssetRow> = serde_json::from_value(
        session_json["assets"].clone()
    ).unwrap_or_default();

    let connections: Vec<ConnectionRow> = serde_json::from_value(
        session_json["connections"].clone()
    ).unwrap_or_default();

    // Save to database with a new session ID
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    let db = inner.db.as_ref().ok_or("Database not available")?;

    let new_session_id = uuid::Uuid::new_v4().to_string();
    db.create_session(&new_session_id, &session_name, &session_desc, &metadata_str)
        .map_err(|e| e.to_string())?;

    for mut asset in assets {
        asset.session_id = new_session_id.clone();
        db.insert_asset(&asset).map_err(|e| e.to_string())?;
    }

    for mut conn in connections {
        conn.session_id = new_session_id.clone();
        db.insert_connection(&conn).map_err(|e| e.to_string())?;
    }

    let session = db.get_session(&new_session_id).map_err(|e| e.to_string())?;
    let asset_count = db.list_assets(&new_session_id).map_err(|e| e.to_string())?.len() as i64;
    let conn_count = db.list_connections(&new_session_id).map_err(|e| e.to_string())?.len() as i64;

    db.update_session_counts(&new_session_id, asset_count, conn_count)
        .map_err(|e| e.to_string())?;

    // Also load the imported session into current state
    let metadata: SessionMetadata = serde_json::from_str(&metadata_str)
        .unwrap_or(SessionMetadata {
            deep_parse_info: HashMap::new(),
            imported_files: Vec::new(),
        });

    let loaded_assets = db.list_assets(&new_session_id).map_err(|e| e.to_string())?;
    let loaded_conns = db.list_connections(&new_session_id).map_err(|e| e.to_string())?;

    let assets_vec: Vec<AssetInfo> = loaded_assets.into_iter().map(row_to_asset_info).collect();
    let conns_vec: Vec<ConnectionInfo> = loaded_conns.into_iter().map(row_to_connection_info).collect();

    // Rebuild topology
    let mut topo_builder = TopologyBuilder::new();
    for conn in &conns_vec {
        let protocol = gm_parsers::IcsProtocol::from_name(&conn.protocol);
        topo_builder.add_connection(
            &conn.src_ip,
            &conn.dst_ip,
            conn.src_mac.as_deref(),
            conn.dst_mac.as_deref(),
            protocol,
            conn.byte_count,
        );
    }

    inner.topology = topo_builder.snapshot();
    inner.assets = assets_vec;
    inner.connections = conns_vec;
    inner.packet_summaries = HashMap::new();
    inner.imported_files = metadata.imported_files;
    inner.deep_parse_info = metadata.deep_parse_info;
    inner.current_session_id = Some(new_session_id);
    inner.current_session_name = Some(session_name.clone());

    log::info!("Imported session archive '{}' from {}", session_name, archive_path);

    Ok(SessionInfo {
        id: session.id,
        name: session.name,
        description: session.description,
        created_at: session.created_at,
        updated_at: session.updated_at,
        asset_count,
        connection_count: conn_count,
    })
}

// ─── Conversion Helpers ─────────────────────────────────────

fn asset_info_to_row(asset: &AssetInfo, session_id: &str) -> AssetRow {
    AssetRow {
        id: asset.id.clone(),
        session_id: session_id.to_string(),
        ip_address: asset.ip_address.clone(),
        mac_address: asset.mac_address.clone(),
        hostname: asset.hostname.clone(),
        device_type: asset.device_type.clone(),
        vendor: asset.vendor.clone(),
        product_family: asset.product_family.clone(),
        protocols: serde_json::to_string(&asset.protocols).unwrap_or_else(|_| "[]".to_string()),
        confidence: asset.confidence as i64,
        purdue_level: asset.purdue_level.map(|l| l as i64),
        tags: serde_json::to_string(&asset.tags).unwrap_or_else(|_| "[]".to_string()),
        notes: asset.notes.clone(),
        packet_count: asset.packet_count as i64,
        signature_matches: serde_json::to_string(&asset.signature_matches)
            .unwrap_or_else(|_| "[]".to_string()),
        oui_vendor: asset.oui_vendor.clone(),
        country: asset.country.clone(),
        is_public_ip: asset.is_public_ip,
        first_seen: asset.first_seen.clone(),
        last_seen: asset.last_seen.clone(),
    }
}

fn connection_info_to_row(conn: &ConnectionInfo, session_id: &str) -> ConnectionRow {
    ConnectionRow {
        id: conn.id.clone(),
        session_id: session_id.to_string(),
        src_ip: conn.src_ip.clone(),
        src_port: conn.src_port as i64,
        src_mac: conn.src_mac.clone(),
        dst_ip: conn.dst_ip.clone(),
        dst_port: conn.dst_port as i64,
        dst_mac: conn.dst_mac.clone(),
        protocol: conn.protocol.clone(),
        transport: conn.transport.clone(),
        packet_count: conn.packet_count as i64,
        byte_count: conn.byte_count as i64,
        first_seen: conn.first_seen.clone(),
        last_seen: conn.last_seen.clone(),
        origin_files: serde_json::to_string(&conn.origin_files)
            .unwrap_or_else(|_| "[]".to_string()),
    }
}

fn row_to_asset_info(row: AssetRow) -> AssetInfo {
    let protocols: Vec<String> = serde_json::from_str(&row.protocols).unwrap_or_default();
    let tags: Vec<String> = serde_json::from_str(&row.tags).unwrap_or_default();
    let signature_matches = serde_json::from_str(&row.signature_matches).unwrap_or_default();

    AssetInfo {
        id: row.id,
        ip_address: row.ip_address,
        mac_address: row.mac_address,
        hostname: row.hostname,
        device_type: row.device_type,
        vendor: row.vendor,
        protocols,
        first_seen: row.first_seen,
        last_seen: row.last_seen,
        notes: row.notes,
        purdue_level: row.purdue_level.map(|l| l as u8),
        tags,
        packet_count: row.packet_count as u64,
        confidence: row.confidence as u8,
        product_family: row.product_family,
        signature_matches,
        oui_vendor: row.oui_vendor,
        country: row.country,
        is_public_ip: row.is_public_ip,
    }
}

fn row_to_connection_info(row: ConnectionRow) -> ConnectionInfo {
    let origin_files: Vec<String> = serde_json::from_str(&row.origin_files).unwrap_or_default();

    ConnectionInfo {
        id: row.id,
        src_ip: row.src_ip,
        src_port: row.src_port as u16,
        src_mac: row.src_mac,
        dst_ip: row.dst_ip,
        dst_port: row.dst_port as u16,
        dst_mac: row.dst_mac,
        protocol: row.protocol,
        transport: row.transport,
        packet_count: row.packet_count as u64,
        byte_count: row.byte_count as u64,
        first_seen: row.first_seen,
        last_seen: row.last_seen,
        origin_files,
    }
}
