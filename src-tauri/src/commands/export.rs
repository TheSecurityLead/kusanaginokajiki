//! Export & reporting commands: CSV, JSON, PDF, SBOM, STIX.
//!
//! These commands serialize the current AppState data into various
//! export formats using the gm-report crate.

use std::collections::{HashMap, HashSet};
use serde::Deserialize;
use tauri::State;

use gm_report::{
    ExportAsset, ExportConnection, ExportProtocolStat, ExportFinding,
    ReportConfig, ReportData,
};

use super::AppState;

// ─── Conversion Helpers ──────────────────────────────────────

/// Convert the in-memory AppState assets to ExportAsset format.
fn state_assets_to_export(state: &super::AppStateInner) -> Vec<ExportAsset> {
    state.assets.iter().map(|a| ExportAsset {
        ip_address: a.ip_address.clone(),
        mac_address: a.mac_address.clone(),
        hostname: a.hostname.clone(),
        device_type: a.device_type.clone(),
        vendor: a.vendor.clone(),
        product_family: a.product_family.clone(),
        protocols: a.protocols.clone(),
        confidence: a.confidence,
        purdue_level: a.purdue_level,
        oui_vendor: a.oui_vendor.clone(),
        country: a.country.clone(),
        is_public_ip: a.is_public_ip,
        first_seen: a.first_seen.clone(),
        last_seen: a.last_seen.clone(),
        notes: a.notes.clone(),
        tags: a.tags.clone(),
        packet_count: a.packet_count,
    }).collect()
}

/// Convert the in-memory connections to ExportConnection format.
fn state_connections_to_export(state: &super::AppStateInner) -> Vec<ExportConnection> {
    state.connections.iter().map(|c| ExportConnection {
        src_ip: c.src_ip.clone(),
        src_port: c.src_port,
        dst_ip: c.dst_ip.clone(),
        dst_port: c.dst_port,
        protocol: c.protocol.clone(),
        transport: c.transport.clone(),
        packet_count: c.packet_count,
        byte_count: c.byte_count,
        first_seen: c.first_seen.clone(),
        last_seen: c.last_seen.clone(),
    }).collect()
}

/// Compute protocol stats from connections.
fn compute_protocol_stats(state: &super::AppStateInner) -> Vec<ExportProtocolStat> {
    let mut stats: HashMap<String, ExportProtocolStat> = HashMap::new();

    for conn in &state.connections {
        let entry = stats.entry(conn.protocol.clone()).or_insert_with(|| {
            ExportProtocolStat {
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
        for conn in &state.connections {
            if &conn.protocol == proto {
                devices.insert(conn.src_ip.clone());
                devices.insert(conn.dst_ip.clone());
            }
        }
        stat.unique_devices = devices.len() as u64;
    }

    let mut result: Vec<ExportProtocolStat> = stats.into_values().collect();
    result.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    result
}

/// Build a complete ReportData from current state.
fn build_report_data(state: &super::AppStateInner) -> ReportData {
    ReportData {
        assets: state_assets_to_export(state),
        connections: state_connections_to_export(state),
        protocol_stats: compute_protocol_stats(state),
        findings: Vec::new(), // Findings will come from Phase 10
        session_name: state.current_session_name.clone(),
    }
}

// ─── CSV Export Commands ─────────────────────────────────────

/// Export all assets as CSV, writing to the specified file path.
#[tauri::command]
pub async fn export_assets_csv(
    output_path: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let assets = state_assets_to_export(&inner);
    let csv = gm_report::csv_export::assets_to_csv(&assets).map_err(|e| e.to_string())?;
    gm_report::csv_export::write_csv_file(&output_path, &csv).map_err(|e| e.to_string())?;
    log::info!("Exported {} assets to CSV: {}", assets.len(), output_path);
    Ok(output_path)
}

/// Export all connections as CSV, writing to the specified file path.
#[tauri::command]
pub async fn export_connections_csv(
    output_path: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let connections = state_connections_to_export(&inner);
    let csv = gm_report::csv_export::connections_to_csv(&connections).map_err(|e| e.to_string())?;
    gm_report::csv_export::write_csv_file(&output_path, &csv).map_err(|e| e.to_string())?;
    log::info!("Exported {} connections to CSV: {}", connections.len(), output_path);
    Ok(output_path)
}

// ─── JSON Export Commands ────────────────────────────────────

/// Export the full topology (assets + connections + stats) as JSON.
#[tauri::command]
pub async fn export_topology_json(
    output_path: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let assets = state_assets_to_export(&inner);
    let connections = state_connections_to_export(&inner);
    let stats = compute_protocol_stats(&inner);
    let session_name = inner.current_session_name.as_deref();

    let json = gm_report::json_export::topology_to_json(&assets, &connections, &stats, session_name)
        .map_err(|e| e.to_string())?;
    gm_report::json_export::write_json_file(&output_path, &json).map_err(|e| e.to_string())?;
    log::info!("Exported topology JSON to: {}", output_path);
    Ok(output_path)
}

/// Export all assets as JSON.
#[tauri::command]
pub async fn export_assets_json(
    output_path: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let assets = state_assets_to_export(&inner);
    let json = gm_report::json_export::assets_to_json(&assets).map_err(|e| e.to_string())?;
    gm_report::json_export::write_json_file(&output_path, &json).map_err(|e| e.to_string())?;
    log::info!("Exported {} assets to JSON: {}", assets.len(), output_path);
    Ok(output_path)
}

// ─── PDF Report Command ─────────────────────────────────────

/// Report configuration from the frontend.
#[derive(Debug, Deserialize)]
pub struct ReportConfigInput {
    pub assessor_name: String,
    pub client_name: String,
    pub assessment_date: Option<String>,
    pub title: Option<String>,
    pub include_executive_summary: bool,
    pub include_asset_inventory: bool,
    pub include_protocol_analysis: bool,
    pub include_findings: bool,
    pub include_recommendations: bool,
}

/// Generate a PDF assessment report.
#[tauri::command]
pub async fn generate_pdf_report(
    config: ReportConfigInput,
    output_path: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let data = build_report_data(&inner);

    let report_config = ReportConfig {
        assessor_name: config.assessor_name,
        client_name: config.client_name,
        assessment_date: config.assessment_date
            .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string()),
        title: config.title,
        include_executive_summary: config.include_executive_summary,
        include_asset_inventory: config.include_asset_inventory,
        include_protocol_analysis: config.include_protocol_analysis,
        include_findings: config.include_findings,
        include_recommendations: config.include_recommendations,
    };

    gm_report::pdf::generate_report(&report_config, &data, &output_path)
        .map_err(|e| e.to_string())?;

    log::info!("Generated PDF report: {}", output_path);
    Ok(output_path)
}

// ─── SBOM Export Command ────────────────────────────────────

/// Export asset inventory as SBOM (CISA BOD 23-01 format).
/// `format` can be "csv" or "json".
#[tauri::command]
pub async fn export_sbom(
    format: String,
    output_path: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let assets = state_assets_to_export(&inner);
    let entries = gm_report::sbom::assets_to_sbom(&assets);

    let content = match format.as_str() {
        "csv" => gm_report::sbom::sbom_to_csv(&entries).map_err(|e| e.to_string())?,
        "json" => gm_report::sbom::sbom_to_json(&entries).map_err(|e| e.to_string())?,
        _ => return Err(format!("Unsupported SBOM format: {}. Use 'csv' or 'json'.", format)),
    };

    std::fs::write(&output_path, content).map_err(|e| e.to_string())?;
    log::info!("Exported SBOM ({}) with {} entries to: {}", format, entries.len(), output_path);
    Ok(output_path)
}

// ─── STIX 2.1 Export Command ─────────────────────────────────

/// Export as STIX 2.1 bundle (JSON).
#[tauri::command]
pub async fn export_stix_bundle(
    output_path: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let assets = state_assets_to_export(&inner);
    let connections = state_connections_to_export(&inner);
    let findings: Vec<ExportFinding> = Vec::new(); // Phase 10 will populate

    let json = gm_report::stix::generate_stix_bundle(&assets, &connections, &findings)
        .map_err(|e| e.to_string())?;
    std::fs::write(&output_path, json).map_err(|e| e.to_string())?;

    log::info!("Exported STIX 2.1 bundle to: {}", output_path);
    Ok(output_path)
}

// ─── Topology Image Export Command ──────────────────────────

/// Save topology image data (PNG base64 or SVG string) to a file.
/// The frontend captures the image from Cytoscape and sends it here.
#[tauri::command]
pub async fn save_topology_image(
    image_data: String,
    output_path: String,
) -> Result<String, String> {
    if let Some(base64_data) = image_data.strip_prefix("data:image/png;base64,") {
        // Decode base64 PNG
        let bytes = base64_decode(base64_data)
            .map_err(|e| format!("Invalid base64 data: {}", e))?;
        std::fs::write(&output_path, bytes).map_err(|e| e.to_string())?;
    } else if image_data.starts_with("<?xml") || image_data.starts_with("<svg") {
        // SVG content
        std::fs::write(&output_path, &image_data).map_err(|e| e.to_string())?;
    } else {
        // Assume raw base64 PNG without data: prefix
        let bytes = base64_decode(&image_data)
            .map_err(|e| format!("Invalid image data: {}", e))?;
        std::fs::write(&output_path, bytes).map_err(|e| e.to_string())?;
    }

    log::info!("Saved topology image to: {}", output_path);
    Ok(output_path)
}

/// Simple base64 decoder (avoids adding a full base64 crate dependency).
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim().replace(['\n', '\r'], "");
    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for ch in input.bytes() {
        let val = if ch == b'=' {
            break;
        } else if let Some(pos) = TABLE.iter().position(|&t| t == ch) {
            pos as u32
        } else {
            continue; // Skip whitespace
        };

        buf = (buf << 6) | val;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}
