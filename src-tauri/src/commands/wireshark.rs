//! Wireshark integration commands.
//!
//! Provides:
//! - Auto-detection of Wireshark binary path
//! - Opening Wireshark with a display filter for a specific connection
//! - Exporting filtered packets to CSV (View Frames)
//!
//! This module uses the Tauri shell plugin to launch Wireshark as a subprocess.
//! It NEVER performs active network operations — only opens captured data.

use std::path::PathBuf;
use serde::Serialize;
use tauri::State;

use super::AppState;

/// Result of detecting Wireshark installation.
#[derive(Serialize)]
pub struct WiresharkInfo {
    pub found: bool,
    pub path: Option<String>,
    pub version: Option<String>,
}

/// A row in the View Frames dialog (packet list for a connection).
#[derive(Serialize, Clone)]
pub struct FrameRow {
    pub number: usize,
    pub timestamp: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub origin_file: String,
}

/// Detect Wireshark installation path.
///
/// Searches well-known locations on Linux, macOS, and Windows.
#[tauri::command]
pub async fn detect_wireshark() -> Result<WiresharkInfo, String> {
    let wireshark_path = find_wireshark_binary();

    if let Some(ref path) = wireshark_path {
        Ok(WiresharkInfo {
            found: true,
            path: Some(path.to_string_lossy().to_string()),
            version: None,
        })
    } else {
        Ok(WiresharkInfo {
            found: false,
            path: None,
            version: None,
        })
    }
}

/// Open Wireshark with a display filter for a specific connection.
///
/// If origin PCAP files are available, opens them in Wireshark
/// with a filter matching the connection's endpoints and ports.
#[tauri::command]
pub async fn open_in_wireshark(
    connection_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let wireshark_path = find_wireshark_binary()
        .ok_or_else(|| "Wireshark not found. Install Wireshark and ensure it's in your PATH.".to_string())?;

    // Get connection info and build display filter
    let (filter, pcap_files) = {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        let conn = inner.connections.iter()
            .find(|c| c.id == connection_id)
            .ok_or_else(|| format!("Connection {} not found", connection_id))?;

        let filter = build_display_filter(conn);
        let pcap_files = conn.origin_files.clone();
        (filter, pcap_files)
    };

    // Build command args
    let mut args: Vec<String> = Vec::new();

    // Add display filter
    args.push("-Y".to_string());
    args.push(filter);

    // Add PCAP file if available (first non-source-tag file)
    for file in &pcap_files {
        if !file.starts_with('[') {
            args.push("-r".to_string());
            args.push(file.clone());
            break;
        }
    }

    // Launch Wireshark
    let status = std::process::Command::new(&wireshark_path)
        .args(&args)
        .spawn()
        .map_err(|e| format!("Failed to launch Wireshark: {}", e))?;

    log::info!("Launched Wireshark (PID: {:?}) with filter for connection {}", status.id(), connection_id);
    Ok(())
}

/// Open Wireshark focused on a specific IP (node).
#[tauri::command]
pub async fn open_wireshark_for_node(
    ip_address: String,
) -> Result<(), String> {
    let wireshark_path = find_wireshark_binary()
        .ok_or_else(|| "Wireshark not found. Install Wireshark and ensure it's in your PATH.".to_string())?;

    let filter = format!("ip.addr == {}", ip_address);

    let args = vec!["-Y".to_string(), filter];

    let status = std::process::Command::new(&wireshark_path)
        .args(&args)
        .spawn()
        .map_err(|e| format!("Failed to launch Wireshark: {}", e))?;

    log::info!("Launched Wireshark (PID: {:?}) for node {}", status.id(), ip_address);
    Ok(())
}

/// Get packet frames for a connection (View Frames dialog data).
#[tauri::command]
pub async fn get_connection_frames(
    connection_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<FrameRow>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;

    let packets = inner.packet_summaries.get(&connection_id)
        .cloned()
        .unwrap_or_default();

    let frames: Vec<FrameRow> = packets.iter().enumerate().map(|(i, pkt)| {
        FrameRow {
            number: i + 1,
            timestamp: pkt.timestamp.clone(),
            src_ip: pkt.src_ip.clone(),
            dst_ip: pkt.dst_ip.clone(),
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
            protocol: pkt.protocol.clone(),
            length: pkt.length,
            origin_file: pkt.origin_file.clone(),
        }
    }).collect();

    Ok(frames)
}

/// Export connection frames as CSV text.
#[tauri::command]
pub async fn export_frames_csv(
    connection_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;

    let packets = inner.packet_summaries.get(&connection_id)
        .cloned()
        .unwrap_or_default();

    let mut csv = String::from("No,Timestamp,Source,SrcPort,Destination,DstPort,Protocol,Length,File\n");

    for (i, pkt) in packets.iter().enumerate() {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            i + 1,
            pkt.timestamp,
            pkt.src_ip,
            pkt.src_port,
            pkt.dst_ip,
            pkt.dst_port,
            pkt.protocol,
            pkt.length,
            pkt.origin_file,
        ));
    }

    Ok(csv)
}

/// Save connection frames CSV to a file on disk.
#[tauri::command]
pub async fn save_frames_csv(
    connection_id: String,
    output_path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let csv = export_frames_csv(connection_id, state).await?;
    std::fs::write(&output_path, csv)
        .map_err(|e| format!("Failed to write CSV: {}", e))?;
    Ok(())
}

// ── Internal helpers ─────────────────────────────────────────

/// Build a Wireshark display filter for a connection.
fn build_display_filter(conn: &super::ConnectionInfo) -> String {
    let mut parts = Vec::new();

    // IP addresses
    parts.push(format!(
        "(ip.addr == {} && ip.addr == {})",
        conn.src_ip, conn.dst_ip
    ));

    // Ports (if non-zero)
    if conn.src_port > 0 && conn.dst_port > 0 {
        let transport = if conn.transport == "udp" { "udp" } else { "tcp" };
        parts.push(format!(
            "({}.port == {} && {}.port == {})",
            transport, conn.src_port, transport, conn.dst_port
        ));
    }

    parts.join(" && ")
}

/// Find the Wireshark binary on the system.
fn find_wireshark_binary() -> Option<PathBuf> {
    // Check PATH first
    if let Ok(output) = std::process::Command::new("which")
        .arg("wireshark")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
    }

    // Well-known locations
    let candidates = [
        // Linux
        "/usr/bin/wireshark",
        "/usr/local/bin/wireshark",
        "/snap/bin/wireshark",
        // macOS
        "/Applications/Wireshark.app/Contents/MacOS/Wireshark",
        "/usr/local/bin/wireshark",
        // Windows
        "C:\\Program Files\\Wireshark\\Wireshark.exe",
        "C:\\Program Files (x86)\\Wireshark\\Wireshark.exe",
    ];

    for path in &candidates {
        let p = PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    None
}
