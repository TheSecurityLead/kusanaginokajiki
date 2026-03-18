use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tauri::{Emitter, Manager, State};

use gm_capture::{CaptureError, LiveCaptureConfig, LiveCaptureHandle, ParsedPacket, PcapReader};

use super::processor::PacketProcessor;
use super::AppState;

/// Payload for a real-time ATT&CK alert emitted during live capture.
#[derive(Debug, Clone, Serialize)]
pub struct LiveAttackAlert {
    pub technique_id: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub affected_assets: Vec<String>,
    pub evidence: String,
    pub timestamp: String,
}

// ─── PCAP Import ─────────────────────────────────────────────

#[derive(Serialize)]
pub struct ImportResult {
    pub file_count: usize,
    pub packet_count: usize,
    pub connection_count: usize,
    pub asset_count: usize,
    pub protocols_detected: Vec<String>,
    pub duration_ms: u64,
    pub per_file: Vec<FileImportResult>,
}

#[derive(Serialize)]
pub struct FileImportResult {
    pub filename: String,
    pub packet_count: usize,
    pub status: String,
}

/// Progress payload emitted as the `import_progress` event during PCAP import.
#[derive(Serialize, Clone)]
pub struct ImportProgressPayload {
    pub current_file: String,
    pub file_index: usize,
    pub file_count: usize,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub file_size: u64,
    pub progress_percent: f64,
    pub elapsed_secs: f64,
}

/// Import one or more PCAP files and process them through the full pipeline.
///
/// Processing runs on a blocking thread so the Tauri async executor stays
/// responsive. Progress is emitted as `import_progress` events roughly every
/// 500ms. The import can be cancelled via the `cancel_import` command.
#[tauri::command]
pub async fn import_pcap(
    paths: Vec<String>,
    state: State<'_, AppState>,
    app_handle: tauri::AppHandle,
) -> Result<ImportResult, String> {
    let start = Instant::now();

    // Reset and clone the cancellation flag for the blocking thread
    state.import_cancelled.store(false, Ordering::SeqCst);
    let cancelled = state.import_cancelled.clone();
    let app_clone = app_handle.clone();
    let paths_clone = paths.clone();
    let file_count = paths.len();

    // Run packet streaming on a blocking thread — reading from a PCAP file is
    // synchronous I/O and must not block the Tauri async executor.
    let blocking_result = tauri::async_runtime::spawn_blocking(move || {
        let reader = PcapReader::new();
        let mut processor = PacketProcessor::new();
        let mut per_file_results: Vec<FileImportResult> = Vec::new();

        for (file_idx, path) in paths_clone.iter().enumerate() {
            if cancelled.load(Ordering::Relaxed) {
                return Err("Import cancelled by user".to_string());
            }

            let filename = std::path::Path::new(path)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.clone());

            let stream_result = reader.stream_file(
                path,
                // on_packet: process each packet immediately, no buffering
                |packet| {
                    processor.process_packet(packet);
                },
                // on_progress: emit Tauri event to frontend (throttled to ~2/sec)
                |progress| {
                    let _ = app_clone.emit(
                        "import_progress",
                        ImportProgressPayload {
                            current_file: progress.current_file,
                            file_index: file_idx,
                            file_count,
                            packets_processed: progress.packets_processed,
                            bytes_processed: progress.bytes_processed,
                            file_size: progress.file_size,
                            progress_percent: progress.progress_percent,
                            elapsed_secs: progress.elapsed_secs,
                        },
                    );
                },
                cancelled.as_ref(),
            );

            match stream_result {
                Ok(stats) => {
                    per_file_results.push(FileImportResult {
                        filename,
                        packet_count: stats.packet_count as usize,
                        status: "ok".to_string(),
                    });
                }
                Err(CaptureError::Cancelled) => {
                    return Err("Import cancelled by user".to_string());
                }
                Err(e) => {
                    log::warn!("Failed to read {}: {}", path, e);
                    per_file_results.push(FileImportResult {
                        filename,
                        packet_count: 0,
                        status: format!("error: {}", e),
                    });
                }
            }
        }

        Ok((processor, per_file_results))
    })
    .await
    .map_err(|e| e.to_string())?;

    let (mut processor, per_file_results) = blocking_result?;

    let total_packet_count: usize = per_file_results.iter().map(|r| r.packet_count).sum();
    if total_packet_count == 0 && !per_file_results.iter().any(|r| r.status == "ok") {
        return Err("No packets could be parsed from the provided files".to_string());
    }

    // Build results (bounded by unique IPs, not packet count)
    let deep_parse_info = processor.build_deep_parse_info();

    // Lock state to run signature matching (needs SignatureEngine + OUI + GeoIP)
    let (assets, sig_results) = {
        let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
        processor.build_assets(
            &state_inner.signature_engine,
            &deep_parse_info,
            &state_inner.oui_lookup,
            &state_inner.geoip_lookup,
        )
    };

    // Build topology enriched with signature data
    let mut topology = processor.topo_builder.snapshot();
    for node in &mut topology.nodes {
        if let Some(sig_matches) = sig_results.get(&node.ip_address) {
            if let Some(best) = sig_matches.first() {
                if let Some(ref v) = best.vendor {
                    node.vendor = Some(v.clone());
                }
                if let Some(ref dt) = best.device_type {
                    if best.confidence >= 3 {
                        node.device_type = dt.clone();
                    }
                }
            }
        }
    }

    let connection_list = processor.get_connections();
    let packet_summaries = processor.get_packet_summaries();
    let (connection_stats, pattern_anomalies) = processor.build_pattern_results();
    let redundancy_protocols = processor.build_redundancy_info();
    let asset_count = assets.len();
    let connection_count = connection_list.len();
    let protocols_detected = processor.get_protocols_detected();

    let imported_files: Vec<String> = per_file_results
        .iter()
        .filter(|f| f.status == "ok")
        .map(|f| f.filename.clone())
        .collect();

    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    state_inner.topology = topology;
    state_inner.assets = assets;
    state_inner.connections = connection_list;
    state_inner.packet_summaries = packet_summaries;
    state_inner.deep_parse_info = deep_parse_info;
    state_inner.connection_stats = connection_stats;
    state_inner.pattern_anomalies = pattern_anomalies;
    state_inner.redundancy_protocols = redundancy_protocols;
    state_inner.imported_files.extend(imported_files);
    state_inner.imported_files.sort();
    state_inner.imported_files.dedup();

    let duration_ms = start.elapsed().as_millis() as u64;

    log::info!(
        "Imported {} files, {} packets → {} assets, {} connections in {}ms",
        paths.len(),
        total_packet_count,
        asset_count,
        connection_count,
        duration_ms
    );

    Ok(ImportResult {
        file_count: paths.len(),
        packet_count: total_packet_count,
        connection_count,
        asset_count,
        protocols_detected,
        duration_ms,
        per_file: per_file_results,
    })
}

/// Cancel an in-progress PCAP import. Safe to call even when no import is running.
#[tauri::command]
pub async fn cancel_import(state: State<'_, AppState>) -> Result<(), String> {
    state.import_cancelled.store(true, Ordering::SeqCst);
    log::info!("PCAP import cancellation requested");
    Ok(())
}

// ─── Live Capture ────────────────────────────────────────────

/// Statistics emitted to the frontend during live capture.
#[derive(Serialize, Clone)]
pub struct CaptureStatsPayload {
    pub packets_captured: u64,
    pub packets_per_second: u64,
    pub bytes_captured: u64,
    pub active_connections: usize,
    pub asset_count: usize,
    pub elapsed_seconds: f64,
}

/// Result of stopping a capture.
#[derive(Serialize)]
pub struct StopCaptureResult {
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub elapsed_seconds: f64,
    pub pcap_saved: bool,
    pub pcap_path: Option<String>,
    pub packets_saved: usize,
}

/// Start a live packet capture on a network interface.
///
/// Opens the interface in promiscuous mode (PASSIVE ONLY — never transmits).
/// Spawns a background capture thread and a processing thread that runs the
/// full pipeline (protocol ID → deep parse → signatures → topology).
/// Emits `capture-stats` events to the frontend at ~10 updates/sec.
#[tauri::command]
pub async fn start_capture(
    interface_name: String,
    bpf_filter: Option<String>,
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<(), String> {
    // Check if a capture is already running
    {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;
        if inner.live_capture.is_some() {
            return Err("A capture is already running. Stop it first.".to_string());
        }
    }

    // Configure and start the capture
    let config = LiveCaptureConfig {
        interface_name: interface_name.clone(),
        bpf_filter: bpf_filter.clone(),
        promiscuous: true,
        ring_buffer_size: 1_000_000,
        snaplen: 65535,
    };

    let (handle, rx) = LiveCaptureHandle::start(config).map_err(|e| e.to_string())?;

    log::info!(
        "Live capture started on {} (filter: {:?})",
        interface_name,
        bpf_filter
    );

    // Spawn the processing thread
    let processing_handle = spawn_processing_thread(rx, app);

    // Store handles in app state
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner.live_capture = Some(handle);
    inner.processing_thread = Some(processing_handle);

    Ok(())
}

/// Stop the live capture, optionally saving to a PCAP file.
#[tauri::command]
pub async fn stop_capture(
    save_path: Option<String>,
    state: State<'_, AppState>,
) -> Result<StopCaptureResult, String> {
    // Take the capture handle and processing thread out of state
    // (releases the lock before stopping, avoiding deadlock)
    let (mut capture, processing_thread) = {
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
        let capture = inner.live_capture.take();
        let processing = inner.processing_thread.take();
        (capture, processing)
    };

    let Some(ref mut handle) = capture else {
        return Err("No capture is running.".to_string());
    };

    // Get final stats before stopping
    let stats = handle.stats();

    // Stop the capture thread (sets stop flag, joins thread)
    handle.stop().map_err(|e| e.to_string())?;

    // Wait for the processing thread to finish
    // (it exits when the channel is disconnected after capture stops)
    if let Some(pt) = processing_thread {
        let _ = pt.join();
    }

    // Save PCAP if requested
    let (pcap_saved, pcap_path, packets_saved) = if let Some(ref path) = save_path {
        let count = handle.save_to_pcap(path).map_err(|e| e.to_string())?;
        log::info!("Saved {} packets to {}", count, path);
        (true, Some(path.clone()), count)
    } else {
        (false, None, 0)
    };

    log::info!(
        "Live capture stopped: {} packets, {} bytes, {:.1}s",
        stats.packets_captured,
        stats.bytes_captured,
        stats.elapsed_seconds
    );

    Ok(StopCaptureResult {
        packets_captured: stats.packets_captured,
        bytes_captured: stats.bytes_captured,
        elapsed_seconds: stats.elapsed_seconds,
        pcap_saved,
        pcap_path,
        packets_saved,
    })
}

/// Pause the live capture (packets arriving while paused are not captured).
#[tauri::command]
pub async fn pause_capture(state: State<'_, AppState>) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    if let Some(ref handle) = inner.live_capture {
        handle.pause();
        log::info!("Live capture paused");
        Ok(())
    } else {
        Err("No capture is running.".to_string())
    }
}

/// Resume a paused live capture.
#[tauri::command]
pub async fn resume_capture(state: State<'_, AppState>) -> Result<(), String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    if let Some(ref handle) = inner.live_capture {
        handle.resume();
        log::info!("Live capture resumed");
        Ok(())
    } else {
        Err("No capture is running.".to_string())
    }
}

/// Get the current capture status.
#[tauri::command]
pub async fn get_capture_status(state: State<'_, AppState>) -> Result<CaptureStatusInfo, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    if let Some(ref handle) = inner.live_capture {
        let stats = handle.stats();
        Ok(CaptureStatusInfo {
            is_running: handle.is_running(),
            is_paused: handle.is_paused(),
            packets_captured: stats.packets_captured,
            bytes_captured: stats.bytes_captured,
            elapsed_seconds: stats.elapsed_seconds,
        })
    } else {
        Ok(CaptureStatusInfo {
            is_running: false,
            is_paused: false,
            packets_captured: 0,
            bytes_captured: 0,
            elapsed_seconds: 0.0,
        })
    }
}

#[derive(Serialize)]
pub struct CaptureStatusInfo {
    pub is_running: bool,
    pub is_paused: bool,
    pub packets_captured: u64,
    pub bytes_captured: u64,
    pub elapsed_seconds: f64,
}

// ─── Processing Thread ───────────────────────────────────────

/// Spawn a background thread that receives parsed packets from the capture
/// thread, processes them through the pipeline, updates AppState, and emits
/// events to the frontend.
fn spawn_processing_thread(
    rx: mpsc::Receiver<ParsedPacket>,
    app: tauri::AppHandle,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let state = app.state::<AppState>();
        let mut processor = PacketProcessor::new();
        let mut batch: Vec<ParsedPacket> = Vec::new();
        let mut last_flush = Instant::now();
        let mut prev_packet_count: u64 = 0;
        let mut prev_stat_time = Instant::now();
        let flush_interval = Duration::from_millis(100);
        // Track how many connections were checked to detect only new ones
        let mut alert_connection_watermark: usize = 0;

        loop {
            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok(packet) => {
                    batch.push(packet);

                    // Flush if interval elapsed or batch is large enough
                    if last_flush.elapsed() >= flush_interval || batch.len() >= 500 {
                        flush_batch(
                            &mut processor,
                            &mut batch,
                            &state,
                            &app,
                            &mut prev_packet_count,
                            &mut prev_stat_time,
                            &mut alert_connection_watermark,
                        );
                        last_flush = Instant::now();
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // No packets available, flush pending batch if interval elapsed
                    if !batch.is_empty() && last_flush.elapsed() >= flush_interval {
                        flush_batch(
                            &mut processor,
                            &mut batch,
                            &state,
                            &app,
                            &mut prev_packet_count,
                            &mut prev_stat_time,
                            &mut alert_connection_watermark,
                        );
                        last_flush = Instant::now();
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    // Capture stopped (sender dropped), process remaining batch
                    if !batch.is_empty() {
                        flush_batch(
                            &mut processor,
                            &mut batch,
                            &state,
                            &app,
                            &mut prev_packet_count,
                            &mut prev_stat_time,
                            &mut alert_connection_watermark,
                        );
                    }
                    log::info!("Processing thread exiting (capture stopped)");
                    break;
                }
            }
        }
    })
}

/// Process a batch of packets, update AppState, and emit events.
fn flush_batch(
    processor: &mut PacketProcessor,
    batch: &mut Vec<ParsedPacket>,
    state: &AppState,
    app: &tauri::AppHandle,
    prev_packet_count: &mut u64,
    prev_stat_time: &mut Instant,
    alert_connection_watermark: &mut usize,
) {
    // Process each packet through the pipeline
    for packet in batch.drain(..) {
        processor.process_packet(&packet);
    }

    // Build deep parse info from accumulators
    let deep_parse_info = processor.build_deep_parse_info();

    // Lock state to run signature matching and update
    let update_result: Result<CaptureStatsPayload, String> = (|| {
        let inner = state.inner.lock().map_err(|e| e.to_string())?;

        // Run signature matching with OUI + GeoIP enrichment
        let (assets, sig_results) = processor.build_assets(
            &inner.signature_engine,
            &deep_parse_info,
            &inner.oui_lookup,
            &inner.geoip_lookup,
        );

        // Build topology snapshot, enriched with signature data
        let mut topology = processor.topo_builder.snapshot();
        for node in &mut topology.nodes {
            if let Some(sig_matches) = sig_results.get(&node.ip_address) {
                if let Some(best) = sig_matches.first() {
                    if let Some(ref v) = best.vendor {
                        node.vendor = Some(v.clone());
                    }
                    if let Some(ref dt) = best.device_type {
                        if best.confidence >= 3 {
                            node.device_type = dt.clone();
                        }
                    }
                }
            }
        }

        let connections = processor.get_connections();
        let packet_summaries = processor.get_packet_summaries();
        let (connection_stats, pattern_anomalies) = processor.build_pattern_results();
        let redundancy_protocols = processor.build_redundancy_info();
        let asset_count = assets.len();
        let connection_count = connections.len();
        let total_packets = processor.total_packets;

        // Drop the immutable borrow and get a mutable one
        drop(inner);
        let mut inner = state.inner.lock().map_err(|e| e.to_string())?;

        inner.topology = topology;
        inner.assets = assets;
        inner.connections = connections;
        inner.packet_summaries = packet_summaries;
        inner.deep_parse_info = deep_parse_info;
        inner.connection_stats = connection_stats;
        inner.pattern_anomalies = pattern_anomalies;
        inner.redundancy_protocols = redundancy_protocols;

        // Compute PPS
        let elapsed = prev_stat_time.elapsed().as_secs_f64();
        let pps = if elapsed > 0.0 {
            ((total_packets - *prev_packet_count) as f64 / elapsed) as u64
        } else {
            0
        };

        // Get capture stats from the live capture handle
        let (bytes_captured, elapsed_seconds) = if let Some(ref handle) = inner.live_capture {
            let stats = handle.stats();
            (stats.bytes_captured, stats.elapsed_seconds)
        } else {
            (0, 0.0)
        };

        Ok(CaptureStatsPayload {
            packets_captured: total_packets,
            packets_per_second: pps,
            bytes_captured,
            active_connections: connection_count,
            asset_count,
            elapsed_seconds,
        })
    })();

    match update_result {
        Ok(stats) => {
            *prev_packet_count = stats.packets_captured;
            *prev_stat_time = Instant::now();

            // Emit stats event to frontend
            if let Err(e) = app.emit("capture-stats", &stats) {
                log::warn!("Failed to emit capture-stats event: {}", e);
            }

            // Run lightweight ATT&CK checks on new connections since last batch
            run_live_attack_detection(state, app, alert_connection_watermark);
        }
        Err(e) => {
            log::error!("Failed to update state during live capture: {}", e);
            // Emit error event
            let _ = app.emit("capture-error", &e);
        }
    }
}

/// Check new connections against lightweight Group 1 ATT&CK rules.
///
/// Only runs checks on connections added since the last call (using the
/// watermark). Emits `live_attack_alert` events for any matches.
///
/// Checks performed (no CaptureContext required):
/// - T0822: Remote access (VNC/RDP) to OT device
/// - T0867: Lateral tool transfer (SMB/FTP) to OT device
/// - T0868: Remote service (SSH/Telnet) to OT device
/// - T0885: Web management UI (HTTP/HTTPS) to OT device
fn run_live_attack_detection(state: &AppState, app: &tauri::AppHandle, watermark: &mut usize) {
    let inner = match state.inner.lock() {
        Ok(g) => g,
        Err(_) => return,
    };

    let connections = &inner.connections;
    if connections.len() <= *watermark {
        // No new connections
        *watermark = connections.len();
        return;
    }

    // Build OT device IP set from asset inventory
    let ot_ips: HashSet<&str> = inner
        .assets
        .iter()
        .filter(|a| is_ot_device_type(&a.device_type))
        .map(|a| a.ip_address.as_str())
        .collect();

    let now = chrono::Utc::now().to_rfc3339();

    // Check only the newly added connections
    for conn in &connections[*watermark..] {
        let dst_is_ot = ot_ips.contains(conn.dst_ip.as_str());
        let src_is_ot = ot_ips.contains(conn.src_ip.as_str());
        if !dst_is_ot && !src_is_ot {
            continue;
        }

        let target_ip = if dst_is_ot {
            &conn.dst_ip
        } else {
            &conn.src_ip
        };
        let port = if dst_is_ot {
            conn.dst_port
        } else {
            conn.src_port
        };

        if let Some(alert) = check_connection_for_live_alert(target_ip, port, conn, &now) {
            if let Err(e) = app.emit("live_attack_alert", &alert) {
                log::warn!("Failed to emit live_attack_alert: {}", e);
            }
        }
    }

    *watermark = connections.len();
}

/// Check a single connection for live ATT&CK alert conditions.
/// Returns Some(alert) if the connection matches a lightweight rule.
fn check_connection_for_live_alert(
    ot_ip: &str,
    port: u16,
    conn: &super::ConnectionInfo,
    timestamp: &str,
) -> Option<LiveAttackAlert> {
    match port {
        // T0822 — Remote Desktop/VNC to OT device
        3389 | 5900 | 5800 => Some(LiveAttackAlert {
            technique_id: "T0822".to_string(),
            title: "Remote Desktop Access to OT Device".to_string(),
            severity: "high".to_string(),
            description: format!(
                "Remote desktop/VNC connection (port {}) to OT device {}",
                port, ot_ip
            ),
            affected_assets: vec![ot_ip.to_string()],
            evidence: format!(
                "{}:{} → {}:{} ({})",
                conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port, conn.protocol
            ),
            timestamp: timestamp.to_string(),
        }),
        // T0867 — Lateral tool transfer (SMB/FTP)
        445 | 20 | 21 => Some(LiveAttackAlert {
            technique_id: "T0867".to_string(),
            title: "Lateral Tool Transfer to OT Device".to_string(),
            severity: "high".to_string(),
            description: format!(
                "File transfer protocol (port {}) to OT device {}",
                port, ot_ip
            ),
            affected_assets: vec![ot_ip.to_string()],
            evidence: format!(
                "{}:{} → {}:{} ({})",
                conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port, conn.protocol
            ),
            timestamp: timestamp.to_string(),
        }),
        // T0868 — Remote services (SSH/Telnet)
        22 | 23 => Some(LiveAttackAlert {
            technique_id: "T0868".to_string(),
            title: "Remote Service Access to OT Device".to_string(),
            severity: "medium".to_string(),
            description: format!(
                "Remote service connection (port {}: {}) to OT device {}",
                port,
                if port == 22 { "SSH" } else { "Telnet" },
                ot_ip
            ),
            affected_assets: vec![ot_ip.to_string()],
            evidence: format!(
                "{}:{} → {}:{} ({})",
                conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port, conn.protocol
            ),
            timestamp: timestamp.to_string(),
        }),
        // T0885 — Web management UI on OT device
        80 | 443 | 8080 | 8443 => Some(LiveAttackAlert {
            technique_id: "T0885".to_string(),
            title: "Web Management Access to OT Device".to_string(),
            severity: "medium".to_string(),
            description: format!(
                "HTTP/HTTPS connection (port {}) to OT device {}",
                port, ot_ip
            ),
            affected_assets: vec![ot_ip.to_string()],
            evidence: format!(
                "{}:{} → {}:{} ({})",
                conn.src_ip, conn.src_port, conn.dst_ip, conn.dst_port, conn.protocol
            ),
            timestamp: timestamp.to_string(),
        }),
        _ => None,
    }
}

/// Check if a device_type string represents an OT field device.
fn is_ot_device_type(device_type: &str) -> bool {
    matches!(
        device_type,
        "plc" | "rtu" | "hmi" | "scada_server" | "historian"
    )
}
