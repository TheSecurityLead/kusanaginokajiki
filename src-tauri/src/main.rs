#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use clap::Parser;
use tauri::Manager;

mod commands;

/// Kusanagi Kajiki — Modern ICS/SCADA passive network discovery tool
#[derive(Parser, Debug, Clone)]
#[command(name = "kusanaginokajiki", version, about)]
struct Cli {
    /// Open a .kkj session archive or PCAP file on startup
    #[arg(long)]
    open: Option<String>,

    /// Import a PCAP file directly on startup
    #[arg(long = "import-pcap")]
    import_pcap: Option<String>,
}

fn main() {
    env_logger::init();

    // Parse CLI arguments before Tauri takes over
    let cli = Cli::parse();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .setup(move |app| {
            log::info!("Kusanagi Kajiki v{} starting", env!("CARGO_PKG_VERSION"));

            // Initialize application state
            app.manage(commands::AppState::new());

            // Store CLI args for deferred processing after window is ready
            app.manage(CliArgs(Mutex::new(cli)));

            // Handle CLI args: open or import on startup
            let app_handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                // Small delay to let the window initialize
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                let cli_args = app_handle.state::<CliArgs>();
                let args = match cli_args.0.lock() {
                    Ok(guard) => guard.clone(),
                    Err(e) => {
                        log::error!("CLI: failed to read CLI args: {}", e);
                        return;
                    }
                };

                if let Some(ref path) = args.import_pcap {
                    log::info!("CLI: importing PCAP from {}", path);
                    let state = app_handle.state::<commands::AppState>();
                    let inner = state.inner.lock();
                    if let Ok(mut inner) = inner {
                        match import_pcap_file(path, &mut inner) {
                            Ok(count) => log::info!("CLI: imported {} packets from {}", count, path),
                            Err(e) => log::error!("CLI: failed to import {}: {}", path, e),
                        }
                    }
                } else if let Some(ref path) = args.open {
                    if path.ends_with(".kkj") {
                        log::info!("CLI: opening session archive {}", path);
                        log::info!("CLI: use the Capture tab to import .kkj archives");
                    } else {
                        log::info!("CLI: opening PCAP file {}", path);
                        let state = app_handle.state::<commands::AppState>();
                        let inner = state.inner.lock();
                        if let Ok(mut inner) = inner {
                            match import_pcap_file(path, &mut inner) {
                                Ok(count) => log::info!("CLI: imported {} packets from {}", count, path),
                                Err(e) => log::error!("CLI: failed to import {}: {}", path, e),
                            }
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // System
            commands::system::list_interfaces,
            commands::system::get_app_info,
            commands::system::get_settings,
            commands::system::save_settings,
            commands::system::list_plugins,
            // Capture / Import
            commands::capture::import_pcap,
            // Live Capture
            commands::capture::start_capture,
            commands::capture::stop_capture,
            commands::capture::pause_capture,
            commands::capture::resume_capture,
            commands::capture::get_capture_status,
            // Data queries
            commands::data::get_topology,
            commands::data::get_assets,
            commands::data::get_connections,
            commands::data::get_protocol_stats,
            commands::data::get_connection_packets,
            commands::data::get_deep_parse_info,
            commands::data::get_function_code_stats,
            commands::data::get_timeline_range,
            // Signatures
            commands::signatures::get_signatures,
            commands::signatures::reload_signatures,
            commands::signatures::test_signature,
            // Sessions & Asset Updates (Phase 6)
            commands::session::save_session,
            commands::session::load_session,
            commands::session::list_sessions,
            commands::session::delete_session,
            commands::session::update_asset,
            commands::session::bulk_update_assets,
            commands::session::export_session_archive,
            commands::session::import_session_archive,
            // Baseline Drift (Phase 11)
            commands::baseline::compare_sessions,
            // Physical Topology (Phase 7)
            commands::physical::import_cisco_config,
            commands::physical::import_mac_table,
            commands::physical::import_cdp_neighbors,
            commands::physical::import_arp_table,
            commands::physical::get_physical_topology,
            commands::physical::clear_physical_topology,
            // External Tool Import (Phase 8)
            commands::ingest::import_zeek_logs,
            commands::ingest::import_suricata_eve,
            commands::ingest::import_nmap_xml,
            commands::ingest::import_masscan_json,
            // Wireshark Integration (Phase 8)
            commands::wireshark::detect_wireshark,
            commands::wireshark::open_in_wireshark,
            commands::wireshark::open_wireshark_for_node,
            commands::wireshark::get_connection_frames,
            commands::wireshark::export_frames_csv,
            commands::wireshark::save_frames_csv,
            // Export & Reporting (Phase 9)
            commands::export::export_assets_csv,
            commands::export::export_connections_csv,
            commands::export::export_topology_json,
            commands::export::export_assets_json,
            commands::export::generate_pdf_report,
            commands::export::export_sbom,
            commands::export::export_stix_bundle,
            commands::export::save_topology_image,
            // Security Analysis (Phase 10)
            commands::analysis::run_analysis,
            commands::analysis::get_findings,
            commands::analysis::get_purdue_assignments,
            commands::analysis::get_anomalies,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Wrapper to store CLI args in Tauri managed state.
struct CliArgs(Mutex<Cli>);

/// Import a PCAP file into the current state (used by CLI).
fn import_pcap_file(
    path: &str,
    inner: &mut commands::AppStateInner,
) -> Result<usize, String> {
    use gm_capture::PcapReader;

    let reader = PcapReader::new();
    let packets = reader.read_file(path).map_err(|e| e.to_string())?;
    let count = packets.len();

    let mut processor = commands::processor::PacketProcessor::new();
    for packet in &packets {
        processor.process_packet(packet);
    }

    let deep_parse_info = processor.build_deep_parse_info();
    let (assets, sig_results) = processor.build_assets(
        &inner.signature_engine,
        &deep_parse_info,
        &inner.oui_lookup,
        &inner.geoip_lookup,
    );

    // Build topology, enriched with signature data
    let mut topo = processor.topo_builder.snapshot();
    for node in &mut topo.nodes {
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

    inner.topology = topo;
    inner.assets = assets;
    inner.connections = processor.get_connections();
    inner.packet_summaries = processor.get_packet_summaries();
    inner.deep_parse_info = deep_parse_info;
    inner.imported_files.push(path.to_string());

    Ok(count)
}
