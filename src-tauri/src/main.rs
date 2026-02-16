#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

mod commands;

fn main() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            log::info!("Kusanagi Kajiki v{} starting", env!("CARGO_PKG_VERSION"));

            // Initialize application state
            app.manage(commands::AppState::new());

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // System
            commands::system::list_interfaces,
            commands::system::get_app_info,
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
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
