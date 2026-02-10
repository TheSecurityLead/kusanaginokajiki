#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;

mod commands;

fn main() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            log::info!("GRASSMARLIN Reborn v{} starting", env!("CARGO_PKG_VERSION"));

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
            // Data queries
            commands::data::get_topology,
            commands::data::get_assets,
            commands::data::get_connections,
            commands::data::get_protocol_stats,
            commands::data::get_connection_packets,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
