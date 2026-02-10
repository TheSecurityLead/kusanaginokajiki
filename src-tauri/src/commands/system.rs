use serde::Serialize;

/// List all available network interfaces.
///
/// This is the Phase 0 deliverable — proof that the Rust backend
/// is communicating with the SvelteKit frontend via Tauri IPC.
#[tauri::command]
pub fn list_interfaces() -> Result<Vec<gm_capture::NetworkInterface>, String> {
    gm_capture::list_interfaces().map_err(|e| e.to_string())
}

#[derive(Serialize)]
pub struct AppInfo {
    version: String,
    rust_version: String,
}

/// Get application version info.
#[tauri::command]
pub fn get_app_info() -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        rust_version: format!("rustc {}", env!("CARGO_PKG_RUST_VERSION")),
    }
}
