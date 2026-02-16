use std::path::PathBuf;
use serde::{Serialize, Deserialize};

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

// ─── Settings Persistence (Phase 11) ────────────────────────

/// Persistent user settings stored as JSON at ~/.kusanaginokajiki/settings.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    /// Theme mode: "dark", "light", or "system"
    #[serde(default = "default_theme")]
    pub theme: String,
}

fn default_theme() -> String {
    "dark".to_string()
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            theme: default_theme(),
        }
    }
}

/// Get the settings file path.
fn settings_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    Ok(home.join(".kusanaginokajiki").join("settings.json"))
}

/// Load user settings from disk. Returns defaults if file doesn't exist.
#[tauri::command]
pub fn get_settings() -> Result<UserSettings, String> {
    let path = settings_path()?;
    if !path.exists() {
        return Ok(UserSettings::default());
    }
    let content = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

/// Save user settings to disk.
#[tauri::command]
pub fn save_settings(settings: UserSettings) -> Result<(), String> {
    let path = settings_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let content = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(&path, content).map_err(|e| e.to_string())?;
    log::info!("Settings saved to {}", path.display());
    Ok(())
}

// ─── Plugin Discovery (Phase 11) ────────────────────────────

/// A plugin manifest describing a plugin pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    /// Plugin type: "signature", "importer", "exporter", "analyzer"
    pub plugin_type: String,
    pub description: String,
    pub author: Option<String>,
}

/// List plugins found in the plugins directory.
///
/// Scans ~/.kusanaginokajiki/plugins/ for manifest.json files.
#[tauri::command]
pub fn list_plugins() -> Result<Vec<PluginManifest>, String> {
    let home = dirs::home_dir().ok_or("Could not determine home directory")?;
    let plugins_dir = home.join(".kusanaginokajiki").join("plugins");

    if !plugins_dir.exists() {
        // Create the directory so users know where to put plugins
        let _ = std::fs::create_dir_all(&plugins_dir);
        return Ok(Vec::new());
    }

    let mut plugins = Vec::new();
    let entries = std::fs::read_dir(&plugins_dir).map_err(|e| e.to_string())?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest_path = path.join("manifest.json");
        if manifest_path.exists() {
            match std::fs::read_to_string(&manifest_path) {
                Ok(content) => {
                    match serde_json::from_str::<PluginManifest>(&content) {
                        Ok(manifest) => plugins.push(manifest),
                        Err(e) => {
                            log::warn!("Invalid plugin manifest at {}: {}", manifest_path.display(), e);
                        }
                    }
                }
                Err(e) => {
                    log::warn!("Failed to read {}: {}", manifest_path.display(), e);
                }
            }
        }
    }

    Ok(plugins)
}
