//! Alert–device correlation commands.
//!
//! Takes imported IDS/SIEM alerts (Suricata, Wazuh) and enriches them with
//! device inventory data — hostname, device type, Purdue level — for the
//! "External Alerts" tab in AnalysisView and the device detail panel.

use serde::Serialize;
use tauri::State;

use super::{AppState, AppStateInner, StoredAlert};

/// An IDS/SIEM alert enriched with device inventory information.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelatedAlert {
    // ─── Alert fields ───────────────────────────────────────────
    pub timestamp: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub signature_id: u64,
    pub signature: String,
    pub category: String,
    /// 1 = high, 2 = medium, 3 = low
    pub severity: u8,
    pub source: String,

    // ─── Correlated device info (src) ──────────────────────────
    pub src_hostname: Option<String>,
    pub src_device_type: Option<String>,
    pub src_purdue_level: Option<u8>,

    // ─── Correlated device info (dst) ──────────────────────────
    pub dst_hostname: Option<String>,
    pub dst_device_type: Option<String>,
    pub dst_purdue_level: Option<u8>,
}

// ─── Commands ────────────────────────────────────────────────

/// Return all imported IDS/SIEM alerts, enriched with device inventory data.
#[tauri::command]
pub async fn get_correlated_alerts(
    state: State<'_, AppState>,
) -> Result<Vec<CorrelatedAlert>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let mut alerts: Vec<CorrelatedAlert> = inner
        .imported_alerts
        .iter()
        .map(|a| correlate_alert(a, &inner))
        .collect();
    // Sort by severity (1=high first), then timestamp descending
    alerts.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.timestamp.cmp(&a.timestamp))
    });
    Ok(alerts)
}

/// Return alerts involving a specific IP address (as src or dst).
#[tauri::command]
pub async fn get_alerts_for_ip(
    ip: String,
    state: State<'_, AppState>,
) -> Result<Vec<CorrelatedAlert>, String> {
    let inner = state.inner.lock().map_err(|e| e.to_string())?;
    let mut alerts: Vec<CorrelatedAlert> = inner
        .imported_alerts
        .iter()
        .filter(|a| a.src_ip == ip || a.dst_ip == ip)
        .map(|a| correlate_alert(a, &inner))
        .collect();
    alerts.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then(b.timestamp.cmp(&a.timestamp))
    });
    Ok(alerts)
}

/// Clear all stored alerts.
#[tauri::command]
pub async fn clear_alerts(state: State<'_, AppState>) -> Result<(), String> {
    let mut inner = state.inner.lock().map_err(|e| e.to_string())?;
    inner.imported_alerts.clear();
    log::info!("Cleared all imported alerts");
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────

/// Enrich a StoredAlert with device inventory info from AppStateInner.
fn correlate_alert(alert: &StoredAlert, inner: &AppStateInner) -> CorrelatedAlert {
    let (src_hostname, src_device_type, src_purdue_level) = lookup_device(&alert.src_ip, inner);
    let (dst_hostname, dst_device_type, dst_purdue_level) = lookup_device(&alert.dst_ip, inner);

    CorrelatedAlert {
        timestamp: alert.timestamp.clone(),
        src_ip: alert.src_ip.clone(),
        src_port: alert.src_port,
        dst_ip: alert.dst_ip.clone(),
        dst_port: alert.dst_port,
        signature_id: alert.signature_id,
        signature: alert.signature.clone(),
        category: alert.category.clone(),
        severity: alert.severity,
        source: alert.source.clone(),
        src_hostname,
        src_device_type,
        src_purdue_level,
        dst_hostname,
        dst_device_type,
        dst_purdue_level,
    }
}

/// Look up a device by IP in the asset inventory.
/// Returns (hostname, device_type, purdue_level).
fn lookup_device(ip: &str, inner: &AppStateInner) -> (Option<String>, Option<String>, Option<u8>) {
    if ip.is_empty() {
        return (None, None, None);
    }
    match inner.assets.iter().find(|a| a.ip_address == ip) {
        Some(asset) => (
            asset.hostname.clone(),
            Some(asset.device_type.clone()),
            asset.purdue_level,
        ),
        None => (None, None, None),
    }
}
