//! Tauri commands for signature management.
//!
//! Provides commands to list, reload, and test signatures from the frontend.

use serde::Serialize;
use tauri::State;

use gm_signatures::{PacketData, Signature};

use super::AppState;

/// Information about a loaded signature, for the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureInfo {
    pub name: String,
    pub description: String,
    pub vendor: Option<String>,
    pub product_family: Option<String>,
    pub protocol: Option<String>,
    pub confidence: u8,
    pub role: Option<String>,
    pub device_type: Option<String>,
    pub filter_count: usize,
}

impl From<&Signature> for SignatureInfo {
    fn from(sig: &Signature) -> Self {
        SignatureInfo {
            name: sig.name.clone(),
            description: sig.description.clone(),
            vendor: sig.vendor.clone(),
            product_family: sig.product_family.clone(),
            protocol: sig.protocol.clone(),
            confidence: sig.confidence,
            role: sig.role.clone(),
            device_type: sig.device_type.clone(),
            filter_count: sig.filters.len(),
        }
    }
}

/// Summary of loaded signatures.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureSummary {
    pub total_count: usize,
    pub signatures: Vec<SignatureInfo>,
}

/// Result of testing a signature against loaded PCAP data.
#[derive(Debug, Clone, Serialize)]
pub struct SignatureTestResult {
    pub match_count: usize,
    pub matches: Vec<TestResultInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TestResultInfo {
    pub packet_index: usize,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub confidence: u8,
}

/// Get all loaded signatures.
#[tauri::command]
pub fn get_signatures(state: State<'_, AppState>) -> Result<SignatureSummary, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    let sigs: Vec<SignatureInfo> = state_inner
        .signature_engine
        .signatures()
        .iter()
        .map(SignatureInfo::from)
        .collect();

    Ok(SignatureSummary {
        total_count: sigs.len(),
        signatures: sigs,
    })
}

/// Reload signatures from disk.
#[tauri::command]
pub fn reload_signatures(state: State<'_, AppState>) -> Result<usize, String> {
    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    let count = state_inner
        .signature_engine
        .reload()
        .map_err(|e| e.to_string())?;
    log::info!("Reloaded {} signatures", count);
    Ok(count)
}

/// Test a YAML signature against the currently loaded PCAP data.
///
/// The frontend sends raw YAML text; we parse it, run it against
/// all stored packet summaries' connection data, and return matches.
#[tauri::command]
pub fn test_signature(
    yaml: String,
    state: State<'_, AppState>,
) -> Result<SignatureTestResult, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    // Build PacketData from stored connections for testing.
    // We don't have full payload data in packet summaries (they're lightweight),
    // so we create basic PacketData from connection info for filter testing.
    let mut test_packets: Vec<PacketData> = Vec::new();

    for conn in &state_inner.connections {
        test_packets.push(PacketData {
            src_ip: conn.src_ip.clone(),
            dst_ip: conn.dst_ip.clone(),
            src_port: conn.src_port,
            dst_port: conn.dst_port,
            src_mac: conn.src_mac.clone(),
            dst_mac: conn.dst_mac.clone(),
            transport: conn.transport.clone(),
            protocol: conn.protocol.to_lowercase(),
            payload: Vec::new(), // No payload in summaries
            length: 0,
        });
    }

    let results = state_inner
        .signature_engine
        .test_signature(&yaml, &test_packets)
        .map_err(|e| e.to_string())?;

    let matches: Vec<TestResultInfo> = results
        .into_iter()
        .map(|r| TestResultInfo {
            packet_index: r.packet_index,
            src_ip: r.src_ip,
            dst_ip: r.dst_ip,
            src_port: r.src_port,
            dst_port: r.dst_port,
            confidence: r.confidence,
        })
        .collect();

    Ok(SignatureTestResult {
        match_count: matches.len(),
        matches,
    })
}
