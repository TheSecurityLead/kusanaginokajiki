//! Security analysis commands: ATT&CK detection, Purdue assignment, anomaly scoring.
//!
//! These commands bridge the gm-analysis crate to the Tauri frontend.
//! They construct AnalysisInput from AppState, run analysis, and
//! store results back into AppState.

use tauri::State;

use gm_analysis::{
    AnalysisInput, AnalysisResult, AssetSnapshot, ConnectionSnapshot,
    DeepParseSnapshot, ModbusSnapshot, Dnp3Snapshot,
    EnipSnapshot, S7Snapshot, BacnetSnapshot, Iec104Snapshot, ProfinetDcpSnapshot,
    FcSnapshot, RelationshipSnapshot, PollingSnapshot,
    Finding, PurdueAssignment, AnomalyScore,
};

use super::AppState;

/// Build AnalysisInput from current AppState.
fn build_analysis_input(state: &super::AppStateInner) -> AnalysisInput {
    let assets: Vec<AssetSnapshot> = state.assets.iter().map(|a| {
        AssetSnapshot {
            ip_address: a.ip_address.clone(),
            device_type: a.device_type.clone(),
            protocols: a.protocols.clone(),
            purdue_level: a.purdue_level,
            is_public_ip: a.is_public_ip,
            tags: a.tags.clone(),
            vendor: a.vendor.clone(),
        }
    }).collect();

    let connections: Vec<ConnectionSnapshot> = state.connections.iter().map(|c| {
        ConnectionSnapshot {
            src_ip: c.src_ip.clone(),
            dst_ip: c.dst_ip.clone(),
            src_port: c.src_port,
            dst_port: c.dst_port,
            protocol: c.protocol.clone(),
            packet_count: c.packet_count,
        }
    }).collect();

    let mut deep_parse = std::collections::HashMap::new();
    for (ip, dp) in &state.deep_parse_info {
        let modbus = dp.modbus.as_ref().map(|m| {
            ModbusSnapshot {
                role: m.role.clone(),
                unit_ids: m.unit_ids.clone(),
                function_codes: m.function_codes.iter().map(|fc| {
                    FcSnapshot {
                        code: fc.code,
                        count: fc.count,
                        is_write: fc.is_write,
                    }
                }).collect(),
                relationships: m.relationships.iter().map(|r| {
                    RelationshipSnapshot {
                        remote_ip: r.remote_ip.clone(),
                        remote_role: r.remote_role.clone(),
                        packet_count: r.packet_count,
                    }
                }).collect(),
                polling_intervals: m.polling_intervals.iter().map(|pi| {
                    PollingSnapshot {
                        remote_ip: pi.remote_ip.clone(),
                        function_code: pi.function_code,
                        avg_interval_ms: pi.avg_interval_ms,
                        min_interval_ms: pi.min_interval_ms,
                        max_interval_ms: pi.max_interval_ms,
                        sample_count: pi.sample_count,
                    }
                }).collect(),
            }
        });

        let dnp3 = dp.dnp3.as_ref().map(|d| {
            Dnp3Snapshot {
                role: d.role.clone(),
                has_unsolicited: d.has_unsolicited,
                function_codes: d.function_codes.iter().map(|fc| {
                    FcSnapshot {
                        code: fc.code,
                        count: fc.count,
                        is_write: fc.is_write,
                    }
                }).collect(),
                relationships: d.relationships.iter().map(|r| {
                    RelationshipSnapshot {
                        remote_ip: r.remote_ip.clone(),
                        remote_role: r.remote_role.clone(),
                        packet_count: r.packet_count,
                    }
                }).collect(),
            }
        });

        let enip = dp.enip.as_ref().map(|e| EnipSnapshot {
            role: e.role.clone(),
            cip_writes_to_assembly: e.cip_writes_to_assembly,
            cip_file_access: e.cip_file_access,
            list_identity_requests: e.list_identity_requests,
        });

        let s7 = dp.s7.as_ref().map(|s| S7Snapshot {
            role: s.role.clone(),
            functions_seen: s.functions_seen.clone(),
        });

        let bacnet = dp.bacnet.as_ref().map(|b| BacnetSnapshot {
            role: b.role.clone(),
            write_to_output: b.write_to_output,
            write_to_notification_class: b.write_to_notification_class,
            reinitialize_device: b.reinitialize_device,
            device_communication_control: b.device_communication_control,
        });

        let iec104 = dp.iec104.as_ref().map(|i| Iec104Snapshot {
            role: i.role.clone(),
            has_control_commands: i.has_control_commands,
            has_reset_process: i.has_reset_process,
            has_interrogation: i.has_interrogation,
        });

        let profinet_dcp = dp.profinet_dcp.as_ref().map(|p| ProfinetDcpSnapshot {
            role: p.role.clone(),
        });

        deep_parse.insert(ip.clone(), DeepParseSnapshot { modbus, dnp3, enip, s7, bacnet, iec104, profinet_dcp });
    }

    AnalysisInput {
        assets,
        connections,
        deep_parse,
    }
}

/// Run the full security analysis pipeline.
///
/// Detects ATT&CK techniques, auto-assigns Purdue levels, scores anomalies.
/// Results are stored in AppState and returned to the frontend.
#[tauri::command]
pub fn run_analysis(state: State<'_, AppState>) -> Result<AnalysisResult, String> {
    let mut state_inner = state.inner.lock().map_err(|e| e.to_string())?;

    let input = build_analysis_input(&state_inner);
    let result = gm_analysis::run_full_analysis(&input);

    // Store results in AppState
    state_inner.findings = result.findings.clone();
    state_inner.purdue_assignments = result.purdue_assignments.clone();
    state_inner.anomalies = result.anomalies.clone();

    // Apply auto-assigned Purdue levels to assets (only where not manually set)
    for assignment in &result.purdue_assignments {
        if let Some(asset) = state_inner.assets.iter_mut()
            .find(|a| a.ip_address == assignment.ip_address)
        {
            if asset.purdue_level.is_none() {
                asset.purdue_level = Some(assignment.level);
            }
        }
    }

    Ok(result)
}

/// Get all findings from the last analysis run.
#[tauri::command]
pub fn get_findings(state: State<'_, AppState>) -> Result<Vec<Finding>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.findings.clone())
}

/// Get Purdue level assignments from the last analysis run.
#[tauri::command]
pub fn get_purdue_assignments(state: State<'_, AppState>) -> Result<Vec<PurdueAssignment>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.purdue_assignments.clone())
}

/// Get anomaly scores from the last analysis run.
#[tauri::command]
pub fn get_anomalies(state: State<'_, AppState>) -> Result<Vec<AnomalyScore>, String> {
    let state_inner = state.inner.lock().map_err(|e| e.to_string())?;
    Ok(state_inner.anomalies.clone())
}
