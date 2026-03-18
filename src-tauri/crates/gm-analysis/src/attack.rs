//! MITRE ATT&CK for ICS technique detection.
//!
//! Analyzes deep parse info, asset data, and connections to detect
//! known attack patterns mapped to MITRE ATT&CK for ICS techniques.
//!
//! ## Detected Techniques
//!
//! | Technique | Behavior | Severity |
//! |-----------|----------|----------|
//! | T0855 | Modbus broadcast/mass writes (FC 5/6/15/16 to unit 0/255) | Critical |
//! | T0814 | Modbus FC 8 diagnostics from non-engineering workstation | High |
//! | T0856 | DNP3 unsolicited response to unknown master | Medium |
//! | T0846 | Unknown device polling PLCs (new source targeting OT ports) | High |
//! | T0886 | Cross-Purdue zone communication (L1 <-> L4) | Medium |

use std::collections::{HashMap, HashSet};

use crate::{AnalysisInput, CaptureContext, Finding, FindingType, Severity};

/// Well-known OT server ports used to identify PLCs/RTUs.
const OT_SERVER_PORTS: &[u16] = &[
    102, 502, 1089, 1090, 1091, 2222, 2404, 4840, 5007, 5094, 18245, 18246, 20000, 34962, 34963,
    34964, 44818, 47808,
];

/// Modbus write function codes.
const MODBUS_WRITE_FCS: &[u8] = &[5, 6, 15, 16];

/// Run all ATT&CK technique detections on the input data.
///
/// Includes the 18 Phase 14C detections from [`crate::context_attacks`] that
/// require the richer [`CaptureContext`] snapshot.
pub fn detect_attack_techniques(input: &AnalysisInput, ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_t0855_unauthorized_writes(input));
    findings.extend(detect_t0814_diagnostic_dos(input));
    findings.extend(detect_t0856_dnp3_unsolicited(input));
    findings.extend(detect_t0846_remote_discovery(input));
    findings.extend(detect_enip_attacks(input));
    findings.extend(detect_s7_attacks(input));
    findings.extend(detect_bacnet_attacks(input));
    findings.extend(detect_iec104_attacks(input));
    findings.extend(detect_flat_network(input));
    findings.extend(detect_cleartext_ot(input));
    findings.extend(detect_internet_exposed_ot(input));
    findings.extend(crate::context_attacks::detect_context_attacks(input, ctx));

    findings
}

/// T0855 — Unauthorized Command Message
///
/// Detects Modbus broadcast/mass writes: FC 5/6/15/16 sent to
/// unit ID 0 (broadcast) or unit ID 255 (all devices), or
/// a single source writing to many targets (high fan-out).
fn detect_t0855_unauthorized_writes(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let modbus = match &dp.modbus {
            Some(m) => m,
            None => continue,
        };

        // Only check masters (devices sending write commands)
        if modbus.role != "master" && modbus.role != "both" {
            continue;
        }

        // Check for broadcast writes (unit ID 0 or 255)
        let has_broadcast_unit = modbus.unit_ids.contains(&0) || modbus.unit_ids.contains(&255);
        let has_write_fcs = modbus
            .function_codes
            .iter()
            .any(|fc| MODBUS_WRITE_FCS.contains(&fc.code) && fc.count > 0);

        if has_broadcast_unit && has_write_fcs {
            let write_count: u64 = modbus
                .function_codes
                .iter()
                .filter(|fc| MODBUS_WRITE_FCS.contains(&fc.code))
                .map(|fc| fc.count)
                .sum();

            let broadcast_ids: Vec<String> = modbus
                .unit_ids
                .iter()
                .filter(|&&uid| uid == 0 || uid == 255)
                .map(|uid| uid.to_string())
                .collect();

            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Critical,
                format!("Modbus broadcast write from {}", ip),
                "Modbus write commands (FC 5/6/15/16) sent to broadcast unit IDs. \
                 This could indicate unauthorized command injection targeting all \
                 devices on the Modbus network simultaneously."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Source {} sent {} write commands to broadcast unit ID(s): {}",
                    ip,
                    write_count,
                    broadcast_ids.join(", ")
                ),
                Some("T0855".to_string()),
            ));
        }

        // Check for high fan-out writes (writing to many different targets)
        let write_targets: Vec<&str> = modbus
            .relationships
            .iter()
            .filter(|r| r.remote_role == "slave")
            .map(|r| r.remote_ip.as_str())
            .collect();

        if write_targets.len() >= 5 && has_write_fcs {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("High fan-out Modbus writes from {}", ip),
                "A single device is sending Modbus write commands to many targets. \
                 This pattern may indicate unauthorized mass command injection."
                    .to_string(),
                std::iter::once(ip.clone())
                    .chain(write_targets.iter().map(|s| s.to_string()))
                    .collect(),
                format!(
                    "Source {} writing to {} targets: {}",
                    ip,
                    write_targets.len(),
                    write_targets.join(", ")
                ),
                Some("T0855".to_string()),
            ));
        }
    }

    findings
}

/// T0814 — Denial of Service
///
/// Detects Modbus FC 8 (Diagnostics) from devices that are not
/// classified as engineering workstations. FC 8 can restart or
/// clear PLC memory — risky from unauthorized sources.
fn detect_t0814_diagnostic_dos(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build set of engineering workstation IPs
    let eng_ws_ips: HashSet<&str> = input
        .assets
        .iter()
        .filter(|a| a.device_type == "engineering_workstation")
        .map(|a| a.ip_address.as_str())
        .collect();

    for (ip, dp) in &input.deep_parse {
        let modbus = match &dp.modbus {
            Some(m) => m,
            None => continue,
        };

        // Look for FC 8 (Diagnostics) usage
        let fc8_count: u64 = modbus
            .function_codes
            .iter()
            .filter(|fc| fc.code == 8)
            .map(|fc| fc.count)
            .sum();

        if fc8_count == 0 {
            continue;
        }

        // If the source is not an engineering workstation, flag it
        if !eng_ws_ips.contains(ip.as_str()) {
            let device_type = input
                .assets
                .iter()
                .find(|a| a.ip_address == *ip)
                .map(|a| a.device_type.as_str())
                .unwrap_or("unknown");

            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("Modbus diagnostics (FC 8) from non-engineer: {}", ip),
                "Modbus Function Code 8 (Diagnostics) can restart slave devices, \
                 clear counters, or force listen-only mode. This function code \
                 should only originate from authorized engineering workstations."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Device {} (type: {}) sent {} Modbus FC 8 diagnostic commands",
                    ip, device_type, fc8_count
                ),
                Some("T0814".to_string()),
            ));
        }
    }

    findings
}

/// T0856 — Modify Alarm Settings (DNP3 Unsolicited Response)
///
/// Detects DNP3 unsolicited responses (FC 130) sent to devices
/// that are not known masters. Unsolicited responses from outstations
/// to unknown destinations may indicate alarm suppression or manipulation.
fn detect_t0856_dnp3_unsolicited(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build set of known DNP3 master IPs
    let known_masters: HashSet<String> = input
        .deep_parse
        .iter()
        .filter_map(|(ip, dp)| {
            dp.dnp3.as_ref().and_then(|d| {
                if d.role == "master" || d.role == "both" {
                    Some(ip.clone())
                } else {
                    None
                }
            })
        })
        .collect();

    for (ip, dp) in &input.deep_parse {
        let dnp3 = match &dp.dnp3 {
            Some(d) => d,
            None => continue,
        };

        if !dnp3.has_unsolicited {
            continue;
        }

        // Check if unsolicited responses go to unknown masters
        let unknown_targets: Vec<String> = dnp3
            .relationships
            .iter()
            .filter(|r| r.remote_role == "master" && !known_masters.contains(&r.remote_ip))
            .map(|r| r.remote_ip.clone())
            .collect();

        if !unknown_targets.is_empty() {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Medium,
                format!("DNP3 unsolicited response from {} to unknown master", ip),
                "DNP3 unsolicited responses (FC 130) are being sent to devices \
                 not recognized as authorized masters. This could indicate alarm \
                 manipulation or unauthorized data exfiltration."
                    .to_string(),
                std::iter::once(ip.clone())
                    .chain(unknown_targets.iter().cloned())
                    .collect(),
                format!(
                    "Outstation {} sent unsolicited responses to unknown master(s): {}",
                    ip,
                    unknown_targets.join(", ")
                ),
                Some("T0856".to_string()),
            ));
        }

        // Also flag if there are no known masters at all (suspicious standalone unsolicited)
        if known_masters.is_empty() && dnp3.has_unsolicited {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Medium,
                format!("DNP3 unsolicited response with no known masters: {}", ip),
                "DNP3 unsolicited responses detected but no authorized masters \
                 have been identified in the network. All unsolicited traffic \
                 is potentially unauthorized."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Device {} sending DNP3 unsolicited responses (FC 130) \
                     but no DNP3 masters detected on network",
                    ip
                ),
                Some("T0856".to_string()),
            ));
        }
    }

    findings
}

/// T0846 — Remote System Discovery
///
/// Detects unknown/IT devices polling OT devices on well-known
/// ICS ports. An unknown device scanning PLC ports suggests
/// reconnaissance.
fn detect_t0846_remote_discovery(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Build set of known OT device IPs (PLCs, RTUs, HMIs, etc.)
    let ot_device_ips: HashSet<&str> = input
        .assets
        .iter()
        .filter(|a| {
            matches!(
                a.device_type.as_str(),
                "plc" | "rtu" | "hmi" | "historian" | "engineering_workstation" | "scada_server"
            )
        })
        .map(|a| a.ip_address.as_str())
        .collect();

    // Find connections where an unknown/IT device connects to OT ports
    let mut scanner_targets: HashMap<String, HashSet<String>> = HashMap::new();

    for conn in &input.connections {
        // Check if destination is an OT server port
        if !OT_SERVER_PORTS.contains(&conn.dst_port) {
            continue;
        }

        // Check if the source is NOT a known OT device
        let src_asset = input.assets.iter().find(|a| a.ip_address == conn.src_ip);
        let is_known_ot = ot_device_ips.contains(conn.src_ip.as_str());

        // Flag if source is IT/unknown AND targeting OT ports on multiple devices
        if !is_known_ot {
            let src_type = src_asset
                .map(|a| a.device_type.as_str())
                .unwrap_or("unknown");
            if src_type == "it_device" || src_type == "unknown" {
                scanner_targets
                    .entry(conn.src_ip.clone())
                    .or_default()
                    .insert(conn.dst_ip.clone());
            }
        }
    }

    // Only flag scanners targeting 3+ different OT devices
    for (scanner_ip, targets) in &scanner_targets {
        if targets.len() >= 3 {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!(
                    "Unknown device {} polling {} PLCs/RTUs",
                    scanner_ip,
                    targets.len()
                ),
                "A device not classified as OT equipment is connecting to \
                 multiple ICS devices on well-known OT service ports. This \
                 behavior resembles network reconnaissance or unauthorized polling."
                    .to_string(),
                std::iter::once(scanner_ip.clone())
                    .chain(targets.iter().cloned())
                    .collect(),
                format!(
                    "Device {} connected to OT ports on {} targets: {}",
                    scanner_ip,
                    targets.len(),
                    targets.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                Some("T0846".to_string()),
            ));
        }
    }

    findings
}

/// EtherNet/IP ATT&CK detections: T0855 (CIP write), T0836 (firmware), T0846 (discovery).
fn detect_enip_attacks(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let enip = match &dp.enip {
            Some(e) => e,
            None => continue,
        };

        // T0855: CIP Write or ReadModifyWrite to Assembly object controls I/O data
        if enip.cip_writes_to_assembly {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("CIP write to Assembly object from {}", ip),
                "CIP Write or ReadModifyWrite command targeting an Assembly object was \
                 detected. Assembly objects control I/O data for connected devices and \
                 writes may cause unexpected actuator behavior."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Source {} sent CIP Write/ReadModifyWrite to Assembly (class 0x04)",
                    ip
                ),
                Some("T0855".to_string()),
            ));
        }

        // T0836: CIP File class access — firmware upload/download or program file transfer
        if enip.cip_file_access {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Critical,
                format!(
                    "CIP File class access from {} (possible firmware operation)",
                    ip
                ),
                "Access to the CIP File object class (0x37) was detected. File class objects \
                 are used for firmware uploads and program file transfers. Unauthorized access \
                 may indicate firmware modification or intellectual property theft."
                    .to_string(),
                vec![ip.clone()],
                format!("Source {} accessed CIP File object class (0x37)", ip),
                Some("T0836".to_string()),
            ));
        }

        // T0846: ListIdentity from an IT/unknown device — OT network reconnaissance
        if enip.list_identity_requests {
            let src_type = input
                .assets
                .iter()
                .find(|a| a.ip_address == *ip)
                .map(|a| a.device_type.as_str())
                .unwrap_or("unknown");
            if src_type == "it_device" || src_type == "unknown" {
                findings.push(Finding::new(
                    FindingType::AttackTechnique,
                    Severity::Medium,
                    format!("EtherNet/IP ListIdentity from non-OT device {}", ip),
                    "ListIdentity requests enumerate all EtherNet/IP devices on the network. \
                     This request from an unclassified or IT device may indicate network \
                     reconnaissance of the OT environment."
                        .to_string(),
                    vec![ip.clone()],
                    format!(
                        "Device {} (type: {}) sent EtherNet/IP ListIdentity requests",
                        ip, src_type
                    ),
                    Some("T0846".to_string()),
                ));
            }
        }
    }

    findings
}

/// S7comm ATT&CK detections: T0843, T0845, T0816, T0809, T0855.
fn detect_s7_attacks(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let s7 = match &dp.s7 {
            Some(s) => s,
            None => continue,
        };

        // T0843: Program download — replaces PLC control logic
        if s7.functions_seen.contains(&"download_start".to_string()) {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Critical,
                format!("S7 program download from {}", ip),
                "An S7 Download Start (function 0x1D) was detected. This initiates a \
                 program download to the PLC, which can replace the control logic and \
                 cause unexpected physical process behavior."
                    .to_string(),
                vec![ip.clone()],
                format!("Source {} initiated S7comm Download Start (FC 0x1D)", ip),
                Some("T0843".to_string()),
            ));
        }

        // T0845: Program upload — reads PLC logic (reconnaissance / IP theft)
        if s7.functions_seen.contains(&"upload_start".to_string()) {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("S7 program upload from {}", ip),
                "An S7 Upload Start (function 0x1A) was detected. This reads the PLC \
                 program logic and may indicate intellectual property theft or \
                 reconnaissance to understand process control before an attack."
                    .to_string(),
                vec![ip.clone()],
                format!("Source {} initiated S7comm Upload Start (FC 0x1A)", ip),
                Some("T0845".to_string()),
            ));
        }

        // T0816: PLC Stop — halts PLC execution
        if s7.functions_seen.contains(&"plc_stop".to_string()) {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Critical,
                format!("S7 PLC Stop command from {}", ip),
                "An S7 PLC Stop command (function 0x29) was detected. This halts PLC \
                 execution, which will cause controlled processes to enter a safe state \
                 or fail, potentially causing loss of control or production disruption."
                    .to_string(),
                vec![ip.clone()],
                format!("Source {} sent S7comm PLC Stop (FC 0x29)", ip),
                Some("T0816".to_string()),
            ));
        }

        // T0809: PI Service — can delete program blocks
        if s7.functions_seen.contains(&"pi_service".to_string()) {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Critical,
                format!("S7 PI Service (possible block delete) from {}", ip),
                "An S7 PI Service command (function 0x28) was detected. This function \
                 can delete program blocks from the PLC, destroying control logic and \
                 requiring full system restoration."
                    .to_string(),
                vec![ip.clone()],
                format!("Source {} sent S7comm PI Service (FC 0x28)", ip),
                Some("T0809".to_string()),
            ));
        }

        // T0855: Write Var — writes directly to PLC memory
        if s7.functions_seen.contains(&"write_var".to_string()) {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("S7 Write Var command from {}", ip),
                "An S7 Write Var command (function 0x05) was detected. This writes values \
                 directly to PLC memory areas (inputs, outputs, merkers, data blocks), \
                 which can cause unauthorized changes to process control variables."
                    .to_string(),
                vec![ip.clone()],
                format!("Source {} sent S7comm Write Var (FC 0x05)", ip),
                Some("T0855".to_string()),
            ));
        }
    }

    findings
}

/// IEC 60870-5-104 ATT&CK detections: T0855 (control commands), T0816 (reset process), T0814 (interrogation flood).
fn detect_iec104_attacks(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let iec104 = match &dp.iec104 {
            Some(i) => i,
            None => continue,
        };

        // T0855: Control command ASDUs (type IDs 45–69) — unauthorized command message
        if iec104.has_control_commands {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("IEC 104 control commands from {}", ip),
                "IEC 60870-5-104 control command ASDUs (type IDs 45–69) were detected. \
                 These commands control physical process elements at the outstation \
                 (e.g., circuit breakers, valves, set-points). Unauthorized command \
                 injection can cause unexpected physical process changes."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Source {} sent IEC 104 control command ASDUs (type IDs 45–69)",
                    ip
                ),
                Some("T0855".to_string()),
            ));
        }

        // T0816: Reset Process command (type ID 105) — disrupts outstation process
        if iec104.has_reset_process {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Critical,
                format!("IEC 104 Reset Process command from {}", ip),
                "An IEC 104 Reset Process command (C_RP_NA_1, type ID 105) was detected. \
                 This command resets the outstation's process, potentially disrupting \
                 power grid control or other critical infrastructure operations and \
                 causing a loss of control or availability."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Source {} sent IEC 104 Reset Process (C_RP_NA_1, type ID 105)",
                    ip
                ),
                Some("T0816".to_string()),
            ));
        }

        // T0814: Interrogation from non-OT device — potential DoS / reconnaissance
        if iec104.has_interrogation {
            let src_type = input
                .assets
                .iter()
                .find(|a| a.ip_address == *ip)
                .map(|a| a.device_type.as_str())
                .unwrap_or("unknown");
            if src_type == "it_device" || src_type == "unknown" {
                findings.push(Finding::new(
                    FindingType::AttackTechnique,
                    Severity::Medium,
                    format!("IEC 104 interrogation from non-OT device {}", ip),
                    "IEC 104 General Interrogation commands (C_IC_NA_1, type ID 100) were \
                     detected from a device not classified as OT equipment. Interrogation \
                     requests from unauthorized sources may indicate network reconnaissance \
                     or an attempt to flood the outstation's response queue."
                        .to_string(),
                    vec![ip.clone()],
                    format!(
                        "Device {} (type: {}) sent IEC 104 General Interrogation (C_IC_NA_1)",
                        ip, src_type
                    ),
                    Some("T0814".to_string()),
                ));
            }
        }
    }

    findings
}

/// BACnet ATT&CK detections: T0855, T0856, T0816, T0811.
fn detect_bacnet_attacks(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let bacnet = match &dp.bacnet {
            Some(b) => b,
            None => continue,
        };

        // T0855: WriteProperty to output object — directly controls physical actuators
        if bacnet.write_to_output {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("BACnet WriteProperty to output object from {}", ip),
                "A BACnet WriteProperty to an AnalogOutput or BinaryOutput object was \
                 detected. Writing to output objects directly controls physical actuators \
                 such as valves, dampers, and relays in building automation systems."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Source {} wrote to BACnet AnalogOutput or BinaryOutput object",
                    ip
                ),
                Some("T0855".to_string()),
            ));
        }

        // T0856: WriteProperty to NotificationClass — suppresses alarms
        if bacnet.write_to_notification_class {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("BACnet alarm suppression from {}", ip),
                "A BACnet WriteProperty to a NotificationClass object was detected. \
                 NotificationClass objects control alarm routing and notification. \
                 Modifying these can suppress alarms, preventing operators from \
                 detecting faults or process anomalies."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Source {} modified BACnet NotificationClass object (alarm routing)",
                    ip
                ),
                Some("T0856".to_string()),
            ));
        }

        // T0816: ReinitializeDevice — restarts or restores device to defaults
        if bacnet.reinitialize_device {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("BACnet ReinitializeDevice from {}", ip),
                "A BACnet ReinitializeDevice service was detected. This command can \
                 restart or restore a BACnet device to defaults, causing loss of \
                 control and potentially overwriting operational configuration."
                    .to_string(),
                vec![ip.clone()],
                format!("Source {} sent BACnet ReinitializeDevice command", ip),
                Some("T0816".to_string()),
            ));
        }

        // T0811: DeviceCommunicationControl — disables device communication (loss of view)
        if bacnet.device_communication_control {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("BACnet DeviceCommunicationControl from {}", ip),
                "A BACnet DeviceCommunicationControl service was detected. This command \
                 can disable a device's ability to initiate communications, causing a \
                 denial of view for operators monitoring the building automation system."
                    .to_string(),
                vec![ip.clone()],
                format!(
                    "Source {} sent BACnet DeviceCommunicationControl command",
                    ip
                ),
                Some("T0811".to_string()),
            ));
        }
    }

    findings
}

/// Flat Network Detection
///
/// If >80% of discovered devices share the same /24 subnet and
/// there are more than 5 devices, this indicates a flat (unsegmented)
/// network, which is a critical OT security risk.
fn detect_flat_network(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    if input.assets.len() < 6 {
        return findings; // Too few devices to make this determination
    }

    // Count devices per /24 subnet
    let mut subnet_counts: HashMap<String, Vec<String>> = HashMap::new();
    for asset in &input.assets {
        let subnet = ip_to_slash24(&asset.ip_address);
        subnet_counts
            .entry(subnet)
            .or_default()
            .push(asset.ip_address.clone());
    }

    let total = input.assets.len();
    for (subnet, ips) in &subnet_counts {
        let pct = ips.len() as f64 / total as f64;
        if pct > 0.8 && ips.len() > 5 {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!(
                    "Flat network detected — {} of {} devices on {}",
                    ips.len(),
                    total,
                    subnet
                ),
                "More than 80% of discovered devices reside on a single /24 subnet. \
                 A flat network provides no lateral movement barriers — a single \
                 compromised device can reach all OT assets without traversing any \
                 security boundary."
                    .to_string(),
                ips.clone(),
                format!(
                    "{}/{} devices ({:.0}%) are on subnet {} — no segmentation detected",
                    ips.len(),
                    total,
                    pct * 100.0,
                    subnet
                ),
                Some("T0886".to_string()),
            ));
        }
    }

    findings
}

/// Convert an IPv4 address to its /24 network prefix (e.g., "192.168.1.100" → "192.168.1.0/24").
fn ip_to_slash24(ip: &str) -> String {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
    } else {
        ip.to_string()
    }
}

/// Protocol Encryption Audit
///
/// All standard ICS protocols (Modbus, DNP3, EtherNet/IP, S7comm, etc.)
/// are cleartext. This function computes what percentage of OT connections
/// are unencrypted and generates a finding if any cleartext OT traffic exists.
fn detect_cleartext_ot(input: &AnalysisInput) -> Vec<Finding> {
    const CLEARTEXT_OT_PORTS: &[u16] = &[
        502,   // Modbus
        20000, // DNP3
        44818, // EtherNet/IP
        102,   // S7comm (ISO-TSAP)
        47808, // BACnet
        2404,  // IEC 104
        34962, 34963, 34964, // PROFINET
        4840,  // OPC UA (unencrypted)
        1883,  // MQTT (unencrypted)
        5094,  // HART-IP
        18245, 18246, // GE SRTP
    ];

    let mut findings = Vec::new();
    let mut cleartext_by_proto: HashMap<String, u64> = HashMap::new();
    let mut total_cleartext: u64 = 0;
    let mut total_ot: u64 = 0;

    for conn in &input.connections {
        if CLEARTEXT_OT_PORTS.contains(&conn.dst_port) {
            *cleartext_by_proto.entry(conn.protocol.clone()).or_insert(0) += conn.packet_count;
            total_cleartext += conn.packet_count;
            total_ot += conn.packet_count;
        } else if conn.protocol == "OpcUa" && conn.dst_port == 4843 {
            // OPC UA with TLS — don't count as cleartext
            total_ot += conn.packet_count;
        }
    }

    if total_cleartext == 0 {
        return findings;
    }

    let pct = if total_ot > 0 {
        (total_cleartext as f64 / total_ot as f64) * 100.0
    } else {
        100.0
    };

    let severity = if pct >= 99.0 {
        Severity::High
    } else if pct >= 50.0 {
        Severity::Medium
    } else {
        Severity::Low
    };

    let proto_breakdown: Vec<String> = cleartext_by_proto
        .iter()
        .map(|(p, c)| format!("{}: {} packets", p, c))
        .collect();

    findings.push(Finding::new(
        FindingType::AttackTechnique,
        severity,
        format!("{:.0}% of OT traffic is unencrypted", pct),
        "Standard OT protocols (Modbus, DNP3, EtherNet/IP, S7comm, BACnet, IEC 104, PROFINET) \
         transmit all data in cleartext. An attacker with network access can read all process \
         values, setpoints, and control commands without any decryption."
            .to_string(),
        vec![],
        format!(
            "{:.1}% cleartext OT traffic ({} of {} packets). Breakdown: {}",
            pct,
            total_cleartext,
            total_ot,
            proto_breakdown.join(", ")
        ),
        None,
    ));

    findings
}

/// Internet Exposure Check
///
/// If an OT device has a public IP address (determined by GeoIP returning
/// a country code), it may be directly internet-accessible. This is a
/// Critical finding — internet-facing PLCs/RTUs are a common attack vector.
fn detect_internet_exposed_ot(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for asset in &input.assets {
        if !asset.is_public_ip {
            continue;
        }

        // Check if this device speaks any OT protocol
        let ot_protocols: Vec<&str> = asset
            .protocols
            .iter()
            .filter(|p| {
                let pl = p.to_lowercase();
                pl.contains("modbus")
                    || pl.contains("dnp3")
                    || pl.contains("s7comm")
                    || pl.contains("ethernet")
                    || pl.contains("bacnet")
                    || pl.contains("iec104")
                    || pl.contains("profinet")
                    || pl.contains("opcua")
            })
            .map(|p| p.as_str())
            .collect();

        if ot_protocols.is_empty() {
            continue;
        }

        // Build Shodan query for assessor
        let ot_ports: Vec<&str> = ot_protocols
            .iter()
            .filter_map(|p| match p.to_lowercase().as_str() {
                s if s.contains("modbus") => Some("port:502"),
                s if s.contains("dnp3") => Some("port:20000"),
                s if s.contains("s7comm") => Some("port:102"),
                s if s.contains("ethernet") => Some("port:44818"),
                s if s.contains("bacnet") => Some("port:47808"),
                s if s.contains("iec104") => Some("port:2404"),
                _ => None,
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        let shodan_query = if ot_ports.is_empty() {
            format!("ip:{}", asset.ip_address)
        } else {
            format!("ip:{} {}", asset.ip_address, ot_ports.join(" "))
        };

        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::Critical,
            format!("Internet-exposed OT device: {}", asset.ip_address),
            format!(
                "Device {} has a public IP address and communicates using OT protocols ({}). \
                 Internet-facing OT devices are directly reachable by global threat actors \
                 and are frequently indexed by Shodan, Censys, and similar scanners. \
                 Verify firewall rules and consider segmenting this device behind a NAT/DMZ.",
                asset.ip_address,
                ot_protocols.join(", ")
            ),
            vec![asset.ip_address.clone()],
            format!(
                "Public IP {} speaks OT protocols: {}. Shodan query: {}",
                asset.ip_address,
                ot_protocols.join(", "),
                shodan_query
            ),
            Some("T0846".to_string()),
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;

    fn make_input() -> AnalysisInput {
        AnalysisInput::default()
    }

    #[test]
    fn test_t0855_broadcast_write() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.100".to_string(),
            DeepParseSnapshot {
                modbus: Some(ModbusSnapshot {
                    role: "master".to_string(),
                    unit_ids: vec![0, 1, 255],
                    function_codes: vec![
                        FcSnapshot {
                            code: 6,
                            count: 50,
                            is_write: true,
                        },
                        FcSnapshot {
                            code: 3,
                            count: 200,
                            is_write: false,
                        },
                    ],
                    relationships: vec![],
                    polling_intervals: vec![],
                }),
                ..Default::default()
            },
        );

        let findings = detect_t0855_unauthorized_writes(&input);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].technique_id, Some("T0855".to_string()));
    }

    #[test]
    fn test_t0855_high_fanout() {
        let mut input = make_input();
        let targets: Vec<RelationshipSnapshot> = (1..=6)
            .map(|i| RelationshipSnapshot {
                remote_ip: format!("10.0.0.{}", i),
                remote_role: "slave".to_string(),
                packet_count: 100,
            })
            .collect();

        input.deep_parse.insert(
            "10.0.0.100".to_string(),
            DeepParseSnapshot {
                modbus: Some(ModbusSnapshot {
                    role: "master".to_string(),
                    unit_ids: vec![1, 2, 3],
                    function_codes: vec![FcSnapshot {
                        code: 16,
                        count: 100,
                        is_write: true,
                    }],
                    relationships: targets,
                    polling_intervals: vec![],
                }),
                ..Default::default()
            },
        );

        let findings = detect_t0855_unauthorized_writes(&input);
        assert!(findings.iter().any(|f| f.title.contains("fan-out")));
    }

    #[test]
    fn test_t0814_fc8_from_non_engineer() {
        let mut input = make_input();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.50".to_string(),
            device_type: "it_device".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
            hostname: None,
            product_family: None,
        });

        input.deep_parse.insert(
            "10.0.0.50".to_string(),
            DeepParseSnapshot {
                modbus: Some(ModbusSnapshot {
                    role: "master".to_string(),
                    unit_ids: vec![1],
                    function_codes: vec![FcSnapshot {
                        code: 8,
                        count: 10,
                        is_write: false,
                    }],
                    relationships: vec![],
                    polling_intervals: vec![],
                }),
                ..Default::default()
            },
        );

        let findings = detect_t0814_diagnostic_dos(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].technique_id, Some("T0814".to_string()));
    }

    #[test]
    fn test_t0814_fc8_from_engineer_ok() {
        let mut input = make_input();
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.50".to_string(),
            device_type: "engineering_workstation".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
            hostname: None,
            product_family: None,
        });

        input.deep_parse.insert(
            "10.0.0.50".to_string(),
            DeepParseSnapshot {
                modbus: Some(ModbusSnapshot {
                    role: "master".to_string(),
                    unit_ids: vec![1],
                    function_codes: vec![FcSnapshot {
                        code: 8,
                        count: 10,
                        is_write: false,
                    }],
                    relationships: vec![],
                    polling_intervals: vec![],
                }),
                ..Default::default()
            },
        );

        let findings = detect_t0814_diagnostic_dos(&input);
        assert!(
            findings.is_empty(),
            "FC 8 from engineering workstation should not be flagged"
        );
    }

    #[test]
    fn test_t0856_unsolicited_unknown_master() {
        let mut input = make_input();

        // Outstation sending unsolicited responses
        input.deep_parse.insert(
            "10.0.0.10".to_string(),
            DeepParseSnapshot {
                dnp3: Some(Dnp3Snapshot {
                    role: "outstation".to_string(),
                    has_unsolicited: true,
                    function_codes: vec![FcSnapshot {
                        code: 130,
                        count: 5,
                        is_write: false,
                    }],
                    relationships: vec![RelationshipSnapshot {
                        remote_ip: "192.168.1.50".to_string(),
                        remote_role: "master".to_string(),
                        packet_count: 5,
                    }],
                }),
                ..Default::default()
            },
        );

        let findings = detect_t0856_dnp3_unsolicited(&input);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].technique_id, Some("T0856".to_string()));
    }

    #[test]
    fn test_t0846_unknown_device_scanning() {
        let mut input = make_input();

        // Known OT devices
        for i in 1..=5 {
            input.assets.push(AssetSnapshot {
                ip_address: format!("10.0.0.{}", i),
                device_type: "plc".to_string(),
                protocols: vec!["modbus".to_string()],
                purdue_level: Some(1),
                is_public_ip: false,
                tags: vec![],
                vendor: None,
                hostname: None,
                product_family: None,
            });
        }

        // Unknown scanner
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.200".to_string(),
            device_type: "unknown".to_string(),
            protocols: vec![],
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
            hostname: None,
            product_family: None,
        });

        // Scanner connecting to 3+ PLCs on Modbus port
        for i in 1..=4 {
            input.connections.push(ConnectionSnapshot {
                src_ip: "10.0.0.200".to_string(),
                dst_ip: format!("10.0.0.{}", i),
                src_port: 49152,
                dst_port: 502,
                protocol: "Modbus".to_string(),
                packet_count: 10,
            });
        }

        let findings = detect_t0846_remote_discovery(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].technique_id, Some("T0846".to_string()));
    }

    #[test]
    fn test_no_false_positive_known_hmi_polling() {
        let mut input = make_input();

        // Known HMI polling PLCs is normal behavior
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.100".to_string(),
            device_type: "hmi".to_string(),
            protocols: vec!["modbus".to_string()],
            purdue_level: Some(2),
            is_public_ip: false,
            tags: vec![],
            vendor: None,
            hostname: None,
            product_family: None,
        });

        for i in 1..=5 {
            input.assets.push(AssetSnapshot {
                ip_address: format!("10.0.0.{}", i),
                device_type: "plc".to_string(),
                protocols: vec!["modbus".to_string()],
                purdue_level: Some(1),
                is_public_ip: false,
                tags: vec![],
                vendor: None,
                hostname: None,
                product_family: None,
            });

            input.connections.push(ConnectionSnapshot {
                src_ip: "10.0.0.100".to_string(),
                dst_ip: format!("10.0.0.{}", i),
                src_port: 49152,
                dst_port: 502,
                protocol: "Modbus".to_string(),
                packet_count: 1000,
            });
        }

        let findings = detect_t0846_remote_discovery(&input);
        assert!(
            findings.is_empty(),
            "HMI polling PLCs should not trigger T0846"
        );
    }

    #[test]
    fn test_t0855_cip_write_assembly() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.50".to_string(),
            DeepParseSnapshot {
                enip: Some(EnipSnapshot {
                    role: "scanner".to_string(),
                    cip_writes_to_assembly: true,
                    cip_file_access: false,
                    list_identity_requests: false,
                }),
                ..Default::default()
            },
        );

        let findings = detect_enip_attacks(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].technique_id, Some("T0855".to_string()));
    }

    #[test]
    fn test_t0836_cip_file_access() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.51".to_string(),
            DeepParseSnapshot {
                enip: Some(EnipSnapshot {
                    role: "scanner".to_string(),
                    cip_writes_to_assembly: false,
                    cip_file_access: true,
                    list_identity_requests: false,
                }),
                ..Default::default()
            },
        );

        let findings = detect_enip_attacks(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].technique_id, Some("T0836".to_string()));
    }

    #[test]
    fn test_t0843_s7_download_start() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.20".to_string(),
            DeepParseSnapshot {
                s7: Some(S7Snapshot {
                    role: "client".to_string(),
                    functions_seen: vec!["download_start".to_string()],
                }),
                ..Default::default()
            },
        );

        let findings = detect_s7_attacks(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].technique_id, Some("T0843".to_string()));
    }

    #[test]
    fn test_t0816_s7_plc_stop() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.21".to_string(),
            DeepParseSnapshot {
                s7: Some(S7Snapshot {
                    role: "client".to_string(),
                    functions_seen: vec!["plc_stop".to_string()],
                }),
                ..Default::default()
            },
        );

        let findings = detect_s7_attacks(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].technique_id, Some("T0816".to_string()));
    }

    #[test]
    fn test_t0855_bacnet_write_output() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.30".to_string(),
            DeepParseSnapshot {
                bacnet: Some(BacnetSnapshot {
                    role: "client".to_string(),
                    write_to_output: true,
                    write_to_notification_class: false,
                    reinitialize_device: false,
                    device_communication_control: false,
                }),
                ..Default::default()
            },
        );

        let findings = detect_bacnet_attacks(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].technique_id, Some("T0855".to_string()));
    }

    #[test]
    fn test_t0811_bacnet_comm_ctrl() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.31".to_string(),
            DeepParseSnapshot {
                bacnet: Some(BacnetSnapshot {
                    role: "client".to_string(),
                    write_to_output: false,
                    write_to_notification_class: false,
                    reinitialize_device: false,
                    device_communication_control: true,
                }),
                ..Default::default()
            },
        );

        let findings = detect_bacnet_attacks(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].technique_id, Some("T0811".to_string()));
    }

    #[test]
    fn test_t0855_iec104_control_commands() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.40".to_string(),
            DeepParseSnapshot {
                iec104: Some(Iec104Snapshot {
                    role: "master".to_string(),
                    has_control_commands: true,
                    has_reset_process: false,
                    has_interrogation: false,
                }),
                ..Default::default()
            },
        );

        let findings = detect_iec104_attacks(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].technique_id, Some("T0855".to_string()));
    }

    #[test]
    fn test_t0816_iec104_reset_process() {
        let mut input = make_input();
        input.deep_parse.insert(
            "10.0.0.41".to_string(),
            DeepParseSnapshot {
                iec104: Some(Iec104Snapshot {
                    role: "master".to_string(),
                    has_control_commands: false,
                    has_reset_process: true,
                    has_interrogation: false,
                }),
                ..Default::default()
            },
        );

        let findings = detect_iec104_attacks(&input);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].technique_id, Some("T0816".to_string()));
    }

    #[test]
    fn test_flat_network_detection() {
        let mut input = make_input();
        // 9 devices on same /24
        for i in 1..=9 {
            input.assets.push(AssetSnapshot {
                ip_address: format!("192.168.1.{}", i),
                device_type: "plc".to_string(),
                protocols: vec!["modbus".to_string()],
                purdue_level: Some(1),
                is_public_ip: false,
                tags: vec![],
                vendor: None,
                hostname: None,
                product_family: None,
            });
        }
        // 1 device on different subnet
        input.assets.push(AssetSnapshot {
            ip_address: "10.0.0.1".to_string(),
            device_type: "it_device".to_string(),
            protocols: vec![],
            purdue_level: Some(4),
            is_public_ip: false,
            tags: vec![],
            vendor: None,
            hostname: None,
            product_family: None,
        });

        let findings = detect_flat_network(&input);
        assert!(!findings.is_empty(), "should detect flat network");
        assert_eq!(findings[0].technique_id, Some("T0886".to_string()));
    }

    #[test]
    fn test_no_flat_network_with_few_devices() {
        let mut input = make_input();
        for i in 1..=4 {
            input.assets.push(AssetSnapshot {
                ip_address: format!("192.168.1.{}", i),
                device_type: "plc".to_string(),
                protocols: vec![],
                purdue_level: Some(1),
                is_public_ip: false,
                tags: vec![],
                vendor: None,
                hostname: None,
                product_family: None,
            });
        }
        let findings = detect_flat_network(&input);
        assert!(
            findings.is_empty(),
            "too few devices should not trigger flat network"
        );
    }
}
