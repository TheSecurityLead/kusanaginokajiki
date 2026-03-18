//! Phase 14C — 18 new MITRE ATT&CK for ICS technique detections.
//!
//! These detections require richer per-session context than the base detections
//! in `attack.rs`. The [`CaptureContext`] struct carries MAC-to-IP mappings,
//! per-device first/last-seen timestamps, write-rate counters, and OT/external
//! IP classification built from `AppStateInner` before calling
//! [`detect_context_attacks`].
//!
//! ## Detected Techniques
//!
//! | Technique | Description | Severity |
//! |-----------|-------------|----------|
//! | T0822 | External Remote Services (RDP/VNC from OT device) | High |
//! | T0867 | Lateral Tool Transfer (FTP/TFTP within OT segment) | High |
//! | T0885 | Commonly Used Port (OT protocol on wrong port) | Medium |
//! | T0849 | Masquerading (non-OT protocol on OT port) | Medium |
//! | T0868 | Detect Operating Mode (S7 upload/download) | High |
//! | T0806 | Brute Force I/O (high write rate to single OT device) | High |
//! | T0802 | Automated Collection (many OT targets polled) | Medium |
//! | T0861 | Point and Tag Identification (wide Modbus unit-ID scan) | Medium |
//! | T0840 | Network Connection Enumeration (OT port sweep) | High |
//! | T0803/T0811 | Block Command / Modify I/O Image (PLC receiving no commands) | Medium |
//! | T0804 | Block Reporting Message (DNP3 outstation not reporting) | Medium |
//! | T0881 | Service Stop (OT device with very low traffic vs peers) | High |
//! | T0864 | Transient Cyber Asset (device seen for < 5 minutes) | Medium |
//! | T0830 | Adversary-in-the-Middle (IP with multiple MACs) | Critical |
//! | T0884 | Connection Proxy (non-OT device relaying OT traffic) | High |
//! | T0866 | Exploitation of Remote Services | High |
//! | T0800 | Activate Firmware Update Mode (CIP File / S7 upload) | Critical |
//! | T0801 | Monitor Process State (reads across many OT endpoints) | Medium |

use std::collections::{HashMap, HashSet};

use crate::{AnalysisInput, Finding, FindingType, Severity};

/// Well-known OT server ports (mirrors the constant in `attack.rs`).
const OT_PORTS: &[u16] = &[
    102, 502, 1089, 1090, 1091, 2222, 2404, 4840, 5007, 5094, 18245, 18246, 20000, 34962, 34963,
    34964, 44818, 47808,
];

/// Remote access / management ports that should not appear on OT segments.
const REMOTE_ACCESS_PORTS: &[u16] = &[
    22,   // SSH
    23,   // Telnet
    3389, // RDP
    5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910, // VNC
    5938, // TeamViewer
    7070, // AnyDesk
];

/// Rich per-capture state used by context-aware ATT&CK detections.
///
/// Built once per analysis run from `AppStateInner` in the commands layer and
/// passed alongside [`AnalysisInput`] to [`detect_context_attacks`].
/// All fields default to empty / zero so the struct can be used in tests without
/// populating every field.
#[derive(Debug, Clone, Default)]
pub struct CaptureContext {
    /// Earliest packet timestamp in this capture (Unix seconds, 0.0 = unknown).
    pub capture_start: f64,
    /// Latest packet timestamp in this capture (Unix seconds, 0.0 = unknown).
    pub capture_end: f64,
    /// IP → list of distinct MAC addresses observed for that IP.
    ///
    /// An IP with ≥ 2 distinct MACs is an AiTM / MAC-spoofing indicator (T0830).
    pub ip_to_macs: HashMap<String, Vec<String>>,
    /// MAC → list of distinct IPs seen using that MAC.
    pub mac_to_ips: HashMap<String, Vec<String>>,
    /// Per-IP: earliest timestamp seen (Unix seconds, 0.0 = unknown).
    pub device_first_seen: HashMap<String, f64>,
    /// Per-IP: latest timestamp seen (Unix seconds, 0.0 = unknown).
    pub device_last_seen: HashMap<String, f64>,
    /// Per-source: set of OT destination IPs queried via read operations.
    pub per_source_read_targets: HashMap<String, HashSet<String>>,
    /// Per-source: set of OT destination IPs targeted by write operations.
    pub per_source_write_targets: HashMap<String, HashSet<String>>,
    /// Per-source: all destination ports contacted.
    pub per_source_dst_ports: HashMap<String, HashSet<u16>>,
    /// Per (src, dst): total write-class packet / command count.
    pub per_connection_write_rate: HashMap<(String, String), u64>,
    /// IPs confirmed as running OT protocols (PLCs, RTUs, HMIs, historians …).
    pub ot_device_ips: HashSet<String>,
    /// IPs that are external / public (non-RFC-1918).
    pub external_ips: HashSet<String>,
}

/// Run all Phase 14C ATT&CK detections.
///
/// Called from [`crate::attack::detect_attack_techniques`] with the same
/// `AnalysisInput` snapshot and a `CaptureContext` built from `AppStateInner`.
pub fn detect_context_attacks(input: &AnalysisInput, ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    findings.extend(detect_t0822_external_remote_services(input, ctx));
    findings.extend(detect_t0867_lateral_tool_transfer(input, ctx));
    findings.extend(detect_t0885_commonly_used_port(input));
    findings.extend(detect_t0849_masquerading(input));
    findings.extend(detect_t0868_detect_operating_mode(input));
    findings.extend(detect_t0806_brute_force_io(input, ctx));
    findings.extend(detect_t0802_automated_collection(input, ctx));
    findings.extend(detect_t0861_point_tag_identification(input));
    findings.extend(detect_t0840_network_connection_enumeration(input, ctx));
    findings.extend(detect_t0803_block_command_reporting(input));
    findings.extend(detect_t0804_block_reporting_message(input));
    findings.extend(detect_t0881_service_stop(input));
    findings.extend(detect_t0864_transient_cyber_asset(input, ctx));
    findings.extend(detect_t0830_adversary_in_the_middle(ctx));
    findings.extend(detect_t0884_connection_proxy(input, ctx));
    findings.extend(detect_t0866_exploitation_remote_services(input, ctx));
    findings.extend(detect_t0800_firmware_update_mode(input));
    findings.extend(detect_t0801_monitor_process_state(input, ctx));

    findings
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` if the device type is an OT field device.
fn is_ot_device_type(device_type: &str) -> bool {
    matches!(
        device_type,
        "plc"
            | "rtu"
            | "hmi"
            | "historian"
            | "engineering_workstation"
            | "scada_server"
            | "io_server"
            | "field_device"
            | "controller"
    )
}

/// Returns the standard port(s) for a known ICS protocol name.
///
/// Returns an empty slice for unknown protocols, which means T0885 will not
/// fire for unrecognised protocol strings.
fn canonical_ot_ports(protocol: &str) -> &'static [u16] {
    match protocol {
        "Modbus" => &[502],
        "Dnp3" => &[20000],
        "EthernetIp" => &[44818, 2222],
        "S7comm" => &[102],
        "Bacnet" => &[47808],
        "OpcUa" => &[4840],
        "Iec104" => &[2404],
        "HartIp" => &[5094],
        "GeSrtp" => &[18245, 18246],
        "WonderwareSuitelink" => &[5007],
        "FfHse" => &[1089, 1090, 1091],
        "ProfinetDcp" => &[34962, 34963, 34964],
        "Mqtt" => &[1883, 8883],
        _ => &[],
    }
}

/// Returns a human-readable name for a remote access port.
fn remote_service_name(port: u16) -> &'static str {
    match port {
        22 => "SSH",
        23 => "Telnet",
        3389 => "RDP",
        5900..=5910 => "VNC",
        5938 => "TeamViewer",
        7070 => "AnyDesk",
        _ => "remote access",
    }
}

/// Returns `true` if the protocol name is a known OT/ICS protocol.
fn is_ot_protocol_name(protocol: &str) -> bool {
    matches!(
        protocol,
        "Modbus"
            | "Dnp3"
            | "EthernetIp"
            | "S7comm"
            | "Bacnet"
            | "OpcUa"
            | "Iec104"
            | "ProfinetDcp"
            | "HartIp"
            | "GeSrtp"
            | "WonderwareSuitelink"
            | "FfHse"
            | "Mqtt"
            | "Snmp"
    )
}

/// Build the effective OT IP set: prefer `ctx.ot_device_ips` when non-empty,
/// otherwise derive from asset classification.
fn effective_ot_ips<'a>(input: &'a AnalysisInput, ctx: &'a CaptureContext) -> HashSet<&'a str> {
    if !ctx.ot_device_ips.is_empty() {
        ctx.ot_device_ips.iter().map(String::as_str).collect()
    } else {
        input
            .assets
            .iter()
            .filter(|a| is_ot_device_type(&a.device_type))
            .map(|a| a.ip_address.as_str())
            .collect()
    }
}

// ── Group 1: simple port / protocol checks ───────────────────────────────────

/// T0822 — External Remote Services
///
/// Detects when an OT device **initiates** connections to remote access ports
/// (RDP, VNC, TeamViewer, AnyDesk, SSH, Telnet). Legitimate OT field devices
/// should never originate remote administration sessions.
fn detect_t0822_external_remote_services(
    input: &AnalysisInput,
    ctx: &CaptureContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ot_ips = effective_ot_ips(input, ctx);
    let mut flagged: HashSet<(&str, &str, u16)> = HashSet::new();

    for conn in &input.connections {
        if !REMOTE_ACCESS_PORTS.contains(&conn.dst_port) {
            continue;
        }
        if !ot_ips.contains(conn.src_ip.as_str()) {
            continue;
        }
        let key = (conn.src_ip.as_str(), conn.dst_ip.as_str(), conn.dst_port);
        if flagged.insert(key) {
            let service = remote_service_name(conn.dst_port);
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!(
                    "OT device {} accessing {} (port {})",
                    conn.src_ip, service, conn.dst_port
                ),
                "An OT device is initiating connections to remote access services. \
                 Legitimate OT controllers do not originate remote desktop or shell \
                 sessions — this may indicate a compromised device being used as a \
                 pivot point into external systems."
                    .to_string(),
                vec![conn.src_ip.clone(), conn.dst_ip.clone()],
                format!(
                    "OT device {} → {} on {} (port {}), {} packets",
                    conn.src_ip, conn.dst_ip, service, conn.dst_port, conn.packet_count
                ),
                Some("T0822".to_string()),
            ));
        }
    }

    findings
}

/// T0867 — Lateral Tool Transfer
///
/// Detects FTP (port 21) or TFTP (port 69) traffic involving at least one
/// OT device. File transfers within or to/from OT segments may indicate
/// firmware uploads, tool staging, or configuration exfiltration.
fn detect_t0867_lateral_tool_transfer(input: &AnalysisInput, ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ot_ips = effective_ot_ips(input, ctx);
    let mut flagged: HashSet<(&str, &str)> = HashSet::new();

    for conn in &input.connections {
        if conn.dst_port != 21 && conn.dst_port != 69 {
            continue;
        }
        let src_is_ot = ot_ips.contains(conn.src_ip.as_str());
        let dst_is_ot = ot_ips.contains(conn.dst_ip.as_str());
        if !src_is_ot && !dst_is_ot {
            continue;
        }
        let key = (conn.src_ip.as_str(), conn.dst_ip.as_str());
        if flagged.insert(key) {
            let proto_name = if conn.dst_port == 21 { "FTP" } else { "TFTP" };
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!(
                    "{} file transfer involving OT device: {} → {}",
                    proto_name, conn.src_ip, conn.dst_ip
                ),
                format!(
                    "{} (port {}) traffic involving an OT device was detected. File \
                     transfers within or to/from OT segments may represent firmware \
                     uploads, malicious tool staging, or configuration data exfiltration.",
                    proto_name, conn.dst_port
                ),
                vec![conn.src_ip.clone(), conn.dst_ip.clone()],
                format!(
                    "{} from {} to {} (port {}), {} packets",
                    proto_name, conn.src_ip, conn.dst_ip, conn.dst_port, conn.packet_count
                ),
                Some("T0867".to_string()),
            ));
        }
    }

    findings
}

/// T0885 — Commonly Used Port
///
/// Detects an OT/ICS protocol running on a port that is not its canonical
/// port. An adversary may configure non-standard ports to evade firewall
/// rules that are written for standard OT port numbers.
fn detect_t0885_commonly_used_port(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut flagged: HashSet<(&str, &str, u16)> = HashSet::new();

    for conn in &input.connections {
        let canonical = canonical_ot_ports(&conn.protocol);
        if canonical.is_empty() {
            continue; // unknown or non-OT protocol
        }
        // Traffic on both src and dst are not the canonical port
        if canonical.contains(&conn.dst_port) || canonical.contains(&conn.src_port) {
            continue;
        }
        let key = (conn.src_ip.as_str(), conn.protocol.as_str(), conn.dst_port);
        if flagged.insert(key) {
            let canonical_str: Vec<String> = canonical.iter().map(|p| p.to_string()).collect();
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Medium,
                format!(
                    "{} on non-standard port {} ({} → {})",
                    conn.protocol, conn.dst_port, conn.src_ip, conn.dst_ip
                ),
                format!(
                    "{} was identified on port {}, which is not its standard port. \
                     Non-standard port usage may indicate deliberate port remapping to \
                     evade protocol-specific firewall rules.",
                    conn.protocol, conn.dst_port
                ),
                vec![conn.src_ip.clone(), conn.dst_ip.clone()],
                format!(
                    "{} on port {} (standard: {}), {} packets",
                    conn.protocol,
                    conn.dst_port,
                    canonical_str.join("/"),
                    conn.packet_count
                ),
                Some("T0885".to_string()),
            ));
        }
    }

    findings
}

/// T0849 — Masquerading
///
/// Detects clearly non-OT protocols (HTTP, SSH, etc.) on canonical OT ports.
/// An adversary may route C2 traffic over port 502 or 44818 to blend with
/// expected Modbus / EtherNet-IP traffic and bypass protocol-aware firewalls.
fn detect_t0849_masquerading(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Map canonical OT port → expected protocol name.
    let ot_port_expected: &[(u16, &str)] = &[
        (502, "Modbus"),
        (20000, "Dnp3"),
        (44818, "EthernetIp"),
        (102, "S7comm"),
        (47808, "Bacnet"),
        (4840, "OpcUa"),
        (2404, "Iec104"),
        (5094, "HartIp"),
        (18245, "GeSrtp"),
        (18246, "GeSrtp"),
        (5007, "WonderwareSuitelink"),
    ];

    // Protocols that are clearly NOT OT (and would constitute masquerading).
    let non_ot: &[&str] = &["Http", "Https", "Ssh", "Ftp", "Tftp", "Smtp", "Telnet"];

    let mut flagged: HashSet<(&str, &str, u16)> = HashSet::new();

    for conn in &input.connections {
        let proto = conn.protocol.as_str();
        if !non_ot.contains(&proto) {
            continue;
        }
        // Check if dst_port is a canonical OT port
        if let Some(&(_, expected)) = ot_port_expected.iter().find(|(p, _)| *p == conn.dst_port) {
            let key = (conn.src_ip.as_str(), proto, conn.dst_port);
            if flagged.insert(key) {
                findings.push(Finding::new(
                    FindingType::AttackTechnique,
                    Severity::Medium,
                    format!(
                        "{} traffic masquerading on OT port {} ({} → {})",
                        proto, conn.dst_port, conn.src_ip, conn.dst_ip
                    ),
                    format!(
                        "Non-OT protocol '{}' was observed on port {}, normally reserved \
                         for {}. This may indicate C2 traffic disguised as OT protocol \
                         traffic to bypass port-based firewall rules.",
                        proto, conn.dst_port, expected
                    ),
                    vec![conn.src_ip.clone(), conn.dst_ip.clone()],
                    format!(
                        "{}→{}:{} uses '{}', expected '{}'",
                        conn.src_ip, conn.dst_ip, conn.dst_port, proto, expected
                    ),
                    Some("T0849".to_string()),
                ));
            }
        }
    }

    findings
}

/// T0868 — Detect Operating Mode
///
/// Detects S7comm Upload or Download functions. These operations read or
/// write PLC program blocks, which reveals the control program structure
/// and the operating mode — a precursor to targeted process manipulation.
fn detect_t0868_detect_operating_mode(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let s7 = match &dp.s7 {
            Some(s) => s,
            None => continue,
        };

        let upload_download: Vec<&str> = s7
            .functions_seen
            .iter()
            .filter(|f| {
                matches!(
                    f.as_str(),
                    "upload" | "download" | "start_upload" | "end_upload"
                )
            })
            .map(String::as_str)
            .collect();

        if upload_download.is_empty() {
            continue;
        }

        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::High,
            format!("S7 program upload/download from {}", ip),
            "S7comm Upload or Download functions were observed. These operations \
             read or write PLC program blocks, enabling an adversary to map the \
             control logic and identify targets for process manipulation."
                .to_string(),
            vec![ip.clone()],
            format!(
                "Device {} used S7 functions: {}",
                ip,
                upload_download.join(", ")
            ),
            Some("T0868".to_string()),
        ));
    }

    findings
}

// ── Group 2: rate / pattern-based ────────────────────────────────────────────

/// T0806 — Brute Force I/O
///
/// Detects a high write rate from a single source to an OT device.
/// Rapid forced writes can overwhelm controller scan cycles and cause
/// process disruption or equipment damage.
///
/// Uses `ctx.per_connection_write_rate` when populated; falls back to
/// Modbus deep-parse write FC totals when context is sparse.
fn detect_t0806_brute_force_io(input: &AnalysisInput, ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    const WRITE_THRESHOLD: u64 = 500;

    // Context path: use pre-computed write counts per (src, dst).
    let mut ctx_reported: HashSet<(&str, &str)> = HashSet::new();
    for ((src, dst), &count) in &ctx.per_connection_write_rate {
        if count >= WRITE_THRESHOLD {
            ctx_reported.insert((src.as_str(), dst.as_str()));
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("High-rate I/O writes from {} to {}", src, dst),
                "A single source is sending a very high number of write commands to an \
                 OT device. Rapid forced writes can overwhelm the controller scan cycle \
                 and cause process disruption or equipment damage."
                    .to_string(),
                vec![src.clone(), dst.clone()],
                format!("{} sent {} write-class commands to {}", src, count, dst),
                Some("T0806".to_string()),
            ));
        }
    }

    // Fallback: Modbus write FC totals targeting a single slave.
    for (ip, dp) in &input.deep_parse {
        let modbus = match &dp.modbus {
            Some(m) => m,
            None => continue,
        };
        if modbus.role != "master" && modbus.role != "both" {
            continue;
        }
        let write_total: u64 = modbus
            .function_codes
            .iter()
            .filter(|fc| matches!(fc.code, 5 | 6 | 15 | 16))
            .map(|fc| fc.count)
            .sum();
        if write_total < WRITE_THRESHOLD {
            continue;
        }
        let slaves: Vec<&str> = modbus
            .relationships
            .iter()
            .filter(|r| r.remote_role == "slave")
            .map(|r| r.remote_ip.as_str())
            .collect();
        if slaves.len() != 1 {
            continue; // only flag single-target saturation here
        }
        let slave = slaves[0];
        if ctx_reported.contains(&(ip.as_str(), slave)) {
            continue; // already reported via context
        }
        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::High,
            format!("Modbus brute force I/O from {} to {}", ip, slave),
            "Extremely high Modbus write rate detected targeting a single slave. \
             This may represent forced setpoint manipulation or coil-flooding."
                .to_string(),
            vec![ip.clone(), slave.to_string()],
            format!(
                "{} sent {} Modbus write commands (FC 5/6/15/16) to {}",
                ip, write_total, slave
            ),
            Some("T0806".to_string()),
        ));
    }

    findings
}

/// T0802 — Automated Collection
///
/// Detects a single source reading process data from many OT devices.
/// Automated polling of many controllers is characteristic of adversarial
/// data harvesting in preparation for targeted disruption.
fn detect_t0802_automated_collection(input: &AnalysisInput, ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    const THRESHOLD: usize = 10;

    // Context path.
    for (src, targets) in &ctx.per_source_read_targets {
        if targets.len() >= THRESHOLD {
            let sample: Vec<String> = targets.iter().take(5).cloned().collect();
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::Medium,
                format!(
                    "Automated collection: {} polling {} OT devices",
                    src,
                    targets.len()
                ),
                "A single source is reading data from many OT devices. This pattern \
                 resembles automated collection — systematically harvesting process \
                 state from controllers across the network."
                    .to_string(),
                std::iter::once(src.clone())
                    .chain(targets.iter().cloned())
                    .collect(),
                format!(
                    "{} sent read requests to {} OT targets (sample: {})",
                    src,
                    targets.len(),
                    sample.join(", ")
                ),
                Some("T0802".to_string()),
            ));
        }
    }

    // Fallback: count unique OT hosts reached per source from connection list.
    if ctx.per_source_read_targets.is_empty() {
        let ot_ips = effective_ot_ips(input, ctx);
        let mut src_to_ot: HashMap<&str, HashSet<&str>> = HashMap::new();
        for conn in &input.connections {
            if OT_PORTS.contains(&conn.dst_port) && ot_ips.contains(conn.dst_ip.as_str()) {
                src_to_ot
                    .entry(conn.src_ip.as_str())
                    .or_default()
                    .insert(conn.dst_ip.as_str());
            }
        }
        for (src, targets) in src_to_ot {
            if targets.len() >= THRESHOLD {
                let target_list: Vec<String> = targets.iter().map(|s| s.to_string()).collect();
                findings.push(Finding::new(
                    FindingType::AttackTechnique,
                    Severity::Medium,
                    format!(
                        "Automated collection: {} connecting to {} OT devices",
                        src,
                        targets.len()
                    ),
                    "A single source is connecting to many OT devices on ICS protocol \
                     ports. This pattern resembles automated collection of process state."
                        .to_string(),
                    std::iter::once(src.to_string())
                        .chain(target_list.iter().cloned())
                        .collect(),
                    format!(
                        "{} connected to {} OT targets on ICS ports",
                        src,
                        targets.len()
                    ),
                    Some("T0802".to_string()),
                ));
            }
        }
    }

    findings
}

/// T0861 — Point and Tag Identification
///
/// Detects Modbus read function codes (FC 1/2/3/4) sent to many distinct unit
/// IDs from a single device. Scanning across unit IDs enumerates all slaves on
/// the RS-485 bus and maps their data point layout.
fn detect_t0861_point_tag_identification(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();
    const UNIT_ID_THRESHOLD: usize = 5;

    for (ip, dp) in &input.deep_parse {
        let modbus = match &dp.modbus {
            Some(m) => m,
            None => continue,
        };
        if modbus.role != "master" && modbus.role != "both" {
            continue;
        }
        let has_reads = modbus
            .function_codes
            .iter()
            .any(|fc| matches!(fc.code, 1..=4) && fc.count > 0);
        if !has_reads || modbus.unit_ids.len() < UNIT_ID_THRESHOLD {
            continue;
        }
        let uid_str: Vec<String> = modbus.unit_ids.iter().map(|u| u.to_string()).collect();
        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::Medium,
            format!(
                "Modbus point/tag scan from {} ({} unit IDs)",
                ip,
                modbus.unit_ids.len()
            ),
            "A Modbus master is reading from many distinct unit IDs. Enumerating unit \
             IDs discovers all slave devices on the RS-485 bus and identifies their \
             data point layout — a precursor to targeted process manipulation."
                .to_string(),
            vec![ip.clone()],
            format!(
                "{} read from {} unit IDs: {}",
                ip,
                modbus.unit_ids.len(),
                uid_str.join(", ")
            ),
            Some("T0861".to_string()),
        ));
    }

    findings
}

/// T0840 — Network Connection Enumeration
///
/// Detects a single source connecting to many different OT hosts or OT
/// service ports. Port-sweeping across OT devices is characteristic of
/// automated host discovery.
fn detect_t0840_network_connection_enumeration(
    input: &AnalysisInput,
    ctx: &CaptureContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    const HOST_THRESHOLD: usize = 10;

    // Context path: count unique OT dst ports per source.
    for (src, ports) in &ctx.per_source_dst_ports {
        let ot_port_count = ports.iter().filter(|&&p| OT_PORTS.contains(&p)).count();
        if ot_port_count >= HOST_THRESHOLD {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!("OT port sweep by {} ({} OT ports)", src, ot_port_count),
                "A single source is connecting to many different OT service ports. \
                 This is characteristic of automated network enumeration mapping the \
                 ICS network topology."
                    .to_string(),
                vec![src.clone()],
                format!(
                    "{} contacted {} distinct OT service ports",
                    src, ot_port_count
                ),
                Some("T0840".to_string()),
            ));
        }
    }

    // Fallback: count unique OT hosts per source from connection list.
    if ctx.per_source_dst_ports.is_empty() {
        let mut src_to_hosts: HashMap<&str, HashSet<&str>> = HashMap::new();
        for conn in &input.connections {
            if OT_PORTS.contains(&conn.dst_port) {
                src_to_hosts
                    .entry(conn.src_ip.as_str())
                    .or_default()
                    .insert(conn.dst_ip.as_str());
            }
        }
        for (src, hosts) in src_to_hosts {
            if hosts.len() >= HOST_THRESHOLD {
                findings.push(Finding::new(
                    FindingType::AttackTechnique,
                    Severity::High,
                    format!("OT host sweep by {} ({} hosts)", src, hosts.len()),
                    "A single source is connecting to many OT devices on ICS ports. \
                     This is characteristic of automated host enumeration."
                        .to_string(),
                    std::iter::once(src.to_string())
                        .chain(hosts.iter().map(|s| s.to_string()))
                        .collect(),
                    format!(
                        "{} connected to {} distinct OT hosts on ICS ports",
                        src,
                        hosts.len()
                    ),
                    Some("T0840".to_string()),
                ));
            }
        }
    }

    findings
}

/// T0803 / T0811 — Block Command Message / Modify I/O Image
///
/// Detects PLC/RTU devices that have network activity but receive **zero**
/// incoming commands on OT ports from any controller. This may indicate
/// that legitimate command traffic is being dropped or intercepted.
fn detect_t0803_block_command_reporting(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    let field_device_ips: HashSet<&str> = input
        .assets
        .iter()
        .filter(|a| matches!(a.device_type.as_str(), "plc" | "rtu" | "field_device"))
        .map(|a| a.ip_address.as_str())
        .collect();

    if field_device_ips.is_empty() {
        return findings;
    }

    // Require that some OT controller traffic exists at all.
    let has_ot_controllers = input
        .connections
        .iter()
        .any(|c| OT_PORTS.contains(&c.dst_port));
    if !has_ot_controllers {
        return findings;
    }

    // Build set of field devices that received at least one incoming OT command.
    let mut receiving_commands: HashSet<&str> = HashSet::new();
    for conn in &input.connections {
        if OT_PORTS.contains(&conn.dst_port) && field_device_ips.contains(conn.dst_ip.as_str()) {
            receiving_commands.insert(conn.dst_ip.as_str());
        }
    }

    // Build set of field devices that have any network traffic at all.
    let mut has_any_traffic: HashSet<&str> = HashSet::new();
    for conn in &input.connections {
        if field_device_ips.contains(conn.src_ip.as_str()) {
            has_any_traffic.insert(conn.src_ip.as_str());
        }
        if field_device_ips.contains(conn.dst_ip.as_str()) {
            has_any_traffic.insert(conn.dst_ip.as_str());
        }
    }

    for ip in &field_device_ips {
        if receiving_commands.contains(ip) || !has_any_traffic.contains(ip) {
            continue;
        }
        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::Medium,
            format!("PLC/RTU {} receiving no OT commands", ip),
            "A PLC or RTU is present on the network but is not receiving any commands \
             on OT protocol ports from any controller. This may indicate that legitimate \
             command traffic is being blocked, filtered, or intercepted."
                .to_string(),
            vec![ip.to_string()],
            format!(
                "Field device {} has network traffic but received no OT-port commands",
                ip
            ),
            Some("T0803".to_string()),
        ));
    }

    findings
}

/// T0804 — Block Reporting Message
///
/// Detects DNP3 outstations that have a known master relationship but are
/// sending no outgoing data. Blocked reporting prevents the control system
/// from receiving process state updates from field devices.
fn detect_t0804_block_reporting_message(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, dp) in &input.deep_parse {
        let dnp3 = match &dp.dnp3 {
            Some(d) => d,
            None => continue,
        };
        if dnp3.role != "outstation" {
            continue;
        }
        // Outstation has a master relationship with some traffic.
        let has_master = dnp3
            .relationships
            .iter()
            .any(|r| r.remote_role == "master" && r.packet_count > 0);
        if !has_master {
            continue;
        }
        // Outstation sends no outgoing OT traffic.
        let outstation_sends = input
            .connections
            .iter()
            .any(|c| c.src_ip == *ip && OT_PORTS.contains(&c.dst_port));
        if outstation_sends {
            continue;
        }
        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::Medium,
            format!("DNP3 outstation {} not reporting to master", ip),
            "A DNP3 outstation has a master relationship but is sending no outgoing \
             data on OT ports. Blocked reporting prevents the control system from \
             receiving process state updates from this field device."
                .to_string(),
            vec![ip.clone()],
            format!(
                "DNP3 outstation {} has master relationship but sends no OT-port traffic",
                ip
            ),
            Some("T0804".to_string()),
        ));
    }

    findings
}

/// T0881 — Service Stop
///
/// Detects OT devices that have active protocol classifications but receive
/// far fewer packets than the average OT device. This may indicate that a
/// process service was forced offline or is no longer responding.
fn detect_t0881_service_stop(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    // Count incoming packets per OT device.
    let mut device_incoming: HashMap<&str, u64> = HashMap::new();
    for conn in &input.connections {
        if OT_PORTS.contains(&conn.dst_port) {
            *device_incoming.entry(conn.dst_ip.as_str()).or_insert(0) += conn.packet_count;
        }
    }

    let device_count = device_incoming.len() as u64;
    if device_count == 0 {
        return findings;
    }
    let total_incoming: u64 = device_incoming.values().sum();
    let avg = total_incoming / device_count;
    if avg < 10 {
        return findings; // too little traffic to make the comparison meaningful
    }

    // Threshold: flag devices receiving < 5% of the average.
    let threshold = (avg / 20).max(1);

    let ot_asset_ips: HashSet<&str> = input
        .assets
        .iter()
        .filter(|a| a.protocols.iter().any(|p| is_ot_protocol_name(p)))
        .map(|a| a.ip_address.as_str())
        .collect();

    for ip in &ot_asset_ips {
        let incoming = device_incoming.get(ip).copied().unwrap_or(0);
        if incoming <= threshold {
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!(
                    "Possible service stop on OT device {} (very low traffic)",
                    ip
                ),
                "An OT device has active protocol classifications but is receiving \
                 significantly fewer packets than peer OT devices. This may indicate \
                 that a process service has been forced offline or stopped responding."
                    .to_string(),
                vec![ip.to_string()],
                format!(
                    "Device {} received {} OT-port packets vs average {} across OT devices",
                    ip, incoming, avg
                ),
                Some("T0881".to_string()),
            ));
        }
    }

    findings
}

// ── Group 3: state-tracking / CaptureContext ─────────────────────────────────

/// T0864 — Transient Cyber Asset
///
/// Detects non-OT devices that appear on the OT segment for less than five
/// minutes and communicate with OT devices. Short-lived devices (laptops,
/// USB adapters, maintenance tools) introduce uncontrolled access vectors.
fn detect_t0864_transient_cyber_asset(input: &AnalysisInput, ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    if ctx.device_first_seen.is_empty() {
        return findings; // no timing data
    }

    const TRANSIENT_SECS: f64 = 300.0; // 5 minutes

    let known_ot: HashSet<&str> = ctx.ot_device_ips.iter().map(String::as_str).collect();

    for (ip, &first) in &ctx.device_first_seen {
        if known_ot.contains(ip.as_str()) {
            continue; // expected OT device
        }
        let last = ctx.device_last_seen.get(ip).copied().unwrap_or(first);
        let duration = last - first;
        if duration <= 0.0 || duration >= TRANSIENT_SECS {
            continue;
        }
        // Only flag if it communicated with an OT device.
        let reached_ot = input.connections.iter().any(|c| {
            (c.src_ip == *ip && ctx.ot_device_ips.contains(&c.dst_ip))
                || (c.dst_ip == *ip && ctx.ot_device_ips.contains(&c.src_ip))
        });
        if !reached_ot {
            continue;
        }
        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::Medium,
            format!(
                "Transient device {} seen for only {:.0}s on OT segment",
                ip, duration
            ),
            "A non-OT device appeared briefly on the OT network and communicated with \
             OT devices. Short-lived devices such as maintenance laptops or USB adapters \
             represent uncontrolled access vectors that may introduce malware or \
             exfiltrate configuration data."
                .to_string(),
            vec![ip.clone()],
            format!(
                "Device {} seen for {:.0}s ({:.1} min), communicated with OT devices",
                ip,
                duration,
                duration / 60.0
            ),
            Some("T0864".to_string()),
        ));
    }

    findings
}

/// T0830 — Adversary-in-the-Middle
///
/// Detects IP addresses associated with multiple distinct MAC addresses.
/// This may indicate ARP cache poisoning, MAC spoofing, or an adversary
/// positioned between legitimate OT communication partners.
fn detect_t0830_adversary_in_the_middle(ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (ip, macs) in &ctx.ip_to_macs {
        let unique: HashSet<String> = macs.iter().map(|m| m.to_lowercase()).collect();
        if unique.len() < 2 {
            continue;
        }
        let mac_list: Vec<String> = unique.into_iter().collect();
        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::Critical,
            format!(
                "IP {} seen with {} distinct MACs (AiTM indicator)",
                ip,
                mac_list.len()
            ),
            "A single IP address has been observed with multiple different MAC addresses. \
             This may indicate ARP cache poisoning, MAC spoofing, or an adversary \
             positioning themselves between legitimate OT communication partners."
                .to_string(),
            vec![ip.clone()],
            format!("IP {} associated with MACs: {}", ip, mac_list.join(", ")),
            Some("T0830".to_string()),
        ));
    }

    findings
}

/// T0884 — Connection Proxy
///
/// Detects a non-OT device that acts as both client and server on the same
/// OT protocol port — a topology characteristic of a connection proxy
/// injected into an OT communication path.
fn detect_t0884_connection_proxy(input: &AnalysisInput, ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ot_ips = effective_ot_ips(input, ctx);

    // For each IP: OT dst ports it connects to (client role).
    let mut client_ports: HashMap<&str, HashSet<u16>> = HashMap::new();
    // For each IP: OT dst ports it receives connections on (server role).
    let mut server_ports: HashMap<&str, HashSet<u16>> = HashMap::new();

    for conn in &input.connections {
        if OT_PORTS.contains(&conn.dst_port) {
            client_ports
                .entry(conn.src_ip.as_str())
                .or_default()
                .insert(conn.dst_port);
            server_ports
                .entry(conn.dst_ip.as_str())
                .or_default()
                .insert(conn.dst_port);
        }
    }

    let mut flagged: HashSet<&str> = HashSet::new();
    for (ip, srv) in &server_ports {
        if ot_ips.contains(ip) || flagged.contains(ip) {
            continue; // legitimate OT server role
        }
        if let Some(cli) = client_ports.get(ip) {
            let shared: Vec<u16> = srv.intersection(cli).copied().collect();
            if !shared.is_empty() {
                flagged.insert(ip);
                let port_list: Vec<String> = shared.iter().map(|p| p.to_string()).collect();
                findings.push(Finding::new(
                    FindingType::AttackTechnique,
                    Severity::High,
                    format!("Possible OT traffic proxy at {}", ip),
                    "A non-OT device is acting as both client and server on the same OT \
                     protocol ports. This topology is characteristic of a connection proxy \
                     or man-in-the-middle device injected into an OT communication path."
                        .to_string(),
                    vec![ip.to_string()],
                    format!(
                        "{} both receives and originates OT connections on port(s): {}",
                        ip,
                        port_list.join(", ")
                    ),
                    Some("T0884".to_string()),
                ));
            }
        }
    }

    findings
}

/// T0866 — Exploitation of Remote Services
///
/// Detects connections from external or non-OT hosts to OT field devices on
/// remote management ports (SSH, Telnet, HTTP, HTTPS, RDP). This may indicate
/// exploitation of internet-exposed management services on OT devices.
fn detect_t0866_exploitation_remote_services(
    input: &AnalysisInput,
    ctx: &CaptureContext,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    const MGMT_PORTS: &[u16] = &[22, 23, 80, 443, 3389];

    let ot_ips = effective_ot_ips(input, ctx);
    let mut flagged: HashSet<(&str, &str, u16)> = HashSet::new();

    for conn in &input.connections {
        if !MGMT_PORTS.contains(&conn.dst_port) {
            continue;
        }
        if !ot_ips.contains(conn.dst_ip.as_str()) {
            continue;
        }
        let src_is_external = ctx.external_ips.contains(&conn.src_ip);
        let src_is_ot = ot_ips.contains(conn.src_ip.as_str());
        // Skip OT-to-OT management (legitimate engineering workstation access).
        if src_is_ot && !src_is_external {
            continue;
        }
        let key = (conn.src_ip.as_str(), conn.dst_ip.as_str(), conn.dst_port);
        if flagged.insert(key) {
            let service = remote_service_name(conn.dst_port);
            let src_label = if src_is_external {
                "External"
            } else {
                "Non-OT"
            };
            findings.push(Finding::new(
                FindingType::AttackTechnique,
                Severity::High,
                format!(
                    "{} host {} connecting to OT device {} via {} (port {})",
                    src_label, conn.src_ip, conn.dst_ip, service, conn.dst_port
                ),
                "A non-OT or external host is connecting to an OT field device on a \
                 remote management port. This may represent exploitation of an exposed \
                 service or unauthorised remote access to a controller."
                    .to_string(),
                vec![conn.src_ip.clone(), conn.dst_ip.clone()],
                format!(
                    "{} {} → OT device {} on {} (port {}), {} packets",
                    src_label, conn.src_ip, conn.dst_ip, service, conn.dst_port, conn.packet_count
                ),
                Some("T0866".to_string()),
            ));
        }
    }

    findings
}

/// T0800 — Activate Firmware Update Mode
///
/// Detects CIP File class access (EtherNet/IP) or S7comm Upload/Download
/// functions targeting known PLC or RTU devices. These operations can activate
/// firmware update mode, enabling malicious firmware upload.
fn detect_t0800_firmware_update_mode(input: &AnalysisInput) -> Vec<Finding> {
    let mut findings = Vec::new();

    let plc_rtu_ips: HashSet<&str> = input
        .assets
        .iter()
        .filter(|a| matches!(a.device_type.as_str(), "plc" | "rtu" | "field_device"))
        .map(|a| a.ip_address.as_str())
        .collect();

    if plc_rtu_ips.is_empty() {
        return findings;
    }

    for (ip, dp) in &input.deep_parse {
        // EtherNet/IP: CIP File class access from a scanner targeting known PLCs.
        if let Some(enip) = &dp.enip {
            if enip.cip_file_access && enip.role == "scanner" {
                let targets: Vec<String> = input
                    .connections
                    .iter()
                    .filter(|c| c.src_ip == *ip && plc_rtu_ips.contains(c.dst_ip.as_str()))
                    .map(|c| c.dst_ip.clone())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                if !targets.is_empty() {
                    findings.push(Finding::new(
                        FindingType::AttackTechnique,
                        Severity::Critical,
                        format!("CIP File Access from {} targeting PLC(s)", ip),
                        "CIP File class access (EtherNet/IP) was observed targeting PLC or \
                         RTU devices. CIP File operations can read/write firmware image files \
                         and activate firmware update mode, enabling malicious firmware upload."
                            .to_string(),
                        std::iter::once(ip.clone())
                            .chain(targets.iter().cloned())
                            .collect(),
                        format!(
                            "{} used CIP File Access targeting: {}",
                            ip,
                            targets.join(", ")
                        ),
                        Some("T0800".to_string()),
                    ));
                }
            }
        }

        // S7comm: Upload/Download from a client targeting known PLCs.
        if let Some(s7) = &dp.s7 {
            let has_up_down = s7.functions_seen.iter().any(|f| {
                matches!(
                    f.as_str(),
                    "upload" | "download" | "start_upload" | "end_upload"
                )
            });
            if has_up_down && s7.role == "client" {
                let targets: Vec<String> = input
                    .connections
                    .iter()
                    .filter(|c| c.src_ip == *ip && plc_rtu_ips.contains(c.dst_ip.as_str()))
                    .map(|c| c.dst_ip.clone())
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect();
                if !targets.is_empty() {
                    findings.push(Finding::new(
                        FindingType::AttackTechnique,
                        Severity::Critical,
                        format!("S7 program upload/download from {} targeting PLC(s)", ip),
                        "S7comm Upload or Download functions were directed at known PLC devices. \
                         These operations can read or activate firmware update mode on Siemens \
                         controllers, enabling malicious control logic upload."
                            .to_string(),
                        std::iter::once(ip.clone())
                            .chain(targets.iter().cloned())
                            .collect(),
                        format!(
                            "{} used S7 upload/download targeting PLC(s): {}",
                            ip,
                            targets.join(", ")
                        ),
                        Some("T0800".to_string()),
                    ));
                }
            }
        }
    }

    findings
}

/// T0801 — Monitor Process State
///
/// Detects a single device issuing read operations to many OT service
/// endpoints. Comprehensive process state monitoring across controllers is
/// characteristic of adversarial surveillance in preparation for disruption.
fn detect_t0801_monitor_process_state(input: &AnalysisInput, ctx: &CaptureContext) -> Vec<Finding> {
    let mut findings = Vec::new();
    const THRESHOLD: usize = 20;

    // Count unique OT (host, port) pairs per source.
    let mut src_to_endpoints: HashMap<&str, HashSet<(&str, u16)>> = HashMap::new();
    for conn in &input.connections {
        if OT_PORTS.contains(&conn.dst_port) {
            src_to_endpoints
                .entry(conn.src_ip.as_str())
                .or_default()
                .insert((conn.dst_ip.as_str(), conn.dst_port));
        }
    }

    for (src, endpoints) in src_to_endpoints {
        if endpoints.len() < THRESHOLD {
            continue;
        }
        // Skip write-dominant sources — T0806/T0855 is more appropriate for those.
        let write_dominant = ctx
            .per_source_write_targets
            .get(src)
            .map(|wt| wt.len() >= endpoints.len() / 2)
            .unwrap_or(false);
        if write_dominant {
            continue;
        }
        let sample: Vec<String> = endpoints
            .iter()
            .take(5)
            .map(|(h, p)| format!("{}:{}", h, p))
            .collect();
        findings.push(Finding::new(
            FindingType::AttackTechnique,
            Severity::Medium,
            format!(
                "Wide process state monitoring by {} ({} OT endpoints)",
                src,
                endpoints.len()
            ),
            "A single device is issuing read/poll requests to many OT service endpoints. \
             Comprehensive process state monitoring across controllers may indicate \
             adversarial surveillance of industrial processes in preparation for \
             targeted disruption."
                .to_string(),
            vec![src.to_string()],
            format!(
                "{} polled {} unique OT endpoints (sample: {})",
                src,
                endpoints.len(),
                sample.join(", ")
            ),
            Some("T0801".to_string()),
        ));
    }

    findings
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AnalysisInput, AssetSnapshot, ConnectionSnapshot, DeepParseSnapshot, Dnp3Snapshot,
        EnipSnapshot, FcSnapshot, ModbusSnapshot, RelationshipSnapshot, S7Snapshot,
    };

    fn asset(ip: &str, device_type: &str, protocols: &[&str]) -> AssetSnapshot {
        AssetSnapshot {
            ip_address: ip.to_string(),
            device_type: device_type.to_string(),
            protocols: protocols.iter().map(|s| s.to_string()).collect(),
            purdue_level: None,
            is_public_ip: false,
            tags: vec![],
            vendor: None,
            hostname: None,
            product_family: None,
        }
    }

    fn conn(
        src: &str,
        dst: &str,
        dst_port: u16,
        protocol: &str,
        packets: u64,
    ) -> ConnectionSnapshot {
        ConnectionSnapshot {
            src_ip: src.to_string(),
            dst_ip: dst.to_string(),
            src_port: 49152,
            dst_port,
            protocol: protocol.to_string(),
            packet_count: packets,
        }
    }

    // ── T0822 ──
    #[test]
    fn test_t0822_ot_device_initiates_rdp() {
        let mut input = AnalysisInput::default();
        input.assets = vec![asset("10.0.0.1", "plc", &["Modbus"])];
        input.connections = vec![conn("10.0.0.1", "1.2.3.4", 3389, "Unknown", 5)];
        let ctx = CaptureContext::default();
        let findings = detect_t0822_external_remote_services(&input, &ctx);
        assert!(!findings.is_empty(), "RDP from OT PLC should be flagged");
        assert_eq!(findings[0].technique_id, Some("T0822".to_string()));
    }

    #[test]
    fn test_t0822_it_device_rdp_not_flagged() {
        let mut input = AnalysisInput::default();
        input.assets = vec![asset("10.0.0.200", "it_device", &[])];
        input.connections = vec![conn("10.0.0.200", "1.2.3.4", 3389, "Unknown", 5)];
        let ctx = CaptureContext::default();
        let findings = detect_t0822_external_remote_services(&input, &ctx);
        assert!(
            findings.is_empty(),
            "RDP from IT device should not be flagged by T0822"
        );
    }

    // ── T0867 ──
    #[test]
    fn test_t0867_ftp_between_ot_devices() {
        let mut input = AnalysisInput::default();
        input.assets = vec![
            asset("10.0.0.1", "plc", &["Modbus"]),
            asset("10.0.0.2", "engineering_workstation", &["Modbus"]),
        ];
        input.connections = vec![conn("10.0.0.2", "10.0.0.1", 21, "Ftp", 20)];
        let ctx = CaptureContext::default();
        let findings = detect_t0867_lateral_tool_transfer(&input, &ctx);
        assert!(
            !findings.is_empty(),
            "FTP involving OT device should be flagged"
        );
        assert_eq!(findings[0].technique_id, Some("T0867".to_string()));
    }

    #[test]
    fn test_t0867_tftp_to_plc_flagged() {
        let mut input = AnalysisInput::default();
        input.assets = vec![asset("10.0.0.5", "plc", &["Modbus"])];
        input.connections = vec![conn("192.168.0.1", "10.0.0.5", 69, "Tftp", 3)];
        let ctx = CaptureContext::default();
        let findings = detect_t0867_lateral_tool_transfer(&input, &ctx);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].technique_id, Some("T0867".to_string()));
    }

    // ── T0885 ──
    #[test]
    fn test_t0885_modbus_on_wrong_port() {
        let mut input = AnalysisInput::default();
        // Modbus identified on port 503 (not 502)
        input.connections = vec![conn("10.0.0.1", "10.0.0.2", 503, "Modbus", 100)];
        let findings = detect_t0885_commonly_used_port(&input);
        assert!(
            !findings.is_empty(),
            "Modbus on port 503 should trigger T0885"
        );
        assert_eq!(findings[0].technique_id, Some("T0885".to_string()));
    }

    #[test]
    fn test_t0885_modbus_standard_port_ok() {
        let mut input = AnalysisInput::default();
        input.connections = vec![conn("10.0.0.1", "10.0.0.2", 502, "Modbus", 100)];
        let findings = detect_t0885_commonly_used_port(&input);
        assert!(findings.is_empty(), "Modbus on port 502 is normal");
    }

    // ── T0849 ──
    #[test]
    fn test_t0849_http_on_modbus_port() {
        let mut input = AnalysisInput::default();
        // HTTP traffic on port 502
        input.connections = vec![conn("10.0.0.100", "10.0.0.1", 502, "Http", 10)];
        let findings = detect_t0849_masquerading(&input);
        assert!(
            !findings.is_empty(),
            "HTTP on port 502 should trigger T0849"
        );
        assert_eq!(findings[0].technique_id, Some("T0849".to_string()));
    }

    // ── T0868 ──
    #[test]
    fn test_t0868_s7_upload_detected() {
        let mut input = AnalysisInput::default();
        input.deep_parse.insert(
            "10.0.0.50".to_string(),
            DeepParseSnapshot {
                s7: Some(S7Snapshot {
                    role: "client".to_string(),
                    functions_seen: vec!["upload".to_string(), "read_var".to_string()],
                }),
                ..Default::default()
            },
        );
        let findings = detect_t0868_detect_operating_mode(&input);
        assert!(!findings.is_empty(), "S7 upload should trigger T0868");
        assert_eq!(findings[0].technique_id, Some("T0868".to_string()));
    }

    // ── T0806 ──
    #[test]
    fn test_t0806_high_write_rate_from_context() {
        let mut input = AnalysisInput::default();
        let mut ctx = CaptureContext::default();
        ctx.per_connection_write_rate
            .insert(("10.0.0.10".to_string(), "10.0.0.1".to_string()), 600);
        let findings = detect_t0806_brute_force_io(&input, &ctx);
        assert!(!findings.is_empty(), "600 writes should trigger T0806");
        assert_eq!(findings[0].technique_id, Some("T0806".to_string()));
        let _ = &mut input; // suppress unused warning
    }

    #[test]
    fn test_t0806_modbus_fallback() {
        let mut input = AnalysisInput::default();
        input.assets = vec![asset("10.0.0.5", "plc", &["Modbus"])];
        input.deep_parse.insert(
            "10.0.0.10".to_string(),
            DeepParseSnapshot {
                modbus: Some(ModbusSnapshot {
                    role: "master".to_string(),
                    unit_ids: vec![1],
                    function_codes: vec![FcSnapshot {
                        code: 6,
                        count: 550,
                        is_write: true,
                    }],
                    relationships: vec![RelationshipSnapshot {
                        remote_ip: "10.0.0.5".to_string(),
                        remote_role: "slave".to_string(),
                        packet_count: 550,
                    }],
                    polling_intervals: vec![],
                }),
                ..Default::default()
            },
        );
        let ctx = CaptureContext::default();
        let findings = detect_t0806_brute_force_io(&input, &ctx);
        assert!(
            !findings.is_empty(),
            "550 Modbus writes to single slave should trigger T0806"
        );
    }

    // ── T0802 ──
    #[test]
    fn test_t0802_many_ot_targets_from_context() {
        let mut input = AnalysisInput::default();
        let mut ctx = CaptureContext::default();
        let targets: HashSet<String> = (1..=12).map(|i| format!("10.0.0.{}", i)).collect();
        ctx.per_source_read_targets
            .insert("192.168.1.99".to_string(), targets);
        let findings = detect_t0802_automated_collection(&input, &ctx);
        assert!(
            !findings.is_empty(),
            "Polling 12 OT targets should trigger T0802"
        );
        assert_eq!(findings[0].technique_id, Some("T0802".to_string()));
        let _ = &mut input;
    }

    // ── T0861 ──
    #[test]
    fn test_t0861_many_unit_ids() {
        let mut input = AnalysisInput::default();
        input.deep_parse.insert(
            "10.0.0.20".to_string(),
            DeepParseSnapshot {
                modbus: Some(ModbusSnapshot {
                    role: "master".to_string(),
                    unit_ids: (1..=8).collect(),
                    function_codes: vec![FcSnapshot {
                        code: 3,
                        count: 80,
                        is_write: false,
                    }],
                    relationships: vec![],
                    polling_intervals: vec![],
                }),
                ..Default::default()
            },
        );
        let findings = detect_t0861_point_tag_identification(&input);
        assert!(!findings.is_empty(), "8 unit IDs should trigger T0861");
        assert_eq!(findings[0].technique_id, Some("T0861".to_string()));
    }

    // ── T0840 ──
    #[test]
    fn test_t0840_ot_host_sweep() {
        let mut input = AnalysisInput::default();
        for i in 1..=12_u32 {
            input.connections.push(conn(
                "10.0.0.200",
                &format!("10.0.0.{}", i),
                502,
                "Modbus",
                1,
            ));
        }
        let ctx = CaptureContext::default();
        let findings = detect_t0840_network_connection_enumeration(&input, &ctx);
        assert!(
            !findings.is_empty(),
            "Connecting to 12 OT hosts should trigger T0840"
        );
        assert_eq!(findings[0].technique_id, Some("T0840".to_string()));
    }

    // ── T0803 ──
    #[test]
    fn test_t0803_plc_receives_no_commands() {
        let mut input = AnalysisInput::default();
        input.assets = vec![
            asset("10.0.0.1", "plc", &["Modbus"]),   // field device
            asset("10.0.0.100", "hmi", &["Modbus"]), // controller
        ];
        // Controller sends to port 502 but to a different PLC (not 10.0.0.1)
        input.connections = vec![
            conn("10.0.0.100", "10.0.0.2", 502, "Modbus", 100), // not to 10.0.0.1
            conn("10.0.0.1", "10.0.0.100", 49152, "Modbus", 10), // PLC has some traffic
        ];
        let findings = detect_t0803_block_command_reporting(&input);
        assert!(
            !findings.is_empty(),
            "PLC with no incoming OT commands should trigger T0803"
        );
        assert_eq!(findings[0].technique_id, Some("T0803".to_string()));
    }

    // ── T0804 ──
    #[test]
    fn test_t0804_dnp3_outstation_not_reporting() {
        let mut input = AnalysisInput::default();
        input.deep_parse.insert(
            "10.0.0.5".to_string(),
            DeepParseSnapshot {
                dnp3: Some(Dnp3Snapshot {
                    role: "outstation".to_string(),
                    has_unsolicited: false,
                    function_codes: vec![],
                    relationships: vec![RelationshipSnapshot {
                        remote_ip: "10.0.0.100".to_string(),
                        remote_role: "master".to_string(),
                        packet_count: 50,
                    }],
                }),
                ..Default::default()
            },
        );
        // Outstation has NO outgoing connections at all — so detect_t0804 should flag it.
        let findings = detect_t0804_block_reporting_message(&input);
        assert!(
            !findings.is_empty(),
            "Outstation with master but no outgoing traffic → T0804"
        );
        assert_eq!(findings[0].technique_id, Some("T0804".to_string()));
    }

    // ── T0881 ──
    #[test]
    fn test_t0881_silent_ot_device() {
        let mut input = AnalysisInput::default();
        // Three OT devices; one receives far less traffic.
        input.assets = vec![
            asset("10.0.0.1", "plc", &["Modbus"]),
            asset("10.0.0.2", "plc", &["Modbus"]),
            asset("10.0.0.3", "plc", &["Modbus"]),
        ];
        // 10.0.0.1 and 10.0.0.2 receive lots of traffic; 10.0.0.3 receives almost none.
        for _ in 0..10 {
            input
                .connections
                .push(conn("10.0.0.100", "10.0.0.1", 502, "Modbus", 1000));
            input
                .connections
                .push(conn("10.0.0.100", "10.0.0.2", 502, "Modbus", 1000));
        }
        input
            .connections
            .push(conn("10.0.0.100", "10.0.0.3", 502, "Modbus", 1));
        let findings = detect_t0881_service_stop(&input);
        let t0881 = findings.iter().any(|f| {
            f.technique_id == Some("T0881".to_string())
                && f.affected_assets.contains(&"10.0.0.3".to_string())
        });
        assert!(t0881, "Silent OT device should trigger T0881");
    }

    // ── T0864 ──
    #[test]
    fn test_t0864_transient_device() {
        let mut input = AnalysisInput::default();
        let mut ctx = CaptureContext::default();
        ctx.ot_device_ips.insert("10.0.0.1".to_string());
        // Transient laptop: seen for 120 seconds, connected to OT device.
        ctx.device_first_seen
            .insert("192.168.0.99".to_string(), 0.0);
        ctx.device_last_seen
            .insert("192.168.0.99".to_string(), 120.0);
        input.connections = vec![conn("192.168.0.99", "10.0.0.1", 502, "Modbus", 3)];
        let findings = detect_t0864_transient_cyber_asset(&input, &ctx);
        assert!(
            !findings.is_empty(),
            "Device seen for 120s touching OT should trigger T0864"
        );
        assert_eq!(findings[0].technique_id, Some("T0864".to_string()));
    }

    // ── T0830 ──
    #[test]
    fn test_t0830_multiple_macs_for_ip() {
        let ctx = CaptureContext {
            ip_to_macs: {
                let mut m = HashMap::new();
                m.insert(
                    "10.0.0.1".to_string(),
                    vec![
                        "AA:BB:CC:DD:EE:FF".to_string(),
                        "11:22:33:44:55:66".to_string(),
                    ],
                );
                m
            },
            ..Default::default()
        };
        let findings = detect_t0830_adversary_in_the_middle(&ctx);
        assert!(
            !findings.is_empty(),
            "Two MACs for one IP should trigger T0830"
        );
        assert_eq!(findings[0].technique_id, Some("T0830".to_string()));
        assert_eq!(findings[0].severity, Severity::Critical);
    }

    // ── T0884 ──
    #[test]
    fn test_t0884_proxy_device() {
        let mut input = AnalysisInput::default();
        // 10.0.0.50 is NOT an OT device. It receives from 10.0.0.100 AND connects to 10.0.0.1,
        // both on port 502 → proxy.
        input.assets = vec![
            asset("10.0.0.1", "plc", &["Modbus"]),
            asset("10.0.0.100", "hmi", &["Modbus"]),
        ];
        input.connections = vec![
            conn("10.0.0.100", "10.0.0.50", 502, "Modbus", 100), // HMI → proxy
            conn("10.0.0.50", "10.0.0.1", 502, "Modbus", 100),   // proxy → PLC
        ];
        let ctx = CaptureContext::default();
        let findings = detect_t0884_connection_proxy(&input, &ctx);
        assert!(!findings.is_empty(), "Relay device should trigger T0884");
        assert_eq!(findings[0].technique_id, Some("T0884".to_string()));
    }

    // ── T0866 ──
    #[test]
    fn test_t0866_external_host_sshing_to_plc() {
        let mut input = AnalysisInput::default();
        input.assets = vec![asset("10.0.0.1", "plc", &["Modbus"])];
        input.connections = vec![conn("203.0.113.5", "10.0.0.1", 22, "Ssh", 8)];
        let mut ctx = CaptureContext::default();
        ctx.ot_device_ips.insert("10.0.0.1".to_string());
        ctx.external_ips.insert("203.0.113.5".to_string());
        let findings = detect_t0866_exploitation_remote_services(&input, &ctx);
        assert!(
            !findings.is_empty(),
            "External SSH to OT PLC should trigger T0866"
        );
        assert_eq!(findings[0].technique_id, Some("T0866".to_string()));
    }

    // ── T0800 ──
    #[test]
    fn test_t0800_cip_file_access_to_plc() {
        let mut input = AnalysisInput::default();
        input.assets = vec![asset("10.0.0.1", "plc", &["EthernetIp"])];
        input.connections = vec![conn("10.0.0.200", "10.0.0.1", 44818, "EthernetIp", 50)];
        input.deep_parse.insert(
            "10.0.0.200".to_string(),
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
        let findings = detect_t0800_firmware_update_mode(&input);
        assert!(
            !findings.is_empty(),
            "CIP File access to PLC should trigger T0800"
        );
        assert_eq!(findings[0].technique_id, Some("T0800".to_string()));
    }

    // ── T0801 ──
    #[test]
    fn test_t0801_wide_process_monitoring() {
        let mut input = AnalysisInput::default();
        // One source reading from 25 unique (host, port) OT endpoints.
        for i in 1..=25_u32 {
            input.connections.push(conn(
                "10.0.0.200",
                &format!("10.0.0.{}", i),
                502,
                "Modbus",
                100,
            ));
        }
        let ctx = CaptureContext::default();
        let findings = detect_t0801_monitor_process_state(&input, &ctx);
        assert!(
            !findings.is_empty(),
            "25 OT endpoints polled should trigger T0801"
        );
        assert_eq!(findings[0].technique_id, Some("T0801".to_string()));
    }
}
