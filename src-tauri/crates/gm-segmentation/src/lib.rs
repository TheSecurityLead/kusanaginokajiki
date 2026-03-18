//! Microsegmentation Recommendation Engine — Phase 15.
//!
//! Implements Elisity-inspired Stage 3 (Recommendation) on top of KNK's existing
//! Stage 1 (Discover) and Stage 2 (Classify) capabilities:
//!
//! - **15A** `identity_groups` — cluster assets into PolicyGroups by identity
//! - **15B** `zones`          — propose IEC 62443 Zone/Conduit boundaries
//! - **15C** `matrix`         — per-zone-pair least-privilege allow rules
//! - **15D** `enforcement`    — export rules as Cisco ACL / Suricata / JSON
//! - **15E** `simulation`     — replay traffic against policy, quantify impact
//!
//! All modules receive a [`SegmentationInput`] assembled by the Tauri command
//! layer and return components that are bundled into a [`SegmentationReport`].
//! No dependency on `gm-analysis`, `gm-topology`, or Tauri state.

pub mod enforcement;
pub mod error;
pub mod identity_groups;
pub mod matrix;
pub mod simulation;
pub mod zones;

pub use enforcement::build_enforcement_config;
pub use error::SegmentationError;
pub use identity_groups::build_policy_groups;
pub use matrix::build_communication_matrix;
pub use simulation::run_simulation;
pub use zones::build_zone_model;

// ── Top-level orchestrator ────────────────────────────────────────────────────

/// Run the full segmentation analysis pipeline (Phases 15A–15E) and return
/// a complete [`SegmentationReport`].
///
/// The five sub-phases run in sequence; each feeds its output into the next:
/// 1. **15A** `build_policy_groups` — cluster assets by identity
/// 2. **15B** `build_zone_model`    — propose IEC 62443 zones & conduits
/// 3. **15C** `build_communication_matrix` — per-zone-pair allow rules
/// 4. **15D** `generate_enforcement_configs` — 5 format enforcement export
/// 5. **15E** `run_simulation`      — replay traffic, quantify impact
///
/// On any sub-phase error the function returns a partial report using the
/// best available outputs so the UI can still display incremental results.
pub fn run_segmentation_analysis(input: &SegmentationInput) -> SegmentationReport {
    // 15A — Identity groups.
    let policy_groups = identity_groups::build_policy_groups(input);

    // 15B — Zone model.
    let zone_model = match zones::recommend_zones(&policy_groups, input) {
        Ok(model) => model,
        Err(_) => ZoneModel {
            zones: Vec::new(),
            conduits: Vec::new(),
            zone_score: 0.0,
            recommendations: Vec::new(),
        },
    };

    // 15C — Communication matrix.
    let communication_matrix = match matrix::generate_matrix(&zone_model, input) {
        Ok(m) => m,
        Err(_) => CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        },
    };

    // 15D — Enforcement configs (all 5 formats).
    let enforcement_configs =
        enforcement::generate_enforcement_configs(&communication_matrix, &zone_model);

    // 15E — Policy simulation.
    let simulation = run_simulation(&zone_model, &communication_matrix, input);

    SegmentationReport::new(
        policy_groups,
        zone_model,
        communication_matrix,
        enforcement_configs,
        simulation,
    )
}

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Input types ───────────────────────────────────────────────────────────────

/// Protocol role observed for a specific device via deep packet inspection.
///
/// Populated from gm-parsers deep parse results (FC 43/14, ListIdentity, SZL,
/// I-Am, DCP, SNMP roles).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolRole {
    /// Protocol name (e.g., `"modbus"`, `"s7comm"`, `"ethernet_ip"`).
    pub protocol: String,
    /// Role within the protocol (e.g., `"slave"`, `"server"`, `"adapter"`, `"outstation"`).
    pub role: String,
}

/// Enriched asset identity combining all KNK subsystem outputs.
///
/// Assembled by `commands/segmentation.rs` from AppState, pulling from:
/// gm-topology (ip, connection_count), gm-parsers (protocol_roles, vendor),
/// gm-analysis/purdue.rs (purdue_level), gm-analysis/risk.rs (criticality),
/// gm-analysis/infrastructure.rs (device_type), gm-analysis/cve_matcher.rs (has_cves),
/// gm-analysis/default_creds.rs (has_default_creds).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetProfile {
    /// Primary identifier.
    pub ip: String,
    /// MAC address (from gm-capture, used for OUI lookup and MAC-based classification).
    pub mac: Option<String>,
    /// Hostname from LLDP or SNMP sysName.
    pub hostname: Option<String>,
    /// Vendor name from OUI lookup, deep parse, or signatures.
    pub vendor: Option<String>,
    /// Device type string (from `infrastructure.rs` or port analysis).
    pub device_type: String,
    /// Specific product name from deep parse (FC 43/14, ListIdentity, SZL, I-Am, DCP, SNMP).
    pub product_name: Option<String>,
    /// Purdue Model level from `purdue.rs` auto-assignment or manual override.
    pub purdue_level: Option<u8>,
    /// Detected protocol names (e.g., `["modbus", "snmp"]`).
    pub protocols: Vec<String>,
    /// Deep parse roles per protocol.
    pub protocol_roles: Vec<ProtocolRole>,
    /// Classification confidence (1=port, 2=pattern, 3=OUI, 4=payload, 5=deep parse).
    pub confidence: u8,
    /// Criticality from `risk.rs` (already computed — passed through as string).
    pub criticality: Option<String>,
    /// Derived /24 subnet string (e.g., `"10.0.0.0/24"`).
    pub subnet: Option<String>,
    /// True if the asset uses any OT protocol.
    pub is_ot: bool,
    /// True if the asset uses only IT protocols.
    pub is_it: bool,
    /// True if the asset has both OT and IT connections (DMZ candidate).
    pub is_dual_homed: bool,
    /// Total connection count from gm-topology (used for community weighting).
    pub connection_count: u64,
    /// True if `cve_matcher.rs` matched at least one CVE for this device.
    pub has_cves: bool,
    /// True if `default_creds.rs` matched default credentials for this device.
    pub has_default_creds: bool,
}

/// Traffic record with deep parse flags for policy decision making.
///
/// Assembled from AppState connections, deep_parse_info, comm_patterns output,
/// allowlist output, and ATT&CK findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservedConnection {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    /// Protocol name (e.g., `"modbus"`, `"http"`).
    pub protocol: String,
    pub packet_count: u64,
    pub byte_count: u64,
    /// RFC 3339 timestamp of first observed packet.
    pub first_seen: String,
    /// RFC 3339 timestamp of last observed packet.
    pub last_seen: String,
    /// True if `comm_patterns.rs` classified this as a periodic connection.
    pub is_periodic: bool,
    /// True if `comm_patterns.rs` flagged an unusual pattern anomaly.
    pub pattern_anomaly: bool,
    /// True if deep parse detected write function codes on this connection.
    pub has_write_operations: bool,
    /// True if deep parse detected read function codes on this connection.
    pub has_read_operations: bool,
    /// True if deep parse detected program transfer, firmware update, or PLC stop.
    pub has_config_operations: bool,
    /// ATT&CK technique IDs from `attack.rs` / `context_attacks.rs` findings.
    pub attack_techniques: Vec<String>,
    /// True if `allowlist.rs` classified this as an expected flow.
    pub is_in_allowlist: bool,
}

/// Simplified security finding for zone/policy decisions.
///
/// Populated from ATT&CK findings, malware findings, and compliance findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityFinding {
    pub id: String,
    pub technique_id: Option<String>,
    /// Severity string: `"critical"`, `"high"`, `"medium"`, `"low"`, or `"info"`.
    pub severity: String,
    pub affected_ips: Vec<String>,
    pub description: String,
}

/// Complete input bundle for the segmentation engine.
///
/// No Tauri state: assembled by `commands/segmentation.rs` and passed in.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SegmentationInput {
    pub assets: Vec<AssetProfile>,
    pub connections: Vec<ObservedConnection>,
    pub findings: Vec<SecurityFinding>,
}

// ── Enums ─────────────────────────────────────────────────────────────────────

/// Functional device category used for PolicyGroup classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceCategory {
    /// PLC, RTU, or IED (L1 basic control).
    Plc,
    /// Sensor or actuator (L0 process level).
    Sensor,
    /// Human-Machine Interface (L2 supervisory).
    Hmi,
    /// Engineering workstation (L2 supervisory, config operations).
    EngineeringStation,
    /// Historian server (L3 site operations).
    Historian,
    /// SCADA server (L3 site operations).
    ScadaServer,
    /// DMZ gateway or dual-homed device (L3.5).
    DmzGateway,
    /// Managed/unmanaged switch, router, firewall, AP.
    NetworkInfra,
    /// IT endpoint (L4 enterprise).
    ItEndpoint,
    /// Classification insufficient.
    Unknown,
}

/// IEC 62443 Security Level (SL1–SL4) assigned from Purdue level.
///
/// Mapping: L0/L1 → SL3 (basic control process isolation),
/// L2/L3/L3.5 → SL2 (supervisory access control),
/// L4+ / unassigned → SL1 (IT network baseline).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityLevel {
    Sl1,
    Sl2,
    Sl3,
    Sl4,
}

/// Asset/group criticality level (mirrors `risk.rs` CriticalityLevel).
///
/// Ordering: Unknown < Low < Medium < High < Critical (for `max()` operations).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criticality {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

// ── 15A Output: PolicyGroup ───────────────────────────────────────────────────

/// Identity-based cluster of assets — the output of Phase 15A.
///
/// Groups assets by what they ARE (vendor, protocol role, Purdue level) rather
/// than where they are (IP range, VLAN). Inspired by Elisity's IdentityGraph
/// Policy Groups concept, adapted for offline PCAP-based assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGroup {
    /// UUID string identifier.
    pub id: String,
    /// Auto-generated descriptive name (e.g., `"L1-Modbus-Rockwell"`).
    pub name: String,
    /// IP addresses of all member assets.
    pub member_ips: Vec<String>,
    /// Purdue level shared by all members (`None` for unclassified communities).
    pub purdue_level: Option<u8>,
    /// Dominant device category for this group.
    pub device_category: DeviceCategory,
    /// IEC 62443 Security Level derived from Purdue level.
    pub security_level: SecurityLevel,
    /// Maximum criticality level of any member (from `risk.rs`).
    pub criticality: Criticality,
}

impl PolicyGroup {
    /// Create a new PolicyGroup with a fresh UUID.
    pub fn new(
        name: impl Into<String>,
        member_ips: Vec<String>,
        purdue_level: Option<u8>,
        device_category: DeviceCategory,
        security_level: SecurityLevel,
        criticality: Criticality,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            member_ips,
            purdue_level,
            device_category,
            security_level,
            criticality,
        }
    }
}

// ── 15B Output: Zone / Conduit / ZoneModel ────────────────────────────────────

/// Direction of conduit traffic flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConduitDirection {
    Unidirectional,
    Bidirectional,
}

/// A single allow rule within a conduit definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConduitRule {
    /// Protocol name (e.g., `"modbus"`, `"http"`).
    pub protocol: String,
    /// Destination port number (`None` for protocol-only rules).
    pub dst_port: Option<u16>,
    /// True if write function codes were observed on this flow.
    pub has_write_ops: bool,
    /// True if configuration/program operations were observed.
    pub has_config_ops: bool,
    /// ATT&CK technique IDs observed on this flow.
    pub attack_techniques: Vec<String>,
    /// Optional risk note (e.g., cross-Purdue violation explanation).
    pub risk_note: Option<String>,
}

/// IEC 62443 conduit — a controlled communication channel between two zones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Conduit {
    /// UUID string identifier.
    pub id: String,
    /// Source zone ID.
    pub src_zone_id: String,
    /// Destination zone ID.
    pub dst_zone_id: String,
    pub direction: ConduitDirection,
    pub rules: Vec<ConduitRule>,
    /// True if this conduit crosses Purdue model boundaries (risk flag).
    pub cross_purdue_risk: bool,
}

/// IEC 62443 security zone — a group of assets with similar security requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    /// UUID string identifier.
    pub id: String,
    /// Human-readable name (e.g., `"Control Zone L1"`, `"Enterprise IT L4"`).
    pub name: String,
    /// Purdue levels contained in this zone.
    pub purdue_levels: Vec<u8>,
    /// IDs of PolicyGroups that form this zone.
    pub policy_group_ids: Vec<String>,
    /// IEC 62443 Security Level target for this zone.
    pub security_level: SecurityLevel,
    /// Total asset count in this zone.
    pub asset_count: usize,
}

/// IEC 62443 zone model with all zones, conduits, score, and recommendations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneModel {
    pub zones: Vec<Zone>,
    pub conduits: Vec<Conduit>,
    /// Segmentation quality score: 1.0 = no cross-Purdue violations, 0.0 = fully flat.
    /// Formula: `1.0 - (cross_purdue_violations / total_inter_zone_connections)`.
    pub zone_score: f64,
    /// Human-readable recommendations (e.g., "Add DMZ between L1 and L4").
    pub recommendations: Vec<String>,
}

// ── 15C Output: CommunicationMatrix ──────────────────────────────────────────

/// Risk classification for a least-privilege communication rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleRisk {
    /// Read-only polling (lowest risk).
    Low,
    /// Write operations to outputs or registers.
    Medium,
    /// Configuration, program transfer, or firmware operations (highest risk).
    High,
}

/// A single least-privilege allow rule for a zone pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Protocol name.
    pub protocol: String,
    /// Destination port (`None` = any port for this protocol).
    pub dst_port: Option<u16>,
    pub risk: RuleRisk,
    /// Justification text (e.g., `"Observed 1243 packets, periodic Modbus polling"`).
    pub justification: String,
    /// Total packets observed for this rule's traffic.
    pub packet_count: u64,
}

/// Allowed communications between a specific zone pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePairPolicy {
    pub src_zone_id: String,
    pub dst_zone_id: String,
    pub rules: Vec<PolicyRule>,
}

/// Per-zone-pair least-privilege communication matrix — the output of Phase 15C.
///
/// Extends `allowlist.rs` output from per-connection granularity to per-zone-pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunicationMatrix {
    pub zone_pairs: Vec<ZonePairPolicy>,
    /// Default action for traffic not matching any rule (always `"deny"`).
    pub default_action: String,
    /// Percentage of observed connections covered by generated rules (0.0–100.0).
    pub coverage_percent: f64,
}

// ── 15D Output: EnforcementConfig ────────────────────────────────────────────

/// Output format for enforcement configuration export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementFormat {
    /// Cisco IOS extended ACL (`ip access-list extended`, `permit tcp`, `deny ip any any log`).
    CiscoIosAcl,
    /// Cisco ASA ACL (`access-list extended`, `object-group`, `access-group`).
    CiscoAsaAcl,
    /// Tab-separated generic table: Action / Zones / Protocol / Port / Risk / Justification.
    GenericFirewallTable,
    /// Suricata `pass`/`drop` rules with SIDs starting at 9000001.
    SuricataRules,
    /// Structured JSON `{zones, conduits, rules}` for automation/SOAR integration.
    JsonPolicy,
}

/// Enforcement configuration in a specific output format — the output of Phase 15D.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnforcementConfig {
    pub format: EnforcementFormat,
    /// Full text content of the generated configuration file.
    pub content: String,
    /// RFC 3339 timestamp when this config was generated.
    pub generated_at: String,
    /// Number of allow/pass rules in the generated config.
    pub rule_count: usize,
}

impl EnforcementConfig {
    /// Create a new EnforcementConfig with the current UTC timestamp.
    pub fn new(format: EnforcementFormat, content: String, rule_count: usize) -> Self {
        Self {
            format,
            content,
            generated_at: Utc::now().to_rfc3339(),
            rule_count,
        }
    }
}

// ── 15E Output: SimulationResult ─────────────────────────────────────────────

/// A connection that would be blocked by the proposed policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedConnection {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub dst_port: u16,
    /// True if this block is likely a false positive (periodic OT read + allowlisted).
    pub is_false_positive_candidate: bool,
    /// Human-readable reason why this connection is blocked.
    pub reason: String,
}

/// Summary of blocked connections between a specific zone pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneBlockSummary {
    pub src_zone_id: String,
    pub dst_zone_id: String,
    pub blocked_count: usize,
}

/// Policy simulation result — the output of Phase 15E.
///
/// Replays observed traffic against the proposed policy to quantify impact
/// before enforcement. Inspired by Elisity's Simulation Mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Connections allowed by the proposed policy.
    pub allowed: usize,
    /// Connections blocked by the proposed policy.
    pub blocked: usize,
    /// `blocked / (allowed + blocked) * 100.0`.
    pub blocked_percent: f64,
    /// Count of ATT&CK/malware/compliance findings that would be blocked,
    /// weighted by severity (critical=4, high=3, medium=2, low=1).
    pub risk_reduction_score: f64,
    /// Weighted policy coverage metric based on IEC 62443 Security Levels.
    /// 1.0 = all SL3 zones fully covered, 0.0 = no coverage.
    pub deployment_score: f64,
    /// Blocked connections that need review before enforcement
    /// (cross-zone, non-periodic, or write operations).
    pub critical_blocks: Vec<BlockedConnection>,
    /// Blocked connections likely to be false positives
    /// (periodic OT read-only traffic between OT devices).
    pub false_positive_candidates: Vec<BlockedConnection>,
    /// Per-zone-pair breakdown of blocked connection counts.
    pub zone_block_summaries: Vec<ZoneBlockSummary>,
}

// ── SegmentationReport ────────────────────────────────────────────────────────

/// Complete segmentation analysis output — all Phase 15A–15E results bundled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationReport {
    pub policy_groups: Vec<PolicyGroup>,
    pub zone_model: ZoneModel,
    pub communication_matrix: CommunicationMatrix,
    pub enforcement_configs: Vec<EnforcementConfig>,
    pub simulation: SimulationResult,
    /// RFC 3339 timestamp when this report was generated.
    pub generated_at: String,
}

impl SegmentationReport {
    /// Bundle all sub-phase outputs into a complete report.
    pub fn new(
        policy_groups: Vec<PolicyGroup>,
        zone_model: ZoneModel,
        communication_matrix: CommunicationMatrix,
        enforcement_configs: Vec<EnforcementConfig>,
        simulation: SimulationResult,
    ) -> Self {
        Self {
            policy_groups,
            zone_model,
            communication_matrix,
            enforcement_configs,
            simulation,
            generated_at: Utc::now().to_rfc3339(),
        }
    }
}
