//! Phase 15D — Enforcement Config Export.
//!
//! Generates ready-to-deploy enforcement configurations in five formats from
//! the communication matrix. Extends `allowlist.rs` firewall rule generation to
//! zone-aware multi-format output.
//!
//! | Format                | Use case                                   |
//! |-----------------------|--------------------------------------------|
//! | CiscoIosAcl           | Most common OT managed switch              |
//! | CiscoAsaAcl           | Dedicated OT firewall deployments          |
//! | GenericFirewallTable  | Vendor-neutral TSV import                  |
//! | SuricataRules         | IDS monitoring before hard enforcement     |
//! | JsonPolicy            | Automation / SOAR integration              |
//!
//! - Cisco ACL names: sanitized uppercase, max 64 characters.
//! - Suricata SIDs: 9000001+.
//! - Vendor-aware remarks when PolicyGroup names encode a vendor suffix.

use std::collections::HashMap;

use crate::{
    CommunicationMatrix, EnforcementConfig, EnforcementFormat, PolicyGroup, Zone, ZoneModel,
    ZonePairPolicy,
};

// ── Public API ──────────────────────────────────────────────────────────────

/// Generate enforcement configurations in all five formats.
///
/// When `groups` is non-empty, vendor-specific port context remarks are added
/// to rules whose zone members include a known vendor (Siemens, Rockwell, etc.).
pub fn generate_enforcement_configs(
    matrix: &CommunicationMatrix,
    zone_model: &ZoneModel,
    groups: &[PolicyGroup],
) -> Vec<EnforcementConfig> {
    let zone_names: HashMap<String, String> = zone_model
        .zones
        .iter()
        .map(|z| (z.id.clone(), z.name.clone()))
        .collect();

    let zone_vendors = build_zone_vendors(&zone_model.zones, groups);

    vec![
        gen_cisco_ios(&matrix.zone_pairs, &zone_names, &zone_vendors),
        gen_cisco_asa(
            &matrix.zone_pairs,
            &zone_names,
            &zone_model.zones,
            &zone_vendors,
        ),
        gen_generic_table(&matrix.zone_pairs, &zone_names, &zone_vendors),
        gen_suricata(&matrix.zone_pairs, &zone_names, &zone_vendors),
        gen_json_policy(matrix, zone_model, &zone_vendors),
    ]
}

/// Generate an enforcement configuration in a single requested format.
///
/// Thin wrapper around [`generate_enforcement_configs`] using an empty zone
/// model so zone IDs serve as fallback names. Preserves the
/// `pub use enforcement::build_enforcement_config` re-export in `lib.rs`.
pub fn build_enforcement_config(
    matrix: &CommunicationMatrix,
    format: EnforcementFormat,
) -> EnforcementConfig {
    let empty_model = ZoneModel {
        zones: Vec::new(),
        conduits: Vec::new(),
        zone_score: 0.0,
        recommendations: Vec::new(),
    };
    generate_enforcement_configs(matrix, &empty_model, &[])
        .into_iter()
        .find(|c| c.format == format)
        .unwrap_or_else(|| EnforcementConfig::new(format, String::new(), 0))
}

// ── Public helpers ───────────────────────────────────────────────────────────

/// Sanitize a zone name for use in a Cisco ACL name.
///
/// Replaces non-alphanumeric characters with `_` and converts to uppercase.
/// The caller is responsible for truncating the result to the IOS 64-char limit.
pub fn sanitize_acl_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

/// Derive the /24 network address and inverse wildcard mask for an IPv4 string.
///
/// Returns `None` if `ip` is not a valid dotted-quad.
///
/// ```
/// # use gm_segmentation::enforcement::ip_to_network_and_wildcard;
/// assert_eq!(
///     ip_to_network_and_wildcard("10.0.1.55"),
///     Some(("10.0.1.0".to_string(), "0.0.0.255".to_string()))
/// );
/// ```
pub fn ip_to_network_and_wildcard(ip: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for p in &parts {
        p.parse::<u8>().ok()?;
    }
    Some((
        format!("{}.{}.{}.0", parts[0], parts[1], parts[2]),
        "0.0.0.255".to_string(),
    ))
}

/// Return the /24 CIDR prefix for an IPv4 address string.
///
/// Returns `None` if `ip` is not a valid dotted-quad.
///
/// ```
/// # use gm_segmentation::enforcement::ip_to_cidr;
/// assert_eq!(ip_to_cidr("10.0.1.55"), Some("10.0.1.0/24".to_string()));
/// ```
pub fn ip_to_cidr(ip: &str) -> Option<String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for p in &parts {
        p.parse::<u8>().ok()?;
    }
    Some(format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]))
}

/// Determine whether a protocol / port combination uses TCP or UDP.
///
/// Falls back to `"tcp"` for unknown combinations.
pub fn protocol_to_transport(protocol: &str, port: Option<u16>) -> &'static str {
    const UDP_PORTS: &[u16] = &[47808, 34962, 34963, 34964, 2222, 161, 162, 69, 123, 514];
    if let Some(p) = port {
        if UDP_PORTS.contains(&p) {
            return "udp";
        }
    }
    match protocol.to_lowercase().as_str() {
        "bacnet" | "profinet_dcp" | "snmp" | "tftp" | "dns" | "ntp" | "syslog" | "ssdp" => "udp",
        _ => "tcp",
    }
}

// ── Vendor-aware context ────────────────────────────────────────────────────

/// Return vendor-specific port context for known OT vendor + port combinations.
///
/// Used to enrich enforcement config remarks with protocol-level context that
/// helps network engineers understand what each firewall rule actually permits.
fn vendor_port_context(vendor: &str, port: u16) -> Option<&'static str> {
    let v = vendor.to_lowercase();
    if v.contains("siemens") {
        match port {
            102 => return Some("S7comm PLC communication"),
            443 => return Some("SCALANCE web management"),
            161 => return Some("SCALANCE SNMP monitoring"),
            34962 => return Some("PROFINET IO"),
            _ => {}
        }
    }
    if v.contains("rockwell") {
        match port {
            44818 => return Some("EtherNet/IP explicit messaging"),
            2222 => return Some("EtherNet/IP I/O"),
            _ => {}
        }
    }
    if v.contains("schneider") && port == 502 {
        return Some("Modbus TCP");
    }
    if v.contains("abb") && port == 502 {
        return Some("Modbus TCP");
    }
    if v.contains("honeywell") && port == 502 {
        return Some("Modbus TCP");
    }
    None
}

/// Extract the vendor suffix from a PolicyGroup auto-generated name.
///
/// Group names follow the pattern `L{N}-{role}` (no vendor) or
/// `L{N}-{role}-{vendor}` (with vendor split). Returns `Some(vendor)` when
/// the name has the three-segment form starting with `L`.
fn extract_vendor_from_group_name(name: &str) -> Option<&str> {
    let parts: Vec<&str> = name.splitn(3, '-').collect();
    if parts.len() == 3 && parts[0].starts_with('L') {
        Some(parts[2])
    } else {
        None
    }
}

/// Build a mapping from zone ID → list of vendor names extracted from the
/// PolicyGroups assigned to each zone.
fn build_zone_vendors(zones: &[Zone], groups: &[PolicyGroup]) -> HashMap<String, Vec<String>> {
    let group_by_id: HashMap<&str, &PolicyGroup> =
        groups.iter().map(|g| (g.id.as_str(), g)).collect();

    let mut zone_vendors: HashMap<String, Vec<String>> = HashMap::new();
    for zone in zones {
        let mut vendors: Vec<String> = Vec::new();
        for gid in &zone.policy_group_ids {
            if let Some(group) = group_by_id.get(gid.as_str()) {
                if let Some(vendor) = extract_vendor_from_group_name(&group.name) {
                    if !vendors.iter().any(|v| v == vendor) {
                        vendors.push(vendor.to_string());
                    }
                }
            }
        }
        zone_vendors.insert(zone.id.clone(), vendors);
    }
    zone_vendors
}

/// Build a vendor context remark for a rule between two zones on a given port.
///
/// Checks both source and destination zone vendors against the port and returns
/// a combined remark string, or `None` if no vendor context applies.
fn vendor_remark_for_rule(
    zone_vendors: &HashMap<String, Vec<String>>,
    src_zone_id: &str,
    dst_zone_id: &str,
    port: Option<u16>,
) -> Option<String> {
    let port = port?;
    let empty = Vec::new();
    let src_vendors = zone_vendors.get(src_zone_id).unwrap_or(&empty);
    let dst_vendors = zone_vendors.get(dst_zone_id).unwrap_or(&empty);

    let mut remarks: Vec<String> = Vec::new();
    for vendor in src_vendors.iter().chain(dst_vendors.iter()) {
        if let Some(context) = vendor_port_context(vendor, port) {
            let remark = format!("{vendor} — {context}");
            if !remarks.contains(&remark) {
                remarks.push(remark);
            }
        }
    }

    if remarks.is_empty() {
        None
    } else {
        Some(remarks.join("; "))
    }
}

// ── Format generators ────────────────────────────────────────────────────────

/// Cisco IOS Extended ACL format.
///
/// One ACL per zone pair, named `ACL-{SRC}-TO-{DST}` (sanitized, max 64 chars).
/// Emits `permit` lines for each rule and a `deny ip any any log` trailer.
fn gen_cisco_ios(
    pairs: &[ZonePairPolicy],
    zone_names: &HashMap<String, String>,
    zone_vendors: &HashMap<String, Vec<String>>,
) -> EnforcementConfig {
    let mut out = String::new();
    out.push_str("! Generated by Kusanagi Kajiki microsegmentation analysis\n");
    out.push_str("! Format: Cisco IOS Extended ACL\n");
    out.push_str("! Note: Replace 'any' with actual IP ranges/subnets before deployment.\n");
    out.push_str("!\n");

    let mut rule_count = 0usize;

    for pair in pairs {
        let src_name = zone_name(zone_names, &pair.src_zone_id);
        let dst_name = zone_name(zone_names, &pair.dst_zone_id);
        let acl_name = build_acl_name(src_name, dst_name);

        out.push_str(&format!("ip access-list extended {acl_name}\n"));
        out.push_str(&format!(" ! Remark: {src_name} → {dst_name}\n"));

        for rule in &pair.rules {
            let transport = protocol_to_transport(&rule.protocol, rule.dst_port);
            let risk_str = format!("{:?}", rule.risk).to_lowercase();

            // Vendor-aware remark (e.g., "Siemens — S7comm PLC communication").
            if let Some(vendor_ctx) = vendor_remark_for_rule(
                zone_vendors,
                &pair.src_zone_id,
                &pair.dst_zone_id,
                rule.dst_port,
            ) {
                out.push_str(&format!(" ! Remark: {vendor_ctx}\n"));
            }

            // Truncate justification to fit within IOS remark line limit.
            let just: String = rule.justification.chars().take(80).collect();
            out.push_str(&format!(" ! Remark: [{risk_str}] {just}\n"));
            if let Some(port) = rule.dst_port {
                out.push_str(&format!(" permit {transport} any any eq {port}\n"));
            } else {
                out.push_str(&format!(" permit {transport} any any\n"));
            }
            rule_count += 1;
        }

        out.push_str(" deny ip any any log\n");
        out.push_str("!\n");
    }

    if pairs.is_empty() {
        out.push_str("! No zone pairs defined — default deny applies to all traffic.\n");
        out.push_str("!\n");
    }

    EnforcementConfig::new(EnforcementFormat::CiscoIosAcl, out, rule_count)
}

/// Cisco ASA Extended ACL format.
///
/// Zones with more than 3 assets use `object-group network` entries.
/// Smaller zones fall back to `any`.
fn gen_cisco_asa(
    pairs: &[ZonePairPolicy],
    zone_names: &HashMap<String, String>,
    zones: &[Zone],
    zone_vendors: &HashMap<String, Vec<String>>,
) -> EnforcementConfig {
    let zone_by_id: HashMap<&str, &Zone> = zones.iter().map(|z| (z.id.as_str(), z)).collect();

    let mut out = String::new();
    out.push_str("! Generated by Kusanagi Kajiki microsegmentation analysis\n");
    out.push_str("! Format: Cisco ASA Extended ACL\n");
    out.push_str(
        "! Note: Populate object-group members with actual IP addresses before deployment.\n",
    );
    out.push_str("!\n");

    let mut rule_count = 0usize;

    // Collect unique zone IDs referenced by any pair (preserving first-seen order).
    let mut zone_ids_seen: Vec<&str> = Vec::new();
    for pair in pairs {
        for zid in [pair.src_zone_id.as_str(), pair.dst_zone_id.as_str()] {
            if !zone_ids_seen.contains(&zid) {
                zone_ids_seen.push(zid);
            }
        }
    }

    // Emit object-groups for zones with more than 3 assets.
    for &zone_id in &zone_ids_seen {
        let asset_count = zone_by_id.get(zone_id).map(|z| z.asset_count).unwrap_or(0);
        if asset_count > 3 {
            let name = zone_names
                .get(zone_id)
                .map(|s| s.as_str())
                .unwrap_or(zone_id);
            let obj_name: String = format!("OBJ-{}", sanitize_acl_name(name))
                .chars()
                .take(64)
                .collect();
            out.push_str(&format!("object-group network {obj_name}\n"));
            out.push_str(&format!(
                " description {name} ({asset_count} assets - add member ip entries)\n"
            ));
            out.push_str("!\n");
        }
    }

    // Emit ACL rules per zone pair.
    for pair in pairs {
        let src_name = zone_name(zone_names, &pair.src_zone_id);
        let dst_name = zone_name(zone_names, &pair.dst_zone_id);
        let acl_name = build_acl_name(src_name, dst_name);

        let src_assets = zone_by_id
            .get(pair.src_zone_id.as_str())
            .map(|z| z.asset_count)
            .unwrap_or(0);
        let dst_assets = zone_by_id
            .get(pair.dst_zone_id.as_str())
            .map(|z| z.asset_count)
            .unwrap_or(0);

        let src_san: String = sanitize_acl_name(src_name).chars().take(28).collect();
        let dst_san: String = sanitize_acl_name(dst_name).chars().take(28).collect();

        let src_clause = if src_assets > 3 {
            format!("object-group OBJ-{src_san}")
        } else {
            "any".to_string()
        };
        let dst_clause = if dst_assets > 3 {
            format!("object-group OBJ-{dst_san}")
        } else {
            "any".to_string()
        };

        out.push_str(&format!("! Zone pair: {src_name} → {dst_name}\n"));

        for rule in &pair.rules {
            let transport = protocol_to_transport(&rule.protocol, rule.dst_port);

            // Vendor-aware remark.
            if let Some(vendor_ctx) = vendor_remark_for_rule(
                zone_vendors,
                &pair.src_zone_id,
                &pair.dst_zone_id,
                rule.dst_port,
            ) {
                out.push_str(&format!("! {vendor_ctx}\n"));
            }

            if let Some(port) = rule.dst_port {
                out.push_str(&format!(
                    "access-list {acl_name} extended permit {transport} \
                     {src_clause} {dst_clause} eq {port}\n"
                ));
            } else {
                out.push_str(&format!(
                    "access-list {acl_name} extended permit {transport} \
                     {src_clause} {dst_clause}\n"
                ));
            }
            rule_count += 1;
        }

        out.push_str(&format!(
            "access-list {acl_name} extended deny ip any any log\n"
        ));
        out.push_str(&format!("access-group {acl_name} in interface <outside>\n"));
        out.push_str("!\n");
    }

    if pairs.is_empty() {
        out.push_str("! No zone pairs defined.\n");
    }

    EnforcementConfig::new(EnforcementFormat::CiscoAsaAcl, out, rule_count)
}

/// Generic Firewall Table — tab-separated, one rule per row.
///
/// Columns: Action | Src Zone | Src Net | Dst Zone | Dst Net | Proto | Port | Dir | Risk | Justification
fn gen_generic_table(
    pairs: &[ZonePairPolicy],
    zone_names: &HashMap<String, String>,
    zone_vendors: &HashMap<String, Vec<String>>,
) -> EnforcementConfig {
    let mut out = String::new();
    out.push_str(
        "Action\tSrc Zone\tSrc Net\tDst Zone\tDst Net\tProto\tPort\tDir\tRisk\tJustification\n",
    );

    let mut rule_count = 0usize;

    for pair in pairs {
        let src_name = zone_name(zone_names, &pair.src_zone_id);
        let dst_name = zone_name(zone_names, &pair.dst_zone_id);

        for rule in &pair.rules {
            let transport = protocol_to_transport(&rule.protocol, rule.dst_port);
            let port_str = rule
                .dst_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "any".to_string());
            let risk_str = format!("{:?}", rule.risk).to_lowercase();
            // Strip tabs to preserve TSV structure.
            let mut just = rule.justification.replace('\t', " ");

            // Append vendor context to justification.
            if let Some(vendor_ctx) = vendor_remark_for_rule(
                zone_vendors,
                &pair.src_zone_id,
                &pair.dst_zone_id,
                rule.dst_port,
            ) {
                just = format!("{just} [{vendor_ctx}]");
            }

            out.push_str(&format!(
                "ALLOW\t{src_name}\tany\t{dst_name}\tany\t{transport}\t{port_str}\t→\t{risk_str}\t{just}\n"
            ));
            rule_count += 1;
        }
    }

    // Default deny row.
    out.push_str("DENY\t*\t*\t*\t*\t*\t*\t*\t—\tDefault deny\n");

    EnforcementConfig::new(EnforcementFormat::GenericFirewallTable, out, rule_count)
}

/// Suricata IDS/IPS rules — `pass`/`drop` syntax with SIDs starting at 9000001.
fn gen_suricata(
    pairs: &[ZonePairPolicy],
    zone_names: &HashMap<String, String>,
    zone_vendors: &HashMap<String, Vec<String>>,
) -> EnforcementConfig {
    let mut out = String::new();
    out.push_str("# Generated by Kusanagi Kajiki microsegmentation analysis\n");
    out.push_str("# Format: Suricata IDS/IPS rules\n");
    out.push_str("# Place in /etc/suricata/rules/knk-policy.rules and enable in suricata.yaml\n");
    out.push_str("#\n");

    let mut sid: u32 = 9_000_001;
    let mut rule_count = 0usize;

    for pair in pairs {
        let src_name = zone_name(zone_names, &pair.src_zone_id);
        let dst_name = zone_name(zone_names, &pair.dst_zone_id);

        out.push_str(&format!("# Zone pair: {src_name} → {dst_name}\n"));

        for rule in &pair.rules {
            let transport = protocol_to_transport(&rule.protocol, rule.dst_port);
            let port_str = rule
                .dst_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "any".to_string());
            let risk_str = format!("{:?}", rule.risk).to_lowercase();

            // Include vendor context in msg if available.
            let vendor_suffix = vendor_remark_for_rule(
                zone_vendors,
                &pair.src_zone_id,
                &pair.dst_zone_id,
                rule.dst_port,
            )
            .map(|ctx| format!(" ({ctx})"))
            .unwrap_or_default();

            let msg = sanitize_suricata_msg(&format!(
                "KNK-ALLOW: {}/{} {} to {} [{}]{}",
                rule.protocol, port_str, src_name, dst_name, risk_str, vendor_suffix
            ));

            out.push_str(&format!(
                "pass {transport} any any -> any {port_str} \
                 (msg:\"{msg}\"; sid:{sid}; rev:1;)\n"
            ));
            sid += 1;
            rule_count += 1;
        }
    }

    // Default drop rule — catches everything not explicitly passed above.
    out.push_str("#\n");
    out.push_str(&format!(
        "drop ip any any -> any any \
         (msg:\"KNK-DENY: No conduit - default deny all unmatched traffic\"; sid:{sid}; rev:1;)\n"
    ));

    EnforcementConfig::new(EnforcementFormat::SuricataRules, out, rule_count)
}

/// JSON Policy — structured `{metadata, zones, conduits, rules, default_action}`.
fn gen_json_policy(
    matrix: &CommunicationMatrix,
    zone_model: &ZoneModel,
    zone_vendors: &HashMap<String, Vec<String>>,
) -> EnforcementConfig {
    let zones_json: Vec<serde_json::Value> = zone_model
        .zones
        .iter()
        .map(|z| {
            serde_json::json!({
                "id": z.id,
                "name": z.name,
                "purdue_levels": z.purdue_levels,
                "asset_count": z.asset_count,
                "security_level": format!("{:?}", z.security_level).to_lowercase()
            })
        })
        .collect();

    let conduits_json: Vec<serde_json::Value> = zone_model
        .conduits
        .iter()
        .map(|c| {
            serde_json::json!({
                "id": c.id,
                "src_zone_id": c.src_zone_id,
                "dst_zone_id": c.dst_zone_id,
                "cross_purdue_risk": c.cross_purdue_risk
            })
        })
        .collect();

    let rules_json: Vec<serde_json::Value> = matrix
        .zone_pairs
        .iter()
        .flat_map(|p| {
            p.rules.iter().map(move |r| {
                let vendor_context = vendor_remark_for_rule(
                    zone_vendors,
                    &p.src_zone_id,
                    &p.dst_zone_id,
                    r.dst_port,
                )
                .unwrap_or_default();

                serde_json::json!({
                    "src_zone_id": p.src_zone_id,
                    "dst_zone_id": p.dst_zone_id,
                    "protocol": r.protocol,
                    "dst_port": r.dst_port,
                    "risk": format!("{:?}", r.risk).to_lowercase(),
                    "packet_count": r.packet_count,
                    "justification": r.justification,
                    "vendor_context": vendor_context
                })
            })
        })
        .collect();

    let rule_count = rules_json.len();

    let policy = serde_json::json!({
        "metadata": {
            "generated_by": "Kusanagi Kajiki",
            "format": "json_policy",
            "coverage_percent": matrix.coverage_percent,
            "zone_score": zone_model.zone_score
        },
        "zones": zones_json,
        "conduits": conduits_json,
        "rules": rules_json,
        "default_action": matrix.default_action,
        "recommendations": zone_model.recommendations
    });

    let content = serde_json::to_string_pretty(&policy)
        .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"));

    EnforcementConfig::new(EnforcementFormat::JsonPolicy, content, rule_count)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Look up a zone display name; fall back to the raw zone ID.
fn zone_name<'a>(zone_names: &'a HashMap<String, String>, id: &'a str) -> &'a str {
    zone_names.get(id).map(|s| s.as_str()).unwrap_or(id)
}

/// Build a sanitized Cisco ACL name from two zone display names.
/// Format: `ACL-{SRC_28}-TO-{DST_28}`, total ≤ 64 characters.
fn build_acl_name(src_name: &str, dst_name: &str) -> String {
    let src: String = sanitize_acl_name(src_name).chars().take(28).collect();
    let dst: String = sanitize_acl_name(dst_name).chars().take(28).collect();
    format!("ACL-{src}-TO-{dst}")
}

/// Strip characters that would break Suricata rule syntax (`"` and `;`).
fn sanitize_suricata_msg(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '"' && c != ';')
        .take(200)
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CommunicationMatrix, PolicyRule, RuleRisk, SecurityLevel, Zone, ZoneModel, ZonePairPolicy,
    };

    // ── Test fixtures ─────────────────────────────────────────────────────────

    fn make_matrix(proto: &str, port: u16, risk: RuleRisk) -> CommunicationMatrix {
        CommunicationMatrix {
            zone_pairs: vec![ZonePairPolicy {
                src_zone_id: "z-ctrl".to_string(),
                dst_zone_id: "z-ent".to_string(),
                rules: vec![PolicyRule {
                    protocol: proto.to_string(),
                    dst_port: Some(port),
                    risk,
                    justification: format!("Observed 100 packets, {proto}/{port}"),
                    packet_count: 100,
                }],
            }],
            default_action: "deny".to_string(),
            coverage_percent: 100.0,
        }
    }

    fn make_model(ctrl_assets: usize, ent_assets: usize) -> ZoneModel {
        ZoneModel {
            zones: vec![
                Zone {
                    id: "z-ctrl".to_string(),
                    name: "Control Zone".to_string(),
                    purdue_levels: vec![0, 1],
                    policy_group_ids: Vec::new(),
                    security_level: SecurityLevel::Sl3,
                    asset_count: ctrl_assets,
                },
                Zone {
                    id: "z-ent".to_string(),
                    name: "Enterprise Zone".to_string(),
                    purdue_levels: vec![4],
                    policy_group_ids: Vec::new(),
                    security_level: SecurityLevel::Sl1,
                    asset_count: ent_assets,
                },
            ],
            conduits: Vec::new(),
            zone_score: 1.0,
            recommendations: Vec::new(),
        }
    }

    fn ios_config(matrix: &CommunicationMatrix, model: &ZoneModel) -> EnforcementConfig {
        generate_enforcement_configs(matrix, model, &[])
            .into_iter()
            .find(|c| c.format == EnforcementFormat::CiscoIosAcl)
            .unwrap()
    }

    fn asa_config(matrix: &CommunicationMatrix, model: &ZoneModel) -> EnforcementConfig {
        generate_enforcement_configs(matrix, model, &[])
            .into_iter()
            .find(|c| c.format == EnforcementFormat::CiscoAsaAcl)
            .unwrap()
    }

    fn table_config(matrix: &CommunicationMatrix, model: &ZoneModel) -> EnforcementConfig {
        generate_enforcement_configs(matrix, model, &[])
            .into_iter()
            .find(|c| c.format == EnforcementFormat::GenericFirewallTable)
            .unwrap()
    }

    fn suricata_config(matrix: &CommunicationMatrix, model: &ZoneModel) -> EnforcementConfig {
        generate_enforcement_configs(matrix, model, &[])
            .into_iter()
            .find(|c| c.format == EnforcementFormat::SuricataRules)
            .unwrap()
    }

    fn json_config(matrix: &CommunicationMatrix, model: &ZoneModel) -> EnforcementConfig {
        generate_enforcement_configs(matrix, model, &[])
            .into_iter()
            .find(|c| c.format == EnforcementFormat::JsonPolicy)
            .unwrap()
    }

    // ── test_cisco_ios_permit_syntax ──────────────────────────────────────────

    #[test]
    fn test_cisco_ios_permit_syntax() {
        let matrix = make_matrix("modbus", 502, RuleRisk::Low);
        let model = make_model(2, 2);
        let cfg = ios_config(&matrix, &model);
        assert!(
            cfg.content.contains("permit tcp any any eq 502"),
            "IOS ACL must include: permit tcp any any eq 502"
        );
        assert!(
            cfg.content.contains("ip access-list extended"),
            "IOS ACL must begin with: ip access-list extended"
        );
    }

    // ── test_cisco_ios_deny_default ───────────────────────────────────────────

    #[test]
    fn test_cisco_ios_deny_default() {
        let matrix = make_matrix("modbus", 502, RuleRisk::Low);
        let model = make_model(2, 2);
        let cfg = ios_config(&matrix, &model);
        assert!(
            cfg.content.contains("deny ip any any log"),
            "IOS ACL must include trailing: deny ip any any log"
        );
    }

    // ── test_cisco_ios_remark ─────────────────────────────────────────────────

    #[test]
    fn test_cisco_ios_remark() {
        let matrix = make_matrix("modbus", 502, RuleRisk::Low);
        let model = make_model(2, 2);
        let cfg = ios_config(&matrix, &model);
        assert!(
            cfg.content.contains("! Remark:"),
            "IOS ACL must include ! Remark: lines for zone pair and per-rule justification"
        );
        // Zone pair name in remark.
        assert!(cfg.content.contains("Control Zone"));
        assert!(cfg.content.contains("Enterprise Zone"));
    }

    // ── test_cisco_asa_object_groups ──────────────────────────────────────────

    #[test]
    fn test_cisco_asa_object_groups() {
        // Zone with >3 assets triggers object-group network generation.
        let matrix = make_matrix("modbus", 502, RuleRisk::Low);
        let model = make_model(5, 2); // ctrl has 5 assets → object-group
        let cfg = asa_config(&matrix, &model);
        assert!(
            cfg.content.contains("object-group network"),
            "ASA ACL must include object-group for zones with >3 assets"
        );
        assert!(
            cfg.content.contains("OBJ-CONTROL_ZONE"),
            "object-group name must be derived from the zone name"
        );
        // Enterprise zone has only 2 assets — should NOT generate an object-group.
        let obj_group_count = cfg.content.matches("object-group network OBJ-").count();
        assert_eq!(
            obj_group_count, 1,
            "only the zone with >3 assets should get an object-group"
        );
    }

    // ── test_generic_table_header ─────────────────────────────────────────────

    #[test]
    fn test_generic_table_header() {
        let matrix = CommunicationMatrix {
            zone_pairs: Vec::new(),
            default_action: "deny".to_string(),
            coverage_percent: 0.0,
        };
        let model = make_model(0, 0);
        let cfg = table_config(&matrix, &model);
        let first_line = cfg.content.lines().next().unwrap_or("");
        assert!(
            first_line.contains("Action"),
            "first line must be the TSV header"
        );
        assert!(
            first_line.contains("Src Zone"),
            "header must include Src Zone"
        );
        assert!(
            first_line.contains('\t'),
            "header columns must be tab-separated"
        );
        assert!(
            cfg.content.contains("DENY"),
            "table must always include the default deny row"
        );
    }

    // ── test_suricata_pass ────────────────────────────────────────────────────

    #[test]
    fn test_suricata_pass() {
        let matrix = make_matrix("modbus", 502, RuleRisk::Low);
        let model = make_model(2, 2);
        let cfg = suricata_config(&matrix, &model);
        assert!(
            cfg.content.contains("pass tcp"),
            "Suricata rules must include a pass tcp rule for modbus/502"
        );
        assert!(
            cfg.content.contains("502"),
            "Suricata pass rule must reference destination port 502"
        );
        assert!(
            cfg.content.contains("KNK-ALLOW"),
            "Suricata pass rule msg must contain KNK-ALLOW prefix"
        );
    }

    // ── test_suricata_sid_range ───────────────────────────────────────────────

    #[test]
    fn test_suricata_sid_range() {
        let matrix = make_matrix("modbus", 502, RuleRisk::Low);
        let model = make_model(2, 2);
        let cfg = suricata_config(&matrix, &model);
        assert!(
            cfg.content.contains("sid:9000001"),
            "first Suricata SID must be 9000001"
        );
        assert!(
            cfg.content.contains("drop ip"),
            "Suricata rules must end with a default drop ip rule"
        );
        assert!(
            cfg.content.contains("KNK-DENY"),
            "Suricata drop rule msg must contain KNK-DENY prefix"
        );
    }

    // ── test_json_parseable ───────────────────────────────────────────────────

    #[test]
    fn test_json_parseable() {
        let matrix = make_matrix("modbus", 502, RuleRisk::Low);
        let model = make_model(2, 2);
        let cfg = json_config(&matrix, &model);
        let parsed: Result<serde_json::Value, _> = serde_json::from_str(&cfg.content);
        assert!(
            parsed.is_ok(),
            "JSON policy output must be valid JSON: {:?}",
            parsed.err()
        );
        let val = parsed.unwrap();
        assert!(val.get("rules").is_some(), "JSON must have a 'rules' field");
        assert!(val.get("zones").is_some(), "JSON must have a 'zones' field");
        assert!(
            val.get("default_action").is_some(),
            "JSON must have a 'default_action' field"
        );
        assert!(
            val.get("metadata").is_some(),
            "JSON must have a 'metadata' field"
        );
        // Verify the rule is in there with the expected protocol.
        let rules = val["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["protocol"], "modbus");
        // Vendor context field must be present (empty when no groups provided).
        assert!(
            rules[0].get("vendor_context").is_some(),
            "JSON rules must include vendor_context field"
        );
    }

    // ── test_all_five_formats ─────────────────────────────────────────────────

    #[test]
    fn test_all_five_formats() {
        let matrix = make_matrix("modbus", 502, RuleRisk::Low);
        let model = make_model(2, 2);
        let configs = generate_enforcement_configs(&matrix, &model, &[]);
        assert_eq!(
            configs.len(),
            5,
            "must generate exactly 5 enforcement configs"
        );
        // All five must be distinct formats.
        let mut seen_formats = std::collections::HashSet::new();
        for cfg in &configs {
            let fmt = format!("{:?}", cfg.format);
            assert!(
                seen_formats.insert(fmt.clone()),
                "duplicate format in output: {fmt}"
            );
        }
        assert_eq!(seen_formats.len(), 5, "all five formats must be distinct");
    }

    // ── test_rule_count_matches ───────────────────────────────────────────────

    #[test]
    fn test_rule_count_matches() {
        let mut matrix = make_matrix("modbus", 502, RuleRisk::Low);
        // Add a second rule to the same pair.
        matrix.zone_pairs[0].rules.push(PolicyRule {
            protocol: "http".to_string(),
            dst_port: Some(80),
            risk: RuleRisk::Low,
            justification: "Observed 50 packets".to_string(),
            packet_count: 50,
        });
        let model = make_model(2, 2);
        let cfg = ios_config(&matrix, &model);
        assert_eq!(
            cfg.rule_count, 2,
            "rule_count must match number of permit rules"
        );
    }

    // ── test_sanitize_acl_name ────────────────────────────────────────────────

    #[test]
    fn test_sanitize_acl_name() {
        assert_eq!(sanitize_acl_name("Control Zone"), "CONTROL_ZONE");
        assert_eq!(sanitize_acl_name("L1-Modbus"), "L1_MODBUS");
        assert_eq!(sanitize_acl_name("Enterprise IT"), "ENTERPRISE_IT");
        // Must not include spaces or special characters.
        let result = sanitize_acl_name("Test Zone (SL3)");
        assert!(!result.contains(' '));
        assert!(!result.contains('('));
    }

    // ── test_ip_helpers ───────────────────────────────────────────────────────

    #[test]
    fn test_ip_helpers() {
        // ip_to_network_and_wildcard
        assert_eq!(
            ip_to_network_and_wildcard("10.0.1.55"),
            Some(("10.0.1.0".to_string(), "0.0.0.255".to_string()))
        );
        assert_eq!(ip_to_network_and_wildcard("not-an-ip"), None);
        assert_eq!(ip_to_network_and_wildcard("1.2.3"), None);

        // ip_to_cidr
        assert_eq!(
            ip_to_cidr("192.168.100.200"),
            Some("192.168.100.0/24".to_string())
        );
        assert_eq!(ip_to_cidr("bad"), None);

        // protocol_to_transport
        assert_eq!(protocol_to_transport("modbus", Some(502)), "tcp");
        assert_eq!(protocol_to_transport("bacnet", Some(47808)), "udp");
        assert_eq!(protocol_to_transport("snmp", Some(161)), "udp");
        assert_eq!(protocol_to_transport("unknown_proto", None), "tcp");
    }

    // ── test_vendor_remark_in_cisco_ios ──────────────────────────────────────

    #[test]
    fn test_vendor_remark_in_cisco_ios() {
        use crate::{Criticality, DeviceCategory, PolicyGroup};

        let matrix = make_matrix("s7comm", 102, RuleRisk::Low);

        // Create a group with vendor suffix "Siemens" and attach it to z-ctrl.
        let group = PolicyGroup::new(
            "L1-S7-Siemens",
            vec!["10.0.0.1".to_string()],
            Some(1),
            DeviceCategory::Plc,
            SecurityLevel::Sl3,
            Criticality::High,
        );

        let model = ZoneModel {
            zones: vec![
                Zone {
                    id: "z-ctrl".to_string(),
                    name: "Control Zone".to_string(),
                    purdue_levels: vec![0, 1],
                    policy_group_ids: vec![group.id.clone()],
                    security_level: SecurityLevel::Sl3,
                    asset_count: 2,
                },
                Zone {
                    id: "z-ent".to_string(),
                    name: "Enterprise Zone".to_string(),
                    purdue_levels: vec![4],
                    policy_group_ids: Vec::new(),
                    security_level: SecurityLevel::Sl1,
                    asset_count: 2,
                },
            ],
            conduits: Vec::new(),
            zone_score: 1.0,
            recommendations: Vec::new(),
        };

        let configs = generate_enforcement_configs(&matrix, &model, &[group]);
        let ios = configs
            .iter()
            .find(|c| c.format == EnforcementFormat::CiscoIosAcl)
            .unwrap();

        assert!(
            ios.content.contains("Siemens"),
            "IOS ACL must include Siemens vendor remark when group name encodes vendor.\nGot:\n{}",
            ios.content
        );
        assert!(
            ios.content.contains("S7comm PLC communication"),
            "IOS ACL must include vendor port context for Siemens/102"
        );
    }

    // ── test_vendor_port_context ─────────────────────────────────────────────

    #[test]
    fn test_vendor_port_context() {
        // Known combinations.
        assert_eq!(
            vendor_port_context("Siemens", 102),
            Some("S7comm PLC communication")
        );
        assert_eq!(
            vendor_port_context("Siemens AG", 443),
            Some("SCALANCE web management")
        );
        assert_eq!(
            vendor_port_context("Rockwell Automation", 44818),
            Some("EtherNet/IP explicit messaging")
        );
        assert_eq!(
            vendor_port_context("Schneider Electric", 502),
            Some("Modbus TCP")
        );
        assert_eq!(vendor_port_context("ABB Ltd", 502), Some("Modbus TCP"));
        assert_eq!(vendor_port_context("Honeywell", 502), Some("Modbus TCP"));
        // Unknown combination.
        assert_eq!(vendor_port_context("Siemens", 80), None);
        assert_eq!(vendor_port_context("UnknownVendor", 502), None);
    }
}
