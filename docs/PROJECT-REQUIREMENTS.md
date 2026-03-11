# PROJECT-REQUIREMENTS.md — Kusanagi Kajiki Implementation Tracking

## Phase Summary

| Phase | Scope | Tests | Status |
|-------|-------|-------|--------|
| 0–11 | Foundation through Advanced Features | 127 | ✅ Complete |
| 12 | Protocol Expansion (5 deep parsers, ATT&CK, signatures, frontend) | ~157 | ✅ Complete |
| **13A** | **Quick Win Features (10 features)** | **~175** | 🔧 In Progress |
| **13B** | **Next Release Features (3 features)** | **~190** | 📋 Planned |
| **13C** | **Roadmap (CVE database, baseline, timeline, malware detection)** | **~210** | 📋 Future |

---

## Phase 13A — Quick Win Features

### Deliverables

| # | Feature | File(s) | Effort | Status |
|---|---------|---------|--------|--------|
| 1 | Default Credential Warnings | `gm-analysis/src/default_creds.rs` + `data/default_credentials.json` | S | ☐ TODO |
| 2 | Remediation Priority List | `gm-report/src/remediation.rs` + `ExportView.svelte` | S | ☐ TODO |
| 3 | Flat Network Detection | `gm-analysis/src/attack.rs` (new detection) | S | ☐ TODO |
| 4 | Protocol Encryption Audit | `gm-analysis/src/attack.rs` (new detection) | S | ☐ TODO |
| 5 | Wireshark Filter Generation | `InventoryView.svelte` / `ConnectionTree.svelte` (frontend only) | S | ☐ TODO |
| 6 | Quick Capture Summary | `CaptureView.svelte` + new `CaptureStats` Tauri command | S | ☐ TODO |
| 7 | SNMP Community String Detection | `gm-parsers/src/snmp.rs` (minimal parser) | S | ☐ TODO |
| 8 | Internet Exposure Check | `gm-analysis/src/attack.rs` + Shodan query generation | S | ☐ TODO |
| 9 | Device Naming Suggestions | `gm-analysis/src/naming.rs` + `InventoryView.svelte` | S | ☐ TODO |
| 10 | Asset Criticality Scoring | `gm-analysis/src/risk.rs` | S | ☐ TODO |

### Acceptance Criteria
- [ ] Default creds: ≥30 ICS device entries, check_device() returns matches, yellow warning in UI
- [ ] Remediation list: sorted by severity, actionable recommendations, exportable
- [ ] Flat network: auto-detect >80% devices on same subnet as critical finding
- [ ] Encryption audit: flag all cleartext OT protocols, compute unencrypted percentage
- [ ] Wireshark filter: right-click → copy filter for any device or connection
- [ ] Capture summary: show packet count, duration, protocol breakdown, device count after import
- [ ] SNMP: extract community strings from SNMPv1/v2c, flag "public"/"private" defaults
- [ ] Internet exposure: flag public IPs on OT devices, generate Shodan query
- [ ] Device naming: suggest "PLC-10.0.1.15" style names, accept/override
- [ ] Criticality: PLC/RTU/Safety=Critical, HMI/EWS=High, Historian=Medium, IT=Low

---

## Phase 13B — Next Release Features

### Deliverables

| # | Feature | File(s) | Effort | Status |
|---|---------|---------|--------|--------|
| 1 | Purdue Layered Topology Layout | `src/lib/layouts/purdueLayout.ts` + `PurdueOverlay.svelte` | M | ☐ TODO |
| 2 | Communication Pattern Analysis | `gm-analysis/src/comm_patterns.rs` + `CommunicationPatterns.svelte` | M | ☐ TODO |
| 3 | Project/Engagement Management | `gm-db` schema + `commands/projects.rs` + `ProjectsView.svelte` | M | ☐ TODO |

### Acceptance Criteria
- [ ] Purdue layout: nodes constrained to horizontal bands by level, colored overlays, export as PNG
- [ ] Comm patterns: per-connection stats (interval, jitter, periodicity), anomaly flagging, sortable table
- [ ] Projects: named engagements with metadata, session scoping, persist across restarts

---

## Phase 13C — Roadmap

| # | Feature | Effort | Status |
|---|---------|--------|--------|
| 1 | Bundled CVE/NVD Database (gm-vuln crate) | L | 📋 Future |
| 2 | Baseline Comparison + Delta Report | L | 📋 Future |
| 3 | Timeline Scrubber (timestamp-indexed filtering) | L | 📋 Future |
| 4 | ICS Malware Pattern Detection (FrostyGoop, PIPEDREAM) | M | 📋 Future |
| 5 | IEC 62443 Zone/Conduit Mapping | L | 📋 Future |
| 6 | Attack Path Visualization | L | 📋 Future |
| 7 | Finding Templates / Knowledge Base | M | 📋 Future |
