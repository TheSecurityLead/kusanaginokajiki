# CLAUDE.md — Kusanagi Kajiki (草薙カジキ)

## Project Identity

**Kusanagi Kajiki** (草薙の梶木) is a modern ICS/SCADA passive network discovery and topology visualization tool — a ground-up rewrite of the NSA's archived [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN). The name is a bilingual nod to the original: 草 (kusa/grass) + marlin (kajiki/カジキ), with Kusanagi (草薙) referencing the legendary sword from Japanese mythology.

**This is a functional tool for real OT security assessments, not a demo or portfolio toy.** Correctness and reliability take priority over feature velocity. If something works wrong in an ICS environment, the consequences can be physical.

**Design goal:** Full feature parity with GRASSMARLIN 3.2, plus modern capabilities GRASSMARLIN never had (MITRE ATT&CK mapping, Purdue Model enforcement, Zeek/Suricata ingestion, PDF reporting, baseline drift detection, and more).

### Naming Convention
Display name: **Kusanagi Kajiki** (草薙カジキ). Binary/package: **`kusanaginokajiki`**. All grassmarlin references cleaned up in Phase 6.

## Developer Context

The developer is learning Rust through this project (beginner level). When writing Rust code:
- Prefer explicit, readable patterns over clever abstractions
- Add comments explaining non-obvious Rust idioms
- Use `thiserror` for error types, `.map_err()` chains over `unwrap()` — never panic in library crates
- Use `clone()` freely; optimize later when profiling shows it matters

## Before You Start — Verify Project State

**This project has completed Phases 0–9. Do NOT recreate files that already exist.** Before writing any code, read the following files to understand what's built:

**Core config (read first):**
```
src-tauri/Cargo.toml                         # Workspace: kusanaginokajiki, deps inc. serde_yaml, zip, quick-xml, genpdf
src-tauri/tauri.conf.json                    # "kusanaginokajiki" everywhere
src-tauri/capabilities/default.json          # Tauri 2.0 permissions (dialog, shell)
package.json                                 # --legacy-peer-deps on Fedora
```

**Rust backend (Phases 0–9 complete):**
```
src-tauri/src/main.rs                        # All commands registered (import, live x5, signatures x3, session x8, physical x6, ingest x4, wireshark x6, export x8)
src-tauri/src/commands/mod.rs                # AppState: SignatureEngine, deep_parse_info, live_capture, processing_thread, oui_lookup, geoip_lookup, db, current_session, physical_topology
src-tauri/src/commands/system.rs             # list_interfaces, get_app_info
src-tauri/src/commands/capture.rs            # import_pcap + start/stop/pause/resume/status
src-tauri/src/commands/processor.rs          # PacketProcessor: protocol ID → deep parse → signatures → topology → OUI/GeoIP
src-tauri/src/commands/data.rs               # get_topology, assets, connections, connection_packets, deep_parse_info, fc_stats
src-tauri/src/commands/signatures.rs         # get/reload/test signatures
src-tauri/src/commands/session.rs            # save/load/list/delete session, update/bulk assets, export/import .kkj
src-tauri/src/commands/physical.rs           # Cisco config/CAM/CDP/ARP import, get/clear physical topology
src-tauri/src/commands/ingest.rs             # import_zeek_logs, import_suricata_eve, import_nmap_xml, import_masscan_json + merge
src-tauri/src/commands/wireshark.rs          # detect/open Wireshark, get_connection_frames, export/save_frames_csv
src-tauri/src/commands/export.rs             # export_assets_csv, export_connections_csv, export_topology_json, export_assets_json, generate_pdf_report, export_sbom_json, export_sbom_csv, export_stix_bundle
src-tauri/crates/gm-capture/src/            # lib, error, interface, packet, pcap_reader, parsing (shared), live (LiveCaptureHandle)
src-tauri/crates/gm-parsers/src/            # lib (DeepParseResult, deep_parse()), protocol (19 variants + from_name() + to_name()), modbus, dnp3
src-tauri/crates/gm-signatures/src/         # lib, signature, engine (SignatureEngine), error
src-tauri/crates/gm-topology/src/           # lib (TopologyBuilder)
src-tauri/crates/gm-db/src/                 # lib (Database), error, schema, sessions, assets, connections, oui (OuiLookup), geoip (GeoIpLookup)
src-tauri/crates/gm-physical/src/           # lib (PhysicalTopology, PhysicalSwitch, etc.), cisco (IOS parsers)
src-tauri/crates/gm-ingest/src/             # lib (IngestResult, IngestSource), zeek, suricata, nmap, masscan, error
src-tauri/crates/gm-report/src/             # lib, pdf (genpdf), csv_export, json_export, sbom, stix, error (19 tests)
src-tauri/signatures/                        # 25 YAML signature files
src-tauri/data/oui.tsv                       # IEEE OUI database (~30k entries)
src-tauri/data/dbip-country-lite.mmdb        # DB-IP Lite GeoIP database
```

**Frontend (Phases 0–9 complete):**
```
src/app.html, src/app.css                    # Shell + design tokens
src/routes/+layout.svelte                    # Sidebar: Signatures, Protocols, Physical, Export tabs
src/routes/+layout.ts, +page.svelte          # SSR disabled, topology sub-tabs + view routing (inc. export)
src/lib/types/index.ts                       # All types: Capture*, Session*, Asset, Ingest*, Wireshark*, Frame*, ReportConfig, SbomEntry, ExportFormat, ViewTab variants
src/lib/types/cytoscape-fcose.d.ts
src/lib/stores/index.ts                      # All stores: capture*, sessions, currentSession, physicalHighlightIp + topology tab helpers
src/lib/utils/tauri.ts                       # All wrappers: capture, signatures, session, physical, ingest, wireshark, export (8 functions), events
src/lib/utils/graph.ts                       # BFS, filtering, scaling, grouping, colors
src/lib/components/CaptureView.svelte        # Import + live capture + session management + external tool import
src/lib/components/ConnectionTree.svelte     # Node → connection → packet tree + Wireshark context menu + View Frames
src/lib/components/InventoryView.svelte      # Table + edit + detail + bulk + OUI + country + confidence
src/lib/components/LogicalView.svelte        # fcose, compound, grouping, vendor labels, Wireshark + "Show in Physical"
src/lib/components/MeshView.svelte           # All-to-all mesh, filters
src/lib/components/FilteredView.svelte       # Subset, hide nodes
src/lib/components/WatchTab.svelte           # N-degree, 500ms refresh
src/lib/components/SignatureEditor.svelte    # CodeMirror 6, test button
src/lib/components/ProtocolStats.svelte      # Traffic bars, FC distribution
src/lib/components/PhysicalView.svelte       # Switch/port Cytoscape graph, import panel, cross-reference
src/lib/components/ExportView.svelte         # Data exports (CSV/JSON), topology image (PNG/SVG), PDF report form, SBOM (JSON/CSV), STIX 2.1 bundle
src/lib/components/SettingsView.svelte       # DB path, OUI count, GeoIP status, reset
.github/workflows/ci.yml
```

**Rules for working with existing code:**
1. **Read before writing.** If a file exists, read it first. Extend or modify — don't duplicate.
2. **Preserve Phases 0–9 functionality.** Everything must keep working.
3. **Follow established patterns.** Error handling, Tauri commands, PacketProcessor pipeline, store management.
4. **Add new crates to workspace.** New crates in `src-tauri/crates/`, add to `Cargo.toml`.
5. **Register new commands** in `main.rs` + typed wrappers in `tauri.ts`.
6. **Use `kusanaginokajiki` everywhere.**

## Phased Implementation

**Only implement the phase currently marked 🔨 CURRENT.**

---

### Phase 0 — Foundation ✅ DONE
### Phase 1 — PCAP Import & Basic Parsing ✅ DONE
### Phase 2 — Topology Visualization ✅ DONE
### Phase 3 — Signature Engine ✅ DONE
### Phase 4 — Deep Protocol Parsing ✅ DONE
### Phase 5 — Live Capture ✅ DONE

### Phase 6 — Persistence & Asset Management ✅ DONE
> SQLite, sessions, MAC OUI, GeoIP, inline editing, .kkj ZIP archives

### Phase 7 — Physical Topology ✅ DONE
> Cisco config/CAM/CDP/ARP import, PhysicalView, cross-reference with logical

### Phase 8 — Wireshark & External Tool Integration ✅ DONE
> gm-ingest (Zeek/Suricata/Nmap/Masscan), Wireshark launch + View Frames, source tagging

### Phase 9 — Export & Reporting ✅ DONE
> Professional outputs for assessment deliverables

**gm-report crate (19 tests):**
- [x] PDF report generation (genpdf): executive summary, asset inventory table, protocol analysis, findings, recommendations — configurable via ReportConfig (assessor, client, date, title, section toggles)
- [x] CSV export: assets, connections (manual string building, Clippy: no needless `Ok()?`)
- [x] JSON export: topology, assets (serde_json)
- [x] SBOM export (CISA BOD 23-01): IP, MAC, hostname, vendor, product, firmware, protocols, zone — JSON + CSV formats
- [x] STIX 2.1 bundle: Cyber Observable objects for assets, Relationship objects for connections, Indicator objects for findings

**Export Commands (commands/export.rs — 8 commands):**
- [x] `export_assets_csv`, `export_connections_csv`, `export_topology_json`, `export_assets_json`
- [x] `generate_pdf_report(config: ReportConfig)`
- [x] `export_sbom_json`, `export_sbom_csv`
- [x] `export_stix_bundle`
- [x] Clippy fixes: `.replace(['\n', '\r'], "")` not chained, `strip_prefix()` not manual

**Frontend — ExportView.svelte:**
- [x] Data Exports section: 2×2 card grid (Assets CSV, Connections CSV, Topology JSON, Assets JSON)
- [x] Topology Image section: PNG + SVG export via Cytoscape cy.png()/cy.svg()
- [x] PDF Assessment Report section: form (assessor, client, date, title) + 5 section checkboxes + generate button
- [x] SBOM section: JSON/CSV format selector + export button
- [x] STIX 2.1 Bundle section: single export button
- [x] Status banner, busy state, empty state notice, save dialogs via @tauri-apps/plugin-dialog
- [x] Types: ReportConfig, SbomEntry, ExportFormat + tauri wrappers (8 functions)
- [x] Sidebar: "Export" nav item, ViewTab 'export' variant

- [x] 103 tests passing (19 new in gm-report + 84 existing), clippy clean, npm check 0 errors (4 pre-existing a11y warnings)
- [x] Deliverable: "Generate Report" → PDF. CSV/JSON/SVG/PNG exports. SBOM + STIX 2.1 ✅

---

### Phase 10 — Security Analysis 🔨 CURRENT
> ATT&CK, Purdue, anomaly scoring, TLS, Shodan

**MITRE ATT&CK for ICS (`gm-analysis`):**
- [ ] T0855 (Modbus broadcast writes), T0814 (FC 8 diagnostics), T0856 (DNP3 unsolicited), T0846 (unknown polling), T0886 (cross-zone)
- [ ] Findings panel: severity, affected assets, evidence

**Purdue Model — `PurdueOverlay.svelte`:**
- [ ] Auto-assign: L1=PLCs/RTUs, L2=HMIs, L3=Historians, L4-5=IT
- [ ] Cross-level violation detection + highlighting
- [ ] Manual override, color-coded zones

**Anomaly Scoring:**
- [ ] Polling deviation, role reversal, new devices, unexpected subnets
- [ ] Severity + confidence + evidence per anomaly

**TLS Fingerprinting:**
- [ ] Flag unencrypted OT (Modbus=always cleartext), JA3/JA4, deprecated TLS 1.0/1.1

**Shodan/Censys (optional, reqwest):**
- [ ] Public IP lookup, API key in settings, opt-in only

- [ ] Deliverable: Purdue overlay + findings: "3 ATT&CK TTPs, 2 Purdue violations, 87% unencrypted"

---

### Phase 11 — Advanced Features
> Baseline drift, timeline, OPC UA certs, plugins, multi-user, theming

- [ ] Baseline drift (new/missing/changed), timeline scrubber, OPC UA cert extraction
- [ ] Plugin architecture, CLI, multi-user merge, dark/light theme
- [ ] Deliverable: Baseline from last quarter → drift report

---

## Phase Summary

| Phase | Scope | Status |
|-------|-------|--------|
| **0** | Foundation | ✅ |
| **1** | PCAP Import | ✅ |
| **2** | Topology Visualization | ✅ |
| **3** | Signature Engine | ✅ |
| **4** | Deep Protocol Parsing | ✅ |
| **5** | Live Capture | ✅ |
| **6** | Persistence & Asset Management | ✅ |
| **7** | Physical Topology | ✅ |
| **8** | External Tool Integration | ✅ |
| **9** | Export & Reporting | ✅ |
| **10** | Security Analysis | 🔨 |
| **11** | Advanced Features | — |

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│  SvelteKit Frontend (Tauri Webview)                        │
│  ├── LogicalView      (fcose + Wireshark + Show Physical)  │
│  ├── PhysicalView     (switch/port Cytoscape)              │
│  ├── MeshView         (all-to-all mesh)                    │
│  ├── InventoryView    (table + edit + detail + bulk)       │
│  ├── CaptureView      (import + live + sessions + ingest)  │
│  ├── ProtocolStats    (traffic + FCs)                      │
│  ├── SignatureEditor  (YAML editor)                        │
│  ├── ExportView       (CSV/JSON/PDF/SBOM/STIX)            │
│  └── Settings                                              │
├────────────────────────────────────────────────────────────┤
│  Tauri IPC: Commands + Events (capture_stats/error)        │
├────────────────────────────────────────────────────────────┤
│  Rust Backend                                              │
│  ├── gm-capture/   (pcap, live, parsing)                   │
│  ├── gm-parsers/   (protocol ID, Modbus/DNP3 deep)        │
│  ├── gm-signatures/ (YAML engine)                          │
│  ├── gm-topology/  (petgraph)                              │
│  ├── gm-db/        (SQLite, OUI, GeoIP)                   │
│  ├── gm-physical/  (Cisco config/CAM/CDP/ARP)             │
│  ├── gm-ingest/    (Zeek, Suricata, Nmap, Masscan)        │
│  ├── gm-report/    (PDF, CSV, JSON, SBOM, STIX)           │
│  ├── gm-analysis/  (ATT&CK, Purdue, anomaly — Ph 10 now) │
│  └── commands/     (processor, export, wireshark, etc.)    │
└────────────────────────────────────────────────────────────┘
```

### Crate Responsibilities

| Crate | Does | Does NOT |
|-------|------|----------|
| `gm-capture` | PCAPs, L2-L4, interfaces, live capture, ring buffer | ICS protocols, UI, Tauri |
| `gm-parsers` | Protocol ID, Modbus/DNP3 deep parse | Network, state, Tauri |
| `gm-signatures` | YAML fingerprints, confidence scoring | Raw packet parsing |
| `gm-topology` | Directed graph (petgraph) | Protocol knowledge |
| `gm-db` | SQLite CRUD, OUI lookup, GeoIP lookup | Parsing, network |
| `gm-physical` | Cisco config/CAM/CDP/ARP, physical topology | Capture, logical topology |
| `gm-ingest` | Zeek, Suricata, Nmap, Masscan import | Capture directly |
| `gm-report` | PDF (genpdf), CSV, JSON, SBOM, STIX 2.1 | UI, capture |
| `gm-analysis` | **ATT&CK, Purdue, anomaly scoring (Ph 10 — implement now)** | Parsing, persistence |
| `commands/processor.rs` | Shared pipeline: parse → deep → sigs → topo → OUI/GeoIP | Own state |

**Data flows:** capture/ingest → parsers → signatures → topology → analysis → db → report → frontend.

---

## Tech Stack

### Rust Backend
Tauri 2.0, pcap, etherparse, petgraph, serde/serde_json/serde_yaml, tokio, thiserror, chrono, uuid, rusqlite (bundled), maxminddb, dirs (v6), zip (v2), regex, quick-xml, genpdf.

### Frontend
SvelteKit (Svelte 5), TypeScript (strict), Cytoscape.js + fcose, Tailwind CSS 4, @tauri-apps/api + plugins (dialog, shell), CodeMirror 6.

---

## ICS/SCADA Domain Knowledge

### Why Passive Only
Active scanning can crash PLCs. This tool ONLY observes — never generates packets. Live capture = promiscuous receive only.

### Protocol → Port Mapping
502=Modbus, 20000=DNP3, 44818=EtherNet/IP, 2222=EtherNet/IP I/O, 47808=BACnet, 102=S7comm, 4840=OPC UA, 34962-34964=PROFINET, 2404=IEC104, 1883/8883=MQTT, 5094=HART-IP, 1089-1091=FF HSE, 18245-18246=GE SRTP, 5007=Wonderware SuiteLink.

### Device Classification
Port-based heuristics + signature + deep parse + OUI enrichment all active (Phases 1-6).

### Purdue Model (Phase 10 — implement now)
- **L0** — sensors/actuators, **L1** — PLCs/RTUs, **L2** — HMIs, **L3** — Historians/SCADA, **L3.5** — DMZ, **L4-5** — Enterprise IT
- Cross-level communication = security finding
- Auto-assign heuristics: Port 502/44818/102 responder → L1, multi-OT client → L2, OPC UA/high fan-out → L3, IT-only → L4-5

### MITRE ATT&CK for ICS Mappings (Phase 10 — implement now)

| Behavior | Technique | Severity |
|----------|-----------|----------|
| Unknown device polling PLCs | T0846 Remote System Discovery | High |
| Modbus broadcast writes (FC 5/6/15/16 to 0.0.0.0 or Unit 255) | T0855 Unauthorized Command Message | Critical |
| Modbus FC 8 from non-engineer | T0814 Denial of Service | High |
| DNP3 unsolicited (FC 130) to unknown master | T0856 Modify Alarm Settings | Medium |
| Cross-Purdue communication (L1↔L4) | T0886 Remote Services | Medium |

---

## Common Pitfalls

### Rust / Backend
1. No `unwrap()` in library crates — `?` / `.map_err()`
2. Tauri commands: `Result<T, String>`, convert with `.map_err(|e| e.to_string())`
3. etherparse 0.16: `tcp.payload()` / `udp.payload()`, not `SlicedPacket.payload`
4. pcap `PacketHeader`: dereference with `*raw_packet.header`
5. Clippy: range patterns, `.contains()`, `.is_multiple_of()`, `allow(type_complexity)`, `.get()` returns ref, `.replace(['\n', '\r'], "")` not chained, `strip_prefix()` not manual, no needless `Ok()?`
6. TopologyBuilder: borrow checker fix applied
7. PacketProcessor: shared pipeline in processor.rs, import + live both use it
8. gm-signatures: PacketData decoupled from gm-capture
9. gm-db: rusqlite bundled, WAL mode, FK enforcement, `dirs` (v6), `zip` (v2)
10. OUI/GeoIP: loaded on AppState::new(), passed to build_assets(), graceful fallback
11. AssetInfo: oui_vendor/country/is_public_ip use `#[serde(default)]`
12. IcsProtocol: `from_name()` for deserialization, `to_name()` for snake_case (Debug gives wrong names)
13. gm-ingest: quick-xml 0.37 `@attr` for Nmap XML; Masscan needs `clean_masscan_json()`
14. gm-physical: normalize_mac() for Cisco dot format, shorten_interface_name()
15. Wireshark: std::process::Command, no plugin-fs (save_frames_csv command)
16. gm-report: genpdf for PDF, manual CSV builder (no csv crate), serde_json for JSON/SBOM/STIX
17. **NEVER generate network traffic**

### Frontend / Build
18. Static adapter only, no `+page.server.ts`
19. Fedora/WSL2: `npm install --legacy-peer-deps`
20. Build order: `npm run build` before `cargo check`
21. Icons: RGBA PNGs, tauri.conf.json: no `app.title`
22. Dynamic import Cytoscape.js, Svelte 5 no event modifiers
23. cytoscape-fcose: .d.ts + guard flag, compound nodes: `parent` + `'compound'` class
24. Context menus: fixed-position div + window listener
25. CodeMirror 6: codemirror, @codemirror/lang-yaml, theme-one-dark, state, view
26. Tauri plugins: dialog (open+save), shell (open); NO plugin-fs

### General
27. Confidence: 1=port, 2=pattern, 3=OUI, 4=payload, 5=deep parse
28. Signatures: runtime YAML in `src-tauri/signatures/`
29. Sessions: SQLite + .kkj ZIP archives
30. DB path: `~/.kusanaginokajiki/data.db`
31. **All identifiers: `kusanaginokajiki`**
32. Active scan data (Nmap/Masscan) gets `[active-scan]` tag
33. Findings table already exists in DB schema (Phase 6) — Phase 10 populates it

---

## Build & Test

```bash
# Fedora WSL2
sudo dnf install libpcap-devel webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel
npm install --legacy-peer-deps
npm run build
npm run tauri dev       # dev
npm run tauri build     # production

# Tests
cd src-tauri && cargo test --all       # 103 tests as of Phase 9
cargo clippy --all -- -D warnings
npm run check
```

**Other:** Ubuntu: libpcap-dev libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf. macOS: brew install libpcap. Windows: Npcap + SDK.
