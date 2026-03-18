# CLAUDE.md — Kusanagi Kajiki (草薙カジキ)

## Project Identity

**Kusanagi Kajiki** (草薙の梶木) — modern ICS/SCADA passive network discovery tool. Ground-up Rust rewrite of NSA's archived GRASSMARLIN. Binary: **`kusanaginokajiki`**. Passive only — NEVER generate network traffic.

## Documentation

| Document | Contents |
|----------|----------|
| `docs/ARCHITECTURE.md` | Crate structure, data pipeline, frontend component map |
| `docs/PROJECT-REQUIREMENTS.md` | Phase tracking, deliverables, test counts |
| `docs/PRODUCT-REQUIREMENTS.md` | Feature specs, ATT&CK detections, protocol matrix |
| `docs/PROTOCOL-DEEP-PARSE.md` | Wire formats, Rust structs, test payloads |
| `docs/CHANGELOG.md` | Phase-by-phase delivery history |

## Current State

**Phases 0–15E complete. 431 tests passing. 95 Tauri commands. 31 YAML signatures. 10 deep-parsed protocols. 28k+ lines across 11 Rust crates.**

### Phase 15 — Microsegmentation Recommendation Engine

> Identity groups, IEC 62443 zones/conduits, enforcement configs, policy simulation

- gm-segmentation crate (11th): SegmentationInput/AssetProfile/ObservedConnection decoupled from Tauri state
- 15A: Identity Group Engine — clusters by Purdue level, role, vendor, communication community
- 15B: Zone/Conduit Recommender — IEC 62443 zone boundaries, conduit definitions, flat network detection, compliance.rs integration
- 15C: Least-Privilege Matrix — per-zone-pair allow rules with risk classification, extends allowlist.rs
- 15D: Enforcement Export — Cisco IOS ACL, Cisco ASA, generic firewall, Suricata rules, JSON policy
- 15E: Policy Simulation — replay traffic vs policy, risk reduction scoring, false positive detection via comm_patterns.rs
- SegmentationView.svelte: 5 tabs (Policy Groups, Zones, Matrix, Enforcement, Simulation)
- Commands: run_segmentation, export_enforcement_config
- Consumes: purdue.rs, risk.rs, infrastructure.rs, comm_patterns.rs, allowlist.rs, compliance.rs

## Rules

1. Read before writing. 2. Preserve existing functionality. 3. Follow established patterns.
4. Register new commands in `main.rs` + `tauri.ts`. 5. Use `kusanaginokajiki` everywhere.
6. No `unwrap()` in library crates. 7. Cross-platform casts for pcap headers.
8. Data bundled via `include_str!` — no network calls for core features.

## File Map

**Backend:** `src-tauri/src/commands/` (system, capture, processor, data, signatures, session, baseline, physical, ingest, wireshark, export, analysis, correlation, patterns, projects, segmentation) + `src-tauri/crates/` (gm-capture, gm-parsers, gm-signatures, gm-topology, gm-db, gm-physical, gm-ingest, gm-report, gm-analysis, gm-segmentation)
**Frontend:** `src/lib/components/` (20 views), `src/lib/layouts/purdueLayout.ts`, `src/lib/types/index.ts`, `src/lib/stores/index.ts`, `src/lib/utils/tauri.ts`

## Pitfalls

- Tauri commands: `Result<T, String>` with `.map_err(|e| e.to_string())`
- pcap `PacketHeader`: cast `tv_sec as i64`, `tv_usec as u32` (i32 on Windows)
- Plugin config: `null` not `{}` in tauri.conf.json
- Build order: `npm run build` before `cargo check`
- DB: `~/.kusanaginokajiki/data.db`, rusqlite bundled, WAL mode
- gm-segmentation: Consumes purdue.rs, risk.rs, comm_patterns.rs, allowlist.rs, compliance.rs outputs. No crate dependency on gm-analysis.
- Enforcement configs: Cisco ACL names sanitized uppercase. Suricata SIDs start 9000001.
- Zone score: 1.0 = perfect segmentation, 0.0 = flat. Cross-Purdue violation ratio.
- SCALANCE detection: classify_scalance_model() in infrastructure.rs classifies by model prefix (X→Switch, W→AP, M→Router, S→Firewall). AssetSnapshot has hostname + product_family fields for LLDP/SNMP enrichment.

## Protocols

10 deep-parsed: Modbus, DNP3, EtherNet/IP, S7comm, BACnet, IEC 104, PROFINET DCP, LLDP, SNMP, Redundancy (MRP/RSTP/HSR/PRP/DLR). 19+ total detected by port+signature.

## Build

```bash
npm install && npm run build && npm run tauri dev
cd src-tauri && cargo test --all && cargo clippy --all -- -D warnings && cd .. && npm run check
```
