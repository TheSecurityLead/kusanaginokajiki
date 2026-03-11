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
| `docs/knk-feature-roadmap.md` | Full roadmap, competitive analysis, implementation sketches |

## Current State

Phases 0–12 complete. Phase 13 (feature expansion) in progress.

**Phase 13A (Quick Wins):** Default creds, remediation priority, flat network detection, encryption audit, Wireshark filters, capture summary, SNMP strings, internet exposure, device naming, criticality scoring.
**Phase 13B (Next Release):** Purdue layered layout, communication patterns, project management.

## Rules

1. Read before writing. 2. Preserve existing functionality. 3. Follow established patterns.
4. Register new commands in `main.rs` + `tauri.ts`. 5. Use `kusanaginokajiki` everywhere.
6. No `unwrap()` in library crates. 7. Cross-platform casts for pcap headers.
8. Data bundled via `include_str!` — no network calls for core features.

## File Map

**Backend:** `src-tauri/src/commands/` (system, capture, processor, data, signatures, session, baseline, physical, ingest, wireshark, export, analysis) + `src-tauri/crates/` (gm-capture, gm-parsers, gm-signatures, gm-topology, gm-db, gm-physical, gm-ingest, gm-report, gm-analysis)
**Frontend:** `src/lib/components/`, `src/lib/types/index.ts`, `src/lib/stores/index.ts`, `src/lib/utils/tauri.ts`

## Pitfalls

- Tauri commands: `Result<T, String>` with `.map_err(|e| e.to_string())`
- pcap `PacketHeader`: cast `tv_sec as i64`, `tv_usec as u32` (i32 on Windows)
- Plugin config: `null` not `{}` in tauri.conf.json
- Build order: `npm run build` before `cargo check`
- DB: `~/.kusanaginokajiki/data.db`, rusqlite bundled, WAL mode

## Protocols

7 deep-parsed: Modbus, DNP3, EtherNet/IP, S7comm, BACnet, IEC 104, PROFINET DCP. 19 total detected by port+signature.

## Build

```bash
npm install && npm run build && npm run tauri dev
cd src-tauri && cargo test --all && cargo clippy --all -- -D warnings && cd .. && npm run check
```
