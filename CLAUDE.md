# CLAUDE.md — Kusanagi Kajiki (草薙カジキ)

## Project Identity

**Kusanagi Kajiki** (草薙の梶木) — modern ICS/SCADA passive network discovery tool. Ground-up Rust rewrite of NSA's archived [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN). Display name: **Kusanagi Kajiki** (草薙カジキ). Binary/package: **`kusanaginokajiki`**.

**This is a functional tool for real OT security assessments.** Correctness and reliability over feature velocity. Passive only — NEVER generate network traffic.

## External Documentation (READ THESE)

| Document | Contents |
|----------|----------|
| `docs/ARCHITECTURE.md` | Full architecture diagram, data pipeline, crate structure, frontend component map |
| `docs/PROJECT-REQUIREMENTS.md` | Implementation tracking, phase status, test counts, technical debt |
| `docs/PRODUCT-REQUIREMENTS.md` | Feature requirements, protocol support matrix, ATT&CK detections |
| `docs/PROTOCOL-DEEP-PARSE.md` | Wire formats, Rust struct definitions, test payloads for all deep-parsed protocols |

## Current State

**Phases 0–11 complete (127 tests passing).** Protocol expansion (Phase 12) in progress — adding 5 new deep parsers.

## Developer Context

Rust beginner. Prefer explicit, readable code. Use `thiserror` for errors, `.map_err()` chains, never `unwrap()` in library crates. Use `clone()` freely.

## Core File Map

### Config
```
src-tauri/Cargo.toml                         # Workspace + all deps
src-tauri/tauri.conf.json                    # "kusanaginokajiki" everywhere
src-tauri/capabilities/default.json          # dialog, shell permissions
package.json                                 # npm config
```

### Rust Backend
```
src-tauri/src/main.rs                        # Command registration + CLI (clap)
src-tauri/src/commands/mod.rs                # AppState definition
src-tauri/src/commands/system.rs             # list_interfaces, get_app_info, settings, plugins
src-tauri/src/commands/capture.rs            # import_pcap + live capture
src-tauri/src/commands/processor.rs          # PacketProcessor pipeline
src-tauri/src/commands/data.rs               # get_topology, assets, connections, timeline
src-tauri/src/commands/signatures.rs         # get/reload/test signatures
src-tauri/src/commands/session.rs            # save/load/list/delete, .kkj export/import
src-tauri/src/commands/baseline.rs           # compare_sessions (drift)
src-tauri/src/commands/physical.rs           # Cisco config/CAM/CDP/ARP
src-tauri/src/commands/ingest.rs             # Zeek/Suricata/Nmap/Masscan import
src-tauri/src/commands/wireshark.rs          # detect/open/export frames
src-tauri/src/commands/export.rs             # CSV, JSON, PDF, SBOM, STIX
src-tauri/src/commands/analysis.rs           # ATT&CK, Purdue, anomalies
```

### Crates
```
gm-capture/    — pcap reading, live capture, L2-L4 parsing
gm-parsers/    — protocol ID + deep parse (Modbus, DNP3 + new: EtherNet/IP, S7comm, BACnet, IEC104, PROFINET DCP)
gm-signatures/ — YAML engine, 25+ signatures
gm-topology/   — petgraph network graph
gm-db/         — SQLite, OUI, GeoIP
gm-physical/   — Cisco IOS parsers
gm-ingest/     — Zeek, Suricata, Nmap, Masscan
gm-report/     — PDF, CSV, JSON, SBOM, STIX
gm-analysis/   — ATT&CK, Purdue, anomaly scoring
```

### Frontend
```
src/app.html, src/app.css                    # Shell + design tokens
src/routes/+layout.svelte                    # Sidebar nav + theme toggle
src/lib/types/index.ts                       # All TypeScript types
src/lib/stores/index.ts                      # All Svelte stores
src/lib/utils/tauri.ts                       # All Tauri command wrappers
src/lib/utils/graph.ts                       # Graph utilities
src/lib/components/                          # All view components (see docs/ARCHITECTURE.md)
```

## Rules

1. **Read before writing.** If a file exists, read it first.
2. **Preserve all existing functionality.** Everything must keep working.
3. **Follow established patterns.** Error handling, Tauri commands, processor pipeline.
4. **Register new commands** in `main.rs` + typed wrappers in `tauri.ts`.
5. **Use `kusanaginokajiki` everywhere.** No "grassmarlin" references.
6. **No `unwrap()` in library crates.** Use `?`, `.map_err()`, `.unwrap_or_default()`.
7. **Cross-platform casts.** pcap `tv_sec`/`tv_usec` need `as i64`/`as u32` (i32 on Windows).

## Common Pitfalls (Quick Reference)

### Rust
- Tauri commands: `Result<T, String>`, convert with `.map_err(|e| e.to_string())`
- etherparse 0.16: `tcp.payload()` / `udp.payload()`, not `SlicedPacket.payload`
- pcap `PacketHeader`: `*raw_packet.header`, cast `tv_sec as i64`, `tv_usec as u32`
- IcsProtocol: `from_name()` for deserialization, `to_name()` for snake_case
- Clippy: range patterns, `.contains()`, `.is_multiple_of()`, `strip_prefix()`
- gm-db: rusqlite bundled, WAL mode, `dirs` v6, `zip` v2
- gm-ingest: quick-xml 0.37 `@attr`; Masscan needs `clean_masscan_json()`

### Frontend
- Static adapter only, no `+page.server.ts`
- Build order: `npm run build` before `cargo check`
- Dynamic import Cytoscape.js, Svelte 5 no event modifiers
- Tauri plugins: dialog (open+save), shell (open); NO plugin-fs
- Plugin config in tauri.conf.json: `null` not `{}` — empty objects cause runtime panic

### Tauri Config
- `src-tauri/icons/icon.ico` required on Windows
- `capabilities/default.json` must include `dialog:allow-open`, `dialog:allow-save`, `shell:allow-open`

### General
- Confidence: 1=port, 2=pattern, 3=OUI, 4=payload, 5=deep parse
- Signatures: runtime YAML in `src-tauri/signatures/`
- Sessions: SQLite + .kkj ZIP archives
- DB: `~/.kusanaginokajiki/data.db`
- Settings: `~/.kusanaginokajiki/settings.json`
- Plugins: `~/.kusanaginokajiki/plugins/`
- Active scan data (Nmap/Masscan) gets `[active-scan]` tag
- All identifiers: `kusanaginokajiki`

## Protocol Detection

### Port Mapping
502=Modbus, 20000=DNP3, 44818=EtherNet/IP, 2222=EtherNet/IP I/O, 47808=BACnet, 102=S7comm, 4840=OPC UA, 34962-34964=PROFINET, 2404=IEC104, 1883/8883=MQTT, 5094=HART-IP, 1089-1091=FF HSE, 18245-18246=GE SRTP, 5007=Wonderware SuiteLink.

### Deep Parse Status
| Protocol | Status | Module | Info Struct |
|----------|--------|--------|-------------|
| Modbus | ✅ Complete | modbus.rs | ModbusInfo |
| DNP3 | ✅ Complete | dnp3.rs | Dnp3Info |
| EtherNet/IP+CIP | 🔧 Phase 12A | enip.rs | EnipInfo |
| S7comm | 🔧 Phase 12A | s7comm.rs | S7Info |
| BACnet | 🔧 Phase 12A | bacnet.rs | BacnetInfo |
| IEC 104 | 🔧 Phase 12B | iec104.rs | Iec104Info |
| PROFINET DCP | 🔧 Phase 12B | profinet_dcp.rs | ProfinetDcpInfo |

See `docs/PROTOCOL-DEEP-PARSE.md` for wire formats, struct definitions, and test payloads.

## ATT&CK Detection Summary

### Existing (Phases 0–11)
T0855 (Modbus broadcast writes), T0814 (FC 8 abuse), T0856 (DNP3 unsolicited), T0846 (unknown polling), T0886 (Purdue cross-zone)

### New (Phase 12)
T0855 (CIP writes, BACnet output writes, IEC104 commands), T0836 (CIP firmware), T0843 (S7 download), T0845 (S7 upload), T0809 (S7 block delete), T0816 (S7 PLC stop, BACnet reinitialize, IEC104 reset), T0856 (BACnet alarm suppress), T0811 (BACnet comm control), T0814 (IEC104 interrogation flood)

See `docs/PRODUCT-REQUIREMENTS.md` for full detection specifications.

## Build & Test

```bash
# Fedora WSL2
sudo dnf install libpcap-devel webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel
npm install
npm run build
npm run tauri dev

# Tests
cd src-tauri && cargo test --all
cargo clippy --all -- -D warnings
cd .. && npm run check

# CLI
kusanaginokajiki --open capture.pcap
kusanaginokajiki --import-pcap data.pcap
kusanaginokajiki --open session.kkj
```

**Windows:** VS C++ Build Tools + Npcap (WinPcap mode) + Npcap SDK (set `LIB` to `Lib\x64`). See README.md.
**Ubuntu:** `libpcap-dev libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`
**macOS:** `brew install libpcap`
