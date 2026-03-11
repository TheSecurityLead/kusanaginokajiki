# ARCHITECTURE.md — Kusanagi Kajiki Technical Architecture

## System Overview

```
┌────────────────────────────────────────────────────────────┐
│  SvelteKit Frontend (Tauri Webview)                        │
│  ├── LogicalView      (fcose + drift + timeline)           │
│  ├── PhysicalView     (switch/port Cytoscape)              │
│  ├── MeshView         (all-to-all mesh)                    │
│  ├── InventoryView    (table + edit + detail + bulk)       │
│  ├── CaptureView      (import + live + sessions + ingest)  │
│  ├── ProtocolStats    (traffic + FCs + deep parse stats)   │
│  ├── SignatureEditor  (YAML editor)                        │
│  ├── ExportView       (CSV/JSON/PDF/SBOM/STIX)            │
│  ├── AnalysisView     (ATT&CK + Purdue + anomaly + drift) │
│  ├── TimelineScrubber (topology playback)                  │
│  └── SettingsView     (theme + plugins + CLI)              │
├────────────────────────────────────────────────────────────┤
│  Tauri IPC: 59+ Commands + Event Streaming                 │
├────────────────────────────────────────────────────────────┤
│  Rust Backend (10 crates)                                  │
│  ├── gm-capture     Packet capture (pcap + etherparse)     │
│  ├── gm-parsers     Protocol ID + deep parse               │
│  ├── gm-signatures  YAML signature engine (25+ sigs)       │
│  ├── gm-topology    Logical graph (petgraph)               │
│  ├── gm-physical    Cisco IOS config/CAM/CDP/ARP parsers   │
│  ├── gm-ingest      Zeek, Suricata, Nmap, Masscan import  │
│  ├── gm-analysis    ATT&CK, Purdue, anomaly scoring       │
│  ├── gm-report      PDF, CSV, JSON, SBOM, STIX export     │
│  └── gm-db          SQLite persistence, OUI, GeoIP        │
└────────────────────────────────────────────────────────────┘
```

## Data Pipeline

```
PCAP / Live Capture
  → gm-capture (L2-L4 parsing via etherparse)
  → gm-parsers (protocol identification by port → deep parse for supported protocols)
  → gm-signatures (YAML pattern matching, confidence 1-4)
  → gm-topology (petgraph network graph construction)
  → OUI / GeoIP enrichment (vendor name from MAC, country from IP)
  → AppState (in-memory state for Tauri commands)
  → gm-analysis (ATT&CK detection + Purdue classification + anomaly scoring)
  → gm-db (SQLite persistence, session save/load)
  → gm-report (PDF / CSV / SBOM / STIX generation)
  → Frontend (Cytoscape topology, tables, charts via Tauri IPC)
```

## Crate Architecture

### gm-capture (`src-tauri/crates/gm-capture/src/`)

Handles raw packet capture from pcap files and live network interfaces.

| File | Purpose |
|------|---------|
| `lib.rs` | Public API |
| `error.rs` | Capture-specific error types |
| `interface.rs` | Network interface enumeration |
| `packet.rs` | `ParsedPacket` struct (L2-L4 fields extracted by etherparse) |
| `pcap_reader.rs` | `PcapReader::read_file()` — reads pcap/pcapng files |
| `parsing.rs` | Shared parsing logic (timestamp extraction, protocol detection) |
| `live.rs` | `LiveCaptureHandle` — async live capture with pause/resume/ring buffer |

**Cross-platform note:** pcap `PacketHeader` fields `tv_sec`/`tv_usec` are `i64` on Linux/macOS but `i32` on Windows. Always cast with `as i64`/`as u32`.

### gm-parsers (`src-tauri/crates/gm-parsers/src/`)

Protocol identification and deep packet inspection.

| File | Purpose |
|------|---------|
| `lib.rs` | `DeepParseResult` enum + `deep_parse()` dispatcher |
| `protocol.rs` | `IcsProtocol` enum (19+ variants), `from_name()`/`to_name()` |
| `modbus.rs` | Modbus TCP deep parse (MBAP, FCs, FC 43/14 Device ID) |
| `dnp3.rs` | DNP3 deep parse (link layer, FCs, master/outstation) |
| `enip.rs` | **NEW** EtherNet/IP + CIP (encapsulation, ListIdentity, CIP services) |
| `s7comm.rs` | **NEW** S7comm (TPKT/COTP/S7, functions, SZL identity) |
| `bacnet.rs` | **NEW** BACnet (BVLCI/NPDU/APDU, I-Am, services) |
| `iec104.rs` | **NEW** IEC 104 (APCI frames, ASDU types, commands) |
| `profinet_dcp.rs` | **NEW** PROFINET DCP (TLV device discovery) |
| `vendor_tables.rs` | **NEW** CIP + PROFINET vendor ID → name lookup |

**Deep parse dispatch pattern:**
```rust
pub fn deep_parse(protocol: IcsProtocol, payload: &[u8]) -> Option<DeepParseResult> {
    match protocol {
        IcsProtocol::Modbus => modbus::parse(payload).map(DeepParseResult::Modbus),
        IcsProtocol::Dnp3 => dnp3::parse(payload).map(DeepParseResult::Dnp3),
        IcsProtocol::EthernetIp => enip::parse(payload).map(DeepParseResult::Enip),
        IcsProtocol::S7comm => s7comm::parse(payload).map(DeepParseResult::S7),
        IcsProtocol::Bacnet => bacnet::parse(payload).map(DeepParseResult::Bacnet),
        IcsProtocol::Iec104 => iec104::parse(payload).map(DeepParseResult::Iec104),
        IcsProtocol::Profinet => profinet_dcp::parse(payload).map(DeepParseResult::ProfinetDcp),
        _ => None,
    }
}
```

### gm-signatures (`src-tauri/crates/gm-signatures/src/`)

Runtime YAML signature matching engine.

| File | Purpose |
|------|---------|
| `lib.rs` | Public API |
| `signature.rs` | `Signature` struct (YAML deserialization) |
| `engine.rs` | `SignatureEngine` — loads YAML dir, matches against packets |
| `error.rs` | Signature-specific errors |

Signatures live in `src-tauri/signatures/` (25+ YAML files). Confidence levels: 1=port, 2=pattern, 3=OUI, 4=payload. Deep parse provides confidence 5.

### gm-topology (`src-tauri/crates/gm-topology/src/`)

Network graph construction using petgraph.

| File | Purpose |
|------|---------|
| `lib.rs` | `TopologyBuilder` — `add_connection()`, `build_assets()`, graph queries |

**Borrow checker note:** `contains_key` check before mutable `entry` to avoid simultaneous borrows.

### gm-db (`src-tauri/crates/gm-db/src/`)

SQLite persistence with OUI and GeoIP enrichment.

| File | Purpose |
|------|---------|
| `lib.rs` | `Database` struct |
| `error.rs` | DB-specific errors |
| `schema.rs` | Table creation (assets, connections, sessions, findings) |
| `sessions.rs` | Session CRUD + .kkj ZIP archive export/import |
| `assets.rs` | Asset queries + update |
| `connections.rs` | Connection queries |
| `oui.rs` | `OuiLookup` — IEEE OUI MAC → vendor (~30k entries from `data/oui.tsv`) |
| `geoip.rs` | `GeoIpLookup` — DB-IP country lookup (`data/dbip-country-lite.mmdb`) |

Config: rusqlite bundled, WAL mode, FK enforcement, `dirs` v6, `zip` v2.

### gm-physical (`src-tauri/crates/gm-physical/src/`)

Physical topology from Cisco network infrastructure data.

| File | Purpose |
|------|---------|
| `lib.rs` | `PhysicalTopology`, `PhysicalSwitch`, etc. |
| `cisco.rs` | IOS running-config, MAC table, CDP neighbor, ARP table parsers |

Utilities: `normalize_mac()` for Cisco dot format, `shorten_interface_name()`.

### gm-ingest (`src-tauri/crates/gm-ingest/src/`)

External tool data import and merge.

| File | Purpose |
|------|---------|
| `lib.rs` | `IngestResult`, `IngestSource` |
| `zeek.rs` | conn.log, modbus.log, dnp3.log, s7comm.log import |
| `suricata.rs` | EVE JSON (flow + alert events) |
| `nmap.rs` | Nmap XML (quick-xml 0.37 `@attr`) |
| `masscan.rs` | Masscan JSON (`clean_masscan_json()` preprocessing) |
| `error.rs` | Ingest-specific errors |

### gm-report (`src-tauri/crates/gm-report/src/`)

Report generation (19 tests).

| File | Purpose |
|------|---------|
| `lib.rs` | Public API |
| `pdf.rs` | PDF via genpdf |
| `csv_export.rs` | Manual CSV builder |
| `json_export.rs` | Topology/assets JSON |
| `sbom.rs` | CISA BOD 23-01 SBOM |
| `stix.rs` | STIX 2.1 bundles |
| `error.rs` | Report-specific errors |

### gm-analysis (`src-tauri/crates/gm-analysis/src/`)

Security analysis engine (24 tests).

| File | Purpose |
|------|---------|
| `lib.rs` | `AnalysisInput`, snapshot types (decoupled from Tauri state) |
| `attack.rs` | ATT&CK for ICS technique detection |
| `purdue.rs` | Purdue Model auto-assignment + cross-zone violations |
| `anomaly.rs` | Polling deviation, role reversal, unexpected public IPs |
| `error.rs` | Analysis-specific errors |

## Frontend Component Map

### Views (SvelteKit + Svelte 5)
| Component | Purpose |
|-----------|---------|
| `CaptureView.svelte` | PCAP import + live capture + session management + external tool ingest |
| `ConnectionTree.svelte` | Node → connection → packet tree + Wireshark integration |
| `InventoryView.svelte` | Asset table + edit + detail + bulk operations + OUI/country/confidence |
| `LogicalView.svelte` | fcose graph + compound subnet nodes + drift highlighting + timeline |
| `PhysicalView.svelte` | Switch/port Cytoscape + Cisco import + cross-reference |
| `MeshView.svelte` | All-to-all connection matrix |
| `FilteredView.svelte` | Subset topology views |
| `WatchTab.svelte` | N-degree neighborhood, 500ms refresh |
| `SignatureEditor.svelte` | CodeMirror 6 YAML editor + test runner |
| `ProtocolStats.svelte` | Traffic bars + FC distribution + deep parse breakdowns |
| `ExportView.svelte` | CSV/JSON/PDF/SBOM/STIX exports |
| `AnalysisView.svelte` | 5 tabs: Summary, Findings, Purdue, Anomalies, Baseline Drift |
| `BaselineDriftView.svelte` | Session selector + drift score + new/missing/changed cards |
| `TimelineScrubber.svelte` | Playback bar (play/pause, speed, slider) |
| `SettingsView.svelte` | Theme picker + plugins + CLI usage + DB path |

### State Management
| Store | Purpose |
|-------|---------|
| `assets` | Discovered device inventory |
| `connections` | Connection tracking data |
| `topology` | Graph nodes/edges |
| `baselineDiff` | Drift comparison results |
| `themeMode` | dark/light/system |
| `timelinePosition`, `timelineEnabled`, `timelinePlaying` | Timeline scrubber state |
| `driftNewIps`, `driftMissingIps`, `driftChangedIps` | Drift highlighting |

### Tech Stack
- **Rust Backend:** Tauri 2.0, pcap, etherparse, petgraph, serde (JSON/YAML), tokio, thiserror, chrono, uuid, rusqlite (bundled), maxminddb, regex, quick-xml, genpdf, clap 4, zip
- **Frontend:** SvelteKit (Svelte 5), TypeScript (strict), Cytoscape.js + fcose, Tailwind CSS 4, CodeMirror 6, @tauri-apps/api + plugins (dialog, shell)

## Tauri Command Registration

All commands registered in `main.rs` via `tauri::generate_handler![...]`. Every `#[tauri::command]` function returns `Result<T, String>`. Frontend wrappers in `src/lib/utils/tauri.ts`.

**Pattern for new commands:**
1. Implement function with `#[tauri::command]` in appropriate `commands/*.rs` file
2. Add to `generate_handler![]` in `main.rs`
3. Add typed wrapper in `tauri.ts`
4. Add permission in `capabilities/default.json` if needed

## File System Layout

```
~/.kusanaginokajiki/
  ├── data.db            # SQLite database (WAL mode)
  ├── settings.json      # Theme, preferences
  └── plugins/           # Plugin manifests (manifest.json per plugin)

src-tauri/
  ├── signatures/        # 25+ YAML signature files (runtime loaded)
  ├── data/
  │   ├── oui.tsv        # IEEE OUI database (~30k entries)
  │   └── dbip-country-lite.mmdb  # DB-IP GeoIP database
  └── icons/
      └── icon.ico       # Required on Windows
```

## ICS/SCADA Domain Knowledge

### Why Passive Only
Active scanning can crash PLCs and disrupt physical processes. This tool ONLY observes — never generates packets. Live capture = promiscuous receive only.

### Purdue Model
L0=sensors/actuators, L1=PLCs/RTUs, L2=HMIs, L3=Historians/SCADA, L3.5=DMZ, L4-5=Enterprise IT.

**Auto-assignment rules:**
- L1: OT server ports (Modbus server, DNP3 outstation, S7 server, EtherNet/IP adapter, IEC104 outstation)
- L2: Multi-OT client (HMI polling multiple PLCs), EtherNet/IP scanner, BACnet client
- L3: Historian, OPC UA server, data aggregator
- L4: IT-only protocols (HTTP, DNS, RDP, SSH)

### Device Classification Pipeline
Port-based heuristics → YAML signature matching → OUI vendor lookup → Deep parse (FC 43/14, ListIdentity, SZL, I-Am, DCP) → Purdue auto-assignment. Confidence: 1=port, 2=pattern, 3=OUI, 4=payload, 5=deep parse.
