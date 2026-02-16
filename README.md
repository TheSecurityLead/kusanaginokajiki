<div align="center"><img src="KusanaginoKajikiLogo.jpg"/></div>

# Kusanagi Kajiki 草薙カジキ

**Modern ICS/SCADA passive network discovery and topology visualization tool.**

A ground-up rewrite of the NSA's [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) (archived 2023), rebuilt with **Tauri 2.0** (Rust backend) and **SvelteKit** (TypeScript frontend) for performance, security, and cross-platform support.

The name is a bilingual nod to the original: 草 (kusa/grass) + marlin (kajiki/カジキ), with Kusanagi (草薙) referencing the legendary Japanese sword.

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Rust](https://img.shields.io/badge/rust-1.77+-orange)
![Tauri](https://img.shields.io/badge/tauri-2.0-blue)

> **Active Development** — This project is under active development. See the [Roadmap](#roadmap) for current status.

---

## What It Does

Kusanagi Kajiki passively discovers and maps Industrial Control System (ICS) and SCADA network devices by analyzing network traffic. It is designed for OT security assessments where **active scanning is not an option** — maintaining availability of industrial systems is paramount.

### Core Capabilities

- **PCAP Import** — Analyze captured traffic offline with multi-file support
- **Live Capture** — Real-time packet capture with streaming topology updates
- **Three Topology Views** — Logical (subnet-grouped), Physical (switch port mapping), and Mesh (Sniffles all-to-all)
- **YAML Signature Engine** — 54+ extensible fingerprint signatures identifying specific vendor products (not just protocols), with confidence scoring 1-5
- **Deep Protocol Parsing** — Modbus function codes, DNP3 object types, register mapping, device identification extraction
- **Physical Topology** — Import Cisco configs, CAM tables, and CDP neighbors to map devices to physical switch ports
- **Asset Inventory** — Searchable database with vendor-specific identification, MAC OUI lookup, and GeoIP for public IPs
- **MITRE ATT&CK for ICS** — Map observed behaviors to ATT&CK techniques with severity ratings
- **Purdue Model Overlay** — Auto-assign Purdue levels, detect and flag cross-zone policy violations
- **Anomaly Scoring** — Detect role reversals, polling deviations, unexpected devices, and unencrypted OT traffic
- **External Tool Integration** — Import Zeek logs, Suricata EVE JSON, Nmap XML. Right-click to open in Wireshark.
- **PDF Assessment Reports** — One-click professional reports with executive summary, topology diagrams, findings, and recommendations
- **SBOM Export** — CISA BOD 23-01 aligned asset inventories for federal compliance
- **Baseline Drift Detection** — Diff current assessment against previous baseline, highlight changes
- **Plugin Architecture** — Extensible via signature packs, importers, exporters, and analyzers

### Supported ICS Protocols

| Protocol | Port(s) | Vendor / Standard |
|----------|---------|-------------------|
| Modbus TCP | 502 | Schneider Electric, many vendors |
| DNP3 | 20000 | IEEE 1815 (utilities, substations) |
| EtherNet/IP (CIP) | 44818, 2222 | Rockwell / Allen-Bradley |
| BACnet/IP | 47808 | ASHRAE (building automation) |
| S7comm | 102 | Siemens S7 PLCs |
| OPC UA | 4840 | OPC Foundation |
| IEC 60870-5-104 | 2404 | Power grid SCADA |
| PROFINET | 34962-34964 | Siemens / PI |
| MQTT | 1883, 8883 | IIoT gateways |
| HART-IP | 5094 | Process instrumentation |
| GE SRTP | 18245-18246 | GE PLCs |
| Wonderware SuiteLink | 5007 | Wonderware SCADA |
| Foundation Fieldbus HSE | 1089-1091 | Process automation |

### Signature-Identified Products (partial list)

Rockwell ControlLogix, Schneider Modicon M340/Unity, Siemens S7-300/400/1200/1500, ABB 800xA, Honeywell Experion, Emerson DeltaV, GE SRTP devices, Wonderware SuiteLink, CODESYS controllers, and more via the extensible YAML signature engine.

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│  SvelteKit Frontend (Tauri Webview)                        │
│  ├── Logical / Physical / Mesh topology views              │
│  ├── Asset inventory, protocol stats, findings panel       │
│  ├── Signature editor, report builder, Purdue overlay      │
│  └── Settings, timeline scrubber, baseline diff            │
├────────────────────────────────────────────────────────────┤
│  Tauri IPC (Commands + Event Streaming)                    │
├────────────────────────────────────────────────────────────┤
│  Rust Backend                                              │
│  ├── gm-capture     (pcap + etherparse)                    │
│  ├── gm-parsers     (protocol ID + deep parsing)           │
│  ├── gm-signatures  (YAML fingerprint engine)              │
│  ├── gm-topology    (petgraph logical graph)               │
│  ├── gm-physical    (Cisco config → physical topology)     │
│  ├── gm-ingest      (Zeek, Suricata, Nmap importers)      │
│  ├── gm-analysis    (ATT&CK, Purdue, anomaly, TLS)        │
│  ├── gm-report      (PDF, SBOM, STIX 2.1)                 │
│  └── gm-db          (SQLite persistence)                   │
└────────────────────────────────────────────────────────────┘
```

---

## Getting Started

### Prerequisites

- **Rust** >= 1.77 — [Install via rustup](https://rustup.rs)
- **Node.js** >= 22 — [Install via nvm](https://github.com/nvm-sh/nvm)
- **libpcap** development headers

#### Platform-specific dependencies

**Linux (Ubuntu/Debian):**
```bash
sudo apt install libpcap-dev libwebkit2gtk-4.1-dev \
  libappindicator3-dev librsvg2-dev patchelf
```

**macOS:**
```bash
brew install libpcap
xcode-select --install
```

**Windows:**
- Install [Npcap](https://npcap.com) (check "Install Npcap in WinPcap API-compatible Mode")
- Download the [Npcap SDK](https://npcap.com/#download) and add `Lib/x64` to your `LIB` environment variable

### Build & Run

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/kusanagi-kajiki.git
cd kusanagi-kajiki

# Install frontend dependencies
npm install

# Run in development mode (hot-reload)
npm run tauri dev

# Build for production
npm run tauri build
```

### Running Without Root (Linux)

For live capture without running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip src-tauri/target/release/kusanagi-kajiki
```

---

## Usage

### PCAP Import

1. Navigate to the **Capture** tab
2. Click **Import PCAP File(s)** — multi-select supported
3. View results across **Topology**, **Inventory**, and **Protocol Stats** tabs
4. Connection tree panel shows per-node expandable packet details with origin file tracking

### Cisco Config Import (Physical Topology)

1. Navigate to **Physical View**
2. Import Cisco IOS configs, `show mac address-table`, `show cdp neighbors`, and `show arp` output
3. Physical topology renders switch port assignments — "PLC on Gi1/0/14 of SW-PLANT-3"

### Zeek / Suricata Import

1. Navigate to **Capture** tab
2. Click **Import Zeek Logs** or **Import Suricata EVE**
3. Select `conn.log`, `modbus.log`, `dnp3.log`, or `eve.json`
4. Data feeds into the same topology and asset pipeline as PCAP

### Assessment Report

1. Complete your analysis (PCAP import, signature matching, Purdue assignment)
2. Navigate to **Report** tab
3. Configure branding, assessor name, client name
4. Click **Generate PDF** — produces a professional report with executive summary, topology diagram, asset inventory, protocol analysis, findings, and recommendations

### Test Data

Public ICS PCAP samples for testing:
- [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) — Curated Modbus, DNP3, EtherNet/IP, S7comm, BACnet captures
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — Various protocol samples
- [4SICS Geek Lounge](https://www.netresec.com/?page=PCAP4SICS) — Real ICS network traffic

---

## Roadmap

Development follows a phased plan. Phases 0–7 achieve GRASSMARLIN feature parity. Phases 8–11 go beyond the original.

| Phase | Status | Description |
|-------|--------|-------------|
| 0 — Foundation | ✅ Done | Project scaffold, interface listing, CI/CD |
| 1 — PCAP Import | ✅ Done | Multi-PCAP import, L2-L4 parsing, connection tree |
| 2 — Topology | ✅ Done | Logical/Mesh views, dynamic grouping, filtered views, watch tabs |
| 3 — Signatures | ✅ Done | YAML fingerprint engine (54+ sigs), confidence scoring, editor |
| 4 — Deep Parsing | ✅ Done  | Modbus/DNP3 deep inspection, protocol statistics |
| 5 — Live Capture | ✅ Done | Real-time capture with streaming topology |
| 6 — Persistence | ✅ Done | SQLite, sessions, MAC OUI, GeoIP, session archives |
| 7 — Physical Topology | ✅ Done | Cisco config/CAM import, physical switch port view |
| 8 — Tool Integration | ✅ Done | Wireshark, Zeek, Suricata, Nmap/Masscan import |
| 9 — Export & Reports | 🔨 Current | PDF reports, SBOM/CISA BOD 23-01, STIX 2.1 |
| 10 — Security Analysis | ⏳ Planned | MITRE ATT&CK for ICS, Purdue overlay, anomaly scoring, TLS, Shodan |
| 11 — Advanced | ⏳ Planned | Baseline drift, timeline replay, OPC UA certs, plugins, multi-user, light theme |

See [CLAUDE.md](CLAUDE.md) for the full specification with detailed checklists per phase.

---

## GRASSMARLIN Feature Parity

Kusanagi Kajiki implements every major GRASSMARLIN 3.2 feature:

| Original Feature | Status | Kusanagi Kajiki Implementation |
|------------------|--------|-------------------------------|
| PCAP import + multi-file | Phase 1 | Multi-select with origin file tracking |
| Logical topology view | Phase 2 | Cytoscape.js with fcose layout |
| Physical topology view | Phase 7 | Cisco config/CAM/CDP import |
| XML fingerprint engine (54 sigs) | Phase 3 | Modernized as YAML with hot-reload |
| Fingerprint editor (GUI) | Phase 3 | CodeMirror 6 YAML editor + test runner |
| Confidence scoring (1-5) | Phase 3 | On every identification, color-coded |
| Device role granularity | Phase 3 | Vendor-specific: "Rockwell ControlLogix L7x" |
| Dynamic graph grouping | Phase 2 | Right-click regroup by any attribute |
| Filtered views | Phase 2 | Multiple simultaneous tab views |
| Watch tabs (N-degree) | Phase 2 | 1-5 hop configurable |
| Connection tree with packet detail | Phase 1 | Expandable per-node, per-connection, per-packet |
| GeoIP with country flags | Phase 6 | MaxMind GeoLite2 |
| MAC OUI vendor lookup | Phase 6 | IEEE OUI database bundled |
| Wireshark integration | Phase 8 | Right-click → Open in Wireshark |
| Session save/load | Phase 6 | SQLite + bundled ZIP archives |
| Cisco config file import | Phase 7 | IOS configs + show commands |
| Sniffles / Mesh graph | Phase 2 | MeshView with protocol/time filters |
| Plugin architecture | Phase 11 | Signature packs, importers, exporters |

---

## Beyond GRASSMARLIN — New Capabilities

| Feature | Phase | Why It Matters |
|---------|-------|---------------|
| YAML signatures (replaces XML) | 3 | Human-readable, git-friendly, community shareable |
| Zeek/Suricata log ingestion | 8 | Leverage existing sensor infrastructure |
| MITRE ATT&CK for ICS mapping | 10 | "Here's what's concerning" not just "here's what exists" |
| Purdue Model overlay + violations | 10 | Cross-zone communication = reportable finding |
| PDF assessment reports | 9 | What assessors actually deliver to clients |
| SBOM/CISA BOD 23-01 export | 9 | Federal compliance alignment |
| Nmap/Masscan result import | 8 | Merge active + passive when permitted |
| TLS fingerprinting (JA3/JA4) | 10 | "87% of OT traffic is unencrypted" |
| Anomaly scoring | 10 | Role reversals, polling deviations, new devices |
| Shodan/Censys cross-reference | 10 | Find internet-exposed OT devices |
| Baseline drift detection | 11 | Diff assessments over time |
| PCAP timeline replay | 11 | Watch topology build chronologically |
| OPC UA certificate analysis | 11 | Expired/self-signed/weak key detection |
| STIX 2.1 export | 9 | Threat intel sharing |
| Multi-user session merge | 11 | Multiple assessors, one topology |
| Dark/light theme | 11 | Control room readability |

---

## Contributing

This project is currently in early development. Contributions welcome once the core architecture stabilizes (Phase 3+).

Areas where contributions would be most valuable:
- **YAML signatures** — If you work with ICS/SCADA protocols, writing new fingerprint signatures for vendor products
- **Test PCAPs** — Sanitized ICS network captures for the test suite
- **Protocol parsers** — Deep parsing for protocols beyond Modbus/DNP3 (BACnet, EtherNet/IP, S7comm, OPC UA)

---

## Acknowledgments

- **NSA Cybersecurity** — Original [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) tool and concept
- **Step Function I/O** — [rodbus](https://github.com/stepfunc/rodbus) and [dnp3](https://github.com/stepfunc/dnp3) Rust crates
- **Tauri** — Cross-platform desktop app framework
- **Cytoscape.js** — Network graph visualization
- **MITRE** — ATT&CK for ICS framework

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

*This is an independent project inspired by GRASSMARLIN. It contains no original GRASSMARLIN source code.*
