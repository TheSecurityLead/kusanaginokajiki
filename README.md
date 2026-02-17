<div align="center">
  <img src="KusanaginoKajikiLogo.jpg" alt="Kusanagi Kajiki Logo" width="400"/>

  # Kusanagi Kajiki 草薙カジキ

  **Passive ICS/SCADA network discovery and topology visualization for OT security assessments.**

  ![Rust](https://img.shields.io/badge/rust-1.77+-orange?logo=rust)
  ![Tauri](https://img.shields.io/badge/tauri-2.0-24C8D8?logo=tauri)
  ![Svelte](https://img.shields.io/badge/svelte-5-FF3E00?logo=svelte)
  ![License](https://img.shields.io/badge/license-Apache%202.0-blue)
  ![Tests](https://img.shields.io/badge/tests-127%20passing-brightgreen)
</div>

---

## What is Kusanagi Kajiki?

Kusanagi Kajiki is a ground-up rewrite of the NSA's [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) (archived 2023), rebuilt from scratch with a Rust backend (Tauri 2.0) and SvelteKit frontend. It passively discovers and maps Industrial Control System (ICS) and SCADA network devices by analyzing network traffic captures and integrating data from external security tools.

In operational technology environments, **active scanning can crash PLCs and disrupt physical processes**. Assessors need visibility into OT networks without generating a single packet. Kusanagi Kajiki operates in passive-only mode — it observes captured traffic, identifies devices and protocols, maps network topology, and flags security concerns, all without touching the production network.

The tool achieves full feature parity with GRASSMARLIN 3.2 and extends well beyond it with MITRE ATT&CK for ICS detection, Purdue Model enforcement, Zeek/Suricata log ingestion, professional PDF reporting, SBOM/STIX export, baseline drift detection, and a modern dark/light UI. The name is a bilingual nod to the original: 草 (kusa/grass) + marlin (kajiki/カジキ), with Kusanagi (草薙) referencing the legendary sword from Japanese mythology.

---

## Key Features

### Network Discovery
- **Multi-PCAP import** with simultaneous file processing and per-packet origin tracking
- **Live capture** with real-time streaming topology updates, pause/resume, ring buffer, and PCAP save
- **19 ICS/IT protocol detection** by port, payload signature, and deep packet inspection
- **Connection tracking** with packet/byte counts, timestamps, and protocol classification

### Topology Visualization
- **Logical view** — fcose layout with subnet grouping, compound nodes, filtered sub-views, and watch tabs (N-degree neighborhood)
- **Physical view** — Cisco switch/port topology from IOS configs, CAM tables, CDP neighbors, and ARP data
- **Mesh view** — All-to-all connection matrix with protocol and time filters
- **Timeline scrubber** — Replay topology construction chronologically with playback controls

### Deep Protocol Analysis
- **Modbus** — MBAP header parsing, function code extraction, read/write classification, register range mapping, FC 8 diagnostics detection, master/slave role identification
- **DNP3** — Link layer validation, function code extraction, master/outstation detection, unsolicited response (FC 130) flagging, DNP3 address extraction
- **FC 43/14 Device Identification** — Extracts vendor name and product code directly from Modbus Device ID responses (confidence level 5)
- **Polling interval detection** — Computes communication periodicity from timestamp analysis

### Device Identification
- **25 YAML signatures** covering 13 OT protocols and vendor-specific patterns (Rockwell, Schneider, Siemens, ABB, Honeywell, Emerson, GE, Wonderware, CODESYS)
- **MAC OUI vendor lookup** — IEEE OUI database (~30k entries) maps MAC prefixes to manufacturers
- **GeoIP enrichment** — Country identification for public IP addresses via DB-IP
- **Confidence scoring** — 5-level system: port (1) < pattern (2) < OUI (3) < payload (4) < deep parse (5)
- **Hot-reloadable signature editor** with CodeMirror 6 YAML editing and live test runner

### Security Analysis
- **MITRE ATT&CK for ICS** — Automated detection of T0855 (unauthorized command messages), T0814 (denial of service via diagnostics), T0856 (alarm setting modification), T0846 (remote system discovery), T0886 (remote services cross-zone)
- **Purdue Model** — Auto-assigns Purdue levels (L1-L4) based on observed behavior, detects and reports cross-zone communication violations
- **Anomaly scoring** — Identifies polling interval deviations (CV > 50%), role reversals (slave sending master function codes), and unexpected public IPs in OT networks

### External Tool Integration
- **Zeek** — Import `conn.log`, `modbus.log`, `dnp3.log`, `s7comm.log` with automatic field mapping
- **Suricata** — Import EVE JSON (flow and alert event types)
- **Nmap/Masscan** — Import scan results with `[active-scan]` tagging to distinguish from passive observation
- **Wireshark** — Auto-detect installation, right-click any node or connection to open in Wireshark, view individual frames with export

### Reporting & Export
- **PDF assessment reports** — Professional reports with executive summary, asset inventory, protocol analysis, findings table, and recommendations
- **CSV/JSON export** — Assets, connections, and full topology data
- **SBOM** — CISA BOD 23-01 aligned software bill of materials for discovered OT assets
- **STIX 2.1** — Threat intelligence bundles with observed indicators and infrastructure objects

### Session Management
- **SQLite persistence** — Save/load sessions with full asset history tracking
- **`.kkj` archives** — Portable ZIP-based session format for sharing assessment data
- **Baseline drift detection** — Compare current assessment against a saved baseline, quantified drift score, new/missing/changed asset identification

### Advanced
- **Dark/light/system theme** — Persistent preference with automatic OS detection
- **CLI** — `--open <file>` (PCAP or .kkj), `--import-pcap <path>` for headless workflows
- **Plugin architecture** — Manifest-based plugin discovery (stubs for signature packs, importers, exporters, analyzers)

---

## Beyond GRASSMARLIN

Kusanagi Kajiki implements every major GRASSMARLIN 3.2 feature and adds capabilities the original never had:

| Capability | GRASSMARLIN 3.2 | Kusanagi Kajiki |
|------------|----------------|-----------------|
| Signature format | XML (opaque) | YAML (human-readable, git-friendly) |
| Security analysis | None | ATT&CK for ICS + Purdue Model + anomaly scoring |
| External tool integration | None | Zeek, Suricata, Nmap, Masscan |
| Reporting | None | PDF assessment reports |
| Compliance export | None | SBOM (CISA BOD 23-01), STIX 2.1 |
| Baseline comparison | None | Session drift detection with quantified scoring |
| Deep protocol parsing | Limited | Modbus FC 43/14 Device ID extraction, DNP3 deep parse |
| Session format | XML archives | SQLite + portable .kkj ZIP archives |
| Theming | Java Swing | Modern dark/light with CSS custom properties |
| CLI support | None | `--open`, `--import-pcap` |
| Architecture | Monolithic Java | 9 Rust crates + SvelteKit frontend |

---

## Supported Protocols

| Protocol | Port(s) | Detection | Standard / Vendor |
|----------|---------|-----------|-------------------|
| Modbus TCP | 502 | Deep parse | Schneider Electric, multi-vendor |
| DNP3 | 20000 | Deep parse | IEEE 1815 (utilities, substations) |
| EtherNet/IP (CIP) | 44818, 2222 | Signature | Rockwell / Allen-Bradley |
| BACnet/IP | 47808 | Signature | ASHRAE (building automation) |
| S7comm | 102 | Signature | Siemens S7 PLCs |
| OPC UA | 4840 | Port + Signature | OPC Foundation |
| IEC 60870-5-104 | 2404 | Port | Power grid SCADA |
| PROFINET | 34962-34964 | Port | Siemens / PROFIBUS International |
| MQTT | 1883, 8883 | Port | IIoT gateways |
| HART-IP | 5094 | Port | Process instrumentation |
| Foundation Fieldbus HSE | 1089-1091 | Port | Process automation |
| GE SRTP | 18245-18246 | Port + Signature | GE Automation PLCs |
| Wonderware SuiteLink | 5007 | Port + Signature | AVEVA / Wonderware |

**Detection depth:** *Port* = identified by TCP/UDP port number. *Signature* = matched by YAML payload/OUI patterns. *Deep parse* = full protocol dissection with function code analysis, device identification, and behavioral profiling.

---

## Short Demo

https://streamable.com/m8crug

<!-- TODO: Add screenshot of LogicalView — fcose topology with compound subnet nodes -->

<!-- TODO: Add screenshot of PhysicalView — Cisco switch/port topology -->

<!-- TODO: Add screenshot of InventoryView — asset table with edit panel and confidence scoring -->

<!-- TODO: Add screenshot of AnalysisView — ATT&CK findings and Purdue diagram -->

<!-- TODO: Add screenshot of ExportView — PDF report generation -->

---

## Installation

### Prerequisites

- **Rust** >= 1.77 — [rustup.rs](https://rustup.rs)
- **Node.js** >= 22 — [nvm](https://github.com/nvm-sh/nvm) recommended
- **libpcap** development headers (platform-specific, see below)

### Quick Reference — Platform Dependencies

| Platform | System Dependencies | Special Notes |
|----------|-------------------|---------------|
| **Fedora/RHEL** | `libpcap-devel webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel` | Primary dev platform |
| **Ubuntu/Debian** | `libpcap-dev libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf` | |
| **macOS** | `brew install libpcap` + Xcode CLI tools | |
| **Windows** | VS C++ Build Tools + Npcap (WinPcap mode) + Npcap SDK | Set `LIB` env var to SDK `Lib/x64` path |

### Fedora / RHEL (primary development platform)

```bash
sudo dnf install libpcap-devel webkit2gtk4.1-devel libsoup3-devel javascriptcoregtk4.1-devel

git clone https://github.com/TheSecurityLead/KusanagiNoKajiki.git
cd KusanagiNoKajiki

npm install
npm run build
npm run tauri dev        # Development mode (hot-reload)
npm run tauri build      # Production binary
```

> **Note:** If `npm install` fails with peer dependency errors on older npm versions, use `npm install --legacy-peer-deps` as a fallback.

### Ubuntu / Debian

```bash
sudo apt install libpcap-dev libwebkit2gtk-4.1-dev \
  libappindicator3-dev librsvg2-dev patchelf

git clone https://github.com/TheSecurityLead/KusanagiNoKajiki.git
cd KusanagiNoKajiki

npm install
npm run build
npm run tauri dev
```

### macOS

```bash
brew install libpcap
xcode-select --install

git clone https://github.com/TheSecurityLead/KusanagiNoKajiki.git
cd KusanagiNoKajiki

npm install
npm run build
npm run tauri dev
```

### Windows

**Prerequisites (install in this order):**

1. **Visual Studio C++ Build Tools** (required — Rust needs `link.exe`):
   - Download from [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)
   - Select **"Desktop development with C++"** workload
   - Ensure "MSVC v143 C++ x64/x86 build tools" and "Windows SDK" are checked
   - Restart terminal after installation

2. **Rust** (if not already installed):
   - Install via [rustup.rs](https://rustup.rs)
   - Default toolchain: `stable-x86_64-pc-windows-msvc`

3. **Npcap** (required for packet capture):
   - Download from [npcap.com](https://npcap.com/#download)
   - During install, check **"Install Npcap in WinPcap API-compatible Mode"**
   - Download the **Npcap SDK** from the same page
   - Extract SDK to e.g. `C:\npcap-sdk`
   - Set LIB environment variable (PowerShell as admin):
     ```powershell
     [System.Environment]::SetEnvironmentVariable("LIB", "C:\npcap-sdk\Lib\x64", "User")
     ```
   - Restart terminal after setting LIB

4. **Node.js** (LTS recommended): [nodejs.org](https://nodejs.org)

**Build steps (PowerShell):**
```powershell
git clone https://github.com/TheSecurityLead/KusanagiNoKajiki.git
cd KusanagiNoKajiki

npm install
npm run build
npm run tauri dev       # development
npm run tauri build     # production binary
```

**If `npm install` fails with ERESOLVE peer dependency conflict:**
The repo pins `vite@^6.3.0` + `@sveltejs/vite-plugin-svelte@^6.2.4`. If you still get errors:
```powershell
Remove-Item -Recurse -Force node_modules -ErrorAction SilentlyContinue
Remove-Item package-lock.json -ErrorAction SilentlyContinue
npm install -D vite@^6.3.0 @sveltejs/vite-plugin-svelte@^6.2.4 @sveltejs/kit@^2.16.0 @sveltejs/adapter-static@^3.0.8
npm install
npm run build
```
Do NOT run `npm audit fix --force` — it creates an infinite downgrade loop.

### Live Capture Without Root (Linux)

```bash
sudo setcap cap_net_raw,cap_net_admin=eip src-tauri/target/release/kusanaginokajiki
```

---

## Quick Start

### 1. Import a PCAP

Open the **Capture** tab and click **Import PCAP File(s)**. Multi-file selection is supported — each packet tracks its origin file.

### 2. Explore the Topology

Switch to the **Topology** tab. The logical view renders an interactive graph grouped by subnet. Right-click nodes to watch neighbors, create filtered views, or open in Wireshark. Use the timeline scrubber at the bottom to replay topology construction.

### 3. Inspect Devices

The **Inventory** tab shows all discovered assets with vendor identification, protocols, confidence scores, OUI vendor, country flags, and deep parse details. Click any asset to see Modbus/DNP3 function code analysis, register ranges, and polling intervals.

### 4. Run Security Analysis

Navigate to the **Analysis** tab and click **Run Analysis**. The engine automatically:
- Maps observed behaviors to MITRE ATT&CK for ICS techniques
- Assigns Purdue Model levels and flags cross-zone violations
- Scores anomalies (polling deviations, role reversals, unexpected public IPs)

### 5. Export a Report

Open the **Export** tab to generate:
- **PDF** — Professional assessment report with findings and recommendations
- **CSV/JSON** — Raw data export for further analysis
- **SBOM** — Asset inventory aligned with CISA BOD 23-01
- **STIX 2.1** — Threat intelligence bundle for sharing

---

## CLI Reference

```bash
# Open a PCAP file directly
kusanaginokajiki --open capture.pcap

# Open a session archive
kusanaginokajiki --open assessment.kkj

# Import a PCAP file on startup
kusanaginokajiki --import-pcap /path/to/capture.pcap
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│  SvelteKit Frontend (Tauri Webview)                        │
│  ├── LogicalView      (fcose + drift + timeline)           │
│  ├── PhysicalView     (switch/port Cytoscape)              │
│  ├── MeshView         (all-to-all mesh)                    │
│  ├── InventoryView    (table + edit + detail + bulk)       │
│  ├── CaptureView      (import + live + sessions + ingest)  │
│  ├── ProtocolStats    (traffic + FCs)                      │
│  ├── SignatureEditor  (YAML editor)                        │
│  ├── ExportView       (CSV/JSON/PDF/SBOM/STIX)            │
│  ├── AnalysisView     (ATT&CK + Purdue + anomaly + drift) │
│  ├── TimelineScrubber (topology playback)                  │
│  └── SettingsView     (theme + plugins + CLI)              │
├────────────────────────────────────────────────────────────┤
│  Tauri IPC: 59 Commands + Event Streaming                  │
├────────────────────────────────────────────────────────────┤
│  Rust Backend (9 crates)                                   │
│  ├── gm-capture     Packet capture (pcap + etherparse)     │
│  ├── gm-parsers     Protocol ID + Modbus/DNP3 deep parse  │
│  ├── gm-signatures  YAML signature engine (25 signatures)  │
│  ├── gm-topology    Logical graph (petgraph)               │
│  ├── gm-physical    Cisco IOS config/CAM/CDP/ARP parsers   │
│  ├── gm-ingest      Zeek, Suricata, Nmap, Masscan import  │
│  ├── gm-analysis    ATT&CK, Purdue, anomaly scoring       │
│  ├── gm-report      PDF, CSV, JSON, SBOM, STIX export     │
│  └── gm-db          SQLite persistence, OUI, GeoIP        │
└────────────────────────────────────────────────────────────┘
```

### Data Pipeline

```
PCAP / Live Capture
  → gm-capture (L2-L4 parsing)
  → gm-parsers (protocol identification + deep parse)
  → gm-signatures (YAML pattern matching, confidence scoring)
  → gm-topology (petgraph network graph)
  → OUI / GeoIP enrichment
  → AppState
  → gm-analysis (ATT&CK + Purdue + anomaly detection)
  → gm-db (SQLite persistence)
  → gm-report (PDF / CSV / SBOM / STIX)
  → Frontend (Cytoscape topology, tables, charts)
```

---

## Tech Stack

### Rust Backend
Tauri 2.0, pcap, etherparse, petgraph, serde (JSON/YAML), tokio, thiserror, chrono, uuid, rusqlite (bundled SQLite), maxminddb, regex, quick-xml, genpdf, clap 4, zip.

### Frontend
SvelteKit (Svelte 5), TypeScript (strict), Cytoscape.js + fcose layout, Tailwind CSS 4, CodeMirror 6, @tauri-apps/api + plugins (dialog, shell).

---

## Testing

```bash
# Run all 127 Rust tests
cd src-tauri && cargo test --all

# Strict clippy (zero warnings)
cargo clippy --all -- -D warnings

# Frontend type checking
cd .. && npm run check

# Full verification suite
npm run build && cd src-tauri && cargo test --all && cargo clippy --all -- -D warnings && cd .. && npm run check
```

### Test Data

Public ICS PCAP samples for testing:
- [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) — Curated Modbus, DNP3, EtherNet/IP, S7comm, BACnet captures
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — Various protocol samples
- [4SICS Geek Lounge](https://www.netresec.com/?page=PCAP4SICS) — Real ICS network traffic

---

## Troubleshooting

**`npm install` fails with ERESOLVE error:**
Clean install with pinned versions — see Windows Installation section above. Do NOT use `npm audit fix --force`.

**`error: linker 'link.exe' not found` during Rust compilation:**
Install Visual Studio Build Tools with "Desktop development with C++" workload. VS Code is not sufficient. Restart your terminal after installation.

**`npm run build` says `'vite' is not recognized`:**
`npm install` did not complete successfully. Fix dependency issues first, then re-run `npm install` and `npm run build`.

**`npm audit` shows cookie vulnerability:**
This is a low-severity server-side issue that does not affect Tauri desktop apps. Safe to ignore.

**Npcap/libpcap linking errors on Windows:**
Ensure Npcap is installed with "WinPcap API-compatible Mode" checked. Download Npcap SDK, extract it, and set `LIB` environment variable to include the SDK's `Lib/x64` directory.

---

## Contributing

Contributions are welcome. Areas where contributions would be most valuable:

- **YAML signatures** — Fingerprint signatures for additional ICS vendor products
- **Protocol parsers** — Deep parsing for BACnet, EtherNet/IP, S7comm, OPC UA
- **Test PCAPs** — Sanitized ICS network captures for the test suite
- **Bug reports** — [Open an issue](https://github.com/TheSecurityLead/KusanagiNoKajiki/issues)

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

This is an independent project inspired by GRASSMARLIN. It contains no original GRASSMARLIN source code.

---

## Acknowledgments

- **NSA Cybersecurity** — Original [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) tool and concept
- **MITRE** — [ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) framework
- **CISA** — [BOD 23-01](https://www.cisa.gov/binding-operational-directive-23-01) asset visibility guidance
- **Tauri** — Cross-platform desktop application framework
- **Cytoscape.js** — Network graph visualization library
- **DB-IP** — [IP to Country Lite](https://db-ip.com/db/lite.php) database
- **IEEE** — OUI vendor database
