<div align="center">
  <img src="KusanaginoKajikiLogo.jpg" alt="Kusanagi Kajiki Logo" width="400"/>

  # Kusanagi Kajiki 草薙カジキ

  **Passive ICS/SCADA network discovery and topology visualization for OT security assessments.**

  ![Rust](https://img.shields.io/badge/rust-1.77+-orange?logo=rust)
  ![Tauri](https://img.shields.io/badge/tauri-2.0-24C8D8?logo=tauri)
  ![Svelte](https://img.shields.io/badge/svelte-5-FF3E00?logo=svelte)
  ![License](https://img.shields.io/badge/license-Apache%202.0-blue)
  ![Tests](https://img.shields.io/badge/tests-180%20passing-brightgreen)
</div>

---

## Demo

![KNK Demo](./demo.gif)

*Passive discovery of ICS/SCADA devices from a PCAP capture — topology visualization, protocol identification, and device fingerprinting in action.*

---

## What is Kusanagi Kajiki?

Kusanagi Kajiki is a ground-up rewrite of the NSA's [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) (archived 2023), rebuilt from scratch with a Rust backend (Tauri 2.0) and SvelteKit frontend. It passively discovers and maps Industrial Control System (ICS) and SCADA network devices by analyzing network traffic captures and integrating data from external security tools.

In operational technology environments, **active scanning can crash PLCs and disrupt physical processes**. Assessors need visibility into OT networks without generating a single packet. Kusanagi Kajiki operates in passive-only mode — it observes captured traffic, identifies devices and protocols, maps network topology, and flags security concerns, all without touching the production network.

The tool achieves full feature parity with GRASSMARLIN 3.2 and extends well beyond it with MITRE ATT&CK for ICS detection, Purdue Model enforcement, deep protocol analysis for 7 ICS protocols, Zeek/Suricata log ingestion, professional PDF reporting, SBOM/STIX export, baseline drift detection, and a modern dark/light UI.

---

## Key Features

### Network Discovery
- **Multi-PCAP import** with simultaneous file processing and per-packet origin tracking
- **Live capture** with real-time streaming topology updates, pause/resume, ring buffer, and PCAP save
- **19 ICS/IT protocol detection** by port, payload signature, and deep packet inspection
- **Connection tracking** with packet/byte counts, timestamps, and protocol classification

### Topology Visualization
- **Logical view** — fcose layout with subnet grouping, compound nodes, filtered sub-views, and watch tabs
- **Physical view** — Cisco switch/port topology from IOS configs, CAM tables, CDP neighbors, and ARP data
- **Mesh view** — All-to-all connection matrix with protocol and time filters
- **Timeline scrubber** — Replay topology construction chronologically with playback controls

### Deep Protocol Analysis
- **Modbus** — MBAP parsing, function code extraction, FC 43/14 Device ID, master/slave detection, register ranges, polling intervals
- **DNP3** — Link layer validation, function code extraction, master/outstation detection, unsolicited response flagging
- **EtherNet/IP + CIP** — Encapsulation header parsing, ListIdentity device identification (vendor/product/serial/firmware), CIP service and class analysis, scanner/adapter role detection
- **S7comm** — TPKT/COTP/S7 layered parsing, function code identification (read/write/upload/download/stop), rack/slot extraction, SZL identity queries, client/server role detection
- **BACnet** — BVLCI/NPDU/APDU parsing, I-Am broadcast extraction (device instance/vendor), service identification, client/server role detection
- **IEC 60870-5-104** — APCI frame classification (I/S/U), ASDU type identification, command vs monitoring classification, master/outstation role detection
- **PROFINET DCP** — TLV device discovery, name/vendor/device ID/IP/role extraction from Identify responses

### Device Identification
- **25+ YAML signatures** covering 13 OT protocols and vendor-specific patterns
- **MAC OUI vendor lookup** — IEEE OUI database (~30k entries)
- **GeoIP enrichment** — Country identification for public IPs
- **CIP/PROFINET vendor ID lookup** — Protocol-specific vendor identification tables
- **Confidence scoring** — 5-level system: port (1) < pattern (2) < OUI (3) < payload (4) < deep parse (5)
- **Hot-reloadable signature editor** with CodeMirror 6 and live test runner

### Security Analysis
- **MITRE ATT&CK for ICS** — 19 automated technique detections across 7 protocols including T0855 (unauthorized commands), T0836 (firmware modification), T0843/T0845 (program download/upload), T0809 (data destruction), T0816 (device shutdown), T0814 (DoS), T0856 (alarm suppression)
- **Purdue Model** — Auto-assigns Purdue levels (L1-L4) based on observed behavior and protocol roles, detects cross-zone violations
- **Anomaly scoring** — Polling interval deviations, role reversals, unexpected public IPs

### External Tool Integration
- **Zeek** — Import conn.log, modbus.log, dnp3.log, s7comm.log
- **Suricata** — Import EVE JSON (flow and alert events)
- **Nmap/Masscan** — Import scan results with `[active-scan]` tagging
- **Wireshark** — Auto-detect, right-click to open, frame-level inspection

### Reporting & Export
- **PDF assessment reports** — Professional reports with executive summary, asset inventory, findings, recommendations
- **CSV/JSON export** — Assets, connections, topology data
- **SBOM** — CISA BOD 23-01 aligned software bill of materials
- **STIX 2.1** — Threat intelligence bundles

### Session Management
- **SQLite persistence** — Save/load sessions with full asset history
- **`.kkj` archives** — Portable ZIP-based session format
- **Baseline drift detection** — Compare assessments, quantified drift score, new/missing/changed assets

### Advanced
- **Dark/light/system theme** — Persistent preference with OS detection
- **CLI** — `--open <file>` (PCAP or .kkj), `--import-pcap <path>`
- **Plugin architecture** — Manifest-based plugin discovery

---

## Beyond GRASSMARLIN

| Capability | GRASSMARLIN 3.2 | Kusanagi Kajiki |
|------------|----------------|-----------------|
| Signature format | XML (opaque) | YAML (human-readable, git-friendly) |
| Security analysis | None | ATT&CK for ICS (19 detections) + Purdue + anomaly |
| Deep protocol parsing | Limited | 7 ICS protocols with full dissection |
| External tool integration | None | Zeek, Suricata, Nmap, Masscan |
| Reporting | None | PDF assessment reports |
| Compliance export | None | SBOM (CISA BOD 23-01), STIX 2.1 |
| Baseline comparison | None | Session drift detection with scoring |
| Session format | XML archives | SQLite + portable .kkj ZIP |
| Theming | Java Swing | Modern dark/light CSS custom properties |
| CLI support | None | `--open`, `--import-pcap` |
| Architecture | Monolithic Java | 10 Rust crates + SvelteKit frontend |

---

## Supported Protocols

| Protocol | Port(s) | Detection | Standard / Vendor |
|----------|---------|-----------|-------------------|
| Modbus TCP | 502 | Deep parse | Schneider Electric, multi-vendor |
| DNP3 | 20000 | Deep parse | IEEE 1815 (utilities, substations) |
| EtherNet/IP (CIP) | 44818, 2222 | Deep parse | Rockwell / Allen-Bradley (ODVA) |
| S7comm | 102 | Deep parse | Siemens S7 PLCs |
| BACnet/IP | 47808 | Deep parse | ASHRAE (building automation) |
| IEC 60870-5-104 | 2404 | Deep parse | Power grid SCADA |
| PROFINET DCP | 34962-34964 | Deep parse | Siemens / PROFIBUS International |
| OPC UA | 4840 | Port + Signature | OPC Foundation |
| MQTT | 1883, 8883 | Port | IIoT gateways |
| HART-IP | 5094 | Port | Process instrumentation |
| Foundation Fieldbus HSE | 1089-1091 | Port | Process automation |
| GE SRTP | 18245-18246 | Port + Signature | GE Automation PLCs |
| Wonderware SuiteLink | 5007 | Port + Signature | AVEVA / Wonderware |

---

## Screenshots

<!-- TODO: Add screenshot of LogicalView — fcose topology with compound subnet nodes -->
<!-- TODO: Add screenshot of PhysicalView — Cisco switch/port topology -->
<!-- TODO: Add screenshot of InventoryView — asset table with edit panel and confidence scoring -->
<!-- TODO: Add screenshot of AnalysisView — ATT&CK findings and Purdue diagram -->
<!-- TODO: Add screenshot of ExportView — PDF report generation -->

---

## Installation

**Quick start:** Clone → `npm install` → drop a PCAP in `tests/pcaps/` → `npm run tauri dev` → import the PCAP from the Capture tab.

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
npm run tauri dev
```

### Ubuntu / Debian

```bash
sudo apt install libpcap-dev libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf
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

**Prerequisites (install in order):**
1. **Visual Studio C++ Build Tools** — "Desktop development with C++" workload
2. **Rust** via [rustup.rs](https://rustup.rs) (stable-x86_64-pc-windows-msvc)
3. **Npcap** — check "Install Npcap in WinPcap API-compatible Mode", download SDK, set `LIB` to SDK `Lib\x64`
4. **Node.js** LTS

```powershell
git clone https://github.com/TheSecurityLead/KusanagiNoKajiki.git
cd KusanagiNoKajiki
npm install
npm run build
npm run tauri dev
```

> If `npm install` fails with ERESOLVE, see Troubleshooting below.

### Live Capture Without Root (Linux)

```bash
sudo setcap cap_net_raw,cap_net_admin=eip src-tauri/target/release/kusanaginokajiki
```

---

## Quick Start

1. **Import a PCAP** — Capture tab → Import PCAP File(s)
2. **Explore topology** — Topology tab → interactive graph grouped by subnet
3. **Inspect devices** — Inventory tab → vendor ID, protocols, confidence, deep parse details
4. **Run analysis** — Analysis tab → Run Analysis → ATT&CK findings, Purdue levels, anomalies
5. **Export report** — Export tab → PDF, CSV, SBOM, or STIX

### CLI

```bash
kusanaginokajiki --open capture.pcap
kusanaginokajiki --open session.kkj
kusanaginokajiki --import-pcap /path/to/capture.pcap
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│  SvelteKit Frontend (Tauri Webview)                        │
│  Topology · Inventory · Analysis · Export · Settings       │
├────────────────────────────────────────────────────────────┤
│  Tauri IPC: 59+ Commands + Event Streaming                 │
├────────────────────────────────────────────────────────────┤
│  Rust Backend (10 crates)                                  │
│  gm-capture · gm-parsers · gm-signatures · gm-topology    │
│  gm-db · gm-physical · gm-ingest · gm-analysis            │
│  gm-report · commands                                      │
└────────────────────────────────────────────────────────────┘
```

**Data Pipeline:** PCAP → L2-L4 parsing → protocol ID + deep parse → signature matching → topology graph → OUI/GeoIP enrichment → ATT&CK analysis → SQLite persistence → PDF/CSV/STIX reporting → frontend visualization.

**Tech Stack:** Tauri 2.0, pcap, etherparse, petgraph, rusqlite, genpdf, clap 4 (Rust). SvelteKit, Svelte 5, TypeScript, Cytoscape.js + fcose, Tailwind CSS 4, CodeMirror 6 (Frontend).

---

## Testing

```bash
cd src-tauri && cargo test --all          # 127+ Rust tests
cargo clippy --all -- -D warnings         # Zero warnings
cd .. && npm run check                    # Frontend type check
```

**Test data:** [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap), [Wireshark Samples](https://wiki.wireshark.org/SampleCaptures), [4SICS](https://www.netresec.com/?page=PCAP4SICS)

---

## Troubleshooting

**`npm install` fails with ERESOLVE:** Clean install with pinned versions. Do NOT use `npm audit fix --force`.

**`error: linker 'link.exe' not found`:** Install VS Build Tools with "Desktop development with C++". Restart terminal.

**Npcap linking errors on Windows:** Ensure WinPcap API-compatible mode. Set `LIB` to Npcap SDK `Lib/x64`.

**`Zone.Identifier` files in git:** Windows NTFS artifacts. Blocked by .gitignore. Remove: `find . -name "*Zone.Identifier" -delete`

---

## Contributing

Contributions welcome — signatures for additional ICS vendors, protocol parsers, test PCAPs, and bug reports.

---

## License

Apache License 2.0 — See [LICENSE](LICENSE).

---

## Acknowledgments

- **NSA Cybersecurity** — Original [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) concept
- **MITRE** — [ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) framework
- **CISA** — [ICSNPP](https://github.com/cisagov) Zeek parsers as protocol reference, [BOD 23-01](https://www.cisa.gov/binding-operational-directive-23-01)
- **ODVA** — EtherNet/IP and CIP specifications
- **Tauri**, **Cytoscape.js**, **DB-IP**, **IEEE OUI**
