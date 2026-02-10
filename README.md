# GRASSMARLIN Reborn

**Modern ICS/SCADA passive network discovery and topology visualization tool.**

A ground-up rewrite of the NSA's [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) (archived 2023), rebuilt with **Tauri 2.0** (Rust backend) and **SvelteKit** (TypeScript frontend) for performance, security, and cross-platform support.

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Rust](https://img.shields.io/badge/rust-1.77+-orange)
![Tauri](https://img.shields.io/badge/tauri-2.0-blue)

> ⚠️ **Active Development** — This project is under active development. See the [Roadmap](#roadmap) for current status.

---

## What It Does

GRASSMARLIN Reborn passively discovers and maps Industrial Control System (ICS) and SCADA network devices by analyzing network traffic. It is designed for OT security assessments where **active scanning is not an option** — maintaining availability of industrial systems is paramount.

**Core Capabilities:**
- 📦 **PCAP Import** — Analyze captured network traffic offline
- 🔴 **Live Capture** — Real-time packet capture and analysis *(Phase 4)*
- 🗺️ **Topology Visualization** — Interactive network graph with Cytoscape.js
- 🏭 **ICS Protocol Detection** — Modbus, DNP3, EtherNet/IP, BACnet, S7comm, OPC UA
- 📋 **Asset Inventory** — Searchable, filterable device database
- 🔍 **Device Classification** — Automatic PLC/RTU/HMI/Historian identification
- 📊 **Protocol Statistics** — Traffic breakdown and anomaly indicators

**Supported ICS Protocols:**

| Protocol | Port(s) | Vendor/Standard |
|----------|---------|-----------------|
| Modbus TCP | 502 | Modicon / Schneider Electric |
| DNP3 | 20000 | IEEE 1815 (utilities) |
| EtherNet/IP | 44818, 2222 | Rockwell / Allen-Bradley |
| BACnet/IP | 47808 | ASHRAE (building automation) |
| S7comm | 102 | Siemens |
| OPC UA | 4840 | OPC Foundation |
| IEC 60870-5-104 | 2404 | Power grid SCADA |
| PROFINET | 34962-34964 | Siemens / PI |

---

## Architecture

```
┌──────────────────────────────────────────────┐
│  SvelteKit Frontend (Tauri Webview)          │
│  ├── Topology View (Cytoscape.js)            │
│  ├── Asset Inventory (filterable table)      │
│  ├── Capture Controls (import / live)        │
│  └── Protocol Statistics                     │
├──────────────────────────────────────────────┤
│  Tauri IPC (Commands + Event Streaming)      │
├──────────────────────────────────────────────┤
│  Rust Backend                                │
│  ├── gm-capture  (pcap + etherparse)         │
│  ├── gm-parsers  (protocol identification)   │
│  ├── gm-topology (petgraph)                  │
│  └── gm-db       (SQLite persistence)        │
└──────────────────────────────────────────────┘
```

---

## Getting Started

### Prerequisites

- **Rust** ≥ 1.77 — [Install via rustup](https://rustup.rs)
- **Node.js** ≥ 22 — [Install via nvm](https://github.com/nvm-sh/nvm)
- **libpcap** development headers

#### Platform-specific dependencies:

**Linux (Ubuntu/Debian):**
```bash
sudo apt install libpcap-dev libwebkit2gtk-4.1-dev \
  libappindicator3-dev librsvg2-dev patchelf
```

**macOS:**
```bash
brew install libpcap
# Xcode command line tools are also required
xcode-select --install
```

**Windows:**
- Install [Npcap](https://npcap.com) (check "Install Npcap in WinPcap API-compatible Mode")
- Download the [Npcap SDK](https://npcap.com/#download) and add the `Lib/x64` folder to your `LIB` environment variable

### Build & Run

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/grassmarlin-reborn.git
cd grassmarlin-reborn

# Install frontend dependencies
npm install

# Run in development mode (hot-reload)
npm run tauri dev

# Build for production
npm run tauri build
```

### Running Without Root (Linux)

For live capture without running as root, grant the binary network capture capabilities:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip src-tauri/target/release/grassmarlin-reborn
```

---

## Usage

### PCAP Import

1. Navigate to the **Capture** tab
2. Click **Import PCAP File**
3. Select a `.pcap` or `.pcapng` file
4. View results in the **Topology** and **Inventory** tabs

### Test Data

Public ICS PCAP samples for testing:
- [automayt/ICS-pcap](https://github.com/automayt/ICS-pcap) — Curated ICS protocol captures
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures) — Various protocol samples
- [4SICS Geek Lounge](https://www.netresec.com/?page=PCAP4SICS) — Real ICS network traffic

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 0 — Foundation | ✅ | Project scaffold, interface listing |
| 1 — PCAP Import | 🔨 | File import, Layer 2-4 parsing, protocol detection |
| 2 — Topology | ⏳ | Cytoscape.js graph visualization |
| 3 — Deep Parsing | ⏳ | Modbus/DNP3 function code analysis |
| 4 — Live Capture | ⏳ | Real-time packet capture + streaming |
| 5 — Persistence | ⏳ | SQLite database, session management |
| 6 — Export | ⏳ | CSV, JSON, SVG topology export |
| 7 — Advanced | ⏳ | MITRE ATT&CK mapping, Purdue overlay, anomaly detection |

---

## Acknowledgments

- **NSA Cybersecurity** — Original [GRASSMARLIN](https://github.com/nsacyber/GRASSMARLIN) tool and concept
- **Step Function I/O** — [rodbus](https://github.com/stepfunc/rodbus) and [dnp3](https://github.com/stepfunc/dnp3) Rust crates
- **Tauri** — Cross-platform app framework
- **Cytoscape.js** — Network graph visualization

---

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

*This is an independent project inspired by GRASSMARLIN. It contains no original GRASSMARLIN source code.*
