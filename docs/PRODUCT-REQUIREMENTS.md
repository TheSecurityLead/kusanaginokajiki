# PRODUCT-REQUIREMENTS.md — Kusanagi Kajiki Product Requirements

## Product Positioning

Kusanagi Kajiki is a **field assessment tool** for ICS security assessors. Single binary, no infrastructure, works offline. The user arrives at a plant, plugs into a SPAN port or loads pcaps, and needs fast answers: what's on this network, what's talking to what, what protocols are in use, and what security concerns exist.

**NOT a SOC platform.** No distributed sensors, no long-term monitoring, no SIEM integration.

---

## Protocol Support Matrix

### Detection Levels
- **Port**: Identified by TCP/UDP port number (confidence 1)
- **Signature**: Matched by YAML payload/OUI patterns (confidence 2-4)
- **Deep Parse**: Full protocol dissection with function code analysis, device identification, behavioral profiling (confidence 5)

### Current Protocols (19 detected)

| Protocol | Port(s) | Detection | Deep Parse | Device ID | ATT&CK | Status |
|----------|---------|-----------|-----------|-----------|--------|--------|
| Modbus TCP | 502 | Deep | ✅ | FC 43/14 vendor/product | T0855, T0814 | ✅ Complete |
| DNP3 | 20000 | Deep | ✅ | Address, master/outstation | T0856, T0846 | ✅ Complete |
| EtherNet/IP + CIP | 44818, 2222 | Signature | 🔧 | ListIdentity: vendor/product/serial/firmware | T0855, T0836, T0843, T0846 | 🔧 Phase 12A |
| S7comm | 102 | Signature | 🔧 | TSAP rack/slot, SZL identity | T0843, T0845, T0809, T0816, T0855 | 🔧 Phase 12A |
| BACnet/IP | 47808 | Signature | 🔧 | I-Am: device instance/vendor | T0855, T0856, T0816, T0811 | 🔧 Phase 12A |
| IEC 60870-5-104 | 2404 | Port | 🔧 | Station address, type IDs | T0855, T0814, T0816 | 🔧 Phase 12B |
| PROFINET DCP | 34962-34964 | Port | 🔧 | Name/vendor/device ID/IP/role | T0846 | 🔧 Phase 12B |
| OPC UA | 4840 | Port+Sig | 📋 | Endpoints, security policies | T0859, T0862 | 📋 Phase 12C |
| MQTT | 1883, 8883 | Port | 📋 | Topics, client IDs, broker | — | 📋 Phase 12C |
| HART-IP | 5094 | Port | ☐ | — | — | Backlog |
| Foundation Fieldbus HSE | 1089-1091 | Port | ☐ | — | — | Backlog |
| GE SRTP | 18245-18246 | Port+Sig | ☐ | — | — | Backlog |
| Wonderware SuiteLink | 5007 | Port+Sig | ☐ | — | — | Backlog |
| HTTP/S | 80, 443 | Port | ☐ | — | — | IT protocol |
| DNS | 53 | Port | ☐ | — | — | IT protocol |
| SSH | 22 | Port | ☐ | — | — | IT protocol |
| RDP | 3389 | Port | ☐ | — | — | IT protocol |
| SNMP | 161, 162 | Port | ☐ | — | — | IT protocol |

---

## ATT&CK for ICS Detection Specifications

### Existing Detections (Phases 0–11)

| ID | Technique | Protocol | Trigger | Severity |
|----|-----------|----------|---------|----------|
| T0855 | Unauthorized Command Message | Modbus | Broadcast writes (unit 0/255), high fan-out writes (5+ targets) | Critical/High |
| T0814 | Denial of Service | Modbus | FC 8 diagnostics from non-engineering station | High |
| T0856 | Spoof Reporting Message | DNP3 | Unsolicited response (FC 130) to unknown master | Medium |
| T0846 | Remote System Discovery | Any | Unknown/IT device polling 3+ PLCs | High |
| T0886 | Remote Services | Purdue | Direct L1↔L4 communication | Medium |

### New Detections (Phase 12A)

| ID | Technique | Protocol | Trigger | Severity |
|----|-----------|----------|---------|----------|
| T0855 | Unauthorized Command | EtherNet/IP | CIP Write (0x4D) or ReadModifyWrite (0x4E) to Assembly class (0x04) | High |
| T0836 | Modify Program | EtherNet/IP | CIP access to File class (0x37) — firmware upload/download | Critical |
| T0846 | Remote Discovery | EtherNet/IP | ListIdentity (0x0063) broadcast from unknown source | Medium |
| T0843 | Program Download | S7comm | Function 0x1D (Download Start), 0x1E, 0x1F (Download End) | Critical |
| T0845 | Program Upload | S7comm | Function 0x1A (Upload Start), 0x1B, 0x1C (Upload End) | High |
| T0809 | Data Destruction | S7comm | PI Service (0x28) with block delete parameters | Critical |
| T0816 | Device Restart/Shutdown | S7comm | Function 0x29 (PLC Stop) | Critical |
| T0855 | Unauthorized Command | S7comm | WriteVar (0x05) to output area (area byte 0x82) | High |
| T0846 | Remote Discovery | S7comm | SZL reads (Userdata SZL-ID 0x001C) — identity enumeration | Medium |
| T0855 | Unauthorized Command | BACnet | WriteProperty (0x0F) to AnalogOutput/BinaryOutput Present-Value | High |
| T0856 | Alarm Suppression | BACnet | WriteProperty to NotificationClass or EventEnable properties | High |
| T0816 | Device Restart | BACnet | ReinitializeDevice service (0x14) | High |
| T0811 | Communication Control | BACnet | DeviceCommunicationControl service (0x11) | High |
| T0846 | Remote Discovery | BACnet | Who-Is broadcasts from unknown sources | Medium |

### New Detections (Phase 12B)

| ID | Technique | Protocol | Trigger | Severity |
|----|-----------|----------|---------|----------|
| T0855 | Unauthorized Command | IEC 104 | Command type IDs (45-69) from unexpected source | High |
| T0814 | Interrogation Flooding | IEC 104 | High-rate Type 100 (C_IC_NA_1) from single source | Medium |
| T0816 | Process Reset | IEC 104 | Type 105 (C_RP_NA_1, Reset Process) | Critical |
| T0846 | Remote Discovery | PROFINET | DCP Identify multicasts from unknown hosts | Medium |

---

## Device Identification Requirements

### Per-Protocol Device Info

| Protocol | Fields Extracted | Confidence |
|----------|-----------------|-----------|
| Modbus | FC 43/14: vendor name, product code; master/slave role; register ranges; polling interval | 5 |
| DNP3 | DNP3 address; master/outstation role; function codes; unsolicited response detection | 5 |
| EtherNet/IP | Vendor ID+name, device type, product code, product name, serial number, firmware major/minor, scanner/adapter role | 5 |
| S7comm | Rack/slot (from TSAP), S7 function codes, client/server role, PDU length; SZL: order number, firmware version, module type, serial | 5 |
| BACnet | Device instance number, vendor ID, max APDU length, segmentation support, client/server role; object type/instance for property ops | 5 |
| IEC 104 | Station address, type IDs used (monitoring vs command), cause of transmission, master/outstation role | 5 |
| PROFINET DCP | Name of station, vendor name, vendor ID, device ID, device role (IO-Device/Controller/Supervisor), IP/subnet/gateway, MAC | 5 |

### Vendor ID Lookup Tables

| Source | Coverage | File |
|--------|----------|------|
| IEEE OUI | ~30k MAC prefixes → manufacturer | `data/oui.tsv` |
| DB-IP | Public IP → country | `data/dbip-country-lite.mmdb` |
| CIP Vendor IDs (ODVA) | ~30 major vendors → name | `vendor_tables.rs` |
| PROFINET Vendor IDs | ~12 major vendors → name | `vendor_tables.rs` |

---

## Purdue Model Auto-Classification

### Assignment Rules (updated for new protocols)

| Purdue Level | Assignment Criteria |
|-------------|-------------------|
| L1 (PLCs/RTUs) | Modbus server, DNP3 outstation, S7comm server, EtherNet/IP adapter, IEC 104 outstation, PROFINET IO-Device |
| L2 (HMI/SCADA) | Multi-OT client polling, EtherNet/IP scanner, BACnet client, S7comm client, IEC 104 master, PROFINET IO-Controller |
| L3 (Historians) | OPC UA server, data aggregation patterns, Zeek-imported historian signatures |
| L3.5 (DMZ) | Dual-homed (both OT and IT protocol connections) |
| L4 (IT/Enterprise) | IT-only protocols (HTTP, DNS, RDP, SSH, SNMP) |

---

## Feature Requirements

### Core Features (Complete)

| Feature | Description | Status |
|---------|-------------|--------|
| Multi-PCAP Import | Simultaneous file processing, per-packet origin tracking | ✅ |
| Live Capture | Real-time streaming, pause/resume, ring buffer, PCAP save | ✅ |
| 19 Protocol Detection | Port + signature matching for 19 ICS/IT protocols | ✅ |
| Logical Topology | fcose layout, compound subnet nodes, drift highlighting | ✅ |
| Physical Topology | Cisco switch/port graph from IOS config imports | ✅ |
| Mesh View | All-to-all connection matrix | ✅ |
| Timeline Scrubber | Replay topology construction chronologically | ✅ |
| Device Inventory | Table + edit + detail + bulk + OUI + country + confidence | ✅ |
| Signature Editor | CodeMirror 6, live test runner | ✅ |
| PDF Reports | Professional assessment reports via genpdf | ✅ |
| CSV/JSON Export | Assets, connections, topology data | ✅ |
| SBOM Export | CISA BOD 23-01 aligned | ✅ |
| STIX 2.1 Export | Threat intelligence bundles | ✅ |
| Session Management | SQLite + .kkj ZIP archives | ✅ |
| Baseline Drift | Compare sessions, drift score, new/missing/changed | ✅ |
| Dark/Light Theme | Persistent preference with OS detection | ✅ |
| CLI | `--open`, `--import-pcap` | ✅ |
| Plugin Architecture | Manifest-based discovery (stubs) | ✅ |

### New Features (Phase 12)

| Feature | Description | Phase | Status |
|---------|-------------|-------|--------|
| EtherNet/IP Deep Parse | ListIdentity extraction, CIP service analysis | 12A | ☐ TODO |
| S7comm Deep Parse | TPKT/COTP/S7, function codes, rack/slot, SZL | 12A | ☐ TODO |
| BACnet Deep Parse | BVLCI/NPDU/APDU, I-Am, service identification | 12A | ☐ TODO |
| CIP Vendor ID Lookup | ODVA vendor ID → manufacturer name | 12A | ☐ TODO |
| Expanded ATT&CK (14 new detections) | See ATT&CK section above | 12A | ☐ TODO |
| Enhanced Purdue Classification | New protocol role → Purdue level mapping | 12A | ☐ TODO |
| IEC 104 Deep Parse | APCI frames, ASDU types, command classification | 12B | ☐ TODO |
| PROFINET DCP Deep Parse | TLV device discovery, name/vendor/IP extraction | 12B | ☐ TODO |
| PROFINET Vendor ID Lookup | Vendor ID → manufacturer name | 12B | ☐ TODO |
| Asset CSV Import | Import known asset list, correlate with discovery | 12B | ☐ TODO |
| OPC UA Binary Parse | Endpoint discovery, security policies | 12C | ☐ TODO |
| MQTT Deep Parse | Topics, client IDs, broker identification | 12C | ☐ TODO |
| Suricata Alert Correlation | Link Suricata alerts to KNK device inventory | 12C | ☐ TODO |
| JA4 TLS Fingerprinting | Device fingerprinting from TLS ClientHello | 12C | ☐ TODO |

---

## Features Evaluated and Rejected

| Feature | Reason |
|---------|--------|
| File extraction/carving (ClamAV/YARA) | Requires deep TCP reassembly, massive effort. Use NetworkMiner/Wireshark instead. |
| Distributed sensors (Hedgehog-style) | Separate product. KNK is a field tool — assessor is physically present. |
| Full packet indexing (Arkime-style) | SOC feature, not field assessment. |
| Active scanning capability | Violates passive-only principle. Active scans can crash PLCs. |

---

## Competitive Positioning

| Capability | GRASSMARLIN | Kusanagi Kajiki | Claroty | Nozomi | Dragos |
|------------|------------|-----------------|---------|--------|--------|
| Deployment | Desktop (Java) | Desktop (single binary) | Appliance/cloud | Appliance/cloud | Appliance/cloud |
| Cost | Free (archived) | Free (open source) | Enterprise license | Enterprise license | Enterprise license |
| Deep protocol parsing | Limited | 7 protocols (expanding) | 200+ | 100+ | 100+ |
| ATT&CK mapping | None | 19 technique detections | Yes | Yes | Yes |
| Purdue Model | None | Auto-classification | Yes | Yes | Yes |
| Offline operation | Yes | Yes | Partial | Partial | Partial |
| Source available | Archived | Yes (Apache 2.0) | No | No | No |
| Single binary | No (JVM) | Yes | No | No | No |
| SBOM/STIX export | No | Yes | Partial | Partial | Partial |
| External tool ingest | No | Zeek/Suricata/Nmap/Masscan | Limited | Zeek | Limited |

**KNK differentiator:** Free, open-source, single binary, offline-first, full ATT&CK coverage with source code transparency. Designed for assessors who need to drop into a plant and deliver results in days, not deploy infrastructure.
