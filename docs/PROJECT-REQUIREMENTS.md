# PROJECT-REQUIREMENTS.md — Kusanagi Kajiki Implementation Tracking

## Phase Summary

| Phase | Scope | Tests | Status |
|-------|-------|-------|--------|
| 0 | Foundation | 10 | ✅ Complete |
| 1 | PCAP Import & Parsing | 10 | ✅ Complete |
| 2 | Topology Visualization | 18 | ✅ Complete |
| 3 | Signature Engine | 18 | ✅ Complete |
| 4 | Deep Protocol Parsing (Modbus/DNP3) | 32 | ✅ Complete |
| 5 | Live Capture | 34 | ✅ Complete |
| 6 | Persistence & Asset Management | 58 | ✅ Complete |
| 7 | Physical Topology | 73 | ✅ Complete |
| 8 | External Tool Integration | 84 | ✅ Complete |
| 9 | Export & Reporting | 103 | ✅ Complete |
| 10 | Security Analysis | 127 | ✅ Complete |
| 11 | Advanced Features | 127 | ✅ Complete |
| **12A** | **Protocol Expansion: EtherNet/IP, S7comm, BACnet** | **164** | ✅ Complete |
| **12B** | **Protocol Expansion: IEC 104, PROFINET DCP** | **180** | ✅ Complete |
| **12C** | **Protocol Expansion: OPC UA, MQTT + feature gaps** | **~195** | 📋 Planned |

## Phase 12A — Protocol Expansion (Core Manufacturing + BAS)

### Scope
Add native Rust deep parsers for the three highest-value ICS protocols. Each parser feeds into the existing processor pipeline (signatures → ATT&CK → Purdue → topology → frontend).

### Deliverables

| # | Deliverable | File(s) | Status |
|---|-------------|---------|--------|
| 1 | EtherNet/IP + CIP parser | `gm-parsers/src/enip.rs` | ✅ Done |
| 2 | S7comm parser | `gm-parsers/src/s7comm.rs` | ✅ Done |
| 3 | BACnet parser | `gm-parsers/src/bacnet.rs` | ✅ Done |
| 4 | Vendor ID lookup tables | `gm-parsers/src/vendor_tables.rs` | ✅ Done |
| 5 | DeepParseResult variants | `gm-parsers/src/lib.rs` | ✅ Done |
| 6 | deep_parse() dispatch arms | `gm-parsers/src/lib.rs` | ✅ Done |
| 7 | ATT&CK detections (EtherNet/IP) | `gm-analysis/src/attack.rs` | ✅ Done |
| 8 | ATT&CK detections (S7comm) | `gm-analysis/src/attack.rs` | ✅ Done |
| 9 | ATT&CK detections (BACnet) | `gm-analysis/src/attack.rs` | ✅ Done |
| 10 | YAML signatures (3 files) | `src-tauri/signatures/enip_cip.yaml`, `s7comm.yaml`, `bacnet.yaml` | ✅ Done |
| 11 | Purdue auto-classification updates | `gm-analysis/src/purdue.rs` | ✅ Done |
| 12 | Frontend: ProtocolStats updates | `ProtocolStats.svelte` | ✅ Done |
| 13 | Frontend: InventoryView detail panels | `InventoryView.svelte` | ✅ Done |
| 14 | Frontend: TypeScript type updates | `types/index.ts` | ✅ Done |
| 15 | Unit tests (≥6 per parser) | Test modules in each .rs file | ✅ Done |

### Test Requirements
- ≥6 unit tests per parser (parse valid, parse truncated, parse each message type)
- All existing 127 tests continue passing
- `cargo clippy --all -- -D warnings` clean
- `npm run check` clean
- Estimated new tests: ~30 → cumulative ~157

### Acceptance Criteria — ALL MET ✅
- [x] `cargo test --all` passes with ≥155 tests (actual: 180)
- [x] EtherNet/IP ListIdentity extracts vendor ID, device type, product name, serial, firmware
- [x] S7comm extracts function codes, rack/slot from COTP TSAP, client/server roles
- [x] BACnet I-Am extracts device instance and vendor ID
- [x] New ATT&CK detections fire on test data (T0836, T0843, T0845, T0809, T0816, T0811)
- [x] Vendor ID → name lookup works for CIP vendor IDs
- [x] Frontend displays new protocol info in InventoryView detail panel
- [x] No regressions in PCAP import pipeline

---

## Phase 12B — Protocol Expansion (Power Grid + Discovery)

### Deliverables

| # | Deliverable | File(s) | Status |
|---|-------------|---------|--------|
| 1 | IEC 104 parser | `gm-parsers/src/iec104.rs` | ✅ Done |
| 2 | PROFINET DCP parser | `gm-parsers/src/profinet_dcp.rs` | ✅ Done |
| 3 | DeepParseResult + dispatch | `gm-parsers/src/lib.rs` | ✅ Done |
| 4 | ATT&CK detections (IEC 104) | `gm-analysis/src/attack.rs` | ✅ Done |
| 5 | ATT&CK detections (PROFINET) | `gm-analysis/src/attack.rs` | — (no ATT&CK techniques for passive DCP discovery) |
| 6 | YAML signatures (2 files) | `iec104.yaml`, `profinet_dcp.yaml` | ✅ Done |
| 7 | PROFINET vendor ID table | `gm-parsers/src/vendor_tables.rs` | ✅ Done |
| 8 | Asset CSV import (backend) | `commands/session.rs` | 📋 Deferred to 12C |
| 9 | Asset CSV import (frontend) | `CaptureView.svelte` or `InventoryView.svelte` | 📋 Deferred to 12C |
| 10 | Frontend updates | Type definitions + display | ✅ Done |
| 11 | Unit tests (≥5 per parser) | Test modules | ✅ Done |

---

## Phase 12C — Modern Protocols + Integration

### Deliverables

| # | Deliverable | Status |
|---|-------------|--------|
| 1 | OPC UA Binary parser | ☐ TODO |
| 2 | MQTT deep parse | ☐ TODO |
| 3 | Suricata alert ↔ device correlation | ☐ TODO |
| 4 | JA4 TLS fingerprinting | ☐ TODO |
| 5 | Enhanced protocol statistics | ☐ TODO |

---

## GRASSMARLIN 3.2 Parity — All Gaps Closed

| Original Feature | KNK Implementation | Phase |
|-----------------|-------------------|-------|
| XML session archives | `.kkj` ZIP archives (manifest.json + session.json) | 6 |
| Multi-PCAP import | `import_pcap(paths: Vec<String>)` with per-file tracking | 1 |
| Device role granularity | 25+ YAML sigs + Modbus FC 43/14 + deep parse + OUI | 3, 4 |
| Physical topology | Cisco IOS config/MAC/CDP/ARP parsers, Cytoscape graph | 7 |
| **Beyond parity** | ATT&CK, Purdue, Zeek/Suricata, PDF/SBOM/STIX, drift, theme, CLI | 8–11 |

---

## Technical Debt & Known Issues

### Must Fix Before Demo
- [ ] Audit all `unwrap()` calls in non-test code (see PROMPT-BUG-SCAN.md)
- [ ] Verify PCAP import pipeline end-to-end on all platforms
- [ ] Confirm Tauri command registration matches frontend wrappers

### Known Limitations
- OPC UA certificate extraction deferred (out of scope v1)
- Multi-user session merge deferred (out of scope v1)
- Plugin system is stubs only (manifest discovery, no execution)
- No TCP reassembly — deep parse operates on individual packets
- IPv6 traffic: detected but not fully parsed for ICS protocols
- VLAN-tagged (802.1Q) packets: depends on etherparse support

### Dependency Notes
- `pcap` crate C FFI: field widths differ by OS (see CLAUDE.md pitfalls)
- `rusqlite` bundled: avoids system SQLite dependency
- `genpdf`: limited font/layout control for PDF reports
- `quick-xml` 0.37: uses `@attr` syntax for Nmap XML attributes
- Fedora/WSL2: may need `--legacy-peer-deps` for npm install

---

## Effort Estimates

| Phase | Est. Lines | Est. Days |
|-------|-----------|-----------|
| 12A (EtherNet/IP, S7comm, BACnet) | ~2,500 | 12-16 |
| 12B (IEC 104, PROFINET DCP, CSV import) | ~800 | 5-7 |
| 12C (OPC UA, MQTT, JA4, correlation) | ~1,500 | 10-14 |
| **Total** | **~4,800** | **~27-37** |
