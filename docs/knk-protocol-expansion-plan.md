# Kusanagi No Kajiki — Protocol Expansion & Feature Gap Plan

**Version:** 1.0 · **Date:** March 10, 2026 · **Author:** David (The Security Lead) + Claude

---

## 1. Validated Priority List

After reviewing real-world OT prevalence data, device-identification value, ATT&CK coverage, and implementation complexity, here is the adjusted priority order. Your original list was strong — I've made two swaps and added reasoning.

### Final Priority Order

| # | Protocol | Prevalence | Device ID Value | ATT&CK Value | Complexity | Est. Lines |
|---|----------|-----------|----------------|-------------|-----------|-----------|
| 1 | **EtherNet/IP + CIP** | ★★★★★ | ★★★★★ | ★★★★ | Medium-High | ~600 |
| 2 | **S7comm** | ★★★★★ | ★★★★★ | ★★★★★ | Medium | ~450 |
| 3 | **BACnet** | ★★★★ | ★★★★★ | ★★★ | Medium | ~400 |
| 4 | **IEC 104** | ★★★★ | ★★★ | ★★★★★ | Low-Medium | ~350 |
| 5 | **PROFINET DCP** | ★★★★ | ★★★★★ | ★★ | Low | ~250 |
| 6 | **OPC UA Binary** | ★★★ | ★★★★ | ★★★★ | High | ~700 |
| 7 | **MQTT** | ★★★ | ★★★ | ★★★ | Low | ~200 |
| 8 | **HART-IP** | ★★ | ★★★ | ★★ | Low | ~200 |
| 9 | **EtherCAT** | ★★ | ★★★ | ★ | Medium | ~350 |
| 10 | **Synchrophasor** | ★★ | ★★ | ★★★ | Low-Medium | ~300 |

**Reasoning for swaps vs your original:**

- **IEC 104 moved up to #4** (was #5): Power grid SCADA is where assessors encounter the highest-consequence environments. IEC 104's wire format is simpler than OPC UA (fixed APCI header + typed ASDUs), and it unlocks critical grid-specific ATT&CK detections. It should come before OPC UA.
- **PROFINET DCP moved up to #5** (was #6): DCP is a *discovery* protocol — it runs on nearly every PROFINET network and directly yields device name, vendor, IP, and MAC in cleartext. It's trivial to parse (fixed TLV format) and gives enormous device-identification value for very low effort. It's the best bang-for-buck protocol on this list.
- **OPC UA dropped to #6** (was #4): OPC UA Binary is the most complex protocol here. The encoding format is deeply nested with variable-length structures, optional extension objects, and security layer negotiations. The payoff is real but the implementation effort is 2-3x any other protocol. Save it for after the easier wins.

### Implementation Phases

- **Phase A (Ship first):** EtherNet/IP + CIP, S7comm, BACnet — covers ~70% of what assessors encounter
- **Phase B (Power grid + discovery):** IEC 104, PROFINET DCP — cheap wins with high impact
- **Phase C (Modern + niche):** OPC UA, MQTT, HART-IP, EtherCAT, Synchrophasor

---

## 2. Implementation Plans — Top 5 Protocols

### 2.1 EtherNet/IP + CIP (Port 44818 TCP/UDP, 2222 UDP I/O)

#### Wire Format

EtherNet/IP wraps CIP inside an encapsulation header on TCP port 44818:

```
Encapsulation Header (24 bytes):
  [0..1]   u16 LE  Command (0x0004=ListServices, 0x0063=ListIdentity, 0x0065=RegisterSession, 0x006F=SendRRData, 0x0070=SendUnitData)
  [2..3]   u16 LE  Length (of data following this header)
  [4..7]   u32 LE  Session Handle
  [8..11]  u32 LE  Status
  [12..19] [u8;8]  Sender Context
  [20..23] u32 LE  Options

CIP Encapsulated Data (inside SendRRData/SendUnitData):
  Common Packet Format items:
    Item Type ID (u16 LE) + Item Length (u16 LE) + Item Data
  
  CIP Message Router Request:
    [0]     u8    Service code (0x01=GetAttrAll, 0x0E=GetAttrSingle, 0x4C=Read, 0x4D=Write, 0x52=UnconnectedSend, 0x54=ForwardOpen)
    [1]     u8    Path size (in words)
    [2..n]  Path  Encoded segment path (Class/Instance/Attribute)
```

The **List Identity** response (command 0x0063) is the gold mine for passive discovery — devices broadcast this via UDP and it contains vendor ID, device type, product name, serial number, firmware revision.

```
List Identity Response Item:
  [0..1]   u16 LE  Encap Protocol Version
  [2..3]   u16 LE  Socket Address Family
  [4..5]   u16 BE  Socket Port
  [6..9]   u32 BE  Socket IP Address
  [10..17] [u8;8]  Socket Zeros
  [18..19] u16 LE  Vendor ID         ← device identification
  [20..21] u16 LE  Device Type       ← device identification
  [22..23] u16 LE  Product Code      ← device identification
  [24]     u8      Major Revision    ← firmware version
  [25]     u8      Minor Revision    ← firmware version
  [26..27] u16 LE  Status
  [28..31] u32 LE  Serial Number     ← unique device ID
  [32]     u8      Product Name Length
  [33..n]  String  Product Name      ← device identification
  [n+1]    u8      State
```

#### Rust Struct

```rust
// src-tauri/crates/gm-parsers/src/enip.rs

use serde::{Deserialize, Serialize};

/// EtherNet/IP encapsulation command codes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnipCommand {
    Nop,                    // 0x0000
    ListServices,           // 0x0004
    ListIdentity,           // 0x0063
    ListInterfaces,         // 0x0064
    RegisterSession,        // 0x0065
    UnregisterSession,      // 0x0066
    SendRRData,             // 0x006F
    SendUnitData,           // 0x0070
    Unknown(u16),
}

/// CIP service codes relevant for ICS assessment
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipService {
    GetAttributeAll,        // 0x01
    GetAttributeSingle,     // 0x0E
    SetAttributeSingle,     // 0x10
    Reset,                  // 0x05
    Read,                   // 0x4C
    Write,                  // 0x4D
    ReadModifyWrite,        // 0x4E
    UnconnectedSend,        // 0x52
    ForwardOpen,            // 0x54
    ForwardClose,           // 0x55
    Unknown(u8),
}

/// CIP object class targeted by the request
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipClass {
    Identity,               // 0x01
    MessageRouter,          // 0x02
    Assembly,               // 0x04
    Connection,             // 0x05
    ConnectionManager,      // 0x06
    File,                   // 0x37
    TcpIp,                  // 0xF5
    EthernetLink,           // 0xF6
    Unknown(u16),
}

/// Identity information extracted from ListIdentity responses
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnipIdentity {
    pub vendor_id: u16,
    pub device_type: u16,
    pub product_code: u16,
    pub major_revision: u8,
    pub minor_revision: u8,
    pub serial_number: u32,
    pub product_name: String,
    pub status: u16,
    pub state: u8,
}

/// Full EtherNet/IP + CIP parse result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnipInfo {
    pub command: EnipCommand,
    pub session_handle: u32,
    pub status: u32,
    /// Populated for ListIdentity responses
    pub identity: Option<EnipIdentity>,
    /// Populated when CIP message is present (SendRRData/SendUnitData)
    pub cip_service: Option<CipService>,
    pub cip_class: Option<CipClass>,
    pub cip_instance: Option<u32>,
    pub cip_attribute: Option<u16>,
    /// True if this is a response (service code has bit 7 set)
    pub is_response: bool,
    /// True if CIP status indicates error
    pub cip_error: bool,
    /// Role inference
    pub role: EnipRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnipRole {
    Scanner,    // originator — sends ForwardOpen, reads/writes
    Adapter,    // target — responds to connections
    Unknown,
}
```

#### Parsing Approach

1. Read the 24-byte encapsulation header (all fields little-endian).
2. Match on command code:
   - `0x0063` (ListIdentity): Parse Common Packet Format items, extract the Identity item, and populate `EnipIdentity`.
   - `0x006F` (SendRRData) / `0x0070` (SendUnitData): Parse CPF items to reach the CIP payload. Extract service code, path (class/instance/attribute).
3. Role detection: devices that send `ForwardOpen` (0x54) or `Write` (0x4D) are Scanners; devices that only respond are Adapters.
4. All reads are bounds-checked. Any truncation returns `None` from `parse()`.

#### Test Payloads (hex)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // ListIdentity Request (broadcast)
    const LIST_IDENTITY_REQ: &[u8] = &[
        0x63, 0x00, // Command: ListIdentity
        0x00, 0x00, // Length: 0
        0x00, 0x00, 0x00, 0x00, // Session: 0
        0x00, 0x00, 0x00, 0x00, // Status: 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Context
        0x00, 0x00, 0x00, 0x00, // Options
    ];

    // ListIdentity Response with identity data
    const LIST_IDENTITY_RESP: &[u8] = &[
        0x63, 0x00, // Command: ListIdentity
        0x3B, 0x00, // Length: 59
        0x00, 0x00, 0x00, 0x00, // Session
        0x00, 0x00, 0x00, 0x00, // Status
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Context
        0x00, 0x00, 0x00, 0x00, // Options
        // CPF: 1 item
        0x01, 0x00, // Item count: 1
        0x0C, 0x00, // Item type: ListIdentity
        0x33, 0x00, // Item length: 51
        // Identity item
        0x01, 0x00, // Encap version: 1
        0x00, 0x02, // Socket family: AF_INET
        0xAF, 0x12, // Socket port: 44818
        0xC0, 0xA8, 0x01, 0x0A, // IP: 192.168.1.10
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Zeros
        0x01, 0x00, // Vendor ID: 1 (Rockwell)
        0x0E, 0x00, // Device Type: 14 (PLC)
        0x36, 0x00, // Product Code: 54
        0x14,       // Major Revision: 20
        0x03,       // Minor Revision: 3
        0x00, 0x00, // Status: 0
        0x78, 0x56, 0x34, 0x12, // Serial: 0x12345678
        0x0F,       // Product Name Length: 15
        // "1756-L71/B V20" (15 bytes)
        0x31, 0x37, 0x35, 0x36, 0x2D, 0x4C, 0x37, 0x31,
        0x2F, 0x42, 0x20, 0x56, 0x32, 0x30, 0x00,
        0x03,       // State: 3
    ];

    // RegisterSession Request
    const REGISTER_SESSION: &[u8] = &[
        0x65, 0x00, // Command: RegisterSession
        0x04, 0x00, // Length: 4
        0x00, 0x00, 0x00, 0x00, // Session: 0
        0x00, 0x00, 0x00, 0x00, // Status
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, // Protocol version: 1
        0x00, 0x00, // Options flags: 0
    ];

    // SendRRData with CIP GetAttributeAll to Identity (class 0x01, instance 1)
    const SEND_RR_GET_IDENTITY: &[u8] = &[
        0x6F, 0x00, // Command: SendRRData
        0x16, 0x00, // Length: 22
        0x01, 0x00, 0x00, 0x00, // Session: 1
        0x00, 0x00, 0x00, 0x00, // Status
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        // Interface handle + timeout
        0x00, 0x00, 0x00, 0x00, // Interface: 0
        0x00, 0x00,             // Timeout: 0
        // CPF: 2 items
        0x02, 0x00, // Item count: 2
        0x00, 0x00, 0x00, 0x00, // Null address item
        0xB2, 0x00, // Unconnected data item
        0x06, 0x00, // Length: 6
        // CIP: GetAttributeAll, class 0x01, instance 1
        0x01,       // Service: GetAttributeAll
        0x02,       // Path size: 2 words
        0x20, 0x01, // Class segment: Identity (0x01)
        0x24, 0x01, // Instance segment: 1
    ];

    // CIP Write to Assembly — potential T0855
    const CIP_WRITE_ASSEMBLY: &[u8] = &[
        0x6F, 0x00,
        0x1A, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x02, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0xB2, 0x00,
        0x0A, 0x00,
        // CIP Write (0x4D) to Assembly class (0x04)
        0x4D,       // Service: Write
        0x03,       // Path size: 3 words
        0x20, 0x04, // Class: Assembly (0x04)
        0x24, 0x64, // Instance: 100
        0x30, 0x03, // Attribute: 3
        0xFF, 0xFF, // Write data
    ];

    #[test]
    fn test_parse_list_identity_request() {
        let result = parse(LIST_IDENTITY_REQ).expect("should parse");
        assert_eq!(result.command, EnipCommand::ListIdentity);
        assert!(result.identity.is_none()); // request has no identity
    }

    #[test]
    fn test_parse_list_identity_response() {
        let result = parse(LIST_IDENTITY_RESP).expect("should parse");
        assert_eq!(result.command, EnipCommand::ListIdentity);
        let id = result.identity.as_ref().expect("should have identity");
        assert_eq!(id.vendor_id, 1); // Rockwell
        assert_eq!(id.device_type, 14); // PLC
        assert_eq!(id.major_revision, 20);
        assert_eq!(id.serial_number, 0x12345678);
        assert!(id.product_name.starts_with("1756-L71"));
    }

    #[test]
    fn test_parse_register_session() {
        let result = parse(REGISTER_SESSION).expect("should parse");
        assert_eq!(result.command, EnipCommand::RegisterSession);
    }

    #[test]
    fn test_parse_cip_get_identity() {
        let result = parse(SEND_RR_GET_IDENTITY).expect("should parse");
        assert_eq!(result.command, EnipCommand::SendRRData);
        assert_eq!(result.cip_service, Some(CipService::GetAttributeAll));
        assert_eq!(result.cip_class, Some(CipClass::Identity));
    }

    #[test]
    fn test_parse_cip_write_assembly() {
        let result = parse(CIP_WRITE_ASSEMBLY).expect("should parse");
        assert_eq!(result.cip_service, Some(CipService::Write));
        assert_eq!(result.cip_class, Some(CipClass::Assembly));
    }

    #[test]
    fn test_truncated_packet() {
        let result = parse(&LIST_IDENTITY_REQ[..10]);
        assert!(result.is_none());
    }
}
```

#### ATT&CK Detections

| Technique | Detection Logic |
|-----------|----------------|
| **T0855** Unauthorized Command Message | CIP Write (0x4D) or ReadModifyWrite (0x4E) to Assembly or safety-class objects |
| **T0836** Modify Program | CIP service targeting File class (0x37) — firmware upload/download |
| **T0843** Program Download | ForwardOpen (0x54) followed by writes to program-related objects |
| **T0846** Remote System Discovery | ListIdentity (0x0063) broadcast — reconnaissance |
| **T0869** Standard Application Layer Protocol | Any EtherNet/IP traffic — protocol presence detection |

#### Estimated Effort
~600 lines of Rust. Medium-high complexity due to the nested CPF item / CIP path encoding, but the encapsulation header is straightforward and ListIdentity parsing is the immediate high-value target.

---

### 2.2 S7comm (Port 102 TCP)

#### Wire Format

S7comm sits inside TPKT → COTP → S7 payload:

```
TPKT Header (4 bytes):
  [0]     u8    Version (always 0x03)
  [1]     u8    Reserved (0x00)
  [2..3]  u16 BE  Length (total including TPKT)

COTP Header (variable, typ. 3 bytes for DT Data):
  [0]     u8    Length (of COTP header minus this byte)
  [1]     u8    PDU Type (0xF0=DT Data, 0xE0=CR, 0xD0=CC)
  [2]     u8    TPDU number / flags (for DT: 0x80=last fragment)
  
  For CR/CC:
  [0]     u8    Length
  [1]     u8    PDU Type (0xE0/0xD0)
  [2..3]  u16   Dst Reference
  [4..5]  u16   Src Reference
  [6]     u8    Class/Option
  [7..n]  TLV   Parameters (code 0xC0=TPDU size, 0xC1=src-tsap, 0xC2=dst-tsap)

S7 Header (10 or 12 bytes):
  [0]     u8    Protocol ID (always 0x32)
  [1]     u8    ROSCTR (PDU type):
                  0x01 = Job (request)
                  0x02 = Ack
                  0x03 = Ack_Data (response with data)
                  0x07 = Userdata
  [2..3]  u16 BE  Reserved (0x0000)
  [4..5]  u16 BE  PDU Reference (request ID)
  [6..7]  u16 BE  Parameter Length
  [8..9]  u16 BE  Data Length
  If ROSCTR == 0x02 or 0x03:
    [10]  u8    Error Class
    [11]  u8    Error Code

S7 Parameters (inside Job/Ack_Data):
  [0]     u8    Function Code:
                  0x04 = Read Var
                  0x05 = Write Var
                  0xF0 = Setup Communication
                  0x28 = PI Service (start/stop PLC)
                  0x29 = PLC Stop
                  0x1A = Upload Start
                  0x1B = Upload
                  0x1C = Upload End
                  0x1D = Download Start (request block download)
                  0x1E = Download
                  0x1F = Download End
```

The COTP Connection Request (0xE0) parameter 0xC1/0xC2 (src-tsap/dst-tsap) encodes the rack/slot addressing, which reveals device topology. The S7 SZL (System Status List) queries inside Userdata (ROSCTR 0x07) return device identity: order number, firmware version, module type, serial number.

#### Rust Struct

```rust
// src-tauri/crates/gm-parsers/src/s7comm.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum S7PduType {
    Job,           // 0x01 — request
    Ack,           // 0x02 — ack without data
    AckData,       // 0x03 — response with data
    Userdata,      // 0x07 — extension (SZL queries, diagnostics)
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum S7Function {
    ReadVar,               // 0x04
    WriteVar,              // 0x05
    SetupCommunication,    // 0xF0
    PiService,             // 0x28 (start PLC, activate)
    PlcStop,               // 0x29
    UploadStart,           // 0x1A
    Upload,                // 0x1B
    UploadEnd,             // 0x1C
    DownloadStart,         // 0x1D
    DownloadEnd,           // 0x1F
    DeleteBlock,           // part of PI Service
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CotpPduType {
    ConnectionRequest,     // 0xE0
    ConnectionConfirm,     // 0xD0
    DtData,                // 0xF0
    DisconnectRequest,     // 0x80
    Unknown(u8),
}

/// COTP Connection Request/Confirm parameters
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CotpParams {
    pub dst_ref: u16,
    pub src_ref: u16,
    pub src_tsap: Option<Vec<u8>>,
    pub dst_tsap: Option<Vec<u8>>,
    pub tpdu_size: Option<u8>,
    /// Extracted rack/slot from TSAP (dst_tsap bytes encode rack*32+slot)
    pub rack: Option<u8>,
    pub slot: Option<u8>,
}

/// Full S7comm parse result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S7Info {
    /// COTP layer info
    pub cotp_pdu_type: CotpPduType,
    pub cotp_params: Option<CotpParams>,
    /// S7 layer (None if COTP-only, e.g. CR/CC)
    pub s7_pdu_type: Option<S7PduType>,
    pub s7_function: Option<S7Function>,
    pub pdu_reference: Option<u16>,
    pub error_class: Option<u8>,
    pub error_code: Option<u8>,
    /// Setup Communication negotiated values
    pub max_amq_calling: Option<u16>,
    pub max_amq_called: Option<u16>,
    pub pdu_length: Option<u16>,
    /// SZL identity data (from Userdata SZL reads)
    pub szl_id: Option<u16>,
    pub order_number: Option<String>,
    pub firmware_version: Option<String>,
    pub module_type: Option<String>,
    pub serial_number: Option<String>,
    /// Role inference
    pub role: S7Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum S7Role {
    Client,     // HMI/SCADA/engineering station — sends Job requests
    Server,     // PLC — sends Ack_Data responses
    Unknown,
}
```

#### Parsing Approach

1. Validate TPKT (first byte 0x03), extract total length.
2. Parse COTP: length byte, PDU type. For CR/CC (0xE0/0xD0), extract TLV parameters including TSAP values. Derive rack/slot from dst-tsap.
3. For DT Data (0xF0): skip COTP, validate S7 protocol ID (0x32), extract ROSCTR, function code.
4. For Userdata (0x07): parse the sub-function group to detect SZL reads (method 0x04, subfunction 0x01, SZL-ID 0x001C for identity).
5. Role: senders of Job (0x01) are Clients; senders of AckData (0x03) are Servers.

#### Test Payloads

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // COTP Connection Request (TPKT + COTP CR)
    const COTP_CR: &[u8] = &[
        // TPKT
        0x03, 0x00, 0x00, 0x16, // Version 3, Length 22
        // COTP CR
        0x11,       // COTP Length: 17
        0xE0,       // PDU Type: CR
        0x00, 0x00, // Dst ref: 0
        0x00, 0x01, // Src ref: 1
        0x00,       // Class: 0
        // Parameters
        0xC0, 0x01, 0x0A,       // TPDU size: 1024
        0xC1, 0x02, 0x01, 0x00, // Src TSAP: 0x0100
        0xC2, 0x02, 0x01, 0x02, // Dst TSAP: 0x0102 → rack 0, slot 2
    ];

    // S7 Setup Communication Request
    const S7_SETUP_COMM: &[u8] = &[
        // TPKT
        0x03, 0x00, 0x00, 0x19, // Length 25
        // COTP DT Data
        0x02,       // Length: 2
        0xF0,       // PDU Type: DT Data
        0x80,       // Last fragment
        // S7 Header
        0x32,       // Protocol ID
        0x01,       // ROSCTR: Job
        0x00, 0x00, // Reserved
        0x00, 0x01, // PDU Reference: 1
        0x00, 0x08, // Parameter length: 8
        0x00, 0x00, // Data length: 0
        // S7 Parameters: Setup Communication
        0xF0,       // Function: Setup Communication
        0x00,       // Reserved
        0x00, 0x01, // Max AmQ calling: 1
        0x00, 0x01, // Max AmQ called: 1
        0x01, 0xE0, // PDU length: 480
    ];

    // S7 Read Var Request (reading DB1.DBW0)
    const S7_READ_VAR: &[u8] = &[
        0x03, 0x00, 0x00, 0x1F,
        0x02, 0xF0, 0x80,
        0x32, 0x01, 0x00, 0x00, 0x00, 0x02,
        0x00, 0x0E, // Param length: 14
        0x00, 0x00, // Data length: 0
        0x04,       // Function: Read Var
        0x01,       // Item count: 1
        // Item:
        0x12,       // Var spec
        0x0A,       // Length
        0x10,       // Syntax ID: S7ANY
        0x02,       // Transport size: WORD
        0x00, 0x01, // Count: 1
        0x00, 0x01, // DB number: 1
        0x84,       // Area: DB
        0x00, 0x00, 0x00, // Byte offset (bit address)
    ];

    // S7 Download Start — T0843
    const S7_DOWNLOAD: &[u8] = &[
        0x03, 0x00, 0x00, 0x13,
        0x02, 0xF0, 0x80,
        0x32, 0x01, 0x00, 0x00, 0x00, 0x03,
        0x00, 0x02, 0x00, 0x00,
        0x1D,       // Function: Download Start
        0x00,
    ];

    // S7 PLC Stop — T0816
    const S7_PLC_STOP: &[u8] = &[
        0x03, 0x00, 0x00, 0x15,
        0x02, 0xF0, 0x80,
        0x32, 0x01, 0x00, 0x00, 0x00, 0x04,
        0x00, 0x04, 0x00, 0x00,
        0x29,       // Function: PLC Stop
        0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_cotp_connection_request() {
        let result = parse(COTP_CR).expect("should parse");
        assert_eq!(result.cotp_pdu_type, CotpPduType::ConnectionRequest);
        let params = result.cotp_params.as_ref().unwrap();
        assert_eq!(params.rack, Some(0));
        assert_eq!(params.slot, Some(2));
    }

    #[test]
    fn test_setup_communication() {
        let result = parse(S7_SETUP_COMM).expect("should parse");
        assert_eq!(result.s7_pdu_type, Some(S7PduType::Job));
        assert_eq!(result.s7_function, Some(S7Function::SetupCommunication));
        assert_eq!(result.pdu_length, Some(480));
        assert_eq!(result.role, S7Role::Client);
    }

    #[test]
    fn test_read_var() {
        let result = parse(S7_READ_VAR).expect("should parse");
        assert_eq!(result.s7_function, Some(S7Function::ReadVar));
    }

    #[test]
    fn test_download_start() {
        let result = parse(S7_DOWNLOAD).expect("should parse");
        assert_eq!(result.s7_function, Some(S7Function::DownloadStart));
    }

    #[test]
    fn test_plc_stop() {
        let result = parse(S7_PLC_STOP).expect("should parse");
        assert_eq!(result.s7_function, Some(S7Function::PlcStop));
    }

    #[test]
    fn test_truncated_tpkt() {
        assert!(parse(&[0x03, 0x00]).is_none());
    }
}
```

#### ATT&CK Detections

| Technique | Detection Logic |
|-----------|----------------|
| **T0843** Program Download | Function 0x1D (Download Start), 0x1E (Download), 0x1F (Download End) |
| **T0845** Program Upload (theft) | Function 0x1A (Upload Start), 0x1B (Upload), 0x1C (Upload End) |
| **T0809** Data Destruction | PI Service (0x28) with "_DELE" block delete parameters |
| **T0816** Device Restart/Shutdown | Function 0x29 (PLC Stop) or PI Service with "_MODU" stop |
| **T0855** Unauthorized Command | WriteVar (0x05) to output areas (area byte 0x82) |
| **T0846** Remote System Discovery | SZL reads (Userdata SZL-ID 0x001C) — identity enumeration |

#### Estimated Effort
~450 lines. Medium complexity. TPKT/COTP is well-documented. The S7 header is fixed-size and function codes are straightforward. SZL parsing for identity adds some complexity but is bounded.

---

### 2.3 BACnet (Port 47808 UDP)

#### Wire Format

BACnet/IP uses a simple 4-byte header (BVLCI) followed by the NPDU and APDU:

```
BVLCI (BACnet Virtual Link Control Info — 4 bytes):
  [0]     u8    Type (always 0x81 for BACnet/IP)
  [1]     u8    Function:
                  0x00 = BVLC-Result
                  0x04 = Forwarded-NPDU
                  0x0A = Original-Unicast-NPDU
                  0x0B = Original-Broadcast-NPDU
  [2..3]  u16 BE  Length (total including BVLCI)

NPDU (Network Protocol Data Unit):
  [0]     u8    Version (always 0x01)
  [1]     u8    Control byte (bit flags: message type, expect reply, etc.)
  [2..n]  Optional source/dest network info

APDU (Application PDU — follows NPDU):
  [0] & 0xF0  PDU Type:
                  0x00 = Confirmed-Request
                  0x10 = Unconfirmed-Request
                  0x20 = SimpleAck
                  0x30 = ComplexAck
                  0x40 = SegmentAck
                  0x50 = Error
                  0x60 = Reject
                  0x70 = Abort

  Service Choices (for requests):
    Confirmed: 0x0C=ReadProperty, 0x0E=ReadPropMultiple, 0x0F=WriteProperty, 0x06=AtomicWriteFile
    Unconfirmed: 0x00=I-Am, 0x01=I-Have, 0x08=Who-Is, 0x07=Who-Has
```

The **I-Am** unconfirmed service (broadcast response to Who-Is) contains the device object's identity: Object ID (device instance number), max APDU length, segmentation support, and Vendor ID. Reading the Device Object properties via ReadProperty/ReadPropertyMultiple yields model name, firmware revision, application software version, description, and location.

#### Rust Struct

```rust
// src-tauri/crates/gm-parsers/src/bacnet.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BvlcFunction {
    BvlcResult,              // 0x00
    WriteBroadcastDistTable, // 0x01
    ForwardedNpdu,           // 0x04
    RegisterForeignDevice,   // 0x05
    OriginalUnicast,         // 0x0A
    OriginalBroadcast,       // 0x0B
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BacnetPduType {
    ConfirmedRequest,    // 0x0
    UnconfirmedRequest,  // 0x1
    SimpleAck,           // 0x2
    ComplexAck,          // 0x3
    SegmentAck,          // 0x4
    Error,               // 0x5
    Reject,              // 0x6
    Abort,               // 0x7
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BacnetService {
    // Confirmed
    ReadProperty,          // 0x0C
    ReadPropertyMultiple,  // 0x0E
    WriteProperty,         // 0x0F
    WritePropertyMultiple, // 0x10
    AtomicReadFile,        // 0x06
    AtomicWriteFile,       // 0x07
    SubscribeCov,          // 0x05
    ReinitializeDevice,    // 0x14
    DeviceCommunicationControl, // 0x11
    // Unconfirmed
    IAm,                   // 0x00
    IHave,                 // 0x01
    WhoIs,                 // 0x08
    WhoHas,                // 0x07
    UnconfirmedCovNotification, // 0x02
    TimeSynchronization,   // 0x06
    Unknown(u8),
}

/// BACnet object types (from the Object Identifier)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BacnetObjectType {
    AnalogInput,    // 0
    AnalogOutput,   // 1
    AnalogValue,    // 2
    BinaryInput,    // 3
    BinaryOutput,   // 4
    BinaryValue,    // 5
    Device,         // 8
    File,           // 10
    NotificationClass, // 15
    Schedule,       // 17
    TrendLog,       // 20
    Unknown(u16),
}

/// I-Am broadcast data
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BacnetIAm {
    pub device_instance: u32,
    pub max_apdu_length: u32,
    pub segmentation_supported: u8,
    pub vendor_id: u16,
}

/// Full BACnet parse result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacnetInfo {
    pub bvlc_function: BvlcFunction,
    pub npdu_version: u8,
    pub is_network_message: bool,
    pub pdu_type: Option<BacnetPduType>,
    pub service: Option<BacnetService>,
    /// Populated from I-Am broadcasts
    pub iam: Option<BacnetIAm>,
    /// Target object type + instance for property reads/writes
    pub object_type: Option<BacnetObjectType>,
    pub object_instance: Option<u32>,
    pub property_id: Option<u32>,
    /// Role inference
    pub role: BacnetRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BacnetRole {
    Client,    // sends Who-Is, ReadProperty requests
    Server,    // sends I-Am, responds to reads
    Unknown,
}
```

#### Parsing Approach

1. Validate BVLCI: byte 0 must be 0x81. Extract function and length.
2. Parse NPDU: validate version 0x01. Extract control byte, skip optional DNET/DADR/SNET/SADR fields based on control bit flags.
3. Parse APDU: extract PDU type from high nibble, then service choice. For I-Am: decode the BACnet-tagged Object Identifier (context tag 0, application tag for unsigned/enum).
4. BACnet uses self-describing ASN.1-like encoding with context tags and application tags. For MVP, focus on I-Am and ReadProperty/WriteProperty service identification without fully decoding all tagged values.

#### Test Payloads

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Who-Is Broadcast
    const WHO_IS: &[u8] = &[
        0x81,       // BVLCI Type
        0x0B,       // Function: Original-Broadcast
        0x00, 0x0C, // Length: 12
        // NPDU
        0x01,       // Version
        0x20,       // Control: expect reply, no DNET/SNET
        0xFF, 0xFF, // DNET: broadcast
        0x00,       // DLEN: 0
        0xFF,       // Hop count
        // APDU
        0x10,       // Unconfirmed Request
        0x08,       // Service: Who-Is
    ];

    // I-Am Response
    const I_AM: &[u8] = &[
        0x81,       // BVLCI Type
        0x0B,       // Function: Original-Broadcast
        0x00, 0x19, // Length: 25
        // NPDU
        0x01,       // Version
        0x20,       // Control
        0xFF, 0xFF, // DNET
        0x00,       // DLEN
        0xFF,       // Hop count
        // APDU: I-Am
        0x10,       // Unconfirmed Request
        0x00,       // Service: I-Am
        // I-Am data (BACnet tagged encoding)
        0xC4, 0x02, 0x00, 0x03, 0xE9, // Object ID: Device #1001
        0x22, 0x01, 0xE0,             // Max APDU: 480
        0x91, 0x00,                    // Segmentation: both
        0x21, 0x03,                    // Vendor ID: 3 (McQuay)
    ];

    // ReadProperty Request (Device Object, Model Name property 70)
    const READ_PROP: &[u8] = &[
        0x81, 0x0A,
        0x00, 0x11,
        0x01, 0x04, // NPDU: no DNET
        // APDU
        0x00,       // Confirmed Request, no segmentation
        0x04,       // Max segments: 0, max APDU response: 1476
        0x01,       // Invoke ID: 1
        0x0C,       // Service: ReadProperty
        // Tagged: Object ID
        0x0C, 0x02, 0x00, 0x03, 0xE9, // Context 0: Device #1001
        // Tagged: Property ID
        0x19, 0x46, // Context 1: Property 70 (model-name)
    ];

    // WriteProperty — potential T0855
    const WRITE_PROP: &[u8] = &[
        0x81, 0x0A,
        0x00, 0x15,
        0x01, 0x04,
        0x00, 0x04, 0x02,
        0x0F,       // Service: WriteProperty
        0x0C, 0x00, 0x80, 0x00, 0x01, // Object: AnalogOutput #1
        0x19, 0x55, // Property: Present-Value (85)
        0x3E,       // Opening tag 3
        0x44, 0x42, 0xC8, 0x00, 0x00, // Real: 100.0
        0x3F,       // Closing tag 3
    ];

    // ReinitializeDevice — T0816
    const REINITIALIZE: &[u8] = &[
        0x81, 0x0A,
        0x00, 0x0D,
        0x01, 0x04,
        0x00, 0x04, 0x03,
        0x14,       // Service: ReinitializeDevice (0x14)
        0x09, 0x01, // State: warmstart
    ];

    #[test]
    fn test_who_is() {
        let result = parse(WHO_IS).expect("should parse");
        assert_eq!(result.service, Some(BacnetService::WhoIs));
        assert_eq!(result.pdu_type, Some(BacnetPduType::UnconfirmedRequest));
    }

    #[test]
    fn test_i_am() {
        let result = parse(I_AM).expect("should parse");
        assert_eq!(result.service, Some(BacnetService::IAm));
        let iam = result.iam.as_ref().unwrap();
        assert_eq!(iam.device_instance, 1001);
        assert_eq!(iam.vendor_id, 3);
    }

    #[test]
    fn test_read_property() {
        let result = parse(READ_PROP).expect("should parse");
        assert_eq!(result.service, Some(BacnetService::ReadProperty));
        assert_eq!(result.object_type, Some(BacnetObjectType::Device));
    }

    #[test]
    fn test_write_property() {
        let result = parse(WRITE_PROP).expect("should parse");
        assert_eq!(result.service, Some(BacnetService::WriteProperty));
        assert_eq!(result.object_type, Some(BacnetObjectType::AnalogOutput));
    }

    #[test]
    fn test_reinitialize() {
        let result = parse(REINITIALIZE).expect("should parse");
        assert_eq!(result.service, Some(BacnetService::ReinitializeDevice));
    }

    #[test]
    fn test_truncated() {
        assert!(parse(&[0x81]).is_none());
    }
}
```

#### ATT&CK Detections

| Technique | Detection Logic |
|-----------|----------------|
| **T0855** Unauthorized Command | WriteProperty to BinaryOutput/AnalogOutput Present-Value |
| **T0856** Alarm Suppression | WriteProperty to NotificationClass or EventEnable properties |
| **T0816** Device Restart | ReinitializeDevice service (0x14) |
| **T0811** Device Communication Control | DeviceCommunicationControl service (0x11) |
| **T0846** Remote System Discovery | Who-Is broadcasts — enumeration |
| **T0869** Standard Application Layer Protocol | BACnet presence on network |

#### Estimated Effort
~400 lines. Medium complexity. BVLCI + NPDU are simple. The APDU service identification is straightforward. The tricky part is BACnet's ASN.1-like tag encoding for I-Am object IDs, but you only need to decode enough to extract device instance and vendor ID.

---

### 2.4 IEC 60870-5-104 (Port 2404 TCP)

#### Wire Format

IEC 104 has a very clean fixed structure:

```
APCI (Application Protocol Control Information — 6 bytes, always):
  [0]     u8    Start byte (always 0x68)
  [1]     u8    APDU Length (bytes following, excl. start + length)
  [2..5]  4 bytes  Control fields (format depends on type):
  
  Type detection (bits of byte[2]):
    If bit 0 == 0:  I-frame (Information transfer)
      [2..3]  u16 LE  Send sequence N(S) << 1
      [4..5]  u16 LE  Receive sequence N(R) << 1
    If bits [1:0] == 01: S-frame (Supervisory)
      [2..3]  Reserved
      [4..5]  u16 LE  Receive sequence N(R) << 1
    If bits [1:0] == 11: U-frame (Unnumbered)
      [2]     Control function:
                0x07 = STARTDT act
                0x0B = STARTDT con
                0x13 = STOPDT act
                0x17 = STOPDT con
                0x43 = TESTFR act
                0x83 = TESTFR con

For I-frames, ASDU follows APCI:
  ASDU Header:
    [0]     u8    Type ID (1-127):
                    1  = M_SP_NA_1 (single-point)
                    3  = M_DP_NA_1 (double-point)
                    9  = M_ME_NA_1 (measured normalized)
                    13 = M_ME_NC_1 (measured short float)
                    30 = M_SP_TB_1 (single-point with time)
                    36 = M_ME_TF_1 (measured float with time)
                    45 = C_SC_NA_1 (single command)
                    46 = C_DC_NA_1 (double command)
                    48 = C_SE_NC_1 (setpoint float)
                    58 = C_SC_TA_1 (single command with time)
                    100 = C_IC_NA_1 (interrogation command)
                    101 = C_CI_NA_1 (counter interrogation)
                    103 = C_CS_NA_1 (clock sync)
    [1]     u8    Variable structure qualifier:
                    bit 7: SQ (sequence flag)
                    bits 0-6: number of objects
    [2..3]  u16 LE  Cause of transmission:
                    bits 0-5: cause (1=periodic, 3=spontaneous, 5=requested, 6=activation, 7=activation_con, 10=activation_term, 20=interrogated, 44-47=unknown)
                    bit 6: P/N (positive/negative confirm)
                    bit 7: T (test)
                    byte [3] bits 0-7: Originator Address
    [4..5]  u16 LE  Common ASDU Address (station address)
    [6..]   Information objects (IOA + value, format depends on Type ID)
```

#### Rust Struct

```rust
// src-tauri/crates/gm-parsers/src/iec104.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Iec104FrameType {
    I,  // Information transfer
    S,  // Supervisory
    U,  // Unnumbered control
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UFrameFunction {
    StartDtAct,   // 0x07
    StartDtCon,   // 0x0B
    StopDtAct,    // 0x13
    StopDtCon,    // 0x17
    TestFrAct,    // 0x43
    TestFrCon,    // 0x83
    Unknown(u8),
}

/// ASDU Type IDs grouped by function
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AsduTypeId {
    // Monitor (station → master)
    SinglePoint,             // 1
    DoublePoint,             // 3
    StepPosition,            // 5
    MeasuredNormalized,      // 9
    MeasuredScaled,          // 11
    MeasuredShortFloat,      // 13
    IntegratedTotals,        // 15
    SinglePointWithTime,     // 30
    DoublePointWithTime,     // 31
    MeasuredFloatWithTime,   // 36
    // Control (master → station)
    SingleCommand,           // 45
    DoubleCommand,           // 46
    RegulatingStep,          // 47
    SetpointNormalized,      // 48 (C_SE_NA_1)
    SetpointScaled,          // 49
    SetpointShortFloat,      // 50
    SingleCommandWithTime,   // 58
    DoubleCommandWithTime,   // 59
    SetpointFloatWithTime,   // 63
    // System
    Interrogation,           // 100
    CounterInterrogation,    // 101
    ReadCommand,             // 102
    ClockSync,               // 103
    ResetProcess,            // 105
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CauseOfTransmission {
    Periodic,           // 1
    Background,         // 2
    Spontaneous,        // 3
    Initialized,        // 4
    Requested,          // 5
    Activation,         // 6
    ActivationCon,      // 7
    Deactivation,       // 8
    DeactivationCon,    // 9
    ActivationTerm,     // 10
    Interrogated,       // 20
    InterrogatedGroup1, // 21-36
    Unknown(u8),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iec104Info {
    pub frame_type: Iec104FrameType,
    /// U-frame function (only for U-frames)
    pub u_function: Option<UFrameFunction>,
    /// I-frame sequence numbers
    pub send_seq: Option<u16>,
    pub recv_seq: Option<u16>,
    /// ASDU fields (only for I-frames)
    pub type_id: Option<AsduTypeId>,
    pub num_objects: Option<u8>,
    pub is_sequence: bool,
    pub cause: Option<CauseOfTransmission>,
    pub is_negative: bool,
    pub is_test: bool,
    pub originator_address: Option<u8>,
    pub common_address: Option<u16>,
    /// First Information Object Address (for quick reference)
    pub first_ioa: Option<u32>,
    /// Is this a command (Type ID 45-69, 100-107)?
    pub is_command: bool,
    /// Is this a monitoring direction message?
    pub is_monitor: bool,
    /// Role inference
    pub role: Iec104Role,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Iec104Role {
    Master,       // sends commands, interrogations
    Outstation,   // sends monitoring data, confirmations
    Unknown,
}
```

#### Parsing Approach

1. Validate start byte (0x68). Read APDU length.
2. Determine frame type from control field bits.
3. For I-frames: extract sequence numbers, then parse ASDU header (type ID, VSQ, COT, common address). Extract first IOA (3 bytes, little-endian).
4. Classify: type IDs 1-44 are monitoring (outstation → master), 45-69 are commands (master → outstation), 100-107 are system commands.

#### Test Payloads

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // U-frame: STARTDT act
    const STARTDT_ACT: &[u8] = &[
        0x68, 0x04, 0x07, 0x00, 0x00, 0x00,
    ];

    // I-frame: Interrogation Command (Type 100)
    const INTERROGATION: &[u8] = &[
        0x68, 0x0E, // Start, length 14
        0x00, 0x00, // N(S) = 0
        0x00, 0x00, // N(R) = 0
        // ASDU
        0x64,       // Type ID: 100 (Interrogation)
        0x01,       // VSQ: 1 object, not sequence
        0x06, 0x00, // COT: 6 (activation), originator 0
        0x01, 0x00, // Common address: 1
        0x00, 0x00, 0x00, // IOA: 0
        0x14,       // QOI: 20 (station interrogation)
    ];

    // I-frame: Single Command (Type 45) — T0855
    const SINGLE_COMMAND: &[u8] = &[
        0x68, 0x0E,
        0x02, 0x00, 0x00, 0x00,
        0x2D,       // Type 45: Single Command
        0x01,       // 1 object
        0x06, 0x00, // COT: activation
        0x01, 0x00, // Station 1
        0x01, 0x00, 0x00, // IOA: 1
        0x01,       // SCS: ON, S/E: execute
    ];

    // I-frame: Measured Short Float (Type 13) — monitoring
    const MEASURED_FLOAT: &[u8] = &[
        0x68, 0x12,
        0x04, 0x00, 0x02, 0x00,
        0x0D,       // Type 13: Measured Short Float
        0x01,       // 1 object
        0x03, 0x00, // COT: spontaneous
        0x01, 0x00, // Station 1
        0x0A, 0x00, 0x00, // IOA: 10
        0x00, 0x00, 0xC8, 0x42, // Float: 100.0
        0x00,       // QDS: good quality
    ];

    // S-frame
    const S_FRAME: &[u8] = &[
        0x68, 0x04, 0x01, 0x00, 0x04, 0x00,
    ];

    #[test]
    fn test_startdt() {
        let result = parse(STARTDT_ACT).expect("should parse");
        assert_eq!(result.frame_type, Iec104FrameType::U);
        assert_eq!(result.u_function, Some(UFrameFunction::StartDtAct));
    }

    #[test]
    fn test_interrogation() {
        let result = parse(INTERROGATION).expect("should parse");
        assert_eq!(result.frame_type, Iec104FrameType::I);
        assert_eq!(result.type_id, Some(AsduTypeId::Interrogation));
        assert!(result.is_command);
        assert_eq!(result.role, Iec104Role::Master);
    }

    #[test]
    fn test_single_command() {
        let result = parse(SINGLE_COMMAND).expect("should parse");
        assert_eq!(result.type_id, Some(AsduTypeId::SingleCommand));
        assert!(result.is_command);
    }

    #[test]
    fn test_measured_float() {
        let result = parse(MEASURED_FLOAT).expect("should parse");
        assert_eq!(result.type_id, Some(AsduTypeId::MeasuredShortFloat));
        assert!(result.is_monitor);
        assert_eq!(result.role, Iec104Role::Outstation);
    }

    #[test]
    fn test_s_frame() {
        let result = parse(S_FRAME).expect("should parse");
        assert_eq!(result.frame_type, Iec104FrameType::S);
    }

    #[test]
    fn test_invalid_start_byte() {
        assert!(parse(&[0x99, 0x04, 0x07, 0x00, 0x00, 0x00]).is_none());
    }
}
```

#### ATT&CK Detections

| Technique | Detection Logic |
|-----------|----------------|
| **T0855** Unauthorized Command | Type IDs 45-69 (commands) from unexpected source IPs |
| **T0814** DoS / Interrogation Flooding | High rate of Type 100 (C_IC_NA_1) from single source |
| **T0816** Device Restart | Type 105 (C_RP_NA_1, Reset Process) |
| **T0855** Setpoint Manipulation | Type 48/49/50 (setpoint commands) |
| **T0846** Remote Discovery | STARTDT act from new/unknown hosts |

#### Estimated Effort
~350 lines. The cleanest protocol here — fixed 6-byte APCI, fixed ASDU header. No complex encoding schemes. Low-medium complexity.

---

### 2.5 PROFINET DCP (UDP Port 34964, also ethertype 0x8892)

#### Wire Format

PROFINET DCP (Discovery and Configuration Protocol) is a Layer 2 protocol (ethertype 0x8892) but KNK may encounter it in pcaps. It uses simple TLV blocks:

```
DCP Header (4 bytes after PROFINET frame ID):
  Frame ID: 0xFEFE (identify multicast) or 0xFEFD (identify response)
  [0]     u8    Service ID:
                  0x03 = Get
                  0x04 = Set
                  0x05 = Identify (multicast request)
                  0x05 = Identify response (same ID, response flag set)
  [1]     u8    Service Type:
                  0x00 = Request
                  0x01 = Response (success)
  [2..3]  u32 BE  Xid (transaction ID)
  [4..5]  u16 BE  Response delay
  [6..7]  u16 BE  DCP data length

DCP Blocks (TLV):
  [0]     u8    Option:
                  0x01 = IP
                  0x02 = Device properties
                  0x03 = DHCP
                  0x05 = Control
  [1]     u8    Suboption:
                  IP:      0x01=MAC, 0x02=IP Suite
                  Device:  0x01=Vendor (manufacturer), 0x02=Name of Station,
                           0x03=Device ID (vendor_id + device_id), 0x04=Device Role,
                           0x05=Device Options, 0x06=Alias
  [2..3]  u16 BE  Block length
  [4..5]  u16 BE  Block info (for responses)
  [6..n]  Data
```

The **Identify Response** is the gold mine — it contains the device's name of station, vendor name, vendor ID, device ID, IP address, MAC address, and device role, all in cleartext TLV blocks.

#### Rust Struct

```rust
// src-tauri/crates/gm-parsers/src/profinet_dcp.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DcpServiceId {
    Get,        // 0x03
    Set,        // 0x04
    Identify,   // 0x05
    Hello,      // 0x06
    Unknown(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DcpServiceType {
    Request,           // 0x00
    ResponseSuccess,   // 0x01
    ResponseError,     // 0x05
    Unknown(u8),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DcpDeviceInfo {
    pub name_of_station: Option<String>,
    pub vendor_name: Option<String>,
    pub vendor_id: Option<u16>,
    pub device_id: Option<u16>,
    pub device_role: Option<u8>,    // 0x01=IO-Device, 0x02=IO-Controller, 0x04=IO-Multidevice, 0x08=IO-Supervisor
    pub ip_address: Option<[u8; 4]>,
    pub subnet_mask: Option<[u8; 4]>,
    pub gateway: Option<[u8; 4]>,
    pub mac_address: Option<[u8; 6]>,
    pub alias_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfinetDcpInfo {
    pub service_id: DcpServiceId,
    pub service_type: DcpServiceType,
    pub xid: u32,
    pub device_info: DcpDeviceInfo,
    /// Role from DCP device role block
    pub role: ProfinetRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfinetRole {
    IoDevice,       // PLC I/O module, sensor
    IoController,   // PLC main controller
    IoSupervisor,   // Engineering station
    Unknown,
}
```

#### Parsing Approach

1. Check frame ID (0xFEFE or 0xFEFD) if parsing from raw Ethernet, or check for DCP header pattern.
2. Extract service ID, service type, XID, DCP data length.
3. Iterate TLV blocks: for each block, match on option+suboption:
   - (0x02, 0x01): Vendor name — read as ASCII string
   - (0x02, 0x02): Name of Station — read as ASCII string
   - (0x02, 0x03): Device ID — read u16 vendor_id + u16 device_id
   - (0x02, 0x04): Device Role — read u16 role bits
   - (0x01, 0x02): IP Suite — read 4+4+4 bytes (IP, mask, gateway)
   - (0x01, 0x01): MAC Address — 6 bytes
4. Advance by block length (padded to even boundary).

#### Estimated Effort
~250 lines. Low complexity. Simple TLV parsing with no nesting. The highest device-identification value per line of code of any protocol on this list.

---

## 3. New ATT&CK Detection Specifications (Summary)

### Detections by Protocol

| Protocol | Technique ID | Technique Name | Detection Logic | Severity |
|----------|-------------|----------------|-----------------|----------|
| EtherNet/IP | T0855 | Unauthorized Command | CIP Write/ReadModifyWrite to Assembly objects | High |
| EtherNet/IP | T0836 | Modify Program | CIP File class access (upload/download firmware) | Critical |
| EtherNet/IP | T0846 | Remote Discovery | ListIdentity broadcast from unknown source | Medium |
| S7comm | T0843 | Program Download | Function 0x1D/0x1E/0x1F (download sequence) | Critical |
| S7comm | T0845 | Program Upload | Function 0x1A/0x1B/0x1C (upload/theft) | High |
| S7comm | T0809 | Data Destruction | PI Service block delete (_DELE) | Critical |
| S7comm | T0816 | Device Shutdown | Function 0x29 (PLC Stop) | Critical |
| S7comm | T0855 | Unauthorized Command | WriteVar (0x05) to output area (0x82) | High |
| BACnet | T0855 | Unauthorized Command | WriteProperty to AnalogOutput/BinaryOutput | High |
| BACnet | T0856 | Alarm Suppression | WriteProperty to NotificationClass | High |
| BACnet | T0816 | Device Restart | ReinitializeDevice (0x14) | High |
| BACnet | T0811 | Communication Control | DeviceCommunicationControl (0x11) | High |
| IEC 104 | T0855 | Unauthorized Command | Command type IDs (45-69) from unexpected source | High |
| IEC 104 | T0814 | DoS | High-rate interrogation commands (Type 100) | Medium |
| IEC 104 | T0816 | Process Reset | Type 105 (C_RP_NA_1) | Critical |
| PROFINET | T0846 | Remote Discovery | DCP Identify multicasts from unknown hosts | Medium |

### Integration into gm-analysis/attack.rs

Each detection should follow the existing pattern:

```rust
// In gm-analysis/src/attack.rs, add to the detect() function:

// EtherNet/IP detections
if let Some(DeepParseResult::Enip(ref enip)) = packet_info.deep_parse {
    if let Some(CipService::Write) | Some(CipService::ReadModifyWrite) = enip.cip_service {
        if enip.cip_class == Some(CipClass::Assembly) {
            findings.push(AttackFinding {
                technique_id: "T0855".into(),
                technique_name: "Unauthorized Command Message".into(),
                description: format!(
                    "CIP write to Assembly object from {}",
                    packet_info.src_ip
                ),
                severity: Severity::High,
                timestamp: packet_info.timestamp,
                src_ip: packet_info.src_ip.clone(),
                dst_ip: packet_info.dst_ip.clone(),
                protocol: "EtherNet/IP".into(),
            });
        }
    }
}
```

---

## 4. Claude Code Prompts

### Prompt 1: EtherNet/IP + CIP Parser

```
@CLAUDE.md Read the project structure and existing parser patterns.

TASK: Implement a native EtherNet/IP + CIP deep parser in gm-parsers.

1. Create src-tauri/crates/gm-parsers/src/enip.rs with:
   - EnipCommand enum (Nop, ListServices, ListIdentity, ListInterfaces, RegisterSession, UnregisterSession, SendRRData, SendUnitData, Unknown(u16))
   - CipService enum (GetAttributeAll, GetAttributeSingle, SetAttributeSingle, Reset, Read, Write, ReadModifyWrite, UnconnectedSend, ForwardOpen, ForwardClose, Unknown(u8))
   - CipClass enum (Identity, MessageRouter, Assembly, Connection, ConnectionManager, File, TcpIp, EthernetLink, Unknown(u16))
   - EnipIdentity struct with fields: vendor_id (u16), device_type (u16), product_code (u16), major_revision (u8), minor_revision (u8), serial_number (u32), product_name (String), status (u16), state (u8)
   - EnipInfo struct as the main parse result
   - EnipRole enum (Scanner, Adapter, Unknown)
   - pub fn parse(payload: &[u8]) -> Option<EnipInfo>
   
2. Parsing logic:
   - Parse 24-byte encapsulation header (all little-endian)
   - For ListIdentity (0x0063) responses: parse CPF items, extract Identity item with vendor/device/serial/product name
   - For SendRRData (0x006F) / SendUnitData (0x0070): parse CPF items to reach CIP message, extract service code and EPATH (class/instance/attribute segments: 0x20=class, 0x24=instance, 0x30=attribute for 8-bit; 0x21/0x25/0x31 for 16-bit)
   - Role: ForwardOpen/Write senders are Scanners; responders are Adapters
   
3. Add DeepParseResult::Enip(EnipInfo) variant in lib.rs
4. Add IcsProtocol::Enip arm in deep_parse() dispatch
5. Add at least 6 unit tests with the test payloads from this conversation
6. CONSTRAINTS: No unwrap(), use ? and .map_err(). All reads must be bounds-checked (use .get() and .checked_sub()). Return None for truncated/malformed packets. Cross-platform, no platform-specific code.
7. Run `cargo test` — all existing 127 tests plus new tests must pass.
```

### Prompt 2: S7comm Parser

```
@CLAUDE.md Read the project structure and existing parser patterns.

TASK: Implement a native S7comm deep parser in gm-parsers.

1. Create src-tauri/crates/gm-parsers/src/s7comm.rs with:
   - CotpPduType enum (ConnectionRequest 0xE0, ConnectionConfirm 0xD0, DtData 0xF0, DisconnectRequest 0x80, Unknown)
   - CotpParams struct with dst_ref, src_ref, src_tsap, dst_tsap, tpdu_size, rack, slot
   - S7PduType enum (Job 0x01, Ack 0x02, AckData 0x03, Userdata 0x07, Unknown)
   - S7Function enum (ReadVar 0x04, WriteVar 0x05, SetupCommunication 0xF0, PiService 0x28, PlcStop 0x29, UploadStart 0x1A, Upload 0x1B, UploadEnd 0x1C, DownloadStart 0x1D, DownloadEnd 0x1F, Unknown)
   - S7Info struct as main parse result
   - S7Role enum (Client, Server, Unknown)
   - pub fn parse(payload: &[u8]) -> Option<S7Info>

2. Parsing logic:
   - Validate TPKT: byte[0]==0x03, extract u16 BE length from bytes[2..4]
   - Parse COTP: length byte, PDU type. For CR/CC: parse TLV params (0xC0=tpdu_size, 0xC1=src-tsap, 0xC2=dst-tsap). Derive rack/slot from dst-tsap byte[1]: rack = (byte >> 5) & 0x07, slot = byte & 0x1F
   - For DT Data: skip COTP (length+1 bytes), validate S7 protocol ID (0x32), parse ROSCTR, PDU reference, param/data lengths
   - Extract function code from first byte of S7 parameters
   - For SetupCommunication (0xF0): extract max_amq_calling, max_amq_called, pdu_length
   - Role: Job senders are Clients, AckData senders are Servers

3. Add DeepParseResult::S7(S7Info) variant
4. Add IcsProtocol::S7comm arm in deep_parse()
5. Add 6+ unit tests with test payloads from this conversation
6. CONSTRAINTS: No unwrap(), bounds-check all reads, return None for malformed packets.
7. Run `cargo test` — all tests must pass.
```

### Prompt 3: BACnet Parser

```
@CLAUDE.md Read the project structure and existing parser patterns.

TASK: Implement a native BACnet deep parser in gm-parsers.

1. Create src-tauri/crates/gm-parsers/src/bacnet.rs with:
   - BvlcFunction enum (BvlcResult, ForwardedNpdu, OriginalUnicast, OriginalBroadcast, etc.)
   - BacnetPduType enum (ConfirmedRequest, UnconfirmedRequest, SimpleAck, ComplexAck, Error, etc.)
   - BacnetService enum (ReadProperty, WriteProperty, IAm, WhoIs, ReinitializeDevice, DeviceCommunicationControl, etc.)
   - BacnetObjectType enum (AnalogInput/Output, BinaryInput/Output, Device, File, etc.)
   - BacnetIAm struct (device_instance, max_apdu_length, segmentation_supported, vendor_id)
   - BacnetInfo struct as main parse result
   - BacnetRole enum (Client, Server, Unknown)
   - pub fn parse(payload: &[u8]) -> Option<BacnetInfo>

2. Parsing logic:
   - Validate BVLCI: byte[0]==0x81. Extract function, length.
   - Parse NPDU: version==0x01, control byte. Skip DNET/DADR/SNET/SADR based on control bits (bit5=dst present, bit3=src present; if dst present: 2-byte DNET + 1-byte DLEN + DLEN bytes DADR + 1 hop count)
   - Parse APDU: high nibble of first byte = PDU type. Service choice follows.
   - For I-Am (unconfirmed service 0x00): parse BACnet-encoded Object ID. Format: Application Tag 12 (0xC4) followed by 4 bytes where bits 31-22 = object type, bits 21-0 = instance number. Then u16 max APDU, u8 segmentation, u16 vendor ID (each with BACnet application tags: 0x22=unsigned16, 0x91=enum, 0x21=unsigned8).
   - For ReadProperty/WriteProperty: extract Object ID and Property ID from context tags.

3. Add DeepParseResult::Bacnet(BacnetInfo) variant
4. Add IcsProtocol::Bacnet arm in deep_parse()
5. Add 6+ unit tests
6. CONSTRAINTS: No unwrap(), safe parsing, return None for malformed.
7. Run `cargo test`.
```

### Prompt 4: IEC 104 Parser

```
@CLAUDE.md Read the project structure and existing parser patterns.

TASK: Implement a native IEC 60870-5-104 deep parser in gm-parsers.

1. Create src-tauri/crates/gm-parsers/src/iec104.rs with:
   - Iec104FrameType enum (I, S, U)
   - UFrameFunction enum (StartDtAct, StartDtCon, StopDtAct, StopDtCon, TestFrAct, TestFrCon, Unknown)
   - AsduTypeId enum covering monitoring types (1,3,5,9,11,13,15,30,31,36), command types (45-50,58-63), and system types (100-103,105)
   - CauseOfTransmission enum (Periodic, Spontaneous, Activation, etc.)
   - Iec104Info struct as main result
   - Iec104Role enum (Master, Outstation, Unknown)
   - pub fn parse(payload: &[u8]) -> Option<Iec104Info>

2. Parsing logic:
   - Validate start byte 0x68, read APDU length (byte[1])
   - Frame type from control bytes: byte[2] bit0==0 → I-frame; bits[1:0]==01 → S-frame; bits[1:0]==11 → U-frame
   - For I-frames: send_seq = u16_le(bytes[2..4]) >> 1, recv_seq = u16_le(bytes[4..6]) >> 1
   - Parse ASDU starting at byte[6]: type_id, VSQ (bit7=SQ, bits0-6=count), COT (bits0-5=cause, bit6=P/N, bit7=T), originator, common_address (u16 LE), first IOA (3 bytes LE)
   - is_command = type_id in 45..=69 or 100..=107
   - is_monitor = type_id in 1..=44
   - Role: command senders are Masters, monitoring senders are Outstations

3. Add DeepParseResult::Iec104(Iec104Info) variant and dispatch
4. Add 6+ unit tests
5. CONSTRAINTS: No unwrap(), safe, cross-platform.
6. Run `cargo test`.
```

### Prompt 5: PROFINET DCP Parser

```
@CLAUDE.md Read the project structure and existing parser patterns.

TASK: Implement a native PROFINET DCP deep parser in gm-parsers.

1. Create src-tauri/crates/gm-parsers/src/profinet_dcp.rs with:
   - DcpServiceId enum (Get 0x03, Set 0x04, Identify 0x05, Hello 0x06, Unknown)
   - DcpServiceType enum (Request 0x00, ResponseSuccess 0x01, ResponseError 0x05, Unknown)
   - DcpDeviceInfo struct with: name_of_station, vendor_name, vendor_id, device_id, device_role, ip_address, subnet_mask, gateway, mac_address, alias_name
   - ProfinetDcpInfo struct as main result
   - ProfinetRole enum (IoDevice, IoController, IoSupervisor, Unknown)
   - pub fn parse(payload: &[u8]) -> Option<ProfinetDcpInfo>

2. Parsing logic:
   - Parse DCP header: service_id (byte[0]), service_type (byte[1]), xid (u32 BE bytes[2..6]), response_delay (u16 BE), dcp_data_length (u16 BE)
   - Iterate TLV blocks within dcp_data_length: option (byte), suboption (byte), block_length (u16 BE), block_info (u16 BE if response), then data
   - Extract by (option, suboption): (2,1)=vendor name as ASCII, (2,2)=name of station as ASCII, (2,3)=u16 vendor_id + u16 device_id, (2,4)=device role bits, (1,1)=MAC 6 bytes, (1,2)=IP suite 12 bytes (ip+mask+gw)
   - Advance by block_length padded to even boundary
   - Role from device_role bits: 0x01=IoDevice, 0x02=IoController, 0x08=IoSupervisor

3. Add DeepParseResult::ProfinetDcp(ProfinetDcpInfo) variant and dispatch
4. Add 5+ unit tests
5. CONSTRAINTS: No unwrap(), safe, cross-platform. Note: DCP is typically Layer 2 (ethertype 0x8892), but KNK may encounter it in pcaps. If payload starts with the DCP header directly (after Ethernet frame has been stripped), parse from there.
6. Run `cargo test`.
```

### Prompt 6: ATT&CK Integration

```
@CLAUDE.md Read gm-analysis/src/attack.rs for the existing detection pattern.

TASK: Add new ATT&CK detections for EtherNet/IP, S7comm, BACnet, IEC 104, and PROFINET DCP.

For each protocol, add detection arms in the detect() function matching on the new DeepParseResult variants:

EtherNet/IP:
- T0855: CIP Write/ReadModifyWrite to Assembly class
- T0836: CIP access to File class (firmware)
- T0846: ListIdentity broadcast from unknown sources

S7comm:
- T0843: Function 0x1D/0x1E/0x1F (Download sequence)
- T0845: Function 0x1A/0x1B/0x1C (Upload/theft)
- T0809: PI Service with block delete
- T0816: Function 0x29 (PLC Stop)
- T0855: WriteVar to output area 0x82

BACnet:
- T0855: WriteProperty to AnalogOutput/BinaryOutput Present-Value
- T0856: WriteProperty to NotificationClass properties
- T0816: ReinitializeDevice service
- T0811: DeviceCommunicationControl service

IEC 104:
- T0855: Command type IDs (45-69) — all commands are flagged
- T0814: High-rate Type 100 interrogation from single source
- T0816: Type 105 Reset Process

PROFINET:
- T0846: DCP Identify from unknown sources

Follow existing severity levels and finding format. Add tests for each new detection.
Run `cargo test`.
```

### Prompt 7: Signature Files

```
@CLAUDE.md Read existing signature files in src-tauri/signatures/ for the YAML format.

TASK: Create YAML signature files for the new protocols.

Create these files following the existing confidence-level pattern (1-4 for signatures, deep parse provides level 5):

1. src-tauri/signatures/enip_cip.yaml — EtherNet/IP + CIP
   - Port match: 44818 (confidence 1)
   - Encapsulation header validation: first 2 bytes match known commands (confidence 2)
   - ListIdentity response pattern match (confidence 3)
   - CIP service code extraction (confidence 4)

2. src-tauri/signatures/s7comm.yaml — S7comm
   - Port match: 102 (confidence 1)
   - TPKT header 0x03 0x00 (confidence 2)
   - COTP + S7 protocol ID 0x32 (confidence 3)
   - Function code extraction (confidence 4)

3. src-tauri/signatures/bacnet.yaml — BACnet
   - Port match: 47808 (confidence 1)
   - BVLCI type 0x81 (confidence 2)
   - NPDU version 0x01 (confidence 3)
   - Service identification (confidence 4)

4. src-tauri/signatures/iec104.yaml — IEC 104
   - Port match: 2404 (confidence 1)
   - Start byte 0x68 (confidence 2)
   - APDU frame type identification (confidence 3)
   - ASDU type ID extraction (confidence 4)

5. src-tauri/signatures/profinet_dcp.yaml — PROFINET DCP
   - Port match: 34964 (confidence 1)
   - DCP service ID validation (confidence 2)
   - TLV block parsing (confidence 3)
   - Device info extraction (confidence 4)

Verify existing signatures still load correctly.
```

### Prompt 8: Frontend Integration

```
@CLAUDE.md Read the frontend components in src/lib/components/.

TASK: Update frontend to display new protocol data.

1. Update src/lib/components/ProtocolStats.svelte:
   - Add entries for EtherNet/IP, S7comm, BACnet, IEC 104, PROFINET DCP
   - Show deep-parse stats (e.g., "42 EtherNet/IP sessions, 12 devices identified")

2. Update src/lib/components/InventoryView.svelte detail panel:
   - For EtherNet/IP devices: show vendor ID/name, device type, product name, serial, firmware rev
   - For S7comm devices: show rack/slot, PLC type, firmware, order number
   - For BACnet devices: show device instance, vendor ID, object name
   - For IEC 104 devices: show station address, monitored types, command types
   - For PROFINET devices: show name of station, vendor, device ID, IP, role

3. Update any TypeScript types in src/lib/types/ to include new protocol info fields.

4. Verify build: `npm run build` succeeds with no type errors.
```

---

## 5. Feature Gap Assessment: KNK vs Malcolm

### Context: KNK is a **field assessment tool**. Malcolm is a **SOC platform**.

These are fundamentally different products for different users:

- **KNK user**: An ICS security assessor who arrives at a plant, plugs into a SPAN port, captures traffic for hours/days, then analyzes offline. Needs: fast setup, single binary, clear topology visualization, device inventory, threat detection report.
- **Malcolm user**: A SOC analyst monitoring ongoing ICS network traffic at scale. Needs: distributed sensors, long-term storage, correlation across millions of events, integration with SIEM.

### Feature-by-Feature Assessment

| Feature | Malcolm | KNK Today | Recommendation | Priority |
|---------|---------|-----------|----------------|----------|
| **File extraction** (ClamAV/YARA/capa) | Full carving + scanning | None | **Skip.** File carving requires deep TCP reassembly and is a massive implementation effort. An assessor reviewing pcaps can use NetworkMiner or Wireshark for ad-hoc file extraction. KNK's value is topology + protocol intelligence, not malware scanning. | Not recommended |
| **JA4 fingerprinting** | Full JA4/JA4S/JA4H | None | **Add (Phase C).** JA4 fingerprinting from TLS ClientHello is relatively simple (~200 lines), provides device fingerprinting without decryption, and is increasingly standard. However, it's IT-layer enrichment, not ICS-critical. Worth adding after protocol expansion. | Low |
| **Asset inventory CSV import** | Yes | Inline editing only | **Add (Phase B).** Simple and high-value. An assessor often has a spreadsheet of known assets from the plant. Importing it as a CSV and correlating with discovered devices is a natural workflow. ~100 lines frontend + ~50 lines backend. | Medium |
| **Distributed sensors** | Hedgehog Linux | Desktop only | **Skip.** Building a remote capture agent is a separate product. KNK's single-binary desktop model is a feature, not a limitation. An assessor at a plant doesn't need distributed sensors — they're physically present. If remote capture is needed, tools like tcpdump + SSH are sufficient. | Not recommended |
| **Alert correlation** | Full Suricata alert ↔ session correlation | Imports Suricata alerts, no correlation | **Add (Phase C).** Correlating a Suricata alert with the session/device that triggered it adds significant value to reports. Implementation: when importing Suricata EVE JSON, match on flow_id/src_ip/dst_ip/timestamp to link alerts to KNK's device inventory. ~200 lines. | Medium |

### Additional Gaps Worth Considering

| Feature | Recommendation |
|---------|----------------|
| **OUI vendor lookup for EtherNet/IP/PROFINET vendor IDs** | KNK already has OUI lookup. Add CIP vendor ID → name mapping table (ODVA publishes the list) and PROFINET vendor ID → name. ~100 lines, high value. **Add in Phase A.** |
| **Protocol statistics dashboard** | KNK has ProtocolStats. Enhance with protocol-specific breakdowns (e.g., "15 S7comm connections, 8 read-only, 3 with write commands, 4 with program operations"). **Add in Phase A.** |
| **PCAP replay / timeline** | Malcolm has Arkime for full packet indexing. KNK doesn't need this — but a simple timeline view showing "when did protocol X first appear" would help assessors identify changes during observation windows. **Phase C.** |
| **Purdue model enrichment** | New protocols should auto-classify into Purdue levels based on device role: BACnet devices → Level 1-2, S7comm PLCs → Level 1, HMI/SCADA stations → Level 2, EtherNet/IP scanners → Level 2. **Add in Phase A alongside parsers.** |

### Summary Recommendation

**Phase A** (ship with protocol expansion): Asset inventory CSV import, CIP/PROFINET vendor ID lookup tables, enhanced protocol stats, Purdue auto-classification for new protocols.

**Phase B** (fast follow): Suricata alert correlation with device inventory.

**Phase C** (nice to have): JA4 fingerprinting, protocol timeline view.

**Skip entirely**: File extraction/carving, distributed sensors, full packet indexing.

---

## Appendix: Vendor ID Lookup Tables

### CIP Vendor IDs (partial — source: ODVA)

```rust
// src-tauri/crates/gm-parsers/src/vendor_tables.rs

pub fn cip_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        1 => "Rockwell Automation/Allen-Bradley",
        2 => "Namco Controls",
        5 => "Rockwell Automation/Reliance Electric",
        9 => "Woodhead Software & Electronics",
        12 => "Siemens",
        13 => "Phoenix Contact",
        15 => "Wago",
        19 => "Turck",
        20 => "Omron",
        28 => "Schneider Electric",
        33 => "ABB",
        43 => "Bosch Rexroth",
        44 => "Parker Hannifin",
        48 => "Molex",
        49 => "HMS Networks (Anybus)",
        50 => "Eaton",
        58 => "Pepperl+Fuchs",
        60 => "Cognex",
        72 => "Danfoss",
        78 => "Beckhoff Automation",
        88 => "SEW-EURODRIVE",
        90 => "Pilz",
        100 => "Endress+Hauser",
        113 => "Balluff",
        119 => "Festo",
        283 => "ODVA",
        _ => "Unknown Vendor",
    }
}

pub fn profinet_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        0x002A => "Siemens",
        0x0019 => "Phoenix Contact",
        0x0109 => "Turck",
        0x0021 => "Wago",
        0x00B0 => "Pepperl+Fuchs",
        0x011E => "Beckhoff",
        0x000E => "ABB",
        0x015D => "Festo",
        0x001C => "Schneider Electric",
        0x014D => "Endress+Hauser",
        0x00DA => "Danfoss",
        0x004E => "Balluff",
        _ => "Unknown Vendor",
    }
}
```

---

## Appendix: Estimated Total Effort

| Component | Est. Lines | Est. Days (solo) |
|-----------|-----------|-----------------|
| enip.rs parser | 600 | 3-4 |
| s7comm.rs parser | 450 | 2-3 |
| bacnet.rs parser | 400 | 2-3 |
| iec104.rs parser | 350 | 1-2 |
| profinet_dcp.rs parser | 250 | 1 |
| vendor_tables.rs | 100 | 0.5 |
| ATT&CK detections (attack.rs) | 300 | 1-2 |
| 5 YAML signature files | 250 | 1 |
| Frontend updates | 400 | 2 |
| Tests (30+ new tests) | 500 | 2 |
| Integration + debugging | — | 2-3 |
| **Total Phase A** | **~3,600** | **~18-23 days** |

Phase B (IEC 104 + PROFINET DCP + CSV import) adds ~800 lines / ~5-7 days.

Phase C (OPC UA + MQTT + JA4 + correlation) adds ~1,500 lines / ~10-14 days.
