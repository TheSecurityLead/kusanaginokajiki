# PROTOCOL-DEEP-PARSE.md — Wire Formats, Rust Structs & Test Payloads

This document contains the detailed technical specifications for all deep-parsed protocols. Claude Code should read this file when implementing or modifying protocol parsers in `gm-parsers`.

---

## Existing Parsers (Complete)

### Modbus TCP (modbus.rs)

**Wire format:** 7-byte MBAP header + PDU.
```
MBAP Header:
  [0..1]  u16 BE  Transaction ID
  [2..3]  u16 BE  Protocol ID (always 0x0000)
  [4..5]  u16 BE  Length (remaining bytes)
  [6]     u8      Unit ID

PDU:
  [0]     u8      Function Code
  [1..n]  Data    (varies by FC)
```

**Key function codes:** 1-4=reads, 5/6/15/16=writes, 8=diagnostics, 43/14=Device ID.

**Device ID (FC 43, sub 14):** Returns vendor name, product code, revision at confidence 5.

**Struct:** `ModbusInfo` — transaction_id, unit_id, function_code, is_read/is_write, register range, device_id fields, master/slave role.

### DNP3 (dnp3.rs)

**Wire format:** 10-byte Data Link Layer header.
```
Data Link Header:
  [0..1]  u16     Start bytes (0x0564)
  [2]     u8      Length
  [3]     u8      Control (bit 7: direction, bit 6: primary)
  [4..5]  u16 LE  Destination address
  [6..7]  u16 LE  Source address
  [8..9]  u16     CRC
```

**Key function codes:** 1=Read, 2=Write, 129=Response, 130=Unsolicited Response.

**Struct:** `Dnp3Info` — start_bytes_valid, src_address, dst_address, function_code, is_master/is_outstation, has_unsolicited.

---

## New Parsers (Phase 12A)

### EtherNet/IP + CIP (enip.rs) — Port 44818 TCP/UDP, 2222 UDP

#### Wire Format

```
Encapsulation Header (24 bytes, ALL LITTLE-ENDIAN):
  [0..1]   u16 LE  Command
             0x0000 = NOP
             0x0004 = ListServices
             0x0063 = ListIdentity
             0x0064 = ListInterfaces
             0x0065 = RegisterSession
             0x0066 = UnregisterSession
             0x006F = SendRRData
             0x0070 = SendUnitData
  [2..3]   u16 LE  Length (of data following this 24-byte header)
  [4..7]   u32 LE  Session Handle
  [8..11]  u32 LE  Status (0=success)
  [12..19] [u8;8]  Sender Context
  [20..23] u32 LE  Options (0)
```

**ListIdentity Response** (command 0x0063):
```
CPF (Common Packet Format):
  [0..1]   u16 LE  Item Count
  Per item:
    [0..1]  u16 LE  Item Type ID (0x000C = ListIdentity)
    [2..3]  u16 LE  Item Length

Identity Item:
  [0..1]   u16 LE  Encap Protocol Version
  [2..3]   u16 LE  Socket Address Family (AF_INET = 2)
  [4..5]   u16 BE  Socket Port
  [6..9]   u32 BE  Socket IP Address
  [10..17] [u8;8]  Socket Zeros
  [18..19] u16 LE  Vendor ID          ← DEVICE ID
  [20..21] u16 LE  Device Type        ← DEVICE ID
  [22..23] u16 LE  Product Code       ← DEVICE ID
  [24]     u8      Major Revision     ← FIRMWARE
  [25]     u8      Minor Revision     ← FIRMWARE
  [26..27] u16 LE  Status
  [28..31] u32 LE  Serial Number      ← UNIQUE ID
  [32]     u8      Product Name Len
  [33..n]  String  Product Name       ← DEVICE ID
  [n+1]    u8      State
```

**SendRRData / SendUnitData** (commands 0x006F / 0x0070):
```
  [0..3]   u32 LE  Interface Handle (0 for CIP)
  [4..5]   u16 LE  Timeout
  [6..7]   u16 LE  Item Count (typically 2)
  
  Item 1: Address (null for unconnected, connected address for connected)
    Type 0x0000: Null Address (length 0)
    Type 0x00A1: Connected Address (4 bytes connection ID)
  
  Item 2: Data
    Type 0xB2: Unconnected Data
    Type 0xB1: Connected Data
    Length: u16 LE
    
CIP Message Router:
  [0]      u8     Service Code
                    0x01 = Get Attribute All
                    0x0E = Get Attribute Single
                    0x10 = Set Attribute Single
                    0x05 = Reset
                    0x4C = Read
                    0x4D = Write
                    0x4E = Read Modify Write
                    0x52 = Unconnected Send
                    0x54 = Forward Open
                    0x55 = Forward Close
                    Response: service code | 0x80
  [1]      u8     Request Path Size (in 16-bit words)
  [2..n]   Path   Encoded segments:
                    0x20 xx = 8-bit Class ID
                    0x21 00 xx xx = 16-bit Class ID
                    0x24 xx = 8-bit Instance ID
                    0x25 00 xx xx = 16-bit Instance ID
                    0x30 xx = 8-bit Attribute ID
                    0x31 00 xx xx = 16-bit Attribute ID
```

#### Rust Structs

```rust
pub enum EnipCommand {
    Nop, ListServices, ListIdentity, ListInterfaces,
    RegisterSession, UnregisterSession, SendRRData, SendUnitData, Unknown(u16),
}

pub enum CipService {
    GetAttributeAll, GetAttributeSingle, SetAttributeSingle, Reset,
    Read, Write, ReadModifyWrite, UnconnectedSend, ForwardOpen, ForwardClose, Unknown(u8),
}

pub enum CipClass {
    Identity, MessageRouter, Assembly, Connection, ConnectionManager,
    File, TcpIp, EthernetLink, Unknown(u16),
}

pub struct EnipIdentity {
    pub vendor_id: u16, pub device_type: u16, pub product_code: u16,
    pub major_revision: u8, pub minor_revision: u8, pub serial_number: u32,
    pub product_name: String, pub status: u16, pub state: u8,
}

pub struct EnipInfo {
    pub command: EnipCommand, pub session_handle: u32, pub status: u32,
    pub identity: Option<EnipIdentity>,
    pub cip_service: Option<CipService>, pub cip_class: Option<CipClass>,
    pub cip_instance: Option<u32>, pub cip_attribute: Option<u16>,
    pub is_response: bool, pub cip_error: bool, pub role: EnipRole,
}

pub enum EnipRole { Scanner, Adapter, Unknown }
```

#### Test Payloads

**ListIdentity Request:**
```
63 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

**ListIdentity Response (Rockwell 1756-L71):**
```
63 00 3B 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
01 00 0C 00 33 00 01 00 00 02 AF 12 C0 A8 01 0A 00 00 00 00 00 00 00 00
01 00 0E 00 36 00 14 03 00 00 78 56 34 12 0F 31 37 35 36 2D 4C 37 31 2F
42 20 56 32 30 00 03
```

**SendRRData with CIP GetAttributeAll to Identity:**
```
6F 00 16 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 02 00 00 00 00 00 B2 00 06 00 01 02 20 01 24 01
```

---

### S7comm (s7comm.rs) — Port 102 TCP

#### Wire Format

```
TPKT Header (4 bytes):
  [0]     u8    Version (MUST be 0x03)
  [1]     u8    Reserved (0x00)
  [2..3]  u16 BE  Total Length (including TPKT)

COTP Header:
  DT Data (typ. 3 bytes):
    [0]   u8    Length (of header minus this byte, typically 0x02)
    [1]   u8    PDU Type: 0xF0 = DT Data
    [2]   u8    TPDU number + EOT flag (0x80 = last fragment)

  Connection Request (CR, 0xE0) / Connection Confirm (CC, 0xD0):
    [0]   u8    Length
    [1]   u8    PDU Type: 0xE0 (CR) or 0xD0 (CC)
    [2..3] u16  Dst Reference
    [4..5] u16  Src Reference
    [6]   u8    Class/Option
    [7..n] TLV parameters:
      0xC0 = TPDU size (1 byte: log2 of size)
      0xC1 = Src TSAP (2 bytes)
      0xC2 = Dst TSAP (2 bytes)
        Dst TSAP byte[1]: rack = (byte >> 5) & 0x07, slot = byte & 0x1F

S7 Header (10 or 12 bytes):
  [0]     u8    Protocol ID (MUST be 0x32)
  [1]     u8    ROSCTR (PDU type):
                  0x01 = Job (request)
                  0x02 = Ack
                  0x03 = Ack_Data (response with data)
                  0x07 = Userdata
  [2..3]  u16 BE  Reserved (0x0000)
  [4..5]  u16 BE  PDU Reference
  [6..7]  u16 BE  Parameter Length
  [8..9]  u16 BE  Data Length
  If ROSCTR == 0x02 or 0x03 (12-byte header):
    [10]  u8    Error Class
    [11]  u8    Error Code

S7 Function Codes (first byte of parameters):
  0x04 = Read Var
  0x05 = Write Var
  0xF0 = Setup Communication
  0x28 = PI Service (start/stop/delete)
  0x29 = PLC Stop
  0x1A = Upload Start
  0x1B = Upload
  0x1C = Upload End
  0x1D = Download Start
  0x1E = Download
  0x1F = Download End

Setup Communication Parameters (after FC 0xF0):
  [1]     u8    Reserved
  [2..3]  u16 BE  Max AmQ Calling
  [4..5]  u16 BE  Max AmQ Called
  [6..7]  u16 BE  PDU Length
```

#### Rust Structs

```rust
pub enum CotpPduType { ConnectionRequest, ConnectionConfirm, DtData, DisconnectRequest, Unknown(u8) }
pub struct CotpParams { dst_ref: u16, src_ref: u16, src_tsap: Option<Vec<u8>>, dst_tsap: Option<Vec<u8>>, tpdu_size: Option<u8>, rack: Option<u8>, slot: Option<u8> }
pub enum S7PduType { Job, Ack, AckData, Userdata, Unknown(u8) }
pub enum S7Function { ReadVar, WriteVar, SetupCommunication, PiService, PlcStop, UploadStart, Upload, UploadEnd, DownloadStart, DownloadEnd, Unknown(u8) }
pub struct S7Info {
    cotp_pdu_type: CotpPduType, cotp_params: Option<CotpParams>,
    s7_pdu_type: Option<S7PduType>, s7_function: Option<S7Function>,
    pdu_reference: Option<u16>, error_class: Option<u8>, error_code: Option<u8>,
    max_amq_calling: Option<u16>, max_amq_called: Option<u16>, pdu_length: Option<u16>,
    szl_id: Option<u16>, order_number: Option<String>, firmware_version: Option<String>,
    module_type: Option<String>, serial_number: Option<String>, role: S7Role,
}
pub enum S7Role { Client, Server, Unknown }
```

#### Test Payloads

**COTP CR (rack 0, slot 2):**
`03 00 00 16 11 E0 00 00 00 01 00 C0 01 0A C1 02 01 00 C2 02 01 02`

**S7 Setup Communication (Job):**
`03 00 00 19 02 F0 80 32 01 00 00 00 01 00 08 00 00 F0 00 00 01 00 01 01 E0`

**S7 PLC Stop:**
`03 00 00 15 02 F0 80 32 01 00 00 00 04 00 04 00 00 29 00 00 00`

**S7 Download Start:**
`03 00 00 13 02 F0 80 32 01 00 00 00 03 00 02 00 00 1D 00`

---

### BACnet (bacnet.rs) — Port 47808 UDP

#### Wire Format

```
BVLCI (4 bytes):
  [0]     u8    Type (MUST be 0x81)
  [1]     u8    Function:
                  0x00 = BVLC-Result
                  0x04 = Forwarded-NPDU
                  0x0A = Original-Unicast-NPDU
                  0x0B = Original-Broadcast-NPDU
  [2..3]  u16 BE  Length (total including BVLCI)

NPDU:
  [0]     u8    Version (MUST be 0x01)
  [1]     u8    Control:
                  bit 7: NSDU contains network-layer message (1) or APDU (0)
                  bit 5: DNET/DADR/Hop present
                  bit 3: SNET/SADR present
                  bit 2: expect reply
  If bit 5 set:
    [2..3] u16 BE  DNET
    [4]    u8      DLEN
    [5..5+DLEN] DADR
    Then: [1 byte] Hop Count
  If bit 3 set:
    SNET (u16 BE), SLEN (u8), SADR (SLEN bytes)

APDU:
  [0] bits 7-4: PDU Type
    0x0 = Confirmed-Request
    0x1 = Unconfirmed-Request
    0x2 = SimpleAck
    0x3 = ComplexAck
    0x5 = Error
    0x6 = Reject
    0x7 = Abort

  Confirmed Request:
    [0] bits 3-0: additional flags
    [1] Max segments / max APDU size
    [2] Invoke ID
    [3] Service Choice

  Unconfirmed Request:
    [1] Service Choice:
      0x00 = I-Am
      0x01 = I-Have
      0x07 = Who-Has
      0x08 = Who-Is

I-Am Data (BACnet tagged encoding):
  Application Tag 0xC4 (Object ID, 4 bytes):
    bits 31-22: Object Type (8 = Device)
    bits 21-0:  Instance Number
  Application Tag 0x22 (Unsigned16): Max APDU Length
  Application Tag 0x91 (Enumerated8): Segmentation Supported
  Application Tag 0x21 (Unsigned8): Vendor ID
```

#### Rust Structs

```rust
pub enum BvlcFunction { BvlcResult, ForwardedNpdu, OriginalUnicast, OriginalBroadcast, Unknown(u8) }
pub enum BacnetPduType { ConfirmedRequest, UnconfirmedRequest, SimpleAck, ComplexAck, Error, Reject, Abort, Unknown(u8) }
pub enum BacnetService { ReadProperty, ReadPropertyMultiple, WriteProperty, WritePropertyMultiple, AtomicReadFile, AtomicWriteFile, SubscribeCov, ReinitializeDevice, DeviceCommunicationControl, IAm, IHave, WhoIs, WhoHas, Unknown(u8) }
pub enum BacnetObjectType { AnalogInput, AnalogOutput, AnalogValue, BinaryInput, BinaryOutput, BinaryValue, Device, File, Unknown(u16) }
pub struct BacnetIAm { device_instance: u32, max_apdu_length: u32, segmentation_supported: u8, vendor_id: u16 }
pub struct BacnetInfo {
    bvlc_function: BvlcFunction, npdu_version: u8, is_network_message: bool,
    pdu_type: Option<BacnetPduType>, service: Option<BacnetService>,
    iam: Option<BacnetIAm>, object_type: Option<BacnetObjectType>,
    object_instance: Option<u32>, property_id: Option<u32>, role: BacnetRole,
}
pub enum BacnetRole { Client, Server, Unknown }
```

#### Test Payloads

**I-Am (Device #1001, Vendor 3):**
`81 0B 00 19 01 20 FF FF 00 FF 10 00 C4 02 00 03 E9 22 01 E0 91 00 21 03`

**Who-Is:**
`81 0B 00 0C 01 20 FF FF 00 FF 10 08`

**WriteProperty to AnalogOutput (T0855):**
`81 0A 00 15 01 04 00 04 02 0F 0C 00 80 00 01 19 55 3E 44 42 C8 00 00 3F`

---

## New Parsers (Phase 12B)

### IEC 60870-5-104 (iec104.rs) — Port 2404 TCP

#### Wire Format

```
APCI (6 bytes, always):
  [0]     u8    Start byte (MUST be 0x68)
  [1]     u8    APDU Length (bytes after this, excluding start+length)
  [2..5]  Control fields:

  Frame type detection from byte[2]:
    bit 0 == 0:     I-frame (Information)
      [2..3] u16 LE  Send seq N(S) << 1
      [4..5] u16 LE  Recv seq N(R) << 1
    bits[1:0] == 01: S-frame (Supervisory)
      [2..3] Reserved
      [4..5] u16 LE  Recv seq N(R) << 1
    bits[1:0] == 11: U-frame (Unnumbered)
      [2] Control function:
        0x07 = STARTDT act
        0x0B = STARTDT con
        0x13 = STOPDT act
        0x17 = STOPDT con
        0x43 = TESTFR act
        0x83 = TESTFR con

ASDU (follows APCI in I-frames):
  [0]   u8    Type ID (1-127):
    Monitoring (station→master): 1-44
      1=M_SP_NA_1(single), 3=M_DP_NA_1(double), 9=M_ME_NA_1(normalized),
      13=M_ME_NC_1(float), 30=M_SP_TB_1(single+time), 36=M_ME_TF_1(float+time)
    Commands (master→station): 45-69
      45=C_SC_NA_1(single cmd), 46=C_DC_NA_1(double cmd), 48=C_SE_NC_1(setpoint float)
    System: 100-107
      100=C_IC_NA_1(interrogation), 101=C_CI_NA_1(counter interrog),
      103=C_CS_NA_1(clock sync), 105=C_RP_NA_1(reset process)
  [1]   u8    VSQ: bit7=SQ(sequence), bits0-6=number of objects
  [2]   u8    COT low: bits0-5=cause, bit6=P/N, bit7=T(test)
  [3]   u8    COT high: Originator Address
  [4..5] u16 LE  Common ASDU Address (station)
  [6..8] 3 bytes LE  First IOA (Information Object Address)
```

#### Rust Structs

```rust
pub enum Iec104FrameType { I, S, U }
pub enum UFrameFunction { StartDtAct, StartDtCon, StopDtAct, StopDtCon, TestFrAct, TestFrCon, Unknown(u8) }
pub enum AsduTypeId { SinglePoint, DoublePoint, MeasuredNormalized, MeasuredShortFloat, SingleCommand, DoubleCommand, SetpointFloat, Interrogation, CounterInterrogation, ClockSync, ResetProcess, Unknown(u8) }
pub enum CauseOfTransmission { Periodic, Spontaneous, Activation, ActivationCon, Deactivation, Unknown(u8) }
pub struct Iec104Info {
    frame_type: Iec104FrameType, u_function: Option<UFrameFunction>,
    send_seq: Option<u16>, recv_seq: Option<u16>,
    type_id: Option<AsduTypeId>, num_objects: Option<u8>, is_sequence: bool,
    cause: Option<CauseOfTransmission>, is_negative: bool, is_test: bool,
    originator_address: Option<u8>, common_address: Option<u16>, first_ioa: Option<u32>,
    is_command: bool, is_monitor: bool, role: Iec104Role,
}
pub enum Iec104Role { Master, Outstation, Unknown }
```

#### Test Payloads

**STARTDT act:** `68 04 07 00 00 00`
**Interrogation Command (Type 100):** `68 0E 00 00 00 00 64 01 06 00 01 00 00 00 00 14`
**Single Command (Type 45):** `68 0E 02 00 00 00 2D 01 06 00 01 00 01 00 00 01`
**Measured Float (Type 13):** `68 12 04 00 02 00 0D 01 03 00 01 00 0A 00 00 00 00 C8 42 00`

---

### PROFINET DCP (profinet_dcp.rs) — Port 34964 / Ethertype 0x8892

#### Wire Format

```
DCP Header (10 bytes):
  [0]     u8    Service ID:
                  0x03 = Get, 0x04 = Set, 0x05 = Identify, 0x06 = Hello
  [1]     u8    Service Type:
                  0x00 = Request, 0x01 = Response Success, 0x05 = Response Error
  [2..5]  u32 BE  Xid (transaction ID)
  [6..7]  u16 BE  Response Delay
  [8..9]  u16 BE  DCP Data Length

DCP Blocks (TLV, within DCP Data Length):
  [0]     u8    Option
  [1]     u8    Suboption
  [2..3]  u16 BE  Block Length
  [4..5]  u16 BE  Block Info (responses only)
  [6..n]  Data

  Key option/suboption pairs:
    (0x01, 0x01) = MAC Address (6 bytes)
    (0x01, 0x02) = IP Suite (4+4+4 = IP, mask, gateway)
    (0x02, 0x01) = Vendor/Manufacturer (ASCII string)
    (0x02, 0x02) = Name of Station (ASCII string)
    (0x02, 0x03) = Device ID (u16 vendor_id + u16 device_id)
    (0x02, 0x04) = Device Role (u16: 0x01=IO-Device, 0x02=IO-Controller, 0x08=IO-Supervisor)
    (0x02, 0x06) = Alias Name (ASCII string)

  Block length padded to even boundary for next block.
```

#### Rust Structs

```rust
pub enum DcpServiceId { Get, Set, Identify, Hello, Unknown(u8) }
pub enum DcpServiceType { Request, ResponseSuccess, ResponseError, Unknown(u8) }
pub struct DcpDeviceInfo {
    name_of_station: Option<String>, vendor_name: Option<String>,
    vendor_id: Option<u16>, device_id: Option<u16>, device_role: Option<u8>,
    ip_address: Option<[u8;4]>, subnet_mask: Option<[u8;4]>, gateway: Option<[u8;4]>,
    mac_address: Option<[u8;6]>, alias_name: Option<String>,
}
pub struct ProfinetDcpInfo {
    service_id: DcpServiceId, service_type: DcpServiceType,
    xid: u32, device_info: DcpDeviceInfo, role: ProfinetRole,
}
pub enum ProfinetRole { IoDevice, IoController, IoSupervisor, Unknown }
```

---

## Vendor ID Lookup Tables (vendor_tables.rs)

### CIP Vendor IDs (ODVA)

```rust
pub fn cip_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        1 => "Rockwell Automation/Allen-Bradley",
        2 => "Namco Controls",
        5 => "Rockwell Automation/Reliance Electric",
        9 => "Woodhead Software & Electronics",
        12 => "Siemens", 13 => "Phoenix Contact", 15 => "Wago",
        19 => "Turck", 20 => "Omron", 28 => "Schneider Electric",
        33 => "ABB", 43 => "Bosch Rexroth", 44 => "Parker Hannifin",
        48 => "Molex", 49 => "HMS Networks (Anybus)", 50 => "Eaton",
        58 => "Pepperl+Fuchs", 60 => "Cognex", 72 => "Danfoss",
        78 => "Beckhoff Automation", 88 => "SEW-EURODRIVE", 90 => "Pilz",
        100 => "Endress+Hauser", 113 => "Balluff", 119 => "Festo", 283 => "ODVA",
        _ => "Unknown Vendor",
    }
}
```

### PROFINET Vendor IDs

```rust
pub fn profinet_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        0x002A => "Siemens", 0x0019 => "Phoenix Contact", 0x0109 => "Turck",
        0x0021 => "Wago", 0x00B0 => "Pepperl+Fuchs", 0x011E => "Beckhoff",
        0x000E => "ABB", 0x015D => "Festo", 0x001C => "Schneider Electric",
        0x014D => "Endress+Hauser", 0x00DA => "Danfoss", 0x004E => "Balluff",
        _ => "Unknown Vendor",
    }
}
```
