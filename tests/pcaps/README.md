# Test PCAP Files

Place ICS/SCADA PCAP files in this directory for testing.

## Recommended Sources

1. **automayt/ICS-pcap** — https://github.com/automayt/ICS-pcap
   - Modbus, DNP3, EtherNet/IP, S7comm, BACnet samples

2. **Wireshark Samples** — https://wiki.wireshark.org/SampleCaptures
   - Search for: Modbus, DNP3, BACnet

3. **4SICS Geek Lounge** — https://www.netresec.com/?page=PCAP4SICS
   - Real ICS network traffic from the 4SICS conference

4. **NETRESEC** — https://www.netresec.com/?page=PcapFiles
   - Various industrial network captures

## File Naming Convention

```
<protocol>_<scenario>_<date>.pcap
```

Examples:
- `modbus_polling_normal.pcap`
- `dnp3_substation_mixed.pcap`
- `mixed_ics_assessment_2024.pcapng`

> ⚠️ PCAP files are excluded from git via `.gitignore` to avoid bloating the repository.
> Only this README is tracked.
