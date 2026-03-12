//! Filtered PCAP export.
//!
//! Reads raw packets from one or more PCAP files, filters by IP address
//! and/or port number, and writes matching packets to an output file.
//!
//! Used by the `export_filtered_pcap` Tauri command.

use std::collections::HashSet;
use std::path::Path;

use crate::error::CaptureError;

/// Export packets matching the given filters from one or more input PCAPs.
///
/// # Filtering
/// - `filter_ips`: keep packets where src_ip OR dst_ip is in this set
/// - `filter_ports`: keep packets where src_port OR dst_port is in this set
/// - If both are non-empty, packets matching EITHER filter are included (OR logic)
/// - If both are empty, all packets are written (copy mode)
///
/// # Input paths
/// Paths starting with `[` (e.g. `[Suricata]`) are ingest-source tags, not
/// file paths — they are silently skipped.
///
/// Returns the number of packets written.
pub fn filter_export_pcap(
    input_paths: &[String],
    filter_ips: &[String],
    filter_ports: &[u16],
    output_path: &str,
) -> Result<u64, CaptureError> {
    let ip_set: HashSet<&str> = filter_ips.iter().map(|s| s.as_str()).collect();
    let port_set: HashSet<u16> = filter_ports.iter().copied().collect();

    // Create a dead (offline) capture handle for writing Ethernet frames
    let dead = pcap::Capture::dead(pcap::Linktype(1))
        .map_err(|e| CaptureError::Capture(format!("Cannot create dead capture: {}", e)))?;

    let mut savefile = dead.savefile(output_path)
        .map_err(|e| CaptureError::FileOpen(format!("Cannot create output '{}': {}", output_path, e)))?;

    let mut written = 0u64;

    for raw_path in input_paths {
        // Skip ingest-source tags (not file paths)
        if raw_path.starts_with('[') {
            continue;
        }

        let path = Path::new(raw_path);
        if !path.exists() {
            log::warn!("filter_export_pcap: file not found, skipping: {}", raw_path);
            continue;
        }

        let mut capture = match pcap::Capture::from_file(path) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("filter_export_pcap: cannot open '{}': {}", raw_path, e);
                continue;
            }
        };

        while let Ok(packet) = capture.next_packet() {
            if packet_matches_filter(packet.data, &ip_set, &port_set) {
                savefile.write(&packet);
                written += 1;
            }
        }
    }

    log::info!("filter_export_pcap: wrote {} packets to '{}'", written, output_path);
    Ok(written)
}

/// Check whether a raw Ethernet frame's IPs/ports match the given filters.
///
/// Parses IPv4 headers inline (no etherparse overhead) to extract src/dst
/// IP and port. Non-IP packets (ARP, IPv6, etc.) are excluded.
fn packet_matches_filter(data: &[u8], ip_set: &HashSet<&str>, port_set: &HashSet<u16>) -> bool {
    // No filters → include everything
    if ip_set.is_empty() && port_set.is_empty() {
        return true;
    }

    // Need at least an Ethernet header (14 bytes)
    if data.len() < 14 {
        return false;
    }

    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    // Only handle IPv4 (0x0800)
    if ethertype != 0x0800 {
        return false;
    }

    if data.len() < 20 + 14 {
        return false;
    }

    let ip_start = 14;
    let ihl = ((data[ip_start] & 0x0f) as usize) * 4;
    let proto = data[ip_start + 9];

    // Format src/dst IP as dotted decimal strings for Set lookup
    let src_ip = format!(
        "{}.{}.{}.{}",
        data[ip_start + 12], data[ip_start + 13],
        data[ip_start + 14], data[ip_start + 15]
    );
    let dst_ip = format!(
        "{}.{}.{}.{}",
        data[ip_start + 16], data[ip_start + 17],
        data[ip_start + 18], data[ip_start + 19]
    );

    // Extract TCP/UDP ports if present
    let (src_port, dst_port) = if (proto == 6 || proto == 17)
        && data.len() >= ip_start + ihl + 4
    {
        let port_start = ip_start + ihl;
        let sp = u16::from_be_bytes([data[port_start], data[port_start + 1]]);
        let dp = u16::from_be_bytes([data[port_start + 2], data[port_start + 3]]);
        (sp, dp)
    } else {
        (0, 0)
    };

    let ip_match = !ip_set.is_empty()
        && (ip_set.contains(src_ip.as_str()) || ip_set.contains(dst_ip.as_str()));

    let port_match = !port_set.is_empty()
        && (port_set.contains(&src_port) || port_set.contains(&dst_port));

    match (!ip_set.is_empty(), !port_set.is_empty()) {
        (true, true) => ip_match || port_match,   // either filter matches
        (true, false) => ip_match,
        (false, true) => port_match,
        (false, false) => true, // unreachable; handled at top
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_packet_matches_no_filters() {
        // Empty filter → always true
        let data = vec![0u8; 34]; // minimal Ethernet+IPv4
        assert!(packet_matches_filter(&data, &HashSet::new(), &HashSet::new()));
    }

    #[test]
    fn test_packet_matches_non_ip() {
        // ARP ethertype (0x0806) → excluded when filters are active
        let mut data = vec![0u8; 60];
        data[12] = 0x08;
        data[13] = 0x06;
        let ip_set: HashSet<&str> = ["10.0.0.1"].iter().copied().collect();
        assert!(!packet_matches_filter(&data, &ip_set, &HashSet::new()));
    }

    #[test]
    fn test_packet_matches_ipv4_by_ip() {
        // Build a minimal IPv4/TCP packet
        let mut data = vec![0u8; 54]; // 14 Ethernet + 20 IP + 20 TCP
        // Ethertype = 0x0800 (IPv4)
        data[12] = 0x08;
        data[13] = 0x00;
        // IP: version/IHL = 0x45 (IPv4, 20 bytes)
        data[14] = 0x45;
        // Protocol = 6 (TCP)
        data[23] = 6;
        // src IP = 10.0.0.5
        data[26] = 10; data[27] = 0; data[28] = 0; data[29] = 5;
        // dst IP = 192.168.1.100
        data[30] = 192; data[31] = 168; data[32] = 1; data[33] = 100;

        let ip_set: HashSet<&str> = ["10.0.0.5"].iter().copied().collect();
        assert!(packet_matches_filter(&data, &ip_set, &HashSet::new()));

        let ip_set2: HashSet<&str> = ["192.168.1.100"].iter().copied().collect();
        assert!(packet_matches_filter(&data, &ip_set2, &HashSet::new()));

        let ip_set3: HashSet<&str> = ["10.0.0.99"].iter().copied().collect();
        assert!(!packet_matches_filter(&data, &ip_set3, &HashSet::new()));
    }
}
