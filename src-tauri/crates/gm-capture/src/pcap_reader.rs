use std::path::Path;
use log::{debug, warn};

use crate::error::CaptureError;
use crate::packet::ParsedPacket;
use crate::parsing;

/// Reads and parses packets from a PCAP/PCAPNG file.
///
/// # Usage
/// ```no_run
/// use gm_capture::PcapReader;
///
/// let reader = PcapReader::new();
/// let packets = reader.read_file("capture.pcap").unwrap();
/// println!("Parsed {} packets", packets.len());
/// ```
pub struct PcapReader;

impl PcapReader {
    pub fn new() -> Self {
        PcapReader
    }

    /// Read all packets from a PCAP or PCAPNG file.
    ///
    /// Returns a Vec of parsed packets with Layer 2-4 information extracted.
    /// Each packet is tagged with the origin filename for multi-PCAP tracking.
    /// Packets that fail to parse are silently skipped (logged at debug level).
    pub fn read_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<ParsedPacket>, CaptureError> {
        let path = path.as_ref();

        // Extract just the filename (not the full path) for origin tracking
        let origin_file = path
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());

        let mut capture = pcap::Capture::from_file(path)
            .map_err(|e| CaptureError::FileOpen(format!("{}: {}", path.display(), e)))?;

        let mut packets = Vec::new();
        let mut skipped = 0u64;

        while let Ok(raw_packet) = capture.next_packet() {
            // Extract timestamp from pcap header
            let timestamp = parsing::timestamp_from_pcap(*raw_packet.header);

            // Parse with etherparse — zero-copy slicing of packet headers
            match etherparse::SlicedPacket::from_ethernet(raw_packet.data) {
                Ok(parsed) => {
                    if let Some(packet) = parsing::extract_packet_info(&parsed, raw_packet.data, timestamp, &origin_file) {
                        packets.push(packet);
                    } else {
                        skipped += 1;
                        debug!("Skipped non-IP packet");
                    }
                }
                Err(e) => {
                    skipped += 1;
                    debug!("Failed to parse packet: {}", e);
                }
            }
        }

        if skipped > 0 {
            warn!("Skipped {} unparseable packets out of {}", skipped, packets.len() + skipped as usize);
        }

        log::info!(
            "Parsed {} packets from {}",
            packets.len(),
            path.display()
        );

        Ok(packets)
    }
}

impl Default for PcapReader {
    fn default() -> Self {
        Self::new()
    }
}
