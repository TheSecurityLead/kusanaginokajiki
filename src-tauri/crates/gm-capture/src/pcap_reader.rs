use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use log::{debug, warn};

use crate::error::CaptureError;
use crate::packet::ParsedPacket;
use crate::parsing;

/// Progress update emitted roughly every 500ms during streaming PCAP processing.
#[derive(Debug, Clone)]
pub struct ProgressUpdate {
    pub current_file: String,
    pub packets_processed: u64,
    pub bytes_processed: u64,
    pub file_size: u64,
    pub progress_percent: f64,
    pub elapsed_secs: f64,
}

/// Statistics returned after a `stream_file` call completes.
#[derive(Debug, Clone, Default)]
pub struct FileProcessStats {
    pub packet_count: u64,
    pub bytes_processed: u64,
    pub skipped: u64,
}

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

    /// Stream-process a PCAP/PCAPNG file one packet at a time without buffering.
    ///
    /// Calls `on_packet` for every successfully parsed packet and `on_progress`
    /// roughly every 500ms. Checks `cancelled` each packet; if set, returns
    /// `Err(CaptureError::Cancelled)` immediately.
    ///
    /// Memory usage is O(1) with respect to file size — only a single
    /// `ParsedPacket` exists in memory at a time.
    pub fn stream_file(
        &self,
        path: &str,
        mut on_packet: impl FnMut(&ParsedPacket),
        mut on_progress: impl FnMut(ProgressUpdate),
        cancelled: &AtomicBool,
    ) -> Result<FileProcessStats, CaptureError> {
        let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        let origin_file = Path::new(path)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string());

        let mut capture = pcap::Capture::from_file(path)
            .map_err(|e| CaptureError::FileOpen(format!("{}: {}", path, e)))?;

        let mut stats = FileProcessStats::default();
        let start = std::time::Instant::now();
        let mut last_progress = std::time::Instant::now();

        while let Ok(raw_packet) = capture.next_packet() {
            if cancelled.load(Ordering::Relaxed) {
                return Err(CaptureError::Cancelled);
            }

            let header = *raw_packet.header;
            let cap_len = header.caplen as u64;
            let timestamp = parsing::timestamp_from_pcap(header);

            match etherparse::SlicedPacket::from_ethernet(raw_packet.data) {
                Ok(parsed) => {
                    if let Some(packet) = parsing::extract_packet_info(
                        &parsed,
                        raw_packet.data,
                        timestamp,
                        &origin_file,
                    ) {
                        on_packet(&packet);
                        stats.packet_count += 1;
                    } else {
                        stats.skipped += 1;
                    }
                }
                Err(_) => {
                    stats.skipped += 1;
                }
            }

            stats.bytes_processed += cap_len;

            // Throttle progress events to ~2/sec to avoid overhead
            if last_progress.elapsed() > std::time::Duration::from_millis(500) {
                let progress_percent = if file_size > 0 {
                    (stats.bytes_processed as f64 / file_size as f64 * 100.0).min(100.0)
                } else {
                    0.0
                };
                on_progress(ProgressUpdate {
                    current_file: origin_file.clone(),
                    packets_processed: stats.packet_count,
                    bytes_processed: stats.bytes_processed,
                    file_size,
                    progress_percent,
                    elapsed_secs: start.elapsed().as_secs_f64(),
                });
                last_progress = std::time::Instant::now();
            }
        }

        // Final progress event at completion
        on_progress(ProgressUpdate {
            current_file: origin_file.clone(),
            packets_processed: stats.packet_count,
            bytes_processed: stats.bytes_processed,
            file_size,
            progress_percent: 100.0,
            elapsed_secs: start.elapsed().as_secs_f64(),
        });

        Ok(stats)
    }
}

// Default impl

impl Default for PcapReader {
    fn default() -> Self {
        Self::new()
    }
}
