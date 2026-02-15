//! Live packet capture from network interfaces.
//!
//! Opens an interface in promiscuous mode (PASSIVE ONLY — never transmits)
//! and captures packets in a background thread. Parsed packets are sent
//! through a channel for processing. Raw packet data is kept in a ring
//! buffer so the capture can be saved to a PCAP file on stop.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::error::CaptureError;
use crate::packet::ParsedPacket;
use crate::parsing;

/// Configuration for starting a live capture.
pub struct LiveCaptureConfig {
    /// Network interface name (e.g., "eth0", "en0")
    pub interface_name: String,
    /// Optional BPF filter expression (e.g., "tcp port 502")
    pub bpf_filter: Option<String>,
    /// Enable promiscuous mode (capture all traffic, not just addressed to us)
    pub promiscuous: bool,
    /// Maximum packets to keep in the ring buffer for PCAP save
    pub ring_buffer_size: usize,
    /// Maximum bytes to capture per packet
    pub snaplen: i32,
}

impl Default for LiveCaptureConfig {
    fn default() -> Self {
        Self {
            interface_name: String::new(),
            bpf_filter: None,
            promiscuous: true,
            ring_buffer_size: 1_000_000,
            snaplen: 65535,
        }
    }
}

/// Snapshot of capture statistics.
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    /// Total packets captured (including non-parseable ones)
    pub packets_captured: u64,
    /// Total bytes of raw packet data captured
    pub bytes_captured: u64,
    /// Elapsed time since capture started (seconds)
    pub elapsed_seconds: f64,
}

/// Raw captured packet data, stored in the ring buffer for PCAP save.
struct RawCapturedPacket {
    header: pcap::PacketHeader,
    data: Vec<u8>,
}

/// Handle to a running live capture session.
///
/// Created by [`LiveCaptureHandle::start`]. Provides methods to control
/// the capture (stop, pause, resume) and save captured data to PCAP.
pub struct LiveCaptureHandle {
    stop_flag: Arc<AtomicBool>,
    pause_flag: Arc<AtomicBool>,
    packets_captured: Arc<AtomicU64>,
    bytes_captured: Arc<AtomicU64>,
    start_time: Instant,
    thread_handle: Option<JoinHandle<Result<(), CaptureError>>>,
    /// Ring buffer of raw packets for PCAP save
    raw_packets: Arc<Mutex<VecDeque<RawCapturedPacket>>>,
    /// pcap linktype (needed for writing PCAP files)
    datalink: pcap::Linktype,
}

impl LiveCaptureHandle {
    /// Start a live capture on the specified interface.
    ///
    /// Returns a handle for controlling the capture and a receiver channel
    /// that yields parsed packets as they are captured. The capture runs
    /// in a background thread in promiscuous mode (PASSIVE ONLY — never transmits).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The interface is not found
    /// - Insufficient privileges (need CAP_NET_RAW on Linux, admin on Windows, BPF on macOS)
    /// - Invalid BPF filter expression
    pub fn start(config: LiveCaptureConfig) -> Result<(Self, mpsc::Receiver<ParsedPacket>), CaptureError> {
        let (tx, rx) = mpsc::channel();

        let stop_flag = Arc::new(AtomicBool::new(false));
        let pause_flag = Arc::new(AtomicBool::new(false));
        let packets_captured = Arc::new(AtomicU64::new(0));
        let bytes_captured = Arc::new(AtomicU64::new(0));
        let raw_packets: Arc<Mutex<VecDeque<RawCapturedPacket>>> =
            Arc::new(Mutex::new(VecDeque::new()));

        // Find the requested network interface
        let device = pcap::Device::list()
            .map_err(|e| CaptureError::InterfaceList(e.to_string()))?
            .into_iter()
            .find(|d| d.name == config.interface_name)
            .ok_or_else(|| CaptureError::InterfaceNotFound(config.interface_name.clone()))?;

        // Open the capture — PROMISCUOUS MODE, PASSIVE ONLY (receive-only, never transmit)
        let mut cap = pcap::Capture::from_device(device)
            .map_err(|e| enhance_privilege_error(e, &config.interface_name))?
            .promisc(config.promiscuous)
            .snaplen(config.snaplen)
            .timeout(100) // 100ms — keeps the loop responsive to stop/pause
            .open()
            .map_err(|e| enhance_privilege_error(e, &config.interface_name))?;

        // Apply BPF filter if provided
        if let Some(ref filter) = config.bpf_filter {
            cap.filter(filter, true)
                .map_err(|e| CaptureError::Capture(
                    format!("Invalid BPF filter '{}': {}", filter, e),
                ))?;
        }

        // Store linktype for PCAP save
        let datalink = cap.get_datalink();
        let ring_buffer_size = config.ring_buffer_size;
        let interface_name = config.interface_name.clone();

        // Clone Arc handles for the background thread
        let stop = stop_flag.clone();
        let pause = pause_flag.clone();
        let pkts_count = packets_captured.clone();
        let bytes_count = bytes_captured.clone();
        let raw_ring = raw_packets.clone();

        let thread_handle = thread::spawn(move || -> Result<(), CaptureError> {
            let origin = format!("live:{}", interface_name);
            log::info!("Live capture started on {}", interface_name);

            loop {
                // Check stop flag
                if stop.load(Ordering::Relaxed) {
                    break;
                }

                // If paused, sleep briefly and loop
                if pause.load(Ordering::Relaxed) {
                    thread::sleep(Duration::from_millis(50));
                    continue;
                }

                match cap.next_packet() {
                    Ok(raw_packet) => {
                        let header = *raw_packet.header;
                        let data = raw_packet.data.to_vec();
                        let length = data.len() as u64;

                        // Update raw counters
                        pkts_count.fetch_add(1, Ordering::Relaxed);
                        bytes_count.fetch_add(length, Ordering::Relaxed);

                        // Store in ring buffer (for PCAP save)
                        if let Ok(mut ring) = raw_ring.lock() {
                            if ring.len() >= ring_buffer_size {
                                ring.pop_front();
                            }
                            ring.push_back(RawCapturedPacket {
                                header,
                                data: data.clone(),
                            });
                        }

                        // Parse with etherparse and send to processing channel
                        let timestamp = parsing::timestamp_from_pcap(header);
                        if let Ok(parsed) = etherparse::SlicedPacket::from_ethernet(&data) {
                            if let Some(packet) = parsing::extract_packet_info(
                                &parsed, &data, timestamp, &origin,
                            ) {
                                // If channel is closed, stop capture
                                if tx.send(packet).is_err() {
                                    log::warn!("Packet channel closed, stopping capture");
                                    break;
                                }
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        // Normal — no packets available within the timeout window
                        continue;
                    }
                    Err(e) => {
                        log::error!("Live capture error: {}", e);
                        return Err(CaptureError::Capture(e.to_string()));
                    }
                }
            }

            log::info!("Live capture stopped on {}", interface_name);
            Ok(())
        });

        let handle = LiveCaptureHandle {
            stop_flag,
            pause_flag,
            packets_captured,
            bytes_captured,
            start_time: Instant::now(),
            thread_handle: Some(thread_handle),
            raw_packets,
            datalink,
        };

        Ok((handle, rx))
    }

    /// Stop the capture and wait for the capture thread to finish.
    pub fn stop(&mut self) -> Result<(), CaptureError> {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread_handle.take() {
            handle
                .join()
                .map_err(|_| CaptureError::Capture("Capture thread panicked".to_string()))?
        } else {
            Ok(())
        }
    }

    /// Pause the capture. Packets arriving while paused are not captured.
    pub fn pause(&self) {
        self.pause_flag.store(true, Ordering::Relaxed);
    }

    /// Resume a paused capture.
    pub fn resume(&self) {
        self.pause_flag.store(false, Ordering::Relaxed);
    }

    /// Check if the capture is currently paused.
    pub fn is_paused(&self) -> bool {
        self.pause_flag.load(Ordering::Relaxed)
    }

    /// Check if the capture is still running (not stopped).
    pub fn is_running(&self) -> bool {
        !self.stop_flag.load(Ordering::Relaxed)
    }

    /// Get a snapshot of current capture statistics.
    pub fn stats(&self) -> CaptureStats {
        CaptureStats {
            packets_captured: self.packets_captured.load(Ordering::Relaxed),
            bytes_captured: self.bytes_captured.load(Ordering::Relaxed),
            elapsed_seconds: self.start_time.elapsed().as_secs_f64(),
        }
    }

    /// Save the ring buffer contents to a PCAP file.
    ///
    /// Returns the number of packets written.
    pub fn save_to_pcap<P: AsRef<Path>>(&self, path: P) -> Result<usize, CaptureError> {
        let path = path.as_ref();
        let ring = self.raw_packets.lock()
            .map_err(|e| CaptureError::Capture(format!("Ring buffer lock poisoned: {}", e)))?;

        if ring.is_empty() {
            return Ok(0);
        }

        let dead = pcap::Capture::dead(self.datalink)
            .map_err(|e| CaptureError::Capture(
                format!("Failed to create dead capture: {}", e),
            ))?;

        let mut savefile = dead.savefile(path)
            .map_err(|e| CaptureError::Capture(
                format!("Failed to create savefile '{}': {}", path.display(), e),
            ))?;

        let count = ring.len();
        for raw in ring.iter() {
            let packet = pcap::Packet {
                header: &raw.header,
                data: &raw.data,
            };
            savefile.write(&packet);
        }

        log::info!("Saved {} packets to {}", count, path.display());
        Ok(count)
    }

    /// Get the number of packets currently in the ring buffer.
    pub fn ring_buffer_count(&self) -> usize {
        self.raw_packets.lock().map(|r| r.len()).unwrap_or(0)
    }
}

/// Enhance pcap error messages with platform-specific privilege guidance.
fn enhance_privilege_error(err: pcap::Error, interface: &str) -> CaptureError {
    let msg = err.to_string();

    // Check if this is a permission/privilege error
    let is_permission = msg.contains("ermission")
        || msg.contains("Operation not permitted")
        || msg.contains("EPERM")
        || msg.contains("you don't have permission");

    if is_permission {
        let guidance = if cfg!(target_os = "linux") {
            format!(
                "Insufficient privileges to capture on '{}'. Solutions:\n\
                 1. Run with sudo: sudo kusanaginokajiki\n\
                 2. Grant capability: sudo setcap cap_net_raw=eip <path-to-binary>\n\
                 3. Add your user to the 'pcap' or 'wireshark' group",
                interface
            )
        } else if cfg!(target_os = "macos") {
            format!(
                "Insufficient privileges to capture on '{}'. Solutions:\n\
                 1. Run with sudo: sudo kusanaginokajiki\n\
                 2. Fix BPF permissions: sudo chmod 644 /dev/bpf*\n\
                 3. Install ChmodBPF: brew install --cask wireshark (includes BPF permissions)",
                interface
            )
        } else if cfg!(target_os = "windows") {
            format!(
                "Cannot capture on '{}'. Ensure Npcap is installed:\n\
                 1. Download from https://npcap.com\n\
                 2. Install with 'WinPcap Compatible Mode' checked\n\
                 3. Restart the application",
                interface
            )
        } else {
            format!("Insufficient privileges to capture on '{}': {}", interface, msg)
        };

        CaptureError::Capture(guidance)
    } else {
        CaptureError::Capture(format!("Failed to open '{}': {}", interface, msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = LiveCaptureConfig::default();
        assert!(config.promiscuous);
        assert_eq!(config.ring_buffer_size, 1_000_000);
        assert_eq!(config.snaplen, 65535);
        assert!(config.bpf_filter.is_none());
    }

    #[test]
    fn test_capture_stats_default() {
        let stats = CaptureStats::default();
        assert_eq!(stats.packets_captured, 0);
        assert_eq!(stats.bytes_captured, 0);
    }
}
