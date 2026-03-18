//! Communication pattern analysis: per-connection timing statistics and anomaly detection.
//!
//! `PatternAnalyzer` accumulates per-packet data using Welford's online algorithm
//! for O(1) per-packet cost and O(1) memory per connection pair regardless of
//! packet count.  No timestamp vectors are stored — intervals are computed
//! incrementally as each packet arrives.
//!
//! `compute_stats()` is O(n_connections) and returns all entries sorted by
//! descending packet count.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-connection-pair timing and traffic statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub port: u16,
    pub packet_count: u64,
    pub byte_count: u64,
    pub first_seen: f64,
    pub last_seen: f64,
    pub duration_secs: f64,
    pub avg_interval_ms: f64,
    pub std_interval_ms: f64,
    pub min_interval_ms: f64,
    pub max_interval_ms: f64,
    /// True when CV < 0.3 and at least 5 inter-packet intervals exist.
    pub is_periodic: bool,
    pub packets_per_sec: f64,
}

/// Type classification for a detected pattern anomaly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternAnomalyType {
    /// OT connection with ≥10 packets but highly variable timing (CV > 1.0).
    IrregularPolling,
    /// Single-packet connection — may indicate a scan or probe.
    OneOffConnection,
    /// More than 100 packets/sec on an OT protocol.
    HighFrequency,
    /// Maximum inter-packet gap is 10× the average (bursty traffic).
    BurstTraffic,
}

/// A detected anomaly in a connection's communication pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternAnomaly {
    pub anomaly_type: PatternAnomalyType,
    pub src_ip: String,
    pub dst_ip: String,
    pub port: u16,
    pub protocol: String,
    pub description: String,
    pub severity: String,
}

// Internal map key: (src_ip, dst_ip, dst_port, protocol)
type ConnKey = (String, String, u16, String);

/// Per-connection accumulator using Welford's online algorithm.
///
/// Stores O(1) state regardless of packet count: no timestamp vectors.
struct ConnEntry {
    packet_count: u64,
    byte_count: u64,
    first_seen: f64,
    last_seen: f64,
    /// Previous packet timestamp (seconds) for computing the next interval.
    prev_ts: Option<f64>,
    /// Number of inter-packet intervals recorded so far.
    interval_count: u64,
    /// Welford running mean of intervals (milliseconds).
    mean_ms: f64,
    /// Welford running M2 — sum of squared deviations from mean (ms²).
    m2_ms: f64,
    /// Minimum interval seen (milliseconds).
    min_ms: f64,
    /// Maximum interval seen (milliseconds).
    max_ms: f64,
}

impl ConnEntry {
    fn new(timestamp_secs: f64, bytes: u64) -> Self {
        Self {
            packet_count: 1,
            byte_count: bytes,
            first_seen: timestamp_secs,
            last_seen: timestamp_secs,
            prev_ts: Some(timestamp_secs),
            interval_count: 0,
            mean_ms: 0.0,
            m2_ms: 0.0,
            min_ms: f64::INFINITY,
            max_ms: f64::NEG_INFINITY,
        }
    }

    fn update(&mut self, timestamp_secs: f64, bytes: u64) {
        self.packet_count += 1;
        self.byte_count += bytes;

        // Track true first/last regardless of packet arrival order.
        if timestamp_secs < self.first_seen {
            self.first_seen = timestamp_secs;
        }
        if timestamp_secs > self.last_seen {
            self.last_seen = timestamp_secs;
        }

        // Welford's online update for the inter-packet interval.
        // Skip negative intervals — they indicate out-of-order arrival.
        if let Some(prev) = self.prev_ts {
            let interval_ms = (timestamp_secs - prev) * 1000.0;
            if interval_ms >= 0.0 {
                self.interval_count += 1;
                let n = self.interval_count as f64;
                // Welford: mean and M2 update
                let delta = interval_ms - self.mean_ms;
                self.mean_ms += delta / n;
                let delta2 = interval_ms - self.mean_ms;
                self.m2_ms += delta * delta2;

                if interval_ms < self.min_ms {
                    self.min_ms = interval_ms;
                }
                if interval_ms > self.max_ms {
                    self.max_ms = interval_ms;
                }
            }
        }

        self.prev_ts = Some(timestamp_secs);
    }
}

/// Accumulates per-packet timing data and computes communication pattern statistics.
///
/// All computation is O(1) per packet (Welford's online algorithm).
/// No timestamp vectors are stored — memory is bounded regardless of packet count.
///
/// # Usage
/// ```
/// use gm_analysis::comm_patterns::PatternAnalyzer;
///
/// let mut analyzer = PatternAnalyzer::new();
/// analyzer.record_packet("10.0.0.1", "10.0.0.2", 502, "Modbus", 0.0, 100);
/// analyzer.record_packet("10.0.0.1", "10.0.0.2", 502, "Modbus", 0.5, 100);
/// let stats = analyzer.compute_stats();
/// assert_eq!(stats.len(), 1);
/// ```
pub struct PatternAnalyzer {
    data: HashMap<ConnKey, ConnEntry>,
}

impl PatternAnalyzer {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    /// Record a single packet.  O(1) — updates Welford accumulators in place.
    pub fn record_packet(
        &mut self,
        src_ip: &str,
        dst_ip: &str,
        port: u16,
        protocol: &str,
        timestamp_secs: f64,
        bytes: u64,
    ) {
        let key = (
            src_ip.to_string(),
            dst_ip.to_string(),
            port,
            protocol.to_string(),
        );
        match self.data.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                e.get_mut().update(timestamp_secs, bytes);
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(ConnEntry::new(timestamp_secs, bytes));
            }
        }
    }

    /// Compute statistics for all tracked connection pairs.
    ///
    /// O(n_connections) — derives stats from pre-computed Welford accumulators.
    /// Returns all entries sorted by descending packet count.
    pub fn compute_stats(&self) -> Vec<ConnectionStats> {
        let mut result = Vec::with_capacity(self.data.len());

        for ((src_ip, dst_ip, port, protocol), entry) in &self.data {
            let duration_secs = entry.last_seen - entry.first_seen;

            let (avg_interval_ms, std_interval_ms, min_interval_ms, max_interval_ms, is_periodic) =
                if entry.interval_count == 0 {
                    (0.0, 0.0, 0.0, 0.0, false)
                } else {
                    let mean = entry.mean_ms;
                    // Population variance from Welford M2.
                    let variance = if entry.interval_count > 1 {
                        entry.m2_ms / entry.interval_count as f64
                    } else {
                        0.0
                    };
                    let std_dev = variance.sqrt();
                    let min = if entry.min_ms.is_finite() {
                        entry.min_ms
                    } else {
                        0.0
                    };
                    let max = if entry.max_ms.is_finite() {
                        entry.max_ms
                    } else {
                        0.0
                    };
                    let cv = if mean > 0.0 {
                        std_dev / mean
                    } else {
                        f64::INFINITY
                    };
                    let periodic = cv < 0.3 && entry.interval_count >= 5;
                    (mean, std_dev, min, max, periodic)
                };

            let packets_per_sec = if duration_secs > 0.0 {
                entry.packet_count as f64 / duration_secs
            } else {
                0.0
            };

            result.push(ConnectionStats {
                src_ip: src_ip.clone(),
                dst_ip: dst_ip.clone(),
                protocol: protocol.clone(),
                port: *port,
                packet_count: entry.packet_count,
                byte_count: entry.byte_count,
                first_seen: entry.first_seen,
                last_seen: entry.last_seen,
                duration_secs,
                avg_interval_ms,
                std_interval_ms,
                min_interval_ms,
                max_interval_ms,
                is_periodic,
                packets_per_sec,
            });
        }

        // Sort descending by packet count.
        result.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
        result
    }

    /// Detect communication pattern anomalies from computed stats.
    ///
    /// Checks for: one-off connections, high-frequency OT polling,
    /// irregular timing, and burst traffic.
    pub fn detect_anomalies(stats: &[ConnectionStats]) -> Vec<PatternAnomaly> {
        let mut anomalies = Vec::new();

        for s in stats {
            // OneOffConnection: single-packet — may be a scan or probe
            if s.packet_count == 1 {
                anomalies.push(PatternAnomaly {
                    anomaly_type: PatternAnomalyType::OneOffConnection,
                    src_ip: s.src_ip.clone(),
                    dst_ip: s.dst_ip.clone(),
                    port: s.port,
                    protocol: s.protocol.clone(),
                    description: format!(
                        "Single packet from {} to {}:{} ({}) — possible scan or probe",
                        s.src_ip, s.dst_ip, s.port, s.protocol
                    ),
                    severity: "low".to_string(),
                });
                continue; // Skip further checks — no timing data
            }

            let is_ot = is_ot_protocol(&s.protocol);

            // HighFrequency: >100 pps on OT protocols can overwhelm PLCs
            if is_ot && s.packets_per_sec > 100.0 {
                anomalies.push(PatternAnomaly {
                    anomaly_type: PatternAnomalyType::HighFrequency,
                    src_ip: s.src_ip.clone(),
                    dst_ip: s.dst_ip.clone(),
                    port: s.port,
                    protocol: s.protocol.clone(),
                    description: format!(
                        "{:.1} pkt/s on {} from {} to {}:{} — exceeds safe polling rate (>100 pps)",
                        s.packets_per_sec, s.protocol, s.src_ip, s.dst_ip, s.port
                    ),
                    severity: "high".to_string(),
                });
            }

            // IrregularPolling: OT connection with high timing variance (CV > 1.0)
            if is_ot && s.packet_count >= 10 && s.avg_interval_ms > 0.0 {
                let cv = s.std_interval_ms / s.avg_interval_ms;
                if cv > 1.0 {
                    anomalies.push(PatternAnomaly {
                        anomaly_type: PatternAnomalyType::IrregularPolling,
                        src_ip: s.src_ip.clone(),
                        dst_ip: s.dst_ip.clone(),
                        port: s.port,
                        protocol: s.protocol.clone(),
                        description: format!(
                            "Irregular {} polling from {} to {}:{}: CV={:.2} (avg={:.1}ms, std={:.1}ms)",
                            s.protocol, s.src_ip, s.dst_ip, s.port, cv,
                            s.avg_interval_ms, s.std_interval_ms
                        ),
                        severity: "medium".to_string(),
                    });
                }
            }

            // BurstTraffic: max gap >> average gap indicates bursty behavior
            if s.packet_count >= 10
                && s.avg_interval_ms > 0.0
                && s.max_interval_ms > 10.0 * s.avg_interval_ms
            {
                anomalies.push(PatternAnomaly {
                    anomaly_type: PatternAnomalyType::BurstTraffic,
                    src_ip: s.src_ip.clone(),
                    dst_ip: s.dst_ip.clone(),
                    port: s.port,
                    protocol: s.protocol.clone(),
                    description: format!(
                        "Burst traffic on {} from {} to {}:{}: max gap {:.1}ms vs avg {:.1}ms",
                        s.protocol,
                        s.src_ip,
                        s.dst_ip,
                        s.port,
                        s.max_interval_ms,
                        s.avg_interval_ms
                    ),
                    severity: "medium".to_string(),
                });
            }
        }

        anomalies
    }
}

impl Default for PatternAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns true if the protocol string identifies an OT/ICS protocol.
fn is_ot_protocol(protocol: &str) -> bool {
    matches!(
        protocol,
        "Modbus"
            | "Dnp3"
            | "EthernetIp"
            | "S7comm"
            | "Bacnet"
            | "OpcUa"
            | "Iec104"
            | "ProfinetDcp"
            | "HartIp"
            | "GeSrtp"
            | "WonderwareSuitelink"
            | "FfHse"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_analyzer() {
        let analyzer = PatternAnalyzer::new();
        let stats = analyzer.compute_stats();
        assert!(stats.is_empty());
        let anomalies = PatternAnalyzer::detect_anomalies(&stats);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_regular_intervals_is_periodic() {
        let mut analyzer = PatternAnalyzer::new();
        // 10 packets at precise 100 ms intervals → CV ≈ 0
        for i in 0..10_u32 {
            analyzer.record_packet(
                "192.168.1.1",
                "192.168.1.2",
                502,
                "Modbus",
                f64::from(i) * 0.1,
                100,
            );
        }
        let stats = analyzer.compute_stats();
        assert_eq!(stats.len(), 1);
        let s = &stats[0];
        assert!(
            s.is_periodic,
            "Expected is_periodic=true for regular intervals"
        );
        assert!(
            (s.avg_interval_ms - 100.0).abs() < 1.0,
            "Expected ~100ms avg interval"
        );
    }

    #[test]
    fn test_single_packet_one_off_anomaly() {
        let mut analyzer = PatternAnalyzer::new();
        analyzer.record_packet("10.0.0.1", "10.0.0.2", 502, "Modbus", 0.0, 64);
        let stats = analyzer.compute_stats();
        assert_eq!(stats[0].packet_count, 1);
        let anomalies = PatternAnalyzer::detect_anomalies(&stats);
        assert_eq!(anomalies.len(), 1);
        assert!(
            matches!(
                anomalies[0].anomaly_type,
                PatternAnomalyType::OneOffConnection
            ),
            "Expected OneOffConnection anomaly"
        );
    }

    #[test]
    fn test_high_frequency_ot_anomaly() {
        let mut analyzer = PatternAnalyzer::new();
        // 200 packets/sec on Modbus → should trigger HighFrequency (>100 pps)
        for i in 0..200_u32 {
            analyzer.record_packet(
                "192.168.1.10",
                "192.168.1.20",
                502,
                "Modbus",
                f64::from(i) * 0.005, // 5 ms apart = 200 pps
                60,
            );
        }
        let stats = analyzer.compute_stats();
        let anomalies = PatternAnalyzer::detect_anomalies(&stats);
        let has_hf = anomalies
            .iter()
            .any(|a| matches!(a.anomaly_type, PatternAnomalyType::HighFrequency));
        assert!(
            has_hf,
            "Expected HighFrequency anomaly at 200 pps on OT protocol"
        );
    }

    #[test]
    fn test_multiple_connections_independent_stats() {
        let mut analyzer = PatternAnalyzer::new();
        // Connection A: 5 packets to dst 10.0.0.2
        for i in 0..5_u32 {
            analyzer.record_packet(
                "10.0.0.1",
                "10.0.0.2",
                502,
                "Modbus",
                f64::from(i) * 0.1,
                100,
            );
        }
        // Connection B: 3 packets to dst 10.0.0.3 (different destination)
        for i in 0..3_u32 {
            analyzer.record_packet(
                "10.0.0.1",
                "10.0.0.3",
                502,
                "Modbus",
                f64::from(i) * 0.2,
                200,
            );
        }
        let stats = analyzer.compute_stats();
        assert_eq!(stats.len(), 2, "Expected 2 independent connection entries");

        let a = stats.iter().find(|s| s.dst_ip == "10.0.0.2").unwrap();
        let b = stats.iter().find(|s| s.dst_ip == "10.0.0.3").unwrap();
        assert_eq!(a.packet_count, 5);
        assert_eq!(b.packet_count, 3);
        assert_eq!(a.byte_count, 500);
        assert_eq!(b.byte_count, 600);
    }

    #[test]
    fn test_irregular_polling_anomaly() {
        let mut analyzer = PatternAnalyzer::new();
        // Bursts of packets separated by long silences — high CV
        let timestamps: &[f64] = &[
            0.0, 0.01, 0.02, // burst 1
            5.0, 5.01, 5.02, // burst 2 (5s gap)
            10.0, 10.01, 10.02, 10.03, // burst 3
        ];
        for (i, &ts) in timestamps.iter().enumerate() {
            analyzer.record_packet(
                "10.0.0.1",
                "10.0.0.2",
                502,
                "Modbus",
                ts,
                (i as u64 + 1) * 10,
            );
        }
        let stats = analyzer.compute_stats();
        let anomalies = PatternAnalyzer::detect_anomalies(&stats);
        let has_irregular = anomalies
            .iter()
            .any(|a| matches!(a.anomaly_type, PatternAnomalyType::IrregularPolling));
        assert!(
            has_irregular,
            "Expected IrregularPolling anomaly for bursty traffic"
        );
    }

    #[test]
    fn test_no_memory_growth_on_large_packet_count() {
        // Simulate 1M packets on a single connection — should not exhaust memory.
        let mut analyzer = PatternAnalyzer::new();
        for i in 0..1_000_000_u64 {
            analyzer.record_packet("10.0.0.1", "10.0.0.2", 502, "Modbus", i as f64 * 0.001, 60);
        }
        let stats = analyzer.compute_stats();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].packet_count, 1_000_000);
        // ~1ms average interval expected
        assert!((stats[0].avg_interval_ms - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_compute_stats_returns_all_connections() {
        // 600 distinct connection pairs — all must be returned.
        let mut analyzer = PatternAnalyzer::new();
        for i in 0..600_u32 {
            let dst = format!("10.0.{}.{}", i / 256, i % 256);
            // Give higher-numbered connections more packets so sort order is predictable.
            for j in 0..=i {
                analyzer.record_packet("10.1.0.1", &dst, 502, "Modbus", f64::from(j), 60);
            }
        }
        let stats = analyzer.compute_stats();
        assert_eq!(
            stats.len(),
            600,
            "compute_stats must return all connection pairs"
        );
        // Top entry should have the most packets (connection i=599 → 600 packets).
        assert_eq!(stats[0].packet_count, 600);
    }
}
