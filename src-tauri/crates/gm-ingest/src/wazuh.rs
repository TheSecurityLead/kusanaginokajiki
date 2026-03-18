//! Wazuh HIDS/SIEM alert parser.
//!
//! Parses Wazuh alert exports in two formats:
//! - Line-delimited JSON (one JSON object per line)
//! - JSON array (array of alert objects)
//!
//! Each alert is converted to an `IngestedAlert` for correlation with
//! the device inventory.

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::Value;

use crate::error::IngestError;
use crate::{IngestResult, IngestSource, IngestedAlert};

// ─── Raw Wazuh JSON structures ────────────────────────────────

#[derive(Debug, Deserialize)]
struct WazuhAlertRaw {
    timestamp: Option<String>,
    rule: Option<WazuhRule>,
    agent: Option<WazuhAgent>,
    data: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct WazuhRule {
    level: Option<u8>,
    description: Option<String>,
    id: Option<Value>, // can be string or number
    groups: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct WazuhAgent {
    ip: Option<String>,
    // name is parsed from JSON for completeness but not currently used
    #[allow(dead_code)]
    name: Option<String>,
}

// ─── Public API ───────────────────────────────────────────────

/// Parse a Wazuh alert export file.
///
/// Accepts both line-delimited JSON (one object per line) and a JSON array.
/// Alerts with no identifiable source IP are skipped.
pub fn parse_wazuh_alerts(path: &Path) -> Result<IngestResult, IngestError> {
    let content = fs::read_to_string(path).map_err(IngestError::Io)?;

    let mut alerts: Vec<IngestedAlert> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    // Try as JSON array first
    let trimmed = content.trim();
    if trimmed.starts_with('[') {
        match serde_json::from_str::<Vec<Value>>(trimmed) {
            Ok(array) => {
                for (i, val) in array.iter().enumerate() {
                    match serde_json::from_value::<WazuhAlertRaw>(val.clone()) {
                        Ok(raw) => {
                            if let Some(alert) = convert_wazuh_alert(raw) {
                                alerts.push(alert);
                            }
                        }
                        Err(e) => {
                            errors.push(format!("Array item {}: {}", i, e));
                        }
                    }
                }
            }
            Err(e) => {
                errors.push(format!("JSON array parse failed: {}", e));
            }
        }
    } else {
        // Try line-delimited JSON
        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<WazuhAlertRaw>(line) {
                Ok(raw) => {
                    if let Some(alert) = convert_wazuh_alert(raw) {
                        alerts.push(alert);
                    }
                }
                Err(e) => {
                    // Only record errors for lines that look like JSON objects
                    if line.starts_with('{') {
                        errors.push(format!("Line {}: {}", line_num + 1, e));
                    }
                }
            }
        }
    }

    Ok(IngestResult {
        source: Some(IngestSource::Wazuh),
        assets: Vec::new(),
        connections: Vec::new(),
        alerts,
        files_processed: 1,
        errors,
    })
}

// ─── Conversion ───────────────────────────────────────────────

/// Convert a raw Wazuh alert to an IngestedAlert.
/// Returns None if there's insufficient data (no rule, no identifiable IPs).
fn convert_wazuh_alert(raw: WazuhAlertRaw) -> Option<IngestedAlert> {
    let rule = raw.rule.as_ref()?;

    // Parse timestamp
    let timestamp = raw
        .timestamp
        .as_deref()
        .and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .ok()
                .map(|d| d.with_timezone(&Utc))
        })
        .unwrap_or_else(Utc::now);

    // Extract rule description and ID
    let signature = rule
        .description
        .clone()
        .unwrap_or_else(|| "Unknown Rule".to_string());
    let signature_id = rule
        .id
        .as_ref()
        .and_then(|v| match v {
            Value::Number(n) => n.as_u64(),
            Value::String(s) => s.parse::<u64>().ok(),
            _ => None,
        })
        .unwrap_or(0);

    // Category from rule groups
    let category = rule
        .groups
        .as_ref()
        .and_then(|g| g.first())
        .cloned()
        .unwrap_or_else(|| "wazuh".to_string());

    // Wazuh severity: 1-15 scale, map to 1-3 (matching Suricata: 1=high, 2=medium, 3=low)
    let level = rule.level.unwrap_or(0);
    let severity = if level >= 12 {
        1
    } else if level >= 7 {
        2
    } else {
        3
    };

    // Extract network data from the `data` field
    let (src_ip, dst_ip, src_port, dst_port) = extract_network_data(&raw.data, &raw.agent);

    // Require at least a source IP
    if src_ip.is_empty() {
        return None;
    }

    Some(IngestedAlert {
        timestamp,
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        signature_id,
        signature,
        category,
        severity,
        source: IngestSource::Wazuh,
    })
}

/// Extract src/dst IP and port from Wazuh `data` object.
///
/// Wazuh data fields vary by decoder:
/// - `srcip` / `dstip` — most network decoders
/// - `src_ip` / `dst_ip` — some custom decoders
/// - `srcport` / `dstport` — port fields (may be strings)
///
/// Falls back to `agent.ip` as src if no srcip found.
fn extract_network_data(
    data: &Option<Value>,
    agent: &Option<WazuhAgent>,
) -> (String, String, u16, u16) {
    let empty = serde_json::Value::Null;
    let data = data.as_ref().unwrap_or(&empty);

    // Helper to extract string fields from the data object
    let get_str = |key: &str| -> String {
        data.get(key)
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .unwrap_or_default()
    };

    let parse_port = |key: &str| -> u16 {
        let s = get_str(key);
        s.parse::<u16>().unwrap_or(0)
    };

    // Try various field name conventions
    let src_ip = {
        let v = get_str("srcip");
        if !v.is_empty() {
            v
        } else {
            let v = get_str("src_ip");
            if !v.is_empty() {
                v
            } else {
                // Fall back to agent.ip
                agent
                    .as_ref()
                    .and_then(|a| a.ip.clone())
                    .unwrap_or_default()
            }
        }
    };

    let dst_ip = {
        let v = get_str("dstip");
        if !v.is_empty() {
            v
        } else {
            get_str("dst_ip")
        }
    };

    let src_port = {
        let v = parse_port("srcport");
        if v != 0 {
            v
        } else {
            parse_port("src_port")
        }
    };

    let dst_port = {
        let v = parse_port("dstport");
        if v != 0 {
            v
        } else {
            parse_port("dst_port")
        }
    };

    (src_ip, dst_ip, src_port, dst_port)
}

// ─── Tests ────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempPath;

    #[test]
    fn test_parse_wazuh_line_delimited() {
        let json = r#"{"timestamp":"2024-01-15T10:30:00.000+0000","rule":{"level":10,"description":"Modbus write command","id":"100001","groups":["ics","modbus"]},"agent":{"id":"001","name":"ot-monitor","ip":"192.168.1.50"},"data":{"srcip":"10.0.0.5","dstip":"192.168.1.100","dstport":"502","srcport":"52341"}}"#;

        let tmp = tempfile_with_content(json);
        let result = parse_wazuh_alerts(tmp.as_ref()).unwrap();

        assert_eq!(result.alerts.len(), 1);
        let alert = &result.alerts[0];
        assert_eq!(alert.src_ip, "10.0.0.5");
        assert_eq!(alert.dst_ip, "192.168.1.100");
        assert_eq!(alert.dst_port, 502);
        assert_eq!(alert.src_port, 52341);
        assert_eq!(alert.severity, 2); // level 10 → medium (2)
        assert_eq!(alert.signature, "Modbus write command");
        assert_eq!(alert.signature_id, 100001);
        assert!(matches!(alert.source, IngestSource::Wazuh));
    }

    #[test]
    fn test_parse_wazuh_array_format() {
        let json = r#"[{"timestamp":"2024-01-15T10:30:00.000+0000","rule":{"level":14,"description":"Critical alert","id":"200001","groups":["attack"]},"agent":{"ip":"10.0.0.1"},"data":{"srcip":"10.0.0.1","dstip":"10.0.0.2","dstport":"102","srcport":"45000"}},{"timestamp":"2024-01-15T10:31:00.000+0000","rule":{"level":5,"description":"Low alert","id":"300001"},"agent":{"ip":"10.0.0.3"}}]"#;

        let tmp = tempfile_with_content(json);
        let result = parse_wazuh_alerts(tmp.as_ref()).unwrap();

        // Both alerts included: first has explicit srcip; second uses agent.ip as fallback
        assert_eq!(result.alerts.len(), 2);
        assert_eq!(result.alerts[0].severity, 1); // level 14 → high (1)
        assert_eq!(result.alerts[1].severity, 3); // level 5  → low  (3)
                                                  // Second alert's src_ip comes from agent.ip fallback
        assert_eq!(result.alerts[1].src_ip, "10.0.0.3");
    }

    #[test]
    fn test_agent_ip_fallback() {
        // When no srcip in data, agent.ip should be used as src_ip
        let json = r#"{"timestamp":"2024-01-15T10:30:00.000+0000","rule":{"level":7,"description":"Auth failure","id":"5503","groups":["authentication_failed"]},"agent":{"ip":"192.168.100.5","name":"server"},"data":{"dstip":"192.168.100.1","dstport":"22"}}"#;

        let tmp = tempfile_with_content(json);
        let result = parse_wazuh_alerts(tmp.as_ref()).unwrap();

        assert_eq!(result.alerts.len(), 1);
        assert_eq!(result.alerts[0].src_ip, "192.168.100.5"); // from agent.ip
        assert_eq!(result.alerts[0].dst_port, 22);
    }

    #[test]
    fn test_severity_mapping() {
        // level >= 12 → severity 1 (high)
        // level  7-11 → severity 2 (medium)
        // level  0-6  → severity 3 (low)
        let make_json = |level: u8| -> String {
            format!(
                r#"{{"timestamp":"2024-01-15T10:30:00.000Z","rule":{{"level":{level},"description":"Test","id":"1"}},"agent":{{"ip":"10.0.0.1"}},"data":{{"srcip":"10.0.0.1","dstip":"10.0.0.2"}}}}"#
            )
        };

        let tmp = tempfile_with_content(&make_json(15));
        assert_eq!(
            parse_wazuh_alerts(tmp.as_ref()).unwrap().alerts[0].severity,
            1
        );

        let tmp = tempfile_with_content(&make_json(9));
        assert_eq!(
            parse_wazuh_alerts(tmp.as_ref()).unwrap().alerts[0].severity,
            2
        );

        let tmp = tempfile_with_content(&make_json(3));
        assert_eq!(
            parse_wazuh_alerts(tmp.as_ref()).unwrap().alerts[0].severity,
            3
        );
    }

    /// Helper: write content to a temp file and return the tempfile handle.
    fn tempfile_with_content(content: &str) -> TempPath {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.into_temp_path()
    }
}
