//! OT infrastructure CVE matching engine.
//!
//! Matches LLDP/SNMP-identified device information against a curated database
//! of known high-impact CVEs affecting OT networking equipment (SCALANCE,
//! Ruggedcom, Hirschmann, Moxa, Phoenix Contact).

use serde::{Deserialize, Serialize};

// ─── Internal Types ────────────────────────────────────────────────────────

/// Internal CVE entry from the embedded database.
#[derive(Debug, Clone, Deserialize)]
struct CveEntry {
    cve_id: String,
    cvss: f32,
    vendor: String,
    products: Vec<String>,
    description: String,
    advisory: String,
    remediation: String,
}

// ─── Public Types ──────────────────────────────────────────────────────────

/// A CVE match result for a discovered device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveMatch {
    /// CVE identifier (e.g. "CVE-2023-44317")
    pub cve_id: String,
    /// CVSS v3 base score
    pub cvss: f32,
    /// Brief description of the vulnerability
    pub description: String,
    /// ICS-CERT advisory or vendor advisory ID
    pub advisory: String,
    /// Recommended remediation steps
    pub remediation: String,
    /// Which product pattern from the database matched
    pub matched_product: String,
    /// Firmware version observed on the device (if available)
    pub matched_firmware: Option<String>,
    /// Match confidence: "high" = product + firmware, "medium" = product only, "low" = vendor only
    pub confidence: String,
    /// CVSS severity label: CRITICAL / HIGH / MEDIUM / LOW
    pub severity_label: String,
}

// ─── Embedded Database ────────────────────────────────────────────────────

const OT_INFRA_CVES: &str = include_str!("../data/ot_infra_cves.json");

// ─── Matcher ──────────────────────────────────────────────────────────────

/// Matches device vendor/model/firmware against the OT infrastructure CVE database.
pub struct CveMatcher {
    cves: Vec<CveEntry>,
}

impl CveMatcher {
    /// Load the embedded CVE database.
    pub fn new() -> Result<Self, String> {
        let cves: Vec<CveEntry> = serde_json::from_str(OT_INFRA_CVES)
            .map_err(|e| format!("Failed to parse OT CVE database: {e}"))?;
        Ok(Self { cves })
    }

    /// Check a device against the CVE database.
    ///
    /// All three parameters are case-insensitive substring matches.
    /// Returns matches sorted by CVSS score descending.
    ///
    /// - `vendor`: Vendor string from LLDP, SNMP sysDescr, or OUI lookup
    /// - `model`:  Model/product string from LLDP sysDescription or SNMP
    /// - `firmware`: Firmware version string if available (e.g. "V5.0.0")
    pub fn check_device(&self, vendor: &str, model: &str, firmware: Option<&str>) -> Vec<CveMatch> {
        let vendor_lower = vendor.to_lowercase();
        let model_lower = model.to_lowercase();

        let mut matches: Vec<CveMatch> = self
            .cves
            .iter()
            .filter_map(|cve| {
                let cve_vendor = cve.vendor.to_lowercase();

                // Vendor must match (bidirectional substring)
                if !vendor_lower.contains(cve_vendor.as_str())
                    && !cve_vendor.contains(vendor_lower.as_str())
                {
                    return None;
                }

                // Try to find a product pattern that matches the model string.
                // Skip product matching when model is empty to avoid matching every CVE.
                let matched_product = if model.is_empty() {
                    None
                } else {
                    cve.products.iter().find(|p| {
                        let p_lower = p.to_lowercase();
                        model_lower.contains(p_lower.as_str())
                            || p_lower.contains(model_lower.as_str())
                    })
                };

                let (confidence, matched_product_str) = match matched_product {
                    Some(prod) => {
                        if firmware.is_some() {
                            ("high".to_string(), prod.clone())
                        } else {
                            ("medium".to_string(), prod.clone())
                        }
                    }
                    None => {
                        // Vendor-only match: only include when no model string is present
                        if model.is_empty() {
                            ("low".to_string(), cve.vendor.clone())
                        } else {
                            return None;
                        }
                    }
                };

                Some(CveMatch {
                    cve_id: cve.cve_id.clone(),
                    cvss: cve.cvss,
                    description: cve.description.clone(),
                    advisory: cve.advisory.clone(),
                    remediation: cve.remediation.clone(),
                    matched_product: matched_product_str,
                    matched_firmware: firmware.map(|f| f.to_string()),
                    confidence,
                    severity_label: cvss_to_label(cve.cvss),
                })
            })
            .collect();

        // Sort by CVSS descending
        matches.sort_by(|a, b| {
            b.cvss
                .partial_cmp(&a.cvss)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        matches
    }
}

fn cvss_to_label(cvss: f32) -> String {
    if cvss >= 9.0 {
        "CRITICAL".to_string()
    } else if cvss >= 7.0 {
        "HIGH".to_string()
    } else if cvss >= 4.0 {
        "MEDIUM".to_string()
    } else {
        "LOW".to_string()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cve_database_loads() {
        let matcher = CveMatcher::new().expect("CVE database should parse");
        assert!(!matcher.cves.is_empty(), "CVE database should not be empty");
    }

    #[test]
    fn test_scalance_match_with_firmware() {
        let matcher = CveMatcher::new().unwrap();
        let matches = matcher.check_device("Siemens", "SCALANCE X-200", Some("V5.0.0"));
        assert!(!matches.is_empty(), "should match SCALANCE CVEs");
        assert!(matches.iter().any(|m| m.cve_id == "CVE-2023-44317"));
        // Firmware present → high confidence
        assert_eq!(matches[0].confidence, "high");
    }

    #[test]
    fn test_product_match_without_firmware() {
        let matcher = CveMatcher::new().unwrap();
        let matches = matcher.check_device("Moxa", "EDS-400A", None);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.cve_id == "CVE-2022-30767"));
        assert_eq!(matches[0].confidence, "medium");
    }

    #[test]
    fn test_no_match_unknown_vendor() {
        let matcher = CveMatcher::new().unwrap();
        let matches = matcher.check_device("Acme Corp", "XYZ-Switch", None);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_sorted_by_cvss_descending() {
        let matcher = CveMatcher::new().unwrap();
        let matches = matcher.check_device("Siemens", "SCALANCE X-200", Some("V5.0.0"));
        if matches.len() >= 2 {
            assert!(
                matches[0].cvss >= matches[1].cvss,
                "results should be sorted by CVSS"
            );
        }
    }

    #[test]
    fn test_vendor_only_match_empty_model() {
        let matcher = CveMatcher::new().unwrap();
        // When model is empty, fall back to vendor-only (low confidence)
        let matches = matcher.check_device("Siemens", "", None);
        // At least some vendor-only matches expected
        assert!(!matches.is_empty());
        assert!(matches.iter().all(|m| m.confidence == "low"));
    }

    #[test]
    fn test_hirschmann_match() {
        let matcher = CveMatcher::new().unwrap();
        let matches = matcher.check_device("Belden/Hirschmann", "HiOS V08", None);
        assert!(!matches.is_empty());
        assert!(matches.iter().any(|m| m.cve_id == "CVE-2023-34260"));
    }

    #[test]
    fn test_severity_labels() {
        assert_eq!(cvss_to_label(9.8), "CRITICAL");
        assert_eq!(cvss_to_label(7.5), "HIGH");
        assert_eq!(cvss_to_label(6.5), "MEDIUM");
        assert_eq!(cvss_to_label(3.0), "LOW");
    }
}
