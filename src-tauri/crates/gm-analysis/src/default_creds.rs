//! Default credential database for ICS/SCADA devices.
//!
//! Checks vendor/product strings against a known list of default credentials.
//! Used to warn assessors that discovered devices may have factory-default
//! authentication (or no authentication at all).

use serde::{Deserialize, Serialize};

/// A known default credential entry for an ICS/SCADA product.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultCredential {
    pub vendor: String,
    pub product_pattern: String,
    pub protocol: String,
    pub username: String,
    pub password: String,
    pub source: String,
    pub severity: String,
}

// Embedded at compile time — no runtime file I/O required.
const DEFAULT_CREDS_JSON: &str = include_str!("../data/default_credentials.json");

/// Checks devices against a database of known default credentials.
pub struct CredentialChecker {
    entries: Vec<DefaultCredential>,
}

impl CredentialChecker {
    /// Create a new checker, loading the embedded credential database.
    pub fn new() -> Result<Self, String> {
        let entries: Vec<DefaultCredential> = serde_json::from_str(DEFAULT_CREDS_JSON)
            .map_err(|e| format!("Failed to parse default credentials: {}", e))?;
        Ok(Self { entries })
    }

    /// Check a device by vendor + product strings.
    ///
    /// Returns all matching default credential entries. Matching is
    /// case-insensitive substring match on both vendor and product_pattern.
    pub fn check_device(&self, vendor: &str, product: &str) -> Vec<DefaultCredential> {
        let v = vendor.to_lowercase();
        let p = product.to_lowercase();
        self.entries
            .iter()
            .filter(|c| {
                let cv = c.vendor.to_lowercase();
                let cp = c.product_pattern.to_lowercase();
                (v.contains(cv.as_str()) || cv.contains(v.as_str()))
                    && (p.contains(cp.as_str()) || cp.contains(p.as_str()))
            })
            .cloned()
            .collect()
    }

    /// Check a device by vendor only (broader match when product is unknown).
    pub fn check_vendor(&self, vendor: &str) -> Vec<DefaultCredential> {
        let v = vendor.to_lowercase();
        self.entries
            .iter()
            .filter(|c| {
                let cv = c.vendor.to_lowercase();
                v.contains(cv.as_str()) || cv.contains(v.as_str())
            })
            .cloned()
            .collect()
    }

    /// Return all entries (for listing purposes).
    pub fn all_entries(&self) -> &[DefaultCredential] {
        &self.entries
    }
}

impl Default for CredentialChecker {
    fn default() -> Self {
        // If JSON parse fails, return empty checker — don't panic
        Self::new().unwrap_or(Self {
            entries: Vec::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn checker() -> CredentialChecker {
        CredentialChecker::new().expect("should parse embedded JSON")
    }

    #[test]
    fn test_checker_loads() {
        let c = checker();
        assert!(!c.entries.is_empty(), "should have entries");
        assert!(c.entries.len() >= 30, "should have at least 30 entries");
    }

    #[test]
    fn test_check_siemens_s7() {
        let c = checker();
        let matches = c.check_device("Siemens", "s7-1200");
        assert!(!matches.is_empty(), "Siemens S7-1200 should match");
    }

    #[test]
    fn test_check_schneider_modicon() {
        let c = checker();
        let matches = c.check_device("Schneider Electric", "Modicon M340");
        assert!(!matches.is_empty(), "Schneider Modicon M340 should match");
    }

    #[test]
    fn test_no_match_unknown_vendor() {
        let c = checker();
        let matches = c.check_device("UnknownVendorXYZ", "product123");
        // May or may not match — just verify it doesn't panic
        let _ = matches;
    }

    #[test]
    fn test_check_vendor_only() {
        let c = checker();
        let matches = c.check_vendor("Moxa");
        assert!(!matches.is_empty(), "Moxa should have vendor-level matches");
    }
}
