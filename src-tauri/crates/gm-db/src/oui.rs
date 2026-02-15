//! IEEE OUI (MAC address prefix) vendor lookup.
//!
//! Loads a TSV file mapping 3-byte MAC prefixes to vendor names.
//! Format: `AA:BB:CC\tVendor Name` per line.

use std::collections::HashMap;
use std::path::Path;

use crate::error::DbError;

/// In-memory OUI lookup table.
pub struct OuiLookup {
    /// Maps normalized OUI prefix (lowercase "aa:bb:cc") to vendor name.
    table: HashMap<String, String>,
}

impl OuiLookup {
    /// Load the OUI database from a TSV file.
    ///
    /// Each line should be: `AA:BB:CC\tVendor Name`
    /// Lines starting with `#` or empty lines are skipped.
    pub fn load_from_file(path: &Path) -> Result<Self, DbError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DbError::Oui(format!("Failed to read OUI file {}: {}", path.display(), e)))?;

        let mut table = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((prefix, vendor)) = line.split_once('\t') {
                let normalized = prefix.trim().to_lowercase();
                table.insert(normalized, vendor.trim().to_string());
            }
        }

        log::info!("Loaded {} OUI entries from {}", table.len(), path.display());
        Ok(Self { table })
    }

    /// Create an empty lookup (when no OUI file is available).
    pub fn empty() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    /// Look up a vendor name by MAC address.
    ///
    /// Extracts the first 8 characters (OUI prefix: "aa:bb:cc") from the MAC,
    /// normalizes to lowercase, and looks up in the table.
    pub fn lookup(&self, mac: &str) -> Option<&str> {
        if mac.len() < 8 {
            return None;
        }
        let prefix = mac[..8].to_lowercase();
        self.table.get(&prefix).map(|s| s.as_str())
    }

    /// Number of entries loaded.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether the lookup table is empty.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn create_temp_oui() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "# OUI Database").unwrap();
        writeln!(file, "00:0E:8C\tSiemens AG").unwrap();
        writeln!(file, "00:00:BC\tRockwell Automation").unwrap();
        writeln!(file, "00:80:F4\tSchneider Electric").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "# Another comment").unwrap();
        writeln!(file, "00:1D:9C\tRockwell Automation").unwrap();
        file
    }

    #[test]
    fn test_load_and_lookup() {
        let file = create_temp_oui();
        let lookup = OuiLookup::load_from_file(file.path()).unwrap();
        assert_eq!(lookup.len(), 4);

        assert_eq!(lookup.lookup("00:0e:8c:01:02:03"), Some("Siemens AG"));
        assert_eq!(lookup.lookup("00:00:BC:11:22:33"), Some("Rockwell Automation"));
        assert_eq!(lookup.lookup("00:80:f4:aa:bb:cc"), Some("Schneider Electric"));
    }

    #[test]
    fn test_unknown_mac() {
        let file = create_temp_oui();
        let lookup = OuiLookup::load_from_file(file.path()).unwrap();
        assert_eq!(lookup.lookup("ff:ff:ff:ff:ff:ff"), None);
    }

    #[test]
    fn test_case_insensitive() {
        let file = create_temp_oui();
        let lookup = OuiLookup::load_from_file(file.path()).unwrap();
        // The TSV has uppercase but lookup normalizes to lowercase
        assert_eq!(lookup.lookup("00:0E:8C:01:02:03"), Some("Siemens AG"));
        assert_eq!(lookup.lookup("00:0e:8c:01:02:03"), Some("Siemens AG"));
    }

    #[test]
    fn test_short_mac() {
        let file = create_temp_oui();
        let lookup = OuiLookup::load_from_file(file.path()).unwrap();
        assert_eq!(lookup.lookup("00:0E"), None);
    }

    #[test]
    fn test_empty_lookup() {
        let lookup = OuiLookup::empty();
        assert!(lookup.is_empty());
        assert_eq!(lookup.lookup("00:0e:8c:01:02:03"), None);
    }
}
