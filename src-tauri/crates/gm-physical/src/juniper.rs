//! Juniper JunOS parser stubs.
//!
//! Not yet implemented. Planned for multi-vendor support.
//! Will parse: `show configuration`, `show ethernet-switching table`,
//! `show lldp neighbors`, `show arp`.

use crate::PhysicalError;

/// Parse Juniper JunOS configuration.
///
/// **Not yet implemented.** Returns an error indicating unsupported vendor.
pub fn parse_junos_config(_content: &str) -> Result<(), PhysicalError> {
    Err(PhysicalError::UnsupportedVendor(
        "Juniper JunOS parsing is not yet implemented".to_string(),
    ))
}
