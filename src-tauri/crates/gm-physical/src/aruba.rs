//! HP/Aruba parser stubs.
//!
//! Not yet implemented. Planned for multi-vendor support.
//! Will parse: `show running-config`, `show mac-address`,
//! `show lldp info remote-device`, `show arp`.

use crate::PhysicalError;

/// Parse HP/Aruba switch configuration.
///
/// **Not yet implemented.** Returns an error indicating unsupported vendor.
pub fn parse_aruba_config(_content: &str) -> Result<(), PhysicalError> {
    Err(PhysicalError::UnsupportedVendor(
        "HP/Aruba parsing is not yet implemented".to_string(),
    ))
}
