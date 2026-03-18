//! Protocol-specific vendor ID lookup tables.
//! CIP vendor IDs are assigned by ODVA for EtherNet/IP devices.
//! PROFINET vendor IDs are assigned by PI International.
//! BACnet vendor IDs are assigned by ASHRAE.

/// Look up CIP vendor name from ODVA-assigned vendor ID.
/// Used for EtherNet/IP ListIdentity and CIP Identity objects.
pub fn cip_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        1 => "Rockwell Automation/Allen-Bradley",
        2 => "Namco Controls",
        5 => "Rockwell Automation/Reliance Electric",
        9 => "Woodhead Software & Electronics",
        12 => "Siemens",
        13 => "Phoenix Contact",
        15 => "Wago",
        19 => "Turck",
        20 => "Omron",
        28 => "Schneider Electric",
        33 => "ABB",
        43 => "Bosch Rexroth",
        44 => "Parker Hannifin",
        48 => "Molex",
        49 => "HMS Networks (Anybus)",
        50 => "Eaton",
        58 => "Pepperl+Fuchs",
        60 => "Cognex",
        72 => "Danfoss",
        78 => "Beckhoff Automation",
        88 => "SEW-EURODRIVE",
        90 => "Pilz",
        100 => "Endress+Hauser",
        113 => "Balluff",
        119 => "Festo",
        283 => "ODVA",
        _ => "Unknown Vendor",
    }
}

/// Look up PROFINET vendor name from PI International assigned vendor ID.
/// Used for PROFINET DCP Identify responses.
pub fn profinet_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        0x002A => "Siemens",
        0x0019 => "Phoenix Contact",
        0x0109 => "Turck",
        0x0021 => "Wago",
        0x00B0 => "Pepperl+Fuchs",
        0x011E => "Beckhoff",
        0x000E => "ABB",
        0x015D => "Festo",
        0x001C => "Schneider Electric",
        0x014D => "Endress+Hauser",
        0x00DA => "Danfoss",
        0x004E => "Balluff",
        _ => "Unknown Vendor",
    }
}

/// Look up PROFINET device product name from vendor_id + device_id.
///
/// Currently covers Siemens SCALANCE product lines. Returns `None` if the
/// combination is not a known device.
pub fn profinet_device_name(vendor_id: u16, device_id: u16) -> Option<&'static str> {
    match (vendor_id, device_id) {
        // Siemens SCALANCE industrial network infrastructure
        (0x002A, 0x0203) => Some("Siemens SCALANCE X200 series"),
        (0x002A, 0x0204) => Some("Siemens SCALANCE X300 series"),
        (0x002A, 0x0207) => Some("Siemens SCALANCE X400 series"),
        (0x002A, 0x020B) => Some("Siemens SCALANCE XR500 series"),
        (0x002A, 0x0209) => Some("Siemens SCALANCE W700 series"),
        _ => None,
    }
}

/// Look up BACnet vendor name from ASHRAE-assigned vendor ID.
/// Used for BACnet I-Am broadcasts.
pub fn bacnet_vendor_name(vendor_id: u16) -> &'static str {
    match vendor_id {
        0 => "ASHRAE",
        2 => "The Trane Company",
        3 => "McQuay International",
        4 => "PolarSoft",
        5 => "Johnson Controls",
        7 => "Siemens Building Technologies",
        8 => "Delta Controls",
        10 => "Schneider Electric",
        15 => "TAC",
        24 => "Automated Logic",
        36 => "Honeywell",
        52 => "Reliable Controls",
        85 => "Carrier",
        86 => "Distech Controls",
        95 => "Alerton",
        171 => "KMC Controls",
        _ => "Unknown Vendor",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cip_known_vendors() {
        assert_eq!(cip_vendor_name(1), "Rockwell Automation/Allen-Bradley");
        assert_eq!(cip_vendor_name(28), "Schneider Electric");
        assert_eq!(cip_vendor_name(33), "ABB");
    }

    #[test]
    fn test_cip_unknown_vendor() {
        assert_eq!(cip_vendor_name(9999), "Unknown Vendor");
    }

    #[test]
    fn test_profinet_known_vendors() {
        assert_eq!(profinet_vendor_name(0x002A), "Siemens");
        assert_eq!(profinet_vendor_name(0x0019), "Phoenix Contact");
    }

    #[test]
    fn test_profinet_unknown_vendor() {
        assert_eq!(profinet_vendor_name(0xFFFF), "Unknown Vendor");
    }

    #[test]
    fn test_profinet_device_name_scalance() {
        assert_eq!(
            profinet_device_name(0x002A, 0x0203),
            Some("Siemens SCALANCE X200 series")
        );
        assert_eq!(
            profinet_device_name(0x002A, 0x020B),
            Some("Siemens SCALANCE XR500 series")
        );
        assert_eq!(
            profinet_device_name(0x002A, 0x0209),
            Some("Siemens SCALANCE W700 series")
        );
    }

    #[test]
    fn test_profinet_device_name_unknown() {
        assert_eq!(profinet_device_name(0x002A, 0xFFFF), None);
        assert_eq!(profinet_device_name(0x0019, 0x0001), None);
    }

    #[test]
    fn test_bacnet_known_vendors() {
        assert_eq!(bacnet_vendor_name(5), "Johnson Controls");
        assert_eq!(bacnet_vendor_name(36), "Honeywell");
    }

    #[test]
    fn test_bacnet_unknown_vendor() {
        assert_eq!(bacnet_vendor_name(9999), "Unknown Vendor");
    }
}
