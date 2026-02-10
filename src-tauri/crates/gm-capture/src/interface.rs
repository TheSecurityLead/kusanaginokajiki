use serde::Serialize;
use crate::CaptureError;

/// Represents a network interface available for capture.
#[derive(Debug, Clone, Serialize)]
pub struct NetworkInterface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<InterfaceAddress>,
    pub flags: InterfaceFlags,
}

/// An address associated with a network interface.
#[derive(Debug, Clone, Serialize)]
pub struct InterfaceAddress {
    pub addr: String,
    pub netmask: Option<String>,
    pub broadcast: Option<String>,
}

/// Interface status flags.
#[derive(Debug, Clone, Serialize)]
pub struct InterfaceFlags {
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_running: bool,
}

/// List all available network interfaces on this system.
///
/// This is the first Rust function you'll see working — it wraps
/// libpcap's device enumeration and returns structured data to the frontend.
///
/// # Example
/// ```no_run
/// let interfaces = gm_capture::list_interfaces().unwrap();
/// for iface in &interfaces {
///     println!("{}: {:?}", iface.name, iface.addresses);
/// }
/// ```
pub fn list_interfaces() -> Result<Vec<NetworkInterface>, CaptureError> {
    let devices = pcap::Device::list()
        .map_err(|e| CaptureError::InterfaceList(e.to_string()))?;

    let interfaces = devices
        .into_iter()
        .map(|device| {
            let addresses = device
                .addresses
                .iter()
                .map(|addr| InterfaceAddress {
                    addr: addr.addr.to_string(),
                    netmask: addr.netmask.map(|a| a.to_string()),
                    broadcast: addr.broadcast_addr.map(|a| a.to_string()),
                })
                .collect();

            // pcap doesn't directly expose all flags, so we infer what we can
            let is_loopback = device.name.contains("lo")
                || device.name.contains("Loopback")
                || device.addresses.iter().any(|a| {
                    a.addr.to_string() == "127.0.0.1" || a.addr.to_string() == "::1"
                });

            NetworkInterface {
                name: device.name,
                description: device.desc,
                addresses,
                flags: InterfaceFlags {
                    is_up: true, // pcap only lists active devices
                    is_loopback,
                    is_running: true,
                },
            }
        })
        .collect();

    Ok(interfaces)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_interfaces() {
        // This test requires libpcap to be installed
        // It may need root/admin privileges depending on the OS
        match list_interfaces() {
            Ok(interfaces) => {
                println!("Found {} interfaces", interfaces.len());
                for iface in &interfaces {
                    println!("  {} - {:?}", iface.name, iface.flags);
                }
                // We should always have at least a loopback interface
                assert!(!interfaces.is_empty(), "Should find at least one interface");
            }
            Err(e) => {
                // Acceptable in CI environments without libpcap
                eprintln!("Could not list interfaces (expected in some environments): {}", e);
            }
        }
    }
}
