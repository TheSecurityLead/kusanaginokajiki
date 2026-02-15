//! GeoIP country lookup using MaxMind/DB-IP MMDB format.

use std::net::IpAddr;
use std::path::Path;

use serde::Deserialize;

use crate::error::DbError;

/// GeoIP lookup using an MMDB database file.
pub struct GeoIpLookup {
    /// Reader is None if no MMDB file was loaded (graceful degradation).
    reader: Option<maxminddb::Reader<Vec<u8>>>,
}

/// Minimal structure for country lookup from MMDB.
#[derive(Deserialize)]
struct CountryRecord {
    country: Option<CountryField>,
}

#[derive(Deserialize)]
struct CountryField {
    iso_code: Option<String>,
}

impl GeoIpLookup {
    /// Load a GeoIP database from an MMDB file.
    pub fn load_from_file(path: &Path) -> Result<Self, DbError> {
        let reader = maxminddb::Reader::open_readfile(path)
            .map_err(|e| DbError::GeoIp(format!("Failed to open MMDB {}: {}", path.display(), e)))?;
        log::info!("Loaded GeoIP database from {}", path.display());
        Ok(Self {
            reader: Some(reader),
        })
    }

    /// Create a stub lookup that always returns None (when no MMDB file is available).
    pub fn empty() -> Self {
        Self { reader: None }
    }

    /// Check whether an IP address is a public (routable) address.
    ///
    /// Returns false for RFC 1918, RFC 6598 (CGNAT), loopback, link-local,
    /// multicast, and other private/special-use ranges.
    pub fn is_public_ip(ip_str: &str) -> bool {
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            return false;
        };

        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // 10.0.0.0/8
                if octets[0] == 10 {
                    return false;
                }
                // 172.16.0.0/12
                if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                    return false;
                }
                // 192.168.0.0/16
                if octets[0] == 192 && octets[1] == 168 {
                    return false;
                }
                // 100.64.0.0/10 (CGNAT / RFC 6598)
                if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                    return false;
                }
                // 127.0.0.0/8 (loopback)
                if octets[0] == 127 {
                    return false;
                }
                // 169.254.0.0/16 (link-local)
                if octets[0] == 169 && octets[1] == 254 {
                    return false;
                }
                // 0.0.0.0/8
                if octets[0] == 0 {
                    return false;
                }
                // 224.0.0.0/4 (multicast)
                if octets[0] >= 224 {
                    return false;
                }
                true
            }
            IpAddr::V6(v6) => {
                // ::1 loopback, :: unspecified, fe80::/10 link-local, fc00::/7 ULA
                if v6.is_loopback() || v6.is_unspecified() {
                    return false;
                }
                let segments = v6.segments();
                // fe80::/10 link-local
                if segments[0] & 0xffc0 == 0xfe80 {
                    return false;
                }
                // fc00::/7 unique local
                if segments[0] & 0xfe00 == 0xfc00 {
                    return false;
                }
                // ff00::/8 multicast
                if segments[0] & 0xff00 == 0xff00 {
                    return false;
                }
                true
            }
        }
    }

    /// Look up the ISO 3166-1 alpha-2 country code for an IP address.
    /// Only returns a result for public IPs.
    pub fn lookup_country(&self, ip_str: &str) -> Option<String> {
        if !Self::is_public_ip(ip_str) {
            return None;
        }

        let reader = self.reader.as_ref()?;
        let ip: IpAddr = ip_str.parse().ok()?;

        let record: CountryRecord = reader.lookup(ip).ok()?;
        record.country?.iso_code
    }

    /// Whether a GeoIP database is loaded.
    pub fn is_loaded(&self) -> bool {
        self.reader.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_ipv4() {
        assert!(!GeoIpLookup::is_public_ip("10.0.0.1"));
        assert!(!GeoIpLookup::is_public_ip("10.255.255.255"));
        assert!(!GeoIpLookup::is_public_ip("172.16.0.1"));
        assert!(!GeoIpLookup::is_public_ip("172.31.255.255"));
        assert!(!GeoIpLookup::is_public_ip("192.168.0.1"));
        assert!(!GeoIpLookup::is_public_ip("192.168.255.255"));
    }

    #[test]
    fn test_cgnat() {
        assert!(!GeoIpLookup::is_public_ip("100.64.0.1"));
        assert!(!GeoIpLookup::is_public_ip("100.127.255.255"));
        // 100.128.x.x is public
        assert!(GeoIpLookup::is_public_ip("100.128.0.1"));
    }

    #[test]
    fn test_loopback_and_link_local() {
        assert!(!GeoIpLookup::is_public_ip("127.0.0.1"));
        assert!(!GeoIpLookup::is_public_ip("169.254.1.1"));
        assert!(!GeoIpLookup::is_public_ip("0.0.0.0"));
    }

    #[test]
    fn test_multicast() {
        assert!(!GeoIpLookup::is_public_ip("224.0.0.1"));
        assert!(!GeoIpLookup::is_public_ip("239.255.255.255"));
        assert!(!GeoIpLookup::is_public_ip("255.255.255.255"));
    }

    #[test]
    fn test_public_ipv4() {
        assert!(GeoIpLookup::is_public_ip("8.8.8.8"));
        assert!(GeoIpLookup::is_public_ip("1.1.1.1"));
        assert!(GeoIpLookup::is_public_ip("203.0.113.1"));
    }

    #[test]
    fn test_empty_stub() {
        let lookup = GeoIpLookup::empty();
        assert!(!lookup.is_loaded());
        assert_eq!(lookup.lookup_country("8.8.8.8"), None);
    }

    #[test]
    fn test_private_ip_no_country() {
        let lookup = GeoIpLookup::empty();
        assert_eq!(lookup.lookup_country("192.168.1.1"), None);
    }

    #[test]
    fn test_invalid_ip() {
        assert!(!GeoIpLookup::is_public_ip("not-an-ip"));
        assert!(!GeoIpLookup::is_public_ip(""));
    }
}
