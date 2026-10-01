use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use zeroize::Zeroize;

/// A WireGuard key in its raw 32-byte representation.
pub type PeerKey = [u8; 32];

/// A canonical IPv4 or IPv6 network prefix.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AllowedIp {
    network: IpAddr,
    prefix_len: u8,
}

impl AllowedIp {
    /// Create a prefix and normalize host bits to zero.
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self, AllowedIpParseError> {
        let network = match network {
            IpAddr::V4(address) if prefix_len <= 32 => {
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_len)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) if prefix_len <= 128 => {
                let mask = if prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix_len)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
            _ => return Err(AllowedIpParseError),
        };
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Return the canonical network address of this prefix.
    pub fn network(self) -> IpAddr {
        self.network
    }

    /// Return the number of significant prefix bits.
    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    /// Check whether an address belongs to this IPv4 or IPv6 prefix.
    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                u32::from(network) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix_len == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                u128::from(network) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for AllowedIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix_len)
    }
}

impl FromStr for AllowedIp {
    type Err = AllowedIpParseError;

    /// Parse an address/prefix pair and normalize its host bits.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or(AllowedIpParseError)?;
        let address = address.parse::<IpAddr>().map_err(|_| AllowedIpParseError)?;
        let prefix = prefix.parse::<u8>().map_err(|_| AllowedIpParseError)?;
        Self::new(address, prefix)
    }
}

/// Invalid address/prefix pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllowedIpParseError;

impl fmt::Display for AllowedIpParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected an IPv4 or IPv6 prefix such as 10.0.0.0/24")
    }
}

impl std::error::Error for AllowedIpParseError {}

impl Drop for super::DeviceConfig {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}
