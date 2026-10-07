use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use portal::{AllowedIp, PeerKey};
use zeroize::Zeroize;

/// Configuration for one foreground runtime instance.
pub struct RuntimeConfig {
    pub tun_name: String,
    pub private_key: SecretKey,
    pub listen: SocketAddr,
    pub addresses: Vec<InterfaceAddress>,
    pub mtu: u32,
    pub workers: Option<usize>,
    pub handshake_rate_limit: Option<u64>,
    pub dual_stack: bool,
    pub auto_routes: bool,
    pub api_listen: SocketAddr,
    pub api_token_file: PathBuf,
    pub grpc_listen: Option<SocketAddr>,
    pub file_service: Option<portal_files::FileServiceConfig>,
    pub smb: Option<SmbConfig>,
}

/// Secret device key that is cleared from memory when its owner is dropped.
pub struct SecretKey(pub PeerKey);

impl Drop for SecretKey {
    // Erase the private key bytes when the owning configuration is discarded.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Address and prefix assigned to the runtime's virtual interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl InterfaceAddress {
    /// Parse an interface address in `IP/PREFIX` notation and validate its prefix length.
    pub fn parse(value: &str) -> Result<Self, String> {
        let (address, prefix) = value
            .rsplit_once('/')
            .ok_or_else(|| format!("invalid interface address `{value}`; expected IP/PREFIX"))?;
        let address = address
            .parse::<IpAddr>()
            .map_err(|error| format!("invalid interface address `{value}`: {error}"))?;
        let prefix_len = prefix
            .parse::<u8>()
            .map_err(|error| format!("invalid interface prefix `{value}`: {error}"))?;
        AllowedIp::new(address, prefix_len)
            .map_err(|error| format!("invalid interface address `{value}`: {error}"))?;
        Ok(Self {
            address,
            prefix_len,
        })
    }
}

impl std::fmt::Display for InterfaceAddress {
    /// Format the address and prefix using the notation accepted by `iproute2`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

pub use portal_files::SmbConfig;
