use ipnet::{Ipv4Net, Ipv6Net};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub state_dir: PathBuf,
    #[serde(default = "default_v4")]
    pub ipv4_network: Ipv4Net,
    #[serde(default = "default_v6")]
    pub ipv6_network: Ipv6Net,
    #[serde(default = "default_lease")]
    pub lease_seconds: u64,
    pub tls: TlsConfig,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

fn default_v4() -> Ipv4Net {
    "10.77.0.0/16".parse().expect("constant network")
}
fn default_v6() -> Ipv6Net {
    "fd77:706f:7274::/64".parse().expect("constant network")
}
fn default_lease() -> u64 {
    300
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("could not read coordinator config: {e}"))?;
        let mut config: Self = serde_json::from_slice(&bytes)
            .map_err(|e| format!("invalid coordinator config: {e}"))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        if config.state_dir.is_relative() {
            config.state_dir = base.join(&config.state_dir);
        }
        if config.tls.cert_file.is_relative() {
            config.tls.cert_file = base.join(&config.tls.cert_file);
        }
        if config.tls.key_file.is_relative() {
            config.tls.key_file = base.join(&config.tls.key_file);
        }
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.tls.cert_file.as_os_str().is_empty() || self.tls.key_file.as_os_str().is_empty() {
            return Err("TLS certificate and key files are required".into());
        }
        if self.state_dir.as_os_str().is_empty() {
            return Err("state_dir is required".into());
        }
        if !(30..=3600).contains(&self.lease_seconds) {
            return Err("lease_seconds must be between 30 and 3600".into());
        }
        if !self.ipv4_network.network().is_private()
            || !self.ipv4_network.broadcast().is_private()
            || !(16..=30).contains(&self.ipv4_network.prefix_len())
            || self.ipv4_network.addr() != self.ipv4_network.network()
        {
            return Err("ipv4_network must be an aligned private /16 to /30 network".into());
        }
        if self.ipv6_network.network().segments()[0] & 0xfe00 != 0xfc00
            || self.ipv6_network.prefix_len() != 64
            || self.ipv6_network.addr() != self.ipv6_network.network()
        {
            return Err("ipv6_network must be an aligned ULA /64 network".into());
        }
        Ok(())
    }
}
