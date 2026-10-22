use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use portal::{AllowedIp, PeerKey};
use zeroize::Zeroize;

/// Configuration for one foreground runtime instance.
pub struct RuntimeConfig {
    pub coordinator: Option<ManagedConfig>,
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
}

/// Persistent managed-mode configuration. Relative paths resolve beside this file.
#[derive(Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedConfig {
    pub url: String,
    pub device_name: String,
    pub credential_file: PathBuf,
    pub policy_file: PathBuf,
    pub map_file: PathBuf,
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default)]
    pub endpoints: Vec<SocketAddr>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub tun_name: String,
    pub private_key_file: PathBuf,
    pub listen: SocketAddr,
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    pub workers: Option<usize>,
    pub handshake_rate_limit: Option<u64>,
    #[serde(default = "yes")]
    pub dual_stack: bool,
    #[serde(default = "yes")]
    pub auto_routes: bool,
    #[serde(default = "default_api")]
    pub api_listen: SocketAddr,
    pub api_token_file: PathBuf,
    pub coordinator: ManagedConfig,
}

fn default_mtu() -> u32 {
    1420
}
fn yes() -> bool {
    true
}
fn default_api() -> SocketAddr {
    "127.0.0.1:51821".parse().expect("constant address")
}

impl FileConfig {
    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let bytes =
            std::fs::read(path).map_err(|e| format!("could not read runtime config: {e}"))?;
        let mut config: Self =
            serde_json::from_slice(&bytes).map_err(|e| format!("invalid runtime config: {e}"))?;
        let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
        for value in [
            &mut config.private_key_file,
            &mut config.api_token_file,
            &mut config.coordinator.credential_file,
            &mut config.coordinator.policy_file,
            &mut config.coordinator.map_file,
        ] {
            if value.is_relative() {
                *value = base.join(&*value);
            }
        }
        if let Some(ca) = &mut config.coordinator.ca_file
            && ca.is_relative()
        {
            *ca = base.join(&*ca);
        }
        crate::validate_interface_name(&config.tun_name)?;
        if !(1280..=65535).contains(&config.mtu) || !config.api_listen.ip().is_loopback() {
            return Err("managed mode requires MTU 1280..65535 and a loopback local API".into());
        }
        if config.coordinator.device_name.trim().is_empty()
            || config.coordinator.device_name.len() > 128
            || config.coordinator.device_name.chars().any(char::is_control)
        {
            return Err("invalid device name".into());
        }
        portal_net::policy::validate_endpoints(&config.coordinator.endpoints)?;
        let mut files = std::collections::HashSet::new();
        for file in [
            &config.private_key_file,
            &config.api_token_file,
            &config.coordinator.credential_file,
            &config.coordinator.policy_file,
            &config.coordinator.map_file,
            &config.coordinator.credential_file.with_extension("lock"),
            &path.to_path_buf(),
        ] {
            let absolute = if file.is_absolute() {
                file.clone()
            } else {
                std::env::current_dir()
                    .map_err(|e| e.to_string())?
                    .join(file)
            };
            let mut normalized = PathBuf::new();
            for component in absolute.components() {
                match component {
                    std::path::Component::CurDir => {}
                    std::path::Component::ParentDir => {
                        normalized.pop();
                    }
                    other => normalized.push(other.as_os_str()),
                }
            }
            if !files.insert(normalized) {
                return Err("runtime configuration, keys, tokens, policy, map and lock must use distinct files".into());
            }
        }
        Ok(config)
    }

    pub fn into_runtime(self, private_key: SecretKey) -> RuntimeConfig {
        RuntimeConfig {
            coordinator: Some(self.coordinator),
            tun_name: self.tun_name,
            private_key,
            listen: self.listen,
            addresses: Vec::new(),
            mtu: self.mtu,
            workers: self.workers,
            handshake_rate_limit: self.handshake_rate_limit,
            dual_stack: self.dual_stack,
            auto_routes: self.auto_routes,
            api_listen: self.api_listen,
            api_token_file: self.api_token_file,
        }
    }
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
