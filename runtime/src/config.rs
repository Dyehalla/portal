use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use portal::{AllowedIp, PeerKey};
use zeroize::Zeroize;

/// Shared defaults for the CLI and file-based startup configuration.
pub mod defaults {
    pub const CONFIG_FILE: &str = "/etc/portal/runtime.json";
    pub const TUN_NAME: &str = "portal0";
    pub const PRIVATE_KEY_FILE: &str = "/etc/portal/device.key";
    pub const LISTEN: &str = "0.0.0.0:51820";
    pub const MTU: u32 = 1420;
    pub const DUAL_STACK: bool = true;
    pub const AUTO_ROUTES: bool = true;
    pub const API_LISTEN: &str = "127.0.0.1:51821";
    pub const API_TOKEN_FILE: &str = "/run/portal.token";
    pub const USER_TOKEN_FILE: &str = "/etc/portal/user.token";
    pub const COORDINATOR_URL: &str = "https://localhost:8443";
    pub const DEVICE_NAME: &str = "my-device";
    pub const CREDENTIAL_FILE: &str = "/etc/portal/device.json";
    pub const POLICY_FILE: &str = "/etc/portal/policy.json";
    pub const MAP_FILE: &str = "/etc/portal/network-map.json";
}

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
#[serde(default, deny_unknown_fields)]
pub struct ManagedConfig {
    pub url: String,
    pub device_name: String,
    pub credential_file: PathBuf,
    pub policy_file: PathBuf,
    pub map_file: PathBuf,
    pub ca_file: Option<PathBuf>,
    pub endpoints: Vec<SocketAddr>,
}

impl Default for ManagedConfig {
    fn default() -> Self {
        Self {
            url: defaults::COORDINATOR_URL.into(),
            device_name: defaults::DEVICE_NAME.into(),
            credential_file: defaults::CREDENTIAL_FILE.into(),
            policy_file: defaults::POLICY_FILE.into(),
            map_file: defaults::MAP_FILE.into(),
            ca_file: None,
            endpoints: Vec::new(),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileConfig {
    pub tun_name: String,
    pub private_key_file: PathBuf,
    pub listen: SocketAddr,
    pub mtu: u32,
    pub workers: Option<usize>,
    pub handshake_rate_limit: Option<u64>,
    pub dual_stack: bool,
    pub auto_routes: bool,
    pub api_listen: SocketAddr,
    pub api_token_file: PathBuf,
    pub coordinator: ManagedConfig,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            tun_name: defaults::TUN_NAME.into(),
            private_key_file: defaults::PRIVATE_KEY_FILE.into(),
            listen: defaults::LISTEN.parse().expect("constant socket address"),
            mtu: defaults::MTU,
            // Device supplies CPU-dependent worker count and its handshake limit.
            workers: None,
            handshake_rate_limit: None,
            dual_stack: defaults::DUAL_STACK,
            auto_routes: defaults::AUTO_ROUTES,
            api_listen: defaults::API_LISTEN
                .parse()
                .expect("constant socket address"),
            api_token_file: defaults::API_TOKEN_FILE.into(),
            coordinator: ManagedConfig::default(),
        }
    }
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
        if config.workers.is_some_and(|n| n == 0 || n > 256) {
            return Err("workers must be between 1 and 256".into());
        }
        if config.handshake_rate_limit == Some(0) {
            return Err("handshake_rate_limit must be greater than zero".into());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_partial_json_keep_shared_defaults_and_explicit_values() {
        let empty: FileConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(empty.tun_name, defaults::TUN_NAME);
        assert_eq!(
            empty.private_key_file,
            PathBuf::from(defaults::PRIVATE_KEY_FILE)
        );
        assert_eq!(empty.listen.to_string(), defaults::LISTEN);
        assert_eq!(empty.api_listen.to_string(), defaults::API_LISTEN);
        assert_eq!(
            empty.api_token_file,
            PathBuf::from(defaults::API_TOKEN_FILE)
        );
        assert_eq!(empty.mtu, defaults::MTU);
        assert!(empty.dual_stack && empty.auto_routes);
        assert!(empty.workers.is_none() && empty.handshake_rate_limit.is_none());
        assert_eq!(empty.coordinator.url, defaults::COORDINATOR_URL);
        assert!(empty.coordinator.endpoints.is_empty() && empty.coordinator.ca_file.is_none());
        let partial: FileConfig = serde_json::from_str(r#"{"tun_name":"test0","dual_stack":false,"coordinator":{"url":"https://example.test:9443"}}"#).unwrap();
        assert_eq!(partial.tun_name, "test0");
        assert!(!partial.dual_stack);
        assert_eq!(partial.listen, empty.listen);
        assert_eq!(partial.coordinator.url, "https://example.test:9443");
        assert_eq!(
            partial.coordinator.policy_file,
            empty.coordinator.policy_file
        );
    }

    #[test]
    fn load_resolves_explicit_relative_paths_without_replacing_defaults_or_accepting_typos() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("runtime.json");
        std::fs::write(
            &path,
            r#"{"private_key_file":"state/key","coordinator":{"policy_file":"state/policy.json"}}"#,
        )
        .unwrap();
        let config = FileConfig::load(&path).unwrap();
        assert_eq!(config.private_key_file, directory.path().join("state/key"));
        assert_eq!(
            config.coordinator.policy_file,
            directory.path().join("state/policy.json")
        );
        assert_eq!(
            config.api_token_file,
            PathBuf::from(defaults::API_TOKEN_FILE)
        );
        for invalid in [
            r#"{"worker":1}"#,
            r#"{"coordinator":{"urll":"https://example.test"}}"#,
            r#"{"workers":0}"#,
            r#"{"handshake_rate_limit":0}"#,
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(FileConfig::load(&path).is_err());
        }
    }
}
