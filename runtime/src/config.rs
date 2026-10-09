use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use portal::{AllowedIp, PeerKey};
use zeroize::Zeroize;

/// Configuration for one foreground runtime instance.
pub struct RuntimeConfig {
    pub private_key: SecretKey,
    pub listen: SocketAddr,
    pub addresses: Vec<InterfaceAddress>,
    pub mtu: u32,
    pub workers: Option<usize>,
    pub handshake_rate_limit: Option<u64>,
    pub dual_stack: bool,
    pub api_listen: SocketAddr,
    pub api_token_file: PathBuf,
    pub peer_http_listen: Option<SocketAddr>,
    pub file_service: Option<portal_files::FileServiceConfig>,
}

/// Secret device key that is cleared from memory when its owner is dropped.
pub struct SecretKey(pub PeerKey);

impl Drop for SecretKey {
    // Erase the private key bytes when the owning configuration is discarded.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Virtual address and prefix owned by the userspace network.
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
    /// Format the address and prefix using the IP/PREFIX notation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

/// Load JSON startup settings. Relative paths are resolved beside the config file.
pub fn load_config(path: &std::path::Path) -> Result<RuntimeConfig, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    let settings: FileConfig = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid configuration {}: {e}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let resolve = |value: PathBuf| {
        if value.is_absolute() {
            value
        } else {
            base.join(value)
        }
    };
    let addresses = settings
        .addresses
        .iter()
        .map(|value| InterfaceAddress::parse(value))
        .collect::<Result<Vec<_>, _>>()?;
    if addresses.is_empty() || addresses.len() > 4 {
        return Err("addresses must contain 1-4 virtual addresses".into());
    }
    if !(1280..=9000).contains(&settings.mtu) {
        return Err("mtu must be between 1280 and 9000".into());
    }
    if !settings.api_listen.ip().is_loopback() {
        return Err("api_listen must use a loopback address".into());
    }
    let file_service = settings
        .files
        .map(|files| {
            if files.allowed_downloaders.is_empty() {
                return Err("files.allowed_downloaders must contain at least one IP".to_owned());
            }
            Ok(portal_files::FileServiceConfig {
                root: resolve(files.root),
                allowed_downloaders: files.allowed_downloaders,
            })
        })
        .transpose()?;
    if settings.peer_http_listen.is_some() != file_service.is_some() {
        return Err("peer_http_listen and files must be configured together".into());
    }
    let private_key = SecretKey(read_key_file(&resolve(settings.private_key_file))?);
    Ok(RuntimeConfig {
        private_key,
        listen: settings.listen,
        addresses,
        mtu: settings.mtu,
        workers: settings.workers,
        handshake_rate_limit: settings.handshake_rate_limit,
        dual_stack: settings.dual_stack,
        api_listen: settings.api_listen,
        api_token_file: settings
            .api_token_file
            .map(resolve)
            .unwrap_or_else(default_token_file),
        peer_http_listen: settings.peer_http_listen,
        file_service,
    })
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    private_key_file: PathBuf,
    listen: SocketAddr,
    addresses: Vec<String>,
    #[serde(default = "default_mtu")]
    mtu: u32,
    #[serde(default)]
    workers: Option<usize>,
    #[serde(default)]
    handshake_rate_limit: Option<u64>,
    #[serde(default = "default_dual_stack")]
    dual_stack: bool,
    #[serde(default = "default_api_listen")]
    api_listen: SocketAddr,
    #[serde(default)]
    api_token_file: Option<PathBuf>,
    #[serde(default)]
    peer_http_listen: Option<SocketAddr>,
    #[serde(default)]
    files: Option<FilesConfig>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesConfig {
    root: PathBuf,
    allowed_downloaders: std::collections::HashSet<IpAddr>,
}
fn default_mtu() -> u32 {
    1420
}
fn default_dual_stack() -> bool {
    true
}
fn default_api_listen() -> SocketAddr {
    "127.0.0.1:51821".parse().expect("constant address")
}
fn default_token_file() -> PathBuf {
    #[cfg(unix)]
    let name = format!("portal-{}.token", unsafe { libc::geteuid() });
    #[cfg(not(unix))]
    let name = "portal.token";
    std::env::temp_dir().join(name)
}

// Read a 32-byte raw or 64-character hexadecimal key, clearing the file buffer afterward.
fn read_key_file(path: &std::path::Path) -> Result<[u8; 32], String> {
    let mut bytes = std::fs::read(path)
        .map_err(|error| format!("could not read key file {}: {error}", path.display()))?;
    if bytes.len() == 32 {
        let key = bytes.as_slice().try_into().expect("length checked");
        bytes.zeroize();
        return Ok(key);
    }
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    let result = parse_key_hex(&bytes[start..end]);
    bytes.zeroize();
    result
}

// Decode an exact-length hexadecimal key and wipe partial output if a digit is invalid.
fn parse_key_hex(value: &[u8]) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("key must be exactly 64 hexadecimal characters".into());
    }
    let mut key = [0_u8; 32];
    for index in 0..key.len() {
        let offset = index * 2;
        let high = match hex_nibble(value[offset]) {
            Ok(nibble) => nibble,
            Err(error) => {
                key.zeroize();
                return Err(error);
            }
        };
        let low = match hex_nibble(value[offset + 1]) {
            Ok(nibble) => nibble,
            Err(error) => {
                key.zeroize();
                return Err(error);
            }
        };
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

// Convert one ASCII hexadecimal character to its four-bit value.
fn hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err("key contains a non-hexadecimal character".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_resolves_paths_and_rejects_invalid_settings() {
        let directory = std::env::temp_dir().join(format!(
            "portal-config-test-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("device.key"), [7_u8; 32]).unwrap();
        let path = directory.join("portal.json");
        let settings = serde_json::json!({
            "private_key_file": "device.key",
            "listen": "127.0.0.1:0",
            "addresses": ["10.20.0.1/32"],
            "api_token_file": "api.token",
            "peer_http_listen": "10.20.0.1:8080",
            "files": {"root": "share", "allowed_downloaders": ["10.20.0.2"]}
        });
        std::fs::write(&path, serde_json::to_vec(&settings).unwrap()).unwrap();
        let config = load_config(&path).unwrap();
        assert_eq!(config.private_key.0, [7; 32]);
        assert_eq!(config.api_token_file, directory.join("api.token"));
        assert_eq!(
            config.file_service.as_ref().unwrap().root,
            directory.join("share")
        );
        assert_eq!(config.mtu, 1420);
        assert!(config.dual_stack);
        for (field, value) in [
            ("unknown", serde_json::json!(true)),
            ("api_listen", serde_json::json!("0.0.0.0:51821")),
            ("mtu", serde_json::json!(9001)),
            ("addresses", serde_json::json!([])),
            ("files", serde_json::Value::Null),
        ] {
            let mut invalid = settings.clone();
            invalid[field] = value;
            std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(load_config(&path).is_err(), "accepted invalid {field}");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
