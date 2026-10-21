use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

pub struct RuntimeConfig {
    pub config_path: Option<PathBuf>,
    pub private_key: SecretKey,
    pub listen: Option<SocketAddr>,
    pub relays: Vec<portal_net::RelayPeer>,
    pub relay_server: Option<crate::RelayServerConfig>,
    pub api_listen: SocketAddr,
    pub api_token_file: PathBuf,
    pub services: Vec<crate::ServiceRegistration>,
}
pub struct SecretKey(pub [u8; 32]);
impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    private_key_file: PathBuf,
    listen: Option<SocketAddr>,
    #[serde(default)]
    relays: Vec<portal_net::RelayPeer>,
    #[serde(default)]
    relay_server: Option<crate::RelayServerConfig>,
    #[serde(default = "default_api_listen")]
    api_listen: SocketAddr,
    #[serde(default)]
    api_token_file: Option<PathBuf>,
    #[serde(default)]
    services: Vec<ServiceConfig>,
}
#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ServiceConfig {
    Files {
        root: PathBuf,
        allowed_downloaders: Vec<String>,
    },
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
fn read_settings(path: &Path) -> Result<FileConfig, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("could not read {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid configuration {}: {e}", path.display()))
}
fn resolve(base: &Path, value: PathBuf) -> PathBuf {
    if value.is_absolute() {
        value
    } else {
        base.join(value)
    }
}
fn build_services(
    configs: Vec<ServiceConfig>,
    base: &Path,
) -> Result<Vec<crate::ServiceRegistration>, String> {
    let mut services = Vec::new();
    for config in configs {
        match config {
            ServiceConfig::Files {
                root,
                allowed_downloaders,
            } => {
                let allowed_downloaders = allowed_downloaders
                    .iter()
                    .map(|key| portal_net::parse_key(key))
                    .collect::<Result<std::collections::HashSet<_>, _>>()?;
                if allowed_downloaders.is_empty() {
                    return Err("files.allowed_downloaders must contain reader public keys".into());
                }
                services.push(crate::ServiceRegistration::files(
                    portal_files::FileServiceConfig {
                        root: resolve(base, root),
                        allowed_downloaders,
                    },
                ));
            }
        }
    }
    Ok(services)
}
pub fn load_config(path: &Path) -> Result<RuntimeConfig, String> {
    let path = std::fs::canonicalize(path)
        .map_err(|e| format!("could not resolve configuration {}: {e}", path.display()))?;
    let settings = read_settings(&path)?;
    let base = path.parent().expect("absolute path");
    if !settings.api_listen.ip().is_loopback() {
        return Err("api_listen must use loopback".into());
    }
    let private_key = SecretKey(read_key_file(&resolve(base, settings.private_key_file))?);
    let services = build_services(settings.services, base)?;
    let relay_server = settings.relay_server;
    if let Some(server) = &relay_server {
        server.validate()?;
    }
    let relays = settings.relays;
    for relay in &relays {
        relay.validate()?;
    }
    if settings.listen.is_none() && relays.is_empty() && relay_server.is_none() {
        return Err("listen or at least one relay is required".into());
    }
    Ok(RuntimeConfig {
        config_path: Some(path.clone()),
        private_key,
        listen: settings.listen,
        relays,
        relay_server,
        api_listen: settings.api_listen,
        api_token_file: settings
            .api_token_file
            .map(|path| resolve(base, path))
            .unwrap_or_else(default_token_file),
        services,
    })
}
pub(crate) fn load_services(path: &Path) -> Result<Vec<crate::ServiceRegistration>, String> {
    build_services(
        read_settings(path)?.services,
        path.parent().unwrap_or_else(|| Path::new(".")),
    )
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
    fn config_uses_peer_keys_and_relative_paths() {
        let directory = std::env::temp_dir().join(format!(
            "portal-quic-config-{:032x}",
            rand::random::<u128>()
        ));
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("device.key"), [7; 32]).unwrap();
        let path = directory.join("portal.json");
        let valid = serde_json::json!({"private_key_file":"device.key", "listen":"127.0.0.1:0", "api_token_file":"api.token", "services": [{"type":"files", "root":"share", "allowed_downloaders":[portal_net::encode_key(&portal_net::public_key(&[8;32]))]}]});
        std::fs::write(&path, serde_json::to_vec(&valid).unwrap()).unwrap();
        let config = load_config(&path).unwrap();
        assert_eq!(config.private_key.0, [7; 32]);
        assert_eq!(config.api_token_file, directory.join("api.token"));
        assert_eq!(config.services.len(), 1);
        let mut relay_only = valid.clone();
        relay_only["listen"] = serde_json::Value::Null;
        relay_only["relays"] = serde_json::json!([{"public_key":portal_net::encode_key(&portal_net::public_key(&[9;32])), "endpoint":"127.0.0.1:40000"}]);
        std::fs::write(&path, serde_json::to_vec(&relay_only).unwrap()).unwrap();
        let config = load_config(&path).unwrap();
        assert!(config.listen.is_none());
        assert_eq!(config.relays.len(), 1);
        for (field, value) in [
            ("addresses", serde_json::json!(["10.20.0.1/32"])),
            ("api_listen", serde_json::json!("0.0.0.0:51821")),
            ("listen", serde_json::Value::Null),
            ("relays", serde_json::json!(["file:///tmp/relay"])),
            ("relays", serde_json::json!(["http://relay.example.com"])),
            (
                "services",
                serde_json::json!([{ "type":"files", "root":"share", "allowed_downloaders":["127.0.0.1"] }]),
            ),
        ] {
            let mut invalid = valid.clone();
            invalid[field] = value;
            std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
            assert!(load_config(&path).is_err(), "accepted invalid {field}");
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
