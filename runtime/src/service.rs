use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::api::LocalApi;
use crate::api::ManagementRequest;
use crate::peer_services::PeerServices;
use crate::platform::{HostPlatform, LinuxPlatform};
use crate::{InterfaceAddress, RuntimeConfig, SecretKey};
use portal::{AllowedIp, Device, DeviceConfig, PeerConfig, PeerKey};
use zeroize::Zeroize;

const LOOP_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone)]
struct PeerRecord {
    endpoint: Option<SocketAddr>,
    keepalive: Option<Duration>,
    allowed_ips: Vec<AllowedIp>,
}

pub(crate) struct Runtime {
    device: Option<Device>,
    addresses: Vec<InterfaceAddress>,
    peers: HashMap<PeerKey, PeerRecord>,
    shutdown_requested: bool,
    network: Option<portal_net::Net>,
}

/// Create the WireGuard device, start its userspace stack, serve the local API, and clean up.
pub(crate) fn run_device(mut options: RuntimeConfig) -> Result<(), String> {
    for listener in options.peer_http_listen.into_iter() {
        if !options
            .addresses
            .iter()
            .any(|address| address.address == listener.ip())
        {
            return Err("peer HTTP listener must use an IP assigned to the tunnel".into());
        }
    }
    let platform: Arc<dyn HostPlatform> = Arc::new(LinuxPlatform);
    platform.install_signal_handlers();

    let mut device_config = DeviceConfig::new(options.private_key.0, options.listen);
    device_config.dual_stack = options.dual_stack;
    if let Some(workers) = options.workers {
        device_config.workers = workers;
    }
    if let Some(rate_limit) = options.handshake_rate_limit {
        device_config.handshake_rate_limit = rate_limit;
    }
    let device = match Device::new(device_config) {
        Ok(device) => device,
        Err(error) => return Err(error.to_string()),
    };
    options.private_key.0.zeroize();

    let network = match portal_net::Net::new(
        device.packet_port(),
        options
            .addresses
            .iter()
            .map(|address| (address.address, address.prefix_len))
            .collect(),
        options.mtu as usize,
    ) {
        Ok(network) => network,
        Err(error) => {
            let mut device = device;
            let _ = device.shutdown();
            return Err(error.to_string());
        }
    };
    let mut peer_services = match start_peer_services(
        network.clone(),
        options.peer_http_listen,
        options.file_service.take(),
    ) {
        Ok(services) => services,
        Err(error) => {
            network.shutdown();
            let mut device = device;
            let _ = device.shutdown();
            return Err(error);
        }
    };
    if let Some(services) = peer_services.as_ref() {
        println!("peer HTTP listening on {}", services.address());
    }

    let runtime = Runtime {
        device: Some(device),
        addresses: options.addresses,
        peers: HashMap::new(),
        shutdown_requested: false,
        network: Some(network.clone()),
    };
    let listen_address = runtime
        .device
        .as_ref()
        .expect("device was just created")
        .listen_addr();
    let public_key = encode_hex(
        &runtime
            .device
            .as_ref()
            .expect("device was just created")
            .public_key(),
    );
    let runtime = Arc::new(Mutex::new(runtime));
    let api = match LocalApi::start(
        options.api_listen,
        options.api_token_file.clone(),
        Arc::clone(&runtime),
        Some(network.clone()),
    ) {
        Ok(api) => api,
        Err(error) => {
            if let Some(services) = peer_services.take() {
                let _ = services.stop();
            }
            let cleanup = runtime
                .lock()
                .map_err(|_| "runtime state is unavailable during cleanup".to_owned())
                .and_then(|mut runtime| runtime.cleanup());
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(format!("{error}; cleanup failed: {cleanup_error}")),
            };
        }
    };

    println!(
        "READY net=userspace listen={} public_key={} api={} token_file={}",
        listen_address,
        public_key,
        api.local_addr(),
        options.api_token_file.display()
    );

    let mut serve_result = Ok(());
    loop {
        if platform.stop_requested() {
            break;
        }
        {
            let runtime = match runtime.lock() {
                Ok(runtime) => runtime,
                Err(_) => {
                    serve_result = Err("runtime state became unavailable".into());
                    break;
                }
            };
            if let Some(device) = runtime.device.as_ref()
                && let Err(error) = device.health()
            {
                serve_result = Err(format!("WireGuard device failed: {error}"));
                break;
            }
            if let Some(network) = &runtime.network
                && let Err(error) = network.health()
            {
                serve_result = Err(error.to_string());
                break;
            }
            if runtime.shutdown_requested {
                break;
            }
        }
        if api.has_exited() {
            serve_result = Err("local HTTP API exited unexpectedly".into());
            break;
        }
        if peer_services.as_ref().is_some_and(PeerServices::has_exited) {
            serve_result = match peer_services
                .take()
                .expect("peer server was present")
                .stop()
            {
                Ok(()) => Err("peer-facing HTTP or HTTP server exited unexpectedly".into()),
                Err(error) => Err(error),
            };
            break;
        }
        thread::sleep(LOOP_INTERVAL);
    }

    let api_result = api.stop();
    if serve_result.is_ok() {
        serve_result = api_result;
    }
    if let Some(services) = peer_services.take() {
        let peer_service_result = services.stop();
        if serve_result.is_ok() {
            serve_result = peer_service_result;
        }
    }

    let cleanup_result = runtime
        .lock()
        .map_err(|_| "runtime state became unavailable during cleanup".to_owned())
        .and_then(|mut runtime| runtime.cleanup());
    serve_result?;
    cleanup_result
}

/// Start the configured peer services or reject incomplete listener configuration.
fn start_peer_services(
    network: portal_net::Net,
    http_address: Option<SocketAddr>,
    file_service: Option<portal_files::FileServiceConfig>,
) -> Result<Option<PeerServices>, String> {
    if file_service.is_none() {
        return if http_address.is_none() {
            Ok(None)
        } else {
            Err("peer_http_listen requires at least one configured HTTP service".into())
        };
    }
    let address = http_address.ok_or("file sharing requires peer_http_listen")?;
    PeerServices::start(
        network,
        address,
        file_service.ok_or("file service configuration is required")?,
    )
    .map(Some)
}

impl Runtime {
    /// Resolve only a registered peer's exact tunnel host route, never a caller-supplied URL.
    pub(crate) fn file_peer_address(
        &self,
        public_key: &str,
        port: u16,
        tunnel_ip: Option<std::net::IpAddr>,
    ) -> Result<SocketAddr, String> {
        if port == 0 {
            return Err("peer HTTP port must be nonzero".into());
        }
        let key = parse_key_hex(public_key)?;
        let peer = self.peers.get(&key).ok_or("peer is not registered")?;
        let mut hosts: Vec<_> = peer
            .allowed_ips
            .iter()
            .filter(|prefix| {
                prefix.prefix_len() == if prefix.network().is_ipv4() { 32 } else { 128 }
                    && !prefix.network().is_loopback()
                    && !prefix.network().is_unspecified()
                    && !prefix.network().is_multicast()
                    && !self
                        .addresses
                        .iter()
                        .any(|address| address.address == prefix.network())
            })
            .map(|prefix| prefix.network())
            .collect();
        hosts.sort();
        hosts.dedup();
        let host = match tunnel_ip {
            Some(ip) if hosts.contains(&ip) => ip,
            Some(_) => {
                return Err(
                    "tunnel_ip must be an exact host AllowedIP assigned to this peer".into(),
                );
            }
            None if hosts.len() == 1 => hosts[0],
            None if hosts.is_empty() => {
                return Err("peer needs an exact tunnel host AllowedIP (/32 or /128)".into());
            }
            None => return Err("peer has multiple tunnel host addresses; specify tunnel_ip".into()),
        };
        Ok(SocketAddr::new(host, port))
    }

    /// Dispatch one authenticated JSON API operation to its Device or host-network operation.
    pub(crate) fn handle_api_request(
        &mut self,
        request: ManagementRequest,
    ) -> Result<String, String> {
        match request {
            ManagementRequest::PeerUpsert {
                public_key,
                preshared_key,
                endpoint,
                keepalive_seconds,
                allowed_ips,
            } => {
                let preshared_key = preshared_key
                    .map(|value| parse_key_hex(&value.0).map(SecretKey))
                    .transpose()?;
                let public_key = parse_key_hex(&public_key)?;
                let keepalive = keepalive_seconds
                    .map(|seconds| {
                        if seconds == 0 || seconds > u16::MAX as u64 {
                            return Err(String::from(
                                "keepalive must be between 1 and 65535 seconds",
                            ));
                        }
                        Ok(Duration::from_secs(seconds))
                    })
                    .transpose()?;
                let allowed_ips = allowed_ips
                    .into_iter()
                    .map(|value| {
                        value
                            .parse::<AllowedIp>()
                            .map_err(|error| format!("invalid allowed IP `{value}`: {error}"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.upsert_peer(public_key, preshared_key, endpoint, keepalive, allowed_ips)
            }
            ManagementRequest::PeerRemove { public_key } => {
                self.remove_peer(parse_key_hex(&public_key)?)
            }
            ManagementRequest::EndpointSet {
                public_key,
                endpoint,
            } => self.set_endpoint(parse_key_hex(&public_key)?, endpoint),
            ManagementRequest::EndpointClear { public_key } => {
                self.clear_endpoint(parse_key_hex(&public_key)?)
            }
            ManagementRequest::Stats => {
                let stats = self.device.as_ref().expect("running device").stats();
                Ok(format!(
                    "received_udp={} received_ip={} dropped={} timer_send_errors={} udp_send_errors={}",
                    stats.received_udp_packets,
                    stats.received_ip_packets,
                    stats.dropped_packets,
                    stats.timer_send_errors,
                    stats.udp_send_errors
                ))
            }
            ManagementRequest::PeerStats { public_key } => {
                let key = parse_key_hex(&public_key)?;
                let stats = self
                    .device
                    .as_ref()
                    .expect("running device")
                    .peer_stats(&key)
                    .map_err(|error| error.to_string())?;
                Ok(format!(
                    "peer={} tx_packets={} tx_bytes={} rx_packets={} rx_bytes={}",
                    encode_hex(&key),
                    stats.tx_packets,
                    stats.tx_bytes,
                    stats.rx_packets,
                    stats.rx_bytes
                ))
            }
            ManagementRequest::Health => {
                self.device
                    .as_ref()
                    .expect("running device")
                    .health()
                    .map_err(|error| error.to_string())?;
                Ok("healthy".into())
            }
            ManagementRequest::Status => {
                let device = self.device.as_ref().expect("running device");
                device.health().map_err(|error| error.to_string())?;
                Ok(format!(
                    "net=userspace listen={} public_key={} peers={}",
                    device.listen_addr(),
                    encode_hex(&device.public_key()),
                    self.peers.len()
                ))
            }
            ManagementRequest::List => {
                let mut peers = self
                    .peers
                    .iter()
                    .map(|(key, peer)| {
                        let ips = if peer.allowed_ips.is_empty() {
                            "-".to_owned()
                        } else {
                            peer.allowed_ips
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(",")
                        };
                        format!(
                            "{} endpoint={} keepalive={} allowed_ips={}",
                            encode_hex(key),
                            peer.endpoint
                                .map(|endpoint| endpoint.to_string())
                                .unwrap_or_else(|| "-".into()),
                            peer.keepalive
                                .map(|value| value.as_secs().to_string())
                                .unwrap_or_else(|| "-".into()),
                            ips
                        )
                    })
                    .collect::<Vec<_>>();
                peers.sort();
                Ok(if peers.is_empty() {
                    "no peers".into()
                } else {
                    peers.join("; ")
                })
            }
            ManagementRequest::Shutdown => {
                self.shutdown_requested = true;
                Ok("shutdown requested".into())
            }
        }
    }

    // Stage route changes, update Device and roll back newly added routes if the peer update fails.
    fn upsert_peer(
        &mut self,
        public_key: PeerKey,
        preshared_key: Option<SecretKey>,
        requested_endpoint: Option<SocketAddr>,
        keepalive: Option<Duration>,
        allowed_ips: Vec<AllowedIp>,
    ) -> Result<String, String> {
        let old_record = self.peers.get(&public_key).cloned();
        let record = PeerRecord {
            endpoint: requested_endpoint
                .or_else(|| old_record.as_ref().and_then(|peer| peer.endpoint)),
            keepalive,
            allowed_ips,
        };
        let mut staged = self.peers.clone();
        staged.insert(public_key, record.clone());
        let peer_config = PeerConfig {
            public_key,
            preshared_key: preshared_key.as_ref().map(|key| key.0),
            endpoint: requested_endpoint,
            persistent_keepalive: keepalive,
            allowed_ips: record.allowed_ips.clone(),
        };
        if let Err(error) = self
            .device
            .as_ref()
            .expect("running device")
            .upsert_peer(peer_config)
        {
            return Err(error.to_string());
        }

        self.peers = staged;
        Ok(format!("peer {} upserted", encode_hex(&public_key)))
    }

    // Remove a peer from Device and then release host routes no longer used by any peer.
    fn remove_peer(&mut self, public_key: PeerKey) -> Result<String, String> {
        self.device
            .as_ref()
            .expect("running device")
            .remove_peer(&public_key)
            .map_err(|error| error.to_string())?;
        self.peers.remove(&public_key);
        Ok(format!("peer {} removed", encode_hex(&public_key)))
    }

    // Change the endpoint of a peer currently tracked by this runtime.
    fn set_endpoint(
        &mut self,
        public_key: PeerKey,
        endpoint: SocketAddr,
    ) -> Result<String, String> {
        if !self.peers.contains_key(&public_key) {
            return Err("peer is not managed by this runtime".into());
        }
        self.device
            .as_ref()
            .expect("running device")
            .set_peer_endpoint(&public_key, endpoint)
            .map_err(|error| error.to_string())?;
        self.peers
            .get_mut(&public_key)
            .expect("peer checked")
            .endpoint = Some(endpoint);
        Ok(format!(
            "endpoint for {} set to {endpoint}",
            encode_hex(&public_key)
        ))
    }

    // Clear the configured endpoint for a tracked peer.
    fn clear_endpoint(&mut self, public_key: PeerKey) -> Result<String, String> {
        if !self.peers.contains_key(&public_key) {
            return Err("peer is not managed by this runtime".into());
        }
        self.device
            .as_ref()
            .expect("running device")
            .clear_peer_endpoint(&public_key)
            .map_err(|error| error.to_string())?;
        self.peers
            .get_mut(&public_key)
            .expect("peer checked")
            .endpoint = None;
        Ok(format!("endpoint for {} cleared", encode_hex(&public_key)))
    }

    // Stop the userspace stack and WireGuard workers.
    fn cleanup(&mut self) -> Result<(), String> {
        let mut errors = Vec::new();
        if let Some(network) = self.network.take() {
            network.shutdown();
        }
        if let Some(mut device) = self.device.take() {
            if let Err(error) = device.shutdown() {
                errors.push(format!("device shutdown failed: {error}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

// Decode a 64-character WireGuard key and clear the partially decoded bytes on failure.
fn parse_key_hex(value: &str) -> Result<PeerKey, String> {
    if value.len() != 64 {
        return Err("key must be exactly 64 hexadecimal characters".into());
    }
    let mut key = [0_u8; 32];
    for index in 0..key.len() {
        let offset = index * 2;
        let high = match hex_nibble(value.as_bytes()[offset]) {
            Ok(nibble) => nibble,
            Err(error) => {
                key.zeroize();
                return Err(error);
            }
        };
        let low = match hex_nibble(value.as_bytes()[offset + 1]) {
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

// Encode bytes as lowercase hexadecimal for local status and operation responses.
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
pub(crate) fn file_api_test_runtime(allowed_ips: Vec<AllowedIp>) -> Runtime {
    Runtime {
        device: None,
        addresses: Vec::new(),
        peers: HashMap::from([(
            [1; 32],
            PeerRecord {
                endpoint: None,
                keepalive: None,
                allowed_ips,
            },
        )]),
        shutdown_requested: false,
        network: None,
    }
}

#[cfg(test)]
mod file_api_tests {
    use super::*;
    #[test]
    fn file_targets_are_registered_exact_host_routes() {
        let key = encode_hex(&[1; 32]);
        let runtime = file_api_test_runtime(vec![
            "10.20.0.2/32".parse().unwrap(),
            "10.30.0.0/24".parse().unwrap(),
        ]);
        assert_eq!(
            runtime
                .file_peer_address(&key, 8080, None)
                .unwrap()
                .to_string(),
            "10.20.0.2:8080"
        );
        assert!(
            runtime
                .file_peer_address(&encode_hex(&[2; 32]), 8080, None)
                .is_err()
        );
        assert!(runtime.file_peer_address(&key, 0, None).is_err());
        assert!(
            runtime
                .file_peer_address(&key, 8080, Some("10.30.0.3".parse().unwrap()))
                .is_err()
        );
        let runtime = file_api_test_runtime(vec![
            "127.0.0.1/32".parse().unwrap(),
            "10.30.0.0/24".parse().unwrap(),
        ]);
        assert!(runtime.file_peer_address(&key, 8080, None).is_err());
        let runtime = file_api_test_runtime(vec![
            "10.20.0.2/32".parse().unwrap(),
            "fd00::2/128".parse().unwrap(),
        ]);
        assert!(runtime.file_peer_address(&key, 8080, None).is_err());
        assert_eq!(
            runtime
                .file_peer_address(&key, 8080, Some("fd00::2".parse().unwrap()))
                .unwrap()
                .to_string(),
            "[fd00::2]:8080"
        );
    }
}
