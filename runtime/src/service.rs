use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

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
    tun_name: String,
    addresses: Vec<InterfaceAddress>,
    link_up: bool,
    auto_routes: bool,
    peers: HashMap<PeerKey, PeerRecord>,
    routes: HashMap<AllowedIp, bool>,
    shutdown_requested: bool,
    platform: Arc<dyn HostPlatform>,
}

/// Create the WireGuard device, configure its host interface, serve local commands, and clean up.
pub(crate) fn run_device(mut options: RuntimeConfig) -> Result<(), String> {
    let platform: Arc<dyn HostPlatform> = Arc::new(LinuxPlatform);
    platform.install_signal_handlers();
    platform.ensure_interface_absent(&options.tun_name)?;

    let mut device_config = DeviceConfig::new(
        options.private_key.0,
        options.listen,
        options.tun_name.clone(),
    );
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

    let mut configured_addresses = Vec::new();
    let mut link_up = false;
    let setup_result = (|| {
        platform.set_mtu(&options.tun_name, options.mtu)?;
        for address in &options.addresses {
            platform.add_interface_address(&options.tun_name, *address)?;
            configured_addresses.push(*address);
        }
        platform.set_interface_up(&options.tun_name)?;
        link_up = true;
        Ok::<(), String>(())
    })();

    if let Err(error) = setup_result {
        let _ = platform.cleanup_interface(&options.tun_name, &configured_addresses, link_up);
        let mut device = device;
        let _ = device.shutdown();
        return Err(error);
    }

    let listener = match crate::platform::linux::control_socket::bind(&options.control_socket) {
        Ok(listener) => listener,
        Err(error) => {
            let _ = platform.cleanup_interface(&options.tun_name, &configured_addresses, link_up);
            let mut device = device;
            let _ = device.shutdown();
            return Err(error);
        }
    };

    let tun_name = options.tun_name.clone();
    println!(
        "READY tun={} listen={} public_key={} socket={}",
        tun_name,
        device.listen_addr(),
        encode_hex(&device.public_key()),
        options.control_socket.display()
    );

    let mut runtime = Runtime {
        device: Some(device),
        tun_name: options.tun_name,
        addresses: configured_addresses,
        link_up,
        auto_routes: options.auto_routes,
        peers: HashMap::new(),
        routes: HashMap::new(),
        shutdown_requested: false,
        platform: Arc::clone(&platform),
    };

    let mut serve_result = Ok(());
    loop {
        if platform.stop_requested() {
            break;
        }
        if let Some(device) = runtime.device.as_ref()
            && let Err(error) = device.health()
        {
            serve_result = Err(format!("WireGuard device failed: {error}"));
            break;
        }
        if runtime.shutdown_requested {
            break;
        }
        if let Err(error) =
            crate::platform::linux::control_socket::process_one(&listener, |stream| {
                crate::control::handle_stream(stream, &mut runtime)
            })
        {
            serve_result = Err(error);
            break;
        }
        thread::sleep(LOOP_INTERVAL);
    }

    let cleanup_result = runtime.cleanup();
    if let Err(error) = fs::remove_file(&options.control_socket) {
        if error.kind() != io::ErrorKind::NotFound {
            eprintln!("portal: could not remove runtime control socket: {error}");
        }
    }
    serve_result?;
    cleanup_result
}

impl Runtime {
    /// Parse one local command and dispatch it to the matching Device or host-network operation.
    pub(crate) fn handle_request(&mut self, request: &str) -> Result<String, String> {
        let fields = request.split_whitespace().collect::<Vec<_>>();
        let Some(command) = fields.first().copied() else {
            return Err("empty control request".into());
        };
        match command {
            "peer-upsert" => {
                if fields.len() != 6 {
                    return Err(
                        "peer-upsert expects key, psk, endpoint, keepalive and allowed IPs".into(),
                    );
                }
                let public_key = parse_key_hex(fields[1])?;
                let preshared_key = parse_optional(fields[2])
                    .map(parse_key_hex)
                    .transpose()?
                    .map(SecretKey);
                let endpoint = parse_optional(fields[3])
                    .map(|value| {
                        value
                            .parse::<SocketAddr>()
                            .map_err(|error| format!("invalid endpoint: {error}"))
                    })
                    .transpose()?;
                let keepalive = parse_optional(fields[4])
                    .map(|value| {
                        let seconds = value
                            .parse::<u64>()
                            .map_err(|error| format!("invalid keepalive: {error}"))?;
                        if seconds == 0 || seconds > u16::MAX as u64 {
                            return Err(String::from(
                                "keepalive must be between 1 and 65535 seconds",
                            ));
                        }
                        Ok(Duration::from_secs(seconds))
                    })
                    .transpose()?;
                let allowed_ips = if fields[5] == "-" {
                    Vec::new()
                } else {
                    fields[5]
                        .split(',')
                        .map(|value| {
                            value
                                .parse::<AllowedIp>()
                                .map_err(|error| format!("invalid allowed IP `{value}`: {error}"))
                        })
                        .collect::<Result<Vec<_>, _>>()?
                };
                self.upsert_peer(public_key, preshared_key, endpoint, keepalive, allowed_ips)
            }
            "peer-remove" if fields.len() == 2 => self.remove_peer(parse_key_hex(fields[1])?),
            "peer-remove" => Err("peer-remove expects one public key".into()),
            "endpoint-set" if fields.len() == 3 => {
                let public_key = parse_key_hex(fields[1])?;
                let endpoint = fields[2]
                    .parse::<SocketAddr>()
                    .map_err(|error| format!("invalid endpoint: {error}"))?;
                self.set_endpoint(public_key, endpoint)
            }
            "endpoint-set" => Err("endpoint-set expects a key and socket address".into()),
            "endpoint-clear" if fields.len() == 2 => self.clear_endpoint(parse_key_hex(fields[1])?),
            "endpoint-clear" => Err("endpoint-clear expects one public key".into()),
            "stats" if fields.len() == 1 => {
                let stats = self.device.as_ref().expect("running device").stats();
                Ok(format!(
                    "received_udp={} received_tun={} dropped={} timer_send_errors={} udp_send_errors={}",
                    stats.received_udp_packets,
                    stats.received_tun_packets,
                    stats.dropped_packets,
                    stats.timer_send_errors,
                    stats.udp_send_errors
                ))
            }
            "peer-stats" if fields.len() == 2 => {
                let key = parse_key_hex(fields[1])?;
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
            "peer-stats" => Err("peer-stats expects one public key".into()),
            "health" if fields.len() == 1 => {
                self.device
                    .as_ref()
                    .expect("running device")
                    .health()
                    .map_err(|error| error.to_string())?;
                Ok("healthy".into())
            }
            "status" if fields.len() == 1 => {
                let device = self.device.as_ref().expect("running device");
                device.health().map_err(|error| error.to_string())?;
                Ok(format!(
                    "tun={} listen={} public_key={} peers={}",
                    self.tun_name,
                    device.listen_addr(),
                    encode_hex(&device.public_key()),
                    self.peers.len()
                ))
            }
            "list" if fields.len() == 1 => {
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
            "shutdown" if fields.len() == 1 => {
                self.shutdown_requested = true;
                Ok("shutdown requested".into())
            }
            "shutdown" => Err("shutdown takes no arguments".into()),
            _ => Err(format!("unknown control request `{command}`")),
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
        let desired_routes = self.desired_routes(&staged);
        let newly_added = self.add_missing_routes(&desired_routes)?;

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
            self.rollback_new_routes(&newly_added);
            return Err(error.to_string());
        }

        self.peers = staged;
        let stale_route_errors = self.remove_stale_routes(&desired_routes);
        if stale_route_errors.is_empty() {
            Ok(format!("peer {} upserted", encode_hex(&public_key)))
        } else {
            Err(format!(
                "peer was updated, but stale host route cleanup failed: {}",
                stale_route_errors.join("; ")
            ))
        }
    }

    // Remove a peer from Device and then release host routes no longer used by any peer.
    fn remove_peer(&mut self, public_key: PeerKey) -> Result<String, String> {
        self.device
            .as_ref()
            .expect("running device")
            .remove_peer(&public_key)
            .map_err(|error| error.to_string())?;
        self.peers.remove(&public_key);
        let desired = self.desired_routes(&self.peers);
        let errors = self.remove_stale_routes(&desired);
        if errors.is_empty() {
            Ok(format!("peer {} removed", encode_hex(&public_key)))
        } else {
            Err(format!(
                "peer was removed, but host route cleanup failed: {}",
                errors.join("; ")
            ))
        }
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

    // Build the set of host routes required by managed peers, or an empty set when disabled.
    fn desired_routes(&self, peers: &HashMap<PeerKey, PeerRecord>) -> HashSet<AllowedIp> {
        if !self.auto_routes {
            return HashSet::new();
        }
        peers
            .values()
            .flat_map(|peer| peer.allowed_ips.iter().copied())
            .collect()
    }

    // Add routes missing from the current set and undo this call's additions if one fails.
    fn add_missing_routes(
        &mut self,
        desired: &HashSet<AllowedIp>,
    ) -> Result<Vec<AllowedIp>, String> {
        let mut added = Vec::new();
        for route in desired {
            if self.routes.contains_key(route) {
                continue;
            }
            match self.platform.ensure_host_route(&self.tun_name, *route) {
                Ok(owned) => {
                    self.routes.insert(*route, owned);
                    added.push(*route);
                }
                Err(error) => {
                    self.rollback_new_routes(&added);
                    return Err(error);
                }
            }
        }
        Ok(added)
    }

    // Undo routes added during a failed peer update while preserving routes owned elsewhere.
    fn rollback_new_routes(&mut self, routes: &[AllowedIp]) {
        for route in routes.iter().rev() {
            match self.routes.get(route).copied() {
                Some(true) => {
                    if self
                        .platform
                        .delete_host_route(&self.tun_name, *route)
                        .is_ok()
                    {
                        self.routes.remove(route);
                    }
                }
                Some(false) => {
                    self.routes.remove(route);
                }
                None => {}
            }
        }
    }

    // Remove routes no longer required and retain entries whose deletion failed for later cleanup.
    fn remove_stale_routes(&mut self, desired: &HashSet<AllowedIp>) -> Vec<String> {
        let stale = self
            .routes
            .keys()
            .filter(|route| !desired.contains(route))
            .copied()
            .collect::<Vec<_>>();
        let mut errors = Vec::new();
        for route in stale {
            let owned = self.routes.get(&route).copied().unwrap_or(false);
            if owned {
                if let Err(error) = self.platform.delete_host_route(&self.tun_name, route) {
                    errors.push(error);
                    continue;
                }
            }
            self.routes.remove(&route);
        }
        errors
    }

    // Release runtime-owned routes, restore interface state, and stop the WireGuard Device.
    fn cleanup(&mut self) -> Result<(), String> {
        let desired = HashSet::new();
        let mut errors = self.remove_stale_routes(&desired);
        if let Err(error) =
            self.platform
                .cleanup_interface(&self.tun_name, &self.addresses, self.link_up)
        {
            errors.push(error);
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

// Interpret the dash marker used by the local command format as an absent value.
fn parse_optional(value: &str) -> Option<&str> {
    (value != "-").then_some(value)
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
