use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::api::LocalApi;
use crate::api::ManagementRequest;
use crate::managed::{Agent, ManagedState, Prepared};
use crate::platform::{HostPlatform, LinuxPlatform};
use crate::{InterfaceAddress, RuntimeConfig, SecretKey};
use portal::{AccessControl, AllowedIp, Device, DeviceConfig, PeerConfig, PeerKey};
use portal_net::{
    model::{NetworkMap, Permissions},
    policy,
};
use zeroize::Zeroize;

const LOOP_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone)]
struct PeerRecord {
    endpoint: Option<SocketAddr>,
    keepalive: Option<Duration>,
    allowed_ips: Vec<AllowedIp>,
}

pub(crate) struct Runtime {
    pub(crate) managed: Option<ManagedState>,
    access_control: Option<Arc<AccessControl>>,
    pub(crate) dual_stack: bool,
    device: Option<Device>,
    tun_name: String,
    addresses: Vec<InterfaceAddress>,
    link_up: bool,
    auto_routes: bool,
    peers: HashMap<PeerKey, PeerRecord>,
    routes: HashMap<AllowedIp, bool>,
    pub(crate) shutdown_requested: bool,
    platform: Arc<dyn HostPlatform>,
}

/// Create the WireGuard device, configure its host interface, serve the local API, and clean up.
pub(crate) fn run_device(options: RuntimeConfig) -> Result<(), String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(run_device_async(options))
}

async fn run_device_async(mut options: RuntimeConfig) -> Result<(), String> {
    let platform: Arc<dyn HostPlatform> = Arc::new(LinuxPlatform);
    platform.install_signal_handlers();
    platform.ensure_interface_absent(&options.tun_name)?;

    let prepared = if let Some(config) = options.coordinator.take() {
        let key = boringtun::x25519::PublicKey::from(&boringtun::x25519::StaticSecret::from(
            options.private_key.0,
        ))
        .to_bytes();
        Some(Prepared::load(config, key).await?)
    } else {
        None
    };
    if let Some(prepared) = &prepared {
        options.addresses = vec![
            InterfaceAddress {
                address: prepared.map.device.ipv4.into(),
                prefix_len: 32,
            },
            InterfaceAddress {
                address: prepared.map.device.ipv6.into(),
                prefix_len: 128,
            },
        ];
    }
    let access_control = prepared
        .as_ref()
        .map(|_| Arc::new(AccessControl::default()));

    let mut device_config = DeviceConfig::new(
        options.private_key.0,
        options.listen,
        options.tun_name.clone(),
    );
    device_config.dual_stack = options.dual_stack;
    device_config.access_control = access_control.clone();
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

    let tun_name = options.tun_name.clone();
    let runtime = Runtime {
        managed: None,
        access_control: access_control.clone(),
        dual_stack: options.dual_stack,
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
    let agent = if let Some(prepared) = prepared {
        match Agent::attach(
            prepared,
            runtime.clone(),
            access_control.clone().expect("managed access control"),
        ) {
            Ok(agent) => Some(agent),
            Err(error) => {
                if let Ok(mut runtime) = runtime.lock() {
                    let _ = runtime.cleanup();
                }
                return Err(error);
            }
        }
    } else {
        None
    };
    let api = match LocalApi::start(
        options.api_listen,
        options.api_token_file.clone(),
        Arc::clone(&runtime),
        agent.clone(),
    ) {
        Ok(api) => api,
        Err(error) => {
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
    let mut agent_task = agent.map(|agent| tokio::spawn(agent.run()));

    println!(
        "READY tun={} listen={} public_key={} api={} token_file={}",
        tun_name,
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
            if runtime.shutdown_requested {
                break;
            }
        }
        if api.has_exited() {
            serve_result = Err("local HTTP API exited unexpectedly".into());
            break;
        }
        if agent_task.as_ref().is_some_and(|t| t.is_finished()) {
            let task = agent_task.take().expect("agent task present");
            serve_result = task
                .await
                .map_err(|e| format!("network agent failed: {e}"))
                .and_then(|r| r)
                .and(Err("network agent exited unexpectedly".into()));
            break;
        }
        tokio::time::sleep(LOOP_INTERVAL).await;
    }

    if let Some(access) = &access_control {
        access.block();
    }
    if let Some(task) = agent_task {
        task.abort();
        let _ = task.await;
    }
    let api_result = api.stop().await;
    if serve_result.is_ok() {
        serve_result = api_result;
    }

    let cleanup_result = runtime
        .lock()
        .map_err(|_| "runtime state became unavailable during cleanup".to_owned())
        .and_then(|mut runtime| runtime.cleanup());
    serve_result?;
    cleanup_result
}

impl Runtime {
    pub(crate) fn apply_managed_map(
        &mut self,
        map: NetworkMap,
        local: Permissions,
        deadline: Instant,
        cache_file: &std::path::Path,
    ) -> Result<(), String> {
        let key = self.device.as_ref().expect("running device").public_key();
        // Concurrent immediate refreshes can finish before the older long poll.
        if let Some(old) = &self.managed
            && map.network_id == old.map.network_id
            && map.generation == old.map.generation
            && (map.revision < old.map.revision || map.generated_at < old.map.generated_at)
        {
            return Ok(());
        }
        let rules = match policy::compile(&map, &local, key, self.managed.as_ref().map(|s| &s.map))
        {
            Ok(rules) => rules,
            Err(e) => {
                if let Some(access) = &self.access_control {
                    access.block();
                }
                self.shutdown_requested = true;
                return Err(e);
            }
        };
        let access = self
            .access_control
            .clone()
            .ok_or("managed access control unavailable")?;
        let result = access.update(rules, deadline, |changed| {
            if changed {
                // Holding the worker gate drains in-flight operations. Discard pending
                // plaintext before enabling new grants, preserving authenticated sessions.
                for key in self.peers.keys().copied().collect::<Vec<_>>() {
                    let device = self.device.as_ref().expect("running device");
                    device.discard_peer_queue(&key).map_err(|e| e.to_string())?;
                    if !map
                        .peers
                        .iter()
                        .any(|peer| policy::public_key(&peer.device.public_key).ok() == Some(key))
                    {
                        device.remove_peer(&key).map_err(|e| e.to_string())?;
                        self.peers.remove(&key);
                    }
                }
            }
            for peer in &map.peers {
                let key = policy::public_key(&peer.device.public_key)?;
                let endpoint_changed = self
                    .managed
                    .as_ref()
                    .and_then(|s| s.map.peers.iter().find(|p| p.device.id == peer.device.id))
                    .is_none_or(|p| p.device.endpoints != peer.device.endpoints);
                let endpoint = endpoint_changed
                    .then(|| {
                        peer.device
                            .endpoints
                            .iter()
                            .copied()
                            .find(|e| self.endpoint_supported(*e))
                    })
                    .flatten();
                self.upsert_peer(
                    key,
                    None,
                    endpoint,
                    Some(Duration::from_secs(25)),
                    vec![
                        AllowedIp::new(peer.device.ipv4.into(), 32).map_err(|e| e.to_string())?,
                        AllowedIp::new(peer.device.ipv6.into(), 128).map_err(|e| e.to_string())?,
                    ],
                )?;
                if endpoint_changed && endpoint.is_none() {
                    self.clear_endpoint(key)?;
                }
            }
            let desired = self.desired_routes(&self.peers);
            let errors = self.remove_stale_routes(&desired);
            if !errors.is_empty() {
                return Err(errors.join("; "));
            }
            let bytes = serde_json::to_vec(&map).map_err(|e| e.to_string())?;
            crate::private_file::write(cache_file, &bytes, false)?;
            Ok(())
        });
        if result.is_err() {
            self.shutdown_requested = true;
        }
        result?;
        self.managed = Some(ManagedState {
            map,
            local,
            deadline,
            connected: true,
        });
        Ok(())
    }

    pub(crate) fn set_managed_endpoint(
        &mut self,
        key: PeerKey,
        endpoint: SocketAddr,
    ) -> Result<(), String> {
        self.set_endpoint(key, endpoint).map(|_| ())
    }

    pub(crate) fn endpoint_supported(&self, endpoint: SocketAddr) -> bool {
        self.dual_stack
            || endpoint.is_ipv4()
                == self
                    .device
                    .as_ref()
                    .expect("running device")
                    .listen_addr()
                    .is_ipv4()
    }

    /// Dispatch one authenticated JSON API operation to its Device or host-network operation.
    pub(crate) fn handle_api_request(
        &mut self,
        request: ManagementRequest,
    ) -> Result<String, String> {
        if self.access_control.is_some()
            && matches!(
                &request,
                ManagementRequest::PeerUpsert { .. }
                    | ManagementRequest::PeerRemove { .. }
                    | ManagementRequest::EndpointSet { .. }
                    | ManagementRequest::EndpointClear { .. }
            )
        {
            return Err("managed peers and endpoints are controlled by the coordinator; edit the local policy file to change access".into());
        }
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
                    "received_udp={} received_tun={} dropped={} timer_send_errors={} udp_send_errors={}",
                    stats.received_udp_packets,
                    stats.received_tun_packets,
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
                    "tun={} listen={} public_key={} peers={} {}",
                    self.tun_name,
                    device.listen_addr(),
                    encode_hex(&device.public_key()),
                    self.peers.len(),
                    self.managed.as_ref().map(|s| format!("mode=managed device={} network={} generation={} revision={} policy_revision={} policy_pending={} coordinator_connected={} lease_active={} lease_remaining_seconds={}", s.map.device.id, s.map.network_id, s.map.generation, s.map.revision, s.map.policy.revision, s.map.policy.permissions != s.local, s.connected, s.deadline > Instant::now(), s.deadline.saturating_duration_since(Instant::now()).as_secs())).unwrap_or_else(|| "mode=manual".into())
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
            ManagementRequest::Connect { .. } => {
                Err("P2P requests require the asynchronous agent handler".into())
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
            if owned && let Err(error) = self.platform.delete_host_route(&self.tun_name, route) {
                errors.push(error);
                continue;
            }
            self.routes.remove(&route);
        }
        errors
    }

    // Release runtime-owned routes, restore interface state, and stop the WireGuard Device.
    fn cleanup(&mut self) -> Result<(), String> {
        let desired = HashSet::new();
        let mut errors = Vec::new();
        errors.extend(self.remove_stale_routes(&desired));
        if let Err(error) =
            self.platform
                .cleanup_interface(&self.tun_name, &self.addresses, self.link_up)
        {
            errors.push(error);
        }
        if let Some(mut device) = self.device.take()
            && let Err(error) = device.shutdown()
        {
            errors.push(format!("device shutdown failed: {error}"));
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
