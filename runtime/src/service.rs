use crate::{
    RuntimeConfig,
    api::{LocalApi, ManagementRequest},
    peer_services::PeerServices,
    platform::{HostPlatform, Platform},
};
use portal_net::{Net, PeerKey, RelayPeer, RelaySnapshot};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use zeroize::Zeroize;

#[derive(Serialize)]
pub(crate) struct NetworkStats {
    connections: usize,
    tx_bytes: u64,
    rx_bytes: u64,
}
impl From<(usize, u64, u64)> for NetworkStats {
    fn from((connections, tx_bytes, rx_bytes): (usize, u64, u64)) -> Self {
        Self {
            connections,
            tx_bytes,
            rx_bytes,
        }
    }
}
#[derive(Serialize)]
pub(crate) struct PeerSnapshot {
    public_key: String,
    endpoint: Option<std::net::SocketAddr>,
    relay: Option<RelayPeer>,
    relay_server: Option<RelayPeer>,
    relay_allowed: bool,
    path: &'static str,
    stats: NetworkStats,
}
#[derive(Serialize)]
pub(crate) struct RuntimeSnapshot {
    healthy: bool,
    public_key: String,
    listen: Option<std::net::SocketAddr>,
    can_reload: bool,
    relay_server: Option<RelaySnapshot>,
    stats: NetworkStats,
    peers: Vec<PeerSnapshot>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerInfo {
    pub(crate) public_key: String,
    pub(crate) relay_server: Option<RelayPeer>,
}

const LOOP_INTERVAL: Duration = Duration::from_millis(100);
pub(crate) struct Runtime {
    network: Option<Net>,
    shutdown_requested: bool,
    pub(crate) reload: Option<std::sync::mpsc::SyncSender<ReloadRequest>>,
    pub(crate) peer_info: HashMap<PeerKey, PeerInfo>,
}
pub(crate) struct ReloadRequest {
    pub(crate) response: tokio::sync::oneshot::Sender<Result<String, String>>,
}

fn start_services(
    executor: &tokio::runtime::Handle,
    network: Net,
    mut services: Vec<crate::ServiceRegistration>,
) -> Result<PeerServices, String> {
    services.push(identity_service(&network));
    PeerServices::start(executor, network, services)
}

/// Advertise capabilities only to authenticated, trusted Portal peers.
fn identity_service(network: &Net) -> crate::ServiceRegistration {
    let info = PeerInfo {
        public_key: portal_net::encode_key(&network.public_key()),
        relay_server: network.relay_server(),
    };
    crate::ServiceRegistration::new("portal", move |_| async move {
        Ok(crate::ServiceImplementation::new(portal_net::Service::new(
            "portal",
            move |_, request| {
                let info = info.clone();
                async move {
                    if request.operation != "info" {
                        return portal_net::Response::error(404, "unknown portal operation");
                    }
                    if request.payload != serde_json::json!({}) {
                        return portal_net::Response::error(
                            400,
                            "info payload must be an empty object",
                        );
                    }
                    portal_net::Response::json(&info)
                        .unwrap_or_else(|e| portal_net::Response::error(500, &e))
                }
            },
        )))
    })
}
fn reload_services(
    executor: &tokio::runtime::Handle,
    network: &Net,
    path: &std::path::Path,
    current: &mut Option<PeerServices>,
) -> Result<String, String> {
    let mut services = crate::config::load_services(path)?;
    services.push(identity_service(network));
    let context = crate::ServiceContext {
        network: network.clone(),
    };
    let (registry, background) = executor.block_on(async {
        tokio::time::timeout(
            Duration::from_secs(10),
            crate::peer_services::prepare_services(context, services),
        )
        .await
        .map_err(|_| "service preparation timed out".to_owned())?
    })?;
    let stop_result = current.take().map(PeerServices::stop).unwrap_or(Ok(()));
    *current = Some(PeerServices::from_prepared(
        executor,
        network.clone(),
        registry,
        background,
    )?);
    stop_result
        .map_err(|e| format!("new services started, but stopping previous services failed: {e}"))?;
    Ok("services reloaded".into())
}
pub(crate) fn run_device(options: RuntimeConfig) -> Result<(), String> {
    let executor = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("portal-async")
        .build()
        .map_err(|e| e.to_string())?;
    let result = run_with_executor(options, executor.handle());
    executor.shutdown_timeout(Duration::from_secs(1));
    result
}
fn run_with_executor(
    mut options: RuntimeConfig,
    executor: &tokio::runtime::Handle,
) -> Result<(), String> {
    let platform = Platform;
    platform.install_signal_handlers();
    let network = executor.block_on(Net::with_relay_server(
        &options.private_key.0,
        options.listen,
        std::mem::take(&mut options.relays),
        options.relay_server.take(),
    ))?;
    options.private_key.0.zeroize();
    let mut peer_services = match start_services(
        executor,
        network.clone(),
        std::mem::take(&mut options.services),
    ) {
        Ok(services) => Some(services),
        Err(error) => {
            shutdown_network(executor, &network);
            return Err(error);
        }
    };
    let config_path = options.config_path.take();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let runtime = Arc::new(Mutex::new(Runtime {
        network: Some(network.clone()),
        shutdown_requested: false,
        reload: config_path.as_ref().map(|_| sender),
        peer_info: HashMap::new(),
    }));
    let api = match LocalApi::start(
        executor,
        options.api_listen,
        options.api_token_file.clone(),
        runtime.clone(),
        Some(network.clone()),
    ) {
        Ok(api) => api,
        Err(error) => {
            if let Some(services) = peer_services.take() {
                let _ = services.stop();
            }
            shutdown_network(executor, &network);
            return Err(error);
        }
    };
    println!(
        "READY net=iroh listen={} public_key={} api={} token_file={} relay_server={}",
        network
            .listen_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "relay-only".into()),
        portal_net::encode_key(&network.public_key()),
        api.local_addr(),
        options.api_token_file.display(),
        network
            .relay_server()
            .map(|relay| relay.endpoint.to_string())
            .unwrap_or_else(|| "disabled".into()),
    );
    let mut result = Ok(());
    loop {
        if platform.stop_requested() {
            break;
        }
        match runtime.lock() {
            Ok(runtime) if runtime.shutdown_requested => break,
            Ok(_) => {}
            Err(_) => {
                result = Err("runtime state is unavailable".into());
                break;
            }
        }
        if let Err(error) = network.health() {
            result = Err(error);
            break;
        }
        if let Ok(request) = receiver.try_recv() {
            let reloaded = reload_services(
                executor,
                &network,
                config_path.as_deref().expect("reload enabled"),
                &mut peer_services,
            );
            let fatal = peer_services.is_none();
            if fatal {
                result = Err(format!(
                    "service reload activation failed; shutting down runtime: {}",
                    reloaded
                        .as_ref()
                        .err()
                        .map(String::as_str)
                        .unwrap_or("no active service host")
                ));
            }
            let _ = request.response.send(reloaded);
            if fatal {
                break;
            }
        }
        if api.has_exited() {
            result = Err("local HTTP API exited unexpectedly".into());
            break;
        }
        if peer_services.as_ref().is_some_and(PeerServices::has_exited) {
            result = peer_services
                .take()
                .expect("present services")
                .stop()
                .and_then(|_| Err("QUIC services exited unexpectedly".into()));
            break;
        }
        thread::sleep(LOOP_INTERVAL);
    }
    let api_result = api.stop();
    let services_result = peer_services
        .take()
        .map(PeerServices::stop)
        .unwrap_or(Ok(()));
    shutdown_network(executor, &network);
    result.and(api_result).and(services_result)
}

fn shutdown_network(executor: &tokio::runtime::Handle, network: &Net) {
    executor.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(5), network.shutdown()).await;
    });
}
impl Runtime {
    /// A structured view for the web client; management commands retain their CLI response format.
    pub(crate) fn snapshot(&self) -> Result<RuntimeSnapshot, String> {
        let network = self.network.as_ref().ok_or("network unavailable")?;
        let mut peers = network
            .peers()
            .into_iter()
            .map(|(key, endpoint)| {
                Ok(PeerSnapshot {
                    public_key: portal_net::encode_key(&key),
                    endpoint,
                    relay: network.peer_relay(&key)?,
                    relay_server: self
                        .peer_info
                        .get(&key)
                        .and_then(|info| info.relay_server.clone()),
                    relay_allowed: network.relay_is_allowed(&key),
                    path: network.peer_path(&key)?,
                    stats: network.stats(Some(&key))?.into(),
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        peers.sort_by(|a, b| a.public_key.cmp(&b.public_key));
        Ok(RuntimeSnapshot {
            healthy: !self.shutdown_requested && network.health().is_ok(),
            public_key: portal_net::encode_key(&network.public_key()),
            listen: network.listen_addr(),
            can_reload: self.reload.is_some(),
            relay_server: network.relay_snapshot(),
            stats: network.stats(None)?.into(),
            peers,
        })
    }
    pub(crate) fn registered_peer(&self, key: &str) -> Result<PeerKey, String> {
        let key = portal_net::parse_key(key)?;
        if !self.network.as_ref().is_some_and(|net| net.has_peer(&key)) {
            return Err("unregistered peer".into());
        }
        Ok(key)
    }
    pub(crate) fn handle_api_request(
        &mut self,
        request: ManagementRequest,
    ) -> Result<String, String> {
        if matches!(request, ManagementRequest::Shutdown) {
            self.shutdown_requested = true;
            return Ok("shutdown requested".into());
        }
        let network = self.network.as_ref().ok_or("network unavailable")?;
        match request {
            ManagementRequest::PeerUpsert {
                public_key,
                endpoint,
                relay,
                allow_relay,
            } => {
                let key = portal_net::parse_key(&public_key)?;
                if allow_relay.is_some() && network.relay_server().is_none() {
                    return Err("this device does not host a relay".into());
                }
                network.upsert_peer(key, endpoint, relay)?;
                if let Some(allowed) = allow_relay {
                    network.set_relay_allowed(key, allowed)?;
                }
                Ok("peer configured".into())
            }
            ManagementRequest::PeerRemove { public_key } => {
                let key = portal_net::parse_key(&public_key)?;
                network.remove_peer(&key)?;
                self.peer_info.remove(&key);
                if network.relay_server().is_some() {
                    network.set_relay_allowed(key, false)?;
                }
                Ok("peer removed".into())
            }
            ManagementRequest::EndpointSet {
                public_key,
                endpoint,
            } => {
                let key = portal_net::parse_key(&public_key)?;
                if !network.has_peer(&key) {
                    return Err("peer not found".into());
                }
                network.upsert_peer(key, Some(endpoint), network.peer_relay(&key)?)?;
                Ok("endpoint updated".into())
            }
            ManagementRequest::EndpointClear { public_key } => {
                let key = portal_net::parse_key(&public_key)?;
                if !network.has_peer(&key) {
                    return Err("peer not found".into());
                }
                network.upsert_peer(key, None, network.peer_relay(&key)?)?;
                Ok("endpoint cleared".into())
            }
            ManagementRequest::Stats => {
                let (connections, tx, rx) = network.stats(None)?;
                Ok(format!(
                    "active_connections={connections} udp_tx_bytes={tx} udp_rx_bytes={rx}"
                ))
            }
            ManagementRequest::PeerStats { public_key } => {
                let key = portal_net::parse_key(&public_key)?;
                let (connections, tx, rx) = network.stats(Some(&key))?;
                Ok(format!(
                    "peer={} active_connections={connections} udp_tx_bytes={tx} udp_rx_bytes={rx} path={}",
                    portal_net::encode_key(&key),
                    network.peer_path(&key)?
                ))
            }
            ManagementRequest::Health => {
                network.health()?;
                Ok("healthy".into())
            }
            ManagementRequest::Status => {
                network.health()?;
                Ok(format!(
                    "net=iroh listen={} public_key={} peers={}",
                    network
                        .listen_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|| "relay-only".into()),
                    portal_net::encode_key(&network.public_key()),
                    network.peers().len()
                ))
            }
            ManagementRequest::List => {
                let mut peers = network
                    .peers()
                    .into_iter()
                    .map(|(key, endpoint)| {
                        format!(
                            "{} endpoint={} path={}",
                            portal_net::encode_key(&key),
                            endpoint
                                .map(|e| e.to_string())
                                .unwrap_or_else(|| "-".into()),
                            network.peer_path(&key).unwrap_or("offline")
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
            ManagementRequest::ServicesReload => {
                Err("reload must be dispatched through controller".into())
            }
            ManagementRequest::RelayAccessSet {
                public_key,
                allowed,
            } => {
                network.set_relay_allowed(portal_net::parse_key(&public_key)?, allowed)?;
                Ok("relay access updated".into())
            }
            ManagementRequest::Shutdown => unreachable!(),
        }
    }
}
#[cfg(test)]
pub(crate) fn test_runtime() -> Runtime {
    Runtime {
        network: None,
        shutdown_requested: false,
        reload: None,
        peer_info: HashMap::new(),
    }
}
