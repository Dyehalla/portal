use crate::{
    RuntimeConfig,
    api::{LocalApi, ManagementRequest},
    peer_services::PeerServices,
    platform::{HostPlatform, Platform},
};
use portal_net::{Net, PeerKey};
use std::{
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use zeroize::Zeroize;

const LOOP_INTERVAL: Duration = Duration::from_millis(100);
pub(crate) struct Runtime {
    network: Option<Net>,
    shutdown_requested: bool,
    pub(crate) reload: Option<std::sync::mpsc::SyncSender<ReloadRequest>>,
}
pub(crate) struct ReloadRequest {
    pub(crate) response: tokio::sync::oneshot::Sender<Result<String, String>>,
}

fn start_services(
    executor: &tokio::runtime::Handle,
    network: Net,
    services: Vec<crate::ServiceRegistration>,
) -> Result<PeerServices, String> {
    PeerServices::start(executor, network, services)
}
fn reload_services(
    executor: &tokio::runtime::Handle,
    network: &Net,
    path: &std::path::Path,
    current: &mut Option<PeerServices>,
) -> Result<String, String> {
    let services = crate::config::load_services(path)?;
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
    let network = {
        let _guard = executor.enter();
        Net::new(&options.private_key.0, options.listen)?
    };
    options.private_key.0.zeroize();
    let mut peer_services = match start_services(
        executor,
        network.clone(),
        std::mem::take(&mut options.services),
    ) {
        Ok(services) => Some(services),
        Err(error) => {
            network.shutdown();
            return Err(error);
        }
    };
    let config_path = options.config_path.take();
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let runtime = Arc::new(Mutex::new(Runtime {
        network: Some(network.clone()),
        shutdown_requested: false,
        reload: config_path.as_ref().map(|_| sender),
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
            network.shutdown();
            return Err(error);
        }
    };
    println!(
        "READY net=quic listen={} public_key={} api={} token_file={}",
        network.listen_addr(),
        portal_net::encode_key(&network.public_key()),
        api.local_addr(),
        options.api_token_file.display()
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
            let _ = request.response.send(reloaded);
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
    network.shutdown();
    executor.block_on(async {
        let _ = tokio::time::timeout(Duration::from_secs(1), network.wait_idle()).await;
    });
    result.and(api_result).and(services_result)
}
impl Runtime {
    pub(crate) fn file_peer(&self, key: &str) -> Result<PeerKey, String> {
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
            } => {
                network.upsert_peer(portal_net::parse_key(&public_key)?, endpoint)?;
                Ok("peer configured".into())
            }
            ManagementRequest::PeerRemove { public_key } => {
                network.remove_peer(&portal_net::parse_key(&public_key)?)?;
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
                network.upsert_peer(key, Some(endpoint))?;
                Ok("endpoint updated".into())
            }
            ManagementRequest::EndpointClear { public_key } => {
                let key = portal_net::parse_key(&public_key)?;
                if !network.has_peer(&key) {
                    return Err("peer not found".into());
                }
                network.upsert_peer(key, None)?;
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
                    "peer={} active_connections={connections} udp_tx_bytes={tx} udp_rx_bytes={rx}",
                    portal_net::encode_key(&key)
                ))
            }
            ManagementRequest::Health => {
                network.health()?;
                Ok("healthy".into())
            }
            ManagementRequest::Status => {
                network.health()?;
                Ok(format!(
                    "net=quic listen={} public_key={} peers={}",
                    network.listen_addr(),
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
                            "{} endpoint={}",
                            portal_net::encode_key(&key),
                            endpoint
                                .map(|e| e.to_string())
                                .unwrap_or_else(|| "-".into())
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
    }
}
