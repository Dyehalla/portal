use std::fs::File;
use std::path::Path;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use boringtun::x25519::{PublicKey, StaticSecret};
use portal::{AccessControl, PeerKey};
use portal_net::client::{ClientError, CoordinatorClient};
use portal_net::model::*;
use portal_net::policy::{self, key_hex};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use zeroize::Zeroizing;

use crate::private_file;
use crate::runtime::Runtime;
use crate::{ManagedConfig, SecretKey};

#[derive(Serialize, Deserialize)]
struct CredentialFile {
    coordinator: String,
    device: Device,
    access_token: String,
}
impl Drop for CredentialFile {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.access_token.zeroize();
    }
}

pub(crate) async fn enroll(
    config: ManagedConfig,
    private_key: SecretKey,
    user_token_file: &Path,
) -> Result<String, String> {
    let _lock = private_file::lock(&config.credential_file.with_extension("lock"))?;
    if config
        .credential_file
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Err(
            "device credential file already exists; enrollment never replaces an identity".into(),
        );
    }
    let token = private_file::read(user_token_file, 128)?;
    let token = std::str::from_utf8(&token)
        .map_err(|_| "invalid user token")?
        .trim();
    if !token.starts_with("usr_") {
        return Err("enrollment requires a user token".into());
    }
    let key = PublicKey::from(&StaticSecret::from(private_key.0)).to_bytes();
    let client = CoordinatorClient::new(&config.url, token.to_owned(), config.ca_file.as_deref())?;
    let reply = client
        .register_device(&RegisterDevice {
            name: config.device_name.clone(),
            public_key: key_hex(&key),
            endpoints: config.endpoints.clone(),
        })
        .await
        .map_err(|e| e.to_string())?;
    if policy::public_key(&reply.device.public_key)? != key
        || !reply.access_token.starts_with("dev_")
    {
        return Err("coordinator returned another device identity".into());
    }
    let credentials = CredentialFile {
        coordinator: config.url,
        device: reply.device,
        access_token: reply.access_token,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&credentials).map_err(|e| e.to_string())?);
    private_file::write(&config.credential_file, &bytes, true)?;
    Ok(format!(
        "enrolled device={} ipv4={} ipv6={}",
        credentials.device.id, credentials.device.ipv4, credentials.device.ipv6
    ))
}

pub(crate) struct Prepared {
    pub config: ManagedConfig,
    pub map: NetworkMap,
    pub local: Permissions,
    pub deadline: Instant,
    client: CoordinatorClient,
    identity_lock: File,
}

impl Prepared {
    pub(crate) async fn load(config: ManagedConfig, key: PeerKey) -> Result<Self, String> {
        let identity_lock = private_file::lock(&config.credential_file.with_extension("lock"))?;
        let bytes = private_file::read(&config.credential_file, 64 * 1024)?;
        let credentials: CredentialFile =
            serde_json::from_slice(&bytes).map_err(|_| "invalid device credential file")?;
        if credentials.coordinator != config.url
            || policy::public_key(&credentials.device.public_key)? != key
            || !credentials.access_token.starts_with("dev_")
        {
            return Err("device credentials do not match this coordinator or private key".into());
        }
        let local = read_policy(&config.policy_file)?;
        let client = CoordinatorClient::new(
            &config.url,
            credentials.access_token.clone(),
            config.ca_file.as_deref(),
        )?;
        let previous = match private_file::read(&config.map_file, 4 * 1024 * 1024) {
            Ok(bytes) => Some(
                serde_json::from_slice::<NetworkMap>(&bytes)
                    .map_err(|_| "invalid saved network map")?,
            ),
            Err(_) if !config.map_file.try_exists().map_err(|e| e.to_string())? => None,
            Err(e) => return Err(e),
        };
        let mut started = Instant::now();
        let mut map = client.network_map(None).await.map_err(|e| e.to_string())?;
        if map.device.id != credentials.device.id
            || map.device.owner_user_id != credentials.device.owner_user_id
            || map.device.ipv4 != credentials.device.ipv4
            || map.device.ipv6 != credentials.device.ipv6
        {
            return Err("coordinator changed the enrolled device identity".into());
        }
        policy::compile(&map, &local, key, previous.as_ref())?;
        if map.device.endpoints != config.endpoints {
            client
                .endpoints(config.endpoints.clone())
                .await
                .map_err(|e| e.to_string())?;
            started = Instant::now();
            map = client.network_map(None).await.map_err(|e| e.to_string())?;
            policy::compile(&map, &local, key, previous.as_ref())?;
        }
        let deadline = policy::lease_deadline(&map, started)?;
        Ok(Self {
            config,
            map,
            local,
            deadline,
            client,
            identity_lock,
        })
    }
}

pub(crate) struct ManagedState {
    pub map: NetworkMap,
    pub map_received_at: Instant,
    pub local: Permissions,
    pub deadline: Instant,
    pub connected: bool,
}

pub(crate) struct Agent {
    pub config: ManagedConfig,
    pub access: Arc<AccessControl>,
    runtime: Arc<Mutex<Runtime>>,
    client: CoordinatorClient,
    changes: watch::Sender<u64>,
    _identity_lock: File,
    owner_managed: AtomicBool,
}

impl Agent {
    pub(crate) fn attach(
        prepared: Prepared,
        runtime: Arc<Mutex<Runtime>>,
        access: Arc<AccessControl>,
    ) -> Result<Arc<Self>, String> {
        let (changes, _) = watch::channel(0);
        let agent = Arc::new(Self {
            config: prepared.config,
            access,
            runtime,
            client: prepared.client,
            changes,
            _identity_lock: prepared.identity_lock,
            owner_managed: AtomicBool::new(false),
        });
        agent
            .runtime
            .lock()
            .map_err(|_| "runtime state unavailable")?
            .apply_managed_map(
                prepared.map,
                prepared.local,
                prepared.deadline,
                &agent.config.map_file,
            )?;
        Ok(agent)
    }

    pub(crate) async fn run(self: Arc<Self>) -> Result<(), String> {
        let result = tokio::select! {
            result = self.maps() => result,
            result = self.policies() => result,
            result = self.incoming() => result,
            result = self.discovery() => result,
            result = self.desired_policies() => result,
        };
        self.access.block();
        result
    }

    fn snapshot(&self) -> Result<(NetworkMap, Permissions, Instant), String> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "runtime state unavailable")?;
        let state = runtime
            .managed
            .as_ref()
            .ok_or("managed state unavailable")?;
        Ok((state.map.clone(), state.local.clone(), state.deadline))
    }

    async fn apply(&self, map: NetworkMap, started: Instant) -> Result<(), String> {
        let deadline = policy::lease_deadline(&map, started)?;
        let mut runtime = self
            .runtime
            .lock()
            .map_err(|_| "runtime state unavailable")?;
        let local = runtime
            .managed
            .as_ref()
            .ok_or("managed state unavailable")?
            .local
            .clone();
        runtime.apply_managed_map(map, local, deadline, &self.config.map_file)
    }

    async fn refresh(&self) -> Result<(), String> {
        let started = Instant::now();
        let map = match self.client.network_map(None).await {
            Ok(map) => map,
            Err(e) => {
                self.transient(&e)?;
                return Err(e.to_string());
            }
        };
        self.apply(map, started).await
    }

    fn transient(&self, error: &ClientError) -> Result<(), String> {
        if matches!(
            error,
            ClientError::Unauthorized | ClientError::InvalidResponse
        ) {
            self.access.block();
            if let Ok(mut runtime) = self.runtime.lock() {
                if let Some(state) = &mut runtime.managed {
                    state.connected = false;
                    state.deadline = Instant::now();
                }
            }
            return Err(error.to_string());
        }
        if let Ok(mut runtime) = self.runtime.lock()
            && let Some(state) = &mut runtime.managed
        {
            state.connected = false;
        }
        eprintln!("portal: {error}; retrying");
        Ok(())
    }

    async fn maps(&self) -> Result<(), String> {
        let mut changes = self.changes.subscribe();
        let mut resync = false;
        loop {
            changes.borrow_and_update();
            let (map, local, deadline) = self.snapshot()?;
            if local != map.policy.permissions && !self.owner_managed.load(Ordering::Acquire) {
                match self
                    .client
                    .publish_policy(&PublishPolicy {
                        base_revision: map.policy.revision,
                        permissions: local,
                    })
                    .await
                {
                    Ok(_) | Err(ClientError::Http(409)) => {
                        // A coordinator outage during the follow-up read must not stop
                        // local policy monitoring. The packet gate still expires the lease.
                        if let Err(e) = self.refresh().await {
                            resync = true;
                            eprintln!("portal: {e}");
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                        continue;
                    }
                    Err(e) => {
                        self.transient(&e)?;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        // A rejected publication must not prevent lease renewal
                        // for the already confirmed, locally restricted map.
                        resync = !matches!(e, ClientError::Http(_));
                    }
                }
            }
            let started = Instant::now();
            let result = tokio::select! {
                _ = changes.changed() => continue,
                result = self.client.network_map((!resync && deadline > Instant::now()).then_some(&map)) => result,
            };
            match result {
                Ok(map) => {
                    self.apply(map, started).await?;
                    resync = false;
                }
                Err(e) => {
                    resync = true;
                    self.transient(&e)?;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    async fn desired_policies(&self) -> Result<(), String> {
        loop {
            match self.client.desired_policy().await {
                Ok(Some(desired)) => {
                    self.owner_managed.store(true, Ordering::Release);
                    let permissions = policy::normalize_permissions(desired.permissions)?;
                    {
                        // Read and apply under one runtime lock: a newer long poll must
                        // not make this apply a no-op before we acknowledge the revision.
                        let mut runtime = self
                            .runtime
                            .lock()
                            .map_err(|_| "runtime state unavailable")?;
                        let state = runtime
                            .managed
                            .as_ref()
                            .ok_or("managed state unavailable")?;
                        if state.local != permissions {
                            let map = state.map.clone();
                            let deadline = state.deadline;
                            private_file::write(
                                &self.config.policy_file,
                                &serde_json::to_vec(&permissions).map_err(|e| e.to_string())?,
                                false,
                            )?;
                            runtime.apply_managed_map(
                                map,
                                permissions,
                                deadline,
                                &self.config.map_file,
                            )?;
                        }
                    }
                    if desired.applied_revision != desired.revision {
                        match self.client.acknowledge_policy(desired.revision).await {
                            Ok(_) => {
                                self.changes.send_modify(|v| *v = v.wrapping_add(1));
                                let _ = self.refresh().await;
                            }
                            Err(ClientError::Http(409)) => {}
                            Err(e) => self.transient(&e)?,
                        }
                    }
                }
                // Compatibility: old coordinators keep the existing local policy mode.
                Ok(None) | Err(ClientError::Http(404)) => {}
                Err(e) => self.transient(&e)?,
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn policies(&self) -> Result<(), String> {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if self.owner_managed.load(Ordering::Acquire) {
                continue;
            }
            let local = read_policy(&self.config.policy_file)?;
            let (map, old, deadline) = self.snapshot()?;
            if local != old {
                self.runtime
                    .lock()
                    .map_err(|_| "runtime state unavailable")?
                    .apply_managed_map(map, local, deadline, &self.config.map_file)?;
                self.changes.send_modify(|v| *v = v.wrapping_add(1));
            }
        }
    }

    async fn discovery(&self) -> Result<(), String> {
        loop {
            let listen = self
                .runtime
                .lock()
                .map_err(|_| "runtime state unavailable")?
                .listen_addr()?;
            let mut endpoints = self.config.endpoints.clone();
            let (map, _, _) = self.snapshot()?;
            let mut servers = self.config.stun_servers.clone();
            if let Some(stun) = &map.stun {
                if stun.endpoints.is_empty() {
                    match tokio::time::timeout(
                        Duration::from_secs(5),
                        tokio::net::lookup_host((
                            self.client.coordinator_host().as_str(),
                            stun.port,
                        )),
                    )
                    .await
                    {
                        Ok(Ok(addresses)) => {
                            for address in addresses {
                                if !servers.contains(&address) && servers.len() < 8 {
                                    servers.push(address);
                                }
                            }
                        }
                        _ => eprintln!("portal: could not resolve coordinator STUN host; retrying"),
                    }
                } else {
                    for address in &stun.endpoints {
                        if !servers.contains(address) && servers.len() < 8 {
                            servers.push(*address);
                        }
                    }
                }
            }
            servers.retain(|address| {
                self.runtime
                    .lock()
                    .is_ok_and(|runtime| runtime.endpoint_supported(*address))
            });
            // Independent servers share the real WireGuard socket. Retry the same
            // transactions with exponential backoff, preserving slower responses.
            if !servers.is_empty() {
                self.runtime
                    .lock()
                    .map_err(|_| "runtime state unavailable")?
                    .start_discovery(&servers)?;
                for delay in [500, 1000, 2000] {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    let runtime = self
                        .runtime
                        .lock()
                        .map_err(|_| "runtime state unavailable")?;
                    for endpoint in runtime.discovered_endpoints()? {
                        if !endpoints.contains(&endpoint) && endpoints.len() < 8 {
                            endpoints.push(endpoint);
                        }
                    }
                    if delay != 2000 {
                        runtime.retry_discovery()?;
                    }
                }
            }
            let (map, _, _) = self.snapshot()?;
            for endpoint in local_candidates(listen, &map) {
                let supported = self
                    .runtime
                    .lock()
                    .map_err(|_| "runtime state unavailable")?
                    .endpoint_supported(endpoint);
                if supported && !endpoints.contains(&endpoint) && endpoints.len() < 8 {
                    endpoints.push(endpoint);
                }
            }
            endpoints.sort();
            endpoints.dedup();
            if endpoints != map.device.endpoints {
                match self.client.endpoints(endpoints).await {
                    Ok(_) => {
                        self.changes.send_modify(|v| *v = v.wrapping_add(1));
                    }
                    Err(e) => self.transient(&e)?,
                }
            }
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    async fn incoming(&self) -> Result<(), String> {
        loop {
            match self.client.incoming().await {
                Ok(batch) => {
                    for signal in batch.requests {
                        let (map, _, _) = self.snapshot()?;
                        if signal.generation != map.generation || signal.revision > map.revision {
                            // Never acknowledge a signal using bindings that have not been applied.
                            if self.refresh().await.is_err() {
                                continue;
                            }
                        }
                        let accepted = self.apply_signal(&signal, true).is_ok();
                        match self.client.respond(&signal.request_id, accepted).await {
                            Ok(_) | Err(ClientError::Http(404)) => {}
                            Err(e) => {
                                self.transient(&e)?;
                            }
                        }
                    }
                    // Delivery is at least once; keep failures from becoming a busy loop.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => {
                    self.transient(&e)?;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        }
    }

    fn apply_signal(&self, signal: &ConnectionInfo, incoming: bool) -> Result<(), String> {
        let runtime = self
            .runtime
            .lock()
            .map_err(|_| "runtime state unavailable")?;
        let state = runtime
            .managed
            .as_ref()
            .ok_or("managed state unavailable")?;
        if state.deadline <= Instant::now() {
            return Err("network map lease expired".into());
        }
        let coordinator_now = state
            .map
            .generated_at
            .saturating_add(state.map_received_at.elapsed().as_secs());
        let key = policy::validate_signal_at(
            signal,
            &state.map,
            &state.local,
            incoming,
            coordinator_now,
        )?;
        let candidates: Vec<_> = signal
            .peer
            .endpoints
            .iter()
            .copied()
            .filter(|e| runtime.endpoint_supported(*e))
            .collect();
        if candidates.is_empty() {
            return Err("peer has no supported endpoint candidate".into());
        }
        runtime.start_managed_probe(key, candidates)
    }

    pub(crate) async fn connect(&self, peer_device_id: String) -> Result<String, String> {
        tokio::time::timeout(Duration::from_secs(28), self.connect_inner(peer_device_id))
            .await
            .map_err(|_| {
                "P2P connection deadline exceeded; background retries continue".to_string()
            })?
    }

    async fn connect_inner(&self, peer_device_id: String) -> Result<String, String> {
        let (map, _, deadline) = self.snapshot()?;
        if deadline <= Instant::now()
            || !map.peers.iter().any(|p| {
                p.device.id == peer_device_id && (!p.outgoing.tcp.is_empty() || p.outgoing.terminal)
            })
        {
            return Err("peer is not authorized by the active network map".into());
        }
        let expected_id = peer_device_id.clone();
        let signal = self
            .client
            .connect(peer_device_id)
            .await
            .map_err(|e| e.to_string())?;
        if signal.peer.id != expected_id {
            return Err("coordinator answered for another P2P target".into());
        }
        let (map, _, _) = self.snapshot()?;
        if map.generation != signal.generation || map.revision < signal.revision {
            self.refresh().await?;
        }
        self.apply_signal(&signal, false)?;
        let key = policy::public_key(&signal.peer.public_key)?;
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            {
                let runtime = self
                    .runtime
                    .lock()
                    .map_err(|_| "runtime state unavailable")?;
                let state = runtime
                    .managed
                    .as_ref()
                    .ok_or("managed state unavailable")?;
                if state.deadline <= Instant::now() {
                    return Err("network map lease expired".into());
                }
                if !state.map.peers.iter().any(|p| {
                    p.device.id == signal.peer.id
                        && p.device.public_key == signal.peer.public_key
                        && (!p.outgoing.tcp.is_empty() || p.outgoing.terminal)
                }) {
                    return Err("peer access revoked".into());
                }
                let path = runtime.managed_path(&key)?;
                if path.state == "direct" {
                    return Ok(format!(
                        "peer={} signaling=accepted path=direct endpoint={}",
                        signal.peer.id,
                        path.endpoint.expect("verified endpoint")
                    ));
                }
            }
            if Instant::now() >= until {
                return Err("P2P direct path timed out; background retries continue".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

// iproute2 is already a runtime prerequisite. Never advertise the overlay itself,
// loopback, link-local IPv6 (which needs an interface scope), or down interfaces.
fn local_candidates(listen: std::net::SocketAddr, map: &NetworkMap) -> Vec<std::net::SocketAddr> {
    use std::net::{IpAddr, SocketAddr};
    if !listen.ip().is_unspecified() {
        return vec![listen];
    }
    let Ok(output) = std::process::Command::new("ip")
        .args(["-j", "address", "show", "up"])
        .output()
    else {
        return Vec::new();
    };
    let Ok(interfaces) = serde_json::from_slice::<Vec<serde_json::Value>>(&output.stdout) else {
        return Vec::new();
    };
    let mut result = Vec::new();
    for interface in interfaces {
        let Some(addresses) = interface["addr_info"].as_array() else {
            continue;
        };
        for address in addresses {
            if address["scope"] != "global" {
                continue;
            }
            let Some(ip) = address["local"]
                .as_str()
                .and_then(|s| s.parse::<IpAddr>().ok())
            else {
                continue;
            };
            if ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip == IpAddr::V4(map.device.ipv4)
                || ip == IpAddr::V6(map.device.ipv6)
            {
                continue;
            }
            result.push(SocketAddr::new(ip, listen.port()));
        }
    }
    result.sort();
    result.dedup();
    result
}

fn read_policy(path: &Path) -> Result<Permissions, String> {
    let bytes = private_file::read(path, 64 * 1024)?;
    policy::normalize_permissions(
        serde_json::from_slice(&bytes).map_err(|_| "invalid local permissions JSON")?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use portal_coordinator::{Coordinator, config::Config};

    #[tokio::test]
    async fn real_https_enrollment_restart_trust_and_signaling_without_tun() {
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .unwrap();
        let ca = dir.path().join("ca.pem");
        let tls_key = dir.path().join("tls.key");
        std::fs::write(&ca, cert.cert.pem()).unwrap();
        std::fs::write(&tls_key, cert.key_pair.serialize_pem()).unwrap();
        let config: Config = serde_json::from_value(serde_json::json!({"listen":"127.0.0.1:0", "state_dir":dir.path().join("server"), "tls":{"cert_file":ca,"key_file":tls_key}})).unwrap();
        let server = Coordinator::open(config).await.unwrap();
        let handle = axum_server::Handle::new();
        let task = tokio::spawn(server.serve(handle.clone()));
        let address = handle.listening().await.unwrap();
        let url = format!("https://{address}");
        let owner_file = dir.path().join("server/admin.token");
        let mut configs = Vec::new();
        for name in ["a", "b"] {
            let state = dir.path().join(name);
            std::fs::create_dir(&state).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
            let policy_file = state.join("policy.json");
            private_file::write(&policy_file, b"{}", true).unwrap();
            configs.push(ManagedConfig {
                url: url.clone(),
                device_name: name.into(),
                credential_file: state.join("device.json"),
                policy_file,
                map_file: state.join("map.json"),
                ca_file: Some(ca.clone()),
                endpoints: vec!["127.0.0.1:51820".parse().unwrap()],
                stun_servers: Vec::new(),
            });
        }
        enroll(configs[0].clone(), SecretKey([7; 32]), &owner_file)
            .await
            .unwrap();
        enroll(configs[1].clone(), SecretKey([8; 32]), &owner_file)
            .await
            .unwrap();
        assert!(
            enroll(configs[0].clone(), SecretKey([7; 32]), &owner_file)
                .await
                .is_err()
        );
        let key_a = PublicKey::from(&StaticSecret::from([7; 32])).to_bytes();
        let key_b = PublicKey::from(&StaticSecret::from([8; 32])).to_bytes();
        assert!(Prepared::load(configs[0].clone(), key_b).await.is_err());
        let a = Prepared::load(configs[0].clone(), key_a).await.unwrap();
        assert!(Prepared::load(configs[0].clone(), key_a).await.is_err());
        let b = Prepared::load(configs[1].clone(), key_b).await.unwrap();
        assert!(a.map.peers.is_empty());
        let grant = Permissions::from([(
            key_hex(&key_a),
            PeerPermissions {
                tcp: vec![443],
                terminal: false,
            },
        )]);
        b.client
            .publish_policy(&PublishPolicy {
                base_revision: b.map.policy.revision,
                permissions: grant.clone(),
            })
            .await
            .unwrap();
        let map_a = a.client.network_map(None).await.unwrap();
        let map_b = b.client.network_map(None).await.unwrap();
        assert_eq!(
            policy::compile(&map_b, &grant, key_b, Some(&b.map))
                .unwrap()
                .peers[&key_a]
                .incoming_tcp,
            [443]
        );
        assert_eq!(map_a.peers[0].outgoing.tcp, [443]);
        let client_a = a.client.clone();
        let target = b.map.device.id.clone();
        let connect = tokio::spawn(async move { client_a.connect(target).await.unwrap() });
        let signals = b.client.incoming().await.unwrap();
        assert_eq!(signals.requests.len(), 1);
        policy::validate_signal(&signals.requests[0], &map_b, &grant, true).unwrap();
        b.client
            .respond(&signals.requests[0].request_id, true)
            .await
            .unwrap();
        let signal = connect.await.unwrap();
        policy::validate_signal(&signal, &map_a, &Permissions::new(), false).unwrap();
        let wrong = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let wrong_ca = dir.path().join("wrong.pem");
        std::fs::write(&wrong_ca, wrong.cert.pem()).unwrap();
        let creds: CredentialFile = serde_json::from_slice(
            &private_file::read(&configs[0].credential_file, 65536).unwrap(),
        )
        .unwrap();
        let untrusted =
            CoordinatorClient::new(&url, creds.access_token.clone(), Some(&wrong_ca)).unwrap();
        assert!(matches!(
            untrusted.network_map(None).await,
            Err(ClientError::Tls)
        ));
        assert!(
            CoordinatorClient::new("http://127.0.0.1", creds.access_token.clone(), None).is_err()
        );
        private_file::write(
            &configs[0].map_file,
            &serde_json::to_vec(&map_a).unwrap(),
            false,
        )
        .unwrap();
        drop(a);
        let restarted = Prepared::load(configs[0].clone(), key_a).await.unwrap();
        assert_eq!(restarted.map.device.id, creds.device.id);
        drop(restarted);
        drop(b);
        handle.shutdown();
        task.await.unwrap().unwrap();
    }
}
