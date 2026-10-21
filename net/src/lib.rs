mod auth;
mod peer_relay;
mod rpc;
use iroh::endpoint::{Builder, Connection, QuicTransportConfig, presets};
use iroh::{Endpoint, EndpointAddr, PublicKey, SecretKey, TransportAddr};
pub use peer_relay::{RelayPeer, RelayServerConfig, RelaySnapshot};
pub use rpc::{IncomingResponse, Registry, Request, Response, ResponseHeader, Service};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        Arc, LazyLock, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

pub type PeerKey = [u8; 32];
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const ALPN: &[u8] = b"portal-rpc/1";
pub(crate) type Peers = Arc<RwLock<HashMap<PeerKey, Arc<Peer>>>>;
#[derive(Debug)]
pub(crate) struct Peer {
    endpoint: Option<SocketAddr>,
    relay: Option<RelayPeer>,
    connections: Mutex<Vec<Connection>>,
    outgoing: tokio::sync::Mutex<Option<Connection>>,
}
#[derive(Clone)]
pub struct Net {
    inner: Arc<Inner>,
}
struct Inner {
    endpoint: Endpoint,
    peers: Peers,
    relays: Vec<RelayPeer>,
    peer_relay: peer_relay::PeerRelayTransport,
    serving: AtomicBool,
    stopped: AtomicBool,
}
static TRANSPORT: LazyLock<QuicTransportConfig> = LazyLock::new(|| {
    QuicTransportConfig::builder()
        .max_concurrent_bidi_streams(32u32.into())
        .max_concurrent_uni_streams(0u32.into())
        .stream_receive_window((1024u32 * 1024).into())
        .receive_window((8u32 * 1024 * 1024).into())
        .send_window(8 * 1024 * 1024)
        .max_idle_timeout(Some(
            Duration::from_secs(60).try_into().expect("valid timeout"),
        ))
        .build()
});
impl Net {
    /// Bind iroh with explicit relay infrastructure and no public address lookup.
    /// A missing listen address enables relay-only operation.
    pub async fn new(
        seed: &[u8; 32],
        listen: Option<SocketAddr>,
        relays: Vec<RelayPeer>,
    ) -> Result<Self, String> {
        Self::with_relay_server(seed, listen, relays, None).await
    }
    pub async fn with_relay_server(
        seed: &[u8; 32],
        listen: Option<SocketAddr>,
        mut relays: Vec<RelayPeer>,
        server: Option<RelayServerConfig>,
    ) -> Result<Self, String> {
        if listen.is_none() && relays.is_empty() && server.is_none() {
            return Err("a UDP listen address or at least one relay is required".into());
        }
        for relay in &relays {
            relay.validate()?;
        }
        let peer_relay = peer_relay::PeerRelayTransport::new(seed, server).await?;
        for relay in &relays {
            peer_relay.add_relay(relay)?;
        }
        if let Some(server) = peer_relay.server() {
            relays.push(server);
        }
        let peers: Peers = Arc::new(RwLock::new(HashMap::new()));
        let mut builder = Builder::new(presets::Minimal)
            .clear_ip_transports()
            .secret_key(SecretKey::from_bytes(seed))
            .transport_config(TRANSPORT.clone())
            .add_custom_transport(Arc::new(peer_relay.clone()))
            .path_selector(Arc::new(peer_relay::PreferDirect))
            .hooks(auth::TrustedPeers(Arc::downgrade(&peers)));
        if let Some(listen) = listen {
            builder = builder.bind_addr(listen).map_err(|e| e.to_string())?;
        }
        let endpoint = builder.bind().await.map_err(|e| e.to_string())?;
        Ok(Self {
            inner: Arc::new(Inner {
                endpoint,
                peers,
                relays,
                peer_relay,
                serving: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
            }),
        })
    }
    pub fn public_key(&self) -> PeerKey {
        *self.inner.endpoint.id().as_bytes()
    }
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.inner.endpoint.bound_sockets().into_iter().next()
    }
    pub fn health(&self) -> Result<(), String> {
        if self.inner.stopped.load(Ordering::Acquire)
            || self.inner.endpoint.is_closed()
            || !self.inner.peer_relay.healthy()
        {
            Err("QUIC endpoint stopped".into())
        } else {
            Ok(())
        }
    }
    pub fn upsert_peer(
        &self,
        key: PeerKey,
        endpoint: Option<SocketAddr>,
        relay: Option<RelayPeer>,
    ) -> Result<(), String> {
        self.health()?;
        PublicKey::from_bytes(&key).map_err(|_| "invalid Ed25519 public key")?;
        if let Some(relay) = &relay {
            relay.validate()?;
        }
        if key == self.public_key()
            || endpoint
                .is_some_and(|e| e.port() == 0 || e.ip().is_unspecified() || e.ip().is_multicast())
        {
            return Err("invalid peer key or endpoint".into());
        }
        let mut peers = self.inner.peers.write().unwrap_or_else(|e| e.into_inner());
        if peers
            .get(&key)
            .is_some_and(|peer| peer.endpoint == endpoint && peer.relay == relay)
        {
            return Ok(());
        }
        // TODO: change or remove the limit
        if peers.len() >= 1024 && !peers.contains_key(&key) {
            return Err("peer limit reached".into());
        }
        if let Some(old) = peers.remove(&key) {
            for connection in old
                .connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
            {
                connection.close(0u32.into(), b"peer updated");
            }
        }
        peers.insert(
            key,
            Arc::new(Peer {
                endpoint,
                relay,
                connections: Mutex::new(Vec::new()),
                outgoing: tokio::sync::Mutex::new(None),
            }),
        );
        Ok(())
    }
    pub fn remove_peer(&self, key: &PeerKey) -> Result<(), String> {
        let peer = self
            .inner
            .peers
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key)
            .ok_or("peer not found")?;
        for connection in peer
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
        {
            connection.close(0u32.into(), b"peer removed");
        }
        Ok(())
    }
    pub fn has_peer(&self, key: &PeerKey) -> bool {
        self.inner
            .peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(key)
    }
    pub fn peers(&self) -> Vec<(PeerKey, Option<SocketAddr>)> {
        self.inner
            .peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(key, peer)| (*key, peer.endpoint))
            .collect()
    }
    fn track(
        &self,
        key: PeerKey,
        connection: Connection,
        expected: Option<&Arc<Peer>>,
    ) -> Result<(), String> {
        let peers = self.inner.peers.read().unwrap_or_else(|e| e.into_inner());
        let peer = peers.get(&key).ok_or("peer revoked")?;
        // Keep the peer map locked through insertion so an update cannot attach an
        // old handshake to a replacement peer or miss closing the new connection.
        if expected.is_some_and(|expected| !Arc::ptr_eq(expected, peer)) {
            return Err("peer changed during handshake".into());
        }
        let mut connections = peer.connections.lock().unwrap_or_else(|e| e.into_inner());
        connections.retain(|c| c.close_reason().is_none());
        if connections.len() >= 4 {
            return Err("connection limit for peer reached".into());
        }
        connections.push(connection);
        Ok(())
    }
    async fn connect(&self, key: PeerKey) -> Result<Connection, String> {
        let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
        self.health()?;
        let peer = self
            .inner
            .peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned()
            .ok_or("unregistered peer")?;
        let mut outgoing = tokio::time::timeout_at(deadline, peer.outgoing.lock())
            .await
            .map_err(|_| "QUIC connection timed out")?;
        // Keep the cache locked through the handshake so concurrent requests share one connection.
        if let Some(connection) = outgoing.as_ref().filter(|c| c.close_reason().is_none()) {
            return Ok(connection.clone());
        }
        let mut address =
            EndpointAddr::new(PublicKey::from_bytes(&key).map_err(|e| e.to_string())?);
        if let Some(endpoint) = peer.endpoint {
            address = address.with_ip_addr(endpoint);
        }
        let relays = peer
            .relay
            .as_ref()
            .map(std::slice::from_ref)
            .unwrap_or(&self.inner.relays);
        for relay in relays {
            self.inner.peer_relay.add_relay(relay)?;
            address = address.with_addrs([TransportAddr::Custom(
                self.inner.peer_relay.peer_address(relay, key),
            )]);
        }
        if address.addrs.is_empty() {
            return Err("peer has no direct address or relay".into());
        }
        // Waiting for another attempt and performing our handshake share a deadline.
        let connection =
            tokio::time::timeout_at(deadline, self.inner.endpoint.connect(address, ALPN))
                .await
                .map_err(|_| "QUIC connection timed out")?
                .map_err(|e| e.to_string())?;
        if let Err(error) = self.track(key, connection.clone(), Some(&peer)) {
            connection.close(0u32.into(), b"connection rejected");
            return Err(error);
        }
        *outgoing = Some(connection.clone());
        Ok(connection)
    }
    /// Counters for currently active QUIC sessions, not lifetime WireGuard counters.
    pub fn stats(&self, key: Option<&PeerKey>) -> Result<(usize, u64, u64), String> {
        let peers = self.inner.peers.read().unwrap_or_else(|e| e.into_inner());
        if key.is_some_and(|key| !peers.contains_key(key)) {
            return Err("peer not found".into());
        }
        let mut result = (0_usize, 0_u64, 0_u64);
        for (_, peer) in peers
            .iter()
            .filter(|(peer_key, _)| key.is_none_or(|key| key == *peer_key))
        {
            for connection in peer
                .connections
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .filter(|c| c.close_reason().is_none())
            {
                let stats = connection.stats();
                result.0 += 1;
                result.1 = result.1.saturating_add(stats.udp_tx.bytes);
                result.2 = result.2.saturating_add(stats.udp_rx.bytes);
            }
        }
        Ok(result)
    }
    /// Return the currently selected route without changing peer configuration.
    pub fn peer_path(&self, key: &PeerKey) -> Result<&'static str, String> {
        let peers = self.inner.peers.read().unwrap_or_else(|e| e.into_inner());
        let peer = peers.get(key).ok_or("peer not found")?;
        let connections = peer.connections.lock().unwrap_or_else(|e| e.into_inner());
        let mut result = "offline";
        for connection in connections.iter().filter(|c| c.close_reason().is_none()) {
            if result == "offline" {
                result = "connecting";
            }
            for path in connection.paths().iter().filter(|p| p.is_selected()) {
                match path.remote_addr() {
                    TransportAddr::Ip(_) => return Ok("direct"),
                    TransportAddr::Custom(_) => result = "relay",
                    _ => {}
                }
            }
        }
        Ok(result)
    }
    pub fn peer_relay(&self, key: &PeerKey) -> Result<Option<RelayPeer>, String> {
        self.inner
            .peers
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .map(|peer| peer.relay.clone())
            .ok_or_else(|| "peer not found".into())
    }
    pub async fn shutdown(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        self.inner.endpoint.close().await;
        self.inner.peer_relay.shutdown().await;
    }
    pub fn relay_server(&self) -> Option<RelayPeer> {
        self.inner.peer_relay.server()
    }
    pub fn relay_snapshot(&self) -> Option<RelaySnapshot> {
        self.inner.peer_relay.snapshot()
    }
    pub fn relay_is_allowed(&self, key: &PeerKey) -> bool {
        self.inner.peer_relay.is_allowed(key)
    }
    pub fn set_relay_allowed(&self, key: PeerKey, allowed: bool) -> Result<(), String> {
        self.inner.peer_relay.set_allowed(key, allowed)
    }
}
pub fn public_key(seed: &[u8; 32]) -> PeerKey {
    *SecretKey::from_bytes(seed).public().as_bytes()
}
pub fn encode_key(key: &PeerKey) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn parse_key(value: &str) -> Result<PeerKey, String> {
    if value.len() != 64 {
        return Err("public key must be 64 hexadecimal characters".into());
    }
    let mut key = [0; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(value.get(i * 2..i * 2 + 2).ok_or("invalid key")?, 16)
            .map_err(|_| "invalid public key")?;
    }
    PublicKey::from_bytes(&key).map_err(|_| "invalid Ed25519 public key")?;
    Ok(key)
}
fn io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
