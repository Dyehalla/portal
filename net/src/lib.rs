mod rpc;
#[cfg(test)]
mod tests;
mod tls;
use quinn::{Connection, Endpoint, ServerConfig, Side, TransportConfig};
pub use rpc::{IncomingResponse, Registry, Request, Response, ResponseHeader, Service};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
pub(crate) type Peers = Arc<RwLock<HashMap<PeerKey, Arc<Peer>>>>;
#[derive(Debug)]
pub(crate) struct Peer {
    endpoint: Option<SocketAddr>,
    connections: Mutex<Vec<Connection>>,
    connect: tokio::sync::Mutex<()>,
}
#[derive(Clone)]
pub struct Net {
    inner: Arc<Inner>,
}
struct Inner {
    endpoint: Endpoint,
    peers: Peers,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    public_key: PeerKey,
    server: ServerConfig,
    serving: AtomicBool,
    stopped: AtomicBool,
}
impl Drop for Inner {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }
}
static TRANSPORT: LazyLock<Arc<TransportConfig>> = LazyLock::new(|| {
    let mut config = TransportConfig::default();
    config
        .max_concurrent_bidi_streams(32u32.into())
        .max_concurrent_uni_streams(0u32.into());
    config
        .stream_receive_window((1024u32 * 1024).into())
        .receive_window((8u32 * 1024 * 1024).into());
    config.send_window(8 * 1024 * 1024);
    config.max_idle_timeout(Some(
        Duration::from_secs(60).try_into().expect("valid timeout"),
    ));
    config.keep_alive_interval(Some(Duration::from_secs(15)));
    Arc::new(config)
});
impl Net {
    /// Bind an ordinary OS UDP socket. Must be called inside a Tokio runtime.
    pub fn new(seed: &[u8; 32], listen: SocketAddr) -> Result<Self, String> {
        let peers: Peers = Arc::new(RwLock::new(HashMap::new()));
        let (cert, key) = tls::identity(seed)?;
        let mut server = tls::server(cert.clone(), key.clone_key(), peers.clone())?;
        server.transport_config(Arc::clone(&TRANSPORT));
        let endpoint = Endpoint::server(server.clone(), listen).map_err(|e| e.to_string())?;
        endpoint.set_server_config(None);
        Ok(Self {
            inner: Arc::new(Inner {
                endpoint,
                peers,
                cert,
                key,
                public_key: public_key(seed),
                server,
                serving: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
            }),
        })
    }
    pub fn public_key(&self) -> PeerKey {
        self.inner.public_key
    }
    pub fn listen_addr(&self) -> SocketAddr {
        self.inner.endpoint.local_addr().expect("bound endpoint")
    }
    pub fn health(&self) -> Result<(), String> {
        if self.inner.stopped.load(Ordering::Acquire) {
            Err("QUIC endpoint stopped".into())
        } else {
            Ok(())
        }
    }
    pub fn upsert_peer(&self, key: PeerKey, endpoint: Option<SocketAddr>) -> Result<(), String> {
        self.health()?;
        ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| "invalid Ed25519 public key")?;
        if key == self.public_key()
            || endpoint
                .is_some_and(|e| e.port() == 0 || e.ip().is_unspecified() || e.ip().is_multicast())
        {
            return Err("invalid peer key or endpoint".into());
        }
        let mut peers = self.inner.peers.write().unwrap_or_else(|e| e.into_inner());
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
                connections: Mutex::new(Vec::new()),
                connect: tokio::sync::Mutex::new(()),
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
        let _guard = tokio::time::timeout_at(deadline, peer.connect.lock())
            .await
            .map_err(|_| "QUIC connection timed out")?;
        // Only reuse locally initiated connections. Incoming connections are served by the receiver.
        if let Some(connection) = peer
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|c| c.side() == Side::Client && c.close_reason().is_none())
            .cloned()
        {
            return Ok(connection);
        }
        let endpoint = peer.endpoint.ok_or("peer has no endpoint")?;
        let mut config = tls::client(
            self.inner.cert.clone(),
            self.inner.key.clone_key(),
            key,
            self.inner.peers.clone(),
        )?;
        config.transport_config(Arc::clone(&TRANSPORT));
        let connecting = self
            .inner
            .endpoint
            .connect_with(config, endpoint, "portal")
            .map_err(|e| e.to_string())?;
        // Waiting for another attempt and performing our handshake share a deadline.
        let connection = tokio::time::timeout_at(deadline, connecting)
            .await
            .map_err(|_| "QUIC connection timed out")?
            .map_err(|e| e.to_string())?;
        if let Err(error) = self.track(key, connection.clone(), Some(&peer)) {
            connection.close(0u32.into(), b"connection rejected");
            return Err(error);
        }
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
    pub fn shutdown(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        self.inner.endpoint.close(0u32.into(), b"shutdown");
    }
    pub async fn wait_idle(&self) {
        self.inner.endpoint.wait_idle().await;
    }
}
pub fn public_key(seed: &[u8; 32]) -> PeerKey {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
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
    ed25519_dalek::VerifyingKey::from_bytes(&key).map_err(|_| "invalid Ed25519 public key")?;
    Ok(key)
}
fn io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
}
