use crate::{PeerKey, encode_key, parse_key};
use bytes::{Bytes, BytesMut};
use iroh::endpoint::transports::{
    Addr, CustomEndpoint, CustomSender, CustomTransport, PathSelection, PathSelectionContext,
    PathSelector, RecvInfo, Transmit,
};
use iroh::endpoint::{Builder, Connection, QuicTransportConfig, presets};
use iroh::{Endpoint, EndpointAddr, SecretKey};
use iroh_base::CustomAddr;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    sync::mpsc,
    task::{AbortHandle, JoinSet},
};

const ALPN: &[u8] = b"portal-peer-relay/1";
// Private transport ID; iroh's unstable transport API is pinned to 1.4.0.
const TRANSPORT_ID: u64 = 0x706f7274616c01;
const CHUNK: usize = 1000;
const HEADER: usize = 42; // destination/source key, packet number, part index, part count
const MAX_PACKET: usize = 2048;
const MAX_PARTS: usize = MAX_PACKET.div_ceil(CHUNK);
const QUEUE: usize = 256;
const MAX_CLIENTS: usize = 128;
const MAX_RELAYS: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelayPeer {
    #[serde(with = "key_json")]
    pub public_key: PeerKey,
    pub endpoint: SocketAddr,
}
impl RelayPeer {
    pub fn validate(&self) -> Result<(), String> {
        parse_key(&encode_key(&self.public_key))?;
        if self.endpoint.port() == 0
            || self.endpoint.ip().is_unspecified()
            || self.endpoint.ip().is_multicast()
        {
            return Err("relay endpoint must be a reachable unicast IP:port".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayServerConfig {
    pub listen: SocketAddr,
    pub public_endpoint: SocketAddr,
    #[serde(with = "key_set_json")]
    pub allowed_peers: HashSet<PeerKey>,
}
impl RelayServerConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.listen.port() == 0
            || self.listen.ip().is_multicast()
            || self.public_endpoint.port() == 0
        {
            return Err("relay ports must be nonzero and listener must be unicast".into());
        }
        let development = self.listen.ip().is_loopback() && self.public_endpoint.ip().is_loopback();
        if !development && !is_public_ip(self.public_endpoint.ip()) {
            return Err(
                "relay public_endpoint requires a public IP (loopback is allowed for local tests)"
                    .into(),
            );
        }
        if development && self.listen != self.public_endpoint {
            return Err("development relay listener and public_endpoint must match".into());
        }
        for key in &self.allowed_peers {
            parse_key(&encode_key(key))?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
pub struct RelaySnapshot {
    pub public_key: String,
    pub endpoint: SocketAddr,
    pub listen: SocketAddr,
    pub allowed_peers: Vec<String>,
    pub connected_clients: usize,
    pub forwarded_bytes: u64,
}

mod key_json {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        key: &PeerKey,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        encode_key(key).serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<PeerKey, D::Error> {
        parse_key(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}
mod key_set_json {
    use super::*;
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<HashSet<PeerKey>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .iter()
            .map(|key| parse_key(key).map_err(serde::de::Error::custom))
            .collect()
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !matches!(a, 0 | 10 | 127 | 224..=255)
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 169 && b == 254)
                && !(a == 172 && (16..=31).contains(&b))
                && !(a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                && !(a == 203 && b == 0 && c == 113)
        }
        IpAddr::V6(ip) => {
            let [a, b, ..] = ip.segments();
            a & 0xe000 == 0x2000
                && !(a == 0x2001 && (b <= 0x1ff || b == 0xdb8))
                && a != 0x2002
                && !(a == 0x3fff && b <= 0xfff)
        }
    }
}

fn address(relay: PeerKey, peer: PeerKey) -> CustomAddr {
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&relay);
    bytes[32..].copy_from_slice(&peer);
    CustomAddr::from_parts(TRANSPORT_ID, &bytes)
}
fn parse_address(address: &CustomAddr) -> io::Result<(PeerKey, PeerKey)> {
    if address.id() != TRANSPORT_ID || address.data().len() != 64 {
        return Err(io::Error::other("invalid peer relay address"));
    }
    Ok((
        address.data()[..32].try_into().expect("length checked"),
        address.data()[32..].try_into().expect("length checked"),
    ))
}

#[derive(Debug)]
struct Packet {
    source: CustomAddr,
    data: Bytes,
}
#[derive(Debug)]
struct ClientRoute {
    config: RelayPeer,
    connection: Mutex<Option<Connection>>,
}
#[derive(Debug, Default)]
struct ServerState {
    allowed: HashSet<PeerKey>,
    clients: HashMap<PeerKey, Connection>,
}
#[derive(Debug)]
struct Shared {
    endpoint: Endpoint,
    own_key: PeerKey,
    server: Option<RelayServerConfig>,
    server_state: Mutex<ServerState>,
    routes: Mutex<HashMap<PeerKey, Arc<ClientRoute>>>,
    incoming: mpsc::Sender<Packet>,
    local_addrs: n0_watcher::Watchable<Vec<CustomAddr>>,
    sequence: AtomicU64,
    forwarded: AtomicU64,
    stopped: AtomicBool,
}
#[derive(Debug, Default)]
struct Workers(Mutex<Vec<AbortHandle>>);
impl Workers {
    fn spawn(&self, future: impl std::future::Future<Output = ()> + Send + 'static) {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(tokio::spawn(future).abort_handle());
    }
}
impl Drop for Workers {
    fn drop(&mut self) {
        for task in self.0.get_mut().unwrap_or_else(|e| e.into_inner()) {
            task.abort();
        }
    }
}

/// An iroh custom transport carrying opaque inner QUIC packets in outer QUIC DATAGRAMs.
#[derive(Clone, Debug)]
pub(crate) struct PeerRelayTransport {
    shared: Arc<Shared>,
    receiver: Arc<Mutex<Option<mpsc::Receiver<Packet>>>>,
    workers: Arc<Workers>,
}
impl PeerRelayTransport {
    pub(crate) async fn new(
        seed: &[u8; 32],
        server: Option<RelayServerConfig>,
    ) -> Result<Self, String> {
        if let Some(server) = &server {
            server.validate()?;
        }
        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(1u32.into())
            .max_concurrent_uni_streams(0u32.into())
            .datagram_receive_buffer_size(Some(256 * 1024))
            .datagram_send_buffer_size(256 * 1024)
            .keep_alive_interval(Duration::from_secs(5))
            .max_idle_timeout(Some(
                Duration::from_secs(20).try_into().expect("valid timeout"),
            ))
            .build();
        let mut builder = Builder::new(presets::Minimal)
            .secret_key(SecretKey::from_bytes(seed))
            .transport_config(transport);
        if let Some(server) = &server {
            builder = builder
                .clear_ip_transports()
                .bind_addr(server.listen)
                .map_err(|e| e.to_string())?
                .alpns(vec![ALPN.to_vec()]);
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|e| format!("could not bind peer relay UDP endpoint: {e}"))?;
        let own_key = *endpoint.id().as_bytes();
        let (incoming, receiver) = mpsc::channel(QUEUE);
        let local = if server.is_some() {
            vec![address(own_key, own_key)]
        } else {
            Vec::new()
        };
        let state = ServerState {
            allowed: server
                .as_ref()
                .map(|s| s.allowed_peers.clone())
                .unwrap_or_default(),
            clients: HashMap::new(),
        };
        let shared = Arc::new(Shared {
            endpoint,
            own_key,
            server,
            server_state: Mutex::new(state),
            routes: Mutex::new(HashMap::new()),
            incoming,
            local_addrs: n0_watcher::Watchable::new(local),
            sequence: AtomicU64::new(0),
            forwarded: AtomicU64::new(0),
            stopped: AtomicBool::new(false),
        });
        let workers = Arc::new(Workers::default());
        if shared.server.is_some() {
            workers.spawn(serve(shared.clone()));
        }
        Ok(Self {
            shared,
            receiver: Arc::new(Mutex::new(Some(receiver))),
            workers,
        })
    }
    pub(crate) fn add_relay(&self, relay: &RelayPeer) -> Result<(), String> {
        relay.validate()?;
        if relay.public_key == self.shared.own_key {
            return if self.shared.server.is_some() {
                Ok(())
            } else {
                Err("a device cannot use itself as an upstream relay".into())
            };
        }
        let mut routes = self.shared.routes.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(route) = routes.get(&relay.public_key) {
            if route.config != *relay {
                return Err(
                    "relay key already registered with another endpoint; restart to change it"
                        .into(),
                );
            }
            return Ok(());
        }
        if routes.len() >= MAX_RELAYS {
            return Err("peer relay limit reached".into());
        }
        let route = Arc::new(ClientRoute {
            config: relay.clone(),
            connection: Mutex::new(None),
        });
        routes.insert(relay.public_key, route.clone());
        self.workers.spawn(client(self.shared.clone(), route));
        let mut addrs: Vec<_> = routes
            .keys()
            .map(|key| address(*key, self.shared.own_key))
            .collect();
        if self.shared.server.is_some() {
            addrs.push(address(self.shared.own_key, self.shared.own_key));
        }
        let _ = self.shared.local_addrs.set(addrs);
        Ok(())
    }
    pub(crate) fn peer_address(&self, relay: &RelayPeer, peer: PeerKey) -> CustomAddr {
        address(relay.public_key, peer)
    }
    pub(crate) fn server(&self) -> Option<RelayPeer> {
        self.shared.server.as_ref().map(|config| RelayPeer {
            public_key: self.shared.own_key,
            endpoint: config.public_endpoint,
        })
    }
    pub(crate) fn snapshot(&self) -> Option<RelaySnapshot> {
        let config = self.shared.server.as_ref()?;
        let state = self
            .shared
            .server_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut allowed_peers: Vec<_> = state.allowed.iter().map(encode_key).collect();
        allowed_peers.sort();
        Some(RelaySnapshot {
            public_key: encode_key(&self.shared.own_key),
            endpoint: config.public_endpoint,
            listen: config.listen,
            allowed_peers,
            connected_clients: state.clients.len(),
            forwarded_bytes: self.shared.forwarded.load(Ordering::Relaxed),
        })
    }
    pub(crate) fn is_allowed(&self, key: &PeerKey) -> bool {
        self.shared
            .server_state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .allowed
            .contains(key)
    }
    pub(crate) fn set_allowed(&self, key: PeerKey, allowed: bool) -> Result<(), String> {
        if self.shared.server.is_none() {
            return Err("this device does not host a peer relay".into());
        }
        parse_key(&encode_key(&key))?;
        let mut state = self
            .shared
            .server_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if allowed {
            state.allowed.insert(key);
        } else {
            state.allowed.remove(&key);
            if let Some(connection) = state.clients.remove(&key) {
                connection.close(403u32.into(), b"relay access revoked");
            }
        }
        Ok(())
    }
    pub(crate) fn healthy(&self) -> bool {
        !self.shared.endpoint.is_closed()
    }
    pub(crate) async fn shutdown(&self) {
        self.shared.stopped.store(true, Ordering::Release);
        self.shared.endpoint.close().await;
    }
}

async fn serve(shared: Arc<Shared>) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CLIENTS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            incoming = shared.endpoint.accept() => {
                let Some(incoming) = incoming else { break; };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let shared = shared.clone();
                tasks.spawn(async move {
                    let _slot = slot;
                    if let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(5), incoming).await {
                        serve_client(shared, connection).await;
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

/// Registration and permission changes share a lock, including admission of an in-flight handshake.
async fn register_client(shared: &Shared, connection: &Connection) -> Result<(), String> {
    let key = *connection.remote_id().as_bytes();
    if connection.max_datagram_size().unwrap_or(0) < HEADER + CHUNK {
        return Err("relay datagrams too small".into());
    }
    let (mut send, mut recv) = connection.accept_bi().await.map_err(|e| e.to_string())?;
    if recv.read_to_end(1).await.map_err(|e| e.to_string())? != [1] {
        return Err("invalid relay registration".into());
    }
    {
        let mut state = shared
            .server_state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !state.allowed.contains(&key)
            || state
                .clients
                .get(&key)
                .is_some_and(|old| old.close_reason().is_none())
        {
            return Err("relay access denied or already connected".into());
        }
        state.clients.insert(key, connection.clone());
    }
    send.write_all(&[1]).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    Ok(())
}

async fn serve_client(shared: Arc<Shared>, connection: Connection) {
    let key = *connection.remote_id().as_bytes();
    let registered = tokio::time::timeout(
        Duration::from_secs(5),
        register_client(&shared, &connection),
    )
    .await;
    if !matches!(registered, Ok(Ok(()))) {
        connection.close(403u32.into(), b"relay registration rejected");
    } else {
        let mut assembler = Assembler::default();
        while let Ok(data) = connection.read_datagram().await {
            let Some(target) = frame_key(&data) else {
                continue;
            };
            let state = shared
                .server_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !authorized(&state, &key, &connection) {
                break;
            }
            if target == shared.own_key {
                if let Some(packet) = assembler.push(key, data) {
                    let _ = shared.incoming.try_send(Packet {
                        source: address(shared.own_key, key),
                        data: packet,
                    });
                }
            } else if state.allowed.contains(&target)
                && let Some(destination) = state.clients.get(&target)
            {
                let mut forwarded = BytesMut::from(data.as_ref());
                // The sender key comes from the authenticated connection, never from the packet.
                forwarded[..32].copy_from_slice(&key);
                if destination.send_datagram(forwarded.freeze()).is_ok() {
                    shared
                        .forwarded
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
        }
    }
    let mut state = shared
        .server_state
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if state
        .clients
        .get(&key)
        .is_some_and(|current| current.stable_id() == connection.stable_id())
    {
        state.clients.remove(&key);
    }
    connection.close(0u32.into(), b"relay session ended");
}

fn authorized(state: &ServerState, key: &PeerKey, connection: &Connection) -> bool {
    state.allowed.contains(key)
        && state
            .clients
            .get(key)
            .is_some_and(|current| current.stable_id() == connection.stable_id())
}

async fn client(shared: Arc<Shared>, route: Arc<ClientRoute>) {
    while !shared.stopped.load(Ordering::Acquire) {
        let session = async {
            let key =
                iroh::PublicKey::from_bytes(&route.config.public_key).map_err(|e| e.to_string())?;
            let connection = shared
                .endpoint
                .connect(
                    EndpointAddr::new(key).with_ip_addr(route.config.endpoint),
                    ALPN,
                )
                .await
                .map_err(|e| e.to_string())?;
            let (mut send, mut recv) = connection.open_bi().await.map_err(|e| e.to_string())?;
            send.write_all(&[1]).await.map_err(|e| e.to_string())?;
            send.finish().map_err(|e| e.to_string())?;
            if recv.read_to_end(1).await.map_err(|e| e.to_string())? != [1] {
                return Err("relay registration failed".to_owned());
            }
            if connection.max_datagram_size().unwrap_or(0) < HEADER + CHUNK {
                return Err("relay datagrams too small".into());
            }
            Ok::<_, String>(connection)
        };
        if let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(8), session).await {
            *route.connection.lock().unwrap_or_else(|e| e.into_inner()) = Some(connection.clone());
            let mut assembler = Assembler::default();
            while let Ok(data) = connection.read_datagram().await {
                if let Some(source) = frame_key(&data)
                    && let Some(packet) = assembler.push(source, data)
                {
                    let _ = shared.incoming.try_send(Packet {
                        source: address(route.config.public_key, source),
                        data: packet,
                    });
                }
            }
            *route.connection.lock().unwrap_or_else(|e| e.into_inner()) = None;
            connection.close(0u32.into(), b"relay session ended");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn frame_key(data: &[u8]) -> Option<PeerKey> {
    if data.len() <= HEADER || data.len() > HEADER + CHUNK {
        return None;
    }
    let part = data[40] as usize;
    let count = data[41] as usize;
    if count == 0
        || count > MAX_PARTS
        || part >= count
        || (part + 1 < count && data.len() != HEADER + CHUNK)
    {
        return None;
    }
    data[..32].try_into().ok()
}
#[derive(Default)]
struct Assembler {
    parts: HashMap<(PeerKey, u64), PartialPacket>,
}
struct PartialPacket {
    created: Instant,
    count: usize,
    chunks: [Option<Bytes>; MAX_PARTS],
}
impl Assembler {
    fn push(&mut self, source: PeerKey, data: Bytes) -> Option<Bytes> {
        frame_key(&data)?;
        let count = data[41] as usize;
        if count == 1 {
            return Some(data.slice(HEADER..));
        }
        self.parts
            .retain(|_, part| part.created.elapsed() < Duration::from_secs(2));
        let id = u64::from_be_bytes(data[32..40].try_into().ok()?);
        let key = (source, id);
        if self.parts.len() >= 64 && !self.parts.contains_key(&key) {
            return None;
        }
        let part = self.parts.entry(key).or_insert_with(|| PartialPacket {
            created: Instant::now(),
            count,
            chunks: Default::default(),
        });
        if part.count != count {
            return None;
        }
        part.chunks[data[40] as usize] = Some(data.slice(HEADER..));
        if part.chunks[..count].iter().any(Option::is_none) {
            return None;
        }
        let part = self.parts.remove(&key)?;
        let len: usize = part.chunks[..count].iter().flatten().map(Bytes::len).sum();
        if len > MAX_PACKET {
            return None;
        }
        let mut packet = BytesMut::with_capacity(len);
        for chunk in part.chunks[..count].iter().flatten() {
            packet.extend_from_slice(chunk);
        }
        Some(packet.freeze())
    }
}

#[derive(Debug)]
struct RelayEndpoint {
    transport: PeerRelayTransport,
    receiver: mpsc::Receiver<Packet>,
}
impl CustomTransport for PeerRelayTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let receiver = self
            .receiver
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or_else(|| io::Error::other("peer relay transport already bound"))?;
        Ok(Box::new(RelayEndpoint {
            transport: self.clone(),
            receiver,
        }))
    }
}
impl CustomEndpoint for RelayEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.transport.shared.local_addrs.watch()
    }
    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(self.transport.clone())
    }
    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        if bufs.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            match self.receiver.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("peer relay stopped")));
                }
                Poll::Ready(Some(packet)) => {
                    if packet.data.len() > bufs[0].len() {
                        continue;
                    }
                    bufs[0][..packet.data.len()].copy_from_slice(&packet.data);
                    metas[0] = noq_udp::RecvMeta::default();
                    metas[0].len = packet.data.len();
                    metas[0].stride = packet.data.len();
                    infos[0] = RecvInfo::new(packet.source, None);
                    return Poll::Ready(Ok(1));
                }
            }
        }
    }
}
impl CustomSender for PeerRelayTransport {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        parse_address(addr).is_ok()
    }
    fn poll_send(
        &self,
        _cx: &mut Context<'_>,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let (relay, target) = match parse_address(dst) {
            Ok(pair) => pair,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let connection = if relay == self.shared.own_key {
            let state = self
                .shared
                .server_state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if !state.allowed.contains(&target) {
                return Poll::Ready(Ok(()));
            }
            state.clients.get(&target).cloned()
        } else {
            self.shared
                .routes
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&relay)
                .and_then(|route| {
                    route
                        .connection
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clone()
                })
        };
        let Some(connection) = connection else {
            return Poll::Ready(Ok(()));
        };
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for packet in transmit.contents.chunks(segment) {
            if packet.is_empty() || packet.len() > MAX_PACKET {
                continue;
            }
            let sequence = self.shared.sequence.fetch_add(1, Ordering::Relaxed);
            let count = packet.len().div_ceil(CHUNK);
            for (index, chunk) in packet.chunks(CHUNK).enumerate() {
                let mut data = BytesMut::with_capacity(HEADER + chunk.len());
                data.extend_from_slice(if relay == self.shared.own_key {
                    &self.shared.own_key
                } else {
                    &target
                });
                data.extend_from_slice(&sequence.to_be_bytes());
                data.extend_from_slice(&[index as u8, count as u8]);
                data.extend_from_slice(chunk);
                let _ = connection.send_datagram(data.freeze());
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Prefer a working direct UDP path over the peer relay, regardless of relay RTT.
#[derive(Debug)]
pub(crate) struct PreferDirect;
impl PathSelector for PreferDirect {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let mut selection = PathSelection::none();
        if let Some(path) = ctx
            .paths()
            .filter_map(|p| p.stats().map(|s| (p, s.rtt)))
            .min_by_key(|(p, rtt)| (!matches!(p.network_path().remote(), Addr::Ip(_)), *rtt))
            .map(|(p, _)| p)
        {
            selection.set(&path);
        }
        selection
    }
}
