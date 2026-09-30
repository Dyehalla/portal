use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use boringtun::noise::Tunn;
use zeroize::Zeroize;

use super::{AllowedIp, PeerKey, PeerStats};

pub(crate) struct DeviceState {
    pub peers: HashMap<PeerKey, Arc<Peer>>,
    by_index: HashMap<u32, Arc<Peer>>,
    routes: RouteTable,
    pub next_peer_index: u32,
}

impl Default for DeviceState {
    fn default() -> Self {
        Self {
            peers: HashMap::new(),
            by_index: HashMap::new(),
            routes: RouteTable::default(),
            next_peer_index: 1,
        }
    }
}

impl DeviceState {
    /// Register a peer, its receiver index, and its AllowedIPs routes.
    pub fn insert(&mut self, peer: Arc<Peer>, allowed_ips: Vec<AllowedIp>) {
        self.by_index.insert(peer.index, Arc::clone(&peer));
        self.peers.insert(peer.public_key, Arc::clone(&peer));
        for prefix in allowed_ips {
            self.routes.insert(prefix, Arc::clone(&peer));
        }
    }

    /// Replace all routes currently owned by a peer.
    pub fn replace_routes(&mut self, peer: &Arc<Peer>, allowed_ips: Vec<AllowedIp>) {
        self.routes.remove_peer(peer);
        for prefix in allowed_ips {
            self.routes.insert(prefix, Arc::clone(peer));
        }
    }

    /// Swap a peer runtime and update its indices and routes in this registry write.
    pub fn replace_peer(
        &mut self,
        old_peer: &Arc<Peer>,
        new_peer: Arc<Peer>,
        allowed_ips: Vec<AllowedIp>,
    ) {
        self.peers
            .insert(new_peer.public_key, Arc::clone(&new_peer));
        self.by_index.remove(&old_peer.index);
        self.by_index.insert(new_peer.index, Arc::clone(&new_peer));
        self.routes.remove_peer(old_peer);
        for prefix in allowed_ips {
            self.routes.insert(prefix, Arc::clone(&new_peer));
        }
    }

    /// Remove a peer and the routes and receiver index that still belong to it.
    pub fn remove(&mut self, public_key: &PeerKey) -> Option<Arc<Peer>> {
        let peer = self.peers.remove(public_key)?;
        self.by_index.remove(&peer.index);
        self.routes.remove_peer(&peer);
        Some(peer)
    }

    /// Resolve BoringTun's encoded receiver index to its owning peer.
    pub fn by_receiver_index(&self, receiver_index: u32) -> Option<Arc<Peer>> {
        self.by_index.get(&(receiver_index >> 8)).cloned()
    }

    /// Find the peer with the longest matching IPv4 or IPv6 prefix.
    pub fn by_route(&self, address: IpAddr) -> Option<Arc<Peer>> {
        self.routes.find(address)
    }
}

#[derive(Default)]
struct RouteTable {
    ipv4: RouteNode,
    ipv6: RouteNode,
}

#[derive(Default)]
struct RouteNode {
    peer: Option<Arc<Peer>>,
    zero: Option<Box<RouteNode>>,
    one: Option<Box<RouteNode>>,
}

impl RouteTable {
    /// Insert a prefix, replacing the owner of an identical prefix.
    fn insert(&mut self, prefix: AllowedIp, peer: Arc<Peer>) {
        match prefix.network() {
            IpAddr::V4(network) => {
                self.ipv4
                    .insert(u32::from(network) as u128, 32, prefix.prefix_len(), peer)
            }
            IpAddr::V6(network) => {
                self.ipv6
                    .insert(u128::from(network), 128, prefix.prefix_len(), peer)
            }
        }
    }

    /// Return the longest-prefix route matching an address.
    fn find(&self, address: IpAddr) -> Option<Arc<Peer>> {
        match address {
            IpAddr::V4(address) => self.ipv4.find(u32::from(address) as u128, 32),
            IpAddr::V6(address) => self.ipv6.find(u128::from(address), 128),
        }
    }

    /// Remove this peer's routes while preserving routes owned by others.
    fn remove_peer(&mut self, peer: &Arc<Peer>) {
        self.ipv4.remove_peer(peer);
        self.ipv6.remove_peer(peer);
    }
}

impl RouteNode {
    /// Walk the prefix bits and store its owner at the terminal trie node.
    fn insert(&mut self, address: u128, address_bits: u8, prefix_len: u8, peer: Arc<Peer>) {
        let mut node = self;
        for depth in 0..prefix_len {
            let bit = (address >> (address_bits - depth - 1)) & 1;
            let child = if bit == 0 {
                &mut node.zero
            } else {
                &mut node.one
            };
            node = child.get_or_insert_with(|| Box::new(RouteNode::default()));
        }
        // A duplicate prefix belongs to the most recently configured peer,
        // matching the single-owner semantics of WireGuard's AllowedIPs trie.
        node.peer = Some(peer);
    }

    /// Track the most specific owner encountered while walking address bits.
    fn find(&self, address: u128, address_bits: u8) -> Option<Arc<Peer>> {
        let mut node = self;
        let mut matched = node.peer.clone();
        for depth in 0..address_bits {
            let bit = (address >> (address_bits - depth - 1)) & 1;
            let child = if bit == 0 {
                node.zero.as_deref()
            } else {
                node.one.as_deref()
            };
            let Some(child) = child else {
                break;
            };
            node = child;
            if node.peer.is_some() {
                matched = node.peer.clone();
            }
        }
        matched
    }

    /// Remove routes owned by this peer and prune empty nodes. Returns true
    /// when this subtree has no route or children left.
    fn remove_peer(&mut self, peer: &Arc<Peer>) -> bool {
        if self
            .peer
            .as_ref()
            .is_some_and(|owner| Arc::ptr_eq(owner, peer))
        {
            self.peer = None;
        }
        if self
            .zero
            .as_mut()
            .is_some_and(|child| child.remove_peer(peer))
        {
            self.zero = None;
        }
        if self
            .one
            .as_mut()
            .is_some_and(|child| child.remove_peer(peer))
        {
            self.one = None;
        }
        self.peer.is_none() && self.zero.is_none() && self.one.is_none()
    }
}

pub(crate) struct Peer {
    pub public_key: PeerKey,
    pub index: u32,
    pub runtime: Mutex<PeerRuntime>,
    counters: PeerCounters,
}

impl Peer {
    /// Create the shared runtime and counters for one configured peer.
    pub fn new(public_key: PeerKey, index: u32, runtime: PeerRuntime) -> Self {
        Self {
            public_key,
            index,
            runtime: Mutex::new(runtime),
            counters: PeerCounters::default(),
        }
    }

    /// Read a snapshot of the peer's atomic traffic counters.
    pub fn stats(&self) -> PeerStats {
        PeerStats {
            tx_packets: self.counters.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.counters.tx_bytes.load(Ordering::Relaxed),
            rx_packets: self.counters.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.counters.rx_bytes.load(Ordering::Relaxed),
        }
    }

    /// Count an inner IP packet accepted by BoringTun for transmission.
    pub fn count_tx(&self, bytes: usize) {
        self.counters.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.counters
            .tx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Count an authenticated inner packet after it has been written to TUN.
    pub fn count_rx(&self, bytes: usize) {
        self.counters.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.counters
            .rx_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct PeerCounters {
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
}

pub(crate) struct PeerRuntime {
    pub tunnel: Tunn,
    pub endpoint: Option<SocketAddr>,
    pub preshared_key: Option<PeerKey>,
    pub keepalive: Option<u16>,
    pub pending_handshake: bool,
}

impl Drop for PeerRuntime {
    fn drop(&mut self) {
        if let Some(key) = &mut self.preshared_key {
            key.zeroize();
        }
    }
}
