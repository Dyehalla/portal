//! Device control plane: peer configuration, cryptokey routes and tunnel
//! placement. Packet processing state belongs to the selected worker.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::index_table::{IndexTable, Route, TunnelId, WorkerId};
use crate::protocol::{DH_PRIVATE, DH_PUBKEY, KEY_LEN, parse_handshake_anon};

/// Peer identity: the peer's static X25519 public key.
pub type PeerKey = [u8; KEY_LEN];

/// Network prefix used by cryptokey routing on decrypted and outgoing packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedIp {
    pub address: IpAddr,
    pub prefix_len: u8,
}

impl AllowedIp {
    /// Validates an address prefix before it enters the routing snapshot.
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, ControlError> {
        let max = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max {
            return Err(ControlError::InvalidPrefix);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    /// Tests whether `address` is within this prefix.
    pub fn contains(&self, address: IpAddr) -> bool {
        let max = match self.address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if self.prefix_len > max {
            return false;
        }
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                prefix_match(u32::from(network), u32::from(address), self.prefix_len, 32)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => prefix_match(
                u128::from(network),
                u128::from(address),
                self.prefix_len,
                128,
            ),
            _ => false,
        }
    }
}

fn prefix_match<T>(network: T, address: T, prefix: u8, width: u8) -> bool
where
    T: Copy + Into<u128>,
{
    let shift = width - prefix;
    if shift == width {
        return true;
    }
    (network.into() >> shift) == (address.into() >> shift)
}

/// A stable assignment from a peer's tunnel to one worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelAssignment {
    pub worker: WorkerId,
    pub tunnel: TunnelId,
}

impl TunnelAssignment {
    fn route(self) -> Route {
        Route {
            worker: self.worker,
            tunnel: self.tunnel,
        }
    }
}

/// Read-only peer routing data published to dispatchers and management readers.
#[derive(Debug, Clone)]
pub struct PeerRoute {
    pub assignment: TunnelAssignment,
    /// Initial peer endpoint, replaced after an authenticated roaming packet.
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<AllowedIp>,
}

/// Immutable view published to packet readers through `ArcSwap`.
pub struct DeviceSnapshot {
    identity: Arc<Identity>,
    peers: HashMap<PeerKey, PeerRoute>,
    allowed: Vec<(AllowedIp, TunnelAssignment)>,
}

impl DeviceSnapshot {
    /// Returns the device's static public key.
    pub fn static_public(&self) -> &PeerKey {
        &self.identity.public
    }

    /// Resolves the destination address by longest-prefix match.
    pub fn route_for_ip(&self, address: IpAddr) -> Option<TunnelAssignment> {
        self.allowed
            .iter()
            .find(|(prefix, _)| prefix.contains(address))
            .map(|(_, assignment)| *assignment)
    }

    /// Looks up a peer's current tunnel assignment.
    pub fn peer_route(&self, peer: &PeerKey) -> Option<&PeerRoute> {
        self.peers.get(peer)
    }

    /// Recovers the peer identity inside an authenticated-format initiation.
    /// MAC verification must happen first, before this DH operation (§5.4.2).
    pub fn identify_initiation(
        &self,
        initiation: &crate::protocol::HandshakeInitiation<'_>,
    ) -> Option<PeerKey> {
        let peer =
            parse_handshake_anon(&self.identity.private, &self.identity.public, initiation).ok()?;
        self.peers.contains_key(&peer).then_some(peer)
    }

    /// Returns the tunnel selected for this peer's inbound initiation.
    pub fn assignment_for_peer(&self, peer: &PeerKey) -> Option<TunnelAssignment> {
        self.peers.get(peer).map(|route| route.assignment)
    }

    /// Checks the authenticated inner source address against that tunnel's
    /// cryptokey routes before a plaintext packet reaches TUN.
    pub fn allows_source(&self, assignment: TunnelAssignment, address: IpAddr) -> bool {
        self.peers
            .values()
            .find(|peer| peer.assignment == assignment)
            .is_some_and(|peer| {
                peer.allowed_ips
                    .iter()
                    .any(|prefix| prefix.contains(address))
            })
    }

    /// Peer tunnel assignments for timer scheduling and initial endpoint setup.
    pub fn assignments(&self) -> Vec<(PeerKey, TunnelAssignment, Option<SocketAddr>)> {
        self.peers
            .iter()
            .map(|(peer, route)| (*peer, route.assignment, route.endpoint))
            .collect()
    }
}

struct Identity {
    private: PeerKey,
    public: PeerKey,
}

impl Drop for Identity {
    fn drop(&mut self) {
        self.private.fill(0);
    }
}

struct PeerConfig {
    preshared_key: Option<PeerKey>,
    persistent_keepalive: Option<Duration>,
    route: PeerRoute,
    stats: Arc<TunnelStats>,
}

impl Drop for PeerConfig {
    fn drop(&mut self) {
        if let Some(key) = &mut self.preshared_key {
            key.fill(0);
        }
    }
}

/// Configuration copied once when a worker creates the assigned tunnel.
#[derive(Debug)]
pub struct TunnelConfig {
    pub peer: PeerKey,
    pub assignment: TunnelAssignment,
    static_private: PeerKey,
    preshared_key: Option<PeerKey>,
    pub persistent_keepalive: Option<Duration>,
    pub(crate) stats: Arc<TunnelStats>,
}

impl TunnelConfig {
    /// Constructs a protocol tunnel owned by the assigned worker.
    pub fn build_tunnel(&self) -> crate::protocol::Tunnel {
        crate::protocol::Tunnel::new(
            self.static_private,
            self.peer,
            self.preshared_key,
            self.persistent_keepalive,
        )
    }
}

impl Drop for TunnelConfig {
    fn drop(&mut self) {
        self.static_private.fill(0);
        self.peer.fill(0);
        if let Some(key) = &mut self.preshared_key {
            key.fill(0);
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct TunnelStats {
    pub(crate) tx_bytes: AtomicU64,
    pub(crate) rx_bytes: AtomicU64,
}

/// Read-only aggregate tunnel byte counters exposed by the control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
}

/// Configuration errors that can be corrected by the management plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlError {
    /// A prefix length exceeds the width of its address family.
    InvalidPrefix,
    /// A matching prefix is already assigned to another peer.
    OverlappingRoute,
    /// At least one worker must be registered before adding peers.
    NoWorkers,
    /// Tunnel identifiers have been exhausted.
    TunnelIdExhausted,
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ControlError {}

/// Control-plane device state. Writers update configuration and publish an
/// immutable snapshot; packet readers only load the current snapshot.
pub struct Device {
    identity: Arc<Identity>,
    peers: HashMap<PeerKey, PeerConfig>,
    worker_load: BTreeMap<WorkerId, usize>,
    next_tunnel_id: TunnelId,
    snapshot: Arc<ArcSwap<DeviceSnapshot>>,
    indices: Arc<IndexTable>,
}

impl Device {
    /// Creates a control plane for a device static private key.
    pub fn new(static_private: PeerKey) -> Self {
        let private = DH_PRIVATE(&static_private);
        let identity = Arc::new(Identity {
            private: static_private,
            public: DH_PUBKEY(&private),
        });
        let snapshot = DeviceSnapshot {
            identity: Arc::clone(&identity),
            peers: HashMap::new(),
            allowed: Vec::new(),
        };
        Self {
            identity,
            peers: HashMap::new(),
            worker_load: BTreeMap::new(),
            next_tunnel_id: 1,
            snapshot: Arc::new(ArcSwap::from_pointee(snapshot)),
            indices: Arc::new(IndexTable::new()),
        }
    }

    /// Registers a worker that can own tunnels.
    pub fn register_worker(&mut self, worker: WorkerId) -> bool {
        if self.worker_load.contains_key(&worker) {
            return false;
        }
        self.worker_load.insert(worker, 0);
        true
    }

    /// Adds or replaces a peer and assigns its phase-one single tunnel to the
    /// least-loaded worker (§5.4.5).
    pub fn add_peer(
        &mut self,
        peer: PeerKey,
        preshared_key: Option<PeerKey>,
        persistent_keepalive: Option<Duration>,
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<AllowedIp>,
    ) -> Result<TunnelConfig, ControlError> {
        let Some((&worker, _)) = self
            .worker_load
            .iter()
            .min_by_key(|(id, load)| (**load, **id))
        else {
            return Err(ControlError::NoWorkers);
        };
        self.validate_routes(&peer, &allowed_ips)?;
        let tunnel = self.next_tunnel_id;
        self.next_tunnel_id = tunnel
            .checked_add(1)
            .ok_or(ControlError::TunnelIdExhausted)?;

        let stats = self
            .peers
            .get(&peer)
            .map(|config| Arc::clone(&config.stats))
            .unwrap_or_default();
        if let Some(old) = self.peers.remove(&peer) {
            self.indices.release_tunnel(old.route.assignment.route());
            if let Some(load) = self.worker_load.get_mut(&old.route.assignment.worker) {
                *load = load.saturating_sub(1);
            }
        }
        *self
            .worker_load
            .get_mut(&worker)
            .expect("selected registered worker") += 1;
        let route = PeerRoute {
            assignment: TunnelAssignment { worker, tunnel },
            endpoint,
            allowed_ips,
        };
        let assignment = route.assignment;
        self.peers.insert(
            peer,
            PeerConfig {
                preshared_key,
                persistent_keepalive,
                route,
                stats: Arc::clone(&stats),
            },
        );
        self.publish_snapshot();

        Ok(TunnelConfig {
            peer,
            assignment,
            static_private: self.identity.private,
            preshared_key,
            persistent_keepalive,
            stats,
        })
    }

    /// Removes a peer, its cryptokey routes and its receiver-index claims.
    pub fn remove_peer(&mut self, peer: &PeerKey) -> Option<TunnelAssignment> {
        let config = self.peers.remove(peer)?;
        let assignment = config.route.assignment;
        self.indices.release_tunnel(assignment.route());
        if let Some(load) = self.worker_load.get_mut(&assignment.worker) {
            *load = load.saturating_sub(1);
        };
        self.publish_snapshot();
        Some(assignment)
    }

    /// Builds a fresh tunnel configuration for a control-plane peer update.
    pub fn tunnel_config(&self, peer: &PeerKey) -> Option<TunnelConfig> {
        let config = self.peers.get(peer)?;
        Some(TunnelConfig {
            peer: *peer,
            assignment: config.route.assignment,
            static_private: self.identity.private,
            preshared_key: config.preshared_key,
            persistent_keepalive: config.persistent_keepalive,
            stats: Arc::clone(&config.stats),
        })
    }

    /// Aggregated wire-byte counters for the currently configured peer.
    pub fn peer_stats(&self, peer: &PeerKey) -> Option<PeerStats> {
        let stats = &self.peers.get(peer)?.stats;
        Some(PeerStats {
            tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
        })
    }

    /// Loads the latest immutable routing and peer snapshot for a packet batch.
    pub fn snapshot(&self) -> Arc<DeviceSnapshot> {
        self.snapshot.load_full()
    }

    /// Shared read-only snapshot handle for dispatcher and worker readers.
    pub fn snapshot_source(&self) -> Arc<ArcSwap<DeviceSnapshot>> {
        Arc::clone(&self.snapshot)
    }

    /// Returns the device-wide receiver-index table shared with dispatchers.
    pub fn index_table(&self) -> Arc<IndexTable> {
        Arc::clone(&self.indices)
    }

    /// Claims a random nonzero receiver index for one worker-owned tunnel.
    pub fn claim_index(&self, assignment: TunnelAssignment) -> Option<u32> {
        for _ in 0..128 {
            let mut bytes = [0u8; 4];
            crate::protocol::RAND(&mut bytes);
            let index = u32::from_le_bytes(bytes);
            if self.indices.try_claim(index, assignment.route()) {
                return Some(index);
            }
        }
        None
    }

    /// Releases one index if it is still owned by this tunnel.
    pub fn release_index(&self, index: u32, assignment: TunnelAssignment) -> bool {
        self.indices.release(index, assignment.route())
    }

    /// Public key used by peers to configure their endpoint.
    pub fn static_public(&self) -> &PeerKey {
        &self.identity.public
    }

    fn validate_routes(&self, peer: &PeerKey, routes: &[AllowedIp]) -> Result<(), ControlError> {
        for route in routes {
            AllowedIp::new(route.address, route.prefix_len)?;
            for (other_peer, config) in &self.peers {
                if other_peer == peer {
                    continue;
                }
                if config.route.allowed_ips.iter().any(|existing| {
                    existing.prefix_len == route.prefix_len
                        && existing.contains(route.address)
                        && route.contains(existing.address)
                }) {
                    return Err(ControlError::OverlappingRoute);
                }
            }
        }
        Ok(())
    }

    fn publish_snapshot(&self) {
        let peers = self
            .peers
            .iter()
            .map(|(key, config)| (*key, config.route.clone()))
            .collect::<HashMap<_, _>>();
        let mut allowed = self
            .peers
            .values()
            .flat_map(|config| {
                config
                    .route
                    .allowed_ips
                    .iter()
                    .copied()
                    .map(move |prefix| (prefix, config.route.assignment))
            })
            .collect::<Vec<_>>();
        allowed.sort_by(|(a, _), (b, _)| b.prefix_len.cmp(&a.prefix_len));
        self.snapshot.store(Arc::new(DeviceSnapshot {
            identity: Arc::clone(&self.identity),
            peers,
            allowed,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn key(byte: u8) -> PeerKey {
        [byte; KEY_LEN]
    }

    /// Longest-prefix lookup routes an IP packet to the most specific peer.
    #[test]
    fn cryptokey_routing_uses_the_longest_prefix() {
        let mut device = Device::new(key(1));
        assert!(device.register_worker(0));
        assert!(device.register_worker(1));
        let broad = AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).unwrap();
        let narrow = AllowedIp::new(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 0)), 16).unwrap();
        device
            .add_peer(key(2), None, None, None, vec![broad])
            .unwrap();
        let narrow_tunnel = device
            .add_peer(key(3), None, None, None, vec![narrow])
            .unwrap()
            .assignment;
        assert_eq!(
            device.snapshot().route_for_ip("10.2.4.5".parse().unwrap()),
            Some(narrow_tunnel)
        );
        assert_ne!(
            device.snapshot().route_for_ip("10.3.4.5".parse().unwrap()),
            Some(narrow_tunnel)
        );
    }

    /// IPv4 and IPv6 prefixes match only their own address family.
    #[test]
    fn allowed_ip_prefixes_match_both_address_families() {
        let v4 = AllowedIp::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24).unwrap();
        let v6 = AllowedIp::new(IpAddr::V6("2001:db8::".parse::<Ipv6Addr>().unwrap()), 32).unwrap();
        assert!(v4.contains("192.0.2.9".parse().unwrap()));
        assert!(!v4.contains("192.0.3.9".parse().unwrap()));
        assert!(v6.contains("2001:db8:1::5".parse().unwrap()));
        assert!(!v6.contains("2001:db9::5".parse().unwrap()));
    }

    /// A peer cannot take another peer's exact cryptokey prefix.
    #[test]
    fn an_allowed_ip_prefix_has_only_one_peer_owner() {
        let mut device = Device::new(key(1));
        device.register_worker(0);
        let prefix = AllowedIp::new("10.0.0.0".parse().unwrap(), 8).unwrap();
        device
            .add_peer(key(2), None, None, None, vec![prefix])
            .unwrap();
        assert_eq!(
            device
                .add_peer(key(3), None, None, None, vec![prefix])
                .unwrap_err(),
            ControlError::OverlappingRoute
        );
    }

    /// Replacing a peer publishes a fresh snapshot without its old prefixes.
    #[test]
    fn replacing_a_peer_replaces_its_published_routes() {
        let mut device = Device::new(key(1));
        device.register_worker(0);
        let old = AllowedIp::new("10.1.0.0".parse().unwrap(), 16).unwrap();
        let new = AllowedIp::new("10.2.0.0".parse().unwrap(), 16).unwrap();
        device
            .add_peer(key(2), None, None, None, vec![old])
            .unwrap();
        device
            .add_peer(key(2), None, None, None, vec![new])
            .unwrap();
        let snapshot = device.snapshot();
        assert_eq!(snapshot.route_for_ip("10.1.2.3".parse().unwrap()), None);
        assert!(snapshot.route_for_ip("10.2.2.3".parse().unwrap()).is_some());
    }
}
