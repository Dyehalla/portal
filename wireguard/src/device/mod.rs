mod config;
pub(crate) mod registry;

pub use config::{AllowedIp, AllowedIpParseError, PeerKey};

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::platform::PacketIo;
use crate::runtime::worker::{self, WorkerContext};
use registry::{DeviceState, Peer, PeerRuntime};

const DEFAULT_WORKERS: usize = 4;
const MAX_WORKERS: usize = 256;
const DEFAULT_HANDSHAKE_RATE_LIMIT: u64 = 100;
const MAX_PEER_INDEX: u32 = 0x00ff_ffff;
pub(crate) const MAX_DATAGRAM_SIZE: usize = 66_000;
pub(crate) const TIMER_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Runtime configuration for one WireGuard interface.
pub struct DeviceConfig {
    /// The device's WireGuard private key.
    pub private_key: PeerKey,
    /// Primary UDP address to bind. Port zero lets the OS select a port.
    /// With `dual_stack`, the other family also gets a wildcard socket on this port.
    pub listen: SocketAddr,
    /// Bind a wildcard socket for the other IP family on the same port. Defaults to true.
    pub dual_stack: bool,
    /// Name of the TUN interface to open or create.
    pub tun_name: String,
    /// Number of packet workers. Zero is invalid.
    pub workers: usize,
    /// Handshakes per second allowed before cookies are required. Zero is invalid.
    pub handshake_rate_limit: u64,
}

impl DeviceConfig {
    /// Construct a configuration using the available parallelism as its worker count.
    pub fn new(private_key: PeerKey, listen: SocketAddr, tun_name: impl Into<String>) -> Self {
        Self {
            private_key,
            listen,
            dual_stack: true,
            tun_name: tun_name.into(),
            workers: std::thread::available_parallelism()
                .map_or(DEFAULT_WORKERS, |count| count.get().min(MAX_WORKERS)),
            handshake_rate_limit: DEFAULT_HANDSHAKE_RATE_LIMIT,
        }
    }
}

/// Configuration for a peer. `allowed_ips` provides both outbound routing and
/// inbound source validation. On an existing peer, `endpoint: None` preserves
/// its endpoint; call `clear_peer_endpoint` to remove it.
pub struct PeerConfig {
    pub public_key: PeerKey,
    pub preshared_key: Option<PeerKey>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<Duration>,
    pub allowed_ips: Vec<AllowedIp>,
}

impl Drop for PeerConfig {
    fn drop(&mut self) {
        if let Some(key) = &mut self.preshared_key {
            key.zeroize();
        }
    }
}

/// Aggregate device counters.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DeviceStats {
    pub received_udp_packets: u64,
    pub received_tun_packets: u64,
    pub dropped_packets: u64,
    /// Timer-generated UDP sends that failed.
    pub timer_send_errors: u64,
    /// UDP sends outside the packet-forwarding path that failed.
    pub udp_send_errors: u64,
}

/// Per-peer inner-IP counters. `tx` counts packets accepted by BoringTun for
/// transmission; it does not mean the remote peer acknowledged delivery.
/// `rx` counts authenticated packets successfully written to TUN.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PeerStats {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

/// Errors returned by device lifecycle and peer management operations.
#[derive(Debug)]
pub enum DeviceError {
    InvalidWorkerCount,
    InvalidHandshakeRateLimit,
    InvalidKeepalive,
    TooManyPeers,
    PeerNotFound,
    ShuttingDown,
    Io(io::Error),
    WorkerPanicked,
    WorkerFailed(String),
}

impl fmt::Display for DeviceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWorkerCount => f.write_str("worker count must be greater than zero"),
            Self::InvalidHandshakeRateLimit => {
                f.write_str("handshake rate limit must be greater than zero")
            }
            Self::InvalidKeepalive => f.write_str("persistent keepalive must fit in u16 seconds"),
            Self::TooManyPeers => f.write_str("device has exhausted its peer index space"),
            Self::PeerNotFound => f.write_str("peer was not found"),
            Self::ShuttingDown => f.write_str("device is shutting down"),
            Self::Io(error) => write!(f, "device I/O error: {error}"),
            Self::WorkerPanicked => f.write_str("a device worker panicked"),
            Self::WorkerFailed(message) => write!(f, "a device worker failed: {message}"),
        }
    }
}

impl std::error::Error for DeviceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DeviceError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub(crate) struct SecretKey(pub(crate) PeerKey);

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Owns one WireGuard interface and starts its packet workers at construction.
pub struct Device {
    state: Arc<RwLock<DeviceState>>,
    io: Option<Arc<PacketIo>>,
    stopping: Arc<AtomicBool>,
    workers: Vec<JoinHandle<io::Result<()>>>,
    worker_failure: Arc<Mutex<Option<WorkerFailure>>>,
    stats: Arc<DeviceCounters>,
    device_private_key: Arc<SecretKey>,
    device_public_key: PeerKey,
    rate_limiter: Arc<RateLimiter>,
    management: Mutex<()>,
    listen_addr: SocketAddr,
}

#[derive(Default)]
pub(crate) struct DeviceCounters {
    pub(crate) received_udp_packets: AtomicU64,
    pub(crate) received_tun_packets: AtomicU64,
    pub(crate) dropped_packets: AtomicU64,
    pub(crate) timer_send_errors: AtomicU64,
    pub(crate) udp_send_errors: AtomicU64,
}

#[derive(Clone)]
enum WorkerFailure {
    Io(String),
    Panicked,
}

impl Device {
    /// Create the interface, bind UDP and start the configured workers.
    pub fn new(mut config: DeviceConfig) -> Result<Self, DeviceError> {
        if config.workers == 0 || config.workers > MAX_WORKERS {
            return Err(DeviceError::InvalidWorkerCount);
        }
        if config.handshake_rate_limit == 0 {
            return Err(DeviceError::InvalidHandshakeRateLimit);
        }

        let private_key = Arc::new(SecretKey(config.private_key));
        config.private_key.zeroize();
        let private = StaticSecret::from(private_key.0);
        let public = PublicKey::from(&private);
        let public_key = *public.as_bytes();
        drop(private);

        let io = Arc::new(PacketIo::open(
            config.listen,
            &config.tun_name,
            config.dual_stack,
        )?);
        let listen_addr = io.local_addr()?;
        let rate_limiter = Arc::new(RateLimiter::new(&public, config.handshake_rate_limit));
        let state = Arc::new(RwLock::new(DeviceState::default()));
        let stopping = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(DeviceCounters::default());
        let worker_failure = Arc::new(Mutex::new(None));
        let mut workers = Vec::with_capacity(config.workers);
        let mut worker_ios = Vec::with_capacity(config.workers);
        for _ in 0..config.workers {
            worker_ios.push(io.create_worker()?);
        }

        for (worker_id, worker_io) in worker_ios.into_iter().enumerate() {
            let context = WorkerContext {
                worker_id,
                io: Arc::clone(&io),
                worker_io,
                state: Arc::clone(&state),
                stopping: Arc::clone(&stopping),
                stats: Arc::clone(&stats),
                rate_limiter: Arc::clone(&rate_limiter),
                local_private_key: Arc::clone(&private_key),
                local_public_key: public_key,
            };
            let failure = Arc::clone(&worker_failure);
            let thread_stopping = Arc::clone(&stopping);
            let thread_io = Arc::clone(&io);
            match thread::Builder::new()
                .name(format!("portal-device-{worker_id}"))
                .spawn(
                    move || match catch_unwind(AssertUnwindSafe(|| worker::run(context))) {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(error)) => {
                            *lock(&failure) = Some(WorkerFailure::Io(error.to_string()));
                            thread_stopping.store(true, Ordering::Release);
                            thread_io.wake_all();
                            Err(error)
                        }
                        Err(_) => {
                            *lock(&failure) = Some(WorkerFailure::Panicked);
                            thread_stopping.store(true, Ordering::Release);
                            thread_io.wake_all();
                            Err(io::Error::other("device worker panicked"))
                        }
                    },
                ) {
                Ok(thread) => workers.push(thread),
                Err(error) => {
                    stopping.store(true, Ordering::Release);
                    io.wake_all();
                    for thread in workers.drain(..) {
                        let _ = thread.join();
                    }
                    return Err(DeviceError::Io(error));
                }
            }
        }

        Ok(Self {
            state,
            io: Some(io),
            stopping,
            workers,
            worker_failure,
            stats,
            device_private_key: private_key,
            device_public_key: public_key,
            rate_limiter,
            management: Mutex::new(()),
            listen_addr,
        })
    }

    /// Return the UDP address selected for the device.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    /// Return the device's WireGuard public key.
    pub fn public_key(&self) -> PeerKey {
        self.device_public_key
    }

    /// Add a peer or atomically replace its routes and configuration.
    pub fn upsert_peer(&self, mut config: PeerConfig) -> Result<(), DeviceError> {
        self.ensure_running()?;
        let _management = lock(&self.management);
        self.ensure_running()?;
        let keepalive = match config.persistent_keepalive {
            Some(value)
                if value.as_secs() > 0
                    && value.as_secs() <= u16::MAX as u64
                    && value.subsec_nanos() == 0 =>
            {
                Some(value.as_secs() as u16)
            }
            Some(_) => return Err(DeviceError::InvalidKeepalive),
            None => None,
        };
        let key = config.public_key;
        let requested_endpoint = config.endpoint;
        let existing = read_lock(&self.state).peers.get(&key).cloned();
        let mut pending_handshake = None;
        if let Some(existing) = existing {
            let psk = config.preshared_key;
            let (replace_tunnel, old_endpoint) = {
                let runtime = lock(&existing.runtime);
                (
                    runtime.preshared_key != psk || runtime.keepalive != keepalive,
                    runtime.endpoint,
                )
            };
            if replace_tunnel {
                let index = self.reserve_peer_index()?;
                let replacement = Arc::new(Peer::new(
                    key,
                    index,
                    PeerRuntime {
                        tunnel: self.make_tunnel(key, psk, keepalive, index),
                        endpoint: requested_endpoint.or(old_endpoint),
                        preshared_key: psk,
                        keepalive,
                        pending_handshake: false,
                    },
                ));
                write_lock(&self.state).replace_peer(
                    &existing,
                    replacement,
                    std::mem::take(&mut config.allowed_ips),
                );
            } else {
                let mut state = write_lock(&self.state);
                state.replace_routes(&existing, std::mem::take(&mut config.allowed_ips));
                if let Some(endpoint) = requested_endpoint {
                    lock(&existing.runtime).endpoint = Some(endpoint);
                }
                drop(state);
                if requested_endpoint.is_some() {
                    pending_handshake = prepare_pending_handshake(&existing);
                }
            }
            drop(_management);
            if let (Some(endpoint), Some(packet)) = (requested_endpoint, pending_handshake) {
                let result = self
                    .io
                    .as_ref()
                    .expect("running device owns its backend")
                    .send_udp(endpoint, &packet);
                if result.is_ok() {
                    lock(&existing.runtime).pending_handshake = false;
                } else {
                    self.stats.udp_send_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            return Ok(());
        }

        let index = self.reserve_peer_index()?;
        let peer = Arc::new(Peer::new(
            key,
            index,
            PeerRuntime {
                tunnel: self.make_tunnel(key, config.preshared_key, keepalive, index),
                endpoint: config.endpoint,
                preshared_key: config.preshared_key,
                keepalive,
                pending_handshake: false,
            },
        ));
        write_lock(&self.state).insert(peer, std::mem::take(&mut config.allowed_ips));
        drop(_management);
        Ok(())
    }

    /// Remove a peer and all of its route and receiver-index entries.
    pub fn remove_peer(&self, public_key: &PeerKey) -> Result<(), DeviceError> {
        self.ensure_running()?;
        let _management = lock(&self.management);
        self.ensure_running()?;
        let removed = write_lock(&self.state).remove(public_key);
        removed.map(|_| ()).ok_or(DeviceError::PeerNotFound)
    }

    /// Set or replace a peer's current UDP endpoint. A pending handshake is
    /// sent best-effort; failures are reported by `DeviceStats::udp_send_errors`.
    pub fn set_peer_endpoint(
        &self,
        public_key: &PeerKey,
        endpoint: SocketAddr,
    ) -> Result<(), DeviceError> {
        self.ensure_running()?;
        let _management = lock(&self.management);
        self.ensure_running()?;
        let peer = self.peer(public_key)?;
        let mut buffer = Vec::new();
        let pending = {
            let mut runtime = lock(&peer.runtime);
            runtime.endpoint = Some(endpoint);
            if runtime.pending_handshake {
                buffer.resize(MAX_DATAGRAM_SIZE, 0);
                match runtime
                    .tunnel
                    .format_handshake_initiation(&mut buffer, true)
                {
                    TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
                    _ => None,
                }
            } else {
                None
            }
        };
        if let Some(packet) = pending {
            let result = self
                .io
                .as_ref()
                .expect("running device owns its backend")
                .send_udp(endpoint, &packet);
            if result.is_err() {
                self.stats.udp_send_errors.fetch_add(1, Ordering::Relaxed);
            } else {
                lock(&peer.runtime).pending_handshake = false;
            }
        }
        Ok(())
    }

    /// Clear a peer's current UDP endpoint.
    pub fn clear_peer_endpoint(&self, public_key: &PeerKey) -> Result<(), DeviceError> {
        self.ensure_running()?;
        let _management = lock(&self.management);
        self.ensure_running()?;
        let peer = self.peer(public_key)?;
        lock(&peer.runtime).endpoint = None;
        Ok(())
    }

    /// Read aggregate packet counters.
    pub fn stats(&self) -> DeviceStats {
        DeviceStats {
            received_udp_packets: self.stats.received_udp_packets.load(Ordering::Relaxed),
            received_tun_packets: self.stats.received_tun_packets.load(Ordering::Relaxed),
            dropped_packets: self.stats.dropped_packets.load(Ordering::Relaxed),
            timer_send_errors: self.stats.timer_send_errors.load(Ordering::Relaxed),
            udp_send_errors: self.stats.udp_send_errors.load(Ordering::Relaxed),
        }
    }

    /// Read packet counters for one peer.
    pub fn peer_stats(&self, public_key: &PeerKey) -> Result<PeerStats, DeviceError> {
        Ok(self.peer(public_key)?.stats())
    }

    /// Return an error if a worker has failed or the device is shutting down.
    pub fn health(&self) -> Result<(), DeviceError> {
        self.ensure_running()
    }

    /// Wake and join all packet workers. Repeated calls are harmless.
    pub fn shutdown(&mut self) -> Result<(), DeviceError> {
        if !self.stopping.swap(true, Ordering::AcqRel) {
            if let Some(io) = self.io.as_ref() {
                io.wake_all();
            }
        }
        let mut first_error = None;
        for thread in self.workers.drain(..) {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    first_error.get_or_insert(DeviceError::Io(error));
                }
                Err(_) => {
                    first_error.get_or_insert(DeviceError::WorkerPanicked);
                }
            }
        }
        self.io.take();
        match lock(&self.worker_failure).clone() {
            Some(WorkerFailure::Io(message)) => Err(DeviceError::WorkerFailed(message)),
            Some(WorkerFailure::Panicked) => Err(DeviceError::WorkerPanicked),
            None => first_error.map_or(Ok(()), Err),
        }
    }

    // Prefer a worker failure over the generic stopped state in API errors.
    fn ensure_running(&self) -> Result<(), DeviceError> {
        match lock(&self.worker_failure).clone() {
            Some(WorkerFailure::Io(message)) => return Err(DeviceError::WorkerFailed(message)),
            Some(WorkerFailure::Panicked) => return Err(DeviceError::WorkerPanicked),
            None => {}
        }
        if self.stopping.load(Ordering::Acquire) {
            Err(DeviceError::ShuttingDown)
        } else {
            Ok(())
        }
    }

    // Look up and clone a peer without holding the registry lock afterward.
    fn peer(&self, public_key: &PeerKey) -> Result<Arc<Peer>, DeviceError> {
        self.ensure_running()?;
        read_lock(&self.state)
            .peers
            .get(public_key)
            .cloned()
            .ok_or(DeviceError::PeerNotFound)
    }

    // Build one BoringTun tunnel using the device identity and shared limiter.
    fn make_tunnel(
        &self,
        peer_key: PeerKey,
        preshared_key: Option<PeerKey>,
        keepalive: Option<u16>,
        index: u32,
    ) -> Tunn {
        Tunn::new(
            StaticSecret::from(self.device_private_key.0),
            PublicKey::from(peer_key),
            preshared_key,
            keepalive,
            index,
            Some(Arc::clone(&self.rate_limiter)),
        )
    }

    // Reserve the next 24-bit index used in BoringTun receiver identifiers.
    fn reserve_peer_index(&self) -> Result<u32, DeviceError> {
        let mut state = write_lock(&self.state);
        if state.next_peer_index > MAX_PEER_INDEX {
            return Err(DeviceError::TooManyPeers);
        }
        let index = state.next_peer_index;
        state.next_peer_index += 1;
        Ok(index)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

// Recover poisoned locks so one panic does not make device cleanup impossible.
pub(crate) fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// Acquire the write side while recovering from a previous panic.
pub(crate) fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// Acquire a mutex while recovering from a previous panic.
pub(crate) fn lock<T>(lock: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// Accept decrypted source addresses only when this peer owns the winning route.
pub(crate) fn allowed_source(
    state: &RwLock<DeviceState>,
    peer: &Arc<Peer>,
    source: IpAddr,
) -> bool {
    read_lock(state)
        .by_route(source)
        .is_some_and(|route_peer| Arc::ptr_eq(&route_peer, peer))
}

// Format a replacement initiation for packets queued before an endpoint existed.
fn prepare_pending_handshake(peer: &Arc<Peer>) -> Option<Vec<u8>> {
    let mut runtime = lock(&peer.runtime);
    if !runtime.pending_handshake {
        return None;
    }
    let mut buffer = vec![0; MAX_DATAGRAM_SIZE];
    match runtime
        .tunnel
        .format_handshake_initiation(&mut buffer, true)
    {
        TunnResult::WriteToNetwork(packet) => Some(packet.to_vec()),
        _ => None,
    }
}
