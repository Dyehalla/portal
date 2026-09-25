//! Public lifecycle and peer-management API for a userspace WireGuard device.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::os::fd::OwnedFd;
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle, Thread};
use std::time::Duration;

use crate::datapath::worker::{WorkerCommand, WorkerCommandError};
use crate::device::{AllowedIp, ControlError, Device, PeerKey, PeerStats, TunnelAssignment};
use crate::index_table::{Route, WorkerId};
use crate::platform::{DispatchCommand, DispatchSource, TunSocket, WorkerPort, WorkerSpawner};

const DEFAULT_RING_CAPACITY: usize = 1024;
const DEFAULT_BUFFER_COUNT: usize = 1024;

/// Configuration for one WireGuard peer.
pub struct PeerConfig {
    /// The peer's static Curve25519 public key.
    pub public_key: PeerKey,
    /// Optional preshared key.
    pub preshared_key: Option<PeerKey>,
    /// Optional persistent keepalive interval.
    pub persistent_keepalive: Option<Duration>,
    /// Initial UDP endpoint; authenticated roaming can replace it.
    pub endpoint: Option<SocketAddr>,
    /// Inner IP prefixes assigned to this peer.
    pub allowed_ips: Vec<AllowedIp>,
}

impl Drop for PeerConfig {
    fn drop(&mut self) {
        if let Some(key) = &mut self.preshared_key {
            key.fill(0);
        }
    }
}

enum TunSource {
    Name(String),
    Descriptor(OwnedFd),
}

/// Builder for a running userspace WireGuard engine.
pub struct EngineBuilder {
    private_key: PeerKey,
    listen: Option<SocketAddr>,
    tun: Option<TunSource>,
    workers: usize,
    peers: Vec<PeerConfig>,
}

impl EngineBuilder {
    /// Creates a builder for the device's static private key.
    pub fn new(private_key: PeerKey) -> Self {
        Self {
            private_key,
            listen: None,
            tun: None,
            workers: 1,
            peers: Vec::new(),
        }
    }

    /// Sets the local UDP bind address.
    pub fn listen(mut self, address: SocketAddr) -> Self {
        self.listen = Some(address);
        self
    }

    /// Opens and attaches a Linux TUN queue with this interface name.
    pub fn tun_name(mut self, name: impl Into<String>) -> Self {
        self.tun = Some(TunSource::Name(name.into()));
        self
    }

    /// Takes ownership of an already-configured TUN descriptor.
    ///
    /// The descriptor must refer to a TUN queue without a packet-info prefix.
    pub fn tun_fd(mut self, descriptor: OwnedFd) -> Self {
        self.tun = Some(TunSource::Descriptor(descriptor));
        self
    }

    /// Sets the number of worker threads. The default is one.
    pub fn workers(mut self, workers: usize) -> Self {
        self.workers = workers;
        self
    }

    /// Adds a peer that will be installed before packet processing starts.
    pub fn peer(mut self, peer: PeerConfig) -> Self {
        self.peers.push(peer);
        self
    }

    /// Binds resources and starts the dispatcher and worker threads.
    pub fn start(mut self) -> Result<Engine, EngineError> {
        if self.workers == 0 {
            return Err(EngineError::InvalidWorkerCount);
        }
        let listen = self.listen.ok_or(EngineError::MissingListenAddress)?;
        let tun = match self.tun.take().ok_or(EngineError::MissingTun)? {
            TunSource::Name(name) => TunSocket::new(&name)?,
            TunSource::Descriptor(descriptor) => TunSocket::from_owned_fd(descriptor)?,
        };

        let mut device = Device::new(self.private_key);
        let mut tunnel_configs = (0..self.workers).map(|_| Vec::new()).collect::<Vec<_>>();
        for worker in 0..self.workers {
            device.register_worker(worker as WorkerId);
        }
        for peer in self.peers.drain(..) {
            let tunnel = device.add_peer(
                peer.public_key,
                peer.preshared_key,
                peer.persistent_keepalive,
                peer.endpoint,
                peer.allowed_ips.clone(),
            )?;
            tunnel_configs[tunnel.assignment.worker].push(tunnel);
        }

        let udp = UdpSocket::bind(listen)?;
        let local_addr = udp.local_addr()?;
        let indices = device.index_table();
        let mut ports = HashMap::with_capacity(self.workers);
        let mut worker_controls = HashMap::with_capacity(self.workers);
        let mut worker_threads = Vec::with_capacity(self.workers);
        for (worker_id, configs) in tunnel_configs.into_iter().enumerate() {
            match WorkerSpawner::spawn(
                worker_id,
                configs,
                Arc::clone(&indices),
                device.snapshot_source(),
                DEFAULT_RING_CAPACITY,
            ) {
                Ok((port, thread)) => {
                    worker_controls.insert(worker_id, WorkerControl::from_port(&port));
                    ports.insert(worker_id, port);
                    worker_threads.push(thread);
                }
                Err(error) => {
                    stop_workers(&worker_controls);
                    join_workers(worker_threads)?;
                    return Err(EngineError::Io(error));
                }
            }
        }

        let (dispatch_tx, dispatch_rx) = mpsc::channel();
        let dispatcher = match DispatchSource::new(
            udp,
            tun,
            &device,
            ports,
            DEFAULT_BUFFER_COUNT,
            dispatch_rx,
        ) {
            Ok(dispatcher) => dispatcher,
            Err(error) => {
                stop_workers(&worker_controls);
                join_workers(worker_threads)?;
                return Err(EngineError::Io(error));
            }
        };
        let dispatcher_thread = match thread::Builder::new()
            .name("portal-dispatcher".to_owned())
            .spawn(move || {
                let mut dispatcher = dispatcher;
                dispatcher.run()
            }) {
            Ok(thread) => thread,
            Err(error) => {
                stop_workers(&worker_controls);
                join_workers(worker_threads)?;
                return Err(EngineError::Io(error));
            }
        };

        let shared = Arc::new(Mutex::new(EngineControl {
            device,
            workers: worker_controls,
            dispatcher: dispatch_tx,
            local_addr,
            running: true,
        }));
        Ok(Engine {
            handle: EngineHandle { shared },
            dispatcher_thread: Some(dispatcher_thread),
            worker_threads,
        })
    }
}

impl Drop for EngineBuilder {
    fn drop(&mut self) {
        self.private_key.fill(0);
    }
}

/// Owns the engine's threads and provides a cloneable control handle.
pub struct Engine {
    handle: EngineHandle,
    dispatcher_thread: Option<JoinHandle<io::Result<()>>>,
    worker_threads: Vec<JoinHandle<io::Result<()>>>,
}

impl Engine {
    /// Creates a builder for a device's static private key.
    pub fn builder(private_key: PeerKey) -> EngineBuilder {
        EngineBuilder::new(private_key)
    }

    /// Returns a handle for peer management and read-only device state.
    pub fn handle(&self) -> EngineHandle {
        self.handle.clone()
    }

    /// Returns the UDP address selected by the operating system.
    pub fn local_addr(&self) -> SocketAddr {
        self.handle.local_addr()
    }

    /// Requests shutdown and joins all engine threads.
    pub fn shutdown(&mut self) -> Result<(), EngineError> {
        self.stop_and_join()
    }

    /// Waits for the dispatcher to exit, then stops and joins the workers.
    pub fn wait(mut self) -> Result<(), EngineError> {
        let dispatcher_result = self.join_dispatcher();
        let shutdown_result = self.stop_and_join();
        dispatcher_result.and(shutdown_result)
    }

    fn join_dispatcher(&mut self) -> Result<(), EngineError> {
        let Some(thread) = self.dispatcher_thread.take() else {
            return Ok(());
        };
        match thread.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(EngineError::Io(error)),
            Err(_) => Err(EngineError::ThreadPanicked),
        }
    }

    fn stop_and_join(&mut self) -> Result<(), EngineError> {
        let mut first_error = None;
        {
            let mut control = match self.handle.shared.lock() {
                Ok(control) => control,
                Err(poisoned) => poisoned.into_inner(),
            };
            if control.running {
                control.running = false;
                if control.dispatcher.send(DispatchCommand::Shutdown).is_err() {
                    first_error = Some(EngineError::DispatcherStopped);
                }
                stop_workers(&control.workers);
            }
        }

        if let Err(error) = self.join_dispatcher() {
            first_error.get_or_insert(error);
        }
        for thread in self.worker_threads.drain(..) {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    first_error.get_or_insert(EngineError::Io(error));
                }
                Err(_) => {
                    first_error.get_or_insert(EngineError::ThreadPanicked);
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        let _ = self.stop_and_join();
    }
}

/// Cloneable, synchronous control-plane handle for a running engine.
#[derive(Clone)]
pub struct EngineHandle {
    shared: Arc<Mutex<EngineControl>>,
}

struct EngineControl {
    device: Device,
    workers: HashMap<WorkerId, WorkerControl>,
    dispatcher: Sender<DispatchCommand>,
    local_addr: SocketAddr,
    running: bool,
}

struct WorkerControl {
    sender: Sender<WorkerCommand>,
    wake: Thread,
}

impl WorkerControl {
    fn from_port(port: &WorkerPort) -> Self {
        Self {
            sender: port.control.clone(),
            wake: port.wake.clone(),
        }
    }

    fn add_tunnel(&self, config: crate::device::TunnelConfig) -> Result<(), EngineError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerCommand::AddTunnel { config, reply })
            .map_err(|_| EngineError::WorkerStopped)?;
        self.wake.unpark();
        match response.recv().map_err(|_| EngineError::WorkerStopped)? {
            Ok(()) => Ok(()),
            Err(WorkerCommandError::WrongWorker) => Err(EngineError::WorkerRejectedTunnel),
            Err(WorkerCommandError::TunnelAlreadyExists) => Err(EngineError::WorkerRejectedTunnel),
        }
    }

    fn remove_tunnel(&self, tunnel: u64) -> Result<(), EngineError> {
        let (reply, response) = mpsc::sync_channel(1);
        self.sender
            .send(WorkerCommand::RemoveTunnel { tunnel, reply })
            .map_err(|_| EngineError::WorkerStopped)?;
        self.wake.unpark();
        response.recv().map_err(|_| EngineError::WorkerStopped)
    }

    fn shutdown(&self) {
        let _ = self.sender.send(WorkerCommand::Shutdown);
        self.wake.unpark();
    }
}

impl EngineHandle {
    /// Adds a peer, or replaces the existing configuration for its public key.
    pub fn upsert_peer(&self, peer: PeerConfig) -> Result<(), EngineError> {
        let mut control = self.lock_running()?;
        let mut prepared = control.device.prepare_peer(
            peer.public_key,
            peer.preshared_key,
            peer.persistent_keepalive,
            peer.endpoint,
            peer.allowed_ips.clone(),
        )?;
        let assignment = prepared.assignment();
        let endpoint = prepared.endpoint();
        let peer_route = route(assignment);
        {
            let worker = control
                .workers
                .get(&assignment.worker)
                .ok_or(EngineError::WorkerStopped)?;
            worker.add_tunnel(prepared.take_tunnel())?;
            if let Err(error) = update_dispatch_endpoint(&control.dispatcher, peer_route, endpoint)
            {
                let _ = worker.remove_tunnel(assignment.tunnel);
                return Err(error);
            }
        }

        let previous = control.device.commit_peer(prepared);
        if let Some(previous) = previous {
            let worker_result = control
                .workers
                .get(&previous.worker)
                .ok_or(EngineError::WorkerStopped)
                .and_then(|old_worker| old_worker.remove_tunnel(previous.tunnel));
            let endpoint_result =
                update_dispatch_endpoint(&control.dispatcher, route(previous), None);
            worker_result?;
            endpoint_result?;
        }
        Ok(())
    }

    /// Removes a peer. Returns `false` when the key is not configured.
    pub fn remove_peer(&self, peer: &PeerKey) -> Result<bool, EngineError> {
        let mut control = self.lock_running()?;
        let Some(assignment) = control.device.remove_peer(peer) else {
            return Ok(false);
        };
        let worker_result = control
            .workers
            .get(&assignment.worker)
            .ok_or(EngineError::WorkerStopped)
            .and_then(|worker| worker.remove_tunnel(assignment.tunnel));
        let endpoint_result =
            update_dispatch_endpoint(&control.dispatcher, route(assignment), None);
        worker_result?;
        endpoint_result?;
        Ok(true)
    }

    /// Requests shutdown without joining threads. The `Engine` owner joins them.
    pub fn request_shutdown(&self) -> Result<(), EngineError> {
        let mut control = self
            .shared
            .lock()
            .map_err(|_| EngineError::ControlPoisoned)?;
        if !control.running {
            return Ok(());
        }
        control.running = false;
        let dispatch_result = control.dispatcher.send(DispatchCommand::Shutdown);
        stop_workers(&control.workers);
        dispatch_result.map_err(|_| EngineError::DispatcherStopped)
    }

    /// Returns byte counters for a configured peer.
    pub fn peer_stats(&self, peer: &PeerKey) -> Result<Option<PeerStats>, EngineError> {
        let control = self.lock_running()?;
        Ok(control.device.peer_stats(peer))
    }

    /// Returns the device's static public key.
    pub fn public_key(&self) -> Result<PeerKey, EngineError> {
        let control = self.lock_running()?;
        Ok(*control.device.static_public())
    }

    /// Returns the UDP address selected by the operating system.
    pub fn local_addr(&self) -> SocketAddr {
        match self.shared.lock() {
            Ok(control) => control.local_addr,
            Err(poisoned) => poisoned.into_inner().local_addr,
        }
    }

    fn lock_running(&self) -> Result<std::sync::MutexGuard<'_, EngineControl>, EngineError> {
        let control = self
            .shared
            .lock()
            .map_err(|_| EngineError::ControlPoisoned)?;
        if !control.running {
            return Err(EngineError::Stopped);
        }
        Ok(control)
    }
}

fn update_dispatch_endpoint(
    dispatcher: &Sender<DispatchCommand>,
    route: Route,
    endpoint: Option<SocketAddr>,
) -> Result<(), EngineError> {
    let (reply, response) = mpsc::sync_channel(1);
    dispatcher
        .send(DispatchCommand::SetEndpoint {
            route,
            endpoint,
            reply,
        })
        .map_err(|_| EngineError::DispatcherStopped)?;
    response.recv().map_err(|_| EngineError::DispatcherStopped)
}

fn stop_workers(workers: &HashMap<WorkerId, WorkerControl>) {
    for worker in workers.values() {
        worker.shutdown();
    }
}

fn join_workers(threads: Vec<JoinHandle<io::Result<()>>>) -> Result<(), EngineError> {
    let mut first_error = None;
    for thread in threads {
        match thread.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                first_error.get_or_insert(EngineError::Io(error));
            }
            Err(_) => {
                first_error.get_or_insert(EngineError::ThreadPanicked);
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn route(assignment: TunnelAssignment) -> Route {
    Route {
        worker: assignment.worker,
        tunnel: assignment.tunnel,
    }
}

/// Errors returned while building, managing, or stopping an engine.
#[derive(Debug)]
pub enum EngineError {
    MissingListenAddress,
    MissingTun,
    InvalidWorkerCount,
    Control(ControlError),
    Io(io::Error),
    WorkerStopped,
    WorkerRejectedTunnel,
    DispatcherStopped,
    ControlPoisoned,
    Stopped,
    ThreadPanicked,
}

impl fmt::Display for EngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingListenAddress => write!(formatter, "listen address is required"),
            Self::MissingTun => write!(formatter, "a TUN interface or descriptor is required"),
            Self::InvalidWorkerCount => write!(formatter, "worker count must be nonzero"),
            Self::Control(error) => write!(formatter, "invalid peer configuration: {error}"),
            Self::Io(error) => write!(formatter, "engine I/O error: {error}"),
            Self::WorkerStopped => {
                write!(formatter, "worker stopped before acknowledging a command")
            }
            Self::WorkerRejectedTunnel => {
                write!(formatter, "worker rejected the tunnel configuration")
            }
            Self::DispatcherStopped => write!(
                formatter,
                "dispatcher stopped before acknowledging a command"
            ),
            Self::ControlPoisoned => write!(formatter, "engine control state was poisoned"),
            Self::Stopped => write!(formatter, "engine is stopped"),
            Self::ThreadPanicked => write!(formatter, "engine thread panicked"),
        }
    }
}

impl std::error::Error for EngineError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Control(error) => Some(error),
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ControlError> for EngineError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

impl From<io::Error> for EngineError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
