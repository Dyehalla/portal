use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::device::{AllowedIp, Device};
use crate::index_table::WorkerId;
use crate::platform::dispatch::DispatchSource;
use crate::platform::socket::TunSocket;
use crate::platform::worker::Worker;

const RING_CAPACITY: usize = 1024;
const BUFFER_COUNT: usize = 1024;

/// One configured peer, including its outer endpoint and cryptokey routes.
pub struct PeerConfig {
    pub static_public: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<Duration>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<AllowedIp>,
}

impl Drop for PeerConfig {
    fn drop(&mut self) {
        if let Some(key) = &mut self.preshared_key {
            key.fill(0);
        }
    }
}

/// Startup configuration for a userspace device.
pub struct RuntimeConfig {
    pub static_private: [u8; 32],
    pub listen: SocketAddr,
    pub tun_name: String,
    pub workers: usize,
    pub peers: Vec<PeerConfig>,
}

impl Drop for RuntimeConfig {
    fn drop(&mut self) {
        self.static_private.fill(0);
    }
}

/// Builds the control plane, worker-owned tunnels and Linux dispatcher, then
/// runs the single-socket packet source.
pub fn run(mut config: RuntimeConfig) -> io::Result<()> {
    if config.workers == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "worker count must be nonzero",
        ));
    }

    let mut device = Device::new(config.static_private);
    config.static_private.fill(0);
    for worker in 0..config.workers {
        device.register_worker(worker as WorkerId);
    }

    let mut tunnel_configs = (0..config.workers).map(|_| Vec::new()).collect::<Vec<_>>();
    for peer in config.peers.drain(..) {
        let tunnel = device
            .add_peer(
                peer.static_public,
                peer.preshared_key,
                peer.persistent_keepalive,
                peer.endpoint,
                peer.allowed_ips.clone(),
            )
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("peer config: {error:?}"),
                )
            })?;
        tunnel_configs[tunnel.assignment.worker].push(tunnel);
    }

    let udp = UdpSocket::bind(config.listen)?;
    let tun = TunSocket::new(&config.tun_name)?;
    let indices = device.index_table();
    let mut ports = HashMap::new();
    let mut worker_threads = Vec::with_capacity(config.workers);
    for (worker_id, tunnels) in tunnel_configs.into_iter().enumerate() {
        let (port, thread) = Worker::spawn(
            worker_id,
            tunnels,
            indices.clone(),
            device.snapshot_source(),
            RING_CAPACITY,
        )?;
        ports.insert(worker_id, port);
        worker_threads.push(thread);
    }

    let mut dispatcher = DispatchSource::new(udp, tun, &device, ports, BUFFER_COUNT)?;
    dispatcher.run()?;

    for worker in worker_threads {
        let _ = worker.join();
    }
    Ok(())
}
