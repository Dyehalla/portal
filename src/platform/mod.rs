use std::net::SocketAddr;

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
mod imp;
#[cfg(target_os = "windows")]
compile_error!("The Windows platform backend is not implemented yet");
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
compile_error!("portal currently supports Linux only");

// Each backend exports concrete `PacketIo` and `WorkerIo` types. `PacketIo`
// provides open, local_addr, create_worker, wait_packet, try_packet, send_udp,
// write_tun, and wake_all with the same signatures. Selection is compile-time, so packet
// processing has no trait object.
#[cfg(target_os = "linux")]
pub(crate) use imp::{PacketIo, WorkerIo};

/// Whether a packet came from the WireGuard UDP socket or virtual interface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PacketSource {
    Udp(SocketAddr),
    Tun,
}

/// Metadata for a packet read into the worker's reusable buffer.
pub(crate) struct ReceivedPacket {
    pub source: PacketSource,
    pub len: usize,
}
