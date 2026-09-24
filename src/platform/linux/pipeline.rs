use std::net::SocketAddr;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::thread::Thread;

use crate::index_table::{Route, TunnelId};
use crate::ring::{BufHandle, Consumer, Producer};

/// Where an input packet came from and how the worker should process it.
pub enum PacketKind {
    Udp { source: SocketAddr },
    Tun,
}

/// A packet or timer work item handed from the single dispatcher to a worker.
pub enum RxMessage {
    Packet {
        handle: BufHandle,
        spare: BufHandle,
        offset: usize,
        len: usize,
        route: Route,
        kind: PacketKind,
    },
    Timer {
        handle: BufHandle,
        tunnel: TunnelId,
    },
    Flush {
        handle: BufHandle,
        tunnel: TunnelId,
    },
}

/// Destination selected by the worker for one completed packet buffer.
pub enum TxTarget {
    /// Reply to this source address for the current datagram.
    Address(SocketAddr),
    /// Send to the currently learned endpoint for the tunnel's peer.
    Peer(Route),
    /// Write decrypted plaintext to TUN.
    Tun,
    /// Discard input and return its buffer to the pool.
    Discard,
}

/// Worker completion returned to the dispatcher.
pub struct Completion {
    pub handle: BufHandle,
    /// An unused input or spare buffer returned alongside this completion.
    pub recycle: Option<BufHandle>,
    pub offset: usize,
    pub len: usize,
    pub route: Route,
    pub target: TxTarget,
    /// A successfully authenticated packet may update the peer's roaming endpoint.
    pub authenticated_source: Option<SocketAddr>,
    /// Ask the dispatcher to schedule the next queued plaintext packet.
    pub flush_more: bool,
}

/// Dispatcher-facing endpoints for one worker's SPSC queues.
pub struct DispatcherPort {
    pub ingress: Producer<RxMessage>,
    pub egress: Consumer<Completion>,
    /// Unparks the worker only when its ingress ring transitions from empty.
    pub wake: Option<Thread>,
    /// eventfd signaled when the worker's completion ring transitions empty.
    pub completion_fd: Option<Arc<OwnedFd>>,
}

/// The worker's halves of the same SPSC queues.
pub struct WorkerQueues {
    pub ingress: Consumer<RxMessage>,
    pub egress: Producer<Completion>,
}

/// Creates the one-producer/one-consumer queues for a worker.
pub fn worker_queues(capacity: usize) -> (DispatcherPort, WorkerQueues) {
    let (dispatch_to_worker, worker_ingress) = crate::ring::spsc_ring(capacity);
    let (worker_to_dispatch, dispatch_egress) = crate::ring::spsc_ring(capacity);
    (
        DispatcherPort {
            ingress: dispatch_to_worker,
            egress: dispatch_egress,
            wake: None,
            completion_fd: None,
        },
        WorkerQueues {
            ingress: worker_ingress,
            egress: worker_to_dispatch,
        },
    )
}
