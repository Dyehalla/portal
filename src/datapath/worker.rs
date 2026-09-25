use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use crate::device::{DeviceSnapshot, TunnelAssignment, TunnelConfig, TunnelStats};
use crate::index_table::{IndexTable, Route, TunnelId, WorkerId};
use crate::datapath::ip::source as packet_source;
use crate::datapath::pipeline::{
    Completion, CompletionNotifier, DispatcherPort, PacketKind, RxMessage, TxTarget, WorkerQueues,
    worker_queues,
};
use crate::protocol::{DATA_HEADER_LEN, Tunnel, TunnelResult};
use crate::ring::BufHandle;
use arc_swap::ArcSwap;

struct TunnelSlot {
    tunnel: Tunnel,
    claimed: HashSet<u32>,
    pending_packets: VecDeque<PendingPacket>,
    stats: Arc<TunnelStats>,
    observed_tx: u64,
    observed_rx: u64,
}

struct PendingPacket {
    handle: BufHandle,
    offset: usize,
    len: usize,
}

const DISPATCH_BATCH: usize = 32;
const MAX_PENDING_PACKETS: usize = 256;

/// One inline worker. Every tunnel in `tunnels` is owned by this thread only.
pub struct Worker {
    id: WorkerId,
    tunnels: HashMap<TunnelId, TunnelSlot>,
    indices: Arc<IndexTable>,
    snapshot: Arc<ArcSwap<DeviceSnapshot>>,
    queues: WorkerQueues,
    completion_notifier: Arc<dyn CompletionNotifier>,
    pending: Option<Completion>,
    scheduled: HashMap<TunnelId, VecDeque<RxMessage>>,
    ready_tunnels: VecDeque<TunnelId>,
}

impl Worker {
    /// Starts a worker thread and returns its dispatcher-facing ring endpoints.
    pub fn spawn(
        id: WorkerId,
        configs: Vec<TunnelConfig>,
        indices: Arc<IndexTable>,
        snapshot: Arc<ArcSwap<DeviceSnapshot>>,
        ring_capacity: usize,
        completion_notifier: Arc<dyn CompletionNotifier>,
    ) -> io::Result<(DispatcherPort, JoinHandle<io::Result<()>>)> {
        let (mut port, queues) = worker_queues(ring_capacity);
        let mut tunnels = HashMap::new();
        for config in configs {
            if config.assignment.worker != id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "tunnel assigned to another worker",
                ));
            }
            let stats = Arc::clone(&config.stats);
            tunnels.insert(
                config.assignment.tunnel,
                TunnelSlot {
                    tunnel: config.build_tunnel(),
                    claimed: HashSet::new(),
                    pending_packets: VecDeque::new(),
                    stats,
                    observed_tx: 0,
                    observed_rx: 0,
                },
            );
        }
        let mut worker = Self {
            id,
            tunnels,
            indices,
            snapshot,
            queues,
            completion_notifier,
            pending: None,
            scheduled: HashMap::new(),
            ready_tunnels: VecDeque::new(),
        };
        let thread = thread::Builder::new()
            .name(format!("portal-worker-{id}"))
            .spawn(move || worker.run())?;
        port.wake = Some(thread.thread().clone());
        Ok((port, thread))
    }

    fn run(&mut self) -> io::Result<()> {
        let mut idle = 0usize;
        loop {
            if let Some(completion) = self.pending.take() {
                let was_empty = self.queues.egress.is_empty();
                match self.queues.egress.try_push(completion) {
                    Ok(()) => {
                        if was_empty {
                            self.wake_dispatcher();
                        }
                        idle = 0;
                    }
                    Err(completion) => {
                        self.pending = Some(completion);
                        thread::yield_now();
                        continue;
                    }
                }
            }
            if let Some(message) = self.next_scheduled() {
                self.pending = Some(self.process(message));
                idle = 0;
            } else {
                for _ in 0..DISPATCH_BATCH {
                    let Some(message) = self.queues.ingress.try_pop() else {
                        break;
                    };
                    self.schedule(message);
                }
                if let Some(message) = self.next_scheduled() {
                    self.pending = Some(self.process(message));
                    idle = 0;
                } else {
                    std::hint::spin_loop();
                    idle += 1;
                    if idle >= 4096 {
                        thread::park();
                        idle = 0;
                    }
                }
            }
        }
    }

    fn wake_dispatcher(&self) {
        self.completion_notifier.notify();
    }

    fn schedule(&mut self, message: RxMessage) {
        let tunnel = message_tunnel(&message);
        let queue = self.scheduled.entry(tunnel).or_default();
        if queue.is_empty() {
            self.ready_tunnels.push_back(tunnel);
        }
        queue.push_back(message);
    }

    fn next_scheduled(&mut self) -> Option<RxMessage> {
        let tunnel = self.ready_tunnels.pop_front()?;
        let queue = self.scheduled.get_mut(&tunnel)?;
        let message = queue.pop_front()?;
        if queue.is_empty() {
            self.scheduled.remove(&tunnel);
        } else {
            self.ready_tunnels.push_back(tunnel);
        }
        Some(message)
    }

    fn process(&mut self, message: RxMessage) -> Completion {
        match message {
            RxMessage::Packet {
                handle,
                spare,
                offset,
                len,
                route,
                kind: PacketKind::Tun,
            } => self.process_tun(handle, spare, offset, len, route),
            RxMessage::Packet {
                handle,
                spare,
                offset,
                len,
                route,
                kind: PacketKind::Udp { source },
            } => self.process_udp(handle, spare, offset, len, route, source),
            RxMessage::Timer { handle, tunnel } => self.process_timer(handle, tunnel),
            RxMessage::Flush { handle, tunnel } => self.process_flush(handle, tunnel),
        }
    }

    fn process_tun(
        &mut self,
        mut handle: BufHandle,
        mut spare: BufHandle,
        offset: usize,
        len: usize,
        route: Route,
    ) -> Completion {
        let Self {
            id,
            tunnels,
            indices,
            ..
        } = self;
        let Some(slot) = tunnels.get_mut(&route.tunnel) else {
            return pair_completion(handle, spare, route);
        };
        let assignment = TunnelAssignment {
            worker: *id,
            tunnel: route.tunnel,
        };
        let mut claim = || claim_index(indices, assignment, &mut slot.claimed);
        let result = slot
            .tunnel
            .try_encapsulate_in_place(handle.storage_mut(), offset, len);
        let attempt = match result {
            TunnelResult::WriteToNetwork(packet) => Ok(packet.len()),
            TunnelResult::NoSession | TunnelResult::RekeyRequired => Err(true),
            _ => Err(false),
        };
        match attempt {
            Ok(output_len) => {
                reconcile(slot, indices, assignment);
                update_stats(slot);
                handle.set_len(output_len);
                Completion {
                    handle,
                    recycle: Some(spare),
                    offset: 0,
                    len: output_len,
                    route,
                    target: TxTarget::Peer(route),
                    authenticated_source: None,
                    flush_more: false,
                }
            }
            Err(true) => {
                if slot.pending_packets.len() >= MAX_PENDING_PACKETS {
                    reconcile(slot, indices, assignment);
                    update_stats(slot);
                    return pair_completion(handle, spare, route);
                }
                slot.pending_packets.push_back(PendingPacket {
                    handle,
                    offset,
                    len,
                });
                let (output_len, sent) = match slot.tunnel.format_handshake_initiation(
                    spare.storage_mut(),
                    &mut claim,
                    false,
                ) {
                    TunnelResult::WriteToNetwork(packet) => (packet.len(), true),
                    _ => (0, false),
                };
                reconcile(slot, indices, assignment);
                update_stats(slot);
                spare.set_len(output_len);
                Completion {
                    handle: spare,
                    recycle: None,
                    offset: 0,
                    len: output_len,
                    route,
                    target: if sent {
                        TxTarget::Peer(route)
                    } else {
                        TxTarget::Discard
                    },
                    authenticated_source: None,
                    flush_more: false,
                }
            }
            Err(false) => {
                reconcile(slot, indices, assignment);
                update_stats(slot);
                pair_completion(handle, spare, route)
            }
        }
    }

    fn process_udp(
        &mut self,
        mut handle: BufHandle,
        mut spare: BufHandle,
        offset: usize,
        len: usize,
        route: Route,
        source: std::net::SocketAddr,
    ) -> Completion {
        let Self {
            id,
            tunnels,
            indices,
            snapshot,
            ..
        } = self;
        let Some(slot) = tunnels.get_mut(&route.tunnel) else {
            return Completion {
                handle,
                recycle: Some(spare),
                offset: 0,
                len: 0,
                route,
                target: TxTarget::Discard,
                authenticated_source: None,
                flush_more: false,
            };
        };
        let assignment = TunnelAssignment {
            worker: *id,
            tunnel: route.tunnel,
        };
        let message_type = handle
            .storage_mut()
            .get(offset..offset.saturating_add(4))
            .and_then(|header| <[u8; 4]>::try_from(header).ok())
            .map(u32::from_le_bytes);
        let mut claim = || claim_index(indices, assignment, &mut slot.claimed);
        let result = {
            let Some(end) = offset.checked_add(len) else {
                return Completion {
                    handle,
                    recycle: Some(spare),
                    offset: 0,
                    len: 0,
                    route,
                    target: TxTarget::Discard,
                    authenticated_source: None,
                    flush_more: false,
                };
            };
            let Some(packet) = handle.storage_mut().get_mut(offset..end) else {
                return Completion {
                    handle,
                    recycle: Some(spare),
                    offset: 0,
                    len: 0,
                    route,
                    target: TxTarget::Discard,
                    authenticated_source: None,
                    flush_more: false,
                };
            };
            slot.tunnel
                .decapsulate(packet, spare.storage_mut(), &mut claim)
        };

        let mut target = TxTarget::Discard;
        let mut use_spare = false;
        let mut output_offset = 0;
        let mut output_len = 0;
        let mut authenticated = false;
        let mut session_usable = false;
        match result {
            TunnelResult::WriteToNetwork(packet) => {
                output_len = packet.len();
                target = TxTarget::Address(source);
                use_spare = true;
                authenticated = true;
                session_usable = message_type == Some(crate::protocol::MSG_HANDSHAKE_RESPONSE);
            }
            TunnelResult::WriteToTunnelInPlace(plaintext) => {
                if plaintext.is_empty() {
                    authenticated = true;
                    session_usable = true;
                } else if let Some(source_ip) = packet_source(plaintext) {
                    let assignment = TunnelAssignment {
                        worker: *id,
                        tunnel: route.tunnel,
                    };
                    if snapshot.load().allows_source(assignment, source_ip) {
                        output_offset = offset.saturating_add(DATA_HEADER_LEN);
                        output_len = plaintext.len();
                        target = TxTarget::Tun;
                        authenticated = true;
                        session_usable = true;
                    }
                }
            }
            TunnelResult::Done if message_type == Some(crate::protocol::MSG_COOKIE_REPLY) => {
                // A cookie reply is authenticated and must trigger an immediate retry.
                let retry =
                    slot.tunnel
                        .format_handshake_initiation(handle.storage_mut(), &mut claim, true);
                if let TunnelResult::WriteToNetwork(packet) = retry {
                    output_len = packet.len();
                    target = TxTarget::Address(source);
                    use_spare = true;
                    authenticated = true;
                }
            }
            _ => {}
        }
        reconcile(slot, indices, assignment);
        update_stats(slot);
        let flush_more = session_usable && !slot.pending_packets.is_empty();
        let (handle, recycle, output_offset) = if use_spare {
            spare.set_len(output_len);
            (spare, Some(handle), 0)
        } else {
            handle.set_len(output_offset.saturating_add(output_len));
            (handle, Some(spare), output_offset)
        };
        Completion {
            handle,
            recycle,
            offset: output_offset,
            len: output_len,
            route,
            target,
            authenticated_source: authenticated.then_some(source),
            flush_more,
        }
    }

    fn process_timer(&mut self, mut handle: BufHandle, tunnel: TunnelId) -> Completion {
        let route = Route {
            worker: self.id,
            tunnel,
        };
        let Self {
            id,
            tunnels,
            indices,
            ..
        } = self;
        let Some(slot) = tunnels.get_mut(&tunnel) else {
            return completion(handle, route, TxTarget::Discard);
        };
        let assignment = TunnelAssignment {
            worker: *id,
            tunnel,
        };
        let mut claim = || claim_index(indices, assignment, &mut slot.claimed);
        let result = slot
            .tunnel
            .update_timers(Instant::now(), handle.storage_mut(), &mut claim);
        let (target, len) = match result {
            TunnelResult::WriteToNetwork(packet) => (TxTarget::Peer(route), packet.len()),
            _ => (TxTarget::Discard, 0),
        };
        reconcile(slot, indices, assignment);
        update_stats(slot);
        handle.set_len(len);
        Completion {
            handle,
            recycle: None,
            offset: 0,
            len,
            route,
            target,
            authenticated_source: None,
            flush_more: false,
        }
    }

    fn process_flush(&mut self, mut handle: BufHandle, tunnel: TunnelId) -> Completion {
        let Self {
            id,
            tunnels,
            indices,
            ..
        } = self;
        let route = Route {
            worker: *id,
            tunnel,
        };
        let Some(slot) = tunnels.get_mut(&tunnel) else {
            return completion(handle, route, TxTarget::Discard);
        };
        let Some(packet) = slot.pending_packets.front_mut() else {
            return completion(handle, route, TxTarget::Discard);
        };
        let result = slot.tunnel.try_encapsulate_in_place(
            packet.handle.storage_mut(),
            packet.offset,
            packet.len,
        );
        let attempt = match result {
            TunnelResult::WriteToNetwork(packet) => Ok(packet.len()),
            TunnelResult::NoSession | TunnelResult::RekeyRequired => Err(true),
            _ => Err(false),
        };
        match attempt {
            Ok(len) => {
                let pending = slot
                    .pending_packets
                    .pop_front()
                    .expect("peeked pending packet");
                update_stats(slot);
                Completion {
                    handle: pending.handle,
                    recycle: Some(handle),
                    offset: 0,
                    len,
                    route,
                    target: TxTarget::Peer(route),
                    authenticated_source: None,
                    flush_more: !slot.pending_packets.is_empty(),
                }
            }
            Err(true) => {
                let assignment = TunnelAssignment {
                    worker: *id,
                    tunnel,
                };
                let mut claim = || claim_index(indices, assignment, &mut slot.claimed);
                let (len, sent) = match slot.tunnel.format_handshake_initiation(
                    handle.storage_mut(),
                    &mut claim,
                    false,
                ) {
                    TunnelResult::WriteToNetwork(packet) => (packet.len(), true),
                    _ => (0, false),
                };
                reconcile(slot, indices, assignment);
                update_stats(slot);
                handle.set_len(len);
                Completion {
                    handle,
                    recycle: None,
                    offset: 0,
                    len,
                    route,
                    target: if sent {
                        TxTarget::Peer(route)
                    } else {
                        TxTarget::Discard
                    },
                    authenticated_source: None,
                    flush_more: false,
                }
            }
            Err(false) => {
                let pending = slot
                    .pending_packets
                    .pop_front()
                    .expect("peeked pending packet");
                update_stats(slot);
                Completion {
                    handle: pending.handle,
                    recycle: Some(handle),
                    offset: 0,
                    len: 0,
                    route,
                    target: TxTarget::Discard,
                    authenticated_source: None,
                    flush_more: !slot.pending_packets.is_empty(),
                }
            }
        }
    }
}

fn completion(handle: BufHandle, route: Route, target: TxTarget) -> Completion {
    Completion {
        handle,
        recycle: None,
        offset: 0,
        len: 0,
        route,
        target,
        authenticated_source: None,
        flush_more: false,
    }
}

fn pair_completion(handle: BufHandle, spare: BufHandle, route: Route) -> Completion {
    Completion {
        handle,
        recycle: Some(spare),
        offset: 0,
        len: 0,
        route,
        target: TxTarget::Discard,
        authenticated_source: None,
        flush_more: false,
    }
}

fn message_tunnel(message: &RxMessage) -> TunnelId {
    match message {
        RxMessage::Packet { route, .. } => route.tunnel,
        RxMessage::Timer { tunnel, .. } | RxMessage::Flush { tunnel, .. } => *tunnel,
    }
}

fn claim_index(
    indices: &IndexTable,
    assignment: TunnelAssignment,
    owned: &mut HashSet<u32>,
) -> Option<u32> {
    for _ in 0..128 {
        let mut bytes = [0u8; 4];
        crate::protocol::RAND(&mut bytes);
        let index = u32::from_le_bytes(bytes);
        if indices.try_claim(
            index,
            Route {
                worker: assignment.worker,
                tunnel: assignment.tunnel,
            },
        ) {
            owned.insert(index);
            return Some(index);
        }
    }
    None
}

fn reconcile(slot: &mut TunnelSlot, indices: &IndexTable, assignment: TunnelAssignment) {
    let live = slot.tunnel.live_indices();
    slot.claimed.retain(|index| {
        if live.contains(index) {
            true
        } else {
            indices.release(
                *index,
                Route {
                    worker: assignment.worker,
                    tunnel: assignment.tunnel,
                },
            );
            false
        }
    });
}

fn update_stats(slot: &mut TunnelSlot) {
    let tx = slot.tunnel.tx_bytes();
    let rx = slot.tunnel.rx_bytes();
    slot.stats
        .tx_bytes
        .fetch_add(tx.saturating_sub(slot.observed_tx), Ordering::Relaxed);
    slot.stats
        .rx_bytes
        .fetch_add(rx.saturating_sub(slot.observed_rx), Ordering::Relaxed);
    slot.observed_tx = tx;
    slot.observed_rx = rx;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{AllowedIp, Device};
    use crate::index_table::IndexTable;
    use crate::datapath::pipeline::{PacketKind, RxMessage, TxTarget, worker_queues};
    use crate::protocol::{KEY_LEN, MAX_PACKET_SIZE};
    use crate::ring::BufPool;
    use std::net::SocketAddr;

    struct NoopNotifier;

    impl CompletionNotifier for NoopNotifier {
        fn notify(&self) {}
    }

    fn key(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    fn worker(
        id: WorkerId,
        config: crate::device::TunnelConfig,
        table: Arc<IndexTable>,
        snapshot: Arc<ArcSwap<DeviceSnapshot>>,
    ) -> Worker {
        let assignment = config.assignment;
        let stats = Arc::clone(&config.stats);
        let (port, queues) = worker_queues(16);
        drop(port);
        Worker {
            id,
            tunnels: HashMap::from([(
                assignment.tunnel,
                TunnelSlot {
                    tunnel: config.build_tunnel(),
                    claimed: HashSet::new(),
                    pending_packets: VecDeque::new(),
                    stats,
                    observed_tx: 0,
                    observed_rx: 0,
                },
            )]),
            indices: table,
            snapshot,
            queues,
            completion_notifier: Arc::new(NoopNotifier),
            pending: None,
            scheduled: HashMap::new(),
            ready_tunnels: VecDeque::new(),
        }
    }

    fn input_pair(pool: &mut BufPool, bytes: &[u8], offset: usize) -> (BufHandle, BufHandle) {
        let mut handle = pool.allocate().unwrap();
        handle.storage_mut()[offset..offset + bytes.len()].copy_from_slice(bytes);
        handle.set_len(offset + bytes.len());
        let spare = pool.allocate().unwrap();
        (handle, spare)
    }

    fn outbound(pool: &mut BufPool, mut completion: Completion) -> Vec<u8> {
        assert!(matches!(
            completion.target,
            TxTarget::Address(_) | TxTarget::Peer(_)
        ));
        let bytes = completion.handle.storage_mut()
            [completion.offset..completion.offset + completion.len]
            .to_vec();
        if let Some(recycle) = completion.recycle.take() {
            pool.recycle(recycle);
        }
        pool.recycle(completion.handle);
        bytes
    }

    /// Worker-owned tunnels handshake inline, then carry the packet held during initiation.
    #[test]
    fn inline_workers_complete_a_handshake_and_deliver_the_queued_packet() {
        let mut initiator = Device::new(key(0x11));
        let mut responder = Device::new(key(0x22));
        initiator.register_worker(0);
        responder.register_worker(1);
        let initiator_public = *initiator.static_public();
        let responder_public = *responder.static_public();
        let allowed = AllowedIp::new("10.9.0.0".parse().unwrap(), 16).unwrap();
        let a_config = initiator
            .add_peer(responder_public, None, None, None, vec![allowed])
            .unwrap();
        let b_config = responder
            .add_peer(initiator_public, None, None, None, vec![allowed])
            .unwrap();
        let a_route = Route {
            worker: a_config.assignment.worker,
            tunnel: a_config.assignment.tunnel,
        };
        let b_route = Route {
            worker: b_config.assignment.worker,
            tunnel: b_config.assignment.tunnel,
        };
        let a_table = initiator.index_table();
        let b_table = responder.index_table();
        let mut a = worker(0, a_config, a_table, initiator.snapshot_source());
        let mut b = worker(1, b_config, b_table, responder.snapshot_source());
        let mut pool = BufPool::new(16, MAX_PACKET_SIZE + 16, 16);
        let a_endpoint: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let b_endpoint: SocketAddr = "127.0.0.1:40001".parse().unwrap();

        let mut ip_packet = [0u8; 20];
        ip_packet[0] = 0x45;
        ip_packet[12..16].copy_from_slice(&[10, 9, 1, 2]);
        ip_packet[16..20].copy_from_slice(&[10, 9, 0, 7]);
        let (handle, spare) = input_pair(&mut pool, &ip_packet, 16);
        let first = a.process(RxMessage::Packet {
            handle,
            spare,
            offset: 16,
            len: ip_packet.len(),
            route: a_route,
            kind: PacketKind::Tun,
        });
        let initiation = outbound(&mut pool, first);
        assert_eq!(u32::from_le_bytes(initiation[..4].try_into().unwrap()), 1);

        let (handle, spare) = input_pair(&mut pool, &initiation, 0);
        let response = b.process(RxMessage::Packet {
            handle,
            spare,
            offset: 0,
            len: initiation.len(),
            route: b_route,
            kind: PacketKind::Udp { source: a_endpoint },
        });
        let response = outbound(&mut pool, response);
        assert_eq!(u32::from_le_bytes(response[..4].try_into().unwrap()), 2);

        let (handle, spare) = input_pair(&mut pool, &response, 0);
        let keepalive = a.process(RxMessage::Packet {
            handle,
            spare,
            offset: 0,
            len: response.len(),
            route: a_route,
            kind: PacketKind::Udp { source: b_endpoint },
        });
        assert!(keepalive.flush_more);
        let keepalive = outbound(&mut pool, keepalive);
        assert_eq!(u32::from_le_bytes(keepalive[..4].try_into().unwrap()), 4);

        let (handle, spare) = input_pair(&mut pool, &keepalive, 0);
        let keepalive_result = b.process(RxMessage::Packet {
            handle,
            spare,
            offset: 0,
            len: keepalive.len(),
            route: b_route,
            kind: PacketKind::Udp { source: a_endpoint },
        });
        assert!(matches!(keepalive_result.target, TxTarget::Discard));
        assert_eq!(keepalive_result.len, 0);
        if let Some(recycle) = keepalive_result.recycle {
            pool.recycle(recycle);
        }
        pool.recycle(keepalive_result.handle);

        let data = a.process(RxMessage::Flush {
            handle: pool.allocate().unwrap(),
            tunnel: a_route.tunnel,
        });
        let data = outbound(&mut pool, data);
        assert_eq!(u32::from_le_bytes(data[..4].try_into().unwrap()), 4);
        let (handle, spare) = input_pair(&mut pool, &data, 0);
        let mut plaintext = b.process(RxMessage::Packet {
            handle,
            spare,
            offset: 0,
            len: data.len(),
            route: b_route,
            kind: PacketKind::Udp { source: a_endpoint },
        });
        assert!(matches!(plaintext.target, TxTarget::Tun));
        assert_eq!(
            &plaintext.handle.storage_mut()[plaintext.offset..plaintext.offset + plaintext.len],
            &ip_packet,
        );
        assert_eq!(plaintext.authenticated_source, Some(a_endpoint));
        if let Some(recycle) = plaintext.recycle {
            pool.recycle(recycle);
        }
        pool.recycle(plaintext.handle);

        // AEAD authentication does not let a peer claim an unassigned source IP.
        ip_packet[12..16].copy_from_slice(&[203, 0, 113, 9]);
        let (handle, spare) = input_pair(&mut pool, &ip_packet, 16);
        let forged_source = a.process(RxMessage::Packet {
            handle,
            spare,
            offset: 16,
            len: ip_packet.len(),
            route: a_route,
            kind: PacketKind::Tun,
        });
        let forged_source = outbound(&mut pool, forged_source);
        let (handle, spare) = input_pair(&mut pool, &forged_source, 0);
        let rejected = b.process(RxMessage::Packet {
            handle,
            spare,
            offset: 0,
            len: forged_source.len(),
            route: b_route,
            kind: PacketKind::Udp { source: a_endpoint },
        });
        assert!(matches!(rejected.target, TxTarget::Discard));
        assert_eq!(rejected.authenticated_source, None);
        if let Some(recycle) = rejected.recycle {
            pool.recycle(recycle);
        }
        pool.recycle(rejected.handle);
        let a_stats = initiator.peer_stats(&responder_public).unwrap();
        let b_stats = responder.peer_stats(&initiator_public).unwrap();
        assert!(a_stats.tx_bytes > 0);
        assert!(b_stats.rx_bytes > 0);
    }
}
