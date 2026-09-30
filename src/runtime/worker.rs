use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

use crate::device::registry::{DeviceState, Peer};
use crate::device::{
    DeviceCounters, MAX_DATAGRAM_SIZE, PeerKey, SecretKey, TIMER_POLL_INTERVAL, allowed_source,
    lock, read_lock,
};
use crate::platform::{PacketIo, PacketSource, WorkerIo};
use boringtun::noise::rate_limiter::RateLimiter;

pub(crate) struct WorkerContext {
    pub worker_id: usize,
    pub io: Arc<PacketIo>,
    pub worker_io: WorkerIo,
    pub state: Arc<RwLock<DeviceState>>,
    pub stopping: Arc<AtomicBool>,
    pub stats: Arc<DeviceCounters>,
    pub rate_limiter: Arc<RateLimiter>,
    pub local_private_key: Arc<SecretKey>,
    pub local_public_key: PeerKey,
}

// Run the event loop, drain bounded batches, and let worker zero service timers.
pub(crate) fn run(context: WorkerContext) -> io::Result<()> {
    let WorkerContext {
        worker_id,
        io,
        mut worker_io,
        state,
        stopping,
        stats,
        rate_limiter,
        local_private_key,
        local_public_key,
    } = context;
    let local_private = StaticSecret::from(local_private_key.0);
    let local_public = PublicKey::from(local_public_key);
    let mut packet_buffer = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut scratch = vec![0u8; MAX_DATAGRAM_SIZE];
    let mut last_timer_tick = Instant::now();

    while !stopping.load(Ordering::Acquire) {
        let timeout = (worker_id == 0).then_some(TIMER_POLL_INTERVAL);
        let event = io.wait_packet(&mut worker_io, &mut packet_buffer, timeout)?;
        if let Some(event) = event {
            process_packet(
                event,
                &packet_buffer,
                &io,
                &state,
                &stats,
                &rate_limiter,
                &local_private,
                &local_public,
                &mut scratch,
            );

            // Drain a bounded batch without another blocking epoll_wait. The
            // budget lets other workers and timer ticks make progress under load.
            for _ in 1..PACKET_BATCH_SIZE {
                if stopping.load(Ordering::Acquire) {
                    break;
                }
                let Some(event) = io.try_packet(&mut worker_io, &mut packet_buffer)? else {
                    break;
                };
                process_packet(
                    event,
                    &packet_buffer,
                    &io,
                    &state,
                    &stats,
                    &rate_limiter,
                    &local_private,
                    &local_public,
                    &mut scratch,
                );
            }
        }

        if worker_id == 0 && last_timer_tick.elapsed() >= TIMER_POLL_INTERVAL {
            run_timers(&io, &state, &rate_limiter, &stats, &mut scratch);
            last_timer_tick = Instant::now();
        }
    }
    Ok(())
}

const PACKET_BATCH_SIZE: usize = 64;

#[allow(clippy::too_many_arguments)]
// Dispatch one received packet and update aggregate ingress/drop counters.
fn process_packet(
    event: crate::platform::ReceivedPacket,
    packet_buffer: &[u8],
    io: &Arc<PacketIo>,
    state: &Arc<RwLock<DeviceState>>,
    stats: &DeviceCounters,
    rate_limiter: &Arc<RateLimiter>,
    local_private: &StaticSecret,
    local_public: &PublicKey,
    scratch: &mut [u8],
) {
    let packet = &packet_buffer[..event.len];
    match event.source {
        PacketSource::Udp(source) => {
            stats.received_udp_packets.fetch_add(1, Ordering::Relaxed);
            if !handle_udp(
                io,
                state,
                stats,
                rate_limiter,
                local_private,
                local_public,
                source,
                packet,
                scratch,
            ) {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
        PacketSource::Tun => {
            stats.received_tun_packets.fetch_add(1, Ordering::Relaxed);
            if !handle_tun(io, state, packet, scratch) {
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

// Validate and classify an inbound datagram, then pass it to the selected tunnel.
fn handle_udp(
    io: &Arc<PacketIo>,
    state: &Arc<RwLock<DeviceState>>,
    stats: &DeviceCounters,
    rate_limiter: &Arc<RateLimiter>,
    local_private: &StaticSecret,
    local_public: &PublicKey,
    source: SocketAddr,
    datagram: &[u8],
    scratch: &mut [u8],
) -> bool {
    let parsed = match Tunn::parse_packet(datagram) {
        Ok(packet) => packet,
        Err(_) => return false,
    };
    let prepared = match rate_limiter.prepare_packet(Some(source.ip()), parsed, scratch) {
        Ok(packet) => packet,
        Err(TunnResult::WriteToNetwork(cookie)) => {
            return io.send_udp(source, cookie).is_ok();
        }
        Err(_) => return false,
    };

    let peer_and_kind = match prepared.packet() {
        Packet::HandshakeInit(init) => {
            let peer_key = match parse_handshake_anon(local_private, local_public, init) {
                Ok(half) => half.peer_static_public,
                Err(_) => return false,
            };
            let peer = read_lock(state).peers.get(&peer_key).cloned();
            let Some(peer) = peer else {
                return false;
            };
            Some((peer, PacketKind::Handshake))
        }
        Packet::HandshakeResponse(response) => {
            lookup_indexed_peer(state, response.receiver_idx, PacketKind::Handshake)
        }
        Packet::PacketCookieReply(reply) => {
            lookup_indexed_peer(state, reply.receiver_idx, PacketKind::Cookie)
        }
        Packet::PacketData(data) => lookup_indexed_peer(state, data.receiver_idx, PacketKind::Data),
    };
    let Some((peer, packet_kind)) = peer_and_kind else {
        return false;
    };

    let (result, flush_endpoint) = {
        let mut runtime = lock(&peer.runtime);
        let result = runtime.tunnel.handle_prepared_packet(prepared, scratch);
        let accepted = !matches!(&result, TunnResult::Err(_));
        let flush_queue = accepted && matches!(&result, TunnResult::WriteToNetwork(_));
        if accepted && packet_kind != PacketKind::Cookie {
            runtime.endpoint = Some(source);
            runtime.pending_handshake = false;
        }
        let endpoint = flush_queue.then(|| runtime.endpoint.unwrap_or(source));
        (result, endpoint)
    };
    let mut io_success = true;
    match result {
        TunnResult::WriteToNetwork(packet) => {
            if io.send_udp(source, packet).is_err() {
                io_success = false;
            }
        }
        TunnResult::WriteToTunnelV4(packet, source_ip) => {
            if !write_inner_packet(io, state, stats, &peer, packet, IpAddr::V4(source_ip)) {
                io_success = false;
            }
        }
        TunnResult::WriteToTunnelV6(packet, source_ip) => {
            if !write_inner_packet(io, state, stats, &peer, packet, IpAddr::V6(source_ip)) {
                io_success = false;
            }
        }
        TunnResult::Done => {}
        TunnResult::Err(_) => return false,
    }

    if let Some(endpoint) = flush_endpoint {
        loop {
            let queued = {
                let mut runtime = lock(&peer.runtime);
                runtime.tunnel.decapsulate(None, &[], scratch)
            };
            match queued {
                TunnResult::WriteToNetwork(packet) => {
                    if io.send_udp(endpoint, packet).is_err() {
                        io_success = false;
                    }
                }
                TunnResult::WriteToTunnelV4(packet, source_ip) => {
                    if !write_inner_packet(io, state, stats, &peer, packet, IpAddr::V4(source_ip)) {
                        io_success = false;
                    }
                }
                TunnResult::WriteToTunnelV6(packet, source_ip) => {
                    if !write_inner_packet(io, state, stats, &peer, packet, IpAddr::V6(source_ip)) {
                        io_success = false;
                    }
                }
                TunnResult::Done | TunnResult::Err(_) => break,
            }
        }
    }
    io_success
}

// Enforce the peer's AllowedIPs source ownership before writing decrypted data to TUN.
fn write_inner_packet(
    io: &PacketIo,
    state: &RwLock<DeviceState>,
    stats: &DeviceCounters,
    peer: &Arc<Peer>,
    packet: &[u8],
    source_ip: IpAddr,
) -> bool {
    if !allowed_source(state, peer, source_ip) {
        stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
        return true;
    }

    if io.write_tun(packet).is_ok() {
        peer.count_rx(packet.len());
        true
    } else {
        false
    }
}

// Resolve a response, cookie, or data packet by its receiver index.
fn lookup_indexed_peer(
    state: &Arc<RwLock<DeviceState>>,
    receiver_index: u32,
    packet_kind: PacketKind,
) -> Option<(Arc<Peer>, PacketKind)> {
    read_lock(state)
        .by_receiver_index(receiver_index)
        .map(|peer| (peer, packet_kind))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PacketKind {
    Handshake,
    Cookie,
    Data,
}

// Route an outbound TUN packet and ask BoringTun to encapsulate or queue it.
fn handle_tun(
    io: &Arc<PacketIo>,
    state: &Arc<RwLock<DeviceState>>,
    packet: &[u8],
    scratch: &mut [u8],
) -> bool {
    let Some(destination) = Tunn::dst_address(packet) else {
        return false;
    };
    let peer = read_lock(state).by_route(destination);
    let Some(peer) = peer else {
        return false;
    };

    let (endpoint, output) = {
        let mut runtime = lock(&peer.runtime);
        let endpoint = runtime.endpoint;
        let output = runtime.tunnel.encapsulate(packet, scratch);
        let packet_queued_for_handshake = matches!(&output, TunnResult::Done)
            || matches!(&output, TunnResult::WriteToNetwork(datagram) if is_handshake_initiation(datagram));
        if endpoint.is_none() && packet_queued_for_handshake {
            runtime.pending_handshake = true;
        }
        (endpoint, output)
    };
    match output {
        TunnResult::WriteToNetwork(datagram) => {
            let handshake_is_queued = endpoint.is_none() && is_handshake_initiation(&datagram);
            if endpoint.is_some() || handshake_is_queued {
                peer.count_tx(packet.len());
            }
            if let Some(endpoint) = endpoint {
                if io.send_udp(endpoint, &datagram).is_err() {
                    return false;
                }
            } else if is_handshake_initiation(&datagram) {
                // BoringTun queued the inner packet while producing the initiation.
            } else {
                return false;
            }
        }
        // With no established session, BoringTun queues the inner packet. It
        // returns Done when a handshake is already in progress and emits the
        // initiation only once.
        TunnResult::Done => peer.count_tx(packet.len()),
        TunnResult::Err(_) => return false,
        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => return false,
    }
    true
}

// Identify handshake-initiation packets by their little-endian message type.
fn is_handshake_initiation(datagram: &[u8]) -> bool {
    datagram.len() >= 4 && u32::from_le_bytes(datagram[..4].try_into().unwrap()) == 1
}

// Advance tunnel timers for peers with endpoints and account for failed sends.
fn run_timers(
    io: &Arc<PacketIo>,
    state: &Arc<RwLock<DeviceState>>,
    rate_limiter: &RateLimiter,
    stats: &DeviceCounters,
    scratch: &mut [u8],
) {
    rate_limiter.reset_count();
    let peers = read_lock(state).peers.values().cloned().collect::<Vec<_>>();
    for peer in peers {
        let (endpoint, output) = {
            let mut runtime = lock(&peer.runtime);
            let Some(endpoint) = runtime.endpoint else {
                continue;
            };
            let result = runtime.tunnel.update_timers(scratch);
            (endpoint, result)
        };
        if let TunnResult::WriteToNetwork(packet) = output {
            if io.send_udp(endpoint, packet).is_err() {
                stats.timer_send_errors.fetch_add(1, Ordering::Relaxed);
                stats.udp_send_errors.fetch_add(1, Ordering::Relaxed);
                stats.dropped_packets.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
