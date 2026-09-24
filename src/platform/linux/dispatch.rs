use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use crate::device::{Device, TunnelAssignment};
use crate::index_table::{IndexTable, Route, WorkerId};
use crate::platform::pipeline::{Completion, DispatcherPort, PacketKind, RxMessage, TxTarget};
use crate::protocol::{
    COOKIE_REPLY_LEN, CookieChallenge, CookieChecker, DATA_HEADER_LEN, HANDSHAKE_INIT_LEN,
    HANDSHAKE_RESPONSE_LEN, MAX_PACKET_SIZE, MSG_DATA, MSG_HANDSHAKE_INIT, MSG_HANDSHAKE_RESPONSE,
    Packet, verify_handshake_macs,
};
use crate::ring::{BufHandle, BufPool};

use super::event::{EventArray, EventToken, Poller};
use super::socket::TunSocket;

const BUFFER_HEADROOM: usize = 16;
const UDP_BATCH: usize = 32;
const COOKIE_REPLY_BUFFER: usize = COOKIE_REPLY_LEN;
const TIMER_INTERVAL: Duration = Duration::from_secs(1);

/// Linux dispatcher backend: one UDP socket and one TUN queue feed per-worker
/// SPSC rings. The dispatcher is the only socket reader and buffer allocator.
pub struct DispatchSource {
    udp: std::net::UdpSocket,
    tun: TunSocket,
    poller: Poller,
    events: EventArray,
    pool: BufPool,
    workers: HashMap<WorkerId, DispatcherPort>,
    snapshot: std::sync::Arc<arc_swap::ArcSwap<crate::device::DeviceSnapshot>>,
    indices: std::sync::Arc<IndexTable>,
    cookies: CookieChecker,
    endpoints: HashMap<Route, SocketAddr>,
    pending_flush: VecDeque<Route>,
    last_timer: Instant,
}

impl DispatchSource {
    /// Opens the read side around existing device sockets and registered workers.
    pub fn new(
        udp: std::net::UdpSocket,
        tun: TunSocket,
        device: &Device,
        workers: HashMap<WorkerId, DispatcherPort>,
        buffer_count: usize,
    ) -> io::Result<Self> {
        if buffer_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer pool must not be empty",
            ));
        }
        udp.set_nonblocking(true)?;
        let poller = Poller::new()?;
        poller.register(EventToken::Udp, udp.as_raw_fd())?;
        poller.register(EventToken::Tun, tun.fd())?;
        for (&worker, port) in &workers {
            if let Some(fd) = &port.completion_fd {
                poller.register(EventToken::WorkerCompletion(worker), fd.as_raw_fd())?;
            }
        }
        let snapshot = device.snapshot();
        let mut endpoints = HashMap::new();
        for (_, assignment, endpoint) in snapshot.assignments() {
            if let Some(endpoint) = endpoint {
                endpoints.insert(route(assignment), endpoint);
            }
        }
        let cookies = CookieChecker::new(*snapshot.static_public());
        Ok(Self {
            udp,
            tun,
            poller,
            events: EventArray::new(),
            pool: BufPool::new(
                buffer_count,
                MAX_PACKET_SIZE + BUFFER_HEADROOM,
                BUFFER_HEADROOM,
            ),
            workers,
            snapshot: device.snapshot_source(),
            indices: device.index_table(),
            cookies,
            endpoints,
            pending_flush: VecDeque::new(),
            last_timer: Instant::now(),
        })
    }

    /// Replaces the active peer/configuration snapshot after a control-plane update.
    pub fn publish_snapshot(&self, device: &Device) {
        self.snapshot.store(device.snapshot());
    }

    /// Runs the dispatcher poll loop until the socket or TUN reports a local error.
    pub fn run(&mut self) -> io::Result<()> {
        loop {
            self.drain_completions();
            self.poller.poll(10, &mut self.events)?;
            for index in 0..self.events.count {
                match self.events.data[index].token {
                    EventToken::Udp => self.receive_udp_batch()?,
                    EventToken::Tun => self.receive_tun_packets()?,
                    EventToken::WorkerCompletion(worker) => self.clear_completion_signal(worker)?,
                }
            }
            self.drain_completions();
            self.schedule_timers();
            self.schedule_pending_flushes();
            self.cookies.rotate_secret_if_stale(Instant::now());
            self.cookies.reset_count(Instant::now());
        }
    }

    fn clear_completion_signal(&self, worker: WorkerId) -> io::Result<()> {
        let Some(fd) = self
            .workers
            .get(&worker)
            .and_then(|port| port.completion_fd.as_ref())
        else {
            return Ok(());
        };
        let mut counter = 0u64;
        let read = unsafe {
            libc::read(
                fd.as_raw_fd(),
                (&mut counter as *mut u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if read >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock || error.raw_os_error() == Some(libc::EINTR) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn receive_udp_batch(&mut self) -> io::Result<()> {
        loop {
            let mut handles = Vec::with_capacity(UDP_BATCH);
            while handles.len() < UDP_BATCH {
                let Some(handle) = self.pool.allocate() else {
                    break;
                };
                let Some(spare) = self.pool.allocate() else {
                    self.pool.recycle(handle);
                    break;
                };
                handles.push((handle, spare));
            }
            if handles.is_empty() {
                return Ok(());
            }

            let mut addresses = (0..handles.len())
                .map(|_| unsafe { std::mem::zeroed::<libc::sockaddr_storage>() })
                .collect::<Vec<_>>();
            let mut iovecs = handles
                .iter_mut()
                .map(|(handle, _)| libc::iovec {
                    iov_base: handle.storage_mut().as_mut_ptr().cast(),
                    iov_len: MAX_PACKET_SIZE,
                })
                .collect::<Vec<_>>();
            let mut messages = (0..handles.len())
                .map(|_| unsafe { std::mem::zeroed::<libc::mmsghdr>() })
                .collect::<Vec<_>>();
            for index in 0..handles.len() {
                messages[index].msg_hdr.msg_name =
                    (&mut addresses[index] as *mut libc::sockaddr_storage).cast();
                messages[index].msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                messages[index].msg_hdr.msg_iov = &mut iovecs[index];
                messages[index].msg_hdr.msg_iovlen = 1;
            }

            let received = unsafe {
                libc::recvmmsg(
                    self.udp.as_raw_fd(),
                    messages.as_mut_ptr(),
                    messages.len() as libc::c_uint,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                )
            };
            if received < 0 {
                let error = io::Error::last_os_error();
                for (handle, spare) in handles {
                    self.pool.recycle(handle);
                    self.pool.recycle(spare);
                }
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(());
                }
                if error.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(error);
            }
            if received == 0 {
                for (handle, spare) in handles {
                    self.pool.recycle(handle);
                    self.pool.recycle(spare);
                }
                return Ok(());
            }

            let mut handles = handles.into_iter();
            for index in 0..received as usize {
                let (mut handle, spare) =
                    handles.next().expect("one buffer pair per recvmmsg entry");
                let len = messages[index].msg_len as usize;
                let flags = messages[index].msg_hdr.msg_flags;
                if flags & libc::MSG_TRUNC != 0 || len > MAX_PACKET_SIZE {
                    self.pool.recycle(handle);
                    self.pool.recycle(spare);
                    continue;
                }
                handle.set_len(len);
                if let Some(source) =
                    socket_addr(&addresses[index], messages[index].msg_hdr.msg_namelen)
                {
                    self.dispatch_udp(handle, spare, len, source);
                } else {
                    self.pool.recycle(handle);
                    self.pool.recycle(spare);
                }
            }
            for (handle, spare) in handles {
                self.pool.recycle(handle);
                self.pool.recycle(spare);
            }
            if (received as usize) < UDP_BATCH {
                return Ok(());
            }
        }
    }

    fn dispatch_udp(
        &mut self,
        mut handle: BufHandle,
        spare: BufHandle,
        len: usize,
        source: SocketAddr,
    ) {
        let snapshot = self.snapshot.load_full();
        let message_type = handle
            .storage_mut()
            .get(..4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes);
        let Some(message_type) = message_type else {
            self.pool.recycle(handle);
            self.pool.recycle(spare);
            return;
        };

        let assignment = match message_type {
            MSG_HANDSHAKE_INIT => {
                if Packet::parse(&handle.storage_mut()[..len]).is_err()
                    || !self.verify_handshake_mac(source, &mut handle, len)
                {
                    self.pool.recycle(handle);
                    self.pool.recycle(spare);
                    return;
                }
                let peer = match Packet::parse(&handle.storage_mut()[..len]) {
                    Ok(Packet::HandshakeInitiation(initiation)) => {
                        snapshot.identify_initiation(&initiation)
                    }
                    _ => None,
                };
                peer.and_then(|peer| snapshot.assignment_for_peer(&peer))
            }
            MSG_HANDSHAKE_RESPONSE => {
                if Packet::parse(&handle.storage_mut()[..len]).is_err()
                    || !self.verify_handshake_mac(source, &mut handle, len)
                {
                    self.pool.recycle(handle);
                    self.pool.recycle(spare);
                    return;
                }
                let index = u32::from_le_bytes(
                    handle.storage_mut()[8..12]
                        .try_into()
                        .expect("validated response length"),
                );
                self.indices.lookup(index).map(|r| TunnelAssignment {
                    worker: r.worker,
                    tunnel: r.tunnel,
                })
            }
            crate::protocol::MSG_COOKIE_REPLY => {
                match Packet::parse(&handle.storage_mut()[..len]) {
                    Ok(Packet::CookieReply(reply)) => self
                        .indices
                        .lookup(reply.receiver_index)
                        .map(|r| TunnelAssignment {
                            worker: r.worker,
                            tunnel: r.tunnel,
                        }),
                    _ => None,
                }
            }
            MSG_DATA if len >= DATA_HEADER_LEN + 16 => {
                let index = handle
                    .storage_mut()
                    .get(4..8)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map(u32::from_le_bytes);
                index
                    .and_then(|index| self.indices.lookup(index))
                    .map(|r| TunnelAssignment {
                        worker: r.worker,
                        tunnel: r.tunnel,
                    })
            }
            _ => None,
        };
        let Some(assignment) = assignment else {
            self.pool.recycle(handle);
            self.pool.recycle(spare);
            return;
        };
        let route = route(assignment);
        self.push_to_worker(
            assignment.worker,
            RxMessage::Packet {
                handle,
                spare,
                offset: 0,
                len,
                route,
                kind: PacketKind::Udp { source },
            },
        );
    }

    fn verify_handshake_mac(
        &mut self,
        source: SocketAddr,
        handle: &mut BufHandle,
        len: usize,
    ) -> bool {
        let bytes = &handle.storage_mut()[..len];
        let kind = u32::from_le_bytes(bytes[..4].try_into().expect("parsed packet has type"));
        let mac_offset = match kind {
            MSG_HANDSHAKE_INIT if len == HANDSHAKE_INIT_LEN => HANDSHAKE_INIT_LEN - 32,
            MSG_HANDSHAKE_RESPONSE if len == HANDSHAKE_RESPONSE_LEN => HANDSHAKE_RESPONSE_LEN - 32,
            _ => return false,
        };
        let under_load = self.cookies.note_handshake();
        let public_key = *self.snapshot.load().static_public();
        let secret = self.cookies.secret();
        match verify_handshake_macs(&public_key, Some(source.ip()), &secret, under_load, bytes) {
            Ok(()) => true,
            Err(CookieChallenge::WrongMac2 { cookie }) => {
                let sender = u32::from_le_bytes(bytes[4..8].try_into().expect("parsed header"));
                let mac1: [u8; 16] = bytes[mac_offset..mac_offset + 16]
                    .try_into()
                    .expect("parsed mac");
                let mut reply = [0u8; COOKIE_REPLY_BUFFER];
                if let Ok(written) = self
                    .cookies
                    .format_cookie_reply(&mut reply, sender, &cookie, &mac1)
                {
                    let _ = self.udp.send_to(&reply[..written], source);
                }
                false
            }
            Err(CookieChallenge::NotForUs | CookieChallenge::NeedSourceAddress) => false,
        }
    }

    fn receive_tun_packets(&mut self) -> io::Result<()> {
        loop {
            let Some(mut handle) = self.pool.allocate() else {
                return Ok(());
            };
            let Some(spare) = self.pool.allocate() else {
                self.pool.recycle(handle);
                return Ok(());
            };
            let read = match self.tun.read(&mut handle.storage_mut()[BUFFER_HEADROOM..]) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.pool.recycle(handle);
                    self.pool.recycle(spare);
                    return Ok(());
                }
                Err(error) => {
                    self.pool.recycle(handle);
                    self.pool.recycle(spare);
                    return Err(error);
                }
            };
            if read == 0 {
                self.pool.recycle(handle);
                self.pool.recycle(spare);
                return Ok(());
            }
            handle.set_len(BUFFER_HEADROOM + read);
            let packet = &handle.storage_mut()[BUFFER_HEADROOM..BUFFER_HEADROOM + read];
            let Some(destination) = packet_destination(packet) else {
                self.pool.recycle(handle);
                self.pool.recycle(spare);
                continue;
            };
            let assignment = self.snapshot.load().route_for_ip(destination);
            let Some(assignment) = assignment else {
                self.pool.recycle(handle);
                self.pool.recycle(spare);
                continue;
            };
            let route = route(assignment);
            self.push_to_worker(
                assignment.worker,
                RxMessage::Packet {
                    handle,
                    spare,
                    offset: BUFFER_HEADROOM,
                    len: read,
                    route,
                    kind: PacketKind::Tun,
                },
            );
        }
    }

    fn push_to_worker(&mut self, worker: WorkerId, message: RxMessage) -> bool {
        let Some(port) = self.workers.get_mut(&worker) else {
            recycle_message(&mut self.pool, message);
            return false;
        };
        let was_empty = port.ingress.is_empty();
        if let Err(message) = port.ingress.try_push(message) {
            recycle_message(&mut self.pool, message);
            false
        } else {
            if was_empty {
                if let Some(wake) = &port.wake {
                    wake.unpark();
                }
            }
            true
        }
    }

    fn drain_completions(&mut self) {
        let worker_ids = self.workers.keys().copied().collect::<Vec<_>>();
        for worker in worker_ids {
            loop {
                let completion = self
                    .workers
                    .get_mut(&worker)
                    .and_then(|port| port.egress.try_pop());
                let Some(completion) = completion else { break };
                self.complete(completion);
            }
        }
    }

    fn complete(&mut self, completion: Completion) {
        let Completion {
            mut handle,
            recycle,
            offset,
            len,
            route,
            target,
            authenticated_source,
            flush_more,
        } = completion;
        if let Some(source) = authenticated_source {
            self.endpoints.insert(route, source);
        }
        match target {
            TxTarget::Address(address) => {
                if let Some(bytes) = handle.storage_mut().get(offset..offset.saturating_add(len)) {
                    let _ = self.udp.send_to(bytes, address);
                }
            }
            TxTarget::Peer(route) => {
                if let Some(address) = self.endpoints.get(&route).copied() {
                    if let Some(bytes) =
                        handle.storage_mut().get(offset..offset.saturating_add(len))
                    {
                        let _ = self.udp.send_to(bytes, address);
                    }
                }
            }
            TxTarget::Tun => {
                if let Some(bytes) = handle.storage_mut().get(offset..offset.saturating_add(len)) {
                    let _ = self.tun.write(bytes);
                }
            }
            TxTarget::Discard => {}
        }
        self.pool.recycle(handle);
        if let Some(recycle) = recycle {
            self.pool.recycle(recycle);
        }
        if flush_more {
            self.pending_flush.push_back(route);
        }
    }

    fn schedule_pending_flushes(&mut self) {
        let pending = self.pending_flush.len();
        for _ in 0..pending {
            let Some(route) = self.pending_flush.pop_front() else {
                break;
            };
            let Some(handle) = self.pool.allocate() else {
                self.pending_flush.push_front(route);
                break;
            };
            if !self.push_to_worker(
                route.worker,
                RxMessage::Flush {
                    handle,
                    tunnel: route.tunnel,
                },
            ) {
                self.pending_flush.push_back(route);
            }
        }
    }

    fn schedule_timers(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_timer) < TIMER_INTERVAL {
            return;
        }
        self.last_timer = now;
        let assignments = self.snapshot.load().assignments();
        for (_, assignment, _) in assignments {
            let Some(handle) = self.pool.allocate() else {
                break;
            };
            self.push_to_worker(
                assignment.worker,
                RxMessage::Timer {
                    handle,
                    tunnel: assignment.tunnel,
                },
            );
        }
    }
}

fn route(assignment: TunnelAssignment) -> Route {
    Route {
        worker: assignment.worker,
        tunnel: assignment.tunnel,
    }
}

fn recycle_message(pool: &mut BufPool, message: RxMessage) {
    match message {
        RxMessage::Packet { handle, spare, .. } => {
            pool.recycle(handle);
            pool.recycle(spare);
        }
        RxMessage::Timer { handle, .. } | RxMessage::Flush { handle, .. } => pool.recycle(handle),
    }
}

fn packet_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4)? {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).ok()?,
        ))),
        _ => None,
    }
}

fn socket_addr(storage: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    if len < std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t {
        return None;
    }
    match storage.ss_family as libc::c_int {
        libc::AF_INET if len as usize >= std::mem::size_of::<libc::sockaddr_in>() => {
            let address = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes()),
                u16::from_be(address.sin_port),
            )))
        }
        libc::AF_INET6 if len as usize >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let address = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address.sin6_addr.s6_addr),
                u16::from_be(address.sin6_port),
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 and IPv6 TUN packets use the correct destination address offsets.
    #[test]
    fn tun_route_extraction_reads_ipv4_and_ipv6_destinations() {
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x45;
        ipv4[16..20].copy_from_slice(&[192, 0, 2, 7]);
        assert_eq!(
            packet_destination(&ipv4),
            Some("192.0.2.7".parse().unwrap())
        );

        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        ipv6[24..40].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            packet_destination(&ipv6),
            Some("2001:db8::7".parse().unwrap())
        );
    }

    /// Truncated IP packets do not reach cryptokey routing.
    #[test]
    fn a_truncated_ip_packet_has_no_destination() {
        assert_eq!(packet_destination(&[0x45; 12]), None);
        assert_eq!(packet_destination(&[0x60; 20]), None);
    }
}
