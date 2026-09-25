use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError};
use std::time::Instant;

use crate::datapath::dispatcher::DispatcherCore;
use crate::datapath::ip::destination as packet_destination;
use crate::datapath::pipeline::{Completion, PacketKind, RxMessage, TxTarget};
use crate::datapath::router::{DatagramRoute, DatagramRouter};
use crate::device::{Device, TunnelAssignment};
use crate::index_table::{Route, WorkerId};
use crate::protocol::MAX_PACKET_SIZE;
use crate::ring::{BufHandle, BufPool};

use super::event::{EventArray, EventToken, Poller};
use super::socket::TunSocket;
use super::worker::WorkerPort;

const BUFFER_HEADROOM: usize = 16;
const UDP_BATCH: usize = 32;
const MAX_UDP_BATCHES_PER_POLL: usize = 4;
const MAX_TUN_PACKETS_PER_POLL: usize = 32;

pub(crate) enum DispatchCommand {
    SetEndpoint {
        route: Route,
        endpoint: Option<SocketAddr>,
        reply: SyncSender<()>,
    },
    Shutdown,
}

/// Linux dispatcher backend: one UDP socket and one TUN queue feed per-worker
/// SPSC rings. The dispatcher is the only socket reader and buffer allocator.
pub struct DispatchSource {
    udp: UdpSocket,
    tun: TunSocket,
    poller: Poller,
    events: EventArray,
    pool: BufPool,
    core: DispatcherCore,
    completion_fds: HashMap<WorkerId, Arc<std::os::fd::OwnedFd>>,
    router: DatagramRouter,
    commands: Receiver<DispatchCommand>,
}

impl DispatchSource {
    /// Opens the read side around existing device sockets and registered workers.
    pub fn new(
        udp: UdpSocket,
        tun: TunSocket,
        device: &Device,
        workers: HashMap<WorkerId, WorkerPort>,
        buffer_count: usize,
        commands: Receiver<DispatchCommand>,
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
        let mut queues = HashMap::with_capacity(workers.len());
        let mut completion_fds = HashMap::with_capacity(workers.len());
        for (worker, port) in workers {
            poller.register(
                EventToken::WorkerCompletion(worker),
                port.completion_fd.as_raw_fd(),
            )?;
            completion_fds.insert(worker, Arc::clone(&port.completion_fd));
            queues.insert(worker, port.queues);
        }
        let snapshot = device.snapshot();
        let snapshot_source = device.snapshot_source();
        let core = DispatcherCore::new(device, queues);
        let router = DatagramRouter::new(
            Arc::clone(&snapshot_source),
            device.index_table(),
            *snapshot.static_public(),
        );
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
            core,
            completion_fds,
            router,
            commands,
        })
    }

    /// Runs until shutdown is requested or the socket/TUN reports a local error.
    pub fn run(&mut self) -> io::Result<()> {
        loop {
            if !self.process_commands() {
                return Ok(());
            }
            self.drain_completions();
            self.poller.poll(10, &mut self.events)?;
            for index in 0..self.events.count {
                match self.events.data[index].token {
                    EventToken::Udp => self.receive_udp_batch()?,
                    EventToken::Tun => self.receive_tun_packets()?,
                    EventToken::WorkerCompletion(worker) => self.clear_completion_signal(worker)?,
                }
            }
            if !self.process_commands() {
                return Ok(());
            }
            self.drain_completions();
            self.schedule_timers();
            self.schedule_pending_flushes();
            self.router.rotate_cookie_secret_if_stale(Instant::now());
            self.router.reset_cookie_count(Instant::now());
        }
    }

    fn process_commands(&mut self) -> bool {
        loop {
            match self.commands.try_recv() {
                Ok(DispatchCommand::SetEndpoint {
                    route,
                    endpoint,
                    reply,
                }) => {
                    self.core.set_endpoint(route, endpoint);
                    let _ = reply.send(());
                }
                Ok(DispatchCommand::Shutdown) => return false,
                Err(TryRecvError::Empty) => return true,
                Err(TryRecvError::Disconnected) => return false,
            }
        }
    }

    fn clear_completion_signal(&self, worker: WorkerId) -> io::Result<()> {
        let Some(fd) = self.completion_fds.get(&worker) else {
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
        let mut batches = 0;
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
            batches += 1;
            if batches >= MAX_UDP_BATCHES_PER_POLL {
                return Ok(());
            }
        }
    }

    fn dispatch_udp(
        &mut self,
        handle: BufHandle,
        spare: BufHandle,
        len: usize,
        source: SocketAddr,
    ) {
        let classification = self.router.classify(source, &handle.bytes()[..len]);
        match classification {
            DatagramRoute::Tunnel(assignment) => {
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
            DatagramRoute::CookieReply { packet, len } => {
                let _ = self.udp.send_to(&packet[..len], source);
                self.pool.recycle(handle);
                self.pool.recycle(spare);
            }
            DatagramRoute::Drop => {
                self.pool.recycle(handle);
                self.pool.recycle(spare);
            }
        }
    }

    fn receive_tun_packets(&mut self) -> io::Result<()> {
        let mut received = 0;
        loop {
            if received >= MAX_TUN_PACKETS_PER_POLL {
                return Ok(());
            }
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
            received += 1;
            handle.set_len(BUFFER_HEADROOM + read);
            let packet = &handle.storage_mut()[BUFFER_HEADROOM..BUFFER_HEADROOM + read];
            let Some(destination) = packet_destination(packet) else {
                self.pool.recycle(handle);
                self.pool.recycle(spare);
                continue;
            };
            let assignment = self.core.route_for_ip(destination);
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
        self.core.push_to_worker(&mut self.pool, worker, message)
    }

    fn drain_completions(&mut self) {
        let worker_ids = self.core.worker_ids();
        for worker in worker_ids {
            loop {
                let completion = self.core.pop_completion(worker);
                let Some(completion) = completion else { break };
                self.complete(completion);
            }
        }
    }

    fn complete(&mut self, completion: Completion) {
        self.core.accept_completion(&completion);
        let Completion {
            mut handle,
            recycle,
            offset,
            len,
            route: _,
            target,
            authenticated_source: _,
            flush_more: _,
        } = completion;
        match target {
            TxTarget::Address(address) => {
                if let Some(bytes) = handle.storage_mut().get(offset..offset.saturating_add(len)) {
                    let _ = self.udp.send_to(bytes, address);
                }
            }
            TxTarget::Peer(route) => {
                if let Some(address) = self.core.endpoint(route) {
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
    }

    fn schedule_pending_flushes(&mut self) {
        self.core.schedule_pending_flushes(&mut self.pool);
    }

    fn schedule_timers(&mut self) {
        self.core.schedule_timers(&mut self.pool, Instant::now());
    }
}

fn route(assignment: TunnelAssignment) -> Route {
    Route {
        worker: assignment.worker,
        tunnel: assignment.tunnel,
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
