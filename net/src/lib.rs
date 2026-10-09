//! Userspace TCP/IP and async streams over authenticated WireGuard IP packets.
mod http;
pub use http::{Connector, serve_http};

use portal::PacketPort;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as StackInstant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use std::collections::HashMap;
use std::future::poll_fn;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

const MAX_SOCKETS: usize = 128;
const BUFFER_SIZE: usize = 64 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone)]
pub struct Net {
    manager: Arc<Manager>,
}
struct Manager {
    inner: Arc<Inner>,
    worker: Mutex<Option<JoinHandle<()>>>,
}
struct Inner {
    core: Mutex<Core>,
    wake: Condvar,
    stopping: AtomicBool,
    dropped: Arc<AtomicU64>,
}
struct Core {
    interface: Interface,
    sockets: SocketSet<'static>,
    addresses: Vec<IpAddr>,
    listeners: HashMap<u64, Listening>,
    next_id: u64,
    next_port: u16,
    detached: Vec<(SocketHandle, Instant)>,
    running: bool,
}
struct Listening {
    address: SocketAddr,
    pending: Option<SocketHandle>,
    accepted: mpsc::Sender<(SocketHandle, SocketAddr)>,
}
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}
fn socket() -> tcp::Socket<'static> {
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; BUFFER_SIZE]),
        tcp::SocketBuffer::new(vec![0; BUFFER_SIZE]),
    );
    socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
    socket.set_nagle_enabled(false);
    socket
}
fn endpoint(address: SocketAddr) -> smoltcp::wire::IpEndpoint {
    smoltcp::wire::IpEndpoint::new(address.ip().into(), address.port())
}
fn address(endpoint: smoltcp::wire::IpEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr.into(), endpoint.port)
}

impl Net {
    /// Start a bounded TCP/IP stack. Addresses exist only inside this process.
    pub fn new(port: PacketPort, addresses: Vec<(IpAddr, u8)>, mtu: usize) -> io::Result<Self> {
        if addresses.is_empty() || addresses.len() > 4 || !(1280..=9000).contains(&mtu) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "need 1-4 virtual addresses and MTU 1280-9000",
            ));
        }
        for (ip, prefix) in &addresses {
            if ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || *prefix > if ip.is_ipv4() { 32 } else { 128 }
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid virtual address",
                ));
            }
        }
        let dropped = Arc::new(AtomicU64::new(0));
        let mut device = IpDevice {
            port,
            mtu,
            budget: 64,
            dropped: dropped.clone(),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut device, StackInstant::from_millis(0));
        interface.update_ip_addrs(|ips| {
            for (ip, prefix) in &addresses {
                ips.push(IpCidr::new((*ip).into(), *prefix))
                    .expect("validated address count");
            }
        });
        if let Some((IpAddr::V4(ip), _)) = addresses.iter().find(|(ip, _)| ip.is_ipv4()) {
            interface
                .routes_mut()
                .add_default_ipv4_route(*ip)
                .map_err(|_| io::Error::other("route capacity"))?;
        }
        if let Some((IpAddr::V6(ip), _)) = addresses.iter().find(|(ip, _)| ip.is_ipv6()) {
            interface
                .routes_mut()
                .add_default_ipv6_route(*ip)
                .map_err(|_| io::Error::other("route capacity"))?;
        }
        let inner = Arc::new(Inner {
            core: Mutex::new(Core {
                interface,
                sockets: SocketSet::new(Vec::new()),
                addresses: addresses.iter().map(|(ip, _)| *ip).collect(),
                listeners: HashMap::new(),
                next_id: 0,
                next_port: 49152,
                detached: Vec::new(),
                running: true,
            }),
            wake: Condvar::new(),
            stopping: AtomicBool::new(false),
            dropped,
        });
        let worker_inner = inner.clone();
        let worker = thread::Builder::new()
            .name("portal-net".into())
            .spawn(move || run(worker_inner, device))?;
        Ok(Self {
            manager: Arc::new(Manager {
                inner,
                worker: Mutex::new(Some(worker)),
            }),
        })
    }
    pub fn shutdown(&self) {
        self.manager.stop();
    }
    pub fn health(&self) -> io::Result<()> {
        if self.manager.inner.stopping.load(Ordering::Acquire)
            || lock(&self.manager.worker)
                .as_ref()
                .is_some_and(|worker| worker.is_finished())
        {
            Err(io::Error::other("userspace network is stopped"))
        } else {
            Ok(())
        }
    }
    pub fn dropped_packets(&self) -> u64 {
        self.manager.inner.dropped.load(Ordering::Relaxed)
    }
    pub fn listen(&self, mut address: SocketAddr) -> io::Result<TcpListener> {
        let inner = &self.manager.inner;
        let mut core = lock(&inner.core);
        if !core.running || !core.addresses.contains(&address.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "listener must use a configured virtual IP",
            ));
        }
        if address.port() == 0 {
            address.set_port(allocate_port(&mut core, address.ip())?);
        }
        if core
            .listeners
            .values()
            .any(|listener| listener.address == address)
        {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "virtual listener already exists",
            ));
        }
        if core.sockets.iter().count() >= MAX_SOCKETS {
            return Err(io::Error::other("network socket limit reached"));
        }
        let mut socket = socket();
        socket.listen(endpoint(address)).map_err(io::Error::other)?;
        let handle = core.sockets.add(socket);
        let (accepted, rx) = mpsc::channel(32);
        let id = core.next_id;
        core.next_id += 1;
        core.listeners.insert(
            id,
            Listening {
                address,
                pending: Some(handle),
                accepted,
            },
        );
        inner.wake.notify_all();
        Ok(TcpListener {
            net: self.clone(),
            id,
            address,
            accepted: rx,
        })
    }
    pub async fn connect(&self, remote: SocketAddr) -> io::Result<TcpStream> {
        if remote.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote port is zero",
            ));
        }
        let inner = &self.manager.inner;
        let (handle, local) = {
            let mut core = lock(&inner.core);
            if !core.running {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "network stopped"));
            }
            if core.sockets.iter().count() >= MAX_SOCKETS {
                return Err(io::Error::other("network socket limit reached"));
            }
            let ip = *core
                .addresses
                .iter()
                .find(|ip| ip.is_ipv4() == remote.is_ipv4())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "virtual address family is disabled",
                    )
                })?;
            let local = SocketAddr::new(ip, allocate_port(&mut core, ip)?);
            let mut socket = socket();
            socket
                .connect(core.interface.context(), endpoint(remote), endpoint(local))
                .map_err(io::Error::other)?;
            (core.sockets.add(socket), local)
        };
        let stream = TcpStream {
            net: self.clone(),
            handle,
            local,
            remote,
        };
        inner.wake.notify_all();
        tokio::time::timeout(
            Duration::from_secs(10),
            poll_fn(|cx| {
                let mut core = lock(&inner.core);
                if !core.running {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "network stopped",
                    )));
                }
                let socket = core.sockets.get_mut::<tcp::Socket>(handle);
                match socket.state() {
                    tcp::State::Established | tcp::State::CloseWait => Poll::Ready(Ok(())),
                    tcp::State::Closed => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "virtual connection refused",
                    ))),
                    _ => {
                        socket.register_recv_waker(cx.waker());
                        Poll::Pending
                    }
                }
            }),
        )
        .await
        .map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "virtual TCP connection timed out")
        })??;
        Ok(stream)
    }
}
fn allocate_port(core: &mut Core, ip: IpAddr) -> io::Result<u16> {
    for _ in 49152..=65535 {
        let port = core.next_port;
        core.next_port = if port == 65535 { 49152 } else { port + 1 };
        if !core.sockets.iter().any(|(_, socket)| match socket {
            smoltcp::socket::Socket::Tcp(socket) => socket
                .local_endpoint()
                .is_some_and(|local| local == endpoint(SocketAddr::new(ip, port))),
        }) {
            return Ok(port);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AddrInUse,
        "virtual ephemeral ports exhausted",
    ))
}
impl Manager {
    fn stop(&self) {
        self.inner.stopping.store(true, Ordering::Release);
        self.inner.wake.notify_all();
        if let Some(worker) = lock(&self.worker).take() {
            let _ = worker.join();
            let mut core = lock(&self.inner.core);
            core.running = false;
            for (_, socket) in core.sockets.iter_mut() {
                let smoltcp::socket::Socket::Tcp(socket) = socket;
                socket.abort();
            }
            core.listeners.clear();
        }
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        self.stop();
    }
}

pub struct TcpListener {
    net: Net,
    id: u64,
    address: SocketAddr,
    accepted: mpsc::Receiver<(SocketHandle, SocketAddr)>,
}
impl TcpListener {
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub async fn accept(&mut self) -> io::Result<(TcpStream, SocketAddr)> {
        let (handle, remote) =
            self.accepted.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "virtual listener closed")
            })?;
        Ok((
            TcpStream {
                net: self.net.clone(),
                handle,
                local: self.address,
                remote,
            },
            remote,
        ))
    }
}
impl Drop for TcpListener {
    fn drop(&mut self) {
        let inner = &self.net.manager.inner;
        let mut core = lock(&inner.core);
        if let Some(listener) = core.listeners.remove(&self.id) {
            if let Some(handle) = listener.pending {
                core.sockets.remove(handle);
            }
        }
        while let Ok((handle, _)) = self.accepted.try_recv() {
            core.sockets.remove(handle);
        }
        inner.wake.notify_all();
    }
}
pub struct TcpStream {
    net: Net,
    handle: SocketHandle,
    local: SocketAddr,
    remote: SocketAddr,
}
impl TcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
    pub fn peer_addr(&self) -> SocketAddr {
        self.remote
    }
}
impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let inner = &self.net.manager.inner;
        let mut core = lock(&inner.core);
        if !core.running {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "network stopped",
            )));
        }
        let socket = core.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.can_recv() {
            let count = socket
                .recv_slice(buffer.initialize_unfilled())
                .map_err(io::Error::other)?;
            buffer.advance(count);
            inner.wake.notify_all();
            Poll::Ready(Ok(()))
        } else if !socket.may_recv() {
            Poll::Ready(Ok(()))
        } else {
            socket.register_recv_waker(cx.waker());
            Poll::Pending
        }
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let inner = &self.net.manager.inner;
        let mut core = lock(&inner.core);
        if !core.running {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "network stopped",
            )));
        }
        let socket = core.sockets.get_mut::<tcp::Socket>(self.handle);
        if !socket.may_send() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "virtual TCP stream closed",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if socket.can_send() {
            let count = socket.send_slice(bytes).map_err(io::Error::other)?;
            inner.wake.notify_all();
            Poll::Ready(Ok(count))
        } else {
            socket.register_send_waker(cx.waker());
            Poll::Pending
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut core = lock(&self.net.manager.inner.core);
        if !core.running {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "network stopped",
            )));
        }
        let socket = core.sockets.get_mut::<tcp::Socket>(self.handle);
        if socket.send_queue() == 0 {
            Poll::Ready(Ok(()))
        } else {
            socket.register_send_waker(cx.waker());
            Poll::Pending
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = &self.net.manager.inner;
        lock(&inner.core)
            .sockets
            .get_mut::<tcp::Socket>(self.handle)
            .close();
        inner.wake.notify_all();
        Poll::Ready(Ok(()))
    }
}
impl Drop for TcpStream {
    fn drop(&mut self) {
        let inner = &self.net.manager.inner;
        let mut core = lock(&inner.core);
        core.sockets.get_mut::<tcp::Socket>(self.handle).close();
        core.detached.push((self.handle, Instant::now()));
        inner.wake.notify_all();
    }
}
fn run(inner: Arc<Inner>, mut device: IpDevice) {
    let start = Instant::now();
    while !inner.stopping.load(Ordering::Acquire) {
        let mut core = lock(&inner.core);
        device.budget = 64;
        let timestamp = StackInstant::from_millis(start.elapsed().as_millis() as i64);
        let Core {
            interface, sockets, ..
        } = &mut *core;
        interface.poll(timestamp, &mut device, sockets);
        let ids: Vec<_> = core.listeners.keys().copied().collect();
        for id in ids {
            let pending = core.listeners[&id].pending;
            if let Some(handle) = pending {
                let socket = core.sockets.get::<tcp::Socket>(handle);
                if matches!(
                    socket.state(),
                    tcp::State::Established | tcp::State::CloseWait
                ) {
                    let remote = address(socket.remote_endpoint().expect("connected socket"));
                    core.listeners.get_mut(&id).unwrap().pending = None;
                    if core.listeners[&id]
                        .accepted
                        .try_send((handle, remote))
                        .is_err()
                    {
                        core.sockets.remove(handle);
                    }
                } else if socket.state() == tcp::State::Closed {
                    core.sockets.remove(handle);
                    core.listeners.get_mut(&id).unwrap().pending = None;
                }
            }
            if core.listeners[&id].pending.is_none() && core.sockets.iter().count() < MAX_SOCKETS {
                let mut socket = socket();
                if socket.listen(endpoint(core.listeners[&id].address)).is_ok() {
                    let handle = core.sockets.add(socket);
                    core.listeners.get_mut(&id).unwrap().pending = Some(handle);
                }
            }
        }
        let detached = std::mem::take(&mut core.detached);
        for (handle, since) in detached {
            if core.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Closed
                || since.elapsed() >= Duration::from_secs(10)
            {
                core.sockets.remove(handle);
            } else {
                core.detached.push((handle, since));
            }
        }
        let _ = inner.wake.wait_timeout(core, POLL_INTERVAL);
    }
    let mut core = lock(&inner.core);
    core.running = false;
    for (_, socket) in core.sockets.iter_mut() {
        let smoltcp::socket::Socket::Tcp(socket) = socket;
        socket.abort();
    }
    core.listeners.clear();
}
struct IpDevice {
    port: PacketPort,
    mtu: usize,
    budget: usize,
    dropped: Arc<AtomicU64>,
}
struct Receive(Vec<u8>);
struct Transmit<'a> {
    port: &'a PacketPort,
    dropped: &'a AtomicU64,
}
impl Device for IpDevice {
    type RxToken<'a>
        = Receive
    where
        Self: 'a;
    type TxToken<'a>
        = Transmit<'a>
    where
        Self: 'a;
    fn receive(&mut self, _timestamp: StackInstant) -> Option<(Receive, Transmit<'_>)> {
        if self.budget == 0 {
            return None;
        }
        let mut bytes = vec![0; 65535];
        match self.port.recv(&mut bytes) {
            Ok(size) => {
                self.budget -= 1;
                bytes.truncate(size);
                Some((
                    Receive(bytes),
                    Transmit {
                        port: &self.port,
                        dropped: &self.dropped,
                    },
                ))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                None
            }
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
    fn transmit(&mut self, _timestamp: StackInstant) -> Option<Transmit<'_>> {
        Some(Transmit {
            port: &self.port,
            dropped: &self.dropped,
        })
    }
    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
impl RxToken for Receive {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
impl TxToken for Transmit<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut bytes = vec![0; len];
        let result = f(&mut bytes);
        if self.port.send(&bytes).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        result
    }
}
