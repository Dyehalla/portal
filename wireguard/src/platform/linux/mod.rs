use std::fs::File;
use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use super::{PacketSource, ReceivedPacket};

const EVENT_UDP4: u64 = 1;
const EVENT_UDP6: u64 = 2;
const EVENT_IP: u64 = 3;
const EVENT_WAKE: u64 = 4;
/// Bounded datagram link carrying plaintext IP packets between WireGuard and a userspace stack.
#[derive(Clone)]
pub struct PacketPort {
    socket: Arc<UnixDatagram>,
}
impl PacketPort {
    pub fn send(&self, packet: &[u8]) -> io::Result<usize> {
        self.socket.send(packet)
    }
    pub fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buffer)
    }
}

pub(crate) struct PacketIo {
    udp_v4: Option<UdpSocket>,
    udp_v6: Option<UdpSocket>,
    listen_addr: SocketAddr,
    ip: UnixDatagram,
    port: PacketPort,
    wakes: Mutex<Vec<Weak<File>>>,
    stopped: AtomicBool,
}

pub(crate) struct WorkerIo {
    epoll: OwnedFd,
    udp_v4: Option<UdpSocket>,
    udp_v6: Option<UdpSocket>,
    ip: UnixDatagram,
    wake: Arc<File>,
    next_poll_index: usize,
}

impl PacketIo {
    /// Bind the requested family and optionally its wildcard counterpart, create an internal IP packet channel.
    pub(crate) fn open(listen: SocketAddr, dual_stack: bool) -> io::Result<Self> {
        let (udp_v4, udp_v6, listen_addr) = bind_udp_pair(listen, dual_stack)?;
        let (ip, socket) = UnixDatagram::pair()?;
        ip.set_nonblocking(true)?;
        socket.set_nonblocking(true)?;
        let port = PacketPort {
            socket: Arc::new(socket),
        };
        Ok(Self {
            udp_v4,
            udp_v6,
            listen_addr,
            ip,
            port,
            wakes: Mutex::new(Vec::new()),
            stopped: AtomicBool::new(false),
        })
    }
    /// Return the address bound in the configured primary family.
    pub(crate) fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.listen_addr)
    }

    /// Clone the shared sockets and register this worker's epoll and wake descriptors.
    pub(crate) fn create_worker(&self) -> io::Result<WorkerIo> {
        let udp_v4 = self.udp_v4.as_ref().map(UdpSocket::try_clone).transpose()?;
        let udp_v6 = self.udp_v6.as_ref().map(UdpSocket::try_clone).transpose()?;
        let ip = self.ip.try_clone()?;
        let epoll_fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if epoll_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let epoll = unsafe { OwnedFd::from_raw_fd(epoll_fd) };
        let wake_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if wake_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let wake = Arc::new(unsafe { File::from_raw_fd(wake_fd) });

        if let Some(udp_v4) = &udp_v4 {
            add_epoll_fd(epoll.as_raw_fd(), udp_v4.as_raw_fd(), EVENT_UDP4)?;
        }
        if let Some(udp_v6) = &udp_v6 {
            add_epoll_fd(epoll.as_raw_fd(), udp_v6.as_raw_fd(), EVENT_UDP6)?;
        }
        add_epoll_fd(epoll.as_raw_fd(), ip.as_raw_fd(), EVENT_IP)?;
        add_epoll_fd(epoll.as_raw_fd(), wake.as_raw_fd(), EVENT_WAKE)?;
        self.wakes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::downgrade(&wake));

        Ok(WorkerIo {
            epoll,
            udp_v4,
            udp_v6,
            ip,
            wake,
            next_poll_index: 0,
        })
    }

    /// Wait for one ready UDP or internal IP packet, respecting the optional timer timeout.
    pub(crate) fn wait_packet(
        &self,
        worker: &mut WorkerIo,
        buffer: &mut [u8],
        timeout: Option<Duration>,
    ) -> io::Result<Option<ReceivedPacket>> {
        if self.stopped.load(Ordering::Acquire) {
            return Ok(None);
        }
        let timeout_ms = timeout
            .map(|timeout| timeout.as_millis() as i32)
            .unwrap_or(-1);
        let mut events: [libc::epoll_event; 8] = std::array::from_fn(|_| unsafe {
            MaybeUninit::<libc::epoll_event>::zeroed().assume_init()
        });
        let count = unsafe {
            libc::epoll_wait(
                worker.epoll.as_raw_fd(),
                events.as_mut_ptr(),
                events.len() as i32,
                timeout_ms,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(error);
        }
        if count == 0 {
            return Ok(None);
        }

        for event in events.iter().take(count as usize) {
            match event.u64 {
                EVENT_WAKE => {
                    drain_eventfd(worker.wake.as_raw_fd());
                    return Ok(None);
                }
                EVENT_UDP4 | EVENT_UDP6 | EVENT_IP => {
                    if let Some(packet) = read_event(worker, event.u64, buffer)? {
                        return Ok(Some(packet));
                    }
                }
                _ => {}
            }
        }
        Ok(None)
    }

    /// Read another packet without waiting for a new epoll event. Workers use
    /// this after the first ready packet to drain a bounded batch.
    pub(crate) fn try_packet(
        &self,
        worker: &mut WorkerIo,
        buffer: &mut [u8],
    ) -> io::Result<Option<ReceivedPacket>> {
        if self.stopped.load(Ordering::Acquire) {
            return Ok(None);
        }
        for offset in 0..3 {
            let index = (worker.next_poll_index + offset) % 3;
            let token = match index {
                0 => EVENT_UDP4,
                1 => EVENT_UDP6,
                _ => EVENT_IP,
            };
            if let Some(packet) = read_event(worker, token, buffer)? {
                return Ok(Some(packet));
            }
        }
        Ok(None)
    }

    /// Send one datagram through the socket matching the endpoint's address family.
    pub(crate) fn send_udp(&self, endpoint: SocketAddr, packet: &[u8]) -> io::Result<()> {
        let socket = match endpoint {
            SocketAddr::V4(_) => self.udp_v4.as_ref(),
            SocketAddr::V6(_) => self.udp_v6.as_ref(),
        };
        let socket = socket.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "UDP socket for endpoint address family is disabled",
            )
        })?;
        let sent = socket.send_to(packet, endpoint)?;
        if sent != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "UDP datagram was only partially sent",
            ));
        }
        Ok(())
    }

    /// Deliver an authenticated IP packet to the userspace stack.
    pub(crate) fn write_ip(&self, packet: &[u8]) -> io::Result<()> {
        if self.ip.send(packet)? != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial IP packet",
            ));
        }
        Ok(())
    }
    pub(crate) fn packet_port(&self) -> PacketPort {
        self.port.clone()
    }

    /// Mark the backend stopped and wake every worker blocked in epoll.
    pub(crate) fn wake_all(&self) {
        self.stopped.store(true, Ordering::Release);
        let mut wakes = self
            .wakes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        wakes.retain(|wake| {
            let Some(wake) = wake.upgrade() else {
                return false;
            };
            signal_eventfd(wake.as_raw_fd());
            true
        });
    }
}

// Mirror loopback/wildcard scope; a specific interface address enables only its family.
fn bind_udp_pair(
    listen: SocketAddr,
    dual_stack: bool,
) -> io::Result<(Option<UdpSocket>, Option<UdpSocket>, SocketAddr)> {
    match listen {
        SocketAddr::V4(address) => {
            let udp_v4 = UdpSocket::bind(SocketAddr::V4(address))?;
            let port = udp_v4.local_addr()?.port();
            udp_v4.set_nonblocking(true)?;
            let udp_v6 =
                if dual_stack && (address.ip().is_loopback() || address.ip().is_unspecified()) {
                    Some(bind_v6(SocketAddrV6::new(
                        if address.ip().is_loopback() {
                            Ipv6Addr::LOCALHOST
                        } else {
                            Ipv6Addr::UNSPECIFIED
                        },
                        port,
                        0,
                        0,
                    ))?)
                } else {
                    None
                };
            let local_addr = udp_v4.local_addr()?;
            Ok((Some(udp_v4), udp_v6, local_addr))
        }
        SocketAddr::V6(address) => {
            let udp_v6 = bind_v6(address)?;
            let port = udp_v6.local_addr()?.port();
            let udp_v4 =
                if dual_stack && (address.ip().is_loopback() || address.ip().is_unspecified()) {
                    let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                        if address.ip().is_loopback() {
                            Ipv4Addr::LOCALHOST
                        } else {
                            Ipv4Addr::UNSPECIFIED
                        },
                        port,
                    )))?;
                    socket.set_nonblocking(true)?;
                    Some(socket)
                } else {
                    None
                };
            let local_addr = udp_v6.local_addr()?;
            Ok((udp_v4, Some(udp_v6), local_addr))
        }
    }
}

// Create a nonblocking IPv6-only socket so its port can coexist with IPv4.
fn bind_v6(address: SocketAddrV6) -> io::Result<UdpSocket> {
    let fd = unsafe {
        libc::socket(
            libc::AF_INET6,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::IPPROTO_UDP,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let value: libc::c_int = 1;
    let result = unsafe {
        libc::setsockopt(
            owned.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    let address = libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: address.port().to_be(),
        sin6_flowinfo: address.flowinfo(),
        sin6_addr: libc::in6_addr {
            s6_addr: address.ip().octets(),
        },
        sin6_scope_id: address.scope_id(),
    };
    let result = unsafe {
        libc::bind(
            owned.as_raw_fd(),
            (&address as *const libc::sockaddr_in6).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw_fd = owned.into_raw_fd();
    Ok(unsafe { UdpSocket::from_raw_fd(raw_fd) })
}

#[cfg(test)]
mod bind_tests {
    use super::*;

    #[test]
    #[ignore = "requires local UDP sockets"]
    fn dual_stack_preserves_loopback_and_wildcard_scope() {
        for listen in ["127.0.0.1:0", "[::1]:0", "0.0.0.0:0", "[::]:0"] {
            let listen: SocketAddr = listen.parse().unwrap();
            let (v4, v6, primary) = bind_udp_pair(listen, true).unwrap();
            for socket in [v4, v6] {
                let address = socket.unwrap().local_addr().unwrap();
                assert_eq!(address.ip().is_loopback(), listen.ip().is_loopback());
                assert_eq!(address.ip().is_unspecified(), listen.ip().is_unspecified());
                assert_eq!(address.port(), primary.port());
            }
        }
    }
}

// Read one packet from a ready descriptor; WouldBlock means another worker won the race.
fn read_event(
    worker: &mut WorkerIo,
    token: u64,
    buffer: &mut [u8],
) -> io::Result<Option<ReceivedPacket>> {
    let received = match token {
        EVENT_UDP4 => {
            let Some(socket) = worker.udp_v4.as_ref() else {
                return Ok(None);
            };
            match socket.recv_from(buffer) {
                Ok((len, source)) => Some(ReceivedPacket {
                    source: PacketSource::Udp(source),
                    len,
                }),
                Err(error) => return classify_read_error(error),
            }
        }
        EVENT_UDP6 => {
            let Some(socket) = worker.udp_v6.as_ref() else {
                return Ok(None);
            };
            match socket.recv_from(buffer) {
                Ok((len, source)) => Some(ReceivedPacket {
                    source: PacketSource::Udp(source),
                    len,
                }),
                Err(error) => return classify_read_error(error),
            }
        }
        EVENT_IP => match worker.ip.recv(buffer) {
            Ok(0) => None,
            Ok(len) => Some(ReceivedPacket {
                source: PacketSource::Ip,
                len,
            }),
            Err(error) => return classify_read_error(error),
        },
        _ => None,
    };
    if received.is_some() {
        worker.next_poll_index = match token {
            EVENT_UDP4 => 0,
            EVENT_UDP6 => 1,
            _ => 2,
        };
    }
    Ok(received)
}

// Treat interruption and stale readiness as no packet, while surfacing other I/O errors.
fn classify_read_error(error: io::Error) -> io::Result<Option<ReceivedPacket>> {
    if error.kind() == io::ErrorKind::WouldBlock || error.kind() == io::ErrorKind::Interrupted {
        Ok(None)
    } else {
        Err(error)
    }
}

// Register a descriptor with a stable event token in one worker's epoll set.
fn add_epoll_fd(epoll_fd: libc::c_int, fd: libc::c_int, token: u64) -> io::Result<()> {
    let mut event = unsafe { MaybeUninit::<libc::epoll_event>::zeroed().assume_init() };
    event.events = libc::EPOLLIN as u32;
    event.u64 = token;
    let result = unsafe { libc::epoll_ctl(epoll_fd, libc::EPOLL_CTL_ADD, fd, &mut event) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

// Clear the eventfd counter after a shutdown wakeup.
fn drain_eventfd(fd: libc::c_int) {
    let mut value = 0u64;
    unsafe {
        libc::read(
            fd,
            (&mut value as *mut u64).cast(),
            std::mem::size_of::<u64>(),
        );
    }
}

// Wake an epoll waiter, retrying if the write was interrupted.
fn signal_eventfd(fd: libc::c_int) {
    let value = 1u64;
    loop {
        let result = unsafe {
            libc::write(
                fd,
                (&value as *const u64).cast(),
                std::mem::size_of::<u64>(),
            )
        };
        if result >= 0 {
            return;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return;
    }
}
