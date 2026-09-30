use std::fs::File;
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use super::{PacketSource, ReceivedPacket};

const EVENT_UDP4: u64 = 1;
const EVENT_UDP6: u64 = 2;
const EVENT_TUN: u64 = 3;
const EVENT_WAKE: u64 = 4;
const IFNAMSIZ: usize = 16;
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

pub(crate) struct PacketIo {
    udp_v4: Option<UdpSocket>,
    udp_v6: Option<UdpSocket>,
    listen_addr: SocketAddr,
    tun: File,
    wakes: Mutex<Vec<Weak<File>>>,
    stopped: AtomicBool,
}

pub(crate) struct WorkerIo {
    epoll: OwnedFd,
    udp_v4: Option<UdpSocket>,
    udp_v6: Option<UdpSocket>,
    tun: File,
    wake: Arc<File>,
    next_poll_index: usize,
}

#[repr(C)]
struct TunIfReq {
    name: [libc::c_char; IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

impl PacketIo {
    /// Bind the requested family and optionally its wildcard counterpart, then open TUN.
    pub(crate) fn open(listen: SocketAddr, tun_name: &str, dual_stack: bool) -> io::Result<Self> {
        let (udp_v4, udp_v6, listen_addr) = bind_udp_pair(listen, dual_stack)?;
        let tun = open_tun(tun_name)?;
        Ok(Self {
            udp_v4,
            udp_v6,
            listen_addr,
            tun,
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
        let tun = self.tun.try_clone()?;
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
        add_epoll_fd(epoll.as_raw_fd(), tun.as_raw_fd(), EVENT_TUN)?;
        add_epoll_fd(epoll.as_raw_fd(), wake.as_raw_fd(), EVENT_WAKE)?;
        self.wakes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(Arc::downgrade(&wake));

        Ok(WorkerIo {
            epoll,
            udp_v4,
            udp_v6,
            tun,
            wake,
            next_poll_index: 0,
        })
    }

    /// Wait for one ready UDP or TUN packet, respecting the optional timer timeout.
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
                EVENT_UDP4 | EVENT_UDP6 | EVENT_TUN => {
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
                _ => EVENT_TUN,
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

    /// Write one complete IP packet to the TUN device.
    pub(crate) fn write_tun(&self, packet: &[u8]) -> io::Result<()> {
        let written =
            unsafe { libc::write(self.tun.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if written as usize != packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "TUN accepted only part of an IP packet",
            ));
        }
        Ok(())
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

// Bind both address families to one port, or only the configured family.
fn bind_udp_pair(
    listen: SocketAddr,
    dual_stack: bool,
) -> io::Result<(Option<UdpSocket>, Option<UdpSocket>, SocketAddr)> {
    match listen {
        SocketAddr::V4(address) => {
            let udp_v4 = UdpSocket::bind(SocketAddr::V4(address))?;
            let port = udp_v4.local_addr()?.port();
            udp_v4.set_nonblocking(true)?;
            let udp_v6 = if dual_stack {
                Some(bind_v6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
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
            let udp_v4 = if dual_stack {
                let socket = UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::UNSPECIFIED,
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
        EVENT_TUN => {
            let mut tun = &worker.tun;
            match tun.read(buffer) {
                Ok(0) => None,
                Ok(len) => Some(ReceivedPacket {
                    source: PacketSource::Tun,
                    len,
                }),
                Err(error) => return classify_read_error(error),
            }
        }
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

// Open or create the named Linux TUN interface without packet-information headers.
fn open_tun(name: &str) -> io::Result<File> {
    let name_bytes = name.as_bytes();
    if name_bytes.is_empty() || name_bytes.len() >= IFNAMSIZ || name_bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TUN name must contain 1 to 15 non-NUL bytes",
        ));
    }
    let fd = unsafe {
        libc::open(
            c"/dev/net/tun".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let tun = unsafe { File::from_raw_fd(fd) };
    let mut request = TunIfReq {
        name: [0; IFNAMSIZ],
        flags: IFF_TUN | IFF_NO_PI,
        padding: [0; 22],
    };
    for (to, from) in request.name.iter_mut().zip(name_bytes) {
        *to = *from as libc::c_char;
    }
    let result = unsafe { libc::ioctl(tun.as_raw_fd(), TUNSETIFF, &mut request) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(tun)
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
