use std::io;
use std::os::fd::RawFd;

use crate::index_table::WorkerId;

const MAX_EVENTS: usize = 64;

/// Events returned by the dispatcher poller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventToken {
    Udp,
    Tun,
    WorkerCompletion(WorkerId),
}

impl EventToken {
    fn encode(self) -> u64 {
        match self {
            Self::Udp => 1,
            Self::Tun => 2,
            Self::WorkerCompletion(worker) => ((worker as u64) << 2) | 3,
        }
    }

    fn decode(value: u64) -> Option<Self> {
        match value {
            1 => Some(Self::Udp),
            2 => Some(Self::Tun),
            value if value & 3 == 3 => Some(Self::WorkerCompletion((value >> 2) as usize)),
            _ => None,
        }
    }
}

/// One ready descriptor and its epoll flags.
#[derive(Debug, Clone, Copy)]
pub struct Event {
    pub flags: u32,
    pub token: EventToken,
}

/// Caller-owned storage for one epoll result batch.
pub struct EventArray {
    pub data: [Event; MAX_EVENTS],
    pub count: usize,
}

impl EventArray {
    pub fn new() -> Self {
        Self {
            data: [Event {
                flags: 0,
                token: EventToken::Udp,
            }; MAX_EVENTS],
            count: 0,
        }
    }
}

/// Thin RAII wrapper around one epoll instance.
pub struct Poller {
    fd: RawFd,
}

impl Poller {
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Registers a descriptor for read readiness.
    pub fn register(&self, token: EventToken, fd: RawFd) -> io::Result<()> {
        let mut event = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLERR | libc::EPOLLHUP) as u32,
            u64: token.encode(),
        };
        let status = unsafe { libc::epoll_ctl(self.fd, libc::EPOLL_CTL_ADD, fd, &mut event) };
        if status < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Waits for readable descriptors and fills caller-owned storage.
    pub fn poll(&self, timeout_ms: i32, output: &mut EventArray) -> io::Result<usize> {
        let mut raw = [libc::epoll_event { events: 0, u64: 0 }; MAX_EVENTS];
        let count =
            unsafe { libc::epoll_wait(self.fd, raw.as_mut_ptr(), MAX_EVENTS as i32, timeout_ms) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                output.count = 0;
                return Ok(0);
            }
            return Err(error);
        }

        output.count = 0;
        for event in &raw[..count as usize] {
            let raw_token = unsafe { std::ptr::addr_of!(event.u64).read_unaligned() };
            let flags = unsafe { std::ptr::addr_of!(event.events).read_unaligned() };
            let Some(token) = EventToken::decode(raw_token) else {
                continue;
            };
            output.data[output.count] = Event { flags, token };
            output.count += 1;
        }
        Ok(output.count)
    }
}

impl Drop for Poller {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}
