type EventToken = u64;
use libc::{epoll_create1, epoll_ctl, epoll_event};
use crate::Error::{self, OS};

const MAX_EVENTS: i32 = 64;

pub trait Event {
    fn fd(&self) -> RawFd;

}

struct Poller {
    fd: RawFd,
}

impl Poller {
    pub fn new() -> Result<Poller, Error> {
        let epoll_fd = unsafe {epoll_create1(0)};
        if epoll_fd < 0 {
            return Err(OS(std::io::Error::last_os_error()))
        }

        Ok(Poller {fd: epoll_fd})
    }

    fn register_fd(&self, fd: RawFd, data: u64) -> Result<(), Error> {
        let mut epoll_event = epoll_event {
            events: EPOLLIN as u32,
            u64: data
        };
        
        let status = unsafe { epoll_ctl(self.epoll_fd, EPOLL_CTL_ADD, fd, &mut epoll_event) };
        if status < 0 {
            return Err(OS(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    pub fn wait(&self, timeout_ms: i32) -> Result<(), Error> {
        let mut events = [epoll_event {events: 0, u64: 0}; MAX_EVENTS];
         
    }

}
