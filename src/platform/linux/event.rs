use libc::{epoll_create1, epoll_ctl, epoll_wait, epoll_event, EPOLL_CTL_ADD, EINTR};
use std::{os::fd::RawFd};
use crate::Error::{self, OS};
use crate::platform::socket::PacketSource;
const MAX_EVENTS: usize = 128;  

type EpollFlags = u32;                 

// Event type, passed to epoll u64 data
#[repr(u64)]
#[derive(Clone, Copy)] 
pub enum EventToken {
    Zero = 0, // only for initialization, never registered
    UDP = 1,
    TUN = 2,
}

impl EventToken {
    pub fn match_token(socket: &PacketSource) -> EventToken {
        match socket {
            PacketSource::TUN(_) => EventToken::TUN,
            // PacketSource::UDP(_) => EventToken::UDP,
        }
    }
}

// Same thing as epoll_event
#[derive(Clone, Copy)]  
pub struct Event {
    pub epoll_flags: EpollFlags,
    pub token: EventToken
}

pub struct EventArray {
    pub data: [Event; MAX_EVENTS],
    pub count: usize,
}     

pub struct Poller {
    fd: RawFd,
    events: EventArray
}

impl Poller {
    pub fn new() -> Result<Poller, Error> {
        let epoll_fd = unsafe {epoll_create1(0)};
        if epoll_fd < 0 {
            return Err(OS(std::io::Error::last_os_error()))
        }

        Ok(Poller {
            fd: epoll_fd,
            events: EventArray {
                data: [Event {epoll_flags: 0, token: EventToken::Zero}; MAX_EVENTS],
                count: 0
            }
        })
    }

    pub fn register_event_trigger(&mut self, token: EventToken, epoll_flags: EpollFlags, fd: RawFd) -> Result<(), Error> {
        let mut epoll_event = epoll_event {
            events: epoll_flags,
            u64: token as u64
        };
        
        let status = unsafe { epoll_ctl(self.fd, EPOLL_CTL_ADD, fd, &mut epoll_event) };
        if status < 0 {
            return Err(OS(std::io::Error::last_os_error()));
        }
        Ok(())
    }

    // Does one event poll, return number of fetched events
    pub fn poll(&mut self, timeout_ms: i32) -> Result<usize, Error> {
        let mut events = [epoll_event {events: 0, u64: 0}; MAX_EVENTS];
        let event_count = unsafe { epoll_wait(self.fd, events.as_mut_ptr(), MAX_EVENTS as i32, timeout_ms) };

        if event_count < 0 {
            // EINTR is not an error, we can continue next time
            if std::io::Error::last_os_error().raw_os_error() == Some(EINTR) {
                return Ok(0)
            }
            return Err(OS(std::io::Error::last_os_error()));
        }

        let n = event_count as usize;
        self.events.count = 0;
        for event in &events[..n] {
            let token = match event.u64 {
                1 => EventToken::UDP,
                2 => EventToken::TUN,
                _ => continue,
            };

            self.events.data[self.events.count] = Event {
                epoll_flags: event.events,
                token,
            };
            self.events.count += 1;
        }

        Ok(self.events.count)
    }

    pub fn get_events(&self) -> &EventArray {
        &self.events
    }

}

impl Drop for Poller {                                                                                                                                 
    fn drop(&mut self) {                                                                                                                               
        unsafe { libc::close(self.fd) };                                                                                                               
    }                                                                                                                                                  
}   
