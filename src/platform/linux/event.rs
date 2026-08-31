use libc::{epoll_create1, epoll_ctl, epoll_wait, epoll_event, EPOLL_CTL_ADD};
use std::os::fd::RawFd;
use crate::Error::{self, OS};

type EpollFlags = u32;

const MAX_EVENTS: usize = 128;                        

pub trait EventHandler {
    fn fd(&self) -> RawFd;
    fn interest(&self) -> EpollFlags;
    fn ready(&mut self, events: EpollFlags);
}



pub struct Poller {
    fd: RawFd,
    ev_handlers: Vec<Box<dyn EventHandler>>
}

impl Poller {
    pub fn new() -> Result<Poller, Error> {
        let epoll_fd = unsafe {epoll_create1(0)};
        if epoll_fd < 0 {
            return Err(OS(std::io::Error::last_os_error()))
        }

        Ok(Poller {
            fd: epoll_fd,
            ev_handlers: Vec::new()
        })
    }

    pub fn register_event_handler(&mut self, ev_handler: impl EventHandler + 'static) -> Result<(), Error> {
        let new_ev_handler_idx = self.ev_handlers.len();
        self.register_fd(ev_handler.fd(), ev_handler.interest(), new_ev_handler_idx as u64)?;
        self.ev_handlers.push(Box::new(ev_handler));
        Ok(())
    }

    // Waits for the events and calls EventHandler::ready()
    pub fn poll(&mut self, timeout_ms: i32) -> Result<(), Error> {
        let mut events = [epoll_event {events: 0, u64: 0}; MAX_EVENTS];
        let wait_res = unsafe { epoll_wait(self.fd, events.as_mut_ptr(), MAX_EVENTS as i32, timeout_ms) };

        if wait_res < 0 {
            return Err(OS(std::io::Error::last_os_error()));
        }

        for i in 0..wait_res {
            let event = events[i as usize];
            let (flags, handler_idx) = (event.events, event.u64);
            
            let Some(handler) = self.ev_handlers.get_mut(handler_idx as usize) else { continue }; 
            
            handler.ready(flags);
        }

        Ok(())
    }

    fn register_fd(&self, fd: RawFd, interest: EpollFlags, data: u64) -> Result<(), Error> {
        let mut epoll_event = epoll_event {
            events: interest,
            u64: data
        };
        
        let status = unsafe { epoll_ctl(self.fd, EPOLL_CTL_ADD, fd, &mut epoll_event) };
        if status < 0 {
            return Err(OS(std::io::Error::last_os_error()));
        }
        Ok(())
    }

}
