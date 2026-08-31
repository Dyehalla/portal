use std::net::UdpSocket;
use libc::EPOLLIN;

use crate::platform::socket::{PacketSource};
use crate::platform::event::{Poller, EventArray, Event, EventToken};
use crate::Error;


struct Worker {
    source: PacketSource,
    wg_socket: UdpSocket,
    poller: Poller,
}

impl Worker {
    // Creates and registers worker. New worker is ready to run 
    pub fn new(source: PacketSource, wg_socket: UdpSocket) -> Result<Worker, Error> {
        let mut poller = Poller::new()?;

        let token = EventToken::match_token(&source);
        let epoll_flags = EPOLLIN as u32;
        let fd = source.fd();

        poller.register_event_trigger(EventToken::UDP, epoll_flags, wg_socket.as_raw_fd())?;       
        poller.register_event_trigger(token, epoll_flags, fd)?;

        Ok(Worker { source, wg_socket, poller })
    }

    pub fn run(&mut self) -> Result<(), Error> {
        let mut buffer = 
    }


}
