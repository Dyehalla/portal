use std::io;
use std::net::UdpSocket;
use std::os::fd::{AsFd, AsRawFd};
use libc::{EPOLLIN, EPOLLERR, EPOLLHUP};

use crate::platform::socket::{PacketSource};
use crate::platform::event::{self, Event, EventArray, EventToken, Poller, EpollFlags};
use crate::Error;

const BUFFER_SIZE: usize = 65535;
// const EPOLL_ERRORS: u32 = (EPOLLERR | EPOLLHUP) as u32;

struct Worker {
    source: PacketSource,
    wg_socket: UdpSocket,
    poller: Poller,
    buffer: [u8; BUFFER_SIZE]
}

impl Worker {
    // Creates and registers worker.
    pub fn new(source: PacketSource, wg_socket: UdpSocket) -> Result<Worker, Error> {
        let mut poller = Poller::new()?;

        let token = EventToken::match_token(&source);
        let epoll_flags = EPOLLIN as u32;
        let fd = source.fd();

        poller.register_event_trigger(EventToken::UDP, epoll_flags, wg_socket.as_fd().as_raw_fd())?;       
        poller.register_event_trigger(token, epoll_flags, fd)?;

        let buffer = [0u8; BUFFER_SIZE];
        Ok(Worker { source, wg_socket, poller, buffer })
    }

    // Main event loop
    pub fn run(&mut self) -> Result<(), Error> {
        let mut events = EventArray::new();

        loop {
            self.poller.poll(-1, &mut events)?;

            let events = events.data[..events.count].to_vec();

            for event in &events {
                let (epoll_flags, token) = (event.epoll_flags, event.token);
                match token {
                    EventToken::TUN => {
                        self.packet_source_readable()?;                                      
                    }

                    EventToken::UDP => {

                    }

                    EventToken::Zero => {}
                }
            }
        }
    }

    fn packet_source_readable(&mut self) -> Result<(), Error> {
        loop {
            let bytes_read = match self.source.read(&mut self.buffer) {
                Ok(n) => n,
                // Non-blocking socket return error if the buffer is empty
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(Error::DeadPacketSource),
            };

            // копия пакета: self.buffer занят, а wg_device нужен &mut self.
            // Потом уберём — когда появятся настоящие буферы устройств.
            let packet = self.buffer[..bytes_read].to_vec();
            self.pass_to_wg_device(&packet)?;
        }
    }


    fn pass_to_wg_device(&mut self, packet: &[u8]) -> Result<(), Error> {
        // TODO: cryptokey routing → encrypt → wg_socket.send_to
        let _ = packet;
        Ok(())
    }

}
