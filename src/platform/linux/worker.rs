use std::net::UdpSocket;

use crate::platform::socket::{PacketSource};
use crate::platform::event::{Poller, EventArray, Event};

struct Worker {
    source: dyn PacketSource,
    dest: UdpSocket,
    poller: Poller,
}
