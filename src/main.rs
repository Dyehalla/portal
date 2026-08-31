mod platform;

use crate::platform::socket::TunSocket;
use std::net::SocketAddr;

const THREADS: usize = 4;
const TUN_NAME: &str = "tun0";

enum Error {
    OS(std::io::Error),
    WouldBlock,
}

struct Device {

}

impl Device {

}

fn main() {


}
