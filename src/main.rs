mod platform;

use crate::platform::tun::TunSocket;
use std::net::SocketAddr;

const THREADS: usize = 4;
const TUN_NAME: &str = "tun0";

enum Error {
    OS(std::io::Error)
}

struct Device {
    queues: Vec<TunSocket>,
}

impl Device {
    fn new() -> std::io::Result<Self> {
        let queues = (0..THREADS)
            .map(|_| TunSocket::new(TUN_NAME))
            .collect::<std::io::Result<Vec<_>>>()?;

        Ok(Self { queues })
    }
}

fn main() {
    let device = Device::new().expect("failed to create TUN device");
    
}
