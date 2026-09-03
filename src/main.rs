mod device;
mod noise;
mod platform;

const THREADS: usize = 4;
const TUN_NAME: &str = "tun0";

enum Error {
    OS(std::io::Error),
    WouldBlock,
    DeadPacketSource
}


fn main() {


}
