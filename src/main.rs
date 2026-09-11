mod device;
mod noise;
mod platform;

const THREADS: usize = 4;
const TUN_NAME: &str = "tun0";

#[derive(Debug)]
enum Error {
    OS(std::io::Error),
    WouldBlock,
    DeadPacketSource,
    InvalidPeerPubKey,
    /// AEAD failed while building a handshake message. Not attacker-reachable
    /// for our own outgoing messages, but we do not panic on it.
    Crypto,
    /// Could not find an unused sender index; practically unreachable.
    NoFreeIndex,
}


fn main() {


}
