use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use portal::{AllowedIp, Device, DeviceConfig, PeerConfig, PeerKey};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

fn read_key(path: &str) -> Result<PeerKey, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let key = bytes.try_into().map_err(|bytes: Vec<u8>| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "key file must contain exactly 32 bytes, got {}",
                bytes.len()
            ),
        )
    })?;
    Ok(key)
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    if !(6..=7).contains(&args.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: wireguard_interop <tun-name> <listen-addr> <private-key-raw> <peer-public-key-raw> <peer-endpoint> <allowed-ips-csv> [preshared-key-raw]",
        )
        .into());
    }

    let private_key = read_key(&args[2])?;
    let peer_public_key = read_key(&args[3])?;
    let preshared_key = args.get(6).map(|path| read_key(path)).transpose()?;
    let listen_addr: SocketAddr = args[1].parse()?;
    let endpoint: SocketAddr = args[4].parse()?;
    let allowed_ips = args[5]
        .split(',')
        .map(str::parse::<AllowedIp>)
        .collect::<Result<Vec<_>, _>>()?;

    let mut config = DeviceConfig::new(private_key, listen_addr, &args[0]);
    config.dual_stack = false;
    let mut device = Device::new(config)?;
    device.upsert_peer(PeerConfig {
        public_key: peer_public_key,
        preshared_key,
        endpoint: Some(endpoint),
        persistent_keepalive: None,
        allowed_ips,
    })?;

    // Let the shell harness stop the device cleanly when it removes namespaces.
    unsafe {
        libc::signal(libc::SIGINT, request_stop as libc::sighandler_t);
        libc::signal(libc::SIGTERM, request_stop as libc::sighandler_t);
    }
    eprintln!("portal WireGuard device ready on {}", device.listen_addr());
    while !STOP.load(Ordering::Relaxed) {
        device.health()?;
        thread::sleep(Duration::from_millis(100));
    }
    device.shutdown()?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("wireguard_interop: {error}");
        std::process::exit(1);
    }
}
