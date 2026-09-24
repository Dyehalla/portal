mod device;
mod index_table;
mod platform;
mod protocol;
mod ring;
mod runtime;

use std::error::Error;
use std::net::SocketAddr;
use std::time::Duration;

use device::AllowedIp;
use runtime::{PeerConfig, RuntimeConfig};

const USAGE: &str = "Usage: portal <listen-socket> <tun-name> <private-key-hex> <workers> [<peer-key-hex> <endpoint|-> <allowed-prefixes|-> <psk-hex|-> <keepalive-seconds|->]...\n\nExample: portal 0.0.0.0:51820 wg0 <private-key> 4 <peer-public-key> 198.51.100.2:51820 10.20.0.0/16 - 25";

fn main() -> Result<(), Box<dyn Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args
        .first()
        .is_some_and(|arg| arg == "-h" || arg == "--help")
    {
        println!("{USAGE}");
        return Ok(());
    }
    if args.len() < 4 || (args.len() - 4) % 5 != 0 {
        return Err(USAGE.into());
    }

    let listen = args[0].parse::<SocketAddr>()?;
    let tun_name = args[1].clone();
    let workers = args[3].parse::<usize>()?;
    let mut peers = Vec::new();
    for fields in args[4..].chunks_exact(5) {
        let static_public = parse_key(&fields[0])?;
        let endpoint = if fields[1] == "-" {
            None
        } else {
            Some(fields[1].parse()?)
        };
        let allowed_ips = if fields[2] == "-" {
            Vec::new()
        } else {
            fields[2]
                .split(',')
                .map(parse_allowed_ip)
                .collect::<Result<Vec<_>, _>>()?
        };
        let preshared_key = if fields[3] == "-" {
            None
        } else {
            Some(parse_key(&fields[3])?)
        };
        let persistent_keepalive = if fields[4] == "-" {
            None
        } else {
            Some(Duration::from_secs(fields[4].parse()?))
        };
        peers.push(PeerConfig {
            static_public,
            preshared_key,
            persistent_keepalive,
            endpoint,
            allowed_ips,
        });
    }

    let static_private = parse_key(&args[2])?;
    runtime::run(RuntimeConfig {
        static_private,
        listen,
        tun_name,
        workers,
        peers,
    })?;
    Ok(())
}

fn parse_key(value: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if value.len() != 64 {
        return Err("WireGuard keys must be 64 hexadecimal characters".into());
    }
    let mut key = [0u8; 32];
    for (byte, pair) in key.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let pair = match std::str::from_utf8(pair) {
            Ok(pair) => pair,
            Err(error) => {
                key.fill(0);
                return Err(error.into());
            }
        };
        match u8::from_str_radix(pair, 16) {
            Ok(parsed) => *byte = parsed,
            Err(error) => {
                key.fill(0);
                return Err(error.into());
            }
        }
    }
    Ok(key)
}

fn parse_allowed_ip(value: &str) -> Result<AllowedIp, Box<dyn Error>> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or("allowed IP must use address/prefix form")?;
    Ok(AllowedIp::new(address.parse()?, prefix.parse()?)?)
}
