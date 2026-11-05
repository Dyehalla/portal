//! Diagnose protocol-sensitive UDP loss without Portal runtime, ACL, TUN or STUN.
//!
//! Build: cargo build -p portal --release --example udp_path_probe
//! Server: udp_path_probe server 0.0.0.0:51878 plain
//! Client: udp_path_probe client SERVER_IP:51878 plain 1420 40
//! Repeat with `masked`, `handshake`, or `data` on BOTH ends. These modes only
//! change the first message-type byte on the wire, restoring it before BoringTun.
//! They are experimental controls, not a Portal transport mode. Synthetic IP
//! payloads and fixed test identities are used; no real host traffic is attached.
//! The server exits after 90 seconds; limit its UDP access to the test client.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
fn wire(mut packet: Vec<u8>, mask: u8) -> Vec<u8> {
    if packet.is_empty() {
        return packet;
    }
    let kind = packet[0] & 0x7f;
    if mask & 1 != 0 && kind <= 3 || mask & 2 != 0 && kind == 4 {
        packet[0] ^= 0x80;
    }
    packet
}
fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 4
        || !matches!(a[1].as_str(), "server" | "client")
        || !matches!(a[3].as_str(), "plain" | "masked" | "handshake" | "data")
        || (a[1] == "client" && a.len() != 6)
    {
        eprintln!(
            "Usage: udp_path_probe server LISTEN plain|masked|handshake|data\n       udp_path_probe client ENDPOINT MODE SIZE COUNT"
        );
        std::process::exit(2);
    }
    let server = a[1] == "server";
    let address: SocketAddr = a[2].parse().unwrap();
    let mask = match a[3].as_str() {
        "masked" => 3,
        "handshake" => 1,
        "data" => 2,
        _ => 0,
    };
    let own = if server { 8 } else { 7 };
    let other = if server { 7 } else { 8 };
    let mut tunnel = Tunn::new(
        StaticSecret::from([own; 32]),
        PublicKey::from(&StaticSecret::from([other; 32])),
        None,
        None,
        1,
        None,
    );
    let socket = UdpSocket::bind(if server {
        address
    } else {
        "0.0.0.0:0".parse().unwrap()
    })
    .unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut input = [0; 66000];
    let mut scratch = [0; 66000];
    let start = Instant::now();
    if server {
        println!("READY mask={mask}");
        let mut received = 0;
        let mut echoed = 0;
        while start.elapsed() < Duration::from_secs(90) {
            let (n, source) = match socket.recv_from(&mut input) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if n == 0 {
                continue;
            }
            received += 1;
            let decoded = wire(input[..n].to_vec(), mask);
            input[..n].copy_from_slice(&decoded);
            let mut reply = None;
            match tunnel.decapsulate(Some(source.ip()), &input[..n], &mut scratch) {
                TunnResult::WriteToNetwork(p) => {
                    socket.send_to(&wire(p.to_vec(), mask), source).unwrap();
                }
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                    reply = Some(p.to_vec())
                }
                TunnResult::Err(e) => println!("DECODE {e:?}"),
                _ => {}
            }
            if let Some(p) = reply
                && let TunnResult::WriteToNetwork(p) = tunnel.encapsulate(&p, &mut scratch)
            {
                socket.send_to(&wire(p.to_vec(), mask), source).unwrap();
                echoed += 1;
            }
            println!("PACKET received={received} echoed={echoed} length={n} from={source}");
        }
    } else {
        socket.connect(address).unwrap();
        let mut ready = false;
        let mut next = Instant::now();
        while start.elapsed() < Duration::from_secs(8) && !ready {
            if Instant::now() >= next {
                if let TunnResult::WriteToNetwork(p) =
                    tunnel.format_handshake_initiation(&mut scratch, true)
                {
                    socket.send(&wire(p.to_vec(), mask)).unwrap();
                }
                next = Instant::now() + Duration::from_secs(2);
            }
            if let Ok(n) = socket.recv(&mut input) {
                let decoded = wire(input[..n].to_vec(), mask);
                input[..n].copy_from_slice(&decoded);
                if let TunnResult::WriteToNetwork(p) =
                    tunnel.decapsulate(Some(address.ip()), &input[..n], &mut scratch)
                {
                    ready = true;
                    socket.send(&wire(p.to_vec(), mask)).unwrap();
                }
            }
        }
        if !ready {
            println!("RESULT mask={mask} handshake=failed");
            std::process::exit(2)
        }
        let size: usize = a[4].parse().unwrap();
        let count: usize = a[5].parse().unwrap();
        assert!(
            (24..=1420).contains(&size) && (1..=100000).contains(&count),
            "SIZE must be 24..1420, COUNT 1..100000"
        );
        let mut received = 0;
        let mut sent = 0;
        let mut failures = 0;
        for sequence in 0..count {
            let mut packet = vec![65; size];
            packet[..20].fill(0);
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
            packet[8] = 64;
            packet[9] = 17;
            packet[12..16].copy_from_slice(&[10, 239, 1, 1]);
            packet[16..20].copy_from_slice(&[10, 239, 1, 2]);
            packet[20..24].copy_from_slice(&(sequence as u32).to_be_bytes());
            if let TunnResult::WriteToNetwork(p) = tunnel.encapsulate(&packet, &mut scratch) {
                socket.send(&wire(p.to_vec(), mask)).unwrap();
                sent += 1;
            }
            let until = Instant::now() + Duration::from_secs(1);
            let mut ok = false;
            while Instant::now() < until {
                let n = match socket.recv(&mut input) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                let decoded = wire(input[..n].to_vec(), mask);
                input[..n].copy_from_slice(&decoded);
                match tunnel.decapsulate(Some(address.ip()), &input[..n], &mut scratch) {
                    TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                        if p == packet {
                            ok = true;
                            break;
                        }
                    }
                    TunnResult::WriteToNetwork(p) => {
                        socket.send(&wire(p.to_vec(), mask)).unwrap();
                    }
                    _ => {}
                }
            }
            if ok {
                received += 1;
                failures = 0;
            } else {
                failures += 1;
            }
            if failures == 3 {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        println!(
            "RESULT mask={mask} handshake=ok sent={sent} received={received} size={size} local={} elapsed_ms={}",
            socket.local_addr().unwrap(),
            start.elapsed().as_millis()
        );
        if received != count {
            std::process::exit(1);
        }
    }
}
