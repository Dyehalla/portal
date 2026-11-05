//! STUN Binding discovery on the existing WireGuard socket (RFC 8489).
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

pub(crate) struct Discovery {
    requests: Vec<(SocketAddr, [u8; 12], Instant)>,
    results: Vec<SocketAddr>,
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            requests: Vec::new(),
            results: Vec::new(),
        }
    }

    pub fn start(&mut self, servers: &[SocketAddr]) -> std::io::Result<Vec<(SocketAddr, Vec<u8>)>> {
        use std::io::Read;
        self.requests.clear();
        self.results.clear();
        let mut random = std::fs::File::open("/dev/urandom")?;
        let mut output = Vec::new();
        for server in servers.iter().take(8) {
            let mut id = [0; 12];
            random.read_exact(&mut id)?;
            let mut packet = vec![0, 1, 0, 0];
            packet.extend_from_slice(&COOKIE);
            packet.extend_from_slice(&id);
            self.requests.push((*server, id, Instant::now()));
            output.push((*server, packet));
        }
        Ok(output)
    }

    pub fn retransmit(&self) -> Vec<(SocketAddr, Vec<u8>)> {
        self.requests
            .iter()
            .filter(|(_, _, sent)| sent.elapsed() < Duration::from_secs(5))
            .map(|(server, id, _)| {
                let mut packet = vec![0, 1, 0, 0];
                packet.extend_from_slice(&COOKIE);
                packet.extend_from_slice(id);
                (*server, packet)
            })
            .collect()
    }

    pub fn receive(&mut self, source: SocketAddr, packet: &[u8]) -> bool {
        if packet.len() < 20 || packet[4..8] != COOKIE {
            return false;
        }
        let Some(index) = self.requests.iter().position(|(server, id, sent)| {
            *server == source && packet[8..20] == *id && sent.elapsed() < Duration::from_secs(5)
        }) else {
            return true;
        };
        if let Some(endpoint) = mapped_address(packet) {
            self.requests.swap_remove(index);
            if !self.results.contains(&endpoint) {
                self.results.push(endpoint);
            }
        }
        true
    }

    pub fn results(&self) -> Vec<SocketAddr> {
        self.results.clone()
    }
}

fn mapped_address(packet: &[u8]) -> Option<SocketAddr> {
    if packet.len() < 20 || packet.len() > 1024 || packet[..2] != [1, 1] || packet[4..8] != COOKIE {
        return None;
    }
    let length = u16::from_be_bytes(packet[2..4].try_into().ok()?) as usize;
    if length & 3 != 0 || length + 20 != packet.len() {
        return None;
    }
    let mut offset = 20;
    let mut found = None;
    while offset < packet.len() {
        let header = packet.get(offset..offset + 4)?;
        let kind = u16::from_be_bytes(header[..2].try_into().ok()?);
        let len = u16::from_be_bytes(header[2..].try_into().ok()?) as usize;
        offset += 4;
        let value = packet.get(offset..offset + len)?;
        offset += (len + 3) & !3;
        if offset > packet.len() {
            return None;
        }
        if kind != 0x0020 {
            continue;
        }
        if found.is_some() || value.len() < 4 || value[0] != 0 {
            return None;
        }
        let port = u16::from_be_bytes(value[2..4].try_into().ok()?) ^ 0x2112;
        let ip = match (value[1], value.len()) {
            (1, 8) => {
                let mut ip: [u8; 4] = value[4..].try_into().ok()?;
                for i in 0..4 {
                    ip[i] ^= COOKIE[i];
                }
                IpAddr::V4(Ipv4Addr::from(ip))
            }
            (2, 20) => {
                let mut ip: [u8; 16] = value[4..].try_into().ok()?;
                for i in 0..16 {
                    ip[i] ^= packet[4 + i];
                }
                IpAddr::V6(Ipv6Addr::from(ip))
            }
            _ => return None,
        };
        if port == 0 || ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST {
            return None;
        }
        found = Some(SocketAddr::new(ip, port));
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(id: [u8; 12], endpoint: SocketAddr) -> Vec<u8> {
        let mut p = vec![1, 1, 0, 0];
        p.extend_from_slice(&COOKIE);
        p.extend_from_slice(&id);
        let mut v = vec![0, if endpoint.is_ipv4() { 1 } else { 2 }];
        v.extend_from_slice(&(endpoint.port() ^ 0x2112).to_be_bytes());
        let octets = match endpoint.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        for (i, byte) in octets.iter().enumerate() {
            v.push(byte ^ p[4 + i]);
        }
        p.extend_from_slice(&[0, 0x20, 0, v.len() as u8]);
        p.extend(v);
        let len = (p.len() - 20) as u16;
        p[2..4].copy_from_slice(&len.to_be_bytes());
        p
    }
    #[test]
    fn ipv4_ipv6_transaction_source_replay_and_malformed_packets() {
        for address in ["198.51.100.2:32123", "[2001:db8::abcd]:54321"] {
            let server = "127.0.0.1:3478".parse().unwrap();
            let endpoint = address.parse().unwrap();
            let mut d = Discovery::new();
            d.start(&[server]).unwrap();
            let id = d.requests[0].1;
            let packet = response(id, endpoint);
            let retry = d.retransmit();
            assert_eq!(retry.len(), 1);
            assert_eq!(&retry[0].1[8..20], &id);
            d.receive("127.0.0.2:3478".parse().unwrap(), &packet);
            assert!(d.results().is_empty());
            let mut wrong = packet.clone();
            wrong[8] ^= 1;
            d.receive(server, &wrong);
            assert!(d.results().is_empty());
            d.receive(server, &packet);
            assert_eq!(d.results(), [endpoint]);
            assert!(d.retransmit().is_empty());
            d.receive(server, &packet);
            assert_eq!(d.results(), [endpoint]);
            for end in 0..packet.len() {
                assert!(mapped_address(&packet[..end]).is_none());
            }
            let mut invalid = packet.clone();
            invalid[23] = 255;
            assert!(mapped_address(&invalid).is_none());
            assert_eq!(mapped_address(&packet), Some(endpoint));
        }
    }
}
