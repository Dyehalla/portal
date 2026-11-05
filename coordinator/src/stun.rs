//! Anonymous STUN Binding over UDP, owned by the coordinator lifecycle (RFC 8489).
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

const COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const MAX_REQUEST: usize = 512;

pub(crate) struct Server {
    socket: UdpSocket,
}

impl Server {
    pub async fn bind(address: SocketAddr) -> io::Result<Self> {
        Ok(Self {
            socket: UdpSocket::bind(address).await?,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub async fn run(self) -> io::Result<()> {
        let mut buffer = [0u8; MAX_REQUEST + 1];
        let mut limits = Limits::new();
        loop {
            let (length, source) = self.socket.recv_from(&mut buffer).await?;
            if source.port() == 0 || !limits.allow(source.ip(), Instant::now()) {
                continue;
            }
            if let Some(response) = binding_response(&buffer[..length], source) {
                // One failed send must not stop discovery for all agents.
                let _ = self.socket.send_to(&response, source).await;
            }
        }
    }
}

struct Limits {
    window: Instant,
    total: u32,
    sources: HashMap<IpAddr, u32>,
}
impl Limits {
    fn new() -> Self {
        Self {
            window: Instant::now(),
            total: 0,
            sources: HashMap::new(),
        }
    }
    fn allow(&mut self, source: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.total = 0;
            self.sources.clear();
        }
        // Group IPv6 addresses by /64 so rotating interface IDs does not bypass limits.
        let source = match source {
            IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(Ipv6Addr::from(u128::from(ip) & (u128::MAX << 64))),
            },
            other => other,
        };
        if self.total >= 2000 || (self.sources.len() >= 4096 && !self.sources.contains_key(&source))
        {
            return false;
        }
        self.total += 1;
        let count = self.sources.entry(source).or_default();
        if *count >= 32 {
            return false;
        }
        *count += 1;
        true
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn attribute(packet: &mut Vec<u8>, kind: u16, value: &[u8]) {
    packet.extend_from_slice(&kind.to_be_bytes());
    packet.extend_from_slice(&(value.len() as u16).to_be_bytes());
    packet.extend_from_slice(value);
    while packet.len() & 3 != 0 {
        packet.push(0);
    }
}

fn binding_response(request: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
    if !(20..=MAX_REQUEST).contains(&request.len())
        || request[..2] != [0, 1]
        || request[4..8] != COOKIE
    {
        return None;
    }
    let length = u16::from_be_bytes(request[2..4].try_into().ok()?) as usize;
    if length & 3 != 0 || length + 20 != request.len() {
        return None;
    }
    let mut offset = 20;
    let mut unknown = Vec::new();
    let mut fingerprint = false;
    while offset < request.len() {
        let header = request.get(offset..offset + 4)?;
        let kind = u16::from_be_bytes(header[..2].try_into().ok()?);
        let len = u16::from_be_bytes(header[2..].try_into().ok()?) as usize;
        let value = request.get(offset + 4..offset + 4 + len)?;
        let next = offset + 4 + ((len + 3) & !3);
        if next > request.len() {
            return None;
        }
        if kind == 0x8028 {
            if len != 4
                || next != request.len()
                || u32::from_be_bytes(value.try_into().ok()?)
                    != crc32(&request[..offset]) ^ 0x5354554e
            {
                return None;
            }
            fingerprint = true;
        } else if kind < 0x8000 && !unknown.contains(&kind) {
            unknown.push(kind);
        }
        offset = next;
    }
    let mut response = request[..20].to_vec();
    if unknown.is_empty() {
        response[..2].copy_from_slice(&[1, 1]);
        let ip = match source.ip() {
            IpAddr::V6(ip) => ip
                .to_ipv4_mapped()
                .map(IpAddr::V4)
                .unwrap_or(IpAddr::V6(ip)),
            ip => ip,
        };
        let mut value = vec![0, if ip.is_ipv4() { 1 } else { 2 }];
        value.extend_from_slice(&(source.port() ^ 0x2112).to_be_bytes());
        let octets = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        for (i, byte) in octets.iter().enumerate() {
            value.push(byte ^ request[4 + i]);
        }
        attribute(&mut response, 0x0020, &value);
    } else {
        response[..2].copy_from_slice(&[1, 0x11]);
        let mut error = vec![0, 0, 4, 20];
        error.extend_from_slice(b"Unknown Attribute");
        attribute(&mut response, 0x0009, &error);
        let values: Vec<u8> = unknown.iter().flat_map(|kind| kind.to_be_bytes()).collect();
        attribute(&mut response, 0x000a, &values);
    }
    let size = response.len() - 20 + if fingerprint { 8 } else { 0 };
    response[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    if fingerprint {
        let crc = crc32(&response) ^ 0x5354554e;
        attribute(&mut response, 0x8028, &crc.to_be_bytes());
    }
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Vec<u8> {
        let mut packet = vec![0, 1, 0, 0];
        packet.extend_from_slice(&COOKIE);
        packet.extend_from_slice(&[7; 12]);
        packet
    }
    #[test]
    fn binding_validates_bounds_fingerprint_and_unknown_required_attributes() {
        let source = "198.51.100.9:45678".parse().unwrap();
        let plain = request();
        let response = binding_response(&plain, source).unwrap();
        assert_eq!(&response[..8], &[1, 1, 0, 12, 0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(&response[8..20], &[7; 12]);
        assert_eq!(
            u16::from_be_bytes(response[26..28].try_into().unwrap()) ^ 0x2112,
            45678
        );
        for n in 0..plain.len() {
            assert!(binding_response(&plain[..n], source).is_none());
        }
        let mut fp = request();
        fp[3] = 8;
        let crc = crc32(&fp) ^ 0x5354554e;
        attribute(&mut fp, 0x8028, &crc.to_be_bytes());
        let response = binding_response(&fp, source).unwrap();
        assert_eq!(
            u32::from_be_bytes(response[36..40].try_into().unwrap()),
            crc32(&response[..32]) ^ 0x5354554e
        );
        fp[24] ^= 1;
        assert!(binding_response(&fp, source).is_none());
        let mut unknown = request();
        attribute(&mut unknown, 0x1234, &[1, 2, 3, 4]);
        unknown[3] = 8;
        let response = binding_response(&unknown, source).unwrap();
        assert_eq!(&response[..2], &[1, 0x11]);
        assert_eq!(&response[24..28], &[0, 0, 4, 20]);
        let mut bad = request();
        bad[3] = 4;
        bad.extend_from_slice(&[0, 1, 0, 255]);
        assert!(binding_response(&bad, source).is_none());
        assert!(binding_response(&vec![0; 513], source).is_none());
    }
    #[test]
    fn rate_limit_is_bounded_and_ipv6_prefixes_share_a_budget() {
        let mut limits = Limits::new();
        let now = Instant::now();
        for _ in 0..32 {
            assert!(limits.allow("2001:db8::1".parse().unwrap(), now));
        }
        assert!(!limits.allow("2001:db8::2".parse().unwrap(), now));
        assert!(limits.allow("2001:db8:0:1::1".parse().unwrap(), now));
        assert!(limits.allow("2001:db8::1".parse().unwrap(), now + Duration::from_secs(1)));
        for n in 0..2000u32 {
            limits.allow(
                IpAddr::V4((0x0a000000 + n).into()),
                now + Duration::from_secs(1),
            );
        }
        assert!(!limits.allow("192.0.2.1".parse().unwrap(), now + Duration::from_secs(1)));
    }
    #[tokio::test]
    async fn udp_binding_reports_actual_ipv4_and_ipv6_source_and_closes_on_cancel() {
        for listen in ["127.0.0.1:0", "[::1]:0"] {
            let server = Server::bind(listen.parse().unwrap()).await.unwrap();
            let address = server.local_addr().unwrap();
            let client = UdpSocket::bind(listen).await.unwrap();
            let task = tokio::spawn(server.run());
            client.send_to(&request(), address).await.unwrap();
            let mut buffer = [0; 512];
            let (len, source) =
                tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(source, address);
            assert_eq!(buffer[25], if address.is_ipv4() { 1 } else { 2 });
            assert_eq!(
                u16::from_be_bytes(buffer[26..28].try_into().unwrap()) ^ 0x2112,
                client.local_addr().unwrap().port()
            );
            let octets: Vec<u8> = (28..len).map(|i| buffer[i] ^ buffer[i - 24]).collect();
            let ip = client.local_addr().unwrap().ip();
            assert_eq!(
                octets,
                match ip {
                    IpAddr::V4(ip) => ip.octets().to_vec(),
                    IpAddr::V6(ip) => ip.octets().to_vec(),
                }
            );
            task.abort();
            let _ = task.await;
            assert!(UdpSocket::bind(address).await.is_ok());
        }
    }
}
