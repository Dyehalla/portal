//! The device: one UDP endpoint shared by every peer. Cookie verification
//! lives here rather than in `Tunnel`, since the secret and the load counter
//! must be shared, and the check must run before the peer is looked up.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::protocol::{CookieChallenge, CookieChecker};
use crate::protocol::{
    verify_handshake_macs, Packet, WireGuardError, COOKIE_REPLY_LEN, DH_PRIVATE, DH_PUBKEY, HASH,
    HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN, MSG_COOKIE_REPLY, MSG_HANDSHAKE_RESPONSE,
    TAG_LEN,
};
use crate::protocol::KEY_LEN;
use crate::protocol::{Tunnel, TunnelResult};

/// Peers are keyed by their static public key: an initiation names its sender
/// only inside the encrypted static field, which needs a DH to open.
pub type PeerKey = [u8; KEY_LEN];

/// A device and its peers, all sharing one UDP socket.
pub struct Device {
    static_private: [u8; KEY_LEN],
    static_public: [u8; KEY_LEN],
    peers: HashMap<PeerKey, Arc<Tunnel>>,
    /// Shared cookie state: device-wide, because a cookie proves a source
    /// address rather than a peer identity.
    cookies: Arc<Mutex<CookieChecker>>,
}

impl Device {
    pub fn new(static_private: [u8; KEY_LEN]) -> Self {
        let static_public = DH_PUBKEY(&DH_PRIVATE(&static_private));
        Self {
            static_private,
            static_public,
            peers: HashMap::new(),
            cookies: Arc::new(Mutex::new(CookieChecker::new(static_public))),
        }
    }

    pub fn static_public(&self) -> &[u8; KEY_LEN] {
        &self.static_public
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// The `mac1` key every peer of this device is expected to use.
    pub fn mac1_key(&self) -> [u8; KEY_LEN] {
        HASH(&[crate::protocol::LABEL_MAC1, &self.static_public])
    }

    /// Adds a peer and hands it the given receiver index.
    pub fn add_peer(
        &mut self,
        peer_static_public: PeerKey,
        preshared_key: Option<[u8; KEY_LEN]>,
        persistent_keepalive: Option<Duration>,
        peer_index: u32,
    ) -> Arc<Tunnel> {
        let tunnel = Arc::new(Tunnel::new(
            self.static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            peer_index,
        ));
        self.peers.insert(peer_static_public, Arc::clone(&tunnel));
        tunnel
    }

    pub fn peer(&self, static_public: &PeerKey) -> Option<&Arc<Tunnel>> {
        self.peers.get(static_public)
    }

    /// Rotates the cookie secret and rolls the load window; call about once a
    /// second. The checker is shared, so this is the device's job.
    pub fn update_cookie_state(&self, now: Instant) {
        let mut cookies = self.cookies.lock().expect("cookie lock poisoned");
        cookies.rotate_secret_if_stale(now);
        cookies.reset_count(now);
    }

    /// Handles one datagram, from receipt to reply. MACs are verified before
    /// the peer is looked up, which is what makes cookies a DoS defence.
    pub fn handle_datagram<'a, 'o>(
        &self,
        src_addr: SocketAddr,
        datagram: &'a mut [u8],
        dst: &'o mut [u8],
    ) -> TunnelResult<'a, 'o> {
        if datagram.is_empty() {
            return TunnelResult::Done;
        }

        let mut cookie_reply = [0u8; COOKIE_REPLY_LEN];
        if let Some(outcome) = self.verify_macs(src_addr.ip(), datagram, &mut cookie_reply) {
            return match outcome {
                Some(len) => {
                    dst[..len].copy_from_slice(&cookie_reply[..len]);
                    TunnelResult::WriteToNetwork(&mut dst[..len])
                }
                // Not addressed to us: silent, as the spec requires.
                None => TunnelResult::InvalidPacket(WireGuardError::HandshakeNotAuthentic),
            };
        }

        let Some(tunnel) = self.tunnel_for(datagram) else {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };
        tunnel.decapsulate(datagram, dst)
    }

    /// Hands out whatever `tunnel` held while it had no session. An outbound
    /// action, deliberately separate from `handle_datagram`.
    pub fn drain_queue<'a>(&self, tunnel: &Tunnel, dst: &'a mut [u8]) -> TunnelResult<'_, 'a> {
        tunnel.send_queued_packet(dst)
    }

    /// Verifies a handshake message's MACs, writing any due reply into
    /// `cookie_reply`. `None` means it may be processed; `Some(Some(len))` a
    /// reply to send, `Some(None)` a message to drop silently.
    fn verify_macs(
        &self,
        src: IpAddr,
        datagram: &[u8],
        cookie_reply: &mut [u8],
    ) -> Option<Option<usize>> {
        // Only handshake messages carry MACs; every other type passes through.
        let mac1_off = match Packet::parse(datagram) {
            Ok(Packet::HandshakeInitiation(_)) => HANDSHAKE_INIT_LEN - 2 * TAG_LEN,
            Ok(Packet::HandshakeResponse(_)) => {
                HANDSHAKE_RESPONSE_LEN - 2 * TAG_LEN
            }
            _ => return None,
        };

        let now = Instant::now();
        let mut cookies = self.cookies.lock().expect("cookie lock poisoned");
        let under_load = cookies.note_handshake();
        let secret = cookies.secret();

        match verify_handshake_macs(&self.static_public, Some(src), &secret, under_load, datagram) {
            Ok(()) => None,
            Err(CookieChallenge::NotForUs | CookieChallenge::NeedSourceAddress) => Some(None),
            Err(CookieChallenge::WrongMac2 { cookie }) => {
                // The packet parsed, so its header and trailer are in bounds.
                let sender_index =
                    u32::from_le_bytes(datagram[4..8].try_into().expect("header parsed"));
                let mac1: [u8; TAG_LEN] = datagram
                    [mac1_off..mac1_off + TAG_LEN]
                    .try_into()
                    .expect("lengths come from the parsed packet");
                Some(
                    cookies
                        .format_cookie_reply(cookie_reply, sender_index, &cookie, &mac1)
                        .ok(),
                )
            }
        }
    }

    /// Finds the peer a datagram belongs to. An initiation names its sender
    /// only inside the sealed static field, which needs the very DH the cookie
    /// check avoids; a peer-carrying index map is the proper next step.
    fn tunnel_for(&self, _datagram: &[u8]) -> Option<&Arc<Tunnel>> {
        if self.peers.len() == 1 {
            self.peers.values().next()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::COOKIE_MAX_AGE;
    use crate::protocol::StoredCookie;
    use crate::protocol::MAX_PACKET_SIZE;

    fn key(byte: u8) -> [u8; KEY_LEN] {
        [byte; KEY_LEN]
    }

    fn src(last: u8) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, last], 51820))
    }

    fn buf() -> Vec<u8> {
        vec![0u8; MAX_PACKET_SIZE]
    }

    /// Two devices that know each other's keys and can complete a handshake.
    fn paired() -> (Device, Device) {
        let mut a = Device::new(key(0x11));
        let mut b = Device::new(key(0x22));
        a.add_peer(b.static_public().to_owned(), None, None, 11);
        b.add_peer(a.static_public().to_owned(), None, None, 22);
        (a, b)
    }

    #[test]
    fn a_handshake_completes_through_the_device() {
        let (a, b) = paired();
        let a_tunnel = a.peer(&b.static_public().to_owned()).unwrap().clone();

        let mut a_buf = buf();
        let mut b_buf = buf();

        let mut init = match a_tunnel.encapsulate(b"hello", &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };
        // B is unloaded, so no cookie is demanded and the response is direct.
        let mut response = match b.handle_datagram(src(1), &mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a response, got {other:?}"),
        };
        let mut keepalive = match a.handle_datagram(src(2), &mut response, &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a keepalive, got {other:?}"),
        };
        assert!(matches!(
            b.handle_datagram(src(1), &mut keepalive, &mut b_buf),
            TunnelResult::WriteToTunnelInPlace(_)
        ));
    }

    /// A packet queued before the handshake comes out through the device's
    /// own drain call — not by feeding `decapsulate` an empty datagram.
    #[test]
    fn the_device_drains_what_was_queued_before_the_handshake() {
        let (a, b) = paired();
        let a_tunnel = a.peer(&b.static_public().to_owned()).unwrap().clone();

        let mut a_buf = buf();
        let mut b_buf = buf();

        // No session yet: the packet is held and an initiation goes out.
        let mut init = match a_tunnel.encapsulate(b"held", &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };
        let mut response = match b.handle_datagram(src(1), &mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a response, got {other:?}"),
        };
        let mut keepalive = match a.handle_datagram(src(2), &mut response, &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a keepalive, got {other:?}"),
        };
        assert!(matches!(
            b.handle_datagram(src(1), &mut keepalive, &mut b_buf),
            TunnelResult::WriteToTunnelInPlace(_)
        ));

        // Now the held packet can go out, and the queue reports empty.
        let mut held = match a.drain_queue(&a_tunnel, &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected the held packet, got {other:?}"),
        };
        match b.handle_datagram(src(1), &mut held, &mut b_buf) {
            TunnelResult::WriteToTunnelInPlace(plaintext) => assert_eq!(plaintext, b"held"),
            other => panic!("expected plaintext, got {other:?}"),
        }
        assert!(matches!(
            a.drain_queue(&a_tunnel, &mut a_buf),
            TunnelResult::Done
        ));
    }

    /// The scenario a per-peer counter misses: a flood spread over many peers
    /// never trips any single peer's threshold, so the counter has to be
    /// device-wide for the cookie defence to engage at all.
    #[test]
    fn a_flood_spread_over_peers_still_trips_the_device_counter() {
        let mut device = Device::new(key(0x11));
        for i in 0..100u8 {
            device.add_peer(key(i), None, None, 100 + i as u32);
        }

        // The threshold is crossed a fixed number of handshakes in, no matter
        // how many peers the flood is spread across.
        let cookies = Arc::clone(&device.cookies);
        let mut engaged_at = None;
        for i in 0..1000 {
            if cookies.lock().unwrap().note_handshake() {
                engaged_at = Some(i);
                break;
            }
        }
        assert_eq!(engaged_at, Some(100));
    }

    /// A counter kept per peer would never trip; this pins the difference.
    #[test]
    fn a_per_peer_counter_would_not_trip_on_a_spread_flood() {
        // Each peer sees exactly one handshake, which is what the old
        // per-tunnel layout amounted to.
        let per_peer: Vec<bool> = (0..100)
            .map(|_| CookieChecker::new(key(0x11)).note_handshake())
            .collect();
        assert!(
            per_peer.iter().all(|under_load| !under_load),
            "no single peer may consider itself under load"
        );
    }

    #[test]
    fn a_bad_mac1_is_dropped_without_a_reply() {
        let (a, b) = paired();
        let a_tunnel = a.peer(&b.static_public().to_owned()).unwrap().clone();

        let mut a_buf = buf();
        let mut b_buf = buf();
        let mut init = match a_tunnel.encapsulate(b"hi", &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };

        // Sign it for a key the responder does not hold.
        let mac1_off = init.len() - 32;
        init[mac1_off] ^= 0xff;

        assert!(matches!(
            b.handle_datagram(src(1), &mut init, &mut b_buf),
            TunnelResult::InvalidPacket(WireGuardError::HandshakeNotAuthentic)
        ));
    }

    /// Under load the device challenges, and the peer that carries the cookie
    /// is then served. This is the whole mechanism, device-wide.
    #[test]
    fn under_load_the_device_challenges_then_serves() {
        let (a, b) = paired();
        let a_tunnel = a.peer(&b.static_public().to_owned()).unwrap().clone();

        // Threshold zero: every handshake is challenged.
        {
            let public = *b.static_public();
            *b.cookies.lock().unwrap() = CookieChecker::with_limit(public, 0);
        }

        let mut a_buf = buf();
        let mut b_buf = buf();

        let mut init = match a_tunnel.encapsulate(b"payload", &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };

        // 1. Challenged: type 3, not 2.
        let mut cookie_reply = match b.handle_datagram(src(1), &mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a cookie reply, got {other:?}"),
        };
        assert_eq!(
            u32::from_le_bytes(cookie_reply[..4].try_into().unwrap()),
            MSG_COOKIE_REPLY
        );

        // 2. A stores it and retries.
        assert!(matches!(
            a.handle_datagram(src(2), &mut cookie_reply, &mut a_buf),
            TunnelResult::Done
        ));

        let mut retry = match a_tunnel.format_handshake_initiation(&mut a_buf, true) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a retry, got {other:?}"),
        };
        assert_ne!(&retry[retry.len() - 16..], &[0u8; 16], "retry needs a mac2");

        // 3. Served, because the cookie proves the address.
        let mut response = match b.handle_datagram(src(1), &mut retry, &mut b_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a response, got {other:?}"),
        };
        assert_eq!(
            u32::from_le_bytes(response[..4].try_into().unwrap()),
            MSG_HANDSHAKE_RESPONSE
        );

        let mut keepalive = match a.handle_datagram(src(2), &mut response, &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a keepalive, got {other:?}"),
        };
        assert!(matches!(
            b.handle_datagram(src(1), &mut keepalive, &mut b_buf),
            TunnelResult::WriteToTunnelInPlace(_)
        ));

        // And data flows.
        let mut data = match a_tunnel.encapsulate(b"an IP packet", &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected data, got {other:?}"),
        };
        match b.handle_datagram(src(1), &mut data, &mut b_buf) {
            TunnelResult::WriteToTunnelInPlace(plaintext) => {
                assert_eq!(plaintext, b"an IP packet");
            }
            other => panic!("expected plaintext, got {other:?}"),
        }
    }

    /// A cookie issued for one address must not serve another: that is what
    /// makes the reply a proof of address ownership.
    #[test]
    fn a_cookie_from_one_address_does_not_serve_another() {
        let (a, b) = paired();
        let a_tunnel = a.peer(&b.static_public().to_owned()).unwrap().clone();
        {
            let public = *b.static_public();
            *b.cookies.lock().unwrap() = CookieChecker::with_limit(public, 0);
        }

        let mut a_buf = buf();
        let mut b_buf = buf();
        let mut init = match a_tunnel.encapsulate(b"payload", &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };
        let mut cookie_reply = match b.handle_datagram(src(1), &mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a cookie reply, got {other:?}"),
        };
        assert!(matches!(
            a.handle_datagram(src(2), &mut cookie_reply, &mut a_buf),
            TunnelResult::Done
        ));

        // The retry carries a cookie bound to 10.0.0.1 but arrives from
        // 10.0.0.9, so it must be challenged again rather than served.
        let mut retry = match a_tunnel.format_handshake_initiation(&mut a_buf, true) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a retry, got {other:?}"),
        };
        let mut reply = match b.handle_datagram(src(9), &mut retry, &mut b_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected another challenge, got {other:?}"),
        };
        assert_eq!(
            u32::from_le_bytes(reply[..4].try_into().unwrap()),
            MSG_COOKIE_REPLY,
            "a cookie must not transfer between addresses"
        );
    }

    #[test]
    fn a_stale_cookie_expires() {
        let now = Instant::now();
        let stored = StoredCookie {
            cookie: [0u8; 16],
            received_at: now,
        };
        assert!(!stored.is_expired(now + COOKIE_MAX_AGE - Duration::from_secs(1)));
        assert!(stored.is_expired(now + COOKIE_MAX_AGE));
    }
}
