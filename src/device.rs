//! The device: one UDP endpoint shared by every peer. Cookie verification is
//! here, not in `Tunnel`: its secret is shared and must precede the lookup.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::protocol::{CookieChallenge, CookieChecker};
use crate::protocol::{
    parse_handshake_anon, verify_handshake_macs, HandshakeInitiation, Packet, WireGuardError, COOKIE_REPLY_LEN,
    DH_PRIVATE, DH_PUBKEY, HASH, HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN, MSG_COOKIE_REPLY,
    MSG_DATA, MSG_HANDSHAKE_INIT, MSG_HANDSHAKE_RESPONSE, TAG_LEN,
};
use crate::protocol::KEY_LEN;
use crate::protocol::{Tunnel, TunnelResult};

/// Peers are keyed by their static public key: an initiation names its sender
/// only inside the encrypted static field, which needs a DH to open.
pub type PeerKey = [u8; KEY_LEN];

/// Where a receiver index leads. This table is the single source of truth for
/// index ownership; a tunnel never decides an index for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub peer: PeerKey,
    /// Which of the peer's tunnels.
    pub tunnel: usize,
    /// The session slot, once a session exists under this index. `None` while
    /// only an initiation has claimed it: the response has not arrived yet.
    pub session: Option<usize>,
}

/// Reserves a receiver index, redrawing until one is free. This check is
/// what keeps an index unique device-wide.
fn next_free_index(routes: &mut HashMap<u32, Route>, peer: PeerKey) -> Option<u32> {
    loop {
        let mut bytes = [0u8; 4];
        crate::protocol::RAND(&mut bytes);
        let index = u32::from_le_bytes(bytes);

        // Zero is reserved as "no index".
        if index == 0 {
            continue;
        }

        if reserve_index(routes, peer, index) {
            return Some(index);
        }
    }
}

/// Claims `index` for `peer`, or `false` if it is taken. Never overwrites:
/// a clash must force a fresh draw, not steal another peer's packets.
fn reserve_index(routes: &mut HashMap<u32, Route>, peer: PeerKey, index: u32) -> bool {
    if index == 0 {
        return false;
    }

    match routes.entry(index) {
        std::collections::hash_map::Entry::Vacant(slot) => {
            slot.insert(Route {
                peer,
                tunnel: 0,
                session: None,
            });
            true
        }
        std::collections::hash_map::Entry::Occupied(_) => false,
    }
}

/// A device and its peers, all sharing one UDP socket. `routes` demultiplexes
/// the receive side: `receiver_index` is all a data packet says about itself.
pub struct Device {
    static_private: [u8; KEY_LEN],
    static_public: [u8; KEY_LEN],
    peers: HashMap<PeerKey, Tunnel>,
    /// Every live receiver index on this device, mapped to its owner. Indices
    /// are unique device-wide, so a hit here resolves the packet outright.
    routes: HashMap<u32, Route>,
    cookies: Arc<Mutex<CookieChecker>>,
}

impl Device {
    pub fn new(static_private: [u8; KEY_LEN]) -> Self {
        let static_public = DH_PUBKEY(&DH_PRIVATE(&static_private));
        Self {
            static_private,
            static_public,
            peers: HashMap::new(),
            routes: HashMap::new(),
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

    /// Adds a peer. Its receiver indices are drawn per handshake and
    /// registered in `routes` when they are installed.
    pub fn add_peer(
        &mut self,
        peer_static_public: PeerKey,
        preshared_key: Option<[u8; KEY_LEN]>,
        persistent_keepalive: Option<Duration>,
    ) -> &mut Tunnel {
        let tunnel = Tunnel::new(
            self.static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
        );
        self.peers.insert(peer_static_public, tunnel);
        self.peers
            .get_mut(&peer_static_public)
            .expect("just inserted")
    }

    pub fn peer(&self, static_public: &PeerKey) -> Option<&Tunnel> {
        self.peers.get(static_public)
    }

    pub fn peer_mut(&mut self, static_public: &PeerKey) -> Option<&mut Tunnel> {
        self.peers.get_mut(static_public)
    }

    /// The route a packet resolves to, or `None` for an unknown index. Read
    /// by hand: the offset varies by type, and data cannot use `Packet::parse`.
    fn route_for(&self, datagram: &[u8]) -> Option<Route> {
        let kind = u32::from_le_bytes(datagram.get(..4)?.try_into().ok()?);

        // An initiation is the one type with no index of ours to read.
        let offset = match kind {
            MSG_HANDSHAKE_INIT => return None,
            MSG_HANDSHAKE_RESPONSE => 8,
            MSG_COOKIE_REPLY => 4,
            MSG_DATA => 4,
            _ => return None,
        };

        let bytes: [u8; 4] = datagram.get(offset..offset + 4)?.try_into().ok()?;
        let index = u32::from_le_bytes(bytes);
        self.routes.get(&index).copied()
    }

    /// Number of receiver indices currently routable.
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// The route an index resolves to, for tests and diagnostics.
    pub fn route(&self, index: u32) -> Option<&Route> {
        self.routes.get(&index)
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
        &mut self,
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

        // Transport data, responses and cookie replies all name our own
        // receiver index, which is how the peer is found without any crypto.
        if let Some(route) = self.route_for(datagram) {
            return self.deliver(route.peer, datagram, dst);
        }

        // An initiation carries no index of ours: its sender is sealed in the
        // static field, so learning it costs a DH the mac1 check defers.
        if let Ok(Packet::HandshakeInitiation(_)) = Packet::parse(datagram) {
            return self.handle_initiation(datagram, dst);
        }

        TunnelResult::InvalidPacket(WireGuardError::InvalidPacket)
    }

    /// Opens an initiation's sealed static field to learn its sender, then
    /// hands the message to that peer's tunnel.
    fn handle_initiation<'a, 'o>(
        &mut self,
        datagram: &'a mut [u8],
        dst: &'o mut [u8],
    ) -> TunnelResult<'a, 'o> {
        let Ok(Packet::HandshakeInitiation(initiation)) = Packet::parse(datagram) else {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };

        let Some(peer) = self.identify(initiation) else {
            // Well-formed but from a stranger: silent, as the spec requires.
            return TunnelResult::InvalidPacket(WireGuardError::HandshakeNotAuthentic);
        };

        self.deliver(peer, datagram, dst)
    }

    /// Hands a datagram to `peer`'s tunnel, issuing an index if it starts a
    /// handshake. The route gains the session slot once one is installed.
    fn deliver<'a, 'o>(
        &mut self,
        peer: PeerKey,
        datagram: &'a mut [u8],
        dst: &'o mut [u8],
    ) -> TunnelResult<'a, 'o> {
        // Taken out of the map so the claim closure can borrow `self` too;
        // it goes straight back, so no other peer can observe the gap.
        let Some(mut tunnel) = self.peers.remove(&peer) else {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };

        let routes = &mut self.routes;
        let mut issued = None;
        let mut claim = || {
            let index = next_free_index(routes, peer)?;
            issued = Some(index);
            Some(index)
        };

        let outcome = tunnel.decapsulate(datagram, dst, &mut claim);

        // A session may have appeared under the index just claimed; record
        // which slot holds it so later packets resolve in one lookup.
        if let Some(index) = issued {
            if let Some(slot) = tunnel.slot_of(index) {
                if let Some(route) = self.routes.get_mut(&index) {
                    route.session = Some(slot);
                }
            }
        }

        // A handshake may also have installed a session under an index claimed
        // during an earlier call, so refresh every route this peer owns.
        self.bind_peer_routes(&peer, &tunnel);
        self.peers.insert(peer, tunnel);
        outcome
    }

    /// Fills in the session slot of every route belonging to `peer`.
    fn bind_peer_routes(&mut self, peer: &PeerKey, tunnel: &Tunnel) {
        let indices: Vec<u32> = self
            .routes
            .iter()
            .filter(|(_, route)| route.peer == *peer)
            .map(|(index, _)| *index)
            .collect();

        for index in indices {
            let slot = tunnel.slot_of(index);
            if let Some(route) = self.routes.get_mut(&index) {
                route.session = slot;
            }
        }
    }

    /// Recovers the sender's static public key from an initiation, using the
    /// device's own private key. This is the one DH paid before routing.
    fn identify(&self, initiation: HandshakeInitiation<'_>) -> Option<PeerKey> {
        let sender = parse_handshake_anon(&self.static_private, &self.static_public, &initiation)
            .ok()?;

        // Sealed under our key but not a peer we know: stay silent.
        self.peers.contains_key(&sender).then_some(sender)
    }

    /// Encrypts one outbound packet for `peer`. The device issues any index a
    /// handshake needs, so the route exists before the reply comes back.
    pub fn encapsulate<'o>(
        &mut self,
        peer: &PeerKey,
        src: &[u8],
        dst: &'o mut [u8],
    ) -> TunnelResult<'o, 'o> {
        let Some(mut tunnel) = self.peers.remove(peer) else {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };

        let routes = &mut self.routes;
        let mut claimed = None;
        let mut claim = || {
            let index = next_free_index(routes, *peer)?;
            claimed = Some(index);
            Some(index)
        };

        // `encapsulate` only ever emits into `dst`, never into the input, so
        // the borrow of the tunnel is dropped here by mapping the result.
        let outcome = tunnel
            .encapsulate(src, dst, &mut claim)
            .into_outbound();

        // A handshake may have installed a session under the index just
        // claimed, or under one claimed during an earlier call.
        self.bind_peer_routes(peer, &tunnel);
        let _ = claimed;
        self.peers.insert(*peer, tunnel);
        outcome
    }

    /// Builds a handshake initiation for `peer`, forcing a retransmission when
    /// `force_resend` is set. The device issues the index it claims.
    pub fn format_handshake_initiation<'o>(
        &mut self,
        peer: &PeerKey,
        dst: &'o mut [u8],
        force_resend: bool,
    ) -> TunnelResult<'o, 'o> {
        let Some(mut tunnel) = self.peers.remove(peer) else {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };

        let routes = &mut self.routes;
        let mut claim = || next_free_index(routes, *peer);

        let outcome = tunnel
            .format_handshake_initiation(dst, &mut claim, force_resend)
            .into_outbound();

        self.bind_peer_routes(peer, &tunnel);
        self.peers.insert(*peer, tunnel);
        outcome
    }

    /// Hands out whatever `tunnel` held while it had no session. An outbound
    /// action, deliberately separate from `handle_datagram`.
    pub fn drain_queue<'a>(&self, tunnel: &mut Tunnel, dst: &'a mut [u8]) -> TunnelResult<'_, 'a> {
        tunnel.send_queued_packet(dst)
    }

    /// Device-wide cookie state, needed by the timer that rotates the secret.
    pub fn cookie_state(&self) -> &Mutex<CookieChecker> {
        &self.cookies
    }

    /// Verifies a handshake's MACs into `cookie_reply`: `None` to process,
    /// `Some(Some(len))` to send a reply, `Some(None)` to drop silently.
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

    /// Stands in for the device's allocator when a test drives a tunnel
    /// directly; uniqueness is the device's job and is tested there.
    fn claimer() -> impl FnMut() -> Option<u32> {
        crate::protocol::tests_claimer()
    }

    fn paired() -> (Device, Device) {
        let mut a = Device::new(key(0x11));
        let mut b = Device::new(key(0x22));
        a.add_peer(b.static_public().to_owned(), None, None);
        b.add_peer(a.static_public().to_owned(), None, None);
        (a, b)
    }

    /// One device, several peers: each packet reaches the peer owning its index.
    #[test]
    fn a_stranger_is_rejected_by_identification() {
        let mut hub = Device::new(key(0x01));
        let mut known = Device::new(key(0x11));
        let mut stranger = Device::new(key(0x33));
        hub.add_peer(known.static_public().to_owned(), None, None);
        // The stranger knows the hub; the hub does not know the stranger.
        stranger.add_peer(hub.static_public().to_owned(), None, None);

        // The stranger handshakes as if it were a peer.
        let mut buf = buf();
        let hub_key = hub.static_public().to_owned();
        let mut init = match stranger.encapsulate(&hub_key, b"hi", &mut buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };

        assert!(
            matches!(
                hub.handle_datagram(src(5), &mut init, &mut buf),
                TunnelResult::InvalidPacket(WireGuardError::HandshakeNotAuthentic)
            ),
            "an unknown peer must not be served"
        );
    }

    /// The guard the whole table rests on: an index already in `routes` is
    /// never handed out again, or one peer's packet would reach another.
    #[test]
    fn an_issued_index_is_never_reissued() {
        let mut routes: HashMap<u32, Route> = HashMap::new();
        let peer = key(0x11);

        let mut seen = std::collections::HashSet::new();
        for _ in 0..512 {
            let index = next_free_index(&mut routes, peer).expect("space is plentiful");
            assert!(seen.insert(index), "index {index:#x} was issued twice");
        }

        // Every issued index is recorded and bound to the peer that asked.
        assert_eq!(routes.len(), 512);
        for (index, route) in &routes {
            assert_eq!(route.peer, peer);
            assert!(route.session.is_none(), "no session exists yet");
            assert!(seen.contains(index));
        }
    }

    /// A taken value must be refused, never overwritten: overwriting hands one
    /// peer's packets to another. Uses a chosen value, not a random draw.
    #[test]
    fn a_taken_index_is_refused_rather_than_overwritten() {
        let mut routes: HashMap<u32, Route> = HashMap::new();
        let owner = key(0x22);
        let rival = key(0x33);

        let taken = 0x1234_5678u32;
        assert!(reserve_index(&mut routes, owner, taken), "the first claim wins");
        assert!(
            !reserve_index(&mut routes, rival, taken),
            "a second claim on the same index must be refused"
        );

        // The owner is untouched, session slot included.
        let route = &routes[&taken];
        assert_eq!(route.peer, owner);
        assert_eq!(route.tunnel, 0);

        // Zero is never a valid index.
        assert!(!reserve_index(&mut routes, owner, 0));
        assert_eq!(routes.len(), 1);
    }

    #[test]
    fn a_devices_routes_send_each_peer_its_own_packets() {
        // One hub talking to two spokes.
        let mut hub = Device::new(key(0x01));
        let mut s1 = Device::new(key(0x11));
        let mut s2 = Device::new(key(0x22));

        hub.add_peer(s1.static_public().to_owned(), None, None);
        hub.add_peer(s2.static_public().to_owned(), None, None);
        s1.add_peer(hub.static_public().to_owned(), None, None);
        s2.add_peer(hub.static_public().to_owned(), None, None);

        let s1_key = s1.static_public().to_owned();
        let s2_key = s2.static_public().to_owned();

        // Both spokes handshake with the hub.
        for (spoke, name) in [(&mut s1, "s1"), (&mut s2, "s2")] {
            let mut spoke_buf = buf();
            let mut hub_buf = buf();

            let hub_key = hub.static_public().to_owned();
            let mut init = match spoke.encapsulate(&hub_key, name.as_bytes(), &mut spoke_buf) {
                TunnelResult::WriteToNetwork(p) => p.to_vec(),
                other => panic!("expected an initiation, got {other:?}"),
            };

            let mut response = match hub.handle_datagram(src(1), &mut init, &mut hub_buf) {
                TunnelResult::WriteToNetwork(p) => p.to_vec(),
                other => panic!("{name}: expected a response, got {other:?}"),
            };
            let mut keepalive = match spoke.handle_datagram(src(2), &mut response, &mut spoke_buf) {
                TunnelResult::WriteToNetwork(p) => p.to_vec(),
                other => panic!("{name}: expected a keepalive, got {other:?}"),
            };
            assert!(matches!(
                hub.handle_datagram(src(3), &mut keepalive, &mut hub_buf),
                TunnelResult::WriteToTunnelInPlace(_)
            ));
        }

        // Four indices are live: a session plus a send-side session per side.
        assert!(
            hub.route_count() >= 2,
            "the hub must route both spokes, got {}",
            hub.route_count()
        );

        // Encrypt one packet for each spoke and check each arrives only at its
        // own destination. This is what a single-peer device could not do.
        deliver(&mut hub, &s1_key, &mut s1, &mut s2, "for s1");
        deliver(&mut hub, &s2_key, &mut s2, &mut s1, "for s2");
    }

    /// Sends one packet from `hub` addressed to `dest` and checks it lands
    /// there, and that `other` refuses the very same datagram.
    fn deliver(hub: &mut Device, spoke_key: &PeerKey, dest: &mut Device, other: &mut Device, expected: &str) {
        let mut hub_buf = buf();
        let mut dest_buf = buf();
        let mut other_buf = buf();

        let mut packet = match hub.encapsulate(spoke_key, expected.as_bytes(), &mut hub_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected data, got {other:?}"),
        };

        match dest.handle_datagram(src(9), &mut packet, &mut dest_buf) {
            TunnelResult::WriteToTunnelInPlace(plaintext) => {
                assert_eq!(plaintext, expected.as_bytes());
            }
            other => panic!("{expected}: expected delivery, got {other:?}"),
        }

        let mut replay = packet.clone();
        assert!(
            !matches!(
                other.handle_datagram(src(9), &mut replay, &mut other_buf),
                TunnelResult::WriteToTunnelInPlace(_)
            ),
            "{expected} was delivered to the wrong peer"
        );
    }

    #[test]
    fn a_handshake_completes_through_the_device() {
        let (mut a, mut b) = paired();
        let b_key = b.static_public().to_owned();

        let mut a_buf = buf();
        let mut b_buf = buf();

        let mut init = match a.encapsulate(&b_key, b"hello", &mut a_buf) {
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

    /// A packet queued before the handshake leaves via the device's drain
    /// call, not by feeding `decapsulate` an empty datagram.
    #[test]
    fn the_device_drains_what_was_queued_before_the_handshake() {
        let (mut a, mut b) = paired();
        let b_key = b.static_public().to_owned();

        let mut a_buf = buf();
        let mut b_buf = buf();

        // No session yet: the packet is held and an initiation goes out.
        let mut init = match a.encapsulate(&b_key, b"held", &mut a_buf) {
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
        let mut held = {
            let a_tunnel = a.peer_mut(&b_key).unwrap();
            match a_tunnel.send_queued_packet(&mut a_buf) {
                TunnelResult::WriteToNetwork(p) => p.to_vec(),
                other => panic!("expected the held packet, got {other:?}"),
            }
        };
        match b.handle_datagram(src(1), &mut held, &mut b_buf) {
            TunnelResult::WriteToTunnelInPlace(plaintext) => assert_eq!(plaintext, b"held"),
            other => panic!("expected plaintext, got {other:?}"),
        }
        let a_tunnel = a.peer_mut(&b_key).unwrap();
        assert!(matches!(
            a_tunnel.send_queued_packet(&mut a_buf),
            TunnelResult::Done
        ));
    }

    /// A flood spread over many peers trips no single peer's threshold, so the
    /// counter must be device-wide for the defence to engage at all.
    #[test]
    fn a_flood_spread_over_peers_still_trips_the_device_counter() {
        let mut device = Device::new(key(0x11));
        for i in 0..100u8 {
            device.add_peer(key(i), None, None);
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
        let (mut a, mut b) = paired();
        let b_key = b.static_public().to_owned();

        let mut a_buf = buf();
        let mut b_buf = buf();
        let mut init = match a.encapsulate(&b_key, b"hi", &mut a_buf) {
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
        let (mut a, mut b) = paired();
        let b_key = b.static_public().to_owned();

        // Threshold zero: every handshake is challenged.
        {
            let public = *b.static_public();
            *b.cookies.lock().unwrap() = CookieChecker::with_limit(public, 0);
        }

        let mut a_buf = buf();
        let mut b_buf = buf();

        let mut init = match a.encapsulate(&b_key, b"payload", &mut a_buf) {
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

        let mut retry = match a.format_handshake_initiation(&b_key, &mut a_buf, true) {
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
        let mut data = match a.encapsulate(&b_key, b"an IP packet", &mut a_buf) {
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
        let (mut a, mut b) = paired();
        let b_key = b.static_public().to_owned();
        {
            let public = *b.static_public();
            *b.cookies.lock().unwrap() = CookieChecker::with_limit(public, 0);
        }

        let mut a_buf = buf();
        let mut b_buf = buf();
        let mut init = match a.encapsulate(&b_key, b"payload", &mut a_buf) {
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
        let mut retry = match a.format_handshake_initiation(&b_key, &mut a_buf, true) {
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
