//! Cookie-based DoS mitigation (§5.4.4/§5.4.7): under load a responder answers
//! an initiation whose `mac2` does not prove ownership of the source address
//! with a `cookie_reply`, and the initiator retries with the cookie in `mac2`.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::packet::{self, CookieReply, WireGuardError};
use super::primitives::{
    HASH, Key, LABEL_COOKIE, LABEL_MAC1, MAC, MAC_KEYED, MAC_LEN, RAND, XAEAD_DECRYPT,
    XAEAD_ENCRYPT,
};

/// How long a secret is used before it is replaced.
pub const COOKIE_SECRET_MAX_AGE: Duration = Duration::from_secs(120);
/// How long a received cookie may be reused (§5.4.7).
pub const COOKIE_MAX_AGE: Duration = Duration::from_secs(120);

/// Length of the cookie itself: 16 bytes, like a MAC tag.
pub const COOKIE_LEN: usize = 16;
const NONCE_LEN: usize = 24;
/// Handshakes per second tolerated before cookies are demanded.
const DEFAULT_RATE_LIMIT: u64 = 100;

pub type Cookie = [u8; COOKIE_LEN];

/// `HASH(LABEL_MAC1 || public_key)`: what a peer's `mac1` must be built with.
pub fn mac1_key(public_key: &Key) -> Key {
    HASH(&[LABEL_MAC1, public_key])
}

/// `HASH(LABEL_COOKIE || public_key)`: the key that wraps a cookie reply.
pub fn cookie_key(public_key: &Key) -> Key {
    HASH(&[LABEL_COOKIE, public_key])
}

/// The cookie a peer expects from `addr`: `MAC(secret, addr)`. The secret is
/// rotated on a timer, so a cookie lives exactly as long as that secret.
pub fn cookie_for(secret: &Key, addr: IpAddr) -> Cookie {
    let mut addr_bytes = [0u8; 16];
    match addr {
        IpAddr::V4(v4) => addr_bytes[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => addr_bytes.copy_from_slice(&v6.octets()),
    }
    MAC_KEYED(secret, &addr_bytes)
}

/// Why `verify_macs` refused a handshake message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieChallenge {
    /// `mac1` did not verify: drop silently and answer nothing at all.
    NotForUs,
    /// Under load, but no source address was available to key a cookie on.
    NeedSourceAddress,
    /// `mac2` did not verify: answer with a cookie reply carrying this cookie.
    WrongMac2 { cookie: Cookie },
}

/// Verifies the two MACs trailing a handshake message. `mac1` is always
/// required; `mac2` only under load, so peers pay no extra round trip.
pub fn verify_macs(
    public_key: &Key,
    src_addr: Option<IpAddr>,
    secret: &Key,
    under_load: bool,
    message: &[u8],
) -> Result<(), CookieChallenge> {
    let mac1_off = message.len() - 2 * MAC_LEN;
    let mac2_off = message.len() - MAC_LEN;
    let body = &message[..mac1_off];
    let mac1: &[u8; MAC_LEN] = message[mac1_off..mac2_off]
        .try_into()
        .expect("slice is MAC_LEN");
    let mac2: &[u8; MAC_LEN] = message[mac2_off..].try_into().expect("slice is MAC_LEN");

    if MAC(&mac1_key(public_key), body) != *mac1 {
        return Err(CookieChallenge::NotForUs);
    }
    if !under_load {
        return Ok(());
    }

    let Some(addr) = src_addr else {
        // Without an address `mac2` cannot be checked at all; refuse rather
        // than skip the check that is protecting us.
        return Err(CookieChallenge::NeedSourceAddress);
    };

    let cookie = cookie_for(secret, addr);
    // `mac2` covers everything before it, `mac1` included.
    if MAC_KEYED(&cookie, &message[..mac2_off]) == *mac2 {
        return Ok(());
    }
    Err(CookieChallenge::WrongMac2 { cookie })
}

/// Constant-time comparison of two MAC tags.
pub fn mac_eq(a: &[u8; MAC_LEN], b: &[u8; MAC_LEN]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// A cookie received from a peer, usable until it expires.
#[derive(Debug, Clone, Copy)]
pub struct StoredCookie {
    pub cookie: Cookie,
    pub received_at: Instant,
}

impl StoredCookie {
    /// True once the cookie is too old to send: a stale one only wastes a
    /// round trip, since the peer would reject it.
    pub fn is_expired(&self, now: Instant) -> bool {
        now.checked_duration_since(self.received_at)
            .is_none_or(|age| age >= COOKIE_MAX_AGE)
    }
}

/// The device-wide half of the cookie mechanism: the secret, the rate counter
/// and the reply codec. Shared by every peer, since a cookie proves a source
/// address rather than a peer identity.
pub struct CookieChecker {
    /// The key our `mac1` and cookie keys are derived from.
    public_key: Key,
    /// Rotated every `COOKIE_SECRET_MAX_AGE`.
    secret: Key,
    /// When `secret` was drawn, so it can be rotated.
    secret_birth: Instant,
    /// Feeds reply nonces; only uniqueness matters.
    nonce_counter: AtomicU64,
    /// Handshakes seen in the current window.
    count: AtomicU64,
    /// Handshakes per window tolerated before cookies are demanded.
    limit: u64,
    /// When `count` was last reset; advanced by `reset_count`.
    window_start: std::cell::Cell<Instant>,
}

impl CookieChecker {
    pub fn new(public_key: Key) -> Self {
        Self::with_limit(public_key, DEFAULT_RATE_LIMIT)
    }

    /// `limit` is handshakes per second tolerated before cookies are demanded.
    pub fn with_limit(public_key: Key, limit: u64) -> Self {
        let mut secret = [0u8; 32];
        RAND(&mut secret);
        let now = Instant::now();
        Self {
            public_key,
            secret,
            secret_birth: now,
            nonce_counter: AtomicU64::new(0),
            count: AtomicU64::new(0),
            limit,
            window_start: std::cell::Cell::new(now),
        }
    }

    /// Test hook: the public key this checker is keyed with.
    #[cfg(test)]
    pub(super) fn public_key_for_tests(&self) -> Key {
        self.public_key
    }

    /// The key a peer must build `mac1` with, and that we verify against.
    pub fn mac1_key(&self) -> Key {
        mac1_key(&self.public_key)
    }

    /// The key that wraps cookie replies we send.
    pub fn cookie_key(&self) -> Key {
        cookie_key(&self.public_key)
    }

    /// The current secret, for verifying a peer's `mac2`.
    pub fn secret(&self) -> Key {
        self.secret
    }

    /// The cookie we currently expect from `addr`.
    pub fn current_cookie(&self, addr: IpAddr) -> Cookie {
        cookie_for(&self.secret, addr)
    }

    /// Redraws the secret once it is older than `COOKIE_SECRET_MAX_AGE`, so a
    /// cookie cannot be banked and replayed indefinitely.
    pub fn rotate_secret_if_stale(&mut self, now: Instant) {
        if now
            .checked_duration_since(self.secret_birth)
            .is_some_and(|age| age >= COOKIE_SECRET_MAX_AGE)
        {
            RAND(&mut self.secret);
            self.secret_birth = now;
        }
    }

    /// Resets the rate counter; meant to run about once a second.
    pub fn reset_count(&self, now: Instant) {
        let start = self.window_start.get();
        if now
            .checked_duration_since(start)
            .is_some_and(|age| age >= Duration::from_secs(1))
        {
            self.count.store(0, Ordering::Relaxed);
            // Advance the window, otherwise every later call would reset
            // again and the device could never stay "under load".
            self.window_start.set(now);
        }
    }

    /// Counts a handshake and reports whether cookies must now be demanded.
    pub fn note_handshake(&self) -> bool {
        self.count.fetch_add(1, Ordering::Relaxed) >= self.limit
    }

    /// Verifies a handshake message's `mac1`/`mac2`, counting it towards the
    /// rate window: an unloaded device demands no cookie.
    pub fn check_handshake(
        &mut self,
        src_addr: Option<IpAddr>,
        message: &[u8],
        now: Instant,
    ) -> Result<(), CookieChallenge> {
        self.rotate_secret_if_stale(now);
        self.reset_count(now);
        let under_load = self.note_handshake();
        verify_macs(
            &self.public_key,
            src_addr,
            &self.secret,
            under_load,
            message,
        )
    }

    /// A fresh reply nonce. It need not be secret, only unique.
    fn nonce(&mut self) -> [u8; NONCE_LEN] {
        let counter = self.nonce_counter.fetch_add(1, Ordering::Relaxed);
        let digest = HASH(&[&self.secret, &counter.to_le_bytes()]);
        let mut out = [0u8; NONCE_LEN];
        out.copy_from_slice(&digest[..NONCE_LEN]);
        out
    }

    /// Builds a `cookie_reply` into `dst`, returning its length. `sender_index`
    /// echoes the initiator's; `mac1` is the reply's AAD. Wrapped with our own
    /// key, since the initiator unwraps with it (§5.4.7).
    pub fn format_cookie_reply(
        &mut self,
        dst: &mut [u8],
        sender_index: u32,
        cookie: &Cookie,
        mac1: &[u8; MAC_LEN],
    ) -> Result<usize, WireGuardError> {
        let len = packet::COOKIE_REPLY_LEN;
        let out = dst.get_mut(..len).ok_or(WireGuardError::InvalidPacket)?;

        let nonce = self.nonce();
        let nonce_arr: &[u8; NONCE_LEN] = &nonce;
        let encrypted = XAEAD_ENCRYPT(&self.cookie_key(), nonce_arr, mac1, cookie)
            .map_err(|_| WireGuardError::HandshakeNotAuthentic)?;
        debug_assert_eq!(encrypted.len(), COOKIE_LEN + MAC_LEN);

        out[0..4].copy_from_slice(&packet::MSG_COOKIE_REPLY.to_le_bytes());
        out[4..8].copy_from_slice(&sender_index.to_le_bytes());
        out[8..32].copy_from_slice(&nonce);
        out[32..64].copy_from_slice(&encrypted);
        Ok(len)
    }

}

/// Recovers the cookie from a reply, given the `mac1` of the initiation it
/// answers; the index must match ours. We are the initiator, so
/// `peer_public_key` is the responder's key, which wrapped it.
pub fn open_cookie_reply(
    peer_public_key: &Key,
    reply: &CookieReply<'_>,
    our_index: u32,
    our_mac1: &[u8; MAC_LEN],
) -> Result<Cookie, WireGuardError> {
    if reply.receiver_index != our_index {
        return Err(WireGuardError::InvalidPacket);
    }
    let plaintext = XAEAD_DECRYPT(
        &cookie_key(peer_public_key),
        reply.nonce,
        our_mac1,
        reply.encrypted_cookie,
    )
    .map_err(|_| WireGuardError::HandshakeNotAuthentic)?;

    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| WireGuardError::InvalidPacket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::primitives::{DH_PRIVATE, DH_PUBKEY};

    fn key(byte: u8) -> Key {
        [byte; 32]
    }

    fn addr(last: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, last))
    }

    /// A handshake-shaped message: arbitrary body plus 32 bytes of MACs.
    fn message(body: &[u8]) -> Vec<u8> {
        let mut msg = body.to_vec();
        msg.extend_from_slice(&[0u8; 2 * MAC_LEN]);
        msg
    }

    fn sign(public_key: &Key, cookie: Option<&Cookie>, msg: &mut [u8]) {
        let mac1_off = msg.len() - 2 * MAC_LEN;
        let mac2_off = msg.len() - MAC_LEN;
        let mac1 = MAC(&mac1_key(public_key), &msg[..mac1_off]);
        msg[mac1_off..mac2_off].copy_from_slice(&mac1);
        if let Some(cookie) = cookie {
            let mac2 = MAC_KEYED(cookie, &msg[..mac2_off]);
            msg[mac2_off..].copy_from_slice(&mac2);
        }
    }

    #[test]
    fn mac1_is_verified_against_our_own_key() {
        let public_key = DH_PUBKEY(&DH_PRIVATE(&key(0x11)));
        let mut msg = message(b"handshake body");
        sign(&public_key, None, &mut msg);

        assert_eq!(
            verify_macs(&public_key, Some(addr(1)), &key(7), false, &msg),
            Ok(())
        );

        // A message signed for another key must not be accepted.
        let stranger = DH_PUBKEY(&DH_PRIVATE(&key(0x22)));
        assert_eq!(
            verify_macs(&stranger, Some(addr(1)), &key(7), false, &msg),
            Err(CookieChallenge::NotForUs)
        );
    }

    /// While unloaded, mac2 is not demanded: a peer with no cookie is served
    /// directly, avoiding the extra round trip.
    #[test]
    fn mac2_is_not_required_while_unloaded() {
        let public_key = DH_PUBKEY(&DH_PRIVATE(&key(0x11)));
        let mut msg = message(b"body");
        sign(&public_key, None, &mut msg);

        assert_eq!(
            verify_macs(&public_key, Some(addr(1)), &key(7), false, &msg),
            Ok(()),
            "an unloaded device must not demand a cookie"
        );
    }

    /// Under load a missing mac2 yields the cookie for that address, which is
    /// what the caller turns into a cookie reply.
    #[test]
    fn under_load_a_missing_mac2_yields_the_cookie() {
        let public_key = DH_PUBKEY(&DH_PRIVATE(&key(0x11)));
        let secret = key(7);
        let mut msg = message(b"body");
        sign(&public_key, None, &mut msg);

        match verify_macs(&public_key, Some(addr(1)), &secret, true, &msg) {
            Err(CookieChallenge::WrongMac2 { cookie }) => {
                assert_eq!(cookie, cookie_for(&secret, addr(1)));
            }
            other => panic!("expected a cookie challenge, got {other:?}"),
        }
    }

    #[test]
    fn under_load_the_right_mac2_is_accepted_and_a_stolen_one_is_not() {
        let public_key = DH_PUBKEY(&DH_PRIVATE(&key(0x11)));
        let secret = key(7);

        // Signed with the cookie that belongs to this very address.
        let cookie = cookie_for(&secret, addr(1));
        let mut good = message(b"body");
        sign(&public_key, Some(&cookie), &mut good);
        assert_eq!(verify_macs(&public_key, Some(addr(1)), &secret, true, &good), Ok(()));

        // The same cookie presented from another address must fail: that is
        // the whole point, it proves ownership of the address.
        assert!(matches!(
            verify_macs(&public_key, Some(addr(2)), &secret, true, &good),
            Err(CookieChallenge::WrongMac2 { .. })
        ));
    }

    /// Under load with no source address there is nothing to key the cookie
    /// on, so the message must be refused rather than waved through.
    #[test]
    fn under_load_without_an_address_refuses() {
        let public_key = DH_PUBKEY(&DH_PRIVATE(&key(0x11)));
        let mut msg = message(b"body");
        sign(&public_key, None, &mut msg);

        assert_eq!(
            verify_macs(&public_key, None, &key(7), true, &msg),
            Err(CookieChallenge::NeedSourceAddress)
        );
    }

    /// The reply round trip: a cookie minted for one address must decrypt for
    /// that peer and carry the index it echoes.
    #[test]
    fn a_cookie_reply_round_trips() {
        // The responder issues; the initiator holds its peer's public key.
        let responder_public = DH_PUBKEY(&DH_PRIVATE(&key(0x22)));
        let mut issuer = CookieChecker::new(responder_public);

        // The issuer wraps with the initiator's key; the initiator opens with
        // the responder's, so each direction uses the other side's key.
        let initiator_public = DH_PUBKEY(&DH_PRIVATE(&key(0x11)));
        let opener = CookieChecker::new(responder_public);

        let cookie = issuer.current_cookie(addr(1));
        let mac1 = [0xab; MAC_LEN];
        let mut dst = [0u8; packet::COOKIE_REPLY_LEN];
        let len = issuer
            .format_cookie_reply(&mut dst, 0x1234, &cookie, &mac1)
            .unwrap();
        assert_eq!(len, packet::COOKIE_REPLY_LEN);

        let parsed = match packet::Packet::parse(&dst).unwrap() {
            packet::Packet::CookieReply(reply) => reply,
            other => panic!("expected a cookie reply, got {other:?}"),
        };
        let recovered = open_cookie_reply(&responder_public, &parsed, 0x1234, &mac1).unwrap();
        assert_eq!(recovered, cookie);
    }

    /// The reply is bound to the mac1 it answers and to the index, so it
    /// cannot be replayed against a different handshake.
    #[test]
    fn a_cookie_reply_is_bound_to_index_and_mac1() {
        let responder_public = DH_PUBKEY(&DH_PRIVATE(&key(0x22)));
        let mut issuer = CookieChecker::new(responder_public);
        let opener = CookieChecker::new(responder_public);
        let initiator_public = DH_PUBKEY(&DH_PRIVATE(&key(0x11)));

        let cookie = issuer.current_cookie(addr(1));
        let mac1 = [0xab; MAC_LEN];
        let mut dst = [0u8; packet::COOKIE_REPLY_LEN];
        issuer
            .format_cookie_reply(&mut dst, 0x1234, &cookie, &mac1)
            .unwrap();
        let parsed = match packet::Packet::parse(&dst).unwrap() {
            packet::Packet::CookieReply(reply) => reply,
            other => panic!("expected a cookie reply, got {other:?}"),
        };

        // Wrong index: refused before any AEAD work.
        assert_eq!(
            open_cookie_reply(&responder_public, &parsed, 0x9999, &mac1).unwrap_err(),
            WireGuardError::InvalidPacket
        );
        // Wrong mac1: the AAD no longer matches.
        assert_eq!(
            open_cookie_reply(&responder_public, &parsed, 0x1234, &[0xcd; MAC_LEN]).unwrap_err(),
            WireGuardError::HandshakeNotAuthentic
        );
    }

    /// A cookie is tied to the address it was issued for.
    #[test]
    fn a_cookie_is_bound_to_the_source_address() {
        let secret = key(7);
        assert_ne!(cookie_for(&secret, addr(1)), cookie_for(&secret, addr(2)));
        assert_eq!(cookie_for(&secret, addr(1)), cookie_for(&secret, addr(1)));

        // IPv6 differs from IPv4 even with matching low bytes.
        let v6 = IpAddr::V6(std::net::Ipv6Addr::LOCALHOST);
        assert_ne!(cookie_for(&secret, addr(1)), cookie_for(&secret, v6));
    }

    #[test]
    fn rotating_the_secret_invalidates_old_cookies() {
        let mut checker = CookieChecker::new(key(0x11));
        let before = checker.current_cookie(addr(1));

        // Not yet stale: the cookie must still be the same.
        checker.rotate_secret_if_stale(Instant::now());
        assert_eq!(checker.current_cookie(addr(1)), before);

        // Past the max age the secret is replaced and cookies change.
        let later = Instant::now() + COOKIE_SECRET_MAX_AGE + Duration::from_secs(1);
        checker.rotate_secret_if_stale(later);
        assert_ne!(checker.current_cookie(addr(1)), before);
    }

    #[test]
    fn the_rate_window_decides_when_cookies_are_demanded() {
        let checker = CookieChecker::with_limit(key(0x11), 3);
        let now = Instant::now();

        // The first `limit` handshakes are served without cookies.
        assert!(!checker.note_handshake());
        assert!(!checker.note_handshake());
        assert!(!checker.note_handshake());
        // The next one crosses the threshold.
        assert!(checker.note_handshake());

        // After the window rolls over, the device is unloaded again.
        checker.reset_count(now + Duration::from_secs(2));
        assert!(!checker.note_handshake());
    }

    #[test]
    fn a_stored_cookie_expires() {
        let now = Instant::now();
        let stored = StoredCookie {
            cookie: [0u8; COOKIE_LEN],
            received_at: now,
        };
        assert!(!stored.is_expired(now + COOKIE_MAX_AGE - Duration::from_secs(1)));
        assert!(stored.is_expired(now + COOKIE_MAX_AGE));
    }
}
