//! WireGuard protocol engine.

mod cookie;
mod handshake;
mod packet;
mod primitives;
mod replay;
mod session;
mod tunnel;

pub use cookie::{Cookie, CookieChallenge, CookieChecker, StoredCookie};
pub use packet::{HandshakeInitiation, Packet, WireGuardError};
pub use session::{DATA_OVERHEAD, MAX_TRANSPORT_PAYLOAD, Session, SessionError};
pub use tunnel::{MAX_PACKET_SIZE, Tunnel, TunnelResult};
// The device layer verifies handshake MACs before looking a peer up, so it
// needs the packet layout and the key helpers as well.
pub use packet::{
    COOKIE_REPLY_LEN, DATA_HEADER_LEN, HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN,
    MSG_COOKIE_REPLY, MSG_DATA, MSG_HANDSHAKE_INIT, MSG_HANDSHAKE_RESPONSE, TAG_LEN,
};
pub(crate) use primitives::RAND;
pub use primitives::{DH_PRIVATE, DH_PUBKEY, HASH, KEY_LEN, LABEL_MAC1};

/// Stand-in index source for tests; see `tunnel::tests::claimer`.
#[cfg(test)]
pub(crate) fn tests_claimer() -> impl FnMut() -> Option<u32> {
    tunnel::tests::claimer()
}
pub use cookie::open_cookie_reply;
pub use cookie::{COOKIE_MAX_AGE, verify_macs as verify_handshake_macs};
pub use handshake::parse_handshake_anon;
