//! WireGuard protocol engine. 

mod cookie;
mod handshake;
mod index;
mod packet;
mod primitives;
mod replay;
mod session;
mod tunnel;

pub use cookie::{Cookie, CookieChallenge, CookieChecker, StoredCookie};
pub use index::{IndexAllocator, SessionIndex};
pub use packet::{Packet, WireGuardError};
pub use session::{DATA_OVERHEAD, MAX_TRANSPORT_PAYLOAD, Session, SessionError};
pub use tunnel::{MAX_PACKET_SIZE, Tunnel, TunnelResult};

// The device layer verifies handshake MACs before looking a peer up, so it
// needs the packet layout and the key helpers as well.
pub use packet::{COOKIE_REPLY_LEN, HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN, MSG_COOKIE_REPLY, MSG_HANDSHAKE_RESPONSE, TAG_LEN};
pub use primitives::{DH_PRIVATE, DH_PUBKEY, HASH, LABEL_MAC1, KEY_LEN};
pub use cookie::{verify_macs as verify_handshake_macs, COOKIE_MAX_AGE};
pub use cookie::open_cookie_reply;
