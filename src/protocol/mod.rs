//! WireGuard protocol engine. The rest of the application only deals in
//! `Tunnel` and `TunnelResult`; packet layouts, replay protection and AEAD
//! state stay private to this module.

pub mod cookie;
pub mod packet;
pub mod primitives;

mod handshake;
mod index;
mod replay;
mod session;
mod tunnel;

pub use session::{DATA_OVERHEAD, MAX_TRANSPORT_PAYLOAD, Session, SessionError};
pub use cookie::{Cookie, CookieChallenge, CookieChecker, StoredCookie};
pub use packet::{Packet, WireGuardError};
pub use index::{IndexAllocator, SessionIndex};
pub use tunnel::{MAX_PACKET_SIZE, Tunnel, TunnelResult};
