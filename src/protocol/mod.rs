//! WireGuard protocol engine. The rest of the application only deals in
//! `Tunnel` and `TunnelResult`; packet layouts, replay protection and AEAD
//! state stay private to this module.

mod handshake;
mod index;
mod packet;
mod primitives;
mod replay;
mod session;
mod tunnel;

pub use session::{DATA_OVERHEAD, MAX_TRANSPORT_PAYLOAD, Session, SessionError};
pub use index::{IndexAllocator, SessionIndex};
pub use tunnel::{MAX_PACKET_SIZE, Tunnel, TunnelResult};
