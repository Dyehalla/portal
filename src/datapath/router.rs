//! Platform-independent WireGuard datagram classification for dispatch.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use crate::device::{DeviceSnapshot, TunnelAssignment};
use crate::index_table::{IndexTable, Route};
use crate::protocol::{
    COOKIE_REPLY_LEN, CookieChallenge, CookieChecker, DATA_HEADER_LEN, HANDSHAKE_INIT_LEN,
    HANDSHAKE_RESPONSE_LEN, MSG_COOKIE_REPLY, MSG_DATA, MSG_HANDSHAKE_INIT,
    MSG_HANDSHAKE_RESPONSE, Packet, verify_handshake_macs,
};

/// Result of examining one outer UDP datagram before it enters a worker ring.
pub enum DatagramRoute {
    Tunnel(TunnelAssignment),
    CookieReply { packet: [u8; COOKIE_REPLY_LEN], len: usize },
    Drop,
}

/// Read-mostly index and peer lookup for incoming WireGuard datagrams.
pub struct DatagramRouter {
    snapshot: Arc<ArcSwap<DeviceSnapshot>>,
    indices: Arc<IndexTable>,
    cookies: CookieChecker,
}

impl DatagramRouter {
    /// Creates a classifier sharing the device's routing snapshot and indices.
    pub fn new(
        snapshot: Arc<ArcSwap<DeviceSnapshot>>,
        indices: Arc<IndexTable>,
        static_public: [u8; 32],
    ) -> Self {
        Self {
            snapshot,
            indices,
            cookies: CookieChecker::new(static_public),
        }
    }

    /// Classifies an outer datagram, verifying handshake MACs before peer lookup.
    pub fn classify(&mut self, source: SocketAddr, bytes: &[u8]) -> DatagramRoute {
        let Some(message_type) = bytes
            .get(..4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
        else {
            return DatagramRoute::Drop;
        };

        let snapshot = self.snapshot.load_full();
        match message_type {
            MSG_HANDSHAKE_INIT => {
                if Packet::parse(bytes).is_err() {
                    return DatagramRoute::Drop;
                }
                if let Some(reply) = self.verify_handshake_mac(source.ip(), bytes) {
                    return reply;
                }
                let peer = match Packet::parse(bytes) {
                    Ok(Packet::HandshakeInitiation(initiation)) => {
                        snapshot.identify_initiation(&initiation)
                    }
                    _ => None,
                };
                peer.and_then(|peer| snapshot.assignment_for_peer(&peer))
                    .map_or(DatagramRoute::Drop, DatagramRoute::Tunnel)
            }
            MSG_HANDSHAKE_RESPONSE => {
                if Packet::parse(bytes).is_err() {
                    return DatagramRoute::Drop;
                }
                if let Some(reply) = self.verify_handshake_mac(source.ip(), bytes) {
                    return reply;
                }
                let Some(index) = bytes
                    .get(8..12)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map(u32::from_le_bytes)
                else {
                    return DatagramRoute::Drop;
                };
                self.assignment_for_index(index)
                    .map_or(DatagramRoute::Drop, DatagramRoute::Tunnel)
            }
            MSG_COOKIE_REPLY => match Packet::parse(bytes) {
                Ok(Packet::CookieReply(reply)) => self
                    .assignment_for_index(reply.receiver_index)
                    .map_or(DatagramRoute::Drop, DatagramRoute::Tunnel),
                _ => DatagramRoute::Drop,
            },
            MSG_DATA if bytes.len() >= DATA_HEADER_LEN + 16 => {
                let Some(index) = bytes
                    .get(4..8)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map(u32::from_le_bytes)
                else {
                    return DatagramRoute::Drop;
                };
                self.assignment_for_index(index)
                    .map_or(DatagramRoute::Drop, DatagramRoute::Tunnel)
            }
            _ => DatagramRoute::Drop,
        }
    }

    /// Rotates the cookie secret when its lifetime expires.
    pub fn rotate_cookie_secret_if_stale(&mut self, now: Instant) {
        self.cookies.rotate_secret_if_stale(now);
    }

    /// Resets the device-wide handshake counter when its rate window expires.
    pub fn reset_cookie_count(&mut self, now: Instant) {
        self.cookies.reset_count(now);
    }

    fn assignment_for_index(&self, index: u32) -> Option<TunnelAssignment> {
        self.indices.lookup(index).map(|Route { worker, tunnel }| TunnelAssignment {
            worker,
            tunnel,
        })
    }

    /// Returns a challenge reply when MAC2 is required; `None` means continue.
    fn verify_handshake_mac(&mut self, source: IpAddr, bytes: &[u8]) -> Option<DatagramRoute> {
        let kind = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?);
        let mac_offset = match kind {
            MSG_HANDSHAKE_INIT if bytes.len() == HANDSHAKE_INIT_LEN => HANDSHAKE_INIT_LEN - 32,
            MSG_HANDSHAKE_RESPONSE if bytes.len() == HANDSHAKE_RESPONSE_LEN => {
                HANDSHAKE_RESPONSE_LEN - 32
            }
            _ => return Some(DatagramRoute::Drop),
        };
        let under_load = self.cookies.note_handshake();
        let public_key = *self.snapshot.load().static_public();
        let secret = self.cookies.secret();
        match verify_handshake_macs(&public_key, Some(source), &secret, under_load, bytes) {
            Ok(()) => None,
            Err(CookieChallenge::WrongMac2 { cookie }) => {
                let sender = u32::from_le_bytes(bytes.get(4..8)?.try_into().ok()?);
                let mac1: [u8; 16] = bytes.get(mac_offset..mac_offset + 16)?.try_into().ok()?;
                let mut packet = [0u8; COOKIE_REPLY_LEN];
                let Ok(len) = self
                    .cookies
                    .format_cookie_reply(&mut packet, sender, &cookie, &mac1)
                else {
                    return Some(DatagramRoute::Drop);
                };
                Some(DatagramRoute::CookieReply { packet, len })
            }
            Err(CookieChallenge::NotForUs | CookieChallenge::NeedSourceAddress) => {
                Some(DatagramRoute::Drop)
            }
        }
    }
}
