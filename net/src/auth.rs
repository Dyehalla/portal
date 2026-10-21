use crate::{ALPN, Peer, PeerKey};
use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock, Weak},
};

#[derive(Debug)]
pub(crate) struct TrustedPeers(pub Weak<RwLock<HashMap<PeerKey, Arc<Peer>>>>);

impl EndpointHooks for TrustedPeers {
    /// Iroh authenticates the Ed25519 identity; Portal decides whether that peer is trusted.
    async fn after_handshake(&self, connection: &Connection) -> AfterHandshakeOutcome {
        let allowed = connection.alpn() == ALPN
            && self.0.upgrade().is_some_and(|peers| {
                peers
                    .read()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains_key(connection.remote_id().as_bytes())
            });
        if allowed {
            AfterHandshakeOutcome::Accept
        } else {
            AfterHandshakeOutcome::Reject {
                error_code: 403u32.into(),
                reason: b"unregistered peer".to_vec(),
            }
        }
    }
}
