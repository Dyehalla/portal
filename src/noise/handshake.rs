//! WireGuard handshake.
//!
//! Implemented here: the first message, initiator -> responder (whitepaper
//! §5.4.2). Message 2 (responder -> initiator, §5.4.3) and the cookie reply
//! (§5.4.7) build on the same primitives and will slot in next to this code.

use crate::{
    Error,
    device::{COOKIE_SECRET_LIFETIME, Identity, Peer, Session},
};

use super::noise_primitives::*;

// initiator.chaining_key = HASH(CONSTRUCTION)
const INITIAL_CHAIN_KEY: [u8; KEY_LEN] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];

// initiator.chaining_hash = HASH(initiator.chaining_key || IDENTIFIER)
const INITIAL_CHAIN_HASH: [u8; KEY_LEN] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

/// On the wire the message type is a little-endian u32; for the four protocol
/// messages (1..=4) only the first byte is non-zero, so a byte constant is
/// enough as long as the three reserved bytes are written as zero.
pub const MSG_HANDSHAKE_INITIATION: u8 = 1;

/// Handshake initiation layout (§5.4.2):
///
/// ```text
///   0  type(1) || reserved(3)
///   4  sender(4)
///   8  ephemeral(32)
///  40  encrypted_static(48)
///  88  encrypted_timestamp(28)
/// 116  mac1(16)          <- msg_alpha is [0..116)
/// 132  mac2(16)          <- msg_beta  is [0..132)
/// ```
pub const HANDSHAKE_INIT_LEN: usize = 148;

const OFF_SENDER: usize = 4;
const OFF_EPHEMERAL: usize = 8;
const OFF_STATIC: usize = 40;
const OFF_TIMESTAMP: usize = 88;
const OFF_MAC1: usize = 116;
const OFF_MAC2: usize = 132;

/// mac1 key: HASH(LABEL_MAC1 || Sm'_pub) — the *peer's* static public key.
/// It never changes for a given peer, so callers may cache it on `Peer`.
pub fn mac1_key(peer_static_public: &Key) -> Key {
    HASH(&[LABEL_MAC1, peer_static_public])
}

/// Random non-zero sender index `Ii`. The same index must never be registered
/// twice, so the caller hands in its view of the device's index table.
fn generate_sender_index(is_taken: impl Fn(u32) -> bool) -> Result<u32, Error> {
    for _ in 0..64 {
        let mut bytes = [0u8; 4];
        RAND(&mut bytes);
        let index = u32::from_le_bytes(bytes);
        if index != 0 && !is_taken(index) {
            return Ok(index);
        }
    }
    Err(Error::NoFreeIndex)
}

/// Initiator side of the handshake: generates the sender index, builds
/// message 1 and returns the pending session state that will be needed to
/// consume message 2.
///
/// `index_taken` is checked before an index is accepted; the caller must make
/// the check-and-register pair atomic (hold the index-table write lock across
/// the call, or insert the returned index and retry on collision).
pub fn init_session(
    local: &Identity,
    peer: &Peer,
    index_taken: impl Fn(u32) -> bool,
) -> Result<(Session, [u8; HANDSHAKE_INIT_LEN]), Error> {
    let local_index = generate_sender_index(index_taken)?;

    let mut chaining_key = INITIAL_CHAIN_KEY;
    let mut hash = INITIAL_CHAIN_HASH;
    hash = HASH(&[&hash, &peer.public_key]);

    let (ephemeral_priv, ephemeral_pub) = DH_GENERATE();
    chaining_key = KDF1(&chaining_key, &ephemeral_pub);
    hash = HASH(&[&hash, &ephemeral_pub]);

    // (Ci, kappa) := Kdf2(Ci, DH(Eipriv, Srpub))
    let dh = DH(&ephemeral_priv, &peer.public_key).map_err(|_| Error::InvalidPeerPubKey)?;
    let (ck, key) = KDF2(&chaining_key, &dh);
    chaining_key = ck;
    let encrypted_static =
        AEAD_ENCRYPT(&key, 0, &hash, &local.public_key).map_err(|_| Error::Crypto)?;
    hash = HASH(&[&hash, &encrypted_static]);

    // (Ci, kappa) := Kdf2(Ci, DH(Sipriv, Srpub))
    let dh = DH(&local.private_key, &peer.public_key).map_err(|_| Error::InvalidPeerPubKey)?;
    let (ck, key) = KDF2(&chaining_key, &dh);
    chaining_key = ck;
    let encrypted_timestamp = AEAD_ENCRYPT(&key, 0, &hash, &TAI64N()).map_err(|_| Error::Crypto)?;
    hash = HASH(&[&hash, &encrypted_timestamp]);

    let mut msg = [0u8; HANDSHAKE_INIT_LEN];
    msg[0] = MSG_HANDSHAKE_INITIATION;
    msg[OFF_SENDER..OFF_EPHEMERAL].copy_from_slice(&local_index.to_le_bytes());
    msg[OFF_EPHEMERAL..OFF_STATIC].copy_from_slice(&ephemeral_pub);
    msg[OFF_STATIC..OFF_TIMESTAMP].copy_from_slice(&encrypted_static);
    msg[OFF_TIMESTAMP..OFF_MAC1].copy_from_slice(&encrypted_timestamp);

    // mac1 := Mac(Hash(Label-Mac1 || Sm'_pub), msg_alpha)
    let mac1 = MAC(&mac1_key(&peer.public_key), &msg[..OFF_MAC1]);
    msg[OFF_MAC1..OFF_MAC2].copy_from_slice(&mac1);

    // mac2 := Mac(Lm, msg_beta) with the last cookie received from the peer,
    // or 0^16 when there is no cookie younger than 120 seconds (§5.4.4).
    if let Some((cookie, received_at)) = &peer.last_received_cookie {
        if received_at.elapsed() < COOKIE_SECRET_LIFETIME {
            let mac2 = MAC(cookie, &msg[..OFF_MAC2]);
            msg[OFF_MAC2..].copy_from_slice(&mac2);
        }
    }

    let session = Session {
        local_index,
        ephemeral_priv: Some(ephemeral_priv),
        ephemeral_pub: Some(ephemeral_pub),
        chaining_key,
        hash,
    };

    Ok((session, msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two hardcoded tables must stay in sync with the strings they are
    /// derived from; a typo here silently breaks interoperability.
    #[test]
    fn initial_constants_match_derivation() {
        assert_eq!(HASH(&[CONSTRUCTION]), INITIAL_CHAIN_KEY);
        assert_eq!(HASH(&[&INITIAL_CHAIN_KEY, IDENTIFIER]), INITIAL_CHAIN_HASH);
    }

    #[test]
    fn message_one_layout_and_macs() {
        let (initiator_priv, initiator_pub) = DH_GENERATE();
        let (_responder_priv, responder_pub) = DH_GENERATE();

        let local = Identity {
            private_key: initiator_priv,
            public_key: initiator_pub,
        };
        let peer = Peer::new(responder_pub);

        let (session, msg) = init_session(&local, &peer, |_| false).unwrap();

        assert_eq!(msg.len(), HANDSHAKE_INIT_LEN);
        assert_eq!(msg[0], MSG_HANDSHAKE_INITIATION);
        assert_eq!(&msg[1..4], &[0, 0, 0]);
        assert_ne!(session.local_index, 0);
        assert_eq!(
            &msg[OFF_SENDER..OFF_EPHEMERAL],
            &session.local_index.to_le_bytes()
        );

        // mac1 covers exactly msg_alpha and uses the responder's public key.
        let expected_mac1 = MAC(&mac1_key(&responder_pub), &msg[..OFF_MAC1]);
        assert_eq!(&msg[OFF_MAC1..OFF_MAC2], &expected_mac1[..]);

        // No cookie stored yet -> mac2 must be all zeros.
        assert_eq!(&msg[OFF_MAC2..], &[0u8; 16]);
    }

    #[test]
    fn sender_index_respects_the_index_table() {
        use std::cell::Cell;

        let (_responder_priv, responder_pub) = DH_GENERATE();
        let peer = Peer::new(responder_pub);
        let (initiator_priv, initiator_pub) = DH_GENERATE();
        let local = Identity {
            private_key: initiator_priv,
            public_key: initiator_pub,
        };

        // Reject the first index that is offered and make sure the generator
        // does not come back with the same one.
        let rejected = Cell::new(None);
        let (session, _) = init_session(&local, &peer, |index| {
            if rejected.get().is_none() {
                rejected.set(Some(index));
                return true;
            }
            index == rejected.get().unwrap()
        })
        .unwrap();

        assert_ne!(Some(session.local_index), rejected.get());
    }

    #[test]
    fn index_exhaustion_is_an_error_not_a_panic() {
        let (_responder_priv, responder_pub) = DH_GENERATE();
        let peer = Peer::new(responder_pub);
        let (initiator_priv, initiator_pub) = DH_GENERATE();
        let local = Identity {
            private_key: initiator_priv,
            public_key: initiator_pub,
        };

        let result = init_session(&local, &peer, |_| true);
        assert!(matches!(result, Err(Error::NoFreeIndex)));
    }
}
