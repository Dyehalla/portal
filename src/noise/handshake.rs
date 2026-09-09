use crate::device::Session;

use super::noise_primitives::*;

#[repr(C)]
struct Handshake {
    message_type: u8,
    reserved_zero: [u8; 3],
    sender_index: u32,
    unencrypted_ephemeral: [u8; 32],
    encrypted_static: [u8; AEAD_LEN(32)],
    encrypted_timestamp: [u8; AEAD_LEN(12)],
    mac1: [u8; 16],
    mac2: [u8; 16]
}

// initiate Session and construct Handshake
pub fn init_session(peer: &Peer) -> (Session, Handshake) {
    let chaining_key = HASH(&[CONSTRUCTION]);
    let hash = HASH(&[&chaining_key, IDENTIFIER]);
    let (ephemeral_priv, ephemeral_pub) = DH_GENERATE();
    chaining_key = KDF1(&chaining_key, &ephemeral_pub);
    

}