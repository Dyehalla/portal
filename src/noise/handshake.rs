use aws_lc_rs::agreement::PrivateKey;

use super::noise_functions::*;

struct WGState {
    ephemeral_private: PrivateKey,
    chaining_key: Key,
    hash: Hash,
    sender_index: u32
}

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

fn construct_init_message(sender_idx: u32) -> (WGState, Handshake) {
    let initiator: WGState;
    initiator.sender_index = sender_idx;
    initiator.chaining_key = HASH(CONSTRUCTION);
    initiator.hash = HASH(HASH(initiator.chaining_key || IDENTIFIER) || responder.static_public);
    initiator.ephemeral_private = DH_GENERATE();
    
    msg.message_type = 1
    msg.reserved_zero = { 0, 0, 0 }
    msg.sender_index = little_endian(initiator.sender_index)

    msg.unencrypted_ephemeral = DH_PUBKEY(initiator.ephemeral_private)
    initiator.hash = HASH(initiator.hash || msg.unencrypted_ephemeral)

    temp = HMAC(initiator.chaining_key, msg.unencrypted_ephemeral)
    initiator.chaining_key = HMAC(temp, 0x1)

    temp = HMAC(initiator.chaining_key, DH(initiator.ephemeral_private, responder.static_public))
    initiator.chaining_key = HMAC(temp, 0x1)
    key = HMAC(temp, initiator.chaining_key || 0x2)

    msg.encrypted_static = AEAD(key, 0, initiator.static_public, initiator.hash)
    initiator.hash = HASH(initiator.hash || msg.encrypted_static)

    temp = HMAC(initiator.chaining_key, DH(initiator.static_private, responder.static_public))
    initiator.chaining_key = HMAC(temp, 0x1)
    key = HMAC(temp, initiator.chaining_key || 0x2)

    msg.encrypted_timestamp = AEAD(key, 0, TAI64N(), initiator.hash)
    initiator.hash = HASH(initiator.hash || msg.encrypted_timestamp)

    msg.mac1 = MAC(HASH(LABEL_MAC1 || responder.static_public), msg[0:offsetof(msg.mac1)])
    if (initiator.last_received_cookie is empty or expired)
        msg.mac2 = [zeros]
    else
        msg.mac2 = MAC(initiator.last_received_cookie, msg[0:offsetof(msg.mac2)])
}