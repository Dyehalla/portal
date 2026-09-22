use std::convert::TryInto;

pub const MSG_HANDSHAKE_INIT: u32 = 1;
pub const MSG_HANDSHAKE_RESPONSE: u32 = 2;
pub const MSG_COOKIE_REPLY: u32 = 3;
pub const MSG_DATA: u32 = 4;

pub const HANDSHAKE_INIT_LEN: usize = 148;
pub const HANDSHAKE_RESPONSE_LEN: usize = 92;
pub const COOKIE_REPLY_LEN: usize = 64;
pub const DATA_HEADER_LEN: usize = 16;
pub const TAG_LEN: usize = 16;
pub const DATA_MIN_LEN: usize = DATA_HEADER_LEN + TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireGuardError {
    /// The datagram could not be parsed: wrong length or a malformed header.
    InvalidPacket,
    /// The message type is not one of the four known values.
    UnknownMessageType,
    /// A transport-data packet was already received (replay).
    DuplicateCounter,
    /// A transport-data packet is outside the replay window (too old).
    CounterTooOld,
    /// The sending counter reached `REJECT_AFTER_MESSAGES`.
    CounterExhausted,
    /// A handshake did not authenticate: forged, corrupt, or for another peer.
    HandshakeNotAuthentic,
    /// The handshake could not be processed: a Diffie-Hellman step was refused,
    /// so no key can be agreed with this peer.
    HandshakeKeyAgreementFailed,
}

impl From<crate::protocol::handshake::HandshakeError> for WireGuardError {
    fn from(error: crate::protocol::handshake::HandshakeError) -> Self {
        use crate::protocol::handshake::HandshakeError;
        match error {
            HandshakeError::Dh(_) => Self::HandshakeKeyAgreementFailed,
            // Not an attack: we sent no initiation, or the peer answered a
            // different one. Reported plainly rather than as a forgery.
            HandshakeError::NoInitiationInFlight | HandshakeError::ResponseNotForUs => {
                Self::InvalidPacket
            }
            HandshakeError::InitiationNotAuthentic
            | HandshakeError::InitiationForAnotherPeer
            | HandshakeError::TimestampNotAuthentic
            | HandshakeError::ResponseNotAuthentic => Self::HandshakeNotAuthentic,
        }
    }
}

#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInitiation(HandshakeInitiation<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    CookieReply(CookieReply<'a>),
    Data(DataPacket<'a>),
}

/// A parsed packet whose data payload is borrowed mutably, so it can be
/// decrypted in place. See `Packet::parse_mut`.
#[derive(Debug)]
pub enum PacketMut<'a> {
    HandshakeInitiation(HandshakeInitiation<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    CookieReply(CookieReply<'a>),
    Data(DataPacket<'a>),
}

/// Reads and validates the 4-byte message type (type byte + 3 reserved zeros).
fn packet_type(src: &[u8]) -> Result<u32, WireGuardError> {
    let bytes = src.get(..4).ok_or(WireGuardError::InvalidPacket)?;
    Ok(u32::from_le_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

#[derive(Debug)]
pub struct HandshakeInitiation<'a> {
    pub sender_index: u32,
    pub ephemeral: &'a [u8; 32],
    pub encrypted_static: &'a [u8; 48],
    pub encrypted_timestamp: &'a [u8; 28],
    pub mac1: &'a [u8; 16],
    pub mac2: &'a [u8; 16],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub ephemeral: &'a [u8; 32],
    pub encrypted_nothing: &'a [u8; 16],
    pub mac1: &'a [u8; 16],
    pub mac2: &'a [u8; 16],
}

#[derive(Debug)]
pub struct CookieReply<'a> {
    pub receiver_index: u32,
    pub nonce: &'a [u8; 24],
    pub encrypted_cookie: &'a [u8; 32],
}

/// A transport-data packet. `encrypted_payload` is mutable because AEAD
/// decryption happens in place inside the receive buffer (zero-copy).
#[derive(Debug)]
pub struct DataPacket<'a> {
    pub receiver_index: u32,
    pub counter: u64,
    pub encrypted_payload: &'a mut [u8],
}

impl<'a> Packet<'a> {
    /// Parses a datagram the caller lets us modify in place: a data packet's
    /// ciphertext is decrypted in the receive buffer without copying.
    pub fn parse_mut(src: &'a mut [u8]) -> Result<PacketMut<'a>, WireGuardError> {
        let packet_type = packet_type(src)?;

        match packet_type {
            MSG_DATA => {
                if src.len() < DATA_MIN_LEN {
                    return Err(WireGuardError::InvalidPacket);
                }
                let receiver_index = u32::from_le_bytes(src[4..8].try_into().unwrap());
                let counter = u64::from_le_bytes(src[8..16].try_into().unwrap());
                // Carve the payload out in place; the header is left behind.
                let (_, encrypted_payload) = src.split_at_mut(DATA_HEADER_LEN);
                Ok(PacketMut::Data(DataPacket {
                    receiver_index,
                    counter,
                    encrypted_payload,
                }))
            }
            // Every other message type is parsed immutably.
            _ => Ok(match Packet::parse(src)? {
                Packet::HandshakeInitiation(packet) => PacketMut::HandshakeInitiation(packet),
                Packet::HandshakeResponse(packet) => PacketMut::HandshakeResponse(packet),
                Packet::CookieReply(packet) => PacketMut::CookieReply(packet),
                Packet::Data(_) => unreachable!("data handled above"),
            }),
        }
    }

    pub fn parse(src: &'a [u8]) -> Result<Self, WireGuardError> {
        let packet_type = packet_type(src)?;

        match packet_type {
            MSG_HANDSHAKE_INIT => Self::parse_handshake_initiation(src),
            MSG_HANDSHAKE_RESPONSE => Self::parse_handshake_response(src),
            MSG_COOKIE_REPLY => Self::parse_cookie_reply(src),
            MSG_DATA => Self::parse_data(src),
            _ => Err(WireGuardError::UnknownMessageType),
        }
    }

    fn parse_handshake_initiation(src: &'a [u8]) -> Result<Self, WireGuardError> {
        if src.len() != HANDSHAKE_INIT_LEN {
            return Err(WireGuardError::InvalidPacket);
        }

        Ok(Self::HandshakeInitiation(HandshakeInitiation {
            sender_index: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            ephemeral: src[8..40].try_into().unwrap(),
            encrypted_static: src[40..88].try_into().unwrap(),
            encrypted_timestamp: src[88..116].try_into().unwrap(),
            mac1: src[116..132].try_into().unwrap(),
            mac2: src[132..148].try_into().unwrap(),
        }))
    }

    fn parse_handshake_response(src: &'a [u8]) -> Result<Self, WireGuardError> {
        if src.len() != HANDSHAKE_RESPONSE_LEN {
            return Err(WireGuardError::InvalidPacket);
        }

        Ok(Self::HandshakeResponse(HandshakeResponse {
            sender_index: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            receiver_index: u32::from_le_bytes(src[8..12].try_into().unwrap()),
            ephemeral: src[12..44].try_into().unwrap(),
            encrypted_nothing: src[44..60].try_into().unwrap(),
            mac1: src[60..76].try_into().unwrap(),
            mac2: src[76..92].try_into().unwrap(),
        }))
    }

    fn parse_cookie_reply(src: &'a [u8]) -> Result<Self, WireGuardError> {
        if src.len() != COOKIE_REPLY_LEN {
            return Err(WireGuardError::InvalidPacket);
        }

        Ok(Self::CookieReply(CookieReply {
            receiver_index: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            nonce: src[8..32].try_into().unwrap(),
            encrypted_cookie: src[32..64].try_into().unwrap(),
        }))
    }

    /// Data packets need a mutable payload, so this immutable entry point
    /// rejects them: callers on the receive path use `parse_mut` instead.
    fn parse_data(_src: &'a [u8]) -> Result<Self, WireGuardError> {
        Err(WireGuardError::InvalidPacket)
    }
}
