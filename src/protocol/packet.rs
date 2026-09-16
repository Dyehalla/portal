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
    InvalidPacket,
    UnknownMessageType,
    DuplicateCounter,
    CounterTooOld,
    CounterExhausted,
}

#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInitiation(HandshakeInitiation<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    CookieReply(CookieReply<'a>),
    Data(DataPacket<'a>),
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

#[derive(Debug)]
pub struct DataPacket<'a> {
    pub receiver_index: u32,
    pub counter: u64,
    pub encrypted_payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn parse(src: &'a [u8]) -> Result<Self, WireGuardError> {
        let packet_type = src
            .get(..4)
            .ok_or(WireGuardError::InvalidPacket)
            .and_then(|bytes| {
                Ok(u32::from_le_bytes(
                    bytes.try_into().expect("length checked"),
                ))
            })?;

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

    fn parse_data(src: &'a [u8]) -> Result<Self, WireGuardError> {
        if src.len() < DATA_MIN_LEN {
            return Err(WireGuardError::InvalidPacket);
        }

        Ok(Self::Data(DataPacket {
            receiver_index: u32::from_le_bytes(src[4..8].try_into().unwrap()),
            counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
            encrypted_payload: &src[16..],
        }))
    }
}
