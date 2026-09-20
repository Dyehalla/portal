//! One established transport session: a pair of direction keys plus the
//! replay window for the receive direction.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use super::packet::{self, DataPacket, WireGuardError};
use super::primitives::{AeadKey, TAG_LEN};
use super::replay::ReplayWindow;

/// Largest plaintext a transport-data packet may carry: the UDP payload limit
/// minus the data header and the Poly1305 tag.
pub const MAX_TRANSPORT_PAYLOAD: usize = 65_535 - packet::DATA_HEADER_LEN - TAG_LEN;

/// Counters at or above this value must not be used; the session has to rekey.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;

/// Bytes a transport-data packet adds to the payload: the 16-byte header
/// (type+reserved, receiver index, counter) plus the Poly1305 tag.
pub const DATA_OVERHEAD: usize = packet::DATA_HEADER_LEN + TAG_LEN;

/// Failure of a single session operation. Kept separate from `TunnelResult` so
/// `Session` does not depend on the public result type; it is converted at the
/// `Tunnel` boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Sending counter exhausted (`REJECT_AFTER_MESSAGES`): rekey.
    RekeyRequired,
    /// The packet was refused, with the specific reason preserved: a failed tag
    /// check, a replayed counter, or a wrong receiver index all land here.
    Rejected(WireGuardError),
    /// The packet is too short to hold a tag, or longer than a datagram allows.
    Malformed,
}

impl From<WireGuardError> for SessionError {
    fn from(error: WireGuardError) -> Self {
        Self::Rejected(error)
    }
}

pub struct Session {
    pub(super) local_id: u32,
    pub(super) remote_index: u32,
    pub(super) sender: AeadKey,
    pub(super) receiver: AeadKey,
    pub(super) sending_counter: AtomicU64,
    pub(super) replay: Mutex<ReplayWindow>,
    pub(super) confirmed: AtomicBool,
    pub(super) created_at: Instant,
}

impl Session {
    /// Builds a session from a completed handshake. The initiator and responder
    /// pass `sending`/`receiving` in opposite order.
    pub fn new(
        local_id: u32,
        remote_index: u32,
        sending: &[u8; 32],
        receiving: &[u8; 32],
    ) -> Self {
        Self {
            local_id,
            remote_index,
            sender: AeadKey::new(sending),
            receiver: AeadKey::new(receiving),
            sending_counter: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::new()),
            confirmed: AtomicBool::new(false),
            created_at: Instant::now(),
        }
    }

    /// Encrypts `src` into a transport-data packet, writing it to `dst`, which
    /// must hold at least `src.len() + DATA_OVERHEAD` bytes.
    pub fn format_packet_data(
        &self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, SessionError> {
        let total = src.len() + DATA_OVERHEAD;

        let counter = self.sending_counter.fetch_add(1, Ordering::Relaxed);
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(SessionError::RekeyRequired);
        }

        let dst = &mut dst[..total];
        let (header, body) = dst.split_at_mut(packet::DATA_HEADER_LEN);
        header[0..4].copy_from_slice(&packet::MSG_DATA.to_le_bytes());
        header[4..8].copy_from_slice(&self.remote_index.to_le_bytes());
        header[8..16].copy_from_slice(&counter.to_le_bytes());

        // body is plaintext || TAG_LEN spare bytes for `seal_in_place`.
        body[..src.len()].copy_from_slice(src);
        self.sender.seal_in_place(counter, body);

        Ok(total)
    }

    /// Authenticates and decrypts a transport-data packet in place, returning
    /// the plaintext borrowed from the packet's own buffer.
    pub fn receive_packet_data<'a>(
        &self,
        packet: DataPacket<'a>,
    ) -> Result<&'a mut [u8], SessionError> {
        let ciphertext_len = packet.encrypted_payload.len();
        // A packet that is not for this session, or whose length cannot hold a
        // tag, is refused before any key work.
        if packet.receiver_index != self.local_id {
            return Err(SessionError::Rejected(WireGuardError::InvalidPacket));
        }
        if ciphertext_len < TAG_LEN || ciphertext_len - TAG_LEN > MAX_TRANSPORT_PAYLOAD {
            return Err(SessionError::Malformed);
        }

        let mut replay = self.replay.lock().expect("replay lock poisoned");
        // Cheap replay check before the expensive AEAD open (DoS defence).
        replay.will_accept(packet.counter)?;

        let DataPacket {
            receiver_index: _,
            counter,
            encrypted_payload,
        } = packet;

        let plaintext = self
            .receiver
            .open_in_place(counter, encrypted_payload)
            .map_err(|_| SessionError::Rejected(WireGuardError::InvalidPacket))?;

        // Commit the counter only after the tag verified.
        replay.mark_received(counter)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::packet::{Packet, PacketMut};

    /// Builds a session pair that can talk to each other: `local_id` of each is
    /// the `remote_index` of the other, and the keys are mirrored.
    fn peer_pair() -> (Session, Session) {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];

        let a = Session {
            local_id: 1,
            remote_index: 2,
            sender: AeadKey::new(&key_a),
            receiver: AeadKey::new(&key_b),
            sending_counter: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::new()),
            confirmed: AtomicBool::new(false),
            created_at: Instant::now(),
        };
        let b = Session {
            local_id: 2,
            remote_index: 1,
            sender: AeadKey::new(&key_b),
            receiver: AeadKey::new(&key_a),
            sending_counter: AtomicU64::new(0),
            replay: Mutex::new(ReplayWindow::new()),
            confirmed: AtomicBool::new(false),
            created_at: Instant::now(),
        };
        (a, b)
    }

    #[test]
    fn an_exhausted_sending_counter_requires_a_rekey() {
        let (sender, _receiver) = peer_pair();

        // Jump the counter to the limit so the next send must refuse.
        sender
            .sending_counter
            .store(REJECT_AFTER_MESSAGES, Ordering::Relaxed);

        let mut datagram = [0u8; 4 + DATA_OVERHEAD];
        assert_eq!(
            sender.format_packet_data(b"ping", &mut datagram),
            Err(SessionError::RekeyRequired)
        );
    }

    #[test]
    fn round_trip_decrypts_in_place_in_the_receive_buffer() {
        let (sender, receiver) = peer_pair();
        let payload = b"an IP packet from the tunnel interface";

        let mut datagram = vec![0u8; payload.len() + DATA_OVERHEAD];
        let n = sender.format_packet_data(payload, &mut datagram).unwrap();
        assert_eq!(n, payload.len() + DATA_OVERHEAD);
        let datagram_len = datagram.len();

        // Decrypt, then check the plaintext is a window into `datagram` itself:
        // its length tells us where in the buffer it starts, and the header is
        // exactly that many bytes.
        let (plaintext_len, plaintext_offset, header_type) = {
            let packet = match Packet::parse_mut(&mut datagram[..n]).unwrap() {
                PacketMut::Data(packet) => packet,
                other => panic!("expected a data packet, got {other:?}"),
            };
            let plaintext = receiver.receive_packet_data(packet).unwrap();
            assert_eq!(plaintext, payload);
            (
                plaintext.len(),
                datagram_len - plaintext.len(),
                u32::from_le_bytes(datagram[0..4].try_into().unwrap()),
            )
        };

        // No copy: the plaintext stays in the datagram, starting after the
        // 16-byte header plus the 16 tag bytes that `open_in_place` consumed.
        assert_eq!(plaintext_offset, DATA_OVERHEAD);
        assert_eq!(header_type, packet::MSG_DATA);
        assert_eq!(plaintext_len, payload.len());
    }

    #[test]
    fn replay_of_the_same_counter_is_rejected() {
        let (sender, receiver) = peer_pair();

        let mut datagram = vec![0u8; 4 + DATA_OVERHEAD];
        let n = sender.format_packet_data(b"ping", &mut datagram).unwrap();

        // First delivery succeeds.
        {
            let packet = match Packet::parse_mut(&mut datagram[..n]).unwrap() {
                PacketMut::Data(packet) => packet,
                other => panic!("expected a data packet, got {other:?}"),
            };
            assert!(receiver.receive_packet_data(packet).is_ok());
        }

        // Replaying the same counter must be reported as exactly that, not as a
        // generic rejection: it is what tells a caller apart from a forgery.
        let packet = match Packet::parse_mut(&mut datagram[..n]).unwrap() {
            PacketMut::Data(packet) => packet,
            other => panic!("expected a data packet, got {other:?}"),
        };
        assert_eq!(
            receiver.receive_packet_data(packet).unwrap_err(),
            SessionError::Rejected(WireGuardError::DuplicateCounter)
        );
    }

    #[test]
    fn packet_for_another_session_is_rejected() {
        let (sender, receiver) = peer_pair();
        let mut datagram = vec![0u8; 4 + DATA_OVERHEAD];
        let n = sender.format_packet_data(b"ping", &mut datagram).unwrap();

        // Rewrite the receiver index so it no longer matches `receiver`.
        datagram[4..8].copy_from_slice(&999u32.to_le_bytes());

        let packet = match Packet::parse_mut(&mut datagram[..n]).unwrap() {
            PacketMut::Data(packet) => packet,
            other => panic!("expected a data packet, got {other:?}"),
        };
        assert_eq!(
            receiver.receive_packet_data(packet).unwrap_err(),
            SessionError::Rejected(WireGuardError::InvalidPacket)
        );
    }

    #[test]
    fn a_forged_tag_is_rejected() {
        let (sender, receiver) = peer_pair();
        let mut datagram = vec![0u8; 4 + DATA_OVERHEAD];
        let n = sender.format_packet_data(b"ping", &mut datagram).unwrap();

        // Corrupt a ciphertext byte; the tag no longer verifies.
        datagram[packet::DATA_HEADER_LEN] ^= 0x01;

        let packet = match Packet::parse_mut(&mut datagram[..n]).unwrap() {
            PacketMut::Data(packet) => packet,
            other => panic!("expected a data packet, got {other:?}"),
        };
        assert_eq!(
            receiver.receive_packet_data(packet).unwrap_err(),
            SessionError::Rejected(WireGuardError::InvalidPacket)
        );
    }

    #[test]
    fn a_counter_below_the_window_is_too_old() {
        let (sender, receiver) = peer_pair();

        // Send and deliver a packet, then one far ahead to move the window past
        // the first counter, then replay the first.
        let mut older = vec![0u8; 4 + DATA_OVERHEAD];
        let n_older = sender.format_packet_data(b"old", &mut older).unwrap();

        let mut datagram = [0u8; 6 + DATA_OVERHEAD];
        for _ in 0..(crate::protocol::replay::WINDOW_BITS + 1) {
            let n = sender
                .format_packet_data(b"filler", &mut datagram)
                .unwrap();
            let packet = match Packet::parse_mut(&mut datagram[..n]).unwrap() {
                PacketMut::Data(packet) => packet,
                other => panic!("expected a data packet, got {other:?}"),
            };
            receiver.receive_packet_data(packet).unwrap();
        }

        let packet = match Packet::parse_mut(&mut older[..n_older]).unwrap() {
            PacketMut::Data(packet) => packet,
            other => panic!("expected a data packet, got {other:?}"),
        };
        assert_eq!(
            receiver.receive_packet_data(packet).unwrap_err(),
            SessionError::Rejected(WireGuardError::CounterTooOld)
        );
    }
}
