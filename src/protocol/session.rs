//! One established transport session: a pair of direction keys plus the
//! replay window for the receive direction.

use std::ops::Range;
use std::time::{Duration, Instant};

use super::packet::{self, DataPacket, WireGuardError};
use super::primitives::{AeadKey, TAG_LEN};
use super::replay::ReplayWindow;

/// Largest plaintext a transport-data packet may carry: the UDP payload limit
/// minus the data header and the Poly1305 tag.
pub const MAX_TRANSPORT_PAYLOAD: usize = 65_535 - packet::DATA_HEADER_LEN - TAG_LEN;

/// Counters at or above this value must not be used; the session has to rekey.
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;

/// A session must not carry traffic older than this (§6.3 reject-after-timer);
/// both directions stop and a fresh handshake takes over.
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// Grace on the receive side: a data packet already in flight when the session
/// turned `REJECT_AFTER_TIME` old must not be dropped on arrival.
pub const REJECT_AFTER_TIME_SLACK: Duration = Duration::from_secs(5);

/// Bytes a transport-data packet adds to the payload: the 16-byte header
/// (type+reserved, receiver index, counter) plus the Poly1305 tag.
pub const DATA_OVERHEAD: usize = packet::DATA_HEADER_LEN + TAG_LEN;

/// Failure of one session operation, kept separate so `Session` does not
/// depend on `TunnelResult`; converted at the `Tunnel` boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    /// Sending counter exhausted (`REJECT_AFTER_MESSAGES`): rekey.
    RekeyRequired,
    /// The packet was refused, with the specific reason preserved: a failed tag
    /// check, a replayed counter, or a wrong receiver index all land here.
    Rejected(WireGuardError),
    /// The packet is too short to hold a tag, or longer than a datagram allows.
    Malformed,
    /// The output buffer cannot hold the packet.
    BufferTooSmall,
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
    pub(super) sending_counter: u64,
    pub(super) replay: ReplayWindow,
    pub(super) confirmed: bool,
    pub(super) created_at: Instant,
}

impl Session {
    /// Builds a session from a completed handshake. The initiator and responder
    /// pass `sending`/`receiving` in opposite order.
    pub fn new(local_id: u32, remote_index: u32, sending: &[u8; 32], receiving: &[u8; 32]) -> Self {
        Self {
            local_id,
            remote_index,
            sender: AeadKey::new(sending),
            receiver: AeadKey::new(receiving),
            sending_counter: 0,
            replay: ReplayWindow::new(),
            confirmed: false,
            created_at: Instant::now(),
        }
    }

    /// Encrypts `src` into a transport-data packet, writing it to `dst`, which
    /// must hold at least `src.len() + DATA_OVERHEAD` bytes. A payload bigger
    /// than [`MAX_TRANSPORT_PAYLOAD`] is refused as `Malformed`, a `dst` too
    /// small as `BufferTooSmall`: neither may panic.
    pub fn format_packet_data(
        &mut self,
        src: &[u8],
        dst: &mut [u8],
    ) -> Result<usize, SessionError> {
        let total = src.len() + DATA_OVERHEAD;
        if src.len() > MAX_TRANSPORT_PAYLOAD {
            return Err(SessionError::Malformed);
        }
        if dst.len() < total {
            return Err(SessionError::BufferTooSmall);
        }

        // Past the reject-after age the session must not send at all: the
        // counter is not even spent, so the caller is free to retry later.
        if self.is_expired(Instant::now()) {
            return Err(SessionError::RekeyRequired);
        }

        // Checked before the increment: a refused send must not burn a counter.
        let counter = self.sending_counter;
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(SessionError::RekeyRequired);
        }
        self.sending_counter = counter + 1;

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

    /// Encrypts a TUN packet in place in a buffer with headroom (§5.4.5).
    ///
    /// `payload_start` identifies the first plaintext byte. The caller reads
    /// the IP packet directly there; this method writes the WireGuard header
    /// into the preceding 16 bytes and the Poly1305 tag into trailing space.
    /// The returned range identifies the complete UDP payload in `buffer`.
    pub fn format_packet_data_in_place(
        &mut self,
        buffer: &mut [u8],
        payload_start: usize,
        payload_len: usize,
    ) -> Result<Range<usize>, SessionError> {
        if payload_len > MAX_TRANSPORT_PAYLOAD || payload_start < packet::DATA_HEADER_LEN {
            return Err(SessionError::Malformed);
        }
        let packet_start = payload_start - packet::DATA_HEADER_LEN;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or(SessionError::Malformed)?;
        let packet_end = payload_end
            .checked_add(TAG_LEN)
            .ok_or(SessionError::Malformed)?;
        if packet_end > buffer.len() {
            return Err(SessionError::BufferTooSmall);
        }

        if self.is_expired(Instant::now()) {
            return Err(SessionError::RekeyRequired);
        }
        let counter = self.sending_counter;
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(SessionError::RekeyRequired);
        }
        self.sending_counter = counter + 1;

        let header = &mut buffer[packet_start..payload_start];
        header[0..4].copy_from_slice(&packet::MSG_DATA.to_le_bytes());
        header[4..8].copy_from_slice(&self.remote_index.to_le_bytes());
        header[8..16].copy_from_slice(&counter.to_le_bytes());
        self.sender
            .seal_in_place(counter, &mut buffer[payload_start..packet_end]);
        Ok(packet_start..packet_end)
    }

    /// True once the session is too old to send on (§6.3).
    pub fn is_expired(&self, now: Instant) -> bool {
        now.checked_duration_since(self.created_at)
            .is_some_and(|age| age >= REJECT_AFTER_TIME)
    }

    /// True once even packets already in flight are too old to accept: the
    /// receive side lives exactly [`REJECT_AFTER_TIME_SLACK`] longer.
    fn is_expired_beyond_slack(&self, now: Instant) -> bool {
        now.checked_duration_since(self.created_at)
            .is_some_and(|age| age >= REJECT_AFTER_TIME + REJECT_AFTER_TIME_SLACK)
    }

    /// Authenticates and decrypts a transport-data packet in place, returning
    /// the plaintext borrowed from the packet's own buffer.
    pub fn receive_packet_data<'a>(
        &mut self,
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
        if self.is_expired_beyond_slack(Instant::now()) {
            return Err(SessionError::Rejected(WireGuardError::SessionExpired));
        }

        // Cheap replay check before the expensive AEAD open (DoS defence).
        self.replay.will_accept(packet.counter)?;

        let DataPacket {
            receiver_index: _,
            counter,
            encrypted_payload,
        } = packet;

        let plaintext = self
            .receiver
            .open_in_place(counter, encrypted_payload)
            .map_err(|_| SessionError::Rejected(WireGuardError::InvalidPacket))?;

        // Commit the counter only after the tag verified. Exclusive ownership
        // makes check-then-mark atomic without a lock.
        self.replay.mark_received(counter)?;

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
            sending_counter: 0,
            replay: ReplayWindow::new(),
            confirmed: false,
            created_at: Instant::now(),
        };
        let b = Session {
            local_id: 2,
            remote_index: 1,
            sender: AeadKey::new(&key_b),
            receiver: AeadKey::new(&key_a),
            sending_counter: 0,
            replay: ReplayWindow::new(),
            confirmed: false,
            created_at: Instant::now(),
        };
        (a, b)
    }

    #[test]
    fn an_exhausted_sending_counter_requires_a_rekey() {
        let (mut sender, _receiver) = peer_pair();

        // Jump the counter to the limit so the next send must refuse.
        sender.sending_counter = REJECT_AFTER_MESSAGES;

        let mut datagram = [0u8; 4 + DATA_OVERHEAD];
        assert_eq!(
            sender.format_packet_data(b"ping", &mut datagram),
            Err(SessionError::RekeyRequired)
        );
        // A refused send must not burn a counter: the gap would drift towards
        // wrapping the u64, which would hand out reused nonces after overflow.
        assert_eq!(sender.sending_counter, REJECT_AFTER_MESSAGES);
    }

    /// Neither a huge payload nor a short buffer may panic: both are errors.
    #[test]
    fn an_oversized_payload_is_refused_rather_than_panicking() {
        let (mut sender, _receiver) = peer_pair();
        let src = vec![0u8; MAX_TRANSPORT_PAYLOAD + 1];
        let mut datagram = vec![0u8; src.len() + DATA_OVERHEAD];

        assert_eq!(
            sender.format_packet_data(&src, &mut datagram),
            Err(SessionError::Malformed)
        );
    }

    #[test]
    fn a_short_output_buffer_is_refused_rather_than_panicking() {
        let (mut sender, _receiver) = peer_pair();
        let mut datagram = [0u8; DATA_OVERHEAD];

        assert_eq!(
            sender.format_packet_data(b"payload", &mut datagram),
            Err(SessionError::BufferTooSmall)
        );
    }

    /// A TUN payload can be framed and authenticated without moving its bytes.
    #[test]
    fn in_place_framing_round_trips_with_reserved_headroom() {
        let (mut sender, mut receiver) = peer_pair();
        let mut buffer = [0u8; 96];
        let payload_start = 16;
        buffer[payload_start..payload_start + 7].copy_from_slice(b"payload");

        let packet_range = sender
            .format_packet_data_in_place(&mut buffer, payload_start, 7)
            .unwrap();
        assert_eq!(packet_range, 0..39);
        let packet = match Packet::parse_mut(&mut buffer[packet_range]).unwrap() {
            PacketMut::Data(packet) => packet,
            other => panic!("expected data packet, got {other:?}"),
        };
        let plaintext = receiver.receive_packet_data(packet).unwrap();
        assert_eq!(plaintext, b"payload");
    }

    /// In-place framing rejects missing headroom or tag space without spending a nonce.
    #[test]
    fn in_place_framing_checks_bounds_before_advancing_the_counter() {
        let (mut sender, _receiver) = peer_pair();
        let mut buffer = [0u8; 20];
        assert_eq!(
            sender.format_packet_data_in_place(&mut buffer, 16, 7),
            Err(SessionError::BufferTooSmall)
        );
        assert_eq!(sender.sending_counter, 0);
        assert_eq!(
            sender.format_packet_data_in_place(&mut buffer, 8, 1),
            Err(SessionError::Malformed)
        );
        assert_eq!(sender.sending_counter, 0);
    }

    /// Past the reject-after age the session stops sending (§6.3).
    #[test]
    fn an_expired_session_refuses_to_send() {
        let (mut sender, _receiver) = peer_pair();
        let Some(past) = Instant::now().checked_sub(REJECT_AFTER_TIME) else {
            return; // the clock has not run long enough to backdate with
        };
        sender.created_at = past;

        let mut datagram = [0u8; 4 + DATA_OVERHEAD];
        assert_eq!(
            sender.format_packet_data(b"ping", &mut datagram),
            Err(SessionError::RekeyRequired)
        );
    }

    /// Within the slack a packet already in flight still decrypts.
    #[test]
    fn the_receive_side_keeps_the_slack_for_packets_in_flight() {
        let (mut sender, mut receiver) = peer_pair();
        let mut datagram = vec![0u8; 4 + DATA_OVERHEAD];
        let n = sender.format_packet_data(b"ping", &mut datagram).unwrap();

        let Some(aged) = Instant::now()
            .checked_sub(REJECT_AFTER_TIME + REJECT_AFTER_TIME_SLACK - Duration::from_secs(1))
        else {
            return;
        };
        receiver.created_at = aged;

        let packet = match Packet::parse_mut(&mut datagram[..n]).unwrap() {
            PacketMut::Data(packet) => packet,
            other => panic!("expected a data packet, got {other:?}"),
        };
        assert!(receiver.receive_packet_data(packet).is_ok());
    }

    /// Past the slack the session is dead in both directions.
    #[test]
    fn a_session_past_the_slack_refuses_to_receive() {
        let (mut sender, mut receiver) = peer_pair();
        let mut datagram = vec![0u8; 4 + DATA_OVERHEAD];
        let n = sender.format_packet_data(b"ping", &mut datagram).unwrap();

        let Some(expired) = Instant::now().checked_sub(REJECT_AFTER_TIME + REJECT_AFTER_TIME_SLACK)
        else {
            return;
        };
        receiver.created_at = expired;

        let packet = match Packet::parse_mut(&mut datagram[..n]).unwrap() {
            PacketMut::Data(packet) => packet,
            other => panic!("expected a data packet, got {other:?}"),
        };
        assert_eq!(
            receiver.receive_packet_data(packet).unwrap_err(),
            SessionError::Rejected(WireGuardError::SessionExpired)
        );
    }

    #[test]
    fn round_trip_decrypts_in_place_in_the_receive_buffer() {
        let (mut sender, mut receiver) = peer_pair();
        let payload = b"an IP packet from the tunnel interface";

        let mut datagram = vec![0u8; payload.len() + DATA_OVERHEAD];
        let n = sender.format_packet_data(payload, &mut datagram).unwrap();
        assert_eq!(n, payload.len() + DATA_OVERHEAD);
        let datagram_len = datagram.len();

        // Decrypt, then check the plaintext is a window into `datagram`: the
        // header is exactly the bytes the plaintext does not cover.
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
        let (mut sender, mut receiver) = peer_pair();

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
        let (mut sender, mut receiver) = peer_pair();
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
        let (mut sender, mut receiver) = peer_pair();
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
        let (mut sender, mut receiver) = peer_pair();

        // Send and deliver a packet, then one far ahead to move the window past
        // the first counter, then replay the first.
        let mut older = vec![0u8; 4 + DATA_OVERHEAD];
        let n_older = sender.format_packet_data(b"old", &mut older).unwrap();

        let mut datagram = [0u8; 6 + DATA_OVERHEAD];
        for _ in 0..(crate::protocol::replay::WINDOW_BITS + 1) {
            let n = sender.format_packet_data(b"filler", &mut datagram).unwrap();
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
