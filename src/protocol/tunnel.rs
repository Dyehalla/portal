//! The peer-facing half of the protocol engine: a thin dispatcher over
//! `handshake` and `session`, writing into caller-owned buffers.

use std::cell::Cell;
use std::collections::VecDeque;
use std::marker::PhantomData;
use std::time::{Duration, Instant};

use super::cookie;
use super::handshake;
use super::packet::{
    self, CookieReply, DataPacket, HandshakeInitiation, HandshakeResponse, Packet, PacketMut,
    WireGuardError,
};
use super::primitives::KEY_LEN;
use super::session::{DATA_OVERHEAD, MAX_TRANSPORT_PAYLOAD, Session, SessionError};

/// How many handshakes may be answered before the oldest session is dropped.
const MAX_QUEUE_DEPTH: usize = 256;

/// How long to wait for a handshake response before retransmitting (§6.1).
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);

/// What `update_timers` decided to do.
enum TimerAction {
    Nothing,
    /// Start or retransmit a handshake.
    Initiate,
    /// Send an empty packet to keep the session alive.
    Keepalive,
}

pub const MAX_PACKET_SIZE: usize = MAX_TRANSPORT_PAYLOAD + DATA_OVERHEAD;

/// How a tunnel obtains a receiver index. The device owns the routing table,
/// so only it can guarantee uniqueness; issuing reserves the index.
pub type IndexClaim<'f> = &'f mut dyn FnMut() -> Option<u32>;

/// Result of one protocol operation. `'d` is the received datagram, `'o` the
/// output buffer; only one is ever borrowed by a given value.
#[derive(Debug)]
pub enum TunnelResult<'d, 'o> {
    /// The call consumed the input and produced no outgoing packet. For
    /// `decapsulate` this also terminates the "drain queued packets" loop.
    Done,
    /// An encrypted WireGuard packet to send over UDP. Borrows `dst`.
    WriteToNetwork(&'o mut [u8]),
    /// Plaintext to write to the TUN device. Borrows `dst`.
    WriteToTunnel(&'o mut [u8]),
    /// Plaintext decrypted in place inside the received `datagram`.
    WriteToTunnelInPlace(&'d mut [u8]),
    /// The peer input was malformed, forged, or unusable. Carries the specific
    /// reason. Not a local failure: the caller normally just drops the datagram.
    InvalidPacket(WireGuardError),
    /// The sending counter is exhausted or the session is too old. The caller
    /// should start a fresh handshake.
    RekeyRequired,
    /// A handshake we sent awaits its response, so this call did nothing:
    /// resending would discard the initiation already in flight.
    HandshakeInProgress,
    /// No session is established yet, so the tunnel cannot carry this packet.
    /// The caller should wait for the handshake to finish.
    NoSession,
    /// The output buffer cannot hold the packet that would be produced.
    BufferTooSmall,
}

impl<'d, 'o> TunnelResult<'d, 'o> {
    /// Reborrows an outbound result so it no longer borrows its input buffer,
    /// which lets the device put the tunnel back in its map.
    pub fn into_outbound(self) -> TunnelResult<'o, 'o> {
        match self {
            Self::Done => TunnelResult::Done,
            Self::WriteToNetwork(dst) => TunnelResult::WriteToNetwork(dst),
            Self::WriteToTunnel(dst) => TunnelResult::WriteToTunnel(dst),
            Self::WriteToTunnelInPlace(_) => {
                TunnelResult::InvalidPacket(WireGuardError::InvalidPacket)
            }
            Self::InvalidPacket(error) => TunnelResult::InvalidPacket(error),
            Self::RekeyRequired => TunnelResult::RekeyRequired,
            Self::HandshakeInProgress => TunnelResult::HandshakeInProgress,
            Self::NoSession => TunnelResult::NoSession,
            Self::BufferTooSmall => TunnelResult::BufferTooSmall,
        }
    }
}

impl<'d, 'o> From<SessionError> for TunnelResult<'d, 'o> {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::RekeyRequired => Self::RekeyRequired,
            // The session's own reason is preserved all the way out.
            SessionError::Rejected(reason) => Self::InvalidPacket(reason),
            SessionError::Malformed => Self::InvalidPacket(WireGuardError::InvalidPacket),
            SessionError::BufferTooSmall => Self::BufferTooSmall,
        }
    }
}

/// The sessions a tunnel holds: carrying traffic, superseded, and negotiated.
/// The fixed count is what stops a flood of initiations growing memory.
#[derive(Default)]
struct Sessions {
    /// Superseded by `current`; kept only while its packets may still arrive.
    previous: Option<Session>,
    /// Carries outbound traffic and is what a rekey replaces.
    current: Option<Session>,
    /// Negotiated but not yet proved usable by traffic from the peer.
    next: Option<Session>,
}

impl Sessions {
    fn by_index(&self, index: u32) -> Option<&Session> {
        self.iter().find(|session| session.local_id == index)
    }

    fn by_index_mut(&mut self, index: u32) -> Option<&mut Session> {
        self.iter_mut().find(|session| session.local_id == index)
    }

    fn current(&self) -> Option<&Session> {
        self.current.as_ref()
    }

    fn current_mut(&mut self) -> Option<&mut Session> {
        self.current.as_mut()
    }

    fn iter(&self) -> impl Iterator<Item = &Session> {
        self.previous
            .iter()
            .chain(self.current.iter())
            .chain(self.next.iter())
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = &mut Session> {
        self.previous
            .iter_mut()
            .chain(self.current.iter_mut())
            .chain(self.next.iter_mut())
    }

    fn count(&self) -> usize {
        self.iter().count()
    }
}

/// A single-peer WireGuard transport tunnel. Owned exclusively by one thread:
/// no field is shared, so the protocol path needs no synchronization.
pub struct Tunnel {
    sessions: Sessions,
    handshake: handshake::Handshake,
    timers: Timers,
    packet_queue: VecDeque<Vec<u8>>,
    tx_bytes: u64,
    rx_bytes: u64,
    /// Encodes the single-thread owner invariant: movable, never shareable.
    _not_sync: PhantomData<Cell<()>>,
}

#[derive(Default)]
struct Timers {
    last_handshake: Option<Instant>,
    last_packet_received: Option<Instant>,
    last_packet_sent: Option<Instant>,
    persistent_keepalive: Option<Duration>,
}

impl Tunnel {
    pub fn new(
        static_private: [u8; KEY_LEN],
        peer_static_public: [u8; KEY_LEN],
        preshared_key: Option<[u8; KEY_LEN]>,
        persistent_keepalive: Option<Duration>,
    ) -> Self {
        Self {
            sessions: Sessions::default(),
            handshake: handshake::Handshake::new(static_private, peer_static_public, preshared_key),
            timers: Timers {
                persistent_keepalive,
                ..Timers::default()
            },
            packet_queue: VecDeque::new(),
            tx_bytes: 0,
            rx_bytes: 0,
            _not_sync: PhantomData,
        }
    }

    /// Encrypts one IP packet into `dst`; without a session this writes an
    /// initiation and queues the packet. `claim` is used only then.
    pub fn encapsulate<'a>(
        &mut self,
        src: &[u8],
        dst: &'a mut [u8],
        claim: IndexClaim<'_>,
    ) -> TunnelResult<'_, 'a> {
        if let Some(session) = self.current_session_mut() {
            match session.format_packet_data(src, dst) {
                Ok(written) => {
                    self.timers.last_packet_sent = Some(Instant::now());

                    // `written` is the whole datagram, header and tag included:
                    // the counter reports bytes on the wire, not payload (§6.6).
                    self.tx_bytes += written as u64;
                    return TunnelResult::WriteToNetwork(&mut dst[..written]);
                }
                // Expired or exhausted: the packet is held, not lost, and the
                // caller starts the fresh handshake `RekeyRequired` asks for.
                Err(SessionError::RekeyRequired) => {
                    self.queue_packet(src);
                    return TunnelResult::RekeyRequired;
                }
                Err(error) => return error.into(),
            }
        }

        // No session yet: hold the packet for when the handshake completes,
        // then (re)start the handshake.
        self.queue_packet(src);
        self.format_handshake_initiation(dst, claim, false)
    }

    /// Encrypts a TUN packet already placed in a buffer with 16 bytes of
    /// headroom (§5.4.5), avoiding the plaintext copy used by [`Self::encapsulate`].
    pub fn encapsulate_in_place<'a>(
        &mut self,
        buffer: &'a mut [u8],
        payload_start: usize,
        payload_len: usize,
        claim: IndexClaim<'_>,
    ) -> TunnelResult<'a, 'a> {
        let Some(payload_end) = payload_start.checked_add(payload_len) else {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };
        if payload_start < packet::DATA_HEADER_LEN
            || payload_len > MAX_TRANSPORT_PAYLOAD
            || payload_end > buffer.len()
        {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        }

        if let Some(session) = self.current_session_mut() {
            match session.format_packet_data_in_place(buffer, payload_start, payload_len) {
                Ok(packet_range) => {
                    self.timers.last_packet_sent = Some(Instant::now());
                    self.tx_bytes += packet_range.len() as u64;
                    return TunnelResult::WriteToNetwork(&mut buffer[packet_range]);
                }
                Err(SessionError::RekeyRequired) => {
                    self.queue_packet(&buffer[payload_start..payload_end]);
                    return TunnelResult::RekeyRequired;
                }
                Err(error) => return error.into(),
            }
        }

        // Until the first session exists, the plaintext must survive the
        // handshake. Queue it before reusing the slot for the initiation.
        self.queue_packet(&buffer[payload_start..payload_end]);
        self.format_handshake_initiation(buffer, claim, false)
            .into_outbound()
    }

    /// Encrypts one already-buffered TUN packet without copying or retaining it
    /// inside `Tunnel`; an inline worker keeps the buffer handle on `NoSession`.
    pub fn try_encapsulate_in_place<'a>(
        &mut self,
        buffer: &'a mut [u8],
        payload_start: usize,
        payload_len: usize,
    ) -> TunnelResult<'a, 'a> {
        let Some(payload_end) = payload_start.checked_add(payload_len) else {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };
        if payload_start < packet::DATA_HEADER_LEN
            || payload_len > MAX_TRANSPORT_PAYLOAD
            || payload_end > buffer.len()
        {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        }
        let Some(session) = self.current_session_mut() else {
            return TunnelResult::NoSession;
        };
        match session.format_packet_data_in_place(buffer, payload_start, payload_len) {
            Ok(packet_range) => {
                self.timers.last_packet_sent = Some(Instant::now());
                self.tx_bytes += packet_range.len() as u64;
                TunnelResult::WriteToNetwork(&mut buffer[packet_range])
            }
            Err(error) => error.into(),
        }
    }

    /// Builds handshake initiation into `dst`. A retransmission keeps the index
    /// already claimed; a fresh handshake asks the device for one.
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        claim: IndexClaim<'_>,
        force_resend: bool,
    ) -> TunnelResult<'_, 'a> {
        if self.handshake.has_pending_response() && !force_resend {
            return TunnelResult::HandshakeInProgress;
        }

        // A retransmit reuses the claim: the peer may already have answered
        // the first attempt, addressed to that very index.
        let local_index = match self.handshake.pending_index() {
            Some(existing) if force_resend => existing,
            _ => match claim() {
                Some(index) => index,
                // Every 32-bit value is taken: nothing sane is left to do.
                None => return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket),
            },
        };

        let Some(message) = dst.get_mut(..packet::HANDSHAKE_INIT_LEN) else {
            return TunnelResult::BufferTooSmall;
        };
        if let Err(error) = self.handshake.format_handshake_init(message, local_index) {
            return TunnelResult::InvalidPacket(error.into());
        }

        let now = Instant::now();
        self.timers.last_handshake = Some(now);
        self.timers.last_packet_sent = Some(now);

        TunnelResult::WriteToNetwork(message)
    }

    /// Stores a packet until a session can carry it.
    fn queue_packet(&mut self, src: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            self.packet_queue.push_back(src.to_vec());
        }
    }

    /// Sends the oldest held packet. Call until it stops returning
    /// `WriteToNetwork`: `Done` is empty, `NoSession` means it went back.
    pub fn send_queued_packet<'d, 'a>(&mut self, dst: &'a mut [u8]) -> TunnelResult<'d, 'a> {
        let Some(src) = self.packet_queue.pop_front() else {
            return TunnelResult::Done;
        };

        if let Some(session) = self.current_session_mut() {
            match session.format_packet_data(&src, dst) {
                Ok(written) => {
                    self.tx_bytes += written as u64;
                    return TunnelResult::WriteToNetwork(&mut dst[..written]);
                }
                Err(error) => {
                    // Like the no-session case, the packet keeps its place at
                    // the front instead of being dropped.
                    self.packet_queue.push_front(src);
                    return error.into();
                }
            }
        }

        // The session vanished between the pop and here: put the packet back
        // so it keeps its place. It just vacated a slot, so no depth check.
        self.packet_queue.push_front(src);
        TunnelResult::NoSession
    }

    /// Test hook: queues a packet as if `encapsulate` had held it.
    #[cfg(test)]
    pub(super) fn queue_for_tests(&mut self, src: &[u8]) {
        self.queue_packet(src);
    }

    /// Test hook: the payloads the queue currently holds, oldest first.
    #[cfg(test)]
    pub(super) fn queued_for_tests(&self) -> Vec<Vec<u8>> {
        self.packet_queue.iter().cloned().collect()
    }

    /// Parses one incoming datagram. `datagram` is `&mut` because a data packet
    /// is decrypted in place there; an empty one drains the queued backlog.
    pub fn decapsulate<'a, 'o>(
        &mut self,
        datagram: &'a mut [u8],
        dst: &'o mut [u8],
        claim: IndexClaim<'_>,
    ) -> TunnelResult<'a, 'o> {
        // An empty datagram is inert input, not a command: draining the queue
        // is `send_queued_packet`, which the caller drives in its own loop.
        if datagram.is_empty() {
            return TunnelResult::Done;
        }

        // mac1/mac2 are verified by the device before it looks the peer up,
        // so a cookie reply never reaches this far.
        match Packet::parse_mut(datagram) {
            Ok(PacketMut::Data(packet)) => self.handle_data(packet),
            Ok(PacketMut::HandshakeInitiation(packet)) => {
                self.handle_handshake_init(packet, dst, claim)
            }
            Ok(PacketMut::HandshakeResponse(packet)) => self.handle_handshake_response(packet, dst),
            Ok(PacketMut::CookieReply(packet)) => self.handle_cookie_reply(packet),
            Err(error) => TunnelResult::InvalidPacket(error),
        }
    }

    /// Decrypts a transport-data packet in place; the plaintext borrows the
    /// datagram, not `dst`. The session comes from the packet's own index.
    fn handle_data<'a, 'o>(&mut self, packet: DataPacket<'a>) -> TunnelResult<'a, 'o> {
        // Capture the on-wire size before decrypting: `open_in_place` leaves
        // only the plaintext, and the header is carved off by `parse_mut`.
        let wire_len = packet.encrypted_payload.len() + packet::DATA_HEADER_LEN;

        // Lookup before any key work, so an index nobody holds costs no AEAD.
        let receiver_index = packet.receiver_index;
        let Some(session) = self.sessions.by_index_mut(receiver_index) else {
            return TunnelResult::NoSession;
        };

        // The payload is decrypted in place inside the received datagram
        let plaintext = match session.receive_packet_data(packet) {
            Ok(plaintext) => plaintext,
            Err(error) => return error.into(),
        };

        // Authenticated traffic is what proves a negotiated session usable, so
        // only here does it displace the one in use.
        self.confirm_session(receiver_index);
        self.timers.last_packet_received = Some(Instant::now());

        self.rx_bytes += wire_len as u64;
        TunnelResult::WriteToTunnelInPlace(plaintext)
    }

    /// Answers a handshake initiation.
    fn handle_handshake_init<'d, 'a>(
        &mut self,
        initiation: HandshakeInitiation<'_>,
        dst: &'a mut [u8],
        claim: IndexClaim<'_>,
    ) -> TunnelResult<'d, 'a> {
        let Some(response) = dst.get_mut(..packet::HANDSHAKE_RESPONSE_LEN) else {
            return TunnelResult::BufferTooSmall;
        };

        let Some(local_index) = claim() else {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };

        // Any failure means the initiation is not authentic, is for another
        // peer, is a replay, or its keys cannot be agreed with ours; we stay
        // silent. The index just claimed is reclaimed by the device.
        let session =
            match self
                .handshake
                .format_handshake_response(response, &initiation, local_index)
            {
                Ok(session) => session,
                Err(error) => return TunnelResult::InvalidPacket(error.into()),
            };

        // Filed as pending: the peer's first authenticated packet proves it.
        self.install_session(session, false);

        let now = Instant::now();
        self.timers.last_packet_received = Some(now);
        self.timers.last_packet_sent = Some(now);

        TunnelResult::WriteToNetwork(response)
    }

    /// Consumes a response, activates the session and confirms with a keepalive.
    fn handle_handshake_response<'d, 'a>(
        &mut self,
        response: HandshakeResponse<'_>,
        dst: &'a mut [u8],
    ) -> TunnelResult<'d, 'a> {
        let mut session = match self.handshake.consume_response(&response) {
            Ok(session) => session,
            Err(error) => return TunnelResult::InvalidPacket(error.into()),
        };

        // The initiator proves liveness with a keepalive, which also tells the
        // responder the session is usable.
        let written = match session.format_packet_data(&[], dst) {
            Ok(written) => written,
            Err(error) => return error.into(),
        };

        // The keepalive just built proves the session works, so use it now.
        self.install_session(session, true);

        let now = Instant::now();
        self.timers.last_packet_received = Some(now);
        self.timers.last_packet_sent = Some(now);
        self.timers.last_handshake = Some(now);

        TunnelResult::WriteToNetwork(&mut dst[..written])
    }

    /// Stores the cookie from a cookie reply for use in `mac2` (§5.4.4/§5.4.7).
    /// Unwrapping with the answered initiation's `mac1` binds it to that handshake.
    fn handle_cookie_reply<'d, 'o>(&mut self, reply: CookieReply<'_>) -> TunnelResult<'d, 'o> {
        let now = Instant::now();
        let peer_static_public = self.handshake.peer_static_public;

        let (Some(our_index), Some(our_mac1)) = (
            self.handshake.pending_index(),
            self.handshake.last_sent_mac1().copied(),
        ) else {
            // Nothing in flight: this answers a handshake we already abandoned.
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };

        match cookie::open_cookie_reply(&peer_static_public, &reply, our_index, &our_mac1) {
            Ok(cookie) => {
                self.handshake.store_cookie(cookie, now);
                TunnelResult::Done
            }
            Err(error) => TunnelResult::InvalidPacket(error),
        }
    }

    /// Acts on whatever came due: retransmit a stalled handshake, start a new
    /// one, or send a keepalive. `dst` follows the `encapsulate` contract.
    pub fn update_timers<'a>(
        &mut self,
        now: Instant,
        dst: &'a mut [u8],
        claim: IndexClaim<'_>,
    ) -> TunnelResult<'_, 'a> {
        let decision = if self.handshake.has_pending_response() {
            // An initiation is in flight: retransmit once the timeout passes.
            let elapsed = self
                .timers
                .last_handshake
                .and_then(|started| now.checked_duration_since(started));
            if elapsed.is_some_and(|age| age >= REKEY_TIMEOUT) {
                TimerAction::Initiate
            } else {
                TimerAction::Nothing
            }
        } else {
            self.session_timer_action(now)
        };

        match decision {
            TimerAction::Nothing => TunnelResult::Done,
            TimerAction::Initiate => self.format_handshake_initiation(dst, claim, true),
            TimerAction::Keepalive => self.encapsulate(&[], dst, claim),
        }
    }

    /// Decides what an established (or absent) session requires. Split out
    /// because the timer path and the tests want the same reasoning.
    fn session_timer_action(&self, now: Instant) -> TimerAction {
        let Some(session) = self.current_session() else {
            // Nothing to keep alive, and no session to replace: `encapsulate`
            // will start a handshake when there is actually a packet to send.
            return TimerAction::Nothing;
        };

        // Past the hard limit the session must not carry more traffic.
        if session.is_expired(now) {
            return TimerAction::Initiate;
        }

        let Some(interval) = self.timers.persistent_keepalive else {
            return TimerAction::Nothing;
        };
        let last_activity = self
            .timers
            .last_packet_sent
            .max(self.timers.last_packet_received);
        let idle = !last_activity.is_some_and(|last| {
            now.checked_duration_since(last)
                .is_none_or(|age| age < interval)
        });

        if idle {
            TimerAction::Keepalive
        } else {
            TimerAction::Nothing
        }
    }

    /// Files a session, returning its index. As *responder* it waits in `next`
    /// until traffic proves it; as *initiator* the keepalive already did.
    fn install_session(&mut self, session: Session, usable: bool) -> u32 {
        let index = session.local_id;

        // A retransmission of a handshake already answered refreshes in place.
        if let Some(existing) = self.sessions.by_index_mut(index) {
            *existing = session;
            return index;
        }

        if usable {
            // The session we supersede becomes `previous`; the one before it
            // is past helping and goes.
            self.sessions.previous = self.sessions.current.replace(session);
            return index;
        }

        self.sessions.next = Some(session);
        index
    }

    /// Promotes the negotiated session once the peer sends traffic on it: the
    /// only moment `current` changes, so initiations cannot disturb it.
    fn confirm_session(&mut self, index: u32) -> bool {
        let Some(next) = self.sessions.next.as_ref() else {
            return false;
        };
        if next.local_id != index {
            return false;
        }

        let mut confirmed = self.sessions.next.take().expect("checked above");
        confirmed.confirmed = true;
        // The session being replaced is still needed for packets in flight.
        self.sessions.previous = self.sessions.current.replace(confirmed);
        true
    }

    /// The position of the session filed under `index`, if any.
    pub fn slot_of(&self, index: u32) -> Option<usize> {
        self.sessions
            .iter()
            .position(|session| session.local_id == index)
    }

    /// Number of sessions held, at most three.
    pub fn session_count(&self) -> usize {
        self.sessions.count()
    }

    /// The index a handshake in flight has claimed, if any. It is routable
    /// before its session exists, because the response names it.
    pub fn pending_index(&self) -> Option<u32> {
        self.handshake.pending_index()
    }

    /// Receiver indices still held by this tunnel, including a handshake in
    /// flight. The worker uses this list to reclaim stale device-wide claims.
    pub fn live_indices(&self) -> Vec<u32> {
        let mut indices = self
            .sessions
            .iter()
            .map(|session| session.local_id)
            .collect::<Vec<_>>();
        if let Some(pending) = self.pending_index() {
            if !indices.contains(&pending) {
                indices.push(pending);
            }
        }
        indices
    }

    /// Test hook: the session a receiver index resolves to, if any.
    #[cfg(test)]
    pub(super) fn session_for_tests(&self, receiver_index: u32) -> Option<&Session> {
        self.sessions.by_index(receiver_index)
    }

    /// The session outbound traffic uses. `current` is set only next to the
    /// slot it names, so a stale pointer is a bug; `None` beats a panic here.
    fn current_session_mut(&mut self) -> Option<&mut Session> {
        self.sessions.current_mut()
    }

    /// The session outbound traffic currently uses.
    pub(super) fn current_session(&self) -> Option<&Session> {
        self.sessions.current()
    }

    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes
    }

    /// Number of plaintext packets held until a usable session can carry them.
    pub fn queued_packet_count(&self) -> usize {
        self.packet_queue.len()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocol::primitives::{DH_PRIVATE, DH_PUBKEY};
    use crate::protocol::session::REJECT_AFTER_TIME;

    /// Two peers with matching static keys and mirrored indexes.
    pub(super) fn pair() -> (Tunnel, Tunnel) {
        let a_private = [0x11u8; 32];
        let b_private = [0x22u8; 32];
        let a_public = DH_PUBKEY(&DH_PRIVATE(&a_private));
        let b_public = DH_PUBKEY(&DH_PRIVATE(&b_private));

        let a = Tunnel::new(a_private, b_public, None, None);
        let b = Tunnel::new(b_private, a_public, None, None);
        (a, b)
    }

    /// Stands in for the device's allocator: the device is the sole issuer, so
    /// the counter is shared and never repeats a value.
    pub(crate) fn claimer() -> impl FnMut() -> Option<u32> {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0x4000_0003);

        // One process-wide counter, so no two draws anywhere are equal: the
        // device is a single issuer and never repeats an index.
        move || Some(NEXT.fetch_add(1, Ordering::Relaxed))
    }

    fn dst() -> Vec<u8> {
        vec![0u8; MAX_PACKET_SIZE]
    }

    /// Runs a full handshake between two peers. `a` and `b` stand for two
    /// devices, so each issues its own indices and their slots stay unrelated.
    pub(super) fn handshake(a: &mut Tunnel, b: &mut Tunnel) {
        let mut a_claim = claimer();
        let mut b_claim = claimer();
        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut init = match a.encapsulate(b"hi", &mut a_buf, &mut a_claim) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected initiation, got {other:?}"),
        };

        let mut response = match b.decapsulate(&mut init, &mut b_buf, &mut b_claim) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected response, got {other:?}"),
        };

        let mut keepalive = match a.decapsulate(&mut response, &mut a_buf, &mut a_claim) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected keepalive, got {other:?}"),
        };

        match b.decapsulate(&mut keepalive, &mut b_buf, &mut b_claim) {
            TunnelResult::WriteToTunnelInPlace(payload) => assert!(payload.is_empty()),
            other => panic!("expected empty keepalive payload, got {other:?}"),
        }
    }

    /// Runs a rekey between peers that already have a session. Unlike
    /// [`handshake`] it cannot start from `encapsulate`, which writes data.
    pub(super) fn exchange_handshake(a: &mut Tunnel, b: &mut Tunnel) {
        let mut a_claim = claimer();
        let mut b_claim = claimer();
        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut init = match a.format_handshake_initiation(&mut a_buf, &mut a_claim, false) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a rekey initiation, got {other:?}"),
        };

        let mut response = match b.decapsulate(&mut init, &mut b_buf, &mut b_claim) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a rekey response, got {other:?}"),
        };

        let mut keepalive = match a.decapsulate(&mut response, &mut a_buf, &mut a_claim) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a rekey keepalive, got {other:?}"),
        };

        match b.decapsulate(&mut keepalive, &mut b_buf, &mut b_claim) {
            TunnelResult::WriteToTunnelInPlace(payload) => assert!(payload.is_empty()),
            other => panic!("expected an empty rekey keepalive, got {other:?}"),
        }
    }

    #[test]
    fn handshake_establishes_a_working_session() {
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b);

        let mut a_buf = dst();
        let mut b_buf = dst();
        let mut packet = match a.encapsulate(b"an IP packet", &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };

        match b.decapsulate(&mut packet, &mut b_buf, &mut claimer()) {
            TunnelResult::WriteToTunnelInPlace(payload) => {
                assert_eq!(payload, b"an IP packet");
            }
            other => panic!("expected plaintext, got {other:?}"),
        }
    }

    #[test]
    fn a_session_carries_traffic_in_both_directions() {
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b);

        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut from_a = match a.encapsulate(b"ping", &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };
        assert!(matches!(
            b.decapsulate(&mut from_a, &mut b_buf, &mut claimer()),
            TunnelResult::WriteToTunnelInPlace(_)
        ));

        let mut from_b = match b.encapsulate(b"pong", &mut b_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };
        match a.decapsulate(&mut from_b, &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToTunnelInPlace(payload) => assert_eq!(payload, b"pong"),
            other => panic!("expected plaintext, got {other:?}"),
        }
    }

    #[test]
    fn a_forged_response_is_rejected() {
        let (mut a, mut b) = pair();
        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut init = match a.encapsulate(b"hi", &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected initiation, got {other:?}"),
        };
        let mut response = match b.decapsulate(&mut init, &mut b_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected response, got {other:?}"),
        };

        response[44] ^= 0x01;
        assert!(matches!(
            a.decapsulate(&mut response, &mut a_buf, &mut claimer()),
            TunnelResult::InvalidPacket(WireGuardError::HandshakeNotAuthentic)
        ));
    }

    #[test]
    fn a_response_without_a_pending_initiation_is_rejected() {
        let (mut a, mut b) = pair();
        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut init = match a.encapsulate(b"hi", &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected initiation, got {other:?}"),
        };
        let mut response = match b.decapsulate(&mut init, &mut b_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected response, got {other:?}"),
        };

        assert!(matches!(
            a.decapsulate(&mut response, &mut a_buf, &mut claimer()),
            TunnelResult::WriteToNetwork(_)
        ));
        assert!(matches!(
            a.decapsulate(&mut response, &mut a_buf, &mut claimer()),
            TunnelResult::InvalidPacket(_)
        ));
    }

    #[test]
    fn encapsulate_writes_a_handshake_initiation() {
        let mut buf = dst();
        let (mut a, _b) = pair();

        match a.encapsulate(b"hello", &mut buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => {
                assert_eq!(packet.len(), packet::HANDSHAKE_INIT_LEN);
            }
            other => panic!("unexpected result: {other:?}"),
        }
        assert_eq!(a.tx_bytes(), 0);
    }

    #[test]
    fn a_second_encapsulate_while_a_handshake_is_in_flight_is_not_a_rekey() {
        // Nothing to do: the initiation we already sent is still in flight, and
        // resending would discard it.
        let mut buf = dst();
        let (mut a, _b) = pair();

        assert!(matches!(
            a.encapsulate(b"hello", &mut buf, &mut claimer()),
            TunnelResult::WriteToNetwork(_)
        ));
        assert!(matches!(
            a.encapsulate(b"second", &mut buf, &mut claimer()),
            TunnelResult::HandshakeInProgress
        ));
    }

    #[test]
    fn empty_datagram_drains_the_queue() {
        let mut buf = dst();
        let (mut a, _b) = pair();

        assert!(matches!(
            a.encapsulate(b"hello", &mut buf, &mut claimer()),
            TunnelResult::WriteToNetwork(_)
        ));
        // Without a session the held packet cannot go out, and draining is a
        // call of its own rather than a side effect of an empty datagram.
        assert!(matches!(
            a.send_queued_packet(&mut buf),
            TunnelResult::NoSession
        ));

        let mut empty: [u8; 0] = [];
        assert!(
            matches!(
                a.decapsulate(&mut empty, &mut buf, &mut claimer()),
                TunnelResult::Done
            ),
            "an empty datagram must not be read as a drain request"
        );
    }

    /// Draining releases what was held, in the order it was queued, and then
    /// reports the queue empty.
    #[test]
    fn draining_sends_the_held_packets_in_order() {
        let (mut a, mut b) = pair();

        // Two packets with no session: both are held, and the first call
        // starts a handshake. The second is refused while one is in flight.
        let mut a_buf = dst();
        let mut b_buf = dst();
        let mut init = match a.encapsulate(b"first", &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };
        assert!(matches!(
            a.encapsulate(b"second", &mut a_buf, &mut claimer()),
            TunnelResult::HandshakeInProgress
        ));

        // Complete the handshake before draining.
        let mut response = match b.decapsulate(&mut init, &mut b_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a response, got {other:?}"),
        };
        let mut keepalive = match a.decapsulate(&mut response, &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a keepalive, got {other:?}"),
        };
        assert!(matches!(
            b.decapsulate(&mut keepalive, &mut b_buf, &mut claimer()),
            TunnelResult::WriteToTunnelInPlace(_)
        ));

        for expected in [&b"first"[..], &b"second"[..]] {
            let mut sent = match a.send_queued_packet(&mut a_buf) {
                TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected a queued packet, got {other:?}"),
            };
            match b.decapsulate(&mut sent, &mut b_buf, &mut claimer()) {
                TunnelResult::WriteToTunnelInPlace(plaintext) => {
                    assert_eq!(plaintext, expected);
                }
                other => panic!("expected plaintext, got {other:?}"),
            }
        }
        assert!(matches!(
            a.send_queued_packet(&mut a_buf),
            TunnelResult::Done
        ));
    }

    #[test]
    fn garbage_datagram_is_invalid() {
        let mut buf = dst();
        let (mut b, _a) = pair();
        let mut garbage = *b"not-a-packet";
        assert!(matches!(
            b.decapsulate(&mut garbage, &mut buf, &mut claimer()),
            TunnelResult::InvalidPacket(WireGuardError::UnknownMessageType)
        ));
    }
    /// A packet that cannot be sent because the session vanished goes back to
    /// the *front*: it keeps the place it had, so ordering survives the retry.
    #[test]
    fn a_packet_that_cannot_be_sent_keeps_its_place_in_the_queue() {
        let mut buf = dst();
        let (mut a, _b) = pair();

        // Queue three packets with no session at all.
        a.queue_for_tests(b"first");
        a.queue_for_tests(b"second");
        a.queue_for_tests(b"third");
        assert_eq!(
            a.queued_for_tests(),
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );

        // No session: the send is refused, and the packet must return to the
        // front rather than being dropped or appended.
        assert!(matches!(
            a.send_queued_packet(&mut buf),
            TunnelResult::NoSession
        ));
        assert_eq!(
            a.queued_for_tests(),
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()],
            "the refused packet must keep its place at the front"
        );

        // Repeated refusals stay idempotent: nothing is consumed or reordered.
        for _ in 0..3 {
            assert!(matches!(
                a.send_queued_packet(&mut buf),
                TunnelResult::NoSession
            ));
        }
        assert_eq!(
            a.queued_for_tests(),
            vec![b"first".to_vec(), b"second".to_vec(), b"third".to_vec()]
        );
    }

    /// A packet the sending session refuses (expired or exhausted) is held for
    /// the next session rather than lost: `RekeyRequired` must cost nothing.
    #[test]
    fn a_packet_the_session_refuses_is_held_not_dropped() {
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b);

        // Backdate A's sending session past the reject-after age.
        let Some(past) = Instant::now().checked_sub(REJECT_AFTER_TIME) else {
            return; // the clock has not run long enough to backdate with
        };
        a.sessions
            .current
            .as_mut()
            .expect("the handshake installed a session")
            .created_at = past;

        // `handshake()` leaves its own `b"hi"` held behind us.
        let before = a.queued_for_tests().len();

        let mut buf = dst();
        assert!(matches!(
            a.encapsulate(b"held", &mut buf, &mut claimer()),
            TunnelResult::RekeyRequired
        ));
        let queued = a.queued_for_tests();
        assert_eq!(queued.len(), before + 1);
        assert_eq!(
            queued.last(),
            Some(&b"held".to_vec()),
            "the refused packet must be held for the next session"
        );
    }

    #[test]
    fn short_datagrams_do_not_panic() {
        let mut buf = dst();
        let (mut b, _a) = pair();

        for len in 0..40usize {
            let mut datagram = vec![0u8; len];
            // Claim to be an initiation so the mac path is attempted too.
            if len >= 4 {
                datagram[..4].copy_from_slice(&packet::MSG_HANDSHAKE_INIT.to_le_bytes());
            }
            let result = b.decapsulate(&mut datagram, &mut buf, &mut claimer());
            let _ = format!("{result:?}");
        }

        // A well-formed header with a truncated body is likewise refused.
        let mut datagram = vec![0u8; packet::HANDSHAKE_INIT_LEN - 1];
        datagram[..4].copy_from_slice(&packet::MSG_HANDSHAKE_INIT.to_le_bytes());
        assert!(matches!(
            b.decapsulate(&mut datagram, &mut buf, &mut claimer()),
            TunnelResult::InvalidPacket(_)
        ));
    }

    /// Counters report bytes on the wire, overhead included: a keepalive has
    /// no payload yet costs `DATA_OVERHEAD` bytes each way.
    #[test]
    fn counters_include_the_wire_overhead() {
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b);

        let mut a_buf = dst();
        let mut b_buf = dst();
        let tx_before = a.tx_bytes();
        let rx_before = b.rx_bytes();

        // An empty payload is a keepalive: the datagram is pure overhead.
        let mut keepalive = match a.encapsulate(&[], &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a keepalive, got {other:?}"),
        };
        assert_eq!(keepalive.len(), DATA_OVERHEAD);
        assert_eq!(
            a.tx_bytes() - tx_before,
            DATA_OVERHEAD as u64,
            "a keepalive must count as {DATA_OVERHEAD} bytes, not zero"
        );

        assert!(matches!(
            b.decapsulate(&mut keepalive, &mut b_buf, &mut claimer()),
            TunnelResult::WriteToTunnelInPlace(_)
        ));
        assert_eq!(
            b.rx_bytes() - rx_before,
            DATA_OVERHEAD as u64,
            "received overhead must be counted too"
        );
    }

    /// A payload of `n` bytes must count as `n + DATA_OVERHEAD` on both sides.
    #[test]
    fn counters_add_the_overhead_to_the_payload() {
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b);

        let payload = [0x42u8; 100];
        let mut a_buf = dst();
        let mut b_buf = dst();

        // The handshake itself already moved bytes, so compare deltas.
        let tx_before = a.tx_bytes();
        let rx_before = b.rx_bytes();

        let mut packet = match a.encapsulate(&payload, &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected data, got {other:?}"),
        };
        assert_eq!(
            a.tx_bytes() - tx_before,
            (payload.len() + DATA_OVERHEAD) as u64
        );

        assert!(matches!(
            b.decapsulate(&mut packet, &mut b_buf, &mut claimer()),
            TunnelResult::WriteToTunnelInPlace(_)
        ));
        assert_eq!(
            b.rx_bytes() - rx_before,
            (payload.len() + DATA_OVERHEAD) as u64
        );
    }

    #[test]
    fn timers_without_a_session_do_nothing() {
        // Nothing to keep alive and no session to replace: no reason to spend a
        // handshake, which `encapsulate` starts when a packet needs to go out.
        let mut buf = dst();
        let mut tunnel = Tunnel::new(
            [7u8; KEY_LEN],
            [9u8; KEY_LEN],
            None,
            Some(Duration::from_secs(1)),
        );
        let now = Instant::now() + Duration::from_secs(2);
        assert!(matches!(
            tunnel.update_timers(now, &mut buf, &mut claimer()),
            TunnelResult::Done
        ));
    }

    #[test]
    fn an_expired_session_makes_the_tunnel_rehandshake_by_itself() {
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b);

        // Jump past REJECT_AFTER_TIME: the session may no longer carry traffic.
        let mut buf = dst();
        let now = Instant::now() + REJECT_AFTER_TIME;
        match a.update_timers(now, &mut buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => {
                assert_eq!(packet.len(), packet::HANDSHAKE_INIT_LEN);
            }
            other => panic!("expected a fresh initiation, got {other:?}"),
        }
    }

    #[test]
    fn a_stalled_handshake_is_retransmitted() {
        let (mut a, _b) = pair();
        let mut buf = dst();

        // Start a handshake and leave it unanswered.
        assert!(matches!(
            a.encapsulate(b"hello", &mut buf, &mut claimer()),
            TunnelResult::WriteToNetwork(_)
        ));

        // Before the timeout nothing happens; the initiation is still in flight.
        let early = Instant::now() + Duration::from_millis(1);
        assert!(matches!(
            a.update_timers(early, &mut buf, &mut claimer()),
            TunnelResult::Done
        ));

        // Past REKEY_TIMEOUT it is retransmitted, without the caller asking.
        let late = Instant::now() + REKEY_TIMEOUT + Duration::from_secs(1);
        match a.update_timers(late, &mut buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => {
                assert_eq!(packet.len(), packet::HANDSHAKE_INIT_LEN);
            }
            other => panic!("expected a retransmission, got {other:?}"),
        }
    }

    #[test]
    fn an_established_idle_session_sends_a_persistent_keepalive() {
        let a_private = [0x11u8; 32];
        let b_private = [0x22u8; 32];
        let a_public = DH_PUBKEY(&DH_PRIVATE(&a_private));
        let b_public = DH_PUBKEY(&DH_PRIVATE(&b_private));

        let keepalive = Duration::from_secs(1);
        let mut a = Tunnel::new(a_private, b_public, None, Some(keepalive));
        let mut b = Tunnel::new(b_private, a_public, None, None);
        handshake(&mut a, &mut b);

        let mut buf = dst();
        let now = Instant::now() + keepalive * 2;
        match a.update_timers(now, &mut buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(packet) => {
                // A keepalive is an empty transport-data packet.
                assert_eq!(packet.len(), DATA_OVERHEAD);
            }
            other => panic!("expected a keepalive, got {other:?}"),
        }
    }

    #[test]
    fn data_without_a_session_reports_no_session() {
        let mut buf = dst();
        let (mut b, _a) = pair();

        // A well-formed data packet for a session we do not have yet.
        let mut datagram = [0u8; 16 + 16];
        datagram[0..4].copy_from_slice(&packet::MSG_DATA.to_le_bytes());
        datagram[4..8].copy_from_slice(&11u32.to_le_bytes());

        assert!(matches!(
            b.decapsulate(&mut datagram, &mut buf, &mut claimer()),
            TunnelResult::NoSession
        ));
    }
}

#[cfg(test)]
mod concurrency {
    use super::tests::{claimer, pair};
    use super::*;

    /// The scheduler moves a tunnel into its owning thread, so both must be
    /// `Send`; a `Sync` bound would mean shared access, which we gave up.
    #[test]
    fn a_tunnel_and_a_session_move_between_threads() {
        fn assert_send<T: Send>() {}
        assert_send::<Tunnel>();
        assert_send::<Session>();

        let (a, b) = pair();
        let moved = std::thread::spawn(move || (a.tx_bytes(), b.rx_bytes()));
        assert_eq!(
            moved.join().expect("a tunnel must move into a thread"),
            (0, 0)
        );
    }

    /// The regression the index scheme exists for: a packet encrypted under S1
    /// must still decrypt against S1 once a rehandshake makes S2 current.
    #[test]
    fn a_packet_straddling_a_rehandshake_still_decrypts() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        // Encrypt a packet under S1 and hold it, as a worker would between
        // receiving it and decrypting it.
        let mut a_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut in_flight =
            match a.encapsulate(b"straddles the rehandshake", &mut a_buf, &mut claimer()) {
                TunnelResult::WriteToNetwork(p) => p.to_vec(),
                other => panic!("expected a data packet, got {other:?}"),
            };
        let s1_index = u32::from_le_bytes(in_flight[4..8].try_into().unwrap());
        let s1_id = b.current_session().expect("S1 is installed").local_id;
        assert_eq!(s1_id, s1_index);

        // The rehandshake installs S2 under a fresh index while that packet is
        // still in flight. `encapsulate` would write data, so go via handshake.
        super::tests::exchange_handshake(&mut a, &mut b);
        let s2_id = b.current_session().expect("S2 is installed").local_id;
        assert_ne!(s1_id, s2_id, "a rehandshake must claim a fresh index");

        // S1 is still routable by its own index even though S2 is current.
        assert_eq!(
            b.session_for_tests(s1_index).map(|s| s.local_id),
            Some(s1_id),
            "the superseded session must still be reachable"
        );

        let mut b_buf = vec![0u8; MAX_PACKET_SIZE];
        match b.decapsulate(&mut in_flight, &mut b_buf, &mut claimer()) {
            TunnelResult::WriteToTunnelInPlace(payload) => {
                assert_eq!(payload, b"straddles the rehandshake");
            }
            other => panic!("expected plaintext from S1, got {other:?}"),
        }
    }

    /// Rotation: confirming a negotiated session moves the one in use to
    /// `previous`, where packets already in flight can still reach it.
    #[test]
    fn confirming_a_session_rotates_the_previous_one_out() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        let first = b.current_session().expect("a session is in use").local_id;
        assert!(b.sessions.previous.is_none(), "nothing superseded yet");

        // A second session, filed as pending, then proved by traffic.
        let second_id = first.wrapping_add(1);
        let second = Session::new(second_id, 7, &[8u8; 32], &[8u8; 32]);
        b.install_session(second, false);
        assert_eq!(
            b.current_session().map(|s| s.local_id),
            Some(first),
            "still pending, so nothing rotates yet"
        );

        assert!(b.confirm_session(second_id), "the pending session confirms");
        assert_eq!(
            b.current_session().map(|s| s.local_id),
            Some(second_id),
            "the confirmed session takes over"
        );
        assert_eq!(
            b.sessions.previous.as_ref().map(|s| s.local_id),
            Some(first),
            "the superseded session moves to `previous`"
        );

        // A third rotation drops the oldest: only two are ever kept.
        let third_id = second_id.wrapping_add(1);
        b.install_session(Session::new(third_id, 7, &[7u8; 32], &[7u8; 32]), false);
        assert!(b.confirm_session(third_id));
        assert_eq!(
            b.sessions.previous.as_ref().map(|s| s.local_id),
            Some(second_id)
        );
        assert!(
            b.session_for_tests(first).is_none(),
            "the session two generations back is gone"
        );
        assert_eq!(
            b.session_count(),
            2,
            "steady state holds current + previous"
        );
    }

    /// Confirming an index that is not the pending one must do nothing: a
    /// forged or stale index must not disturb the session in use.
    #[test]
    fn confirming_an_unknown_index_changes_nothing() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        let current = b.current_session().expect("a session is in use").local_id;
        assert!(!b.confirm_session(0xdead_beef));
        assert!(!b.confirm_session(current), "`current` is not pending");
        assert_eq!(b.current_session().map(|s| s.local_id), Some(current));
        assert!(b.sessions.previous.is_none());
    }

    /// The bound that stops a session flood: unconfirmed handshakes replace
    /// each other instead of accumulating, so memory cannot grow with input.
    #[test]
    fn repeated_initiations_do_not_accumulate_sessions() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        // Two hundred initiations, each answered by `b`. `encapsulate` would
        // just send data once a session exists, so force a rekey each time.
        for _ in 0..200 {
            super::tests::exchange_handshake(&mut a, &mut b);
        }

        assert!(
            b.session_count() <= 3,
            "at most three sessions may be held, got {}",
            b.session_count()
        );
    }

    /// A negotiated session becomes usable only once the peer sends traffic,
    /// and only then does it displace the session carrying that traffic.
    #[test]
    fn a_negotiated_session_is_pending_until_traffic_proves_it() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        let first = b.current_session().expect("a session is in use").local_id;

        // A fresh session under a new index, as the responder would file it.
        let second = Session::new(first.wrapping_add(1), 7, &[8u8; 32], &[8u8; 32]);
        assert_eq!(b.install_session(second, false), first.wrapping_add(1));

        assert_eq!(
            b.current_session().map(|s| s.local_id),
            Some(first),
            "an unconfirmed session must not displace the one in use"
        );
        assert_eq!(
            b.session_for_tests(first.wrapping_add(1)).is_some(),
            true,
            "the pending session is still reachable by its index"
        );
        assert_eq!(b.session_count(), 2, "current plus pending");

        // The same index again is a retransmission: it refreshes, not adds.
        let duplicate = Session::new(first, 7, &[9u8; 32], &[9u8; 32]);
        assert_eq!(b.install_session(duplicate, false), first);
        assert!(b.session_count() <= 3);
    }

    /// A packet whose index matches nothing must be refused, never handed to
    /// whichever session happens to sit in that slot.
    #[test]
    fn a_packet_with_a_stale_index_is_refused() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        let mut a_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut b_buf = vec![0u8; MAX_PACKET_SIZE];

        let mut packet = match a.encapsulate(b"payload", &mut a_buf, &mut claimer()) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };

        // Point the packet at an index no session holds: it must not be
        // decrypted via `current` regardless.
        let real = u32::from_le_bytes(packet[4..8].try_into().unwrap());
        let stale = real.wrapping_add(1);
        packet[4..8].copy_from_slice(&stale.to_le_bytes());

        assert!(
            b.session_for_tests(stale).is_none(),
            "a stale index must not resolve to a session"
        );
        assert!(matches!(
            b.decapsulate(&mut packet, &mut b_buf, &mut claimer()),
            TunnelResult::NoSession
        ));
    }

    /// An index a tunnel was handed is the one its session answers to, and
    /// `slot_of` reports where that session sits. The device relies on both.
    #[test]
    fn a_tunnel_files_its_session_under_the_index_it_was_given() {
        use crate::protocol::primitives::{DH_PRIVATE, DH_PUBKEY};

        let a_private = [0x11u8; 32];
        let b_private = [0x22u8; 32];
        let a_public = DH_PUBKEY(&DH_PRIVATE(&a_private));
        let b_public = DH_PUBKEY(&DH_PRIVATE(&b_private));

        let mut a = Tunnel::new(a_private, b_public, None, None);
        let mut b = Tunnel::new(b_private, a_public, None, None);

        // A fixed index handed in from outside, exactly as the device would.
        let handed = 0x1234_5678u32;
        let mut claim = || Some(handed);

        let mut init = vec![0u8; MAX_PACKET_SIZE];
        let written = match a.encapsulate(b"hello", &mut init, &mut claim) {
            TunnelResult::WriteToNetwork(packet) => packet.len(),
            other => panic!("expected an initiation, got {other:?}"),
        };
        assert_eq!(
            a.handshake.pending_index(),
            Some(handed),
            "the initiation must claim the index it was handed"
        );

        // The responder claims an index of its own and files its session
        // under exactly that value, which `slot_of` must resolve.
        let responder_index = 0x0abc_def0u32;
        let mut responder_claim = || Some(responder_index);
        let mut response = vec![0u8; MAX_PACKET_SIZE];
        let mut b_buf = vec![0u8; MAX_PACKET_SIZE];
        match b.decapsulate(&mut init[..written], &mut response, &mut responder_claim) {
            TunnelResult::WriteToNetwork(_) => {}
            other => panic!("expected a response, got {other:?}"),
        }

        b.slot_of(responder_index)
            .expect("the responder's session is filed under the index it claimed");
        assert!(
            b.slot_of(0xdead_beef).is_none(),
            "an index nobody claimed must not resolve"
        );
        let _ = b_buf;
    }

    /// A packet addressed to an index nobody claimed must not resolve to a
    /// session, in either tunnel.
    #[test]
    fn an_unclaimed_index_resolves_to_no_session() {
        use crate::protocol::primitives::{DH_PRIVATE, DH_PUBKEY};

        let a_private = [0x11u8; 32];
        let b_private = [0x22u8; 32];
        let a_public = DH_PUBKEY(&DH_PRIVATE(&a_private));
        let b_public = DH_PUBKEY(&DH_PRIVATE(&b_private));

        let a = Tunnel::new(a_private, b_public, None, None);
        let b = Tunnel::new(b_private, a_public, None, None);

        assert!(a.current_session().is_none());
        assert!(b.current_session().is_none());

        for index in [1u32, 2, 0xdead_beef] {
            assert!(a.session_for_tests(index).is_none());
            assert!(b.session_for_tests(index).is_none());
        }
    }
}
