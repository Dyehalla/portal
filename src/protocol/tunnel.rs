//! The peer-facing half of the protocol engine: a thin dispatcher over
//! `handshake` and `session`, writing into caller-owned buffers.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;

use super::cookie;
use super::handshake;
use super::index::SessionIndex;
use super::packet::{
    self, CookieReply, DataPacket, HandshakeInitiation, HandshakeResponse, Packet, PacketMut,
    WireGuardError,
};
use super::primitives::{self, DH_PRIVATE, DH_PUBKEY, MAC_LEN, KEY_LEN};
use super::session::{DATA_OVERHEAD, MAX_TRANSPORT_PAYLOAD, Session, SessionError};

pub(crate) const N_SESSIONS: usize = 8;
/// The ring maps an index to a slot with `% N_SESSIONS`, which is only a
/// bitmask over the low index bits while this stays a power of two.
const _: () = assert!(N_SESSIONS.is_power_of_two(), "N_SESSIONS must be a power of two");
const MAX_QUEUE_DEPTH: usize = 256;
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// A data packet is never allowed to sit in the ring longer than this: one
/// already in flight when the session turns 180s old must not be dropped.
const REJECT_AFTER_TIME_SLACK: Duration = Duration::from_secs(5);

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
}

impl<'d, 'o> From<SessionError> for TunnelResult<'d, 'o> {
    fn from(error: SessionError) -> Self {
        match error {
            SessionError::RekeyRequired => Self::RekeyRequired,
            // The session's own reason is preserved all the way out.
            SessionError::Rejected(reason) => Self::InvalidPacket(reason),
            SessionError::Malformed => Self::InvalidPacket(WireGuardError::InvalidPacket),
        }
    }
}

/// A single-peer WireGuard transport tunnel.
pub struct Tunnel {
    sessions: SessionTable,
    control: Mutex<ControlState>,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

struct SessionTable {
    slots: [ArcSwapOption<Session>; N_SESSIONS],
    /// The session outbound traffic uses: the most recent one installed.
    ///
    /// A send-side hint only: inbound packets are routed by receiver index.
    current: ArcSwapOption<Session>,
}

#[derive(Default)]
struct Timers {
    last_handshake: Option<Instant>,
    last_packet_received: Option<Instant>,
    last_packet_sent: Option<Instant>,
    persistent_keepalive: Option<Duration>,
}

struct ControlState {
    handshake: handshake::Handshake,
    timers: Timers,
    packet_queue: VecDeque<Vec<u8>>,
}

impl SessionTable {
    fn empty() -> Self {
        Self {
            slots: std::array::from_fn(|_| ArcSwapOption::empty()),
            current: ArcSwapOption::empty(),
        }
    }
}

impl Default for SessionTable {
    fn default() -> Self {
        Self::empty()
    }
}

/// True when a session may no longer carry traffic at all. A dead slot can be
/// recycled: nothing still on the wire can be addressed to it.
fn is_dead(session: &Session) -> bool {
    session.created_at.elapsed() >= REJECT_AFTER_TIME + REJECT_AFTER_TIME_SLACK
}

impl Default for ControlState {
    fn default() -> Self {
        Self {
            handshake: handshake::Handshake::default(),
            timers: Timers::default(),
            packet_queue: VecDeque::new(),
        }
    }
}

impl Tunnel {
    pub fn new(
        static_private: [u8; KEY_LEN],
        peer_static_public: [u8; KEY_LEN],
        preshared_key: Option<[u8; KEY_LEN]>,
        persistent_keepalive: Option<Duration>,
        peer_index: u32,
    ) -> Self {
        Self {
            sessions: SessionTable::default(),
            control: Mutex::new(ControlState {
                handshake: handshake::Handshake::new(
                    static_private,
                    peer_static_public,
                    preshared_key,
                    SessionIndex::new(peer_index),
                ),
                timers: Timers {
                    persistent_keepalive,
                    ..Timers::default()
                },
                packet_queue: VecDeque::new(),
            }),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        }
    }

    /// Encrypts one IP packet into `dst` (`MAX_PACKET_SIZE` bytes); without a
    /// session this writes an initiation and queues the packet instead.
    pub fn encapsulate<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> TunnelResult<'_, 'a> {
        if let Some(session) = self.current_session() {
            let written = match session.format_packet_data(src, dst) {
                Ok(written) => written,
                Err(error) => return error.into(),
            };

            self.control().timers.last_packet_sent = Some(Instant::now());

            // `written` is the whole datagram, header and tag included: the
            // counter reports bytes on the wire, not payload (§6.6).
            self.tx_bytes.fetch_add(written as u64, Ordering::Relaxed);
            return TunnelResult::WriteToNetwork(&mut dst[..written]);
        }

        // No session yet: hold the packet for when the handshake completes,
        // then (re)start the handshake. 
        self.queue_packet(src);
        self.format_handshake_initiation(dst, false)
    }

    /// Builds handshake initiation into `dst`.
    /// One handshake is in flight at a time; `force_resend` retransmits it.
    pub fn format_handshake_initiation<'a>(
        &self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnelResult<'_, 'a> {
        let mut control = self.control();

        if control.handshake.has_pending_response() && !force_resend {
            return TunnelResult::HandshakeInProgress;
        }

        let message = &mut dst[..packet::HANDSHAKE_INIT_LEN];
        if let Err(error) = control.handshake.format_handshake_init(message) {
            return TunnelResult::InvalidPacket(error.into());
        }

        let now = Instant::now();
        control.timers.last_handshake = Some(now);
        control.timers.last_packet_sent = Some(now);
        drop(control);

        TunnelResult::WriteToNetwork(message)
    }

    /// Stores a packet until a session can carry it.
    fn queue_packet(&self, src: &[u8]) {
        let mut control = self.control();
        if control.packet_queue.len() < MAX_QUEUE_DEPTH {
            control.packet_queue.push_back(src.to_vec());
        }
    }

    /// Sends the oldest packet held while no session existed. Call repeatedly
    /// until it stops returning `WriteToNetwork`: `Done` means the queue is
    /// empty, `NoSession` that the packet went back to the front.
    pub fn send_queued_packet<'d, 'a>(&self, dst: &'a mut [u8]) -> TunnelResult<'d, 'a> {
        let mut control = self.control();
        let Some(src) = control.packet_queue.pop_front() else {
            return TunnelResult::Done;
        };
        drop(control);

        if let Some(session) = self.current_session() {
            let written = match session.format_packet_data(&src, dst) {
                Ok(written) => written,
                Err(error) => return error.into(),
            };
            self.tx_bytes.fetch_add(written as u64, Ordering::Relaxed);
            return TunnelResult::WriteToNetwork(&mut dst[..written]);
        }

        // The session vanished between the pop and here: put the packet back
        // at the front so it keeps its place. No depth check is needed, as
        // this packet just vacated a slot; a bound could only drop it.
        let mut control = self.control();
        control.packet_queue.push_front(src);
        TunnelResult::NoSession
    }

    /// Test hook: queues a packet as if `encapsulate` had held it.
    #[cfg(test)]
    pub(super) fn queue_for_tests(&self, src: &[u8]) {
        self.queue_packet(src);
    }

    /// Test hook: the payloads the queue currently holds, oldest first.
    #[cfg(test)]
    pub(super) fn queued_for_tests(&self) -> Vec<Vec<u8>> {
        self.control().packet_queue.iter().cloned().collect()
    }

    /// Locks the control state. A poisoned lock means a thread panicked
    /// mid-update, leaving state we cannot repair: panicking is the honest exit.
    fn control(&self) -> std::sync::MutexGuard<'_, ControlState> {
        self.control.lock().expect("control lock poisoned")
    }


    /// Parses one incoming datagram. `datagram` is `&mut` because a data packet
    /// is decrypted in place there; an empty one drains the queued backlog.
    pub fn decapsulate<'a, 'o>(
        &self,
        datagram: &'a mut [u8],
        dst: &'o mut [u8],
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
            Ok(PacketMut::HandshakeInitiation(packet)) => self.handle_handshake_init(packet, dst),
            Ok(PacketMut::HandshakeResponse(packet)) => {
                self.handle_handshake_response(packet, dst)
            }
            Ok(PacketMut::CookieReply(packet)) => self.handle_cookie_reply(packet),
            Err(error) => TunnelResult::InvalidPacket(error),
        }
    }

    /// Decrypts a transport-data packet in place; the plaintext borrows the
    /// datagram buffer, not `dst`. The session is chosen by the packet's own
    /// receiver index, so a packet from the previous session still decrypts.
    fn handle_data<'a, 'o>(&self, packet: DataPacket<'a>) -> TunnelResult<'a, 'o> {
        let Some(session) = self.session_for(packet.receiver_index) else {
            return TunnelResult::NoSession;
        };

        // Capture the on-wire size before decrypting: `open_in_place` leaves
        // only the plaintext, and the header is carved off by `parse_mut`.
        let wire_len = packet.encrypted_payload.len() + packet::DATA_HEADER_LEN;

        // The payload is decrypted in place inside the received datagram
        let plaintext = match session.receive_packet_data(packet) {
            Ok(plaintext) => plaintext,
            Err(error) => return error.into(),
        };

        self.control().timers.last_packet_received = Some(Instant::now());

        self.rx_bytes.fetch_add(wire_len as u64, Ordering::Relaxed);
        TunnelResult::WriteToTunnelInPlace(plaintext)
    }

    /// Answers a handshake initiation.
    fn handle_handshake_init<'d, 'a>(
        &self,
        initiation: HandshakeInitiation<'_>,
        dst: &'a mut [u8],
    ) -> TunnelResult<'d, 'a> {
        let response = &mut dst[..packet::HANDSHAKE_RESPONSE_LEN];
        let mut control = self.control();

        // Any failure means the initiation is not authentic, is for another
        // peer, or its keys cannot be agreed with ours; we stay silent.
        let (session, index) = match control
            .handshake
            .format_handshake_response(response, &initiation)
        {
            Ok(pair) => pair,
            Err(error) => return TunnelResult::InvalidPacket(error.into()),
        };

        // The responder can read the initiator's traffic as soon as it replies.
        // If the ring refuses the session, the response must not go out: the
        // peer would encrypt to an index we cannot receive on.
        if !self.install_session(session) {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        }
        debug_assert_eq!(index, self.sessions.slots[index as usize % N_SESSIONS]
            .load_full()
            .map(|s| s.local_id)
            .unwrap_or_default());

        let now = Instant::now();
        control.timers.last_packet_received = Some(now);
        control.timers.last_packet_sent = Some(now);

        TunnelResult::WriteToNetwork(response)
    }

    /// Consumes a handshake response, activates the session and confirms it
    /// with a keepalive.
    fn handle_handshake_response<'d, 'a>(
        &self,
        response: HandshakeResponse<'_>,
        dst: &'a mut [u8],
    ) -> TunnelResult<'d, 'a> {
        let mut control = self.control();

        let (session, _index) = match control.handshake.consume_response(&response) {
            Ok(pair) => pair,
            Err(error) => return TunnelResult::InvalidPacket(error.into()),
        };

        // The initiator proves liveness with a keepalive, which also tells the
        // responder the session is usable.
        let written = match session.format_packet_data(&[], dst) {
            Ok(written) => written,
            Err(error) => return error.into(),
        };

        if !self.install_session(session) {
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        }

        let now = Instant::now();
        control.timers.last_packet_received = Some(now);
        control.timers.last_packet_sent = Some(now);
        control.timers.last_handshake = Some(now);
        drop(control);

        TunnelResult::WriteToNetwork(&mut dst[..written])
    }

    /// Stores the cookie from a cookie reply for use in `mac2` (§5.4.4/§5.4.7).
    /// Unwrapping with the answered initiation's `mac1` binds it to that handshake.
    fn handle_cookie_reply<'d, 'o>(&self, reply: CookieReply<'_>) -> TunnelResult<'d, 'o> {
        let now = Instant::now();
        let mut control = self.control();
        // Read the peer key before any further `control()` call: the mutex is
        // not reentrant, so calling the accessor while holding it would hang.
        let peer_static_public = control.handshake.peer_static_public;

        let (Some(our_index), Some(our_mac1)) = (
            control.handshake.pending_index(),
            control.handshake.last_sent_mac1().copied(),
        ) else {
            // Nothing in flight, so this reply answers a handshake we have
            // already abandoned.
            return TunnelResult::InvalidPacket(WireGuardError::InvalidPacket);
        };

        match cookie::open_cookie_reply(&peer_static_public, &reply, our_index, &our_mac1) {
            Ok(cookie) => {
                control.handshake.store_cookie(cookie, now);
                TunnelResult::Done
            }
            Err(error) => TunnelResult::InvalidPacket(error),
        }
    }

    /// Advances timers and acts on whatever came due: retransmitting a stalled
    /// handshake, starting a new one, or sending a keepalive. `dst` must satisfy
    /// the same contract as `encapsulate`; the tunnel starts its own handshake.
    pub fn update_timers<'a>(&self, now: Instant, dst: &'a mut [u8]) -> TunnelResult<'_, 'a> {
        let decision = {
            let control = self.control();

            // An initiation is in flight: retransmit once the timeout passes.
            if control.handshake.has_pending_response() {
                let elapsed = control
                    .timers
                    .last_handshake
                    .and_then(|started| now.checked_duration_since(started));
                if elapsed.is_some_and(|age| age >= REKEY_TIMEOUT) {
                    TimerAction::Initiate
                } else {
                    TimerAction::Nothing
                }
            } else {
                self.session_timer_action(&control, now)
            }
        };

        match decision {
            TimerAction::Nothing => TunnelResult::Done,
            TimerAction::Initiate => self.format_handshake_initiation(dst, true),
            TimerAction::Keepalive => self.encapsulate(&[], dst),
        }
    }

    /// Decides what an established (or absent) session requires. Split out
    /// because the timer path and the tests want the same reasoning.
    fn session_timer_action(&self, control: &ControlState, now: Instant) -> TimerAction {
        let Some(session) = self.current_session() else {
            // Nothing to keep alive, and no session to replace: `encapsulate`
            // will start a handshake when there is actually a packet to send.
            return TimerAction::Nothing;
        };

        let age = now.checked_duration_since(session.created_at);

        // Past the hard limit the session must not carry more traffic.
        if age.is_some_and(|age| age >= REJECT_AFTER_TIME) {
            return TimerAction::Initiate;
        }

        let Some(interval) = control.timers.persistent_keepalive else {
            return TimerAction::Nothing;
        };
        let last_activity = control
            .timers
            .last_packet_sent
            .max(control.timers.last_packet_received);
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

    /// Registers a new session in the ring and makes it current. Returns
    /// `false` when that would evict a session another worker may still be
    /// decrypting against; a slot may only be reused once its session is dead.
    fn install_session(&self, session: Session) -> bool {
        let slot = session.local_id as usize % N_SESSIONS;

        if let Some(existing) = self.sessions.slots[slot].load_full() {
            // Same index means a retransmission of a handshake we already
            // answered; refreshing it is fine and must not be refused.
            if existing.local_id != session.local_id && !is_dead(&existing) {
                return false;
            }
        }

        let session = Arc::new(session);
        self.sessions.slots[slot].store(Some(Arc::clone(&session)));
        self.sessions.current.store(Some(session));
        true
    }

    /// Finds the session a received packet is addressed to. Routing is by the
    /// full 32-bit receiver index, not the slot: the slot is only a cache
    /// position and may since have been reused by a different session.
    fn session_for(&self, receiver_index: u32) -> Option<Arc<Session>> {
        let slot = receiver_index as usize % N_SESSIONS;
        let session = self.sessions.slots[slot].load_full()?;

        if session.local_id != receiver_index {
            // A forged index, or a session whose slot was reused. Refusing
            // stops it being decrypted under a stranger's keys.
            return None;
        }
        Some(session)
    }

    fn current_session(&self) -> Option<Arc<Session>> {
        self.sessions.current.load_full()
    }


    pub fn tx_bytes(&self) -> u64 {
        self.tx_bytes.load(Ordering::Relaxed)
    }

    pub fn rx_bytes(&self) -> u64 {
        self.rx_bytes.load(Ordering::Relaxed)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::primitives::{DH_PRIVATE, DH_PUBKEY};


    /// Two peers with matching static keys and mirrored indexes.
    pub(super) fn pair() -> (Tunnel, Tunnel) {
        let a_private = [0x11u8; 32];
        let b_private = [0x22u8; 32];
        let a_public = DH_PUBKEY(&DH_PRIVATE(&a_private));
        let b_public = DH_PUBKEY(&DH_PRIVATE(&b_private));

        let a = Tunnel::new(a_private, b_public, None, None, 11);
        let b = Tunnel::new(b_private, a_public, None, None, 22);
        (a, b)
    }

    fn dst() -> Vec<u8> {
        vec![0u8; MAX_PACKET_SIZE]
    }

    /// Runs a full handshake between two peers.
    pub(super) fn handshake(a: &mut Tunnel, b: &mut Tunnel) {
        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut init = match a.encapsulate(b"hi", &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected initiation, got {other:?}"),
        };

        let mut response = match b.decapsulate(&mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected response, got {other:?}"),
        };

        let mut keepalive = match a.decapsulate(&mut response, &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected keepalive, got {other:?}"),
        };

        match b.decapsulate(&mut keepalive, &mut b_buf) {
            TunnelResult::WriteToTunnelInPlace(payload) => assert!(payload.is_empty()),
            other => panic!("expected empty keepalive payload, got {other:?}"),
        }
    }

    /// Runs a handshake between peers that already have a session, i.e. a
    /// rekey. Unlike [`handshake`] this cannot start from `encapsulate`, which
    /// writes data whenever a session exists.
    pub(super) fn exchange_handshake(a: &mut Tunnel, b: &mut Tunnel) {
        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut init = match a.format_handshake_initiation(&mut a_buf, false) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a rekey initiation, got {other:?}"),
        };

        let mut response = match b.decapsulate(&mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a rekey response, got {other:?}"),
        };

        let mut keepalive = match a.decapsulate(&mut response, &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a rekey keepalive, got {other:?}"),
        };

        match b.decapsulate(&mut keepalive, &mut b_buf) {
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
        let mut packet = match a.encapsulate(b"an IP packet", &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };

        match b.decapsulate(&mut packet, &mut b_buf) {
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

        let mut from_a = match a.encapsulate(b"ping", &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };
        assert!(matches!(
            b.decapsulate(&mut from_a, &mut b_buf),
            TunnelResult::WriteToTunnelInPlace(_)
        ));

        let mut from_b = match b.encapsulate(b"pong", &mut b_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };
        match a.decapsulate(&mut from_b, &mut a_buf) {
            TunnelResult::WriteToTunnelInPlace(payload) => assert_eq!(payload, b"pong"),
            other => panic!("expected plaintext, got {other:?}"),
        }
    }

    #[test]
    fn a_forged_response_is_rejected() {
        let (mut a, mut b) = pair();
        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut init = match a.encapsulate(b"hi", &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected initiation, got {other:?}"),
        };
        let mut response = match b.decapsulate(&mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected response, got {other:?}"),
        };

        response[44] ^= 0x01;
        assert!(matches!(
            a.decapsulate(&mut response, &mut a_buf),
            TunnelResult::InvalidPacket(WireGuardError::HandshakeNotAuthentic)
        ));
    }

    #[test]
    fn a_response_without_a_pending_initiation_is_rejected() {
        let (mut a, mut b) = pair();
        let mut a_buf = dst();
        let mut b_buf = dst();

        let mut init = match a.encapsulate(b"hi", &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected initiation, got {other:?}"),
        };
        let mut response = match b.decapsulate(&mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected response, got {other:?}"),
        };

        assert!(matches!(
            a.decapsulate(&mut response, &mut a_buf),
            TunnelResult::WriteToNetwork(_)
        ));
        assert!(matches!(
            a.decapsulate(&mut response, &mut a_buf),
            TunnelResult::InvalidPacket(_)
        ));
    }

    #[test]
    fn encapsulate_writes_a_handshake_initiation() {
        let mut buf = dst();
        let (mut a, _b) = pair();

        match a.encapsulate(b"hello", &mut buf) {
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
            a.encapsulate(b"hello", &mut buf),
            TunnelResult::WriteToNetwork(_)
        ));
        assert!(matches!(
            a.encapsulate(b"second", &mut buf),
            TunnelResult::HandshakeInProgress
        ));
    }

    #[test]
    fn empty_datagram_drains_the_queue() {
        let mut buf = dst();
        let (mut a, _b) = pair();

        assert!(matches!(
            a.encapsulate(b"hello", &mut buf),
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
            matches!(a.decapsulate(&mut empty, &mut buf), TunnelResult::Done),
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
        let mut init = match a.encapsulate(b"first", &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected an initiation, got {other:?}"),
        };
        assert!(matches!(
            a.encapsulate(b"second", &mut a_buf),
            TunnelResult::HandshakeInProgress
        ));

        // Complete the handshake before draining.
        let mut response = match b.decapsulate(&mut init, &mut b_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a response, got {other:?}"),
        };
        let mut keepalive = match a.decapsulate(&mut response, &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected a keepalive, got {other:?}"),
        };
        assert!(matches!(
            b.decapsulate(&mut keepalive, &mut b_buf),
            TunnelResult::WriteToTunnelInPlace(_)
        ));

        for expected in [&b"first"[..], &b"second"[..]] {
            let mut sent = match a.send_queued_packet(&mut a_buf) {
                TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("expected a queued packet, got {other:?}"),
            };
            match b.decapsulate(&mut sent, &mut b_buf) {
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
            b.decapsulate(&mut garbage, &mut buf),
            TunnelResult::InvalidPacket(WireGuardError::UnknownMessageType)
        ));
    }
    /// A packet that cannot be sent because the session vanished goes back to
    /// the *front*: it keeps the place it had, so ordering survives the retry.
    #[test]
    fn a_packet_that_cannot_be_sent_keeps_its_place_in_the_queue() {
        let mut buf = dst();
        let (a, _b) = pair();

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

    #[test]
    fn short_datagrams_do_not_panic() {
        let mut buf = dst();
        let (b, _a) = pair();

        for len in 0..40usize {
            let mut datagram = vec![0u8; len];
            // Claim to be an initiation so the mac path is attempted too.
            if len >= 4 {
                datagram[..4].copy_from_slice(&packet::MSG_HANDSHAKE_INIT.to_le_bytes());
            }
            let result = b.decapsulate(&mut datagram, &mut buf);
            let _ = format!("{result:?}");
        }

        // A well-formed header with a truncated body is likewise refused.
        let mut datagram = vec![0u8; packet::HANDSHAKE_INIT_LEN - 1];
        datagram[..4].copy_from_slice(&packet::MSG_HANDSHAKE_INIT.to_le_bytes());
        assert!(matches!(
            b.decapsulate(&mut datagram, &mut buf),
            TunnelResult::InvalidPacket(_)
        ));
    }

    /// Transfer counters report bytes on the wire, overhead included. The
    /// clearest case is a keepalive: no payload at all, yet it costs exactly
    /// `DATA_OVERHEAD` bytes in each direction.
    #[test]
    fn counters_include_the_wire_overhead() {
        let (mut a, mut b) = pair();
        handshake(&mut a, &mut b);

        let mut a_buf = dst();
        let mut b_buf = dst();
        let tx_before = a.tx_bytes();
        let rx_before = b.rx_bytes();

        // An empty payload is a keepalive: the datagram is pure overhead.
        let mut keepalive = match a.encapsulate(&[], &mut a_buf) {
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
            b.decapsulate(&mut keepalive, &mut b_buf),
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

        let mut packet = match a.encapsulate(&payload, &mut a_buf) {
            TunnelResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected data, got {other:?}"),
        };
        assert_eq!(
            a.tx_bytes() - tx_before,
            (payload.len() + DATA_OVERHEAD) as u64
        );

        assert!(matches!(
            b.decapsulate(&mut packet, &mut b_buf),
            TunnelResult::WriteToTunnelInPlace(_)
        ));
        assert_eq!(
            b.rx_bytes() - rx_before,
            (payload.len() + DATA_OVERHEAD) as u64
        );
    }

    #[test]
    fn timers_without_a_session_do_nothing() {
        // With nothing to keep alive and no session to replace, there is no
        // reason to spend a handshake; `encapsulate` starts one when a real
        // packet needs to go out.
        let mut buf = dst();
        let mut tunnel = Tunnel::new(
            [7u8; KEY_LEN],
            [9u8; KEY_LEN],
            None,
            Some(Duration::from_secs(1)),
            11,
        );
        let now = Instant::now() + Duration::from_secs(2);
        assert!(matches!(
            tunnel.update_timers(now, &mut buf),
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
        match a.update_timers(now, &mut buf) {
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
            a.encapsulate(b"hello", &mut buf),
            TunnelResult::WriteToNetwork(_)
        ));

        // Before the timeout nothing happens; the initiation is still in flight.
        let early = Instant::now() + Duration::from_millis(1);
        assert!(matches!(
            a.update_timers(early, &mut buf),
            TunnelResult::Done
        ));

        // Past REKEY_TIMEOUT it is retransmitted, without the caller asking.
        let late = Instant::now() + REKEY_TIMEOUT + Duration::from_secs(1);
        match a.update_timers(late, &mut buf) {
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
        let mut a = Tunnel::new(a_private, b_public, None, Some(keepalive), 11);
        let mut b = Tunnel::new(b_private, a_public, None, None, 22);
        handshake(&mut a, &mut b);

        let mut buf = dst();
        let now = Instant::now() + keepalive * 2;
        match a.update_timers(now, &mut buf) {
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
            b.decapsulate(&mut datagram, &mut buf),
            TunnelResult::NoSession
        ));
    }
}

#[cfg(test)]
mod concurrency {
    use super::tests::pair;
    use super::*;

    /// Compile-time proof that a `Tunnel` can be shared across worker threads:
    /// all workers decrypt in parallel, only the control lock serialises.
    #[test]
    fn tunnel_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Tunnel>();
        assert_send_sync::<Arc<Tunnel>>();
    }

    #[test]
    fn workers_decrypt_one_peers_packets_in_parallel() {
        use std::thread;

        let (mut a, mut b) = super::tests::pair();
        super::tests::handshake(&mut a, &mut b);

        let b = Arc::new(b);

        // Build one datagram per worker, each with its own counter.
        let mut datagrams: Vec<Vec<u8>> = Vec::new();
        for i in 0..8 {
            let mut buf = vec![0u8; MAX_PACKET_SIZE];
            let payload = format!("packet {i}");
            match a.encapsulate(payload.as_bytes(), &mut buf) {
                TunnelResult::WriteToNetwork(p) => datagrams.push(p.to_vec()),
                other => panic!("expected a data packet, got {other:?}"),
            }
        }

        let handles: Vec<_> = datagrams
            .into_iter()
            .enumerate()
            .map(|(i, mut datagram)| {
                let b = Arc::clone(&b);
                thread::spawn(move || {
                    let mut dst = vec![0u8; MAX_PACKET_SIZE];
                    // The borrow cannot cross the thread boundary, so decide here.
                    let ok = matches!(
                        b.decapsulate(&mut datagram, &mut dst),
                        TunnelResult::WriteToTunnelInPlace(_)
                    );
                    (i, ok)
                })
            })
            .collect();

        for handle in handles {
            let (i, ok) = handle.join().expect("decrypt must not panic");
            assert!(ok, "packet {i} failed to decrypt");
        }
    }

    /// The regression this whole index scheme exists for: a packet encrypted
    /// under S1 must still decrypt against S1 after a rehandshake makes S2
    /// current, rather than being dropped or handed to S2.
    #[test]
    fn a_packet_straddling_a_rehandshake_still_decrypts() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        // Encrypt a packet under S1 and hold it, as a worker would between
        // receiving it and decrypting it.
        let mut a_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut in_flight = match a.encapsulate(b"straddles the rehandshake", &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };
        let s1_index = u32::from_le_bytes(in_flight[4..8].try_into().unwrap());
        let s1 = b.current_session().expect("S1 is installed");
        assert_eq!(s1.local_id, s1_index);

        // The rehandshake completes while that packet is still in flight and
        // installs S2 under a fresh index. It goes through
        // `format_handshake_initiation`: `encapsulate` would just write data.
        super::tests::exchange_handshake(&mut a, &mut b);
        let s2 = b.current_session().expect("S2 is installed");
        assert_ne!(
            s1.local_id, s2.local_id,
            "a rehandshake must claim a fresh index"
        );
        assert_ne!(
            s1.local_id as usize % N_SESSIONS,
            s2.local_id as usize % N_SESSIONS,
            "consecutive sessions must land in different ring slots"
        );

        // S1 is still routable by its own index even though S2 is current.
        assert_eq!(
            b.session_for(s1_index).map(|s| s.local_id),
            Some(s1.local_id),
            "the superseded session must still be reachable"
        );

        let mut b_buf = vec![0u8; MAX_PACKET_SIZE];
        match b.decapsulate(&mut in_flight, &mut b_buf) {
            TunnelResult::WriteToTunnelInPlace(payload) => {
                assert_eq!(payload, b"straddles the rehandshake");
            }
            other => panic!("expected plaintext from S1, got {other:?}"),
        }
    }

    /// A rehandshake must not evict the session currently carrying traffic:
    /// the ring is only reusable once a session is genuinely dead.
    #[test]
    fn installing_a_session_never_evicts_a_live_one() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        let live = b.current_session().expect("handshake installed a session");
        let local_id = live.local_id;

        // A second session claiming the *same* index is a retransmission and is
        // allowed to replace it.
        let duplicate = Session::new(local_id, 7, &[9u8; 32], &[9u8; 32]);
        assert!(b.install_session(duplicate), "same index may be refreshed");

        // A different session that happens to hash to the same slot must be
        // refused while the incumbent is alive.
        let colliding_id = local_id + N_SESSIONS as u32;
        let colliding = Session::new(colliding_id, 7, &[8u8; 32], &[8u8; 32]);
        assert_eq!(
            colliding_id as usize % N_SESSIONS,
            local_id as usize % N_SESSIONS,
            "the test needs a genuine slot collision"
        );
        assert!(
            !b.install_session(colliding),
            "a live session must not be evicted from its slot"
        );
        assert_eq!(
            b.session_for(colliding_id).map(|s| s.local_id),
            None,
            "the refused session must not be reachable"
        );
    }

    /// A packet whose index matches nothing must be refused, never handed to
    /// whichever session happens to sit in that slot.
    #[test]
    fn a_packet_with_a_stale_index_is_refused() {
        let (mut a, mut b) = pair();
        super::tests::handshake(&mut a, &mut b);

        let mut a_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut b_buf = vec![0u8; MAX_PACKET_SIZE];

        let mut packet = match a.encapsulate(b"payload", &mut a_buf) {
            TunnelResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected a data packet, got {other:?}"),
        };

        // Point the packet at another index that shares the same ring slot:
        // the old code would have decrypted it via `current` regardless.
        let real = u32::from_le_bytes(packet[4..8].try_into().unwrap());
        let stale = real + N_SESSIONS as u32;
        packet[4..8].copy_from_slice(&stale.to_le_bytes());

        assert!(
            b.session_for(stale).is_none(),
            "a stale index must not resolve to a session"
        );
        assert!(matches!(
            b.decapsulate(&mut packet, &mut b_buf),
            TunnelResult::NoSession
        ));
    }

    /// The allocator is what feeds `Tunnel::new` in the real device: every peer
    /// gets its own 24-bit number, and two peers must never collide even though
    /// their session bytes start out identical.
    #[test]
    fn peers_allocated_from_one_device_get_disjoint_index_spaces() {
        use super::super::index::{IndexAllocator, peer_of, session_of};

        let mut allocator = IndexAllocator::new();
        let a_peer = allocator.next_peer().expect("space is not exhausted");
        let b_peer = allocator.next_peer().expect("space is not exhausted");
        assert_ne!(a_peer, b_peer);

        let a_first = SessionIndex::new(a_peer).next_index();
        let b_first = SessionIndex::new(b_peer).next_index();

        assert_ne!(a_first, b_first);
        assert_eq!(peer_of(a_first), a_peer);
        assert_eq!(peer_of(b_first), b_peer);
        // The session bytes match, so the ring *slot* collides; only the full
        // index distinguishes them, which is what `session_for` checks.
        assert_eq!(session_of(a_first), session_of(b_first));
        assert_eq!(
            a_first as usize % N_SESSIONS,
            b_first as usize % N_SESSIONS
        );
    }

    /// Two independently built tunnels start with no session, and a packet
    /// addressed to an index nobody claimed must not resolve to anything.
    #[test]
    fn an_unclaimed_index_resolves_to_no_session() {
        use super::super::index::{IndexAllocator, SessionIndex};
        use crate::protocol::primitives::{DH_PRIVATE, DH_PUBKEY};

        let mut allocator = IndexAllocator::new();
        let a_peer = allocator.next_peer().unwrap();
        let b_peer = allocator.next_peer().unwrap();

        let a_private = [0x11u8; 32];
        let b_private = [0x22u8; 32];
        let a_public = DH_PUBKEY(&DH_PRIVATE(&a_private));
        let b_public = DH_PUBKEY(&DH_PRIVATE(&b_private));

        let a = Tunnel::new(a_private, b_public, None, None, a_peer);
        let b = Tunnel::new(b_private, a_public, None, None, b_peer);

        assert!(a.current_session().is_none());
        assert!(b.current_session().is_none());

        // Each peer's own first index, not yet claimed by any session.
        for index in [SessionIndex::new(a_peer).peek(), SessionIndex::new(b_peer).peek()] {
            assert!(a.session_for(index).is_none());
            assert!(b.session_for(index).is_none());
        }
    }
}
