//! The peer-facing half of the protocol engine: a thin dispatcher over
//! `handshake` and `session`, writing into caller-owned buffers.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;

use super::handshake;
use super::packet::{
    self, CookieReply, DataPacket, HandshakeInitiation, HandshakeResponse, Packet, PacketMut,
    WireGuardError,
};
use super::primitives::KEY_LEN;
use super::session::{DATA_OVERHEAD, MAX_TRANSPORT_PAYLOAD, Session, SessionError};

const N_SESSIONS: usize = 8;
const MAX_QUEUE_DEPTH: usize = 256;
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);

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

/// Result of one protocol operation.
/// `'d` is the received datagram, `'o` the output buffer; only one is ever
/// borrowed by a given value.
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
    /// A handshake we sent is still awaiting its response, so this call did
    /// nothing. The caller should wait: resending would discard the initiation
    /// already in flight.
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
        local_index: u32,
    ) -> Self {
        Self {
            sessions: SessionTable::default(),
            control: Mutex::new(ControlState {
                handshake: handshake::Handshake::new(
                    static_private,
                    peer_static_public,
                    preshared_key,
                    local_index,
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

            self.tx_bytes.fetch_add(src.len() as u64, Ordering::Relaxed);
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

    /// Sends the oldest queued packet. Called with an empty input until it
    fn send_queued_packet<'d, 'a>(&self, dst: &'a mut [u8]) -> TunnelResult<'d, 'a> {
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
            self.tx_bytes.fetch_add(src.len() as u64, Ordering::Relaxed);
            return TunnelResult::WriteToNetwork(&mut dst[..written]);
        }

        // Session disappeared meanwhile: put the packet back at the front.
        let mut control = self.control();
        if control.packet_queue.len() < MAX_QUEUE_DEPTH {
            control.packet_queue.push_front(src);
        }
        TunnelResult::NoSession
    }

    /// Locks the control state.
    ///
    /// A poisoned lock means a thread panicked mid-update, leaving state we
    /// cannot repair here. Panicking lets the worker unwind and be replaced
    /// rather than serving a corrupt tunnel.
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
        if datagram.is_empty() {
            // Nothing to decrypt; the queued packets are written to `dst`.
            return self.send_queued_packet(dst);
        }

        match Packet::parse_mut(datagram) {
            Ok(PacketMut::Data(packet)) => self.handle_data(packet),
            Ok(PacketMut::HandshakeInitiation(packet)) => self.handle_handshake_init(packet, dst),
            Ok(PacketMut::HandshakeResponse(packet)) => {
                self.handle_handshake_response(packet, dst)
            }
            Ok(PacketMut::CookieReply(packet)) => self.handle_cookie_reply(packet, dst),
            Err(error) => TunnelResult::InvalidPacket(error),
        }
    }

    /// Decrypts a transport-data packet in place
    /// The returned plaintext borrows the datagram buffer, not `dst`.
    fn handle_data<'a, 'o>(&self, packet: DataPacket<'a>) -> TunnelResult<'a, 'o> {
        let Some(session) = self.current_session() else {
            return TunnelResult::NoSession;
        };

        // The payload is decrypted in place inside the received datagram
        let plaintext = match session.receive_packet_data(packet) {
            Ok(plaintext) => plaintext,
            Err(error) => return error.into(),
        };
        let written = plaintext.len();

        self.control().timers.last_packet_received = Some(Instant::now());

        self.rx_bytes.fetch_add(written as u64, Ordering::Relaxed);
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
        let session = match control
            .handshake
            .format_handshake_response(response, &initiation)
        {
            Ok(session) => session,
            Err(error) => return TunnelResult::InvalidPacket(error.into()),
        };

        // The responder can read the initiator's traffic as soon as it replies.
        self.install_session(session);

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

        let session = match control.handshake.consume_response(&response) {
            Ok(session) => session,
            Err(error) => return TunnelResult::InvalidPacket(error.into()),
        };

        // The initiator proves liveness with a keepalive, which also tells the
        // responder the session is usable.
        let written = match session.format_packet_data(&[], dst) {
            Ok(written) => written,
            Err(error) => return error.into(),
        };

        self.install_session(session);

        let now = Instant::now();
        control.timers.last_packet_received = Some(now);
        control.timers.last_packet_sent = Some(now);
        control.timers.last_handshake = Some(now);
        drop(control);

        TunnelResult::WriteToNetwork(&mut dst[..written])
    }

    /// Stores the cookie from a cookie reply for use in `mac2` (§5.4.4/§5.4.7).
    fn handle_cookie_reply<'d, 'a>(
        &self,
        _reply: CookieReply<'_>,
        _dst: &'a mut [u8],
    ) -> TunnelResult<'d, 'a> {
        // TODO(M4): store the cookie together with its receive time.
        TunnelResult::InvalidPacket(WireGuardError::InvalidPacket)
    }

    /// Advances timers and acts on whatever came due: retransmitting a stalled
    /// handshake, starting a new one, or sending a keepalive.
    ///
    /// `dst` must satisfy the same contract as `encapsulate`. The tunnel starts
    /// its own handshake here, so the caller never calls
    /// `format_handshake_initiation` to recover; it only sends what it is given.
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

    /// Decides what an established (or absent) session requires.
    ///
    /// Split out because both the "no initiation in flight" timer path and the
    /// tests want the same reasoning.
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

    /// Registers a new session in the ring and makes it current.
    fn install_session(&self, session: Session) {
        let slot = session.local_id as usize % N_SESSIONS;
        let session = Arc::new(session);
        self.sessions.slots[slot].store(Some(Arc::clone(&session)));
        self.sessions.current.store(Some(session));
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
        let mut empty: [u8; 0] = [];
        assert!(matches!(
            a.decapsulate(&mut empty, &mut buf),
            TunnelResult::NoSession
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

    #[test]
    #[should_panic]
    fn undersized_dst_panics_inside_the_caller() {
        let mut small = [0u8; 8];
        let (mut a, _b) = pair();
        let _ = a.encapsulate(b"hello", &mut small);
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
}
