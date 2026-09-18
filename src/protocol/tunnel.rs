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

/// Buffer size that always suffices for any packet `Tunnel` can produce: the
/// largest datagram plus the data-path overhead. Callers should size a reusable
/// `dst` with this, since the buffer contract is not checked.
pub const MAX_PACKET_SIZE: usize = MAX_TRANSPORT_PAYLOAD + DATA_OVERHEAD;

/// Result of one protocol operation.
///
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
    /// The sending counter is exhausted or the session is too old: the tunnel
    /// needs a new handshake before it can carry more data.
    RekeyRequired,
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
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnelResult<'_, 'a> {
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
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnelResult<'_, 'a> {
        let mut control = self.control();

        if control.handshake.has_pending_response() && !force_resend {
            return TunnelResult::RekeyRequired;
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
    fn queue_packet(&mut self, src: &[u8]) {
        let mut control = self.control();
        if control.packet_queue.len() < MAX_QUEUE_DEPTH {
            control.packet_queue.push_back(src.to_vec());
        }
    }

    /// Sends the oldest queued packet. Called with an empty input until it
    fn send_queued_packet<'d, 'a>(&mut self, dst: &'a mut [u8]) -> TunnelResult<'d, 'a> {
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
        TunnelResult::RekeyRequired
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
        &mut self,
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
    fn handle_data<'a, 'o>(&mut self, packet: DataPacket<'a>) -> TunnelResult<'a, 'o> {
        let Some(session) = self.current_session() else {
            return TunnelResult::RekeyRequired;
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
        &mut self,
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
        &mut self,
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
        &mut self,
        _reply: CookieReply<'_>,
        _dst: &'a mut [u8],
    ) -> TunnelResult<'d, 'a> {
        // TODO(M4): store the cookie together with its receive time.
        TunnelResult::InvalidPacket(WireGuardError::InvalidPacket)
    }

    /// Advances timers and emits a keepalive packet when it is due.
    ///
    /// `dst` must satisfy the same contract as `encapsulate`.
    pub fn update_timers<'a>(&mut self, now: Instant, dst: &'a mut [u8]) -> TunnelResult<'_, 'a> {
        let Some(session) = self.current_session() else {
            return TunnelResult::RekeyRequired;
        };
        if now
            .checked_duration_since(session.created_at)
            .is_some_and(|age| age >= REJECT_AFTER_TIME)
        {
            return TunnelResult::RekeyRequired;
        }

        let due = {
            let control = self.control();
            let Some(interval) = control.timers.persistent_keepalive else {
                return TunnelResult::Done;
            };
            let last_activity = control
                .timers
                .last_packet_sent
                .max(control.timers.last_packet_received);
            !last_activity.is_some_and(|last| {
                now.checked_duration_since(last)
                    .is_none_or(|age| age < interval)
            })
        };
        if !due {
            return TunnelResult::Done;
        }

        self.encapsulate(&[], dst)
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

