pub mod handshake;
pub mod packet;
pub mod primitives;
pub mod replay;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
pub use packet::{Packet, WireGuardError};
pub use replay::ReplayWindow;
use primitives::AeadKey;

const N_SESSIONS: usize = 8;

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

pub struct Session {
    local_id: u32,
    remote_index: u32,
    peer_index: u32,
    sender: AeadKey,
    receiver: AeadKey,
    sending_counter: AtomicU64,
    replay: Mutex<ReplayWindow>,
    confirmed: AtomicBool,
    created_at: Instant,
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
