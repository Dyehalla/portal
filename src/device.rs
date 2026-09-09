//! Device-level state, split by lifetime (whitepaper §6):
//! - `Device`  — global: static identity, cookie secret, peer table, index table.
//! - `Peer`    — configured facts + per-peer session slots.
//! - `Session` — everything one handshake produced; erased after REJECT_AFTER_TIME.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use aws_lc_rs::error::Unspecified;

use crate::noise::{Key, PrivateKey};
use crate::noise::noise_primitives::{DH_PUBKEY, KEY_LEN, RAND, TIMESTAMP_LEN};

// Timers

pub const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
pub const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1; // 2^64 - 2^13 - 1
pub const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
pub const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
pub const REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
pub const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
pub const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
pub const COOKIE_SECRET_LIFETIME: Duration = Duration::from_secs(120);

/// Which of the peer's three session slots an entry refers to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SessionSlot {
    /// Established session, used for sending.
    Current,
    /// Old session kept briefly after rekey so in-flight packets aren't lost.
    Previous,
    /// Handshake in progress, not usable for transport data yet.
    Pending,
}

pub struct Device {
    private_key: PrivateKey,
    pub public_key: Key,

    cookie_secret: Key,

    /// Peers keyed by their static public key.
    pub peers: HashMap<Key, Peer>,

    /// sender_index -> (peer public key, slot). Filled when a session is
    /// registered; lookup target for transport data packets and
    /// handshake responses (which only carry our receiver index).
    index_table: HashMap<u32, (Key, SessionSlot)>,
}

impl Device {
    pub fn new(private_key: PrivateKey) -> Self {
        let public_key = DH_PUBKEY(&private_key);
        let mut cookie_secret = [0u8; 32];
        RAND(&mut cookie_secret);

        Self {
            private_key,
            public_key,
            cookie_secret,
            peers: HashMap::new(),
            index_table: HashMap::new(),
        }
    }
}

pub struct Peer {
    /// Static public key — the peer's identity.
    public_key: Key,

    /// None means "not set", which on the wire is the all-zero key
    preshared_key: Option<Key>,

    /// Cryptokey routing: subnets this peer is allowed to source packets from
    /// (inbound check) and that we route to it (outbound).
    allowed_ips: Vec<AllowedIp>,

    /// May be absent (peer initiates); updated by roaming on valid packets
    endpoint: Option<SocketAddr>,

    persistent_keepalive: Option<Duration>,

    /// Newest TAI64N timestamp accepted in a handshake initiation
    last_handshake_timestamp: Option<[u8; TIMESTAMP_LEN]>,

    /// When the last handshake completed — drives passive keepalive and
    /// "respond, don't initiate" rekey decisions.
    last_handshake_at: Option<Instant>,

    /// The cookie WE received from the peer (whitepaper's
    /// last_received_cookie), used to fill MAC2 when we send under load.
    /// (cookie, received_at) — cookies expire with the secret that made them.
    last_received_cookie: Option<(Key, Instant)>,

    /// Current, previous and pending sessions, indexed by SessionSlot.
    sessions: [Option<Session>; 3],
}

impl Peer {
    pub fn new(public_key: Key) -> Self {
        Self {
            public_key,
            preshared_key: None,
            allowed_ips: Vec::new(),
            endpoint: None,
            persistent_keepalive: None,
            last_handshake_timestamp: None,
            last_handshake_at: None,
            last_received_cookie: None,
            sessions: [None, None, None],
        }
    }

}

pub struct Session {
    local_index: u32,
    ephemeral_priv: Option<PrivateKey>,
    ephemeral_pub: Option<Key>,
}

#[derive(Clone, Copy, Debug)]
pub struct AllowedIp {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl AllowedIp {
    pub fn matches(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let (a, b) = (u32::from(a), u32::from(b));
                self.cidr >= 32 || a >> (32 - self.cidr) == b >> (32 - self.cidr)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let (a, b) = (u128::from(a), u128::from(b));
                self.cidr >= 128 || a >> (128 - self.cidr) == b >> (128 - self.cidr)
            }
            _ => false, // address family mismatch can never match
        }
    }
}
