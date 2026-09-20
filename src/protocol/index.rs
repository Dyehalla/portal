use super::primitives::RAND;

/// Bits reserved for the peer part of an index.
pub const PEER_BITS: u32 = 24;
/// Bits reserved for the cyclic session counter.
pub const SESSION_BITS: u32 = 8;

/// Largest peer number: 2^24 - 1, matching BoringTun's 16M peers per device.
pub const MAX_PEERS: u32 = (1 << PEER_BITS) - 1;
/// The session counter wraps after this many handshakes.
pub const SESSION_CYCLE: u32 = 1 << SESSION_BITS;

const SESSION_MASK: u32 = SESSION_CYCLE - 1;

/// The all-zero index is reserved: it means "no peer assigned", so an index of
/// zero can never be confused with a valid one.
const FIRST_VALID_PEER: u32 = 1;

/// Hands out the 24-bit peer part of an index, shared by every peer.
pub struct IndexAllocator {
    /// Next peer number; pseudo-random so a peer cannot guess another's index.
    lfsr: u32,
    /// The seed `lfsr` started from, used to detect exhaustion.
    initial: u32,
    /// XOR mask applied to the output stream.
    mask: u32,
    used: u32,
}

impl Default for IndexAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexAllocator {
    /// Seeds the generator from the system RNG.
    pub fn new() -> Self {
        let mut seed = [0u8; 4];
        RAND(&mut seed);
        let mask = u32::from_le_bytes(seed);

        let mut lfsr = 0;
        while lfsr == 0 {
            let mut bytes = [0u8; 4];
            RAND(&mut bytes);
            lfsr = u32::from_le_bytes(bytes) & MAX_PEERS;
        }

        Self {
            lfsr,
            initial: lfsr,
            mask,
            used: 0,
        }
    }

    /// Hands out the next peer number, or `None` when all 2^24 are taken.
    /// The LFSR visits every non-zero 24-bit value once before repeating.
    pub fn next_peer(&mut self) -> Option<u32> {
        if self.used >= MAX_PEERS {
            return None;
        }

        // A 24-bit polynomial, arbitrarily chosen to inject bit flips.
        const LFSR_POLY: u32 = 0xd80000;

        let value = self.lfsr - 1; // lfsr is never zero
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1)) & LFSR_POLY);
        self.used += 1;

        // From a 24-bit seed the shift-and-xor cannot set bit 24 or above, so
        // `value` always fits in `PEER_BITS`; the mask is applied afterwards.
        let folded = value ^ (value & !MAX_PEERS);
        let peer = (folded ^ self.mask) & MAX_PEERS;
        Some(if peer == 0 { 1 } else { peer })
    }

    /// True once every peer number has been handed out.
    pub fn is_exhausted(&self) -> bool {
        self.used >= MAX_PEERS
    }

    /// Number of peer numbers handed out so far.
    pub fn allocated(&self) -> u32 {
        self.used
    }
}

/// Advances the session byte of a receiver index, leaving the peer part alone:
/// a rehandshake would otherwise reuse the index it replaces.
#[derive(Debug, Clone)]
pub struct SessionIndex {
    /// The last index handed out; its high bits are this peer's identity.
    next: u32,
}

impl SessionIndex {
    /// Starts a generator for `peer_index`, which must come from
    /// [`IndexAllocator::next_peer`] and fit in `PEER_BITS`; first index is 1.
    pub fn new(peer_index: u32) -> Self {
        debug_assert!(
            peer_index <= MAX_PEERS,
            "peer index must fit in {PEER_BITS} bits"
        );
        Self {
            next: (peer_index & MAX_PEERS) << SESSION_BITS,
        }
    }

    /// Returns the next index: same peer bits, session byte incremented.
    pub fn next_index(&mut self) -> u32 {
        let index = self.next;
        let session = index & SESSION_MASK;
        self.next = (index & !SESSION_MASK) | session.wrapping_add(1);
        self.next
    }

    /// The current (not yet handed out) index, for diagnostics and tests.
    pub fn peek(&self) -> u32 {
        self.next
    }
}

/// The peer number an index belongs to.
pub fn peer_of(index: u32) -> u32 {
    index >> SESSION_BITS
}

/// The session byte of an index.
pub fn session_of(index: u32) -> u32 {
    index & SESSION_MASK
}
