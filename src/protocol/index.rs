//! Allocation of the 32-bit WireGuard receiver indexes, laid out the way
//! BoringTun does it: the top 24 bits identify the peer, the low 8 bits are a
//! cyclic session counter.
//!
//! ```text
//!  31            8 7            0
//! +---------------+--------------+
//! |  peer (24)    | session (8)  |
//! +---------------+--------------+
//! ```
//!
//! The session byte is what makes the session ring work: `N_SESSIONS` is a
//! power of two, so `local_id % N_SESSIONS` is exactly the low bits, and
//! consecutive sessions of one peer land in consecutive slots instead of
//! overwriting each other.
//!
//! Every session keeps the mask bit for its own peer in the high bits, so even
//! once the low byte wraps around after 256 handshakes the index on the wire is
//! never the same as an old one.

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

/// Hands out the 24-bit peer part of an index and advances the session byte.
///
/// One allocator lives in the device and is shared by every peer; each `Tunnel`
/// gets its own generator seeded from the allocated peer number.
#[derive(Debug, Clone)]
pub struct IndexAllocator {
    /// Next peer number to hand out. Values are pseudo-random rather than
    /// sequential so a peer cannot guess another peer's index.
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
    ///
    /// The sequence is an LFSR: it visits every non-zero 24-bit value exactly
    /// once before repeating, so it cannot hand out the same peer twice until
    /// the whole space is exhausted.
    pub fn next_peer(&mut self) -> Option<u32> {
        if self.used >= MAX_PEERS {
            return None;
        }

        // A 24-bit polynomial, arbitrarily chosen to inject bit flips.
        const LFSR_POLY: u32 = 0xd80000;

        let value = self.lfsr - 1; // lfsr is never zero
        self.lfsr = (self.lfsr >> 1) ^ ((0u32.wrapping_sub(self.lfsr & 1)) & LFSR_POLY);
        self.used += 1;

        // `value` is already a 24-bit non-zero number: the shift-and-xor above
        // cannot set a bit at or above position 24 while the seed stays within
        // 24 bits, which `IndexAllocator::new` guarantees. Folding here is
        // belt-and-braces so a stray high bit can never leak into the peer
        // part, and the mask is applied *after* folding: folding alone can
        // collapse a value to zero, which is the one reserved peer number.
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

/// Advances the session byte of a receiver index, leaving the peer part alone.
///
/// This is the counter that makes back-to-back handshakes of one peer produce
/// *different* indexes: without it a rehandshake would reuse the index of the
/// session it is replacing and overwrite that session's ring slot.
#[derive(Debug, Clone)]
pub struct SessionIndex {
    /// The last index handed out; its high bits are this peer's identity.
    next: u32,
}

impl SessionIndex {
    /// Starts a generator for `peer_index`, which must come from
    /// [`IndexAllocator::next_peer`] and therefore fit in `PEER_BITS`.
    ///
    /// The peer part is shifted up into place; the low byte starts at zero and
    /// the first index handed out is 1.
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

/// True when `candidate` is a structurally valid index: a non-zero peer part.
pub fn is_valid(index: u32) -> bool {
    peer_of(index) >= FIRST_VALID_PEER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_allocator_hands_out_distinct_nonzero_peer_numbers() {
        let mut allocator = IndexAllocator::new();
        let mut seen = std::collections::HashSet::new();

        for _ in 0..1000 {
            let peer = allocator.next_peer().expect("space is not exhausted yet");
            assert!(peer <= MAX_PEERS, "peer {peer} exceeds 24 bits");
            assert!(peer != 0, "peer zero is reserved");
            assert!(is_valid(peer << SESSION_BITS), "index must not be all zero");
            assert!(seen.insert(peer), "peer {peer} handed out twice");
        }
    }

    #[test]
    fn consecutive_session_indexes_differ_only_in_the_low_byte() {
        let mut index = SessionIndex::new(0x1234);

        let first = index.next_index();
        let second = index.next_index();

        assert_eq!(peer_of(first), 0x1234);
        assert_eq!(peer_of(second), 0x1234);
        assert_eq!(session_of(first), 1);
        assert_eq!(session_of(second), 2);
        assert_ne!(first, second, "a rehandshake must not reuse the index");
    }

    /// The whole point of the split: consecutive sessions of one peer have to
    /// land in *different* ring slots.
    #[test]
    fn consecutive_indexes_land_in_different_ring_slots() {
        let mut index = SessionIndex::new(0x9abc);
        let slots: Vec<u32> = (0..crate::protocol::tunnel::N_SESSIONS)
            .map(|_| index.next_index() % crate::protocol::tunnel::N_SESSIONS as u32)
            .collect();

        let unique: std::collections::HashSet<u32> = slots.iter().copied().collect();
        assert_eq!(
            unique.len(),
            slots.len(),
            "the first {N} sessions must not collide: {slots:?}",
            N = slots.len()
        );
    }

    #[test]
    fn the_session_byte_wraps_without_touching_the_peer_bits() {
        let mut index = SessionIndex::new(0x0001);
        // Walk the low byte all the way round. 256 draws go from session 1 to
        // session 0 — the wrap happens on the last of them.
        for draw in 0..SESSION_CYCLE {
            let next = index.next_index();
            assert_eq!(peer_of(next), 0x0001, "peer bits must survive draw {draw}");
            assert_eq!(session_of(next), (draw + 1) % SESSION_CYCLE);
        }
        // A further draw continues from the wrapped byte rather than restarting.
        let after_wrap = index.next_index();
        assert_eq!(peer_of(after_wrap), 0x0001);
        assert_eq!(session_of(after_wrap), 1);
    }

    #[test]
    fn exhaustion_is_reported_rather_than_wrapping() {
        let mut allocator = IndexAllocator::new();
        allocator.used = MAX_PEERS - 1;

        assert!(!allocator.is_exhausted());
        assert!(allocator.next_peer().is_some(), "the last one is still free");
        assert!(allocator.is_exhausted());
        assert_eq!(allocator.next_peer(), None, "must not reuse an index");
        assert_eq!(allocator.allocated(), MAX_PEERS);
    }

    #[test]
    fn index_parts_round_trip() {
        let mut allocator = IndexAllocator::new();
        let peer = allocator.next_peer().unwrap();
        let allocated = SessionIndex::new(peer).next_index();

        assert_eq!(peer_of(allocated), peer << SESSION_BITS >> SESSION_BITS);
        assert_eq!(session_of(allocated), 1);
        assert_eq!(allocated >> SESSION_BITS, peer);
        assert!(is_valid(allocated));
    }

    #[test]
    fn a_zero_index_is_never_valid() {
        assert!(!is_valid(0), "index zero is reserved");
        assert!(is_valid(1 << SESSION_BITS), "peer 1, session 0 is valid");
    }
}
