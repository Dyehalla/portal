use std::time::Instant;

use super::cookie::{self, StoredCookie};
use super::packet::{
    HANDSHAKE_INIT_LEN, HANDSHAKE_RESPONSE_LEN, HandshakeInitiation, HandshakeResponse,
};
use super::primitives::{
    AEAD_DECRYPT, AEAD_ENCRYPT, DH, DH_GENERATE, DH_PRIVATE, DH_PUBKEY, DhError, HASH, KDF1, KDF2,
    KDF3, LABEL_MAC1, MAC, MAC_KEYED, MAC_LEN, PrivateKey, TAI64N, TIMESTAMP_LEN,
};
use super::session::Session;

//   INITIAL_CHAIN_KEY  = HASH(Construction)
//   INITIAL_CHAIN_HASH = HASH(INITIAL_CHAIN_KEY || Identifier)
const INITIAL_CHAIN_KEY: [u8; 32] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];
const INITIAL_CHAIN_HASH: [u8; 32] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

// ===== Message 1 (initiation) layout =====
//
//   0  type(1) || reserved(3)
//   4  sender(4)
//   8  ephemeral(32)
//  40  encrypted_static(48)
//  88  encrypted_timestamp(28)
// 116  mac1(16)          <- msg_alpha is [0..116)
// 132  mac2(16)          <- msg_beta  is [0..132)
const MSG_HANDSHAKE_INITIATION: u8 = 1;
const OFF_SENDER: usize = 4;
const OFF_EPHEMERAL: usize = 8;
const OFF_STATIC: usize = 40;
const OFF_TIMESTAMP: usize = 88;
const OFF_MAC1: usize = 116;
const OFF_MAC2: usize = 132;

// ===== Message 2 (response) layout =====
//
//   0  type(1) || reserved(3)
//   4  sender(4)
//   8  receiver(4)
//  12  ephemeral(32)
//  44  encrypted_nothing(16)
//  60  mac1(16)          <- msg_alpha is [0..60)
//  76  mac2(16)          <- msg_beta  is [0..76)
const MSG_HANDSHAKE_RESPONSE: u8 = 2;
const R_OFF_SENDER: usize = 4;
const R_OFF_RECEIVER: usize = 8;
const R_OFF_EPHEMERAL: usize = 12;
const R_OFF_EMPTY: usize = 44;
const R_OFF_MAC1: usize = 60;
const R_OFF_MAC2: usize = 76;

/// Failure while building or consuming a handshake message. `Dh`,
/// `NoInitiationInFlight` and `ResponseNotForUs` are local, not peer attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    /// A Diffie-Hellman step was refused, so no message can be built. Not
    /// caused by anything the peer sent in this message.
    Dh(DhError),
    /// `encrypted_static` failed to authenticate: forged, corrupt, or not ours.
    InitiationNotAuthentic,
    /// The initiation authenticated, but claims a static key other than our
    /// peer's, so this tunnel is not the one it was built for.
    InitiationForAnotherPeer,
    /// The initiation's `encrypted_timestamp` failed to authenticate.
    TimestampNotAuthentic,
    /// The initiation's timestamp is not newer than the greatest accepted from
    /// this peer: a replay of a message we have already answered.
    TimestampReplayed,
    /// The response's `encrypted_nothing` failed to authenticate.
    ResponseNotAuthentic,
    /// The response authenticated, but answers an initiation that is not the
    /// one in flight: a stale or duplicate response, not a forgery.
    ResponseNotForUs,
    /// No initiation is awaiting a response, so there is nothing to consume.
    NoInitiationInFlight,
}

impl From<DhError> for HandshakeError {
    fn from(error: DhError) -> Self {
        Self::Dh(error)
    }
}

/// mac1 key: `HASH(LABEL_MAC1 || Sm'_pub)` — the *peer's* static public key.
/// Constant for a given peer, so callers may cache it.
pub fn mac1_key(peer_static_public: &[u8; 32]) -> [u8; 32] {
    HASH(&[LABEL_MAC1, peer_static_public])
}

/// Recovers an initiation's sender without knowing which peer sent it
/// (§5.4.2). Only a DH against our static key opens the sealed field.
pub fn parse_handshake_anon(
    static_private: &[u8; 32],
    static_public: &[u8; 32],
    initiation: &HandshakeInitiation<'_>,
) -> Result<[u8; 32], HandshakeError> {
    // Ci := Hash(Construction); Hi := Hash(Ci || Identifier)
    // Hi := Hash(Hi || Srpub)
    let mut chaining_key = INITIAL_CHAIN_KEY;
    let mut hash = HASH(&[&INITIAL_CHAIN_HASH, static_public]);

    // Ci := Kdf1(Ci, Eipub); Hi := Hash(Hi || Eipub)
    let initiator_ephemeral = initiation.ephemeral;
    chaining_key = KDF1(&chaining_key, initiator_ephemeral);
    hash = HASH(&[&hash, initiator_ephemeral]);

    // (Ci, κ) := Kdf2(Ci, DH(Srpriv, Eipub))
    // msg.static := Aead(κ, 0, Sipub, Hi)
    let private = DH_PRIVATE(static_private);
    let dh = DH(&private, initiator_ephemeral)?;
    let (_, key) = KDF2(&chaining_key, &dh);

    let plain = AEAD_DECRYPT(&key, 0, &hash, initiation.encrypted_static)
        .map_err(|_| HandshakeError::InitiationNotAuthentic)?;

    plain
        .as_slice()
        .try_into()
        .map_err(|_| HandshakeError::InitiationNotAuthentic)
}

pub struct Handshake {
    pub static_private: [u8; 32],
    pub peer_static_public: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// The index claimed by the initiation we await a response for.
    /// The session built by `consume_response` must be filed under it.
    pending_index: Option<u32>,
    /// The `mac1` of the initiation we last sent, needed to unwrap a cookie
    /// reply: the reply's AAD is exactly this value.
    last_sent_mac1: Option<[u8; MAC_LEN]>,
    /// A cookie received from the peer, put into `mac2` of later messages.
    cookie: Option<StoredCookie>,
    /// The greatest authenticated timestamp seen from this peer: an initiation
    /// must beat it, which is what makes a captured message die on replay.
    last_timestamp: Option<[u8; TIMESTAMP_LEN]>,
    ephemeral_private: Option<PrivateKey>,
    chaining_key: Option<[u8; 32]>,
    hash: Option<[u8; 32]>,
    last_started: Option<Instant>,
}

impl Handshake {
    pub fn new(
        static_private: [u8; 32],
        peer_static_public: [u8; 32],
        preshared_key: Option<[u8; 32]>,
    ) -> Self {
        Self {
            static_private,
            peer_static_public,
            preshared_key,
            pending_index: None,
            last_sent_mac1: None,
            cookie: None,
            last_timestamp: None,
            ephemeral_private: None,
            chaining_key: None,
            hash: None,
            last_started: None,
        }
    }

    /// Builds handshake initiation (message 1, §5.4.2) into `buf`, returning
    /// its length. `local_index` comes from the device, the one issuer.
    pub fn format_handshake_init(
        &mut self,
        buf: &mut [u8],
        local_index: u32,
    ) -> Result<usize, HandshakeError> {
        // Ci := Hash(Construction); Hi := Hash(Ci || Identifier); Hi := Hash(Hi || Srpub)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        let mut hash = HASH(&[&INITIAL_CHAIN_HASH, &self.peer_static_public]);

        // (Eipriv, Eipub) := DH-Generate()
        // Ci := Kdf1(Ci, Eipub); Hi := Hash(Hi || Eipub)
        let (ephemeral_private, ephemeral_public) = DH_GENERATE();
        chaining_key = KDF1(&chaining_key, &ephemeral_public);
        hash = HASH(&[&hash, &ephemeral_public]);

        // (Ci, κ) := Kdf2(Ci, DH(Eipriv, Srpub))
        // msg.static := Aead(κ, 0, Sipub, Hi)
        let static_private = DH_PRIVATE(&self.static_private);
        let dh = DH(&ephemeral_private, &self.peer_static_public)?;
        let (ck, key) = KDF2(&chaining_key, &dh);
        chaining_key = ck;
        let encrypted_static = AEAD_ENCRYPT(&key, 0, &hash, &DH_PUBKEY(&static_private));
        hash = HASH(&[&hash, &encrypted_static]);

        // (Ci, κ) := Kdf2(Ci, DH(Sipriv, Srpub))
        // msg.timestamp := Aead(κ, 0, Timestamp(), Hi)
        let dh = DH(&static_private, &self.peer_static_public)?;
        let (ck, key) = KDF2(&chaining_key, &dh);
        chaining_key = ck;
        let encrypted_timestamp = AEAD_ENCRYPT(&key, 0, &hash, &TAI64N());
        hash = HASH(&[&hash, &encrypted_timestamp]);

        let msg = &mut buf[..HANDSHAKE_INIT_LEN];
        msg[0] = MSG_HANDSHAKE_INITIATION;
        msg[1..OFF_SENDER].fill(0); // reserved
        msg[OFF_SENDER..OFF_EPHEMERAL].copy_from_slice(&local_index.to_le_bytes());
        msg[OFF_EPHEMERAL..OFF_STATIC].copy_from_slice(&ephemeral_public);
        msg[OFF_STATIC..OFF_TIMESTAMP].copy_from_slice(&encrypted_static);
        msg[OFF_TIMESTAMP..OFF_MAC1].copy_from_slice(&encrypted_timestamp);

        // msg.mac1 := Mac(Hash(Label-Mac1 || Srpub), msg_alpha)
        let mac1 = MAC(&mac1_key(&self.peer_static_public), &msg[..OFF_MAC1]);
        msg[OFF_MAC1..OFF_MAC2].copy_from_slice(&mac1);

        // msg.mac2 := Mac(cookie, msg[..mac2]) with a cookie, else 0^16.
        let now = Instant::now();
        let mac2 = self.mac2(now, &msg[..OFF_MAC2]);
        msg[OFF_MAC2..].copy_from_slice(&mac2);

        // A cookie reply is unwrapped with the mac1 it answers, so keep it.
        self.last_sent_mac1 = Some(mac1);

        self.ephemeral_private = Some(ephemeral_private);
        self.chaining_key = Some(chaining_key);
        self.hash = Some(hash);
        self.last_started = Some(now);
        // The response must come back addressed to exactly this index.
        self.pending_index = Some(local_index);

        Ok(HANDSHAKE_INIT_LEN)
    }

    /// Builds handshake response into `buf`, returning the session that reads
    /// the initiator's traffic. The response is written under `local_index`.
    pub fn format_handshake_response(
        &mut self,
        buf: &mut [u8],
        initiation: &HandshakeInitiation<'_>,
        local_index: u32,
    ) -> Result<Session, HandshakeError> {
        let static_private = DH_PRIVATE(&self.static_private);
        let static_public = DH_PUBKEY(&static_private);

        // Replay the initiator's state; "responder's static public" is our own
        // key. Ci := Hash(Construction); Hi := Hash(Ci || Identifier)
        let mut chaining_key = INITIAL_CHAIN_KEY;
        let mut hash = HASH(&[&INITIAL_CHAIN_HASH, &static_public]);

        let initiator_ephemeral = initiation.ephemeral;
        chaining_key = KDF1(&chaining_key, initiator_ephemeral);
        hash = HASH(&[&hash, initiator_ephemeral]);

        // (Cr, κ) := Kdf2(Cr, DH(Srpriv, Eipub)) -> decrypt Sipub
        let dh = DH(&static_private, initiator_ephemeral)?;
        let (ck, key) = KDF2(&chaining_key, &dh);
        chaining_key = ck;
        let initiator_static = AEAD_DECRYPT(&key, 0, &hash, initiation.encrypted_static)
            .map_err(|_| HandshakeError::InitiationNotAuthentic)?;
        if initiator_static.as_slice() != self.peer_static_public.as_slice() {
            return Err(HandshakeError::InitiationForAnotherPeer);
        }
        hash = HASH(&[&hash, initiation.encrypted_static]);

        // (Cr, κ) := Kdf2(Cr, DH(Srpriv, Sipub)) -> decrypt Timestamp()
        let dh = DH(&static_private, &self.peer_static_public)?;
        let (ck, key) = KDF2(&chaining_key, &dh);
        chaining_key = ck;
        let timestamp = AEAD_DECRYPT(&key, 0, &hash, initiation.encrypted_timestamp)
            .map_err(|_| HandshakeError::TimestampNotAuthentic)?;
        let timestamp: [u8; TIMESTAMP_LEN] = timestamp
            .as_slice()
            .try_into()
            .map_err(|_| HandshakeError::TimestampNotAuthentic)?;

        // Replay defence (§5.4.4): the timestamp must be strictly greater
        // than the greatest accepted, so a captured initiation cannot be
        // presented again to mint fresh sessions.
        if self.last_timestamp.is_some_and(|last| timestamp <= last) {
            return Err(HandshakeError::TimestampReplayed);
        }
        hash = HASH(&[&hash, initiation.encrypted_timestamp]);

        // (Erpriv, Erpub) := DH-Generate()
        // Cr := Kdf1(Cr, Erpub); Hr := Hash(Hr || Erpub)
        let (ephemeral_private, ephemeral_public) = DH_GENERATE();
        chaining_key = KDF1(&chaining_key, &ephemeral_public);
        hash = HASH(&[&hash, &ephemeral_public]);

        // Cr := Kdf1(Cr, DH(Erpriv, Eipub))
        // Cr := Kdf1(Cr, DH(Erpriv, Sipub))
        chaining_key = KDF1(&chaining_key, &DH(&ephemeral_private, initiator_ephemeral)?);
        chaining_key = KDF1(
            &chaining_key,
            &DH(&ephemeral_private, &self.peer_static_public)?,
        );

        // (Cr, τ, κ) := Kdf3(Cr, Q); Hr := Hash(Hr || τ)
        // msg.empty := Aead(κ, 0, ε, Hr)
        let psk = self.preshared_key.unwrap_or([0u8; 32]);
        let (ck, tau, key) = KDF3(&chaining_key, &psk);
        chaining_key = ck;
        hash = HASH(&[&hash, &tau]);
        let encrypted_nothing = AEAD_ENCRYPT(&key, 0, &hash, &[]);

        let msg = &mut buf[..HANDSHAKE_RESPONSE_LEN];
        msg[0] = MSG_HANDSHAKE_RESPONSE;
        msg[1..R_OFF_SENDER].fill(0); // reserved
        msg[R_OFF_SENDER..R_OFF_RECEIVER].copy_from_slice(&local_index.to_le_bytes());
        msg[R_OFF_RECEIVER..R_OFF_EPHEMERAL]
            .copy_from_slice(&initiation.sender_index.to_le_bytes());
        msg[R_OFF_EPHEMERAL..R_OFF_EMPTY].copy_from_slice(&ephemeral_public);
        msg[R_OFF_EMPTY..R_OFF_MAC1].copy_from_slice(&encrypted_nothing);

        // msg.mac1 := Mac(Hash(Label-Mac1 || Sipub), msg_alpha)
        let mac1 = MAC(&mac1_key(&self.peer_static_public), &msg[..R_OFF_MAC1]);
        msg[R_OFF_MAC1..R_OFF_MAC2].copy_from_slice(&mac1);

        // msg.mac2 := Mac(cookie, msg[..mac2]) with a cookie, else 0^16.
        let now = Instant::now();
        let mac2 = self.mac2(now, &msg[..R_OFF_MAC2]);
        msg[R_OFF_MAC2..].copy_from_slice(&mac2);
        self.last_sent_mac1 = Some(mac1);

        // The responder's ephemeral key is not retained: `ephemeral_private`
        // tracks *our* initiation awaiting a response, and we await nothing.
        self.last_started = Some(now);
        // The watermark advances only now: a message we did not fully accept
        // must not block a genuine retry of the same timestamp.
        self.last_timestamp = Some(timestamp);

        // (T_send, T_recv) := Kdf2(Cr, ε) — as responder, tau_2 sends.
        let (recv, send) = KDF2(&chaining_key, &[]);
        Ok(Session::new(
            local_index,
            initiation.sender_index,
            &send,
            &recv,
        ))
    }

    /// `msg.mac2`: `MAC(cookie, message)` when a fresh cookie is held, else
    /// zero. Sending zero is correct, it simply invites a cookie reply (§5.4.4).
    fn mac2(&self, now: Instant, message: &[u8]) -> [u8; MAC_LEN] {
        match self.cookie {
            Some(stored) if !stored.is_expired(now) => MAC_KEYED(&stored.cookie, message),
            _ => [0u8; MAC_LEN],
        }
    }

    /// Stores a cookie received from the peer, replacing any older one.
    pub fn store_cookie(&mut self, cookie: cookie::Cookie, now: Instant) {
        self.cookie = Some(StoredCookie {
            cookie,
            received_at: now,
        });
    }

    /// The `mac1` of the last message we built, needed to unwrap a cookie
    /// reply. `None` before we have sent anything.
    pub fn last_sent_mac1(&self) -> Option<&[u8; MAC_LEN]> {
        self.last_sent_mac1.as_ref()
    }

    /// The index we claimed in the initiation awaiting a response.
    pub fn pending_index(&self) -> Option<u32> {
        self.pending_index
    }

    /// True while an initiation we sent is still awaiting a response.
    pub fn has_pending_response(&self) -> bool {
        self.ephemeral_private.is_some()
    }

    /// Verifies a handshake response and derives the transport session (§5.4.5).
    /// Consumes the pending initiation, on failure as well as success.
    pub fn consume_response(
        &mut self,
        response: &HandshakeResponse<'_>,
    ) -> Result<Session, HandshakeError> {
        let ephemeral_private = self
            .ephemeral_private
            .take()
            .ok_or(HandshakeError::NoInitiationInFlight)?;
        // Consumed on failure too: the initiation in flight is spent either way.
        let local_index = self
            .pending_index
            .take()
            .ok_or(HandshakeError::NoInitiationInFlight)?;

        // We are the initiator, so our saved state continues the chain.
        // Cr := Kdf1(Cr, Erpub); Hr := Hash(Hr || Erpub)
        let mut chaining_key = self
            .chaining_key
            .take()
            .ok_or(HandshakeError::NoInitiationInFlight)?;
        let mut hash = self
            .hash
            .take()
            .ok_or(HandshakeError::NoInitiationInFlight)?;

        let responder_ephemeral = response.ephemeral;
        chaining_key = KDF1(&chaining_key, responder_ephemeral);
        hash = HASH(&[&hash, responder_ephemeral]);

        // Cr := Kdf1(Cr, DH(Eipriv, Erpub))
        // Cr := Kdf1(Cr, DH(Sipriv, Erpub))
        chaining_key = KDF1(&chaining_key, &DH(&ephemeral_private, responder_ephemeral)?);
        let static_private = DH_PRIVATE(&self.static_private);
        chaining_key = KDF1(&chaining_key, &DH(&static_private, responder_ephemeral)?);

        // (Cr, τ, κ) := Kdf3(Cr, Q); Hr := Hash(Hr || τ)
        // msg.empty := Aead(κ, 0, ε, Hr)
        let psk = self.preshared_key.unwrap_or([0u8; 32]);
        let (ck, tau, key) = KDF3(&chaining_key, &psk);
        chaining_key = ck;
        hash = HASH(&[&hash, &tau]);
        AEAD_DECRYPT(&key, 0, &hash, response.encrypted_nothing)
            .map_err(|_| HandshakeError::ResponseNotAuthentic)?;

        // The response must be addressed to the initiation we sent. It already
        // authenticated, so a mismatch is a stale response, not a forgery.
        if response.receiver_index != local_index {
            return Err(HandshakeError::ResponseNotForUs);
        }

        // (T_send, T_recv) := Kdf2(Cr, ε) — as initiator, tau_1 sends.
        let (send, recv) = KDF2(&chaining_key, &[]);
        Ok(Session::new(
            local_index,
            response.sender_index,
            &send,
            &recv,
        ))
    }
}

/// Hand-rolled so the raw key material does not outlive the handshake.
impl Drop for Handshake {
    fn drop(&mut self) {
        self.static_private.fill(0);
        if let Some(psk) = self.preshared_key.as_mut() {
            psk.fill(0);
        }
        if let Some(key) = self.chaining_key.as_mut() {
            key.fill(0);
        }
    }
}

impl Default for Handshake {
    fn default() -> Self {
        Self::new([0; 32], [0; 32], None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::packet::Packet;

    fn handshake(peer_static_public: [u8; 32]) -> Handshake {
        Handshake::new([7u8; 32], peer_static_public, None)
    }

    #[test]
    fn builds_an_initiation_for_a_valid_peer_key() {
        let mut hs = handshake([9u8; 32]);
        let mut buf = [0u8; HANDSHAKE_INIT_LEN];

        let written = hs.format_handshake_init(&mut buf, 1).unwrap();
        assert_eq!(written, HANDSHAKE_INIT_LEN);
        assert_eq!(buf[0], MSG_HANDSHAKE_INITIATION);
        // Reserved bytes must be zero.
        assert_eq!(&buf[1..4], &[0, 0, 0]);
        // The sender index is the one the device's allocator supplied, so the
        // message and the claim can never disagree.
        assert_eq!(u32::from_le_bytes(buf[4..8].try_into().unwrap()), 1);
        // mac2 is zero without a cookie.
        assert_eq!(&buf[OFF_MAC2..], &[0u8; 16]);
        assert!(hs.has_pending_response());
    }

    #[test]
    fn a_low_order_peer_key_fails_instead_of_panicking() {
        // The all-zero key is a low-order point: X25519 with it yields an
        // all-zero secret, which aws-lc-rs refuses. Peer-triggerable.
        let mut hs = handshake([0u8; 32]);
        let mut buf = [0u8; HANDSHAKE_INIT_LEN];

        assert_eq!(
            hs.format_handshake_init(&mut buf, 1).unwrap_err(),
            HandshakeError::Dh(DhError::InvalidPeerKey)
        );
    }

    #[test]
    fn a_rejected_initiation_leaves_no_pending_state() {
        // A failed build must not look like an in-flight handshake, otherwise
        // the rekey timer would wait forever on a response that cannot come.
        let mut hs = handshake([0u8; 32]);
        let mut buf = [0u8; HANDSHAKE_INIT_LEN];

        assert!(hs.format_handshake_init(&mut buf, 1).is_err());
        assert!(!hs.has_pending_response());
    }

    #[test]
    fn answering_an_initiation_does_not_leave_a_pending_response() {
        // The responder awaits nothing, so it must stay free to initiate its
        // own handshake later; otherwise it can never rekey.
        let (mut initiator, mut responder) = peer_pair();
        let mut init = [0u8; HANDSHAKE_INIT_LEN];
        initiator
            .format_handshake_init(&mut init, 0x0a0b_0c0d)
            .unwrap();

        let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
        responder
            .format_handshake_response(&mut response, &parse_initiation(&init), 0x1122_3344)
            .unwrap();

        assert!(!responder.has_pending_response());
    }

    /// A real initiator/responder pair with matching static keys. Returns
    /// (initiator, responder) sharing one derivation of each other's pubkey.
    fn peer_pair() -> (Handshake, Handshake) {
        let initiator_private = [0x11u8; 32];
        let responder_private = [0x22u8; 32];

        let initiator_public = DH_PUBKEY(&DH_PRIVATE(&initiator_private));
        let responder_public = DH_PUBKEY(&DH_PRIVATE(&responder_private));

        let initiator = Handshake::new(initiator_private, responder_public, None);
        let responder = Handshake::new(responder_private, initiator_public, None);
        (initiator, responder)
    }

    fn parse_initiation(buf: &[u8]) -> HandshakeInitiation<'_> {
        match Packet::parse(buf).unwrap() {
            Packet::HandshakeInitiation(initiation) => initiation,
            other => panic!("expected an initiation, got {other:?}"),
        }
    }

    #[test]
    fn answers_a_genuine_initiation_from_the_configured_peer() {
        let (mut initiator, mut responder) = peer_pair();

        let mut init = [0u8; HANDSHAKE_INIT_LEN];
        initiator
            .format_handshake_init(&mut init, 0x0a0b_0c0d)
            .unwrap();

        let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
        let session = responder
            .format_handshake_response(&mut response, &parse_initiation(&init), 0x1122_3344)
            .unwrap();

        // The responder's session reads the initiator's index and writes to ours.
        assert_eq!(session.remote_index, 0x0a0b_0c0d);
        assert_eq!(
            session.local_id, 0x1122_3344,
            "the response must claim our index"
        );
        assert_eq!(response[0], MSG_HANDSHAKE_RESPONSE);
        assert_eq!(&response[1..4], &[0, 0, 0]);
        // Sender is the responder's own index, receiver is the initiator's.
        assert_eq!(
            u32::from_le_bytes(response[R_OFF_SENDER..R_OFF_RECEIVER].try_into().unwrap()),
            0x1122_3344
        );
        assert_eq!(
            u32::from_le_bytes(
                response[R_OFF_RECEIVER..R_OFF_EPHEMERAL]
                    .try_into()
                    .unwrap()
            ),
            0x0a0b_0c0d
        );
        assert_eq!(&response[R_OFF_MAC2..], &[0u8; 16]);
    }

    #[test]
    fn a_tampered_initiation_is_not_authentic() {
        let (mut initiator, mut responder) = peer_pair();

        let mut init = [0u8; HANDSHAKE_INIT_LEN];
        initiator
            .format_handshake_init(&mut init, 0x0a0b_0c0d)
            .unwrap();

        // Flip a byte inside encrypted_static; the AEAD tag must reject it.
        init[OFF_STATIC] ^= 0x01;

        let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
        let error = responder
            .format_handshake_response(&mut response, &parse_initiation(&init), 0x1122_3344)
            .err()
            .expect("a tampered initiation must not be answered");
        assert_eq!(error, HandshakeError::InitiationNotAuthentic);
    }

    #[test]
    fn an_initiation_for_another_peer_names_the_peer_it_was_built_for() {
        let (mut initiator, _responder) = peer_pair();

        let mut init = [0u8; HANDSHAKE_INIT_LEN];
        initiator
            .format_handshake_init(&mut init, 0x0a0b_0c0d)
            .unwrap();

        // A responder configured for a *different* initiator static key: the
        // ciphertext authenticates, but the claimed static is not ours.
        let stranger = DH_PUBKEY(&DH_PRIVATE(&[0x33u8; 32]));
        let mut other = Handshake::new([0x22u8; 32], stranger, None);

        let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
        let error = other
            .format_handshake_response(&mut response, &parse_initiation(&init), 0x1122_3344)
            .err()
            .expect("an initiation for another peer must not be answered");
        assert_eq!(error, HandshakeError::InitiationForAnotherPeer);
    }

    /// A response that authenticates but answers another initiation is stale,
    /// not forged, and must be reported that way.
    #[test]
    fn a_response_for_another_initiation_is_not_a_forgery() {
        let (mut initiator, mut responder) = peer_pair();

        let mut init = [0u8; HANDSHAKE_INIT_LEN];
        initiator
            .format_handshake_init(&mut init, 0x0a0b_0c0d)
            .unwrap();

        let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
        responder
            .format_handshake_response(&mut response, &parse_initiation(&init), 0x1122_3344)
            .unwrap();

        // Retarget the receiver index; `encrypted_nothing` still verifies.
        let genuine = u32::from_le_bytes(
            response[R_OFF_RECEIVER..R_OFF_EPHEMERAL]
                .try_into()
                .unwrap(),
        );
        response[R_OFF_RECEIVER..R_OFF_EPHEMERAL].copy_from_slice(&(genuine + 1).to_le_bytes());

        let parsed = match Packet::parse(&response).unwrap() {
            Packet::HandshakeResponse(response) => response,
            other => panic!("expected a response, got {other:?}"),
        };
        match initiator.consume_response(&parsed) {
            Ok(_) => panic!("a response for another initiation must not be consumed"),
            Err(error) => assert_eq!(error, HandshakeError::ResponseNotForUs),
        }
    }

    #[test]
    fn a_tampered_timestamp_is_reported() {
        let (mut initiator, mut responder) = peer_pair();

        let mut init = [0u8; HANDSHAKE_INIT_LEN];
        initiator
            .format_handshake_init(&mut init, 0x0a0b_0c0d)
            .unwrap();

        // Corrupt encrypted_timestamp only; encrypted_static stays valid, so
        // the failure must be attributed to the timestamp step, not the first.
        init[OFF_TIMESTAMP] ^= 0x01;

        let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
        let error = responder
            .format_handshake_response(&mut response, &parse_initiation(&init), 0x1122_3344)
            .err()
            .expect("a tampered timestamp must not be answered");
        assert_eq!(error, HandshakeError::TimestampNotAuthentic);
    }

    /// The replay defence: a captured initiation presented again must not mint
    /// another session, even though every MAC and AEAD tag still verifies.
    #[test]
    fn a_replayed_initiation_is_refused() {
        let (mut initiator, mut responder) = peer_pair();

        let mut init = [0u8; HANDSHAKE_INIT_LEN];
        initiator
            .format_handshake_init(&mut init, 0x0a0b_0c0d)
            .unwrap();

        let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
        responder
            .format_handshake_response(&mut response, &parse_initiation(&init), 0x1122_3344)
            .expect("the genuine initiation is answered");

        // The very same bytes again: authentic, but not newer.
        let error = responder
            .format_handshake_response(&mut response, &parse_initiation(&init), 0x5566_7788)
            .err()
            .expect("a replayed initiation must not be answered");
        assert_eq!(error, HandshakeError::TimestampReplayed);
    }

    /// The watermark must not overreach: a fresh initiation after an accepted
    /// one is still answered, even if the clock ticks close together.
    #[test]
    fn a_fresh_initiation_after_an_accepted_one_is_still_answered() {
        let (mut initiator, mut responder) = peer_pair();

        for index in [0x0a0b_0c0du32, 0x1122_3344] {
            let mut init = [0u8; HANDSHAKE_INIT_LEN];
            initiator.format_handshake_init(&mut init, index).unwrap();
            let mut response = [0u8; HANDSHAKE_RESPONSE_LEN];
            responder
                .format_handshake_response(&mut response, &parse_initiation(&init), 0x5566_7788)
                .expect("a strictly newer initiation must be answered");
        }
    }
}
