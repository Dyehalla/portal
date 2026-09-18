//! WireGuard noise functions. Every function in ALL_CAPS matches whitepaper.
#![allow(non_snake_case)]

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{self, CHACHA20_POLY1305, UnboundKey};
use aws_lc_rs::agreement;
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand;
use blake2::digest::consts::U16;
use blake2::digest::{KeyInit, Mac as MacTrait};
use blake2::{Blake2sMac, Blake2s256, Digest};

pub const CONSTRUCTION: &[u8; 37] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8; 34] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8; 8] = b"mac1----";
pub const LABEL_COOKIE: &[u8; 8] = b"cookie--";

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const TIMESTAMP_LEN: usize = 12;
pub const MAC_LEN: usize = 16;

pub type Key = [u8; KEY_LEN];
pub type PrivateKey = agreement::PrivateKey;
pub type Hash = Key;
pub type Tag = [u8; TAG_LEN];

/// HASH(input1, input2, ...): Blake2s(concat(input1, input2, ...), 32).
pub fn HASH(inputs: &[&[u8]]) -> Hash {
    let mut hasher = Blake2s256::new();
    for input in inputs {
        hasher.update(input);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&digest);
    out
}

/// MAC(key, input): Keyed-Blake2s(key, input, 16), returning 16 bytes of output
pub fn MAC(key: &Key, input: &[u8]) -> Tag {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).expect("key len is const");
    MacTrait::update(&mut mac, input);
    let tag = MacTrait::finalize(mac);
    let mut out = [0u8; MAC_LEN];
    let tag = tag.into_bytes();
    out.copy_from_slice(&tag);
    out
}

pub fn HMAC(key: &[u8], input: &[u8]) -> Key {
    // (1) keys longer than the block size are hashed first
    // (2) keys are zero-padded up to the block size
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..KEY_LEN].copy_from_slice(&HASH(&[key]));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    // inner: H(K ^ ipad, text)
    let mut inner = Blake2s256::new();
    for i in 0..64 {
        inner.update([block[i] ^ 0x36]);
    }
    inner.update(input);
    let inner_hash = inner.finalize();

    // outer: H(K ^ opad, inner)
    let mut outer = Blake2s256::new();
    for i in 0..64 {
        outer.update([block[i] ^ 0x5c]);
    }
    outer.update(inner_hash);
    let digest = outer.finalize();
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&digest);
    out
}

/// WG nonce: 32 zero bits followed by counter LE64
fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// AEAD(key, counter, plain text, auth text) — encryption half:
/// returns ciphertext || tag. `auth text` is authenticated, not encrypted.
pub fn AEAD_ENCRYPT(key: &Key, counter: u64, auth: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key).expect("key is always KEY_LEN bytes");
    let key = aead::LessSafeKey::new(unbound);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce_from_counter(counter)),
        aead::Aad::from(auth),
        &mut in_out,
    )
    .expect("sealing cannot fail");

    in_out
}

/// AEAD(key, counter, cipher text, auth text) — decryption half.
/// `Err` means the tag did not verify: a normal outcome for network data.
pub fn AEAD_DECRYPT(
    key: &Key,
    counter: u64,
    auth: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, key).expect("key is always KEY_LEN bytes");
    let key = aead::LessSafeKey::new(unbound);

    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce_from_counter(counter)),
            aead::Aad::from(auth),
            &mut in_out,
        )
        .map_err(|_| AeadError::InvalidTag)?;

    Ok(plaintext.to_vec())
}

/// AEAD_LEN(plain len): plain len + 16
pub const fn AEAD_LEN(plain_len: usize) -> usize {
    plain_len + TAG_LEN
}

/// Failure of an AEAD operation: only the tag check can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadError {
    /// The tag did not verify: forgery, corruption or the wrong key.
    InvalidTag,
}

/// A ready-to-use ChaCha20-Poly1305 key, built once per session since
/// `UnboundKey::new` allocates a BoringSSL context.
pub struct AeadKey {
    inner: aead::LessSafeKey,
}

impl AeadKey {
    /// Infallible: `UnboundKey::new` only rejects a wrong key length, and `Key`
    /// is always `KEY_LEN` bytes.
    pub fn new(key: &Key) -> Self {
        let unbound =
            UnboundKey::new(&CHACHA20_POLY1305, key).expect("key is always KEY_LEN bytes");
        Self {
            inner: aead::LessSafeKey::new(unbound),
        }
    }

    /// Encrypts in place. `buf` holds the plaintext followed by `TAG_LEN`
    /// spare bytes, which receive the tag.
    pub fn seal_in_place(&self, counter: u64, buf: &mut [u8]) {
        let plain_len = buf
            .len()
            .checked_sub(TAG_LEN)
            .expect("buf must have room for the tag");
        let nonce = aead::Nonce::assume_unique_for_key(nonce_from_counter(counter));
        let (plaintext, tag_out) = buf.split_at_mut(plain_len);
        let tag = self
            .inner
            .seal_in_place_separate_tag(nonce, aead::Aad::empty(), plaintext)
            .expect("sealing cannot fail");
        tag_out.copy_from_slice(tag.as_ref());
    }

    /// Decrypts in place. `buf` holds the ciphertext followed by the tag;
    /// `Err` means the tag did not verify.
    pub fn open_in_place<'a>(
        &self,
        counter: u64,
        buf: &'a mut [u8],
    ) -> Result<&'a mut [u8], AeadError> {
        let nonce = aead::Nonce::assume_unique_for_key(nonce_from_counter(counter));
        self.inner
            .open_in_place(nonce, aead::Aad::empty(), buf)
            .map_err(|_| AeadError::InvalidTag)
    }
}

/// XAEAD(key, nonce, plain text, auth text): XChaCha20Poly1305, needed only
/// for cookies (§5.4.7). Not in aws-lc-rs; pick a crate or hand-roll HChaCha20.
pub fn XAEAD_ENCRYPT(
    key: &Key,
    nonce: &[u8; 24],
    auth: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let _ = (key, nonce, auth, plaintext);
    unimplemented!("XChaCha20Poly1305: needed at M4 (cookie), not in aws-lc-rs 1.18")
}

pub fn XAEAD_DECRYPT(
    key: &Key,
    nonce: &[u8; 24],
    auth: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let _ = (key, nonce, auth, ciphertext);
    unimplemented!("XChaCha20Poly1305: needed at M4 (cookie), not in aws-lc-rs 1.18")
}


/// Failure of a Diffie-Hellman operation: the peer key is malformed or a
/// low-order point, so the shared secret would be all zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhError {
    /// The peer's public key is unusable: malformed, or a low-order point.
    InvalidPeerKey,
}

/// DH(private key, public key): Curve25519 point multiplication, 32 bytes.
/// `peer_pub` is attacker-controlled, so `Err` is a normal outcome.
pub fn DH(my_priv: &PrivateKey, peer_pub: &[u8; 32]) -> Result<Key, DhError> {
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_pub);
    agreement::agree(my_priv, peer, Unspecified, |secret| {
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(secret);
        Ok(out)
    })
    .map_err(|_| DhError::InvalidPeerKey)
}

/// Rebuilds a `PrivateKey` from the raw 32 secret bytes WireGuard stores
/// (e.g. `Handshake.static_private`). X25519 private keys are exactly 32
/// bytes, so an invalid encoding here is a programming error, not input.
pub fn DH_PRIVATE(bytes: &[u8; KEY_LEN]) -> PrivateKey {
    PrivateKey::from_private_key(&agreement::X25519, bytes)
        .expect("32-byte X25519 private key")
}

/// DH_GENERATE(): generate a random Curve25519 private key and derive its
/// public key. We draw the raw bytes ourselves so the caller keeps the same
/// byte-oriented representation the rest of WireGuard uses.
pub fn DH_GENERATE() -> (PrivateKey, Key) {
    let mut bytes = [0u8; KEY_LEN];
    RAND(&mut bytes);
    let priv_key = DH_PRIVATE(&bytes);
    let pub_key = DH_PUBKEY(&priv_key);
    (priv_key, pub_key)
}

/// DH-PUBKEY(private key): derive the Curve25519 public key.
pub fn DH_PUBKEY(priv_key: &PrivateKey) -> Key {
    let pub_key = priv_key
        .compute_public_key()
        .unwrap(); // Realistically never panics
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(pub_key.as_ref());
    out
}

/// RAND(len): fill buffer with random bytes
pub fn RAND<const N: usize>(buf: &mut [u8; N]){
    rand::fill(buf).expect("Unexpected RNG generator failure"); 
}

/// TAI64N(): 12-byte timestamp. TAI64 label (2^62 + unix seconds, BE) || nanoseconds BE.
/// Must strictly increase between handshake attempts (replay protection).
pub fn TAI64N() -> [u8; TIMESTAMP_LEN] {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Your system clock is before 1970"); // TODO: use something else in this case
    let mut out = [0u8; TIMESTAMP_LEN];
    out[..8].copy_from_slice(&(0x4000_0000_0000_0000u64 + unix.as_secs()).to_be_bytes());
    out[8..].copy_from_slice(&unix.subsec_nanos().to_be_bytes());
    out
}

// Cascade of HMACs: "chews" a secret into n output keys. No allocation.

/// KDFn(key, input): tau_0 = HMAC(key, input), tau_1 = HMAC(tau_0, 0x1),
/// tau_i = HMAC(tau_0, tau_{i-1} || i) for i >= 2. Returns (tau_1, ..., tau_n)
/// per whitepaper §5.4; tau_1 is the new chaining key.
fn kdf<const N: usize>(key: &Key, input: &[u8]) -> [Key; N] {
    let tau0 = HMAC(key, input);
    let mut taus = [[0u8; KEY_LEN]; N];

    taus[0] = HMAC(&tau0, &[1]);
    for i in 1..N {
        let mut material = [0u8; KEY_LEN + 1];
        material[..KEY_LEN].copy_from_slice(&taus[i - 1]);
        material[KEY_LEN] = (i + 1) as u8;
        taus[i] = HMAC(&tau0, &material);
    }

    taus
}

/// Kdf1(key, input) -> new chaining key (tau_1).
pub fn KDF1(key: &Key, input: &[u8]) -> Key {
    kdf::<1>(key, input)[0]
}

/// Kdf2(key, input) -> (new chaining key, output key) = (tau_1, tau_2).
pub fn KDF2(key: &Key, input: &[u8]) -> (Key, Key) {
    let taus = kdf::<2>(key, input);
    (taus[0], taus[1])
}

/// Kdf3(key, input) -> (tau_1, tau_2, tau_3); used for message 2 with the PSK.
pub fn KDF3(key: &Key, input: &[u8]) -> (Key, Key, Key) {
    let taus = kdf::<3>(key, input);
    (taus[0], taus[1], taus[2])
}
