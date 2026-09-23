//! WireGuard noise functions. Every function in ALL_CAPS matches whitepaper.
#![allow(non_snake_case)]

use std::sync::Mutex;
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
    MAC_KEYED(key, input)
}

/// Like [`MAC`], but for a key of any length: `mac2` is keyed with a 16-byte
/// cookie rather than a 32-byte hash (§5.4.4).
pub fn MAC_KEYED(key: &[u8], input: &[u8]) -> Tag {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).expect("blake2s key is <= 32");
    MacTrait::update(&mut mac, input);
    let tag = MacTrait::finalize(mac);
    let mut out = [0u8; MAC_LEN];
    out.copy_from_slice(&tag.into_bytes());
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
    AeadKey::new(key)
        .seal(nonce_from_counter(counter), auth, plaintext)
        .expect("sealing cannot fail")
}

/// AEAD(key, counter, cipher text, auth text) — decryption half.
/// `Err` means the tag did not verify: a normal outcome for network data.
pub fn AEAD_DECRYPT(
    key: &Key,
    counter: u64,
    auth: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    AeadKey::new(key)
        .open(nonce_from_counter(counter), auth, ciphertext)
        .map_err(|_| AeadError::InvalidTag)
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

    /// Encrypts into a fresh buffer, returning ciphertext || tag. Unlike
    /// `seal_in_place` this takes an explicit nonce and AAD, as XAEAD needs.
    pub fn seal(&self, nonce: [u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let mut out = plaintext.to_vec();
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        self.inner
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut out)?;
        Ok(out)
    }

    /// Decrypts ciphertext || tag into a fresh buffer; `Err` on a bad tag.
    pub fn open(&self, nonce: [u8; 12], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Unspecified> {
        let mut out = ciphertext.to_vec();
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let plaintext = self
            .inner
            .open_in_place(nonce, aead::Aad::from(aad), &mut out)?;
        let len = plaintext.len();
        out.truncate(len);
        Ok(out)
    }
}

/// `QUARTERROUND(a, b, c, d)` from RFC 8439 §2.1, in place.
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// HChaCha20(key, nonce): the XChaCha20 subkey derivation (§2.2). Counterless,
/// and returns words 0..4 and 12..16 with no final feed-forward.
fn hchacha20(key: &Key, nonce: &[u8; 16]) -> Key {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for (i, chunk) in key.chunks_exact(4).enumerate() {
        state[4 + i] = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    for (i, chunk) in nonce.chunks_exact(4).enumerate() {
        state[12 + i] = u32::from_le_bytes(chunk.try_into().expect("4-byte chunk"));
    }

    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; KEY_LEN];
    for i in 0..4 {
        out[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
        out[16 + i * 4..16 + i * 4 + 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }
    out
}

/// The 12-byte ChaCha20 nonce XChaCha20 derives from a 24-byte one: four NUL
/// bytes followed by `nonce[16..24]` (§2.3).
fn xchacha_nonce(nonce: &[u8; 24]) -> [u8; 12] {
    let mut derived = [0u8; 12];
    derived[4..].copy_from_slice(&nonce[16..24]);
    derived
}

/// XAEAD(key, nonce, plaintext, auth): XChaCha20Poly1305, used by cookies
/// (§5.4.7). HChaCha20 produces the subkey; the rest is ordinary ChaCha20.
pub fn XAEAD_ENCRYPT(
    key: &Key,
    nonce: &[u8; 24],
    auth: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let subkey = hchacha20(key, nonce[..16].try_into().expect("16-byte prefix"));
    AeadKey::new(&subkey).seal(xchacha_nonce(nonce), auth, plaintext)
}

pub fn XAEAD_DECRYPT(
    key: &Key,
    nonce: &[u8; 24],
    auth: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let subkey = hchacha20(key, nonce[..16].try_into().expect("16-byte prefix"));
    AeadKey::new(&subkey).open(xchacha_nonce(nonce), auth, ciphertext)
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

/// Rebuilds a `PrivateKey` from the raw 32 secret bytes WireGuard stores. An
/// invalid encoding here is a programming error, not attacker input.
pub fn DH_PRIVATE(bytes: &[u8; KEY_LEN]) -> PrivateKey {
    PrivateKey::from_private_key(&agreement::X25519, bytes)
        .expect("32-byte X25519 private key")
}

/// DH_GENERATE(): a random Curve25519 private key and its public key, kept in
/// the byte representation the rest of WireGuard uses.
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

    // A timestamp must be strictly greater than every one we sent before
    // (§5.4.4 replay protection), but the clock can tick twice in a row or
    // stand still. Bump by one nanosecond rather than emit a repeat.
    static LAST: Mutex<Option<[u8; TIMESTAMP_LEN]>> = Mutex::new(None);
    let mut last = LAST.lock().expect("timestamp lock poisoned");
    if let Some(previous) = *last {
        if out <= previous {
            out = previous;
            for byte in out.iter_mut().rev() {
                let (bumped, carry) = byte.overflowing_add(1);
                *byte = bumped;
                if !carry {
                    break;
                }
            }
        }
    }
    *last = Some(out);
    out
}

// Cascade of HMACs: "chews" a secret into n output keys. No allocation.

/// KDFn(key, input) per whitepaper §5.4: tau_0 = HMAC(key, input), then
/// tau_i = HMAC(tau_0, tau_{i-1} || i), returning (tau_1, ..., tau_n).
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

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC vectors use `00:01:02:...` notation; decode hex for readability.
    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    /// draft-irtf-cfrg-xchacha §2.2.1: the HChaCha20 test vector, including
    /// the intermediate state before the final row selection.
    #[test]
    fn hchacha20_matches_the_draft_vector() {
        let key: [u8; 32] = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .try_into()
            .unwrap();
        let nonce: [u8; 16] = hex("000000090000004a0000000031415927")
            .try_into()
            .unwrap();

        let subkey = hchacha20(&key, &nonce);
        assert_eq!(
            subkey.as_slice(),
            hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"),
            "HChaCha20 subkey"
        );
    }

    /// The ChaCha20 quarter round, RFC 8439 §2.1.1. Pinned separately so a
    /// bug in the round is not masked by a wrong state layout.
    #[test]
    fn quarter_round_matches_the_rfc_vector() {
        let mut state = [0u32; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;

        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(
            [state[0], state[1], state[2], state[3]],
            [0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb]
        );
    }

    /// draft-irtf-cfrg-xchacha A.3.1: the full AEAD_XChaCha20_Poly1305 vector.
    #[test]
    fn xaead_matches_the_draft_vector() {
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce: [u8; 24] = hex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";

        let sealed = XAEAD_ENCRYPT(&key, &nonce, &aad, plaintext).unwrap();

        let (ciphertext, tag) = sealed.split_at(sealed.len() - TAG_LEN);
        assert_eq!(
            ciphertext,
            hex(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
                 731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
                 2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
                 21f9664c97637da9768812f615c68b13b52e"
            )
            .as_slice()
        );
        assert_eq!(tag, hex("c0875924c1c7987947deafd8780acf49").as_slice());

        // And it round-trips.
        let opened = XAEAD_DECRYPT(&key, &nonce, &aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn xaead_rejects_a_forged_tag_or_wrong_aad() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let sealed = XAEAD_ENCRYPT(&key, &nonce, b"aad", b"cookie").unwrap();

        let mut forged = sealed.clone();
        let last = forged.len() - 1;
        forged[last] ^= 0x01;
        assert!(XAEAD_DECRYPT(&key, &nonce, b"aad", &forged).is_err());

        // The AAD is authenticated too, so changing it must fail.
        assert!(XAEAD_DECRYPT(&key, &nonce, b"other", &sealed).is_err());
    }

    /// A different key or nonce must not decrypt: this is what stops a cookie
    /// minted for another session from being accepted.
    #[test]
    fn xaead_binds_the_key_and_the_whole_nonce() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let sealed = XAEAD_ENCRYPT(&key, &nonce, b"", b"cookie").unwrap();

        assert!(XAEAD_DECRYPT(&[8u8; 32], &nonce, b"", &sealed).is_err());

        // The last nonce byte only affects the ChaCha20 part, the first ones
        // only affect HChaCha20; both must be bound.
        let mut later = nonce;
        later[23] ^= 0x01;
        assert!(XAEAD_DECRYPT(&key, &later, b"", &sealed).is_err());

        let mut earlier = nonce;
        earlier[0] ^= 0x01;
        assert!(XAEAD_DECRYPT(&key, &earlier, b"", &sealed).is_err());
    }

    /// Cross-check against RustCrypto's independent implementation, so a
    /// matching-but-wrong vector transcription cannot pass unnoticed.
    #[test]
    fn xaead_agrees_with_the_rustcrypto_implementation() {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        use chacha20poly1305::{XChaCha20Poly1305, XNonce};

        let mut seed = [0u8; 64];
        RAND(&mut seed);

        for (key, nonce, aad, plaintext) in [
            ([0u8; 32], [0u8; 24], &b""[..], &b""[..]),
            (
                seed[..32].try_into().unwrap(),
                seed[32..56].try_into().unwrap(),
                &b"associated data"[..],
                &b"a cookie worth 32 bytes exactly!!"[..],
            ),
            (
                [0xffu8; 32],
                [0xffu8; 24],
                &b"aad"[..],
                &[0xabu8; 200][..],
            ),
        ] {
            let cipher = XChaCha20Poly1305::new(&key.into());
            let expected = cipher
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .unwrap();

            let ours = XAEAD_ENCRYPT(&key, &nonce, aad, plaintext).unwrap();
            assert_eq!(ours, expected, "ciphertext mismatch against RustCrypto");
            assert_eq!(
                XAEAD_DECRYPT(&key, &nonce, aad, &expected).unwrap(),
                plaintext,
                "we must decrypt their ciphertext"
            );
        }
    }
}
