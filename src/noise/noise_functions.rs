//! WireGuard noise functions. Every function matches whitepaper §5.1 signature.
//! Naming follows whitepaper (hence non_snake_case) to keep handshake code
//! line-by-line comparable with the paper.

#![allow(non_snake_case)]

use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::aead::{self, CHACHA20_POLY1305, UnboundKey};
use aws_lc_rs::agreement::{self, PrivateKey};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand;
use blake2::digest::consts::U16;
use blake2::digest::{KeyInit, Mac as MacTrait};
use blake2::{Blake2sMac, Blake2s256, Digest};

pub(crate) const CONSTRUCTION: &[u8; 37] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub(crate) const IDENTIFIER: &[u8; 34] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub(crate) const LABEL_MAC1: &[u8; 8] = b"mac1----";
pub(crate) const LABEL_COOKIE: &[u8; 8] = b"cookie--";

pub(crate) const KEY_LEN: usize = 32;
pub(crate) const TAG_LEN: usize = 16;
pub(crate) const TIMESTAMP_LEN: usize = 12;
pub(crate) const MAC_LEN: usize = 16;

pub(crate) type Key = [u8; KEY_LEN];
pub(crate) type Hash = Key;
pub(crate) type Tag = [u8; TAG_LEN];

// ===== hashes =====

/// HASH(input): Blake2s(input, 32), returning 32 bytes of output
pub(crate) fn HASH(input: &[u8]) -> Hash {
    let digest = Blake2s256::digest(input);
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&digest);
    out
}

/// MAC(key, input): Keyed-Blake2s(key, input, 16), returning 16 bytes of output
pub(crate) fn MAC(key: &Key, input: &[u8]) -> Tag {
    let mut mac = <Blake2sMac<U16> as KeyInit>::new_from_slice(key).expect("key len is const");
    MacTrait::update(&mut mac, input);
    let tag = MacTrait::finalize(mac);
    let mut out = [0u8; MAC_LEN];
    let tag = tag.into_bytes();
    out.copy_from_slice(&tag);
    out
}

pub(crate) fn HMAC(key: &[u8], input: &[u8]) -> Key {
    // (1) keys longer than the block size are hashed first
    // (2) keys are zero-padded up to the block size
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..KEY_LEN].copy_from_slice(&HASH(key));
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

/// WG nonce: 32 zero bits followed by counter LE64 (whitepaper §5.1)
fn nonce_from_counter(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

/// AEAD(key, counter, plain text, auth text) — encryption half:
/// returns ciphertext || tag. `auth text` is authenticated, not encrypted.
///
/// For handshake-sized buffers a copy is fine; the transport data path will
/// switch to in-place buffers later.
pub(crate) fn AEAD_ENCRYPT(
    key: &Key,
    counter: u64,
    auth: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)?;
    let key = aead::LessSafeKey::new(unbound);

    let mut in_out = plaintext.to_vec();
    key.seal_in_place_append_tag(
        aead::Nonce::try_assume_unique_for_key(&nonce_from_counter(counter))?,
        aead::Aad::from(auth),
        &mut in_out,
    )?;
    Ok(in_out)
}

/// AEAD(key, counter, cipher text, auth text) — decryption half:
/// verifies tag over `auth` || ciphertext, then decrypts.
/// Err = forged/corrupted input; this is a NORMAL outcome for network data.
pub(crate) fn AEAD_DECRYPT(
    key: &Key,
    counter: u64,
    auth: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)?;
    let key = aead::LessSafeKey::new(unbound);

    let mut in_out = ciphertext.to_vec();
    let plaintext = key.open_in_place(
        aead::Nonce::try_assume_unique_for_key(&nonce_from_counter(counter))?,
        aead::Aad::from(auth),
        &mut in_out,
    )?;
    Ok(plaintext.to_vec())
}

/// AEAD_LEN(plain len): plain len + 16
pub(crate) const fn AEAD_LEN(plain_len: usize) -> usize {
    plain_len + TAG_LEN
}

/// XAEAD(key, nonce, plain text, auth text): XChaCha20Poly1305 with a random
/// 24-byte nonce. Used only for cookie encryption in CookieReply (§5.4.7, M4).
/// aws-lc-rs 1.18 has no XChaCha20Poly1305 — decide at M4: RustCrypto
/// chacha20poly1305 crate for this one function, or hand-rolled HChaCha20.
pub(crate) fn XAEAD_ENCRYPT(
    key: &Key,
    nonce: &[u8; 24],
    auth: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let _ = (key, nonce, auth, plaintext);
    unimplemented!("XChaCha20Poly1305: needed at M4 (cookie), not in aws-lc-rs 1.18")
}

pub(crate) fn XAEAD_DECRYPT(
    key: &Key,
    nonce: &[u8; 24],
    auth: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let _ = (key, nonce, auth, ciphertext);
    unimplemented!("XChaCha20Poly1305: needed at M4 (cookie), not in aws-lc-rs 1.18")
}

// ===== DH =====

/// DH(private key, public key): Curve25519 point multiplication, 32 bytes.
/// peer_pub is attacker-controlled -> Err is a normal outcome (drop the packet).
pub(crate) fn DH(my_priv: &PrivateKey, peer_pub: &[u8; 32]) -> Result<Key, Unspecified> {
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_pub);
    agreement::agree(my_priv, peer, Unspecified, |secret| {
        let mut out = [0u8; KEY_LEN];
        out.copy_from_slice(secret);
        Ok(out)
    })
}

/// DH_GENERATE(): generate a random Curve25519 private key.
/// Whitepaper says "32 bytes of output", but aws-lc API keeps bytes opaque —
/// we hold the PrivateKey object (can't do otherwise: its bytes are private).
pub(crate) fn DH_GENERATE() -> PrivateKey {
    agreement::PrivateKey::generate(&agreement::X25519).unwrap()
}

/// DH_PUBKEY(private key): Curve25519 public key, 32 bytes
pub(crate) fn DH_PUBKEY(priv_key: &PrivateKey) -> Key {
    let pk = priv_key.compute_public_key().unwrap(); // PrivateKey is always valid
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(pk.as_ref());
    out
}

// ===== randomness and time =====

/// RAND(len): len cryptographically secure random bytes
pub(crate) fn RAND(len: usize) -> Result<Vec<u8>, Unspecified> {
    let mut buf = vec![0u8; len];
    rand::fill(&mut buf)?;
    Ok(buf)
}

/// TAI64N(): 12-byte timestamp. TAI64 label (2^62 + unix seconds, BE) || nanoseconds BE.
/// Must strictly increase between handshake attempts (§5.4 replay protection).
pub(crate) fn TAI64N() -> [u8; TIMESTAMP_LEN] {
    let unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970");
    let mut out = [0u8; TIMESTAMP_LEN];
    out[..8].copy_from_slice(&(0x4000_0000_0000_0000u64 + unix.as_secs()).to_be_bytes());
    out[8..].copy_from_slice(&unix.subsec_nanos().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn hash_rfc7693() {
        // BLAKE2s-256("abc"), RFC 7693 appendix / python hashlib
        assert_eq!(HASH(b"abc").to_vec(), hex("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"));
    }

    #[test]
    fn mac_keyed_blake2s_16() {
        // hashlib.blake2s(b"WireGuard auth", key=bytes(range(32)), digest_size=16)
        let key = Key::try_from((0u8..32).collect::<Vec<_>>().as_slice()).unwrap();
        assert_eq!(MAC(&key, b"WireGuard auth").to_vec(), hex("ee4992913ba1ae147e7b9efd87f6caad"));
    }

    #[test]
    fn hmac_blake2s() {
        // hmac.new(bytes(range(32)), b"handshake test", hashlib.blake2s)
        let key: Vec<u8> = (0u8..32).collect();
        assert_eq!(
            HMAC(&key, b"handshake test").to_vec(),
            hex("9efe81f98608fa07f3071bc2b8ac2553578453226a8c213ed99b0c61273a6209")
        );
        // long key branch (key.len() > 64)
        let long_key: Vec<u8> = (0u8..70).collect();
        assert_eq!(
            HMAC(&long_key, b"long key test").to_vec(),
            hex("0d02785bc39805bcd122ad5c10d82383949243de88f5bc90fa107f134aea04c9")
        );
    }

    #[test]
    fn aead_roundtrip() {
        let key = Key::from([7u8; 32]);
        let auth = b"transport header";
        let msg = b"hello through the tunnel";

        let cipher = AEAD_ENCRYPT(&key, 1, auth, msg).unwrap();
        assert_eq!(cipher.len(), AEAD_LEN(msg.len()));
        assert_eq!(AEAD_DECRYPT(&key, 1, auth, &cipher).unwrap(), msg);
    }

    #[test]
    fn aead_forgeries_rejected() {
        let key = Key::from([7u8; 32]);
        let mut cipher = AEAD_ENCRYPT(&key, 5, b"aad", b"secret").unwrap();

        cipher[3] ^= 0x01; // flip one ciphertext bit
        assert!(AEAD_DECRYPT(&key, 5, b"aad", &cipher).is_err());

        let cipher = AEAD_ENCRYPT(&key, 5, b"aad", b"secret").unwrap();
        assert!(AEAD_DECRYPT(&key, 5, b"WRONG aad", &cipher).is_err()); // wrong auth text
        assert!(AEAD_DECRYPT(&key, 6, b"aad", &cipher).is_err()); // wrong counter/nonce
    }

    #[test]
    fn dh_symmetric() {
        let a = DH_GENERATE();
        let b = DH_GENERATE();
        let ka = DH(&a, &DH_PUBKEY(&b)).unwrap();
        let kb = DH(&b, &DH_PUBKEY(&a)).unwrap();
        assert_eq!(ka, kb);
    }

    #[test]
    fn tai64n_shape() {
        let ts = TAI64N();
        assert_eq!(ts.len(), TIMESTAMP_LEN);
        assert_eq!(ts[0], 0x40); // TAI64 label prefix 2^62
    }

    #[test]
    fn rand_works() {
        let a = RAND(32).unwrap();
        let b = RAND(32).unwrap();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b); // 2^-256 chance, fine for a smoke test
    }
}

// ===== KDF (whitepaper §5.2) =====
// Cascade of HMACs: "chews" a secret into n output keys + a new chaining key.

/// KDFn(key, input) -> (tau1..taun, new_ch): helper that keeps the cascade honest.
/// ch_i = HMAC(ch_{i-1} || tau_i, input) per whitepaper.
fn kdf_cascade<const N: usize>(key: &Key, input: &[u8]) -> ([Key; N], Key) {
    let mut taus: [Key; N] = [[0u8; KEY_LEN]; N];

    for i in 0..N {
        // tau_i = HMAC(tau0 || tau1 || ... || tau_{i-1}, input)
        // (every tau is derived from the ORIGINAL key, whitepaper §5.2)
        let mut chained = Vec::with_capacity(KEY_LEN * (i + 1));
        chained.extend_from_slice(key);
        for tau in &taus[..i] {
            chained.extend_from_slice(tau);
        }
        taus[i] = HMAC(&chained, input);
    }

    // new chaining key = HMAC(tau0 || tau1 || ... || taun, input)
    let mut chained = Vec::with_capacity(KEY_LEN * (N + 1));
    chained.extend_from_slice(key);
    for tau in &taus {
        chained.extend_from_slice(tau);
    }
    let new_ch = HMAC(&chained, input);

    (taus, new_ch)
}

pub(crate) fn KDF1(key: &Key, input: &[u8]) -> ([Key; 1], Key) {
    kdf_cascade(key, input)
}

pub(crate) fn KDF2(key: &Key, input: &[u8]) -> ([Key; 2], Key) {
    kdf_cascade(key, input)
}

pub(crate) fn KDF3(key: &Key, input: &[u8]) -> ([Key; 3], Key) {
    kdf_cascade(key, input)
}

#[cfg(test)]
mod kdf_tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn kdf2_reference() {
        // independent python implementation (hmac-over-blake2s cascade, §5.2)
        let key = Key::try_from((0u8..32).collect::<Vec<_>>().as_slice()).unwrap();
        let (taus, new_ch) = KDF2(&key, b"kdf test");
        assert_eq!(taus[0].to_vec(), hex("c2d62050936c37013c4d76a35aa0fde5473c55aa41521592062aa2ab21895ab8"));
        assert_eq!(taus[1].to_vec(), hex("3a354bad1bccc3cb14ce04222833cd34787fd28629fccd0cce9819dc771891c2"));
        assert_eq!(new_ch.to_vec(), hex("4b53988c5ba201e32ed810babb92ddf7c263c58ada52bfcb9bbe607a095ffd95"));
    }
}
