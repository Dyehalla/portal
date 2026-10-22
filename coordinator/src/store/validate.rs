use crate::error::{Error, Result};
use std::net::{Ipv4Addr, SocketAddr};

pub(super) fn name(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(Error::bad_request(
            "name must contain 1-128 bytes without control characters",
        ));
    }
    Ok(value.to_owned())
}

pub(super) fn public_key(value: &str) -> Result<String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::bad_request(
            "public_key must contain 64 hexadecimal WireGuard key characters",
        ));
    }
    let mut key = [0; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::bad_request("invalid public_key"))?;
    }
    // Reject alternative encodings of the same X25519 coordinate, as well as low-order keys.
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if key.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less
        || x25519_dalek::x25519([9; 32], key) == [0; 32]
    {
        return Err(Error::bad_request(
            "public_key must be a canonical contributory WireGuard public key",
        ));
    }
    Ok(value.to_ascii_lowercase())
}

pub(super) fn endpoints(mut values: Vec<SocketAddr>) -> Result<Vec<SocketAddr>> {
    if values.len() > 8
        || values.iter().any(|a| {
            a.port() == 0
                || a.ip().is_unspecified()
                || a.ip().is_multicast()
                || a.ip() == Ipv4Addr::BROADCAST
        })
    {
        return Err(Error::bad_request(
            "endpoints must contain at most eight unicast IP:port addresses with nonzero ports",
        ));
    }
    values.sort();
    values.dedup();
    Ok(values)
}

pub(super) fn tcp_ports(mut ports: Vec<u16>) -> Result<Vec<u16>> {
    if ports.len() > 1024 || ports.contains(&0) {
        return Err(Error::bad_request(
            "TCP permissions allow at most 1024 ports in 1-65535",
        ));
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_trim_whitespace_and_reject_empty_control_and_oversized_values() {
        assert_eq!(name("  laptop  ").unwrap(), "laptop");
        for value in [" ", "a\nb", &"x".repeat(129)] {
            assert!(name(value).is_err());
        }
    }

    #[test]
    fn keys_require_canonical_contributory_x25519_points() {
        let bytes = x25519_dalek::x25519([7; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
        let key: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(public_key(&key.to_uppercase()).unwrap(), key);
        let mut alias = bytes;
        alias[31] |= 0x80;
        let alias: String = alias.iter().map(|b| format!("{b:02x}")).collect();
        for invalid in ["00".repeat(32), "ff".repeat(32), alias, "invalid".into()] {
            assert!(public_key(&invalid).is_err());
        }
    }

    #[test]
    fn endpoint_limits_apply_before_normalization() {
        let address: SocketAddr = "198.51.100.10:51820".parse().unwrap();
        assert_eq!(endpoints(vec![address, address]).unwrap(), vec![address]);
        assert!(endpoints(vec![address; 9]).is_err());
        for address in [
            "0.0.0.0:123",
            "[::]:123",
            "224.0.0.1:123",
            "255.255.255.255:123",
            "198.51.100.10:0",
        ] {
            assert!(endpoints(vec![address.parse().unwrap()]).is_err());
        }
    }

    #[test]
    fn ports_are_bounded_sorted_and_deduplicated() {
        assert_eq!(
            tcp_ports(vec![65535, 443, 22, 443]).unwrap(),
            vec![22, 443, 65535]
        );
        assert!(tcp_ports(vec![]).unwrap().is_empty());
        assert!(tcp_ports(vec![0]).is_err());
        assert!(tcp_ports(vec![443; 1025]).is_err());
    }
}
