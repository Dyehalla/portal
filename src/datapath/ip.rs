//! Helpers for reading addresses from inner IPv4 and IPv6 packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Extracts the destination address from a complete IPv4 or IPv6 header.
pub fn destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4)? {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).ok()?,
        ))),
        _ => None,
    }
}

/// Extracts the source address from a complete IPv4 or IPv6 header.
pub fn source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4)? {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        6 if packet.len() >= 40 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).ok()?,
        ))),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// IPv4 and IPv6 TUN packets use the correct destination address offsets.
    #[test]
    fn tun_route_extraction_reads_ipv4_and_ipv6_destinations() {
        let mut ipv4 = [0u8; 20];
        ipv4[0] = 0x45;
        ipv4[16..20].copy_from_slice(&[192, 0, 2, 7]);
        assert_eq!(
            destination(&ipv4),
            Some("192.0.2.7".parse().unwrap())
        );

        let mut ipv6 = [0u8; 40];
        ipv6[0] = 0x60;
        ipv6[24..40].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            destination(&ipv6),
            Some("2001:db8::7".parse().unwrap())
        );
    }

    /// Truncated IP packets do not reach cryptokey routing.
    #[test]
    fn a_truncated_ip_packet_has_no_destination() {
        assert_eq!(destination(&[0x45; 12]), None);
        assert_eq!(destination(&[0x60; 20]), None);
    }
}
