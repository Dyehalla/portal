use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::model::*;
use portal::{AccessRules, PeerAccess, PeerKey};

pub fn public_key(value: &str) -> Result<PeerKey, String> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid WireGuard public key".into());
    }
    let mut key = [0; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).map_err(|_| "invalid public key")?;
    }
    let mut modulus = [0xff; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;
    if key.iter().rev().cmp(modulus.iter().rev()) != std::cmp::Ordering::Less
        || x25519_dalek::x25519([9; 32], key) == [0; 32]
    {
        return Err("public key must be canonical and contributory".into());
    }
    Ok(key)
}

pub fn key_hex(key: &PeerKey) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn normalize_permissions(permissions: Permissions) -> Result<Permissions, String> {
    if permissions.len() > 256 {
        return Err("policy exceeds 256 peers".into());
    }
    let mut result = Permissions::new();
    let mut seen = HashSet::new();
    for (key, mut ports) in permissions {
        let key = key_hex(&public_key(&key)?);
        if !seen.insert(key.clone()) {
            return Err("duplicate normalized policy key".into());
        }
        validate_ports(&ports)?;
        ports.tcp.sort_unstable();
        ports.tcp.dedup();
        if !ports.tcp.is_empty() {
            result.insert(key, ports);
        }
    }
    Ok(result)
}

fn validate_ports(ports: &PeerPermissions) -> Result<(), String> {
    if ports.tcp.len() > 1024 || ports.tcp.contains(&0) {
        return Err("invalid TCP permissions".into());
    }
    Ok(())
}

pub fn validate_endpoints(endpoints: &[SocketAddr]) -> Result<(), String> {
    if endpoints.len() > 8
        || endpoints.iter().any(|e| {
            e.port() == 0
                || e.ip().is_unspecified()
                || e.ip().is_multicast()
                || e.ip() == Ipv4Addr::BROADCAST
        })
    {
        return Err("invalid endpoint candidates".into());
    }
    Ok(())
}

pub fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| "system clock is before Unix epoch".into())
}

pub fn lease_deadline(map: &NetworkMap, request_started: Instant) -> Result<Instant, String> {
    let now = unix_now()?;
    let duration = map
        .expires_at
        .checked_sub(map.generated_at)
        .filter(|d| (30..=3600).contains(d))
        .ok_or("invalid network map lease")?;
    if map.generated_at > now.saturating_add(30) || map.expires_at <= now {
        return Err("network map expired or system clock is incorrect".into());
    }
    // Long polling generates the map after waiting. Start its monotonic lease
    // on receipt; counting the polling interval twice would expire short leases.
    if request_started.elapsed() > Duration::from_secs(35) {
        return Err("network map request exceeded its time budget".into());
    }
    let deadline = Instant::now() + Duration::from_secs(duration.min(map.expires_at - now));
    if deadline <= Instant::now() {
        return Err("network map lease was consumed by the request".into());
    }
    Ok(deadline)
}

/// Validate the entire map before changing host or WireGuard state. Local inbound
/// grants are intersected with confirmed bindings; ownership never grants traffic.
pub fn compile(
    map: &NetworkMap,
    local: &Permissions,
    expected_key: PeerKey,
    previous: Option<&NetworkMap>,
) -> Result<AccessRules, String> {
    if map.protocol_version != PROTOCOL_VERSION
        || map.network_id.is_empty()
        || map.generation.is_empty()
        || map.peers.len() > 4096
    {
        return Err("unsupported or oversized network map".into());
    }
    if public_key(&map.device.public_key)? != expected_key
        || map.device.owner_user_id != map.user.id
    {
        return Err("network map belongs to another device or owner".into());
    }
    if let Some(old) = previous
        && (map.network_id != old.network_id
            || map.device.id != old.device.id
            || map.user.id != old.user.id
            || map.device.ipv4 != old.device.ipv4
            || map.device.ipv6 != old.device.ipv6
            || map.generation == old.generation
                && (map.revision < old.revision
                    || map.generated_at < old.generated_at
                    || map.policy.revision < old.policy.revision))
    {
        return Err("network map identity changed or revision went backwards".into());
    }
    validate_device(&map.device)?;
    if normalize_permissions(map.policy.permissions.clone())? != map.policy.permissions {
        return Err("noncanonical published policy".into());
    }
    let mut ids = HashSet::from([map.device.id.clone()]);
    let mut keys = HashSet::from([expected_key]);
    let mut addresses = HashSet::from([IpAddr::V4(map.device.ipv4), IpAddr::V6(map.device.ipv6)]);
    let mut rules = AccessRules {
        local_addresses: vec![map.device.ipv4.into(), map.device.ipv6.into()],
        ..Default::default()
    };
    for peer in &map.peers {
        validate_device(&peer.device)?;
        let key = public_key(&peer.device.public_key)?;
        if !ids.insert(peer.device.id.clone())
            || !keys.insert(key)
            || !addresses.insert(peer.device.ipv4.into())
            || !addresses.insert(peer.device.ipv6.into())
        {
            return Err("duplicate device, key or virtual address".into());
        }
        validate_ports(&peer.incoming)?;
        validate_ports(&peer.outgoing)?;
        let confirmed = map
            .policy
            .permissions
            .get(&key_hex(&key))
            .cloned()
            .unwrap_or_default();
        if peer.incoming != confirmed {
            return Err("map incoming grants disagree with device policy".into());
        }
        let local_ports = local.get(&key_hex(&key)).cloned().unwrap_or_default();
        let incoming_tcp = confirmed
            .tcp
            .into_iter()
            .filter(|p| local_ports.tcp.contains(p))
            .collect();
        rules.peers.insert(
            key,
            PeerAccess {
                addresses: vec![peer.device.ipv4.into(), peer.device.ipv6.into()],
                incoming_tcp,
                outgoing_tcp: peer.outgoing.tcp.clone(),
            },
        );
    }
    Ok(rules)
}

fn validate_device(device: &Device) -> Result<(), String> {
    if device.id.is_empty()
        || device.owner_user_id.is_empty()
        || !device.ipv4.is_private()
        || device.ipv4.is_broadcast()
        || (device.ipv6.segments()[0] & 0xfe00) != 0xfc00
    {
        return Err("invalid device identity or virtual addresses".into());
    }
    validate_endpoints(&device.endpoints)
}

pub fn validate_signal(
    signal: &ConnectionInfo,
    map: &NetworkMap,
    local: &Permissions,
    incoming: bool,
) -> Result<PeerKey, String> {
    if signal.protocol_version != PROTOCOL_VERSION
        || signal.network_id != map.network_id
        || signal.generation != map.generation
        || signal.expires_at <= unix_now()?
        || signal.expires_at > unix_now()?.saturating_add(15)
        || signal.revision > map.revision
    {
        return Err("stale or unknown P2P signal".into());
    }
    let peer = map
        .peers
        .iter()
        .find(|p| p.device.id == signal.peer.id)
        .ok_or("P2P peer is absent from the current map")?;
    let key = public_key(&peer.device.public_key)?;
    if signal.peer.public_key != peer.device.public_key
        || signal.peer.ipv4 != peer.device.ipv4
        || signal.peer.ipv6 != peer.device.ipv6
        || signal.peer.owner_user_id != peer.device.owner_user_id
    {
        return Err("P2P signal changes a peer identity".into());
    }
    validate_endpoints(&signal.peer.endpoints)?;
    let allowed = if incoming {
        local.get(&key_hex(&key)).cloned().unwrap_or_default()
    } else {
        peer.outgoing.clone()
    };
    if signal.permissions.tcp.is_empty()
        || signal
            .permissions
            .tcp
            .iter()
            .any(|p| !allowed.tcp.contains(p))
        || incoming
            && (signal.target_policy_revision != map.policy.revision
                || signal
                    .permissions
                    .tcp
                    .iter()
                    .any(|p| !peer.incoming.tcp.contains(p)))
        || !incoming && signal.target_policy_revision != peer.policy_revision
    {
        return Err("P2P signal is not authorized by the applied policy".into());
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> String {
        key_hex(&x25519_dalek::x25519(
            [seed; 32],
            x25519_dalek::X25519_BASEPOINT_BYTES,
        ))
    }

    fn map() -> NetworkMap {
        let own = Device {
            id: "a".into(),
            owner_user_id: "owner".into(),
            name: "a".into(),
            public_key: key(7),
            ipv4: "10.77.0.1".parse().unwrap(),
            ipv6: "fd00::1".parse().unwrap(),
            endpoints: vec!["192.0.2.1:51820".parse().unwrap()],
            created_at: 1,
        };
        let mut remote = own.clone();
        remote.id = "b".into();
        remote.public_key = key(8);
        remote.ipv4 = "10.77.0.2".parse().unwrap();
        remote.ipv6 = "fd00::2".parse().unwrap();
        let ports = PeerPermissions { tcp: vec![443] };
        NetworkMap {
            protocol_version: PROTOCOL_VERSION,
            network_id: "network".into(),
            generation: "generation".into(),
            revision: 5,
            generated_at: unix_now().unwrap(),
            expires_at: unix_now().unwrap() + 30,
            user: User {
                id: "owner".into(),
                name: "owner".into(),
                is_admin: false,
                created_at: 1,
            },
            device: own,
            policy: DevicePolicy {
                revision: 2,
                permissions: Permissions::from([(key(8), ports.clone())]),
            },
            peers: vec![Peer {
                device: remote,
                policy_revision: 3,
                incoming: ports,
                outgoing: PeerPermissions::default(),
            }],
        }
    }

    #[test]
    fn local_policy_and_confirmed_binding_are_both_required_without_owner_bypass() {
        let map = map();
        let own = public_key(&key(7)).unwrap();
        let remote = public_key(&key(8)).unwrap();
        let rules = compile(&map, &Permissions::new(), own, None).unwrap();
        assert!(rules.peers[&remote].incoming_tcp.is_empty());
        assert!(rules.peers[&remote].outgoing_tcp.is_empty());
        let rules = compile(&map, &map.policy.permissions, own, None).unwrap();
        assert_eq!(rules.peers[&remote].incoming_tcp, [443]);
        assert!(rules.peers[&remote].outgoing_tcp.is_empty());
        let unknown = Permissions::from([(key(9), PeerPermissions { tcp: vec![443] })]);
        assert_eq!(compile(&map, &unknown, own, None).unwrap().peers.len(), 1);
    }

    #[test]
    fn forged_bindings_collisions_policy_and_replays_are_rejected_before_apply() {
        let map = map();
        let own = public_key(&key(7)).unwrap();
        for kind in 0..8 {
            let mut bad = map.clone();
            match kind {
                0 => bad.device.public_key = key(8),
                1 => bad.peers[0].device.ipv4 = bad.device.ipv4,
                2 => bad.peers.push(bad.peers[0].clone()),
                3 => bad.peers[0].incoming.tcp.push(22),
                4 => bad.network_id = "other".into(),
                5 => bad.revision = 1,
                6 => bad.user.id = "other-owner".into(),
                _ => bad.peers[0].outgoing.tcp.push(0),
            }
            assert!(
                compile(&bad, &bad.policy.permissions, own, Some(&map)).is_err(),
                "case {kind}"
            );
        }
    }

    #[test]
    fn short_leases_renew_after_long_poll_and_signals_cannot_expand_applied_grants() {
        let map = map();
        let deadline = lease_deadline(&map, Instant::now() - Duration::from_secs(15)).unwrap();
        assert!(deadline > Instant::now() + Duration::from_secs(28));
        let mut expired = map.clone();
        expired.generated_at -= 31;
        expired.expires_at -= 31;
        assert!(lease_deadline(&expired, Instant::now()).is_err());
        let mut signal = ConnectionInfo {
            request_id: "request".into(),
            protocol_version: PROTOCOL_VERSION,
            network_id: map.network_id.clone(),
            generation: map.generation.clone(),
            revision: map.revision,
            peer: map.peers[0].device.clone(),
            permissions: PeerPermissions { tcp: vec![443] },
            target_policy_revision: map.policy.revision,
            expires_at: unix_now().unwrap() + 10,
        };
        assert!(validate_signal(&signal, &map, &map.policy.permissions, true).is_ok());
        assert!(validate_signal(&signal, &map, &Permissions::new(), true).is_err());
        signal.permissions.tcp.push(22);
        assert!(validate_signal(&signal, &map, &map.policy.permissions, true).is_err());
        signal.permissions.tcp.pop();
        signal.peer.ipv4 = "10.77.0.3".parse().unwrap();
        assert!(validate_signal(&signal, &map, &map.policy.permissions, true).is_err());
    }
}
