//! Optional device-local TCP ACL. Manual WireGuard devices do not enable it.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::PeerKey;

const MAX_FLOWS: usize = 8192;
const SYN_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const FIN_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerAccess {
    pub addresses: Vec<IpAddr>,
    pub incoming_tcp: Vec<u16>,
    pub outgoing_tcp: Vec<u16>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccessRules {
    pub local_addresses: Vec<IpAddr>,
    pub peers: HashMap<PeerKey, PeerAccess>,
}

/// Serializes policy replacement with packet processing, including queued sends.
/// The applying closure must discard pending plaintext when `changed` is true.
#[derive(Default)]
pub struct AccessControl(Mutex<State>);

#[derive(Default)]
struct State {
    rules: AccessRules,
    deadline: Option<Instant>,
    flows: HashMap<FlowKey, Flow>,
    next_prune: Option<Instant>,
}

impl AccessControl {
    pub fn update<T>(
        &self,
        rules: AccessRules,
        deadline: Instant,
        apply: impl FnOnce(bool) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut state = self.0.lock().map_err(|_| "access control is unavailable")?;
        let expired = state.deadline.is_none_or(|d| d <= Instant::now());
        let changed = state.rules != rules || expired;
        // Errors leave all traffic blocked. Never restore old grants after a partial apply.
        state.deadline = None;
        let result = apply(changed)?;
        if expired {
            state.flows.clear();
        } else if changed {
            let local_changed = state.rules.local_addresses != rules.local_addresses;
            let old_rules = std::mem::take(&mut state.rules);
            state.flows.retain(|key, flow| {
                !local_changed
                    && rules.peers.get(&key.peer).is_some_and(|peer| {
                        old_rules
                            .peers
                            .get(&key.peer)
                            .is_some_and(|old| old.addresses == peer.addresses)
                            && if flow.inbound {
                                peer.incoming_tcp.contains(&key.local_port)
                            } else {
                                peer.outgoing_tcp.contains(&key.remote_port)
                            }
                    })
            });
        }
        state.rules = rules;
        state.deadline = Some(deadline);
        Ok(result)
    }

    pub fn block(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.deadline = None;
            state.flows.clear();
        }
    }

    pub(crate) fn lock(&self) -> AccessGuard<'_> {
        let state = match self.0.lock() {
            Ok(state) => state,
            Err(e) => {
                let mut state = e.into_inner();
                state.deadline = None;
                state
            }
        };
        AccessGuard(state)
    }
}

pub(crate) struct AccessGuard<'a>(MutexGuard<'a, State>);

impl AccessGuard<'_> {
    pub(crate) fn peer_allowed(&self, key: &PeerKey) -> bool {
        self.0.deadline.is_some_and(|d| d > Instant::now()) && self.0.rules.peers.contains_key(key)
    }

    pub(crate) fn packet_allowed(&mut self, key: PeerKey, inbound: bool, packet: &[u8]) -> bool {
        if !self.peer_allowed(&key) {
            return false;
        }
        let Some(tcp) = TcpPacket::parse(packet) else {
            return false;
        };
        let peer = &self.0.rules.peers[&key];
        let (local_ip, remote_ip, local_port, remote_port) = if inbound {
            (
                tcp.destination,
                tcp.source,
                tcp.destination_port,
                tcp.source_port,
            )
        } else {
            (
                tcp.source,
                tcp.destination,
                tcp.source_port,
                tcp.destination_port,
            )
        };
        if !self.0.rules.local_addresses.contains(&local_ip) || !peer.addresses.contains(&remote_ip)
        {
            return false;
        }
        let permitted = if inbound {
            peer.incoming_tcp.contains(&local_port)
        } else {
            peer.outgoing_tcp.contains(&remote_port)
        };
        let flow_key = FlowKey {
            peer: key,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
        };
        let now = Instant::now();
        // Prune before admission; bounded even under a flood of distinct SYNs.
        if self.0.next_prune.is_none_or(|d| d <= now) {
            self.0.flows.retain(|_, f| f.deadline > now);
            self.0.next_prune = Some(now + Duration::from_secs(1));
        }
        if self
            .0
            .flows
            .get(&flow_key)
            .is_some_and(|f| f.deadline <= now)
        {
            self.0.flows.remove(&flow_key);
        }
        let syn = tcp.flags & 0x02 != 0;
        let ack = tcp.flags & 0x10 != 0;
        let rst = tcp.flags & 0x04 != 0;
        let fin = tcp.flags & 0x01 != 0;
        if syn && (rst || fin) {
            return false;
        }
        if let Some(flow) = self.0.flows.get_mut(&flow_key) {
            let initiator = flow.inbound == inbound;
            let valid = match flow.stage {
                Stage::Syn => {
                    if !initiator
                        && syn
                        && ack
                        && tcp.acknowledgment == flow.initial_sequence.wrapping_add(1)
                    {
                        flow.response_sequence = tcp.sequence;
                        flow.stage = Stage::SynAck;
                        true
                    } else {
                        initiator && syn && !ack && tcp.sequence == flow.initial_sequence
                            || !initiator
                                && rst
                                && ack
                                && tcp.acknowledgment == flow.initial_sequence.wrapping_add(1)
                    }
                }
                Stage::SynAck => {
                    if initiator
                        && ack
                        && !syn
                        && tcp.acknowledgment == flow.response_sequence.wrapping_add(1)
                    {
                        flow.stage = Stage::Established;
                        true
                    } else {
                        !initiator
                            && syn
                            && ack
                            && tcp.sequence == flow.response_sequence
                            && tcp.acknowledgment == flow.initial_sequence.wrapping_add(1)
                            || initiator && syn && !ack && tcp.sequence == flow.initial_sequence
                            || rst && ack
                    }
                }
                Stage::Established => !syn && (ack || rst),
            };
            if !valid {
                return false;
            }
            if !flow.closing {
                flow.deadline = now
                    + if fin {
                        FIN_TIMEOUT
                    } else if flow.stage == Stage::Established {
                        IDLE_TIMEOUT
                    } else {
                        SYN_TIMEOUT
                    };
            }
            if fin {
                flow.closing = true;
            }
            if rst {
                self.0.flows.remove(&flow_key);
            }
            return true;
        }
        if !syn || ack || rst || fin || tcp.payload_len != 0 {
            return false;
        }
        if !permitted || self.0.flows.len() >= MAX_FLOWS {
            return false;
        }
        self.0.flows.insert(
            flow_key,
            Flow {
                inbound,
                stage: Stage::Syn,
                initial_sequence: tcp.sequence,
                response_sequence: 0,
                deadline: now + SYN_TIMEOUT,
                closing: false,
            },
        );
        true
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    Syn,
    SynAck,
    Established,
}
struct Flow {
    inbound: bool,
    stage: Stage,
    initial_sequence: u32,
    response_sequence: u32,
    deadline: Instant,
    closing: bool,
}
#[derive(Hash, PartialEq, Eq)]
struct FlowKey {
    peer: PeerKey,
    local_ip: IpAddr,
    remote_ip: IpAddr,
    local_port: u16,
    remote_port: u16,
}

struct TcpPacket {
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    flags: u8,
    sequence: u32,
    acknowledgment: u32,
    payload_len: usize,
}

impl TcpPacket {
    fn parse(packet: &[u8]) -> Option<Self> {
        let (source, destination, offset, end) = match packet.first()? >> 4 {
            4 => {
                if packet.len() < 20 || packet[9] != 6 {
                    return None;
                }
                let offset = usize::from(packet[0] & 15) * 4;
                let end = usize::from(u16::from_be_bytes(packet[2..4].try_into().ok()?));
                // All fragments (including the first), IP options and reserved bits fail closed.
                if offset != 20 || u16::from_be_bytes(packet[6..8].try_into().ok()?) & 0xbfff != 0 {
                    return None;
                }
                (
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?)),
                    IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?)),
                    offset,
                    end,
                )
            }
            6 => {
                // Extension headers, fragments and jumbograms are not supported in this version.
                if packet.len() < 40 || packet[6] != 6 {
                    return None;
                }
                let end = 40 + usize::from(u16::from_be_bytes(packet[4..6].try_into().ok()?));
                (
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?)),
                    IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?)),
                    40,
                    end,
                )
            }
            _ => return None,
        };
        if end != packet.len() || offset + 20 > end {
            return None;
        }
        let tcp = &packet[offset..end];
        let header = usize::from(tcp[12] >> 4) * 4;
        if header < 20 || header > tcp.len() || tcp[12] & 0x0e != 0 {
            return None;
        }
        let source_port = u16::from_be_bytes(tcp[0..2].try_into().ok()?);
        let destination_port = u16::from_be_bytes(tcp[2..4].try_into().ok()?);
        if source_port == 0 || destination_port == 0 {
            return None;
        }
        Some(Self {
            source,
            destination,
            source_port,
            destination_port,
            flags: tcp[13],
            sequence: u32::from_be_bytes(tcp[4..8].try_into().ok()?),
            acknowledgment: u32::from_be_bytes(tcp[8..12].try_into().ok()?),
            payload_len: tcp.len() - header,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(inbound: bool, flags: u8, sequence: u32, acknowledgment: u32, ipv6: bool) -> Vec<u8> {
        let offset = if ipv6 { 40 } else { 20 };
        let mut p = vec![0; offset + 20];
        if ipv6 {
            p[0] = 0x60;
            p[4..6].copy_from_slice(&20u16.to_be_bytes());
            p[6] = 6;
            let local = "fd00::1".parse::<Ipv6Addr>().unwrap().octets();
            let remote = "fd00::2".parse::<Ipv6Addr>().unwrap().octets();
            p[8..24].copy_from_slice(if inbound { &remote } else { &local });
            p[24..40].copy_from_slice(if inbound { &local } else { &remote });
        } else {
            p[0] = 0x45;
            p[2..4].copy_from_slice(&40u16.to_be_bytes());
            p[9] = 6;
            p[12..16].copy_from_slice(if inbound {
                &[10, 77, 0, 2]
            } else {
                &[10, 77, 0, 1]
            });
            p[16..20].copy_from_slice(if inbound {
                &[10, 77, 0, 1]
            } else {
                &[10, 77, 0, 2]
            });
        }
        p[offset..offset + 2]
            .copy_from_slice(&(if inbound { 443u16 } else { 50000u16 }).to_be_bytes());
        p[offset + 2..offset + 4]
            .copy_from_slice(&(if inbound { 50000u16 } else { 443u16 }).to_be_bytes());
        p[offset + 4..offset + 8].copy_from_slice(&sequence.to_be_bytes());
        p[offset + 8..offset + 12].copy_from_slice(&acknowledgment.to_be_bytes());
        p[offset + 12] = 0x50;
        p[offset + 13] = flags;
        p
    }

    fn rules() -> AccessRules {
        AccessRules {
            local_addresses: vec!["10.77.0.1".parse().unwrap(), "fd00::1".parse().unwrap()],
            peers: HashMap::from([(
                [1; 32],
                PeerAccess {
                    addresses: vec!["10.77.0.2".parse().unwrap(), "fd00::2".parse().unwrap()],
                    incoming_tcp: vec![],
                    outgoing_tcp: vec![443],
                },
            )]),
        }
    }

    #[test]
    fn reply_requires_observed_tcp_handshake_for_both_ip_families() {
        for ipv6 in [false, true] {
            let acl = AccessControl::default();
            acl.update(
                rules(),
                Instant::now() + Duration::from_secs(60),
                |_| Ok(()),
            )
            .unwrap();
            let mut guard = acl.lock();
            assert!(!guard.packet_allowed([1; 32], true, &packet(true, 0x10, 10, 11, ipv6)));
            assert!(!guard.packet_allowed([1; 32], true, &packet(true, 0x02, 10, 0, ipv6)));
            assert!(guard.packet_allowed([1; 32], false, &packet(false, 0x02, 100, 0, ipv6)));
            assert!(!guard.packet_allowed([1; 32], true, &packet(true, 0x12, 200, 999, ipv6)));
            assert!(guard.packet_allowed([1; 32], true, &packet(true, 0x12, 200, 101, ipv6)));
            assert!(guard.packet_allowed([1; 32], false, &packet(false, 0x10, 101, 201, ipv6)));
            assert!(guard.packet_allowed([1; 32], true, &packet(true, 0x18, 201, 101, ipv6)));
            assert!(guard.packet_allowed([1; 32], false, &packet(false, 0x14, 101, 201, ipv6)));
            assert!(!guard.packet_allowed([1; 32], true, &packet(true, 0x18, 201, 101, ipv6)));
        }
    }

    #[test]
    fn malformed_fragments_protocols_and_spoofed_sources_are_blocked() {
        let acl = AccessControl::default();
        acl.update(
            rules(),
            Instant::now() + Duration::from_secs(60),
            |_| Ok(()),
        )
        .unwrap();
        let valid = packet(false, 2, 100, 0, false);
        for n in 0..valid.len() {
            assert!(!acl.lock().packet_allowed([1; 32], false, &valid[..n]));
        }
        for (offset, value) in [
            (6, 0x20),
            (7, 1),
            (9, 17),
            (12, 11),
            (16, 11),
            (32, 0x40),
            (22, 0),
            (23, 22),
        ] {
            let mut bad = valid.clone();
            bad[offset] = value;
            assert!(!acl.lock().packet_allowed([1; 32], false, &bad));
        }
        let mut ext = packet(false, 2, 100, 0, true);
        ext[6] = 44;
        assert!(!acl.lock().packet_allowed([1; 32], false, &ext));
        assert!(!acl.lock().packet_allowed([2; 32], false, &valid));
    }

    #[test]
    fn lease_renewal_preserves_flows_and_revocation_expiry_or_failed_apply_blocks_them() {
        let acl = AccessControl::default();
        let future = Instant::now() + Duration::from_secs(60);
        acl.update(rules(), future, |changed| {
            assert!(changed);
            Ok(())
        })
        .unwrap();
        assert!(
            acl.lock()
                .packet_allowed([1; 32], false, &packet(false, 2, 100, 0, false))
        );
        acl.update(rules(), future, |changed| {
            assert!(!changed);
            Ok(())
        })
        .unwrap();
        assert_eq!(acl.lock().0.flows.len(), 1);
        let mut revoked = rules();
        revoked
            .peers
            .get_mut(&[1; 32])
            .unwrap()
            .outgoing_tcp
            .clear();
        acl.update(revoked, future, |changed| {
            assert!(changed);
            Ok(())
        })
        .unwrap();
        assert!(acl.lock().0.flows.is_empty());
        assert!(
            !acl.lock()
                .packet_allowed([1; 32], false, &packet(false, 2, 100, 0, false))
        );
        acl.update(rules(), Instant::now() - Duration::from_secs(1), |_| Ok(()))
            .unwrap();
        assert!(!acl.lock().peer_allowed(&[1; 32]));
        let result: Result<(), String> =
            acl.update(rules(), future, |_| Err("route update failed".into()));
        assert!(result.is_err());
        assert!(!acl.lock().peer_allowed(&[1; 32]));
    }

    #[test]
    fn policy_replacement_waits_for_inflight_packet_processing() {
        let acl = std::sync::Arc::new(AccessControl::default());
        let guard = acl.lock();
        let (started, receiver) = std::sync::mpsc::channel();
        let other = acl.clone();
        let task = std::thread::spawn(move || {
            other
                .update(rules(), Instant::now() + Duration::from_secs(60), |_| {
                    started.send(()).unwrap();
                    Ok(())
                })
                .unwrap()
        });
        assert!(receiver.recv_timeout(Duration::from_millis(30)).is_err());
        drop(guard);
        receiver.recv_timeout(Duration::from_secs(1)).unwrap();
        task.join().unwrap();
    }

    #[test]
    fn discarding_pending_plaintext_preserves_wireguard_handshake_and_session() {
        use boringtun::noise::{Tunn, TunnResult};
        use boringtun::x25519::{PublicKey, StaticSecret};
        let secret_a = StaticSecret::from([7; 32]);
        let secret_b = StaticSecret::from([8; 32]);
        let key_a = PublicKey::from(&secret_a);
        let key_b = PublicKey::from(&secret_b);
        let mut a = Tunn::new(secret_a, key_b, None, None, 1, None);
        let mut b = Tunn::new(secret_b, key_a, None, None, 2, None);
        let mut buffer = vec![0u8; 66000];
        let init = match a.encapsulate(&packet(false, 2, 100, 0, false), &mut buffer) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected initiation: {other:?}"),
        };
        assert_eq!(a.discard_queued_packets(), 1);
        assert_eq!(a.discard_queued_packets(), 0);
        let response = match b.decapsulate(None, &init, &mut buffer) {
            TunnResult::WriteToNetwork(p) => p.to_vec(),
            other => panic!("expected response: {other:?}"),
        };
        assert!(matches!(
            a.decapsulate(None, &response, &mut buffer),
            TunnResult::WriteToNetwork(_)
        ));
        assert!(matches!(
            a.decapsulate(None, &[], &mut buffer),
            TunnResult::Done
        ));
        match a.encapsulate(&packet(false, 2, 200, 0, false), &mut buffer) {
            TunnResult::WriteToNetwork(p) => assert_eq!(&p[..4], &4u32.to_le_bytes()),
            other => panic!("session should remain established: {other:?}"),
        }
    }
}
