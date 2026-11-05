//! Bounded direct-path probing. Authentication is supplied by WireGuard itself.
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const FRESH: Duration = Duration::from_secs(90);
const ROUND: Duration = Duration::from_secs(15);
const BACKOFF: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug)]
pub struct PeerPath {
    pub state: &'static str,
    pub endpoint: Option<SocketAddr>,
}

#[derive(Default)]
pub(crate) struct DirectPath {
    candidates: Vec<SocketAddr>,
    verified: Option<(SocketAddr, Instant)>,
    round: Option<Instant>,
    next: Option<Instant>,
}

impl DirectPath {
    pub fn configure(&mut self, candidates: Vec<SocketAddr>, now: Instant) {
        if candidates != self.candidates {
            self.candidates = candidates;
            self.round = None;
            self.next = Some(now);
        }
    }

    pub fn request_probe(&mut self, now: Instant) {
        if self.snapshot(now).state != "direct" && self.round.is_none() {
            self.next = Some(now);
        }
    }

    pub fn received(&mut self, source: SocketAddr, now: Instant) {
        self.verified = Some((source, now));
        self.round = None;
        self.next = Some(now + FRESH);
    }

    pub fn snapshot(&self, now: Instant) -> PeerPath {
        if let Some((endpoint, time)) = self.verified
            && now.duration_since(time) < FRESH
        {
            return PeerPath {
                state: "direct",
                endpoint: Some(endpoint),
            };
        }
        PeerPath {
            state: if self.round.is_some() {
                "probing"
            } else {
                "offline"
            },
            endpoint: None,
        }
    }

    pub fn probes(&mut self, now: Instant) -> Vec<SocketAddr> {
        if self.candidates.is_empty() || self.next.is_some_and(|next| now < next) {
            return Vec::new();
        }
        if self
            .round
            .is_some_and(|start| now.duration_since(start) >= ROUND)
        {
            self.round = None;
            self.next = Some(now + BACKOFF);
            return Vec::new();
        }
        self.round.get_or_insert(now);
        self.next = Some(now + Duration::from_secs(5));
        let mut candidates = self.candidates.clone();
        if let Some((endpoint, _)) = self.verified
            && !candidates.contains(&endpoint)
        {
            candidates.push(endpoint);
        }
        candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_round_backoff_confirmation_roaming_and_expiry() {
        let now = Instant::now();
        let a = "127.0.0.1:1".parse().unwrap();
        let b = "127.0.0.1:2".parse().unwrap();
        let mut path = DirectPath::default();
        path.configure(vec![a, b], now);
        assert_eq!(path.probes(now), [a, b]);
        assert_eq!(path.snapshot(now).state, "probing");
        assert!(path.probes(now + Duration::from_secs(1)).is_empty());
        assert!(path.probes(now + ROUND).is_empty());
        assert_eq!(path.snapshot(now + ROUND).state, "offline");
        assert!(
            path.probes(now + ROUND + BACKOFF - Duration::from_secs(1))
                .is_empty()
        );
        assert_eq!(path.probes(now + ROUND + BACKOFF), [a, b]);
        path.received(b, now + ROUND + BACKOFF);
        assert_eq!(path.snapshot(now + ROUND + BACKOFF).endpoint, Some(b));
        assert!(path.probes(now + ROUND + BACKOFF).is_empty());
        assert_eq!(
            path.snapshot(now + ROUND + BACKOFF + FRESH).state,
            "offline"
        );
        assert_eq!(path.probes(now + ROUND + BACKOFF + FRESH), [a, b]);
    }
}
