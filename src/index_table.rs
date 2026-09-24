//! Read-mostly mapping from WireGuard receiver indices to worker-owned tunnels.

use std::collections::HashMap;
use std::sync::RwLock;

/// Stable worker identifier used by the control and dispatcher planes.
pub type WorkerId = usize;
/// Stable tunnel identifier within a worker.
pub type TunnelId = u64;

/// The destination of a packet addressed to a receiver index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Route {
    pub worker: WorkerId,
    pub tunnel: TunnelId,
}

/// Device-wide index ownership. The lock is held only around a hash lookup or
/// one table mutation; packet processing and cryptography run after lookup.
pub struct IndexTable {
    routes: RwLock<HashMap<u32, Route>>,
}

impl Default for IndexTable {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexTable {
    /// Creates an empty index table.
    pub fn new() -> Self {
        Self {
            routes: RwLock::new(HashMap::new()),
        }
    }

    /// Claims a nonzero receiver index without replacing another owner's route.
    pub fn try_claim(&self, index: u32, route: Route) -> bool {
        if index == 0 {
            return false;
        }
        let Ok(mut routes) = self.routes.write() else {
            return false;
        };
        match routes.entry(index) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(route);
                true
            }
            std::collections::hash_map::Entry::Occupied(_) => false,
        }
    }

    /// Looks up the owner of an index.
    pub fn lookup(&self, index: u32) -> Option<Route> {
        self.routes.read().ok()?.get(&index).copied()
    }

    /// Releases an index only if it is still owned by `route`.
    pub fn release(&self, index: u32, route: Route) -> bool {
        let Ok(mut routes) = self.routes.write() else {
            return false;
        };
        if routes.get(&index) != Some(&route) {
            return false;
        }
        routes.remove(&index);
        true
    }

    /// Removes all routes belonging to one tunnel and returns the count.
    pub fn release_tunnel(&self, route: Route) -> usize {
        let Ok(mut routes) = self.routes.write() else {
            return 0;
        };
        let before = routes.len();
        routes.retain(|_, owner| *owner != route);
        before - routes.len()
    }

    /// Number of currently claimed receiver indices.
    pub fn len(&self) -> usize {
        self.routes.read().map_or(0, |routes| routes.len())
    }

    /// Whether no receiver indices are claimed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    /// Claims are unique device-wide and a collision never steals a route.
    #[test]
    fn a_receiver_index_cannot_be_claimed_twice() {
        let table = IndexTable::new();
        let first = Route {
            worker: 1,
            tunnel: 10,
        };
        let second = Route {
            worker: 2,
            tunnel: 20,
        };

        assert!(!table.try_claim(0, first));
        assert!(table.try_claim(7, first));
        assert!(!table.try_claim(7, second));
        assert_eq!(table.lookup(7), Some(first));
    }

    /// A stale owner cannot release an index that has since changed ownership.
    #[test]
    fn release_requires_the_current_owner() {
        let table = IndexTable::new();
        let first = Route {
            worker: 0,
            tunnel: 1,
        };
        let other = Route {
            worker: 0,
            tunnel: 2,
        };
        assert!(table.try_claim(42, first));
        assert!(!table.release(42, other));
        assert_eq!(table.lookup(42), Some(first));
        assert!(table.release(42, first));
        assert_eq!(table.lookup(42), None);
    }

    /// Competing workers cannot both reserve one receiver index.
    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        let table = Arc::new(IndexTable::new());
        let workers = (0..8)
            .map(|worker| {
                let table = Arc::clone(&table);
                thread::spawn(move || {
                    table.try_claim(
                        9,
                        Route {
                            worker,
                            tunnel: worker as u64,
                        },
                    )
                })
            })
            .collect::<Vec<_>>();
        let wins = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(wins, 1);
        assert!(table.lookup(9).is_some());
    }

    /// Closing a tunnel reclaims only its own receiver indices.
    #[test]
    fn tunnel_reclaim_preserves_neighbor_routes() {
        let table = IndexTable::new();
        let a = Route {
            worker: 1,
            tunnel: 4,
        };
        let b = Route {
            worker: 1,
            tunnel: 5,
        };
        assert!(table.try_claim(1, a));
        assert!(table.try_claim(2, a));
        assert!(table.try_claim(3, b));
        assert_eq!(table.release_tunnel(a), 2);
        assert_eq!(table.lookup(1), None);
        assert_eq!(table.lookup(3), Some(b));
    }
}
