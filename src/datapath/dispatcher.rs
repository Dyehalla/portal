//! Platform-independent scheduling between packet sources and worker rings.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;

use crate::datapath::pipeline::{Completion, DispatcherPort, RxMessage};
use crate::device::{Device, DeviceSnapshot, TunnelAssignment};
use crate::index_table::{Route, WorkerId};
use crate::ring::BufPool;

const TIMER_INTERVAL: Duration = Duration::from_secs(1);

/// Shared dispatch state that does not depend on a particular socket or TUN API.
pub struct DispatcherCore {
    workers: HashMap<WorkerId, DispatcherPort>,
    snapshot: Arc<ArcSwap<DeviceSnapshot>>,
    endpoints: HashMap<Route, SocketAddr>,
    pending_flush: VecDeque<Route>,
    last_timer: Instant,
}

impl DispatcherCore {
    /// Connects worker queues to the current device snapshot and endpoints.
    pub fn new(device: &Device, workers: HashMap<WorkerId, DispatcherPort>) -> Self {
        let snapshot = device.snapshot();
        let endpoints = snapshot
            .assignments()
            .into_iter()
            .filter_map(|(_, assignment, endpoint)| {
                endpoint.map(|endpoint| (route(assignment), endpoint))
            })
            .collect();
        Self {
            workers,
            snapshot: device.snapshot_source(),
            endpoints,
            pending_flush: VecDeque::new(),
            last_timer: Instant::now(),
        }
    }

    /// Returns worker identifiers for polling their completion queues.
    pub fn worker_ids(&self) -> Vec<WorkerId> {
        self.workers.keys().copied().collect()
    }

    /// Routes one message into a worker ring, recycling owned packet buffers on failure.
    pub fn push_to_worker(
        &mut self,
        pool: &mut BufPool,
        worker: WorkerId,
        message: RxMessage,
    ) -> bool {
        let Some(port) = self.workers.get_mut(&worker) else {
            recycle_message(pool, message);
            return false;
        };
        let was_empty = port.ingress.is_empty();
        if let Err(message) = port.ingress.try_push(message) {
            recycle_message(pool, message);
            false
        } else {
            if was_empty {
                if let Some(wake) = &port.wake {
                    wake.unpark();
                }
            }
            true
        }
    }

    /// Removes one completion from a worker's SPSC egress ring.
    pub fn pop_completion(&mut self, worker: WorkerId) -> Option<Completion> {
        self.workers.get_mut(&worker)?.egress.try_pop()
    }

    /// Records authenticated roaming and schedules any queued tunnel packets.
    pub fn accept_completion(&mut self, completion: &Completion) {
        if let Some(source) = completion.authenticated_source {
            self.endpoints.insert(completion.route, source);
        }
        if completion.flush_more {
            self.pending_flush.push_back(completion.route);
        }
    }

    /// Resolves a worker's peer route to its current authenticated endpoint.
    pub fn endpoint(&self, route: Route) -> Option<SocketAddr> {
        self.endpoints.get(&route).copied()
    }

    /// Replaces a configured or authenticated endpoint after a peer update.
    pub fn set_endpoint(&mut self, route: Route, endpoint: Option<SocketAddr>) {
        if let Some(endpoint) = endpoint {
            self.endpoints.insert(route, endpoint);
        } else {
            self.endpoints.remove(&route);
        }
    }

    /// Schedules flush work for worker-held packets after a handshake completes.
    pub fn schedule_pending_flushes(&mut self, pool: &mut BufPool) {
        let pending = self.pending_flush.len();
        for _ in 0..pending {
            let Some(route) = self.pending_flush.pop_front() else {
                break;
            };
            let Some(handle) = pool.allocate() else {
                self.pending_flush.push_front(route);
                break;
            };
            if !self.push_to_worker(
                pool,
                route.worker,
                RxMessage::Flush {
                    handle,
                    tunnel: route.tunnel,
                },
            ) {
                self.pending_flush.push_back(route);
            }
        }
    }

    /// Schedules periodic timer work for each configured tunnel.
    pub fn schedule_timers(&mut self, pool: &mut BufPool, now: Instant) {
        if now.duration_since(self.last_timer) < TIMER_INTERVAL {
            return;
        }
        self.last_timer = now;
        let assignments = self.snapshot.load().assignments();
        for (_, assignment, _) in assignments {
            let Some(handle) = pool.allocate() else {
                break;
            };
            self.push_to_worker(
                pool,
                assignment.worker,
                RxMessage::Timer {
                    handle,
                    tunnel: assignment.tunnel,
                },
            );
        }
    }

    /// Resolves the inner destination using the current longest-prefix routes.
    pub fn route_for_ip(&self, address: IpAddr) -> Option<TunnelAssignment> {
        self.snapshot.load().route_for_ip(address)
    }
}

fn route(assignment: TunnelAssignment) -> Route {
    Route {
        worker: assignment.worker,
        tunnel: assignment.tunnel,
    }
}

fn recycle_message(pool: &mut BufPool, message: RxMessage) {
    match message {
        RxMessage::Packet { handle, spare, .. } => {
            pool.recycle(handle);
            pool.recycle(spare);
        }
        RxMessage::Timer { handle, .. } | RxMessage::Flush { handle, .. } => pool.recycle(handle),
    }
}
