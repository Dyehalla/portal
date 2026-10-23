use crate::{
    credentials::{self, Credential},
    error::{Error, Result},
    store::ConnectionContext,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio::{
    sync::{oneshot, watch},
    time::Instant,
};

pub(crate) const REQUEST_TTL: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub(crate) struct PendingInfo {
    pub id: String,
    pub requester_id: String,
    pub target_id: String,
    pub requester_credential: Credential,
    pub deadline: Instant,
    pub expires_at: u64,
}

struct Pending {
    info: PendingInfo,
    response: oneshot::Sender<Result<bool>>,
}

#[derive(Default)]
struct State {
    pending: HashMap<String, Pending>,
}

struct Shared {
    state: Mutex<State>,
    changes: watch::Sender<u64>,
}

/// In-memory rendezvous only. No session forwarding or persistent offline queue.
#[derive(Clone)]
pub(crate) struct Signaling(Arc<Shared>);

impl Signaling {
    pub fn new() -> Self {
        let (changes, _) = watch::channel(0);
        Self(Arc::new(Shared {
            state: Mutex::new(State::default()),
            changes,
        }))
    }

    fn state(&self) -> Result<MutexGuard<'_, State>> {
        let mut state = self.0.state.lock().map_err(|_| Error::internal())?;
        let now = Instant::now();
        let expired: Vec<_> = state
            .pending
            .iter()
            .filter(|(_, p)| p.info.deadline <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired {
            if let Some(pending) = state.pending.remove(&id) {
                let _ = pending.response.send(Err(Error::timeout()));
            }
        }
        Ok(state)
    }

    fn notify(&self) {
        self.0
            .changes
            .send_modify(|version| *version = version.wrapping_add(1));
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.changes.subscribe()
    }

    pub fn request(&self, context: &ConnectionContext, credential: Credential) -> Result<Ticket> {
        let mut state = self.state()?;
        if state.pending.values().any(|p| {
            p.info.requester_id == context.requester.id && p.info.target_id == context.target.id
        }) {
            return Err(Error::conflict(
                "a connection request for this peer is already pending",
            ));
        }
        if state.pending.len() >= 64
            || state
                .pending
                .values()
                .filter(|p| p.info.requester_id == context.requester.id)
                .count()
                >= 4
            || state
                .pending
                .values()
                .filter(|p| p.info.target_id == context.target.id)
                .count()
                >= 8
        {
            return Err(Error::busy());
        }
        let info = PendingInfo {
            id: credentials::random_hex(16),
            requester_id: context.requester.id.clone(),
            target_id: context.target.id.clone(),
            requester_credential: credential,
            deadline: Instant::now() + REQUEST_TTL,
            expires_at: context.generated_at + REQUEST_TTL.as_secs(),
        };
        let (sender, response) = oneshot::channel();
        state.pending.insert(
            info.id.clone(),
            Pending {
                info: info.clone(),
                response: sender,
            },
        );
        drop(state);
        self.notify();
        Ok(Ticket {
            info,
            response,
            signaling: self.clone(),
        })
    }

    pub fn incoming(&self, target_id: &str) -> Result<Vec<PendingInfo>> {
        let mut pending: Vec<_> = self
            .state()?
            .pending
            .values()
            .filter(|p| p.info.target_id == target_id)
            .map(|p| p.info.clone())
            .collect();
        pending.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(pending)
    }

    pub fn get(&self, id: &str) -> Result<PendingInfo> {
        self.state()?
            .pending
            .get(id)
            .map(|p| p.info.clone())
            .ok_or_else(Error::not_found)
    }

    pub fn respond(&self, id: &str, target_id: &str, accept: bool) -> Result<()> {
        let mut state = self.state()?;
        let pending = state.pending.get(id).ok_or_else(Error::not_found)?;
        if pending.info.target_id != target_id {
            return Err(Error::not_found());
        }
        let pending = state.pending.remove(id).expect("validated pending request");
        drop(state);
        self.notify();
        pending
            .response
            .send(Ok(accept))
            .map_err(|_| Error::conflict("requester is no longer waiting"))
    }

    pub fn fail(&self, id: &str, error: Error) {
        if let Ok(mut state) = self.0.state.lock()
            && let Some(pending) = state.pending.remove(id)
        {
            let _ = pending.response.send(Err(error));
            drop(state);
            self.notify();
        }
    }
}

pub(crate) struct Ticket {
    pub info: PendingInfo,
    pub response: oneshot::Receiver<Result<bool>>,
    signaling: Signaling,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.signaling
            .fail(&self.info.id, Error::conflict("requester stopped waiting"));
    }
}
