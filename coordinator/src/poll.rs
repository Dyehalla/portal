use crate::error::{Error, Result};
use std::{
    collections::HashSet,
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};

#[derive(Clone)]
pub(crate) struct KeyedLimiter {
    keys: Arc<Mutex<HashSet<[u8; 32]>>>,
    capacity: usize,
}

impl KeyedLimiter {
    pub fn new(capacity: usize) -> Self {
        Self {
            keys: Arc::new(Mutex::new(HashSet::new())),
            capacity,
        }
    }

    pub fn acquire(&self, key: [u8; 32]) -> Result<PollPermit> {
        let mut keys = self.keys.lock().map_err(|_| Error::internal())?;
        if keys.len() >= self.capacity || !keys.insert(key) {
            return Err(Error::busy());
        }
        Ok(PollPermit {
            limiter: self.clone(),
            key,
        })
    }
}

pub(crate) struct PollPermit {
    limiter: KeyedLimiter,
    key: [u8; 32],
}

impl Drop for PollPermit {
    fn drop(&mut self) {
        if let Ok(mut keys) = self.limiter.keys.lock() {
            keys.remove(&self.key);
        }
    }
}

/// Subscribe before reading state; after each wake callers recheck authenticated state.
pub(crate) struct WaitUntilChange {
    changes: watch::Receiver<u64>,
    signals: Option<watch::Receiver<u64>>,
    deadline: Instant,
}

impl WaitUntilChange {
    pub fn new(
        wait_seconds: Option<u64>,
        maximum: Duration,
        mut changes: watch::Receiver<u64>,
        mut signals: Option<watch::Receiver<u64>>,
    ) -> Result<Self> {
        let seconds = wait_seconds.unwrap_or(25);
        if seconds > 25 {
            return Err(Error::bad_request("wait_seconds must be between 0 and 25"));
        }
        changes.borrow_and_update();
        if let Some(signals) = &mut signals {
            signals.borrow_and_update();
        }
        Ok(Self {
            changes,
            signals,
            deadline: Instant::now() + Duration::from_secs(seconds).min(maximum),
        })
    }

    pub fn expired(&self) -> bool {
        Instant::now() >= self.deadline
    }

    pub async fn recheck<T, F: Future<Output = Result<T>>>(
        &mut self,
        authenticated_read: impl FnOnce() -> F,
    ) -> Result<T> {
        let signals = async {
            match &mut self.signals {
                Some(signals) => signals.changed().await.map_err(|_| Error::internal()),
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            result = self.changes.changed() => { result.map_err(|_| Error::internal())?; }
            result = signals => { result?; }
            _ = tokio::time::sleep_until(self.deadline) => {}
        }
        authenticated_read().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_unique_bounded_and_returned_on_drop() {
        let limiter = KeyedLimiter::new(2);
        let first = limiter.acquire([1; 32]).unwrap();
        assert!(limiter.acquire([1; 32]).is_err());
        let second = limiter.acquire([2; 32]).unwrap();
        assert!(limiter.acquire([3; 32]).is_err());
        drop(first);
        let third = limiter.acquire([3; 32]).unwrap();
        drop((second, third));
        assert!(limiter.acquire([1; 32]).is_ok());
    }
}
