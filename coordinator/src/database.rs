use crate::{
    error::{Error, Result},
    store::Store,
};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, watch};

type Job = Box<dyn FnOnce(&mut Store) + Send>;

struct Inner {
    sender: Option<mpsc::Sender<Job>>,
    worker: Option<std::thread::JoinHandle<()>>,
    changes: watch::Receiver<u64>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// All SQLite work runs on one dedicated thread, behind a bounded queue.
#[derive(Clone)]
pub(crate) struct Database(Arc<Inner>);

impl Database {
    pub fn new(mut store: Store) -> std::result::Result<Self, String> {
        let revision = store
            .revision()
            .map_err(|_| "could not read network revision")?;
        let (sender, mut receiver) = mpsc::channel::<Job>(128);
        let (changes, change_receiver) = watch::channel(revision);
        let worker = std::thread::Builder::new()
            .name("portal-coordinator-db".into())
            .spawn(move || {
                while let Some(job) = receiver.blocking_recv() {
                    job(&mut store);
                    let Ok(revision) = store.revision() else {
                        break;
                    };
                    changes.send_if_modified(|current| {
                        if *current == revision {
                            return false;
                        }
                        *current = revision;
                        true
                    });
                }
            })
            .map_err(|e| format!("could not start coordinator database worker: {e}"))?;
        Ok(Self(Arc::new(Inner {
            sender: Some(sender),
            worker: Some(worker),
            changes: change_receiver,
        })))
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.0.changes.clone()
    }

    pub async fn call<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (sender, receiver) = oneshot::channel();
        self.0
            .sender
            .as_ref()
            .expect("live database sender")
            .try_send(Box::new(move |store| {
                let _ = sender.send(operation(store));
            }))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => Error::busy(),
                mpsc::error::TrySendError::Closed(_) => Error::internal(),
            })?;
        receiver.await.map_err(|_| Error::internal())?
    }
}
