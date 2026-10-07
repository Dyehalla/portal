use std::net::SocketAddr;
use std::time::Duration;

// HTTP connections and Samba each have a bounded five-second shutdown budget.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(11);

use portal_files::{FileService, FileServiceConfig};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Own the Tokio tasks that serve peer-facing HTTP feature services.
pub(crate) struct PeerServices {
    runtime: Runtime,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), String>>,
    http_address: SocketAddr,
}

impl PeerServices {
    /// Bind configured peer services, and start serving in a Tokio runtime.
    pub(crate) fn start(
        http_address: SocketAddr,
        file_config: Option<FileServiceConfig>,
        smb_config: Option<portal_files::SmbConfig>,
    ) -> Result<Self, String> {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not create peer service runtime: {error}"))?;
        let file_service =
            runtime.block_on(FileService::new(http_address, file_config, smb_config))?;
        let http_address = file_service.http_addr();

        let (shutdown, receiver) = watch::channel(false);
        let task = runtime.spawn(file_service.serve(wait_for_shutdown(receiver)));

        Ok(Self {
            runtime,
            shutdown,
            task,
            http_address,
        })
    }

    /// Return the bound HTTP addresses for the runtime's startup log.
    pub(crate) fn address(&self) -> SocketAddr {
        self.http_address
    }

    /// Report whether peer-facing server task exited before runtime shutdown.
    pub(crate) fn has_exited(&self) -> bool {
        self.task.is_finished()
    }

    /// Stop the server and wait until their listeners have shut down.
    pub(crate) fn stop(self) -> Result<(), String> {
        let _ = self.shutdown.send(true);
        let result = self.runtime.block_on(stop_task(self.task));
        // Drop all remaining connection tasks without waiting indefinitely for blocking IO.
        self.runtime.shutdown_timeout(Duration::from_secs(1));
        result
    }
}

/// Wait until the owning runtime sends the shared shutdown signal.
async fn wait_for_shutdown(mut receiver: watch::Receiver<bool>) {
    while !*receiver.borrow() {
        if receiver.changed().await.is_err() {
            break;
        }
    }
}

async fn stop_task(mut task: JoinHandle<Result<(), String>>) -> Result<(), String> {
    match tokio::time::timeout(SHUTDOWN_GRACE, &mut task).await {
        Ok(result) => result.map_err(|error| format!("peer service task failed: {error}"))?,
        Err(_) => {
            task.abort();
            let _ = task.await;
            Err("peer services exceeded shutdown grace period; connections were cancelled".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancels_stalled_server() {
        let task = tokio::spawn(std::future::pending::<Result<(), String>>());
        let abort = task.abort_handle();
        assert!(stop_task(task).await.unwrap_err().contains("grace period"));
        assert!(abort.is_finished());
    }
}
