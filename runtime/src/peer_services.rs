use std::net::SocketAddr;
use std::time::Duration;

// HTTP connections and Samba each have a bounded five-second shutdown budget.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(11);

use crate::grpc::GrpcServer;
use portal_files::{FileService, FileServiceConfig};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Own the Tokio tasks that serve peer-facing gRPC and HTTP feature services.
pub(crate) struct PeerServices {
    runtime: Runtime,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), String>>,
    grpc_address: SocketAddr,
    http_address: Option<SocketAddr>,
}

impl PeerServices {
    /// Bind configured peer services, register their RPCs, and start serving in a Tokio runtime.
    pub(crate) fn start(
        grpc_address: SocketAddr,
        file_config: Option<FileServiceConfig>,
        smb_config: Option<portal_files::SmbConfig>,
    ) -> Result<Self, String> {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not create peer service runtime: {error}"))?;
        let file_service = runtime.block_on(FileService::new_with_smb(file_config, smb_config))?;
        let http_address = file_service.http_addr();
        let mut grpc_server = GrpcServer::new(grpc_address);
        grpc_server.add_service(file_service.grpc_service());
        let grpc_server = runtime.block_on(grpc_server.bind())?;
        let grpc_address = grpc_server.local_addr();

        let (shutdown, receiver) = watch::channel(false);
        let grpc_receiver = receiver.clone();
        let task = runtime.spawn(async move {
            let grpc = grpc_server.serve_with_shutdown(wait_for_shutdown(grpc_receiver));
            let http = file_service.serve(wait_for_shutdown(receiver));
            tokio::try_join!(grpc, http).map(|_| ())
        });

        Ok(Self {
            runtime,
            shutdown,
            task,
            grpc_address,
            http_address,
        })
    }

    /// Return the bound gRPC and HTTP addresses for the runtime's startup log.
    pub(crate) fn addresses(&self) -> (SocketAddr, Option<SocketAddr>) {
        (self.grpc_address, self.http_address)
    }

    /// Report whether either peer-facing server task exited before runtime shutdown.
    pub(crate) fn has_exited(&self) -> bool {
        self.task.is_finished()
    }

    /// Stop both servers and wait until their listeners have shut down.
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
