use std::time::Duration;

// Bound the time spent stopping service tasks.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(6);

use crate::services::{ServiceContext, ServiceRegistration, ServiceTask};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Own the Tokio tasks that serve peer-facing QUIC services.
pub(crate) struct PeerServices {
    executor: Handle,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), String>>,
}

impl PeerServices {
    /// Prepare services and spawn their tasks on the shared application runtime.
    pub(crate) fn start(
        executor: &Handle,
        network: portal_net::Net,
        services: Vec<ServiceRegistration>,
    ) -> Result<Self, String> {
        let context = ServiceContext {
            network: network.clone(),
        };
        let (registry, background) = executor.block_on(prepare_services(context, services))?;
        Self::from_prepared(executor, network, registry, background)
    }

    pub(crate) fn from_prepared(
        executor: &Handle,
        network: portal_net::Net,
        registry: portal_net::Registry,
        background: Vec<(String, ServiceTask)>,
    ) -> Result<Self, String> {
        let (shutdown, receiver) = watch::channel(false);
        let (ready, started) = tokio::sync::oneshot::channel();
        let task = executor.spawn(serve_services(
            network, registry, background, receiver, ready,
        ));
        let result = executor
            .block_on(async { tokio::time::timeout(Duration::from_secs(5), started).await });
        if !matches!(result, Ok(Ok(()))) {
            task.abort();
            let _ = executor.block_on(task);
            return Err("QUIC service host failed to start".into());
        }
        Ok(Self {
            executor: executor.clone(),
            shutdown,
            task,
        })
    }

    /// Report whether peer-facing server task exited before runtime shutdown.
    pub(crate) fn has_exited(&self) -> bool {
        self.task.is_finished()
    }

    /// Stop the server and wait until their listeners have shut down.
    pub(crate) fn stop(self) -> Result<(), String> {
        let _ = self.shutdown.send(true);
        self.executor.block_on(stop_task(self.task))
    }
}

pub(crate) async fn prepare_services(
    context: ServiceContext,
    services: Vec<ServiceRegistration>,
) -> Result<(portal_net::Registry, Vec<(String, ServiceTask)>), String> {
    let mut names = std::collections::HashSet::new();
    for service in &services {
        if service.name.is_empty() || !names.insert(service.name.clone()) {
            return Err(format!(
                "invalid or duplicate service name `{}`",
                service.name
            ));
        }
    }
    let mut registry = portal_net::Registry::default();
    let mut background = Vec::new();
    for service in services {
        let prepared = (service.factory)(context.clone())
            .await
            .map_err(|e| format!("service `{}` could not start: {e}", service.name))?;
        registry.register(prepared.service)?;
        if let Some(task) = prepared.background {
            background.push((service.name, task));
        }
    }
    Ok((registry, background))
}

async fn serve_services(
    network: portal_net::Net,
    registry: portal_net::Registry,
    background: Vec<(String, ServiceTask)>,
    receiver: watch::Receiver<bool>,
    ready: tokio::sync::oneshot::Sender<()>,
) -> Result<(), String> {
    let mut tasks = tokio::task::JoinSet::new();
    for (name, task) in background {
        tasks.spawn(async move { (name, task.await) });
    }
    let server = network.serve_with_ready(registry, wait_for_shutdown(receiver), move || {
        let _ = ready.send(());
    });
    tokio::pin!(server);
    let result = tokio::select! {
        result = &mut server => result.map_err(|e| format!("peer QUIC server failed: {e}")),
        Some(result) = tasks.join_next(), if !tasks.is_empty() => {
            match result {
                Ok((name, Ok(()))) => Err(format!("service `{name}` background task exited unexpectedly")),
                Ok((name, Err(error))) => Err(format!("service `{name}` failed: {error}")),
                Err(error) => Err(format!("service background task failed: {error}")),
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
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
