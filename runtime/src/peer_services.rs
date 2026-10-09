use std::net::SocketAddr;
use std::time::Duration;

// Bound the time spent stopping service tasks.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(6);

use crate::services::{ServiceContext, ServiceRegistration, ServiceTask};
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
        network: portal_net::Net,
        http_address: SocketAddr,
        services: Vec<ServiceRegistration>,
    ) -> Result<Self, String> {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not create peer service runtime: {error}"))?;
        let listener = network.listen(http_address).map_err(|e| e.to_string())?;
        let http_address = listener.local_addr();
        let context = ServiceContext {
            network,
            http_address,
        };
        let (router, background) = runtime.block_on(prepare_services(context, services))?;
        let (shutdown, receiver) = watch::channel(false);
        let task = runtime.spawn(serve_services(listener, router, background, receiver));

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

async fn prepare_services(
    context: ServiceContext,
    services: Vec<ServiceRegistration>,
) -> Result<(axum::Router, Vec<(String, ServiceTask)>), String> {
    let mut names = std::collections::HashSet::new();
    for service in &services {
        if service.name.is_empty() || !names.insert(service.name.clone()) {
            return Err(format!(
                "invalid or duplicate service name `{}`",
                service.name
            ));
        }
    }
    let mut router = axum::Router::new();
    let mut background = Vec::new();
    for service in services {
        let prepared = (service.factory)(context.clone())
            .await
            .map_err(|e| format!("service `{}` could not start: {e}", service.name))?;
        // Axum rejects overlapping routes by panicking. Report a startup error instead.
        router = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            router.merge(prepared.router)
        }))
        .map_err(|_| format!("service `{}` has conflicting HTTP routes", service.name))?;
        if let Some(task) = prepared.background {
            background.push((service.name, task));
        }
    }
    Ok((router, background))
}

async fn serve_services(
    listener: portal_net::TcpListener,
    router: axum::Router,
    background: Vec<(String, ServiceTask)>,
    receiver: watch::Receiver<bool>,
) -> Result<(), String> {
    let mut tasks = tokio::task::JoinSet::new();
    for (name, task) in background {
        tasks.spawn(async move { (name, task.await) });
    }
    let server = portal_net::serve_http(listener, router, wait_for_shutdown(receiver));
    tokio::pin!(server);
    let result = tokio::select! {
        result = &mut server => result.map_err(|e| format!("peer HTTP server failed: {e}")),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires local UDP sockets; no root or TUN"]
    fn hosts_files_and_independent_service_on_one_listener() {
        use crate::ServiceRoutes;
        use portal::{Device, DeviceConfig, PeerConfig};
        use std::sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        struct Cancelled(Arc<AtomicBool>);
        impl Drop for Cancelled {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let root =
            std::env::temp_dir().join(format!("portal-services-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&root).unwrap();
        let mut devices = Vec::new();
        for key in [1, 2] {
            let mut config = DeviceConfig::new([key; 32], "127.0.0.1:0".parse().unwrap());
            config.dual_stack = false;
            config.workers = 1;
            devices.push(Device::new(config).unwrap());
        }
        let ips = ["10.153.0.1", "10.153.0.2"];
        for i in 0..2 {
            devices[i]
                .upsert_peer(PeerConfig {
                    public_key: devices[1 - i].public_key(),
                    preshared_key: None,
                    endpoint: Some(devices[1 - i].listen_addr()),
                    persistent_keepalive: None,
                    allowed_ips: vec![format!("{}/32", ips[1 - i]).parse().unwrap()],
                })
                .unwrap();
        }
        let networks: Vec<_> = devices
            .iter()
            .zip(ips)
            .map(|(device, ip)| {
                portal_net::Net::new(device.packet_port(), vec![(ip.parse().unwrap(), 32)], 1420)
                    .unwrap()
            })
            .collect();
        let cancelled = Arc::new(AtomicBool::new(false));
        let guard = Cancelled(cancelled.clone());
        let extension = ServiceRegistration::new("extension", move |_| async move {
            let router =
                axum::Router::new().route(
                    "/extension",
                    axum::routing::get(
                        |axum::extract::ConnectInfo(source): axum::extract::ConnectInfo<
                            SocketAddr,
                        >| async move { source.ip().to_string() },
                    ),
                );
            Ok(ServiceRoutes::new(router).with_background(async move {
                let _guard = guard;
                std::future::pending::<Result<(), String>>().await
            }))
        });
        let address = "10.153.0.2:8080".parse().unwrap();
        let services = PeerServices::start(
            networks[1].clone(),
            address,
            vec![
                ServiceRegistration::files(portal_files::FileServiceConfig {
                    root: root.clone(),
                    allowed_downloaders: std::collections::HashSet::from([ips[0].parse().unwrap()]),
                }),
                extension,
            ],
        )
        .unwrap();
        let client = Builder::new_current_thread().enable_all().build().unwrap();
        client.block_on(async {
            for (path, expected) in [("/extension", ips[0]), ("/v1/resources", "read_only")] {
                let response = tokio::time::timeout(Duration::from_secs(15), async {
                    let mut stream = networks[0].connect(address).await.unwrap();
                    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n").as_bytes()).await.unwrap();
                    let mut body = Vec::new();
                    stream.read_to_end(&mut body).await.unwrap();
                    String::from_utf8(body).unwrap()
                }).await.unwrap();
                assert!(response.starts_with("HTTP/1.1 200"), "{response}");
                assert!(response.contains(expected), "{response}");
            }
        });
        services.stop().unwrap();
        assert!(cancelled.load(Ordering::Acquire));
        let failed = PeerServices::start(
            networks[1].clone(),
            address,
            vec![ServiceRegistration::new("broken", |_| async {
                Ok(ServiceRoutes::new(axum::Router::new())
                    .with_background(async { Err("failure".into()) }))
            })],
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while !failed.has_exited() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(failed.has_exited());
        assert!(failed.stop().unwrap_err().contains("failure"));
        for network in networks {
            network.shutdown();
        }
        for device in &mut devices {
            device.shutdown().unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancels_stalled_server() {
        let task = tokio::spawn(std::future::pending::<Result<(), String>>());
        let abort = task.abort_handle();
        assert!(stop_task(task).await.unwrap_err().contains("grace period"));
        assert!(abort.is_finished());
    }
}
