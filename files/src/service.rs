use std::collections::{HashMap, HashSet};
use std::future::{Future, IntoFuture};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Path as AxumPath, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use tokio_util::io::ReaderStream;

const MAX_OPEN_DOWNLOADS: usize = 128;

/// Settings for the peer-facing file service.
pub struct FileServiceConfig {
    pub root: PathBuf,
    pub http_listen: SocketAddr,
    pub allowed_downloaders: HashSet<IpAddr>,
}

#[derive(Clone)]
pub(super) struct SharedState {
    pub(super) root: Arc<PathBuf>,
    pub(super) download_slots: Arc<Semaphore>,
    pub(super) http_advertise: Arc<str>,
    pub(super) allowed_downloaders: Arc<HashSet<IpAddr>>,
    pub(super) tickets: Arc<Mutex<HashMap<String, DownloadTicket>>>,
}

pub(super) struct DownloadTicket {
    pub(super) file: tokio::fs::File,
    pub(super) size_bytes: u64,
    pub(super) requester: IpAddr,
    pub(super) expires: Instant,
    pub(super) permit: OwnedSemaphorePermit,
}

/// File-transfer feature state registered by the runtime in its shared gRPC server.
pub struct FileService {
    state: Option<SharedState>,
    http_listener: Option<TcpListener>,
    http_address: Option<SocketAddr>,
    #[cfg(target_os = "linux")]
    smb: Option<crate::platform::SmbService>,
}

impl FileService {
    /// Validate the shared directory and bind its HTTP listener before runtime startup completes.
    pub async fn new(config: FileServiceConfig) -> Result<Self, String> {
        let root = tokio::fs::canonicalize(&config.root)
            .await
            .map_err(|error| {
                format!(
                    "could not resolve file root {}: {error}",
                    config.root.display()
                )
            })?;
        if !tokio::fs::metadata(&root)
            .await
            .map_err(|error| format!("could not inspect file root: {error}"))?
            .is_dir()
        {
            return Err(format!("file root {} is not a directory", root.display()));
        }
        if config.allowed_downloaders.is_empty() {
            return Err("at least one --allow-download peer IP is required".into());
        }

        let http_listener = TcpListener::bind(config.http_listen)
            .await
            .map_err(|error| {
                format!(
                    "could not bind HTTP listener {}: {error}",
                    config.http_listen
                )
            })?;
        let http_address = http_listener
            .local_addr()
            .map_err(|error| format!("could not inspect HTTP listener: {error}"))?;
        let state = SharedState {
            root: Arc::new(root),
            download_slots: Arc::new(Semaphore::new(MAX_OPEN_DOWNLOADS)),
            http_advertise: Arc::from(format!("http://{http_address}")),
            allowed_downloaders: Arc::new(config.allowed_downloaders),
            tickets: Arc::new(Mutex::new(HashMap::new())),
        };
        Ok(Self {
            state: Some(state),
            http_listener: Some(http_listener),
            http_address: Some(http_address),
            #[cfg(target_os = "linux")]
            smb: None,
        })
    }

    /// Host downloads, SMB, or both under the same FileTransfer service.
    pub async fn new_with_smb(
        downloads: Option<FileServiceConfig>,
        smb: Option<crate::SmbConfig>,
    ) -> Result<Self, String> {
        if downloads.is_none() && smb.is_none() {
            return Err("at least one file sharing backend is required".into());
        }
        let mut service = match downloads {
            Some(config) => Self::new(config).await?,
            None => Self {
                state: None,
                http_listener: None,
                http_address: None,
                #[cfg(target_os = "linux")]
                smb: None,
            },
        };
        if let Some(config) = smb {
            #[cfg(target_os = "linux")]
            {
                service.smb = Some(
                    tokio::task::spawn_blocking(move || crate::platform::SmbService::start(config))
                        .await
                        .map_err(|e| format!("Samba startup task failed: {e}"))??,
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = config;
                return Err("managed Samba currently supports Linux only".into());
            }
        }
        Ok(service)
    }

    /// Return the file-transfer RPC handler for registration in the runtime's shared server.
    pub fn grpc_service(
        &self,
    ) -> crate::rpc::file_transfer_server::FileTransferServer<crate::FileTransferRpc> {
        #[cfg(target_os = "linux")]
        let smb = self.smb.as_ref().map(|smb| smb.access());
        #[cfg(not(target_os = "linux"))]
        let smb = None;
        crate::grpc::server(self.state.clone(), smb)
    }

    /// Return the address chosen for the HTTP byte-stream endpoint.
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http_address
    }

    /// Compatibility entry point; also supervises SMB when configured.
    pub async fn serve_http<F>(self, shutdown: F) -> Result<(), String>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.serve(shutdown).await
    }

    /// Serve file bytes and supervise Samba until the runtime signals shutdown.
    pub async fn serve<F>(self, shutdown: F) -> Result<(), String>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let state = self.state.clone();
        let has_http = self.http_listener.is_some();
        let (http_shutdown, mut http_stopped) = tokio::sync::watch::channel(false);
        let http = async move {
            match (self.http_listener, self.state) {
                (Some(listener), Some(state)) => {
                    let app = Router::new()
                        .route("/v1/download/:ticket", get(http_download))
                        .with_state(state);
                    axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(async move {
                        while !*http_stopped.borrow() {
                            if http_stopped.changed().await.is_err() {
                                break;
                            }
                        }
                    })
                    .into_future()
                    .await
                    .map_err(|error| format!("file HTTP server failed: {error}"))
                }
                _ => std::future::pending().await,
            }
        };
        tokio::pin!(http);
        tokio::pin!(shutdown);
        let mut cleanup = tokio::time::interval(std::time::Duration::from_secs(1));
        #[cfg(target_os = "linux")]
        let mut smb = self.smb;
        let result = loop {
            tokio::select! {
                result = &mut http => break result,
                _ = &mut shutdown => {
                    let _ = http_shutdown.send(true);
                    break if has_http {
                        tokio::time::timeout(std::time::Duration::from_secs(5), &mut http).await
                            .map_err(|_| "file HTTP connections exceeded shutdown grace period".to_owned())
                            .and_then(|result| result)
                    } else { Ok(()) };
                },
                _ = cleanup.tick() => {
                    if let Some(state) = &state { state.prune_expired().await; }
                    #[cfg(target_os = "linux")]
                    if let Some(smb) = &mut smb {
                        if let Err(error) = smb.health() { break Err(error); }
                    }
                },
            }
        };
        #[cfg(target_os = "linux")]
        if let Some(mut smb) = smb {
            tokio::task::spawn_blocking(move || smb.stop())
                .await
                .map_err(|e| format!("Samba shutdown task failed: {e}"))??;
        }
        result
    }
}

/// Consume a valid ticket only when its HTTP caller matches the peer that requested it.
async fn http_download(
    State(state): State<SharedState>,
    ConnectInfo(requester): ConnectInfo<SocketAddr>,
    AxumPath(ticket_id): AxumPath<String>,
) -> Response {
    let requester = requester.ip();
    let mut tickets = state.tickets.lock().await;
    let Some(ticket) = tickets.get(&ticket_id) else {
        return http_error(StatusCode::NOT_FOUND, "download ticket not found");
    };
    if ticket.expires <= Instant::now() {
        tickets.remove(&ticket_id);
        return http_error(StatusCode::GONE, "download ticket expired");
    }
    if ticket.requester != requester {
        return http_error(
            StatusCode::FORBIDDEN,
            "download ticket belongs to another peer",
        );
    }
    let ticket = tickets
        .remove(&ticket_id)
        .expect("ticket was checked while holding the map lock");
    drop(tickets);

    // Keep the slot until the body is consumed or the connection is dropped.
    let file_stream = DownloadStream {
        inner: ReaderStream::new(ticket.file.take(ticket.size_bytes)),
        _permit: ticket.permit,
    };
    let mut response = Response::new(Body::from_stream(file_stream));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&ticket.size_bytes.to_string())
            .expect("a decimal size is a valid header value"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Return a small plain-text HTTP error response.
fn http_error(status: StatusCode, message: &'static str) -> Response {
    (status, message).into_response()
}

impl SharedState {
    pub(super) async fn prune_expired(&self) {
        let now = Instant::now();
        self.tickets
            .lock()
            .await
            .retain(|_, ticket| ticket.expires > now);
    }
}

struct DownloadStream {
    inner: ReaderStream<tokio::io::Take<tokio::fs::File>>,
    _permit: OwnedSemaphorePermit,
}

impl tokio_stream::Stream for DownloadStream {
    type Item = Result<bytes::Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        std::pin::Pin::new(&mut self.inner).poll_next(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> SharedState {
        SharedState {
            root: Arc::new(std::env::temp_dir()),
            download_slots: Arc::new(Semaphore::new(1)),
            http_advertise: Arc::from("http://127.0.0.1:8080"),
            allowed_downloaders: Arc::new(HashSet::new()),
            tickets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn insert_ticket(state: &SharedState, expires: Instant) {
        let path = std::env::temp_dir().join(format!("portal-ticket-{}", rand::random::<u64>()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        let permit = state.download_slots.clone().try_acquire_owned().unwrap();
        state.tickets.lock().await.insert(
            "ticket".into(),
            DownloadTicket {
                file: tokio::fs::File::from_std(file),
                size_bytes: 0,
                requester: "127.0.0.1".parse().unwrap(),
                expires,
                permit,
            },
        );
    }

    #[tokio::test]
    async fn expired_ticket_releases_capacity() {
        let state = state();
        insert_ticket(&state, Instant::now()).await;
        assert!(state.download_slots.clone().try_acquire_owned().is_err());
        state.prune_expired().await;
        assert!(state.tickets.lock().await.is_empty());
        assert!(state.download_slots.clone().try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn ticket_is_peer_bound_one_use_and_holds_slot_until_body_drop() {
        let state = state();
        insert_ticket(&state, Instant::now() + std::time::Duration::from_secs(300)).await;
        let wrong = http_download(
            State(state.clone()),
            ConnectInfo("127.0.0.2:1234".parse().unwrap()),
            AxumPath("ticket".into()),
        )
        .await;
        assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
        assert_eq!(state.tickets.lock().await.len(), 1);
        let response = http_download(
            State(state.clone()),
            ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            AxumPath("ticket".into()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.tickets.lock().await.is_empty());
        assert!(state.download_slots.clone().try_acquire_owned().is_err());
        let reused = http_download(
            State(state.clone()),
            ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            AxumPath("ticket".into()),
        )
        .await;
        assert_eq!(reused.status(), StatusCode::NOT_FOUND);
        drop(response);
        assert!(state.download_slots.clone().try_acquire_owned().is_ok());
    }
}
