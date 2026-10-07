use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Router, body::Bytes};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

use crate::service::Runtime;

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct ApiState {
    runtime: Arc<Mutex<Runtime>>,
    token: Arc<Zeroizing<String>>,
    listen_address: SocketAddr,
}

/// JSON operations accepted by the local management API.
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum ManagementRequest {
    PeerUpsert {
        public_key: String,
        #[serde(default)]
        preshared_key: Option<SecretText>,
        #[serde(default)]
        endpoint: Option<SocketAddr>,
        #[serde(default)]
        keepalive_seconds: Option<u64>,
        #[serde(default)]
        allowed_ips: Vec<String>,
    },
    PeerRemove {
        public_key: String,
    },
    EndpointSet {
        public_key: String,
        endpoint: SocketAddr,
    },
    EndpointClear {
        public_key: String,
    },
    PeerStats {
        public_key: String,
    },
    Status,
    Health,
    Stats,
    List,
    Shutdown,
}

/// String wrapper that clears a deserialized preshared key when it is dropped.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct SecretText(pub(crate) String);

impl Drop for SecretText {
    /// Erase the preshared key bytes from the request model.
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// JSON response returned for a successful or rejected management command.
#[derive(Serialize)]
struct CommandResponse {
    message: String,
}

/// Serve the local HTTP API and remove its token file when it stops.
pub(crate) struct LocalApi {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), String>>,
    address: SocketAddr,
    token_file: PathBuf,
}

impl LocalApi {
    /// Bind the loopback listener, create its bearer token, and start the API task.
    pub(crate) fn start(
        address: SocketAddr,
        token_file: PathBuf,
        runtime: Arc<Mutex<Runtime>>,
    ) -> Result<Self, String> {
        if !address.ip().is_loopback() {
            return Err("--api-listen must use a loopback address".into());
        }
        let listener = match StdTcpListener::bind(address) {
            Ok(listener) => listener,
            Err(error) => {
                return Err(format!(
                    "could not bind local API listener {address}: {error}"
                ));
            }
        };
        if let Err(error) = listener.set_nonblocking(true) {
            return Err(format!("could not configure local API listener: {error}"));
        }
        let address = match listener.local_addr() {
            Ok(address) => address,
            Err(error) => {
                return Err(format!("could not inspect local API listener: {error}"));
            }
        };
        let token = crate::platform::linux::api_token::create(&token_file)?;

        let state = ApiState {
            runtime,
            token: Arc::new(Zeroizing::new(token)),
            listen_address: address,
        };
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = match thread::Builder::new()
            .name("portal-local-api".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| format!("could not create local API runtime: {error}"))?;
                runtime.block_on(async move {
                    let listener = TcpListener::from_std(listener)
                        .map_err(|error| format!("could not start local API listener: {error}"))?;
                    let app = Router::new()
                        .route("/api/v1/command", post(handle_command))
                        .with_state(state);
                    axum::serve(
                        listener,
                        app.into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(async {
                        let _ = shutdown_receiver.await;
                    })
                    .await
                    .map_err(|error| format!("local API server failed: {error}"))
                })
            }) {
            Ok(task) => task,
            Err(error) => {
                let _ = crate::platform::linux::api_token::remove(&token_file);
                return Err(format!("could not start local API thread: {error}"));
            }
        };

        Ok(Self {
            shutdown: Some(shutdown),
            task,
            address,
            token_file,
        })
    }

    /// Return the address selected for the local API listener.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Report whether the HTTP server task exited before runtime shutdown.
    pub(crate) fn has_exited(&self) -> bool {
        self.task.is_finished()
    }

    /// Stop the HTTP server, join its thread, and remove the bearer token file.
    pub(crate) fn stop(mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task_result = match self.task.join() {
            Ok(result) => result,
            Err(_) => Err("local API thread panicked".to_owned()),
        };
        let token_result = crate::platform::linux::api_token::remove(&self.token_file);
        task_result.and(token_result)
    }
}

/// Authenticate a loopback request, dispatch its command, and return a JSON result.
async fn handle_command(
    State(state): State<ApiState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CommandResponse>, (StatusCode, Json<CommandResponse>)> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request is too large",
        ));
    }
    if !remote.ip().is_loopback() || !valid_host(&headers, state.listen_address) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "request must target the local API",
        ));
    }
    if !valid_origin(&headers, state.listen_address) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "request origin is not allowed",
        ));
    }
    if headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|value| value.split(';').next() != Some("application/json"))
    {
        return Err(api_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/json",
        ));
    }
    if !valid_token(&headers, state.token.as_str()) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid API bearer token",
        ));
    }

    let request: ManagementRequest = serde_json::from_slice(&body).map_err(|error| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid JSON request: {error}"),
        )
    })?;
    let mut runtime = state.runtime.lock().map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime state is unavailable",
        )
    })?;
    let result = runtime.handle_api_request(request);
    result
        .map(|message| Json(CommandResponse { message }))
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, &error))
}

/// Build a JSON error response with the matching HTTP status.
fn api_error(status: StatusCode, message: &str) -> (StatusCode, Json<CommandResponse>) {
    (
        status,
        Json(CommandResponse {
            message: message.to_owned(),
        }),
    )
}

/// Accept only Host values that address this loopback listener and port.
fn valid_host(headers: &HeaderMap, address: SocketAddr) -> bool {
    let Some(host) = headers.get(HOST).and_then(|value| value.to_str().ok()) else {
        return false;
    };
    allowed_authority(host, address.port())
}

/// Allow same-origin browser requests while rejecting cross-origin and DNS-rebinding hosts.
fn valid_origin(headers: &HeaderMap, address: SocketAddr) -> bool {
    let Some(origin) = headers.get(ORIGIN) else {
        return true;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    origin
        .strip_prefix("http://")
        .is_some_and(|authority| allowed_authority(authority, address.port()))
}

/// Match localhost and loopback IP authorities on the API listener's port.
fn allowed_authority(authority: &str, port: u16) -> bool {
    authority == format!("localhost:{port}")
        || authority == format!("127.0.0.1:{port}")
        || authority == format!("[::1]:{port}")
}

/// Compare the supplied bearer token without data-dependent early exit.
fn valid_token(headers: &HeaderMap, expected: &str) -> bool {
    let Some(supplied) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    if supplied.len() != expected.len() {
        return false;
    }
    supplied
        .bytes()
        .zip(expected.bytes())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}
