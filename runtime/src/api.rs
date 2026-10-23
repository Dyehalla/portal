use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

use axum::Json;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, body::Bytes};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

use crate::runtime::Runtime;

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct ApiState {
    agent: Option<Arc<crate::managed::Agent>>,
    runtime: Arc<Mutex<Runtime>>,
    token: Arc<Zeroizing<String>>,
    listen_address: SocketAddr,
}

/// JSON operations accepted by the local management API.
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub(crate) enum ManagementRequest {
    Connect {
        peer_device_id: String,
    },
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
        agent: Option<Arc<crate::managed::Agent>>,
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
            agent,
            runtime,
            token: Arc::new(Zeroizing::new(token)),
            listen_address: address,
        };
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let listener = TcpListener::from_std(listener)
                .map_err(|error| format!("could not start local API listener: {error}"))?;
            println!(
                "web panel: http://{address}/#token={}",
                state.token.as_str()
            );
            let api = Router::new()
                .route("/api/v1/command", post(handle_command))
                .route("/api/v1/snapshot", get(handle_snapshot))
                .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
            let app = Router::new()
                .route("/", get(index))
                .route("/app.js", get(javascript))
                .route("/style.css", get(stylesheet))
                .merge(api)
                .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
                .layer(middleware::from_fn_with_state(state.clone(), local_request))
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
        });

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

    /// Stop the HTTP server, await its task, and remove the bearer token file.
    pub(crate) async fn stop(mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task_result = match self.task.await {
            Ok(result) => result,
            Err(_) => Err("local API task failed".to_owned()),
        };
        let token_result = crate::platform::linux::api_token::remove(&self.token_file);
        task_result.and(token_result)
    }
}

/// Authenticate a loopback request, dispatch its command, and return a JSON result.
async fn handle_command(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CommandResponse>, (StatusCode, Json<CommandResponse>)> {
    if body.len() > MAX_REQUEST_BYTES {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "request is too large",
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
    let request: ManagementRequest = serde_json::from_slice(&body).map_err(|error| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid JSON request: {error}"),
        )
    })?;
    if let ManagementRequest::Connect { peer_device_id } = request {
        let agent = state.agent.as_ref().ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "P2P signaling requires managed mode",
            )
        })?;
        return agent
            .connect(peer_device_id)
            .await
            .map(|message| Json(CommandResponse { message }))
            .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e));
    }
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

async fn handle_snapshot(
    State(state): State<ApiState>,
) -> Result<Json<crate::snapshot::Snapshot>, (StatusCode, Json<CommandResponse>)> {
    let runtime = state.runtime.lock().map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime state is unavailable",
        )
    })?;
    runtime
        .snapshot()
        .map(Json)
        .map_err(|e| api_error(StatusCode::SERVICE_UNAVAILABLE, &e))
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn javascript() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/app.js"),
    )
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/style.css"),
    )
}

/// Assets are public; every endpoint containing device data requires the API token.
async fn authenticate(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    if !valid_token(request.headers(), state.token.as_str()) {
        return api_error(StatusCode::UNAUTHORIZED, "invalid API bearer token").into_response();
    }
    next.run(request).await
}

async fn local_request(
    State(state): State<ApiState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let mut response = if !remote.ip().is_loopback() || !valid_host(headers, state.listen_address) {
        api_error(StatusCode::FORBIDDEN, "request must target the local API").into_response()
    } else if !valid_origin(headers, state.listen_address) {
        api_error(StatusCode::FORBIDDEN, "request origin is not allowed").into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    ] {
        headers.insert(name, value.parse().expect("constant response header"));
    }
    response
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
    if headers.get_all(AUTHORIZATION).iter().count() != 1 {
        return false;
    }
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
