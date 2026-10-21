use std::future::IntoFuture;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

use axum::Json;
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, body::Bytes};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

use crate::service::Runtime;

const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_COMMAND_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Clone)]
struct ApiState {
    runtime: Arc<Mutex<Runtime>>,
    token: Arc<Zeroizing<String>>,
    listen_address: SocketAddr,
    network: Option<portal_net::Net>,
}

/// JSON operations accepted by the local management API.
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ManagementRequest {
    PeerUpsert {
        public_key: String,
        #[serde(default)]
        endpoint: Option<SocketAddr>,
        #[serde(default)]
        relay: Option<portal_net::RelayPeer>,
        #[serde(default)]
        allow_relay: Option<bool>,
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
    Stats,
    PeerStats {
        public_key: String,
    },
    Status,
    Health,
    List,
    ServicesReload,
    RelayAccessSet {
        public_key: String,
        allowed: bool,
    },
    Shutdown,
}

/// JSON response returned for a successful or rejected management command.
#[derive(Serialize)]
struct CommandResponse {
    message: String,
}

/// Serve the local HTTP API and remove its token file when it stops.
pub(crate) struct LocalApi {
    executor: Handle,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<Result<(), String>>,
    address: SocketAddr,
    token_file: crate::platform::linux::api_token::TokenFile,
}

impl LocalApi {
    /// Bind the loopback listener, create its bearer token, and start the API task.
    pub(crate) fn start(
        executor: &Handle,
        address: SocketAddr,
        token_file: PathBuf,
        runtime: Arc<Mutex<Runtime>>,
        network: Option<portal_net::Net>,
    ) -> Result<Self, String> {
        if !address.ip().is_loopback() {
            return Err("api_listen must use a loopback address".into());
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
        let listener = {
            let _guard = executor.enter();
            TcpListener::from_std(listener)
                .map_err(|error| format!("could not start local API listener: {error}"))?
        };
        let (token, token_file) = crate::platform::linux::api_token::create(&token_file)?;

        let state = ApiState {
            runtime,
            token: Arc::new(Zeroizing::new(token)),
            listen_address: address,
            network,
        };
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = executor.spawn(async move {
            let app = Router::new()
                .route("/", get(handle_web))
                .route("/app.js", get(handle_web))
                .route("/styles.css", get(handle_web))
                .route("/favicon.svg", get(handle_web))
                .route("/api/v1/state", post(handle_state))
                .route("/api/v1/peers/info", post(handle_peer_info))
                .route("/api/v1/command", post(handle_command))
                .route("/api/v1/files/:operation", post(handle_files))
                .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
                .with_state(state);
            let (drain, mut draining) = tokio::sync::watch::channel(false);
            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                while !*draining.borrow() {
                    if draining.changed().await.is_err() {
                        break;
                    }
                }
            })
            .into_future();
            tokio::pin!(server);
            tokio::select! {
                result = &mut server => result.map_err(|e| format!("local API server failed: {e}")),
                _ = shutdown_receiver => {
                    let _ = drain.send(true);
                    tokio::time::timeout(std::time::Duration::from_secs(5), &mut server).await
                        .map_err(|_| "local API exceeded shutdown grace period".to_owned())?
                        .map_err(|e| format!("local API server failed: {e}"))
                }
            }
        });

        Ok(Self {
            executor: executor.clone(),
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

    /// Stop the HTTP task on the shared executor and remove its bearer token file.
    pub(crate) fn stop(mut self) -> Result<(), String> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task_result = self.executor.block_on(async {
            match tokio::time::timeout(std::time::Duration::from_secs(6), &mut self.task).await {
                Ok(result) => result.map_err(|error| format!("local API task failed: {error}"))?,
                Err(_) => {
                    self.task.abort();
                    let _ = self.task.await;
                    Err("local API exceeded shutdown grace period; task was cancelled".into())
                }
            }
        });
        let token_result = self.token_file.remove();
        task_result.and(token_result)
    }
}

/// Static assets contain no credentials. The browser authenticates API calls separately.
async fn handle_web(
    State(state): State<ApiState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Response, (StatusCode, Json<CommandResponse>)> {
    if !remote.ip().is_loopback()
        || !valid_host(&headers, state.listen_address)
        || !valid_origin(&headers, state.listen_address)
    {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "request must target the local API",
        ));
    }
    let (content_type, body) = crate::web::asset(uri.path())
        .ok_or_else(|| api_error(StatusCode::NOT_FOUND, "asset not found"))?;
    let mut response = Response::new(axum::body::Body::from(body));
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("content-security-policy", HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"));
    Ok(response)
}

async fn handle_state(
    State(state): State<ApiState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, Json<CommandResponse>)> {
    authenticate(&state, remote, &headers)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StateRequest {}
    serde_json::from_slice::<StateRequest>(&body).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "state request must be an empty JSON object",
        )
    })?;
    let snapshot = state
        .runtime
        .lock()
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "runtime state is unavailable",
            )
        })?
        .snapshot()
        .map_err(|e| api_error(StatusCode::SERVICE_UNAVAILABLE, &e))?;
    Ok(([("cache-control", "no-store")], Json(snapshot)).into_response())
}

/// Query authenticated capabilities over QUIC without holding the runtime lock during IO.
async fn handle_peer_info(
    State(state): State<ApiState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, Json<CommandResponse>)> {
    use tokio::io::AsyncReadExt;
    authenticate(&state, remote, &headers)?;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct InfoRequest {
        peer: String,
    }
    let request: InfoRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "expected a peer public key"))?;
    let key = state
        .runtime
        .lock()
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "runtime state is unavailable",
            )
        })?
        .registered_peer(&request.peer)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    let network = state
        .network
        .as_ref()
        .ok_or_else(|| api_error(StatusCode::SERVICE_UNAVAILABLE, "network unavailable"))?;
    let mut response = network
        .request(
            key,
            portal_net::Request {
                service: "portal".into(),
                operation: "info".into(),
                payload: serde_json::json!({}),
            },
        )
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, &e))?;
    if response.header.status != 200 || response.header.length > 4096 {
        return Err(api_error(
            StatusCode::BAD_GATEWAY,
            "peer did not return supported capabilities",
        ));
    }
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        response.body.read_to_end(&mut bytes),
    )
    .await
    .map_err(|_| api_error(StatusCode::GATEWAY_TIMEOUT, "peer info timed out"))?
    .map_err(|_| api_error(StatusCode::BAD_GATEWAY, "could not read peer info"))?;
    let info: crate::service::PeerInfo = serde_json::from_slice(&bytes)
        .map_err(|_| api_error(StatusCode::BAD_GATEWAY, "invalid peer info"))?;
    if portal_net::parse_key(&info.public_key).ok() != Some(key) {
        return Err(api_error(
            StatusCode::BAD_GATEWAY,
            "peer info identity mismatch",
        ));
    }
    if let Some(relay) = &info.relay_server {
        if relay.public_key != key {
            return Err(api_error(
                StatusCode::BAD_GATEWAY,
                "relay capability identity mismatch",
            ));
        }
        relay
            .validate()
            .map_err(|_| api_error(StatusCode::BAD_GATEWAY, "invalid advertised peer relay"))?;
    }
    let mut runtime = state.runtime.lock().map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime state is unavailable",
        )
    })?;
    runtime
        .registered_peer(&request.peer)
        .map_err(|e| api_error(StatusCode::CONFLICT, &e))?;
    runtime.peer_info.insert(key, info.clone());
    Ok(([("cache-control", "no-store")], Json(info)).into_response())
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
    authenticate(&state, remote, &headers)?;

    let request: ManagementRequest = serde_json::from_slice(&body).map_err(|error| {
        api_error(
            StatusCode::BAD_REQUEST,
            &format!("invalid JSON request: {error}"),
        )
    })?;
    if matches!(request, ManagementRequest::ServicesReload) {
        let sender = {
            let runtime = state.runtime.lock().map_err(|_| {
                api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "runtime state is unavailable",
                )
            })?;
            runtime.reload.clone().ok_or_else(|| {
                api_error(
                    StatusCode::BAD_REQUEST,
                    "reload requires a configuration file",
                )
            })?
        };
        let (response, receiver) = oneshot::channel();
        sender
            .try_send(crate::service::ReloadRequest { response })
            .map_err(|_| {
                api_error(
                    StatusCode::CONFLICT,
                    "service reload is busy or unavailable",
                )
            })?;
        let result = receiver.await.map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime stopped during reload",
            )
        })?;
        return result
            .map_err(|error| api_error(StatusCode::BAD_REQUEST, &error))
            .and_then(command_response);
    }
    let mut runtime = state.runtime.lock().map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime state is unavailable",
        )
    })?;
    let result = runtime.handle_api_request(request);
    result
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, &error))
        .and_then(command_response)
}

fn command_response(
    message: String,
) -> Result<Json<CommandResponse>, (StatusCode, Json<CommandResponse>)> {
    let response = CommandResponse { message };
    let size = serde_json::to_vec(&response)
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not encode command response",
            )
        })?
        .len();
    if size > MAX_COMMAND_RESPONSE_BYTES {
        return Err(api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "command response exceeds the 256 KiB limit",
        ));
    }
    Ok(Json(response))
}

fn authenticate(
    state: &ApiState,
    remote: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<CommandResponse>)> {
    if !remote.ip().is_loopback() || !valid_host(headers, state.listen_address) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "request must target the local API",
        ));
    }
    if !valid_origin(headers, state.listen_address) {
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
    if !valid_token(headers, state.token.as_str()) {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "invalid API bearer token",
        ));
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRequest {
    peer: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    offset: usize,
    #[serde(default = "portal_files::models::default_page_size")]
    limit: usize,
}
async fn handle_files(
    State(state): State<ApiState>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Path(operation): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, (StatusCode, Json<CommandResponse>)> {
    authenticate(&state, remote, &headers)?;
    let request: FileRequest = serde_json::from_slice(&body)
        .map_err(|_| api_error(StatusCode::BAD_REQUEST, "invalid file API request"))?;
    let payload = match operation.as_str() {
        "resources" => serde_json::json!({}),
        "list" => {
            serde_json::json!({"path": request.path, "offset": request.offset, "limit": request.limit})
        }
        "metadata" | "download" => serde_json::json!({"path": request.path}),
        _ => {
            return Err(api_error(
                StatusCode::NOT_FOUND,
                "unknown file API operation",
            ));
        }
    };
    let peer_request = portal_net::Request {
        service: "files".into(),
        operation,
        payload,
    };
    peer_request
        .validate_size()
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, &error))?;
    // Release the runtime lock before any network IO.
    let address = state
        .runtime
        .lock()
        .map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "runtime state is unavailable",
            )
        })?
        .registered_peer(&request.peer)
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, &error))?;
    let network = state.network.clone().ok_or_else(|| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "QUIC transport unavailable",
        )
    })?;
    let response = network
        .request(address, peer_request)
        .await
        .map_err(|error| api_error(StatusCode::BAD_GATEWAY, &error))?;
    let header = response.header.clone();
    let mut result = Response::new(axum::body::Body::from_stream(
        portal_files::response_stream(response),
    ));
    *result.status_mut() = StatusCode::from_u16(header.status)
        .map_err(|_| api_error(StatusCode::BAD_GATEWAY, "invalid peer status"))?;
    result.headers_mut().insert(
        axum::http::header::CONTENT_LENGTH,
        axum::http::HeaderValue::from_str(&header.length.to_string()).expect("numeric size"),
    );
    result.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    result.headers_mut().insert(
        CONTENT_TYPE,
        axum::http::HeaderValue::from_static(if header.file_name.is_some() {
            "application/octet-stream"
        } else {
            "application/json"
        }),
    );
    if let Some(name) = header.file_name {
        let encoded: String = name.bytes().map(|b| format!("%{b:02X}")).collect();
        result.headers_mut().insert(
            axum::http::header::CONTENT_DISPOSITION,
            axum::http::HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{encoded}"))
                .map_err(|_| api_error(StatusCode::BAD_GATEWAY, "invalid filename"))?,
        );
    }
    Ok(result)
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

#[cfg(test)]
mod file_api_tests {
    use super::*;
    #[tokio::test]
    async fn file_routes_require_local_host_origin_and_bearer_token() {
        let state = ApiState {
            runtime: Arc::new(Mutex::new(crate::service::test_runtime())),
            token: Arc::new(Zeroizing::new("secret".into())),
            listen_address: "127.0.0.1:51821".parse().unwrap(),
            network: None,
        };
        let mut headers = HeaderMap::new();
        headers.insert(HOST, "127.0.0.1:51821".parse().unwrap());
        headers.insert(CONTENT_TYPE, "application/json".parse().unwrap());
        let body = Bytes::from_static(
            br#"{"peer":"0101010101010101010101010101010101010101010101010101010101010101"}"#,
        );
        let result = handle_files(
            State(state.clone()),
            ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            Path("resources".into()),
            headers.clone(),
            body.clone(),
        )
        .await;
        assert_eq!(result.err().unwrap().0, StatusCode::UNAUTHORIZED);
        headers.insert(AUTHORIZATION, "Bearer secret".parse().unwrap());
        headers.insert(ORIGIN, "http://example.com".parse().unwrap());
        let result = handle_files(
            State(state.clone()),
            ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            Path("resources".into()),
            headers.clone(),
            body.clone(),
        )
        .await;
        assert_eq!(result.err().unwrap().0, StatusCode::FORBIDDEN);
        headers.remove(ORIGIN);
        headers.insert(HOST, "example.com:51821".parse().unwrap());
        let result = handle_files(
            State(state.clone()),
            ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            Path("resources".into()),
            headers.clone(),
            body.clone(),
        )
        .await;
        assert_eq!(result.err().unwrap().0, StatusCode::FORBIDDEN);
        headers.insert(HOST, "127.0.0.1:51821".parse().unwrap());
        let result = handle_files(
            State(state.clone()),
            ConnectInfo("10.20.0.3:1234".parse().unwrap()),
            Path("resources".into()),
            headers.clone(),
            body.clone(),
        )
        .await;
        assert_eq!(result.err().unwrap().0, StatusCode::FORBIDDEN);
        let result = handle_files(State(state.clone()), ConnectInfo("127.0.0.1:1234".parse().unwrap()), Path("resources".into()), headers.clone(), Bytes::from_static(br#"{"peer":"0101010101010101010101010101010101010101010101010101010101010101","url":"http://127.0.0.1"}"#)).await;
        assert_eq!(result.err().unwrap().0, StatusCode::BAD_REQUEST);
        // Valid local JSON can exceed the QUIC frame limit after encoding its envelope.
        let result = handle_files(
            State(state.clone()),
            ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            Path("download".into()),
            headers.clone(),
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "peer": "01".repeat(32), "path": "\u{0001}".repeat(3000)
                }))
                .unwrap(),
            ),
        )
        .await;
        let (status, Json(error)) = result.err().unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(error.message.contains("16 KiB"));
        let result = handle_files(
            State(state),
            ConnectInfo("127.0.0.1:1234".parse().unwrap()),
            Path("unknown".into()),
            headers,
            body,
        )
        .await;
        assert_eq!(result.err().unwrap().0, StatusCode::NOT_FOUND);
    }
}
