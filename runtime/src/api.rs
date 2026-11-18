use std::collections::HashMap;
use std::io::IsTerminal;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;

use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN};
use axum::http::{HeaderMap, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, body::Bytes};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::sync::oneshot;
use zeroize::{Zeroize, Zeroizing};

use crate::runtime::Runtime;

const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct ApiState {
    agent: Option<Arc<crate::managed::Agent>>,
    account: Arc<tokio::sync::Mutex<crate::web_account::Account>>,
    runtime: Arc<Mutex<Runtime>>,
    token: Arc<Zeroizing<String>>,
    terminal_sessions: Arc<tokio::sync::Mutex<HashMap<String, TerminalTicket>>>,
    active_terminal_sessions: Arc<AtomicUsize>,
}

struct TerminalTicket {
    target: std::net::IpAddr,
    port: u16,
    user: String,
    expires_at: Instant,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalSessionRequest {
    device_id: String,
    #[serde(default)]
    user: Option<String>,
}

#[derive(Serialize)]
struct TerminalSessionResponse {
    ticket: String,
    expires_in_seconds: u64,
    status: &'static str,
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
        profile_file: Option<PathBuf>,
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
        let mut account = crate::web_account::Account::open(profile_file)?;
        account.agent = agent.clone();
        account.expected_owner = runtime
            .lock()
            .map_err(|_| "Агент недоступен")?
            .snapshot()?
            .network
            .map(|n| n.user_id);
        let token = crate::platform::linux::api_token::create(&token_file)?;
        let state = ApiState {
            account: Arc::new(tokio::sync::Mutex::new(account)),
            agent,
            runtime,
            token: Arc::new(Zeroizing::new(token)),
            terminal_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            active_terminal_sessions: Arc::new(AtomicUsize::new(0)),
        };
        let (shutdown, shutdown_receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            let listener = TcpListener::from_std(listener)
                .map_err(|error| format!("could not start local API listener: {error}"))?;
            // Redirected service stdout may be collected by a shared journal.
            if std::io::stdout().is_terminal() {
                println!(
                    "web panel: http://{address}/#token={}",
                    state.token.as_str()
                );
            } else {
                println!("web panel: http://{address}/");
            }
            let restore_state = state.clone();
            let restore_task = tokio::spawn(async move {
                let mut account = restore_state.account.lock().await;
                if let Ok(view) = account
                    .view(&local_public_key(&restore_state.runtime).unwrap_or_default())
                    .await
                {
                    if view.error.is_none()
                        && view.user.is_some()
                        && !view.needs_device
                        && account.agent.is_none()
                    {
                        let _ = account
                            .activate(view.device_name, &restore_state.runtime)
                            .await;
                    }
                }
            });
            let api = Router::new()
                .route(
                    "/api/v1/command",
                    post(handle_command).layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES)),
                )
                .route("/api/v1/snapshot", get(handle_snapshot))
                .route("/api/v1/account", get(account_view).post(account_login))
                .route("/api/v1/account/activate", post(account_activate))
                .route("/api/v1/account/token", post(account_token))
                .route("/api/v1/account/device", post(account_device))
                .route("/api/v1/terminal/session", post(create_terminal_session))
                .route(
                    "/api/v1/files/:device_id/*path",
                    axum::routing::any(proxy_files),
                )
                .route_layer(middleware::from_fn_with_state(state.clone(), authenticate));
            let app = Router::new()
                .route("/", get(index))
                .route("/app.js", get(javascript))
                .route("/map.js", get(map_javascript))
                .route("/xterm.js", get(xterm_javascript))
                .route("/xterm.css", get(xterm_stylesheet))
                .route("/style.css", get(stylesheet))
                // The ticket is authenticated in the first WebSocket frame. It is
                // deliberately not put in the URL or a browser cookie.
                .route("/api/v1/terminal/ws", get(terminal_websocket))
                .merge(api)
                .layer(middleware::from_fn(local_request))
                .with_state(state);
            let result = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = shutdown_receiver.await;
            })
            .await
            .map_err(|error| format!("local API server failed: {error}"));
            restore_task.abort();
            let _ = restore_task.await;
            result
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

async fn proxy_files(
    State(state): State<ApiState>,
    Path((device_id, path)): Path<(String, String)>,
    request: Request,
) -> Response {
    let agent = state
        .account
        .lock()
        .await
        .agent
        .clone()
        .or_else(|| state.agent.clone());
    let Some(agent) = agent else {
        return api_plain(
            StatusCode::BAD_REQUEST,
            "File Explorer доступен только в управляемом режиме",
        );
    };
    if device_id.is_empty() || device_id.len() > 128 {
        return api_plain(
            StatusCode::BAD_REQUEST,
            "некорректный идентификатор устройства",
        );
    }
    if let Err(error) = agent.connect(device_id.clone()).await {
        return api_plain(StatusCode::BAD_GATEWAY, &error);
    }
    let snapshot = match state
        .runtime
        .lock()
        .map_err(|_| ())
        .and_then(|runtime| runtime.snapshot().map_err(|_| ()))
    {
        Ok(snapshot) => snapshot,
        Err(_) => {
            return api_plain(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime state is unavailable",
            );
        }
    };
    let Some(peer) = snapshot
        .peers
        .iter()
        .find(|peer| peer.device_id.as_deref() == Some(device_id.as_str()))
    else {
        return api_plain(
            StatusCode::FORBIDDEN,
            "target device is absent from the active network map",
        );
    };
    if peer.files != Some(true) {
        return api_plain(
            StatusCode::FORBIDDEN,
            "file access is not granted for this device",
        );
    }
    if peer.path != "direct" {
        return api_plain(
            StatusCode::BAD_GATEWAY,
            "target device has no available direct path",
        );
    }
    let Some(target) = peer
        .allowed_ips
        .iter()
        .find_map(|value| value.split('/').next()?.parse::<std::net::IpAddr>().ok())
    else {
        return api_plain(
            StatusCode::BAD_GATEWAY,
            "target device has no virtual address",
        );
    };
    let Some(files) = snapshot.files else {
        return api_plain(
            StatusCode::SERVICE_UNAVAILABLE,
            "file service is disabled on this agent",
        );
    };
    let host = match target {
        std::net::IpAddr::V4(value) => value.to_string(),
        std::net::IpAddr::V6(value) => format!("[{value}]"),
    };
    let target_url = format!(
        "http://{host}:{}{}",
        files.port,
        if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        }
    );
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(900))
        .build();
    let client = match client {
        Ok(client) => client,
        Err(_) => return api_plain(StatusCode::BAD_GATEWAY, "file proxy is unavailable"),
    };
    let mut outbound = client.request(request.method().clone(), target_url);
    for (name, value) in request.headers() {
        if *name != header::HOST
            && *name != header::AUTHORIZATION
            && *name != header::CONTENT_LENGTH
        {
            outbound = outbound.header(name, value);
        }
    }
    let body = request.into_body().into_data_stream();
    let response = match outbound.body(reqwest::Body::wrap_stream(body)).send().await {
        Ok(response) => response,
        Err(error) => {
            return api_plain(
                StatusCode::BAD_GATEWAY,
                &format!("file service unavailable: {error}"),
            );
        }
    };
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut builder = Response::builder().status(status);
    for (name, value) in response.headers() {
        if *name != header::CONNECTION && *name != header::TRANSFER_ENCODING {
            builder = builder.header(name, value);
        }
    }
    builder
        .body(axum::body::Body::from_stream(response.bytes_stream()))
        .unwrap_or_else(|_| api_plain(StatusCode::BAD_GATEWAY, "invalid file service response"))
}

fn api_plain(status: StatusCode, message: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(axum::body::Body::from(message.to_owned()))
        .unwrap_or_else(|_| Response::new(axum::body::Body::empty()))
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
        let web_agent = state.account.lock().await.agent.clone();
        let agent = state.agent.as_ref().or(web_agent.as_ref()).ok_or_else(|| {
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

fn local_public_key(runtime: &Arc<Mutex<Runtime>>) -> Result<String, String> {
    Ok(runtime
        .lock()
        .map_err(|_| "Агент недоступен")?
        .snapshot()?
        .interface
        .public_key)
}

async fn account_view(
    State(state): State<ApiState>,
) -> Result<Json<crate::web_account::View>, (StatusCode, Json<CommandResponse>)> {
    let mut account = state.account.lock().await;
    let mut view = account
        .view(
            &local_public_key(&state.runtime)
                .map_err(|e| api_error(StatusCode::SERVICE_UNAVAILABLE, &e))?,
        )
        .await
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    if view.error.is_none() && view.user.is_some() && !view.needs_device && account.agent.is_none()
    {
        if let Err(error) = account
            .activate(view.device_name.clone(), &state.runtime)
            .await
        {
            view.activation_error = Some(error);
        }
    }
    Ok(Json(view))
}
async fn account_login(
    State(state): State<ApiState>,
    Json(request): Json<crate::web_account::Login>,
) -> Result<Json<crate::web_account::View>, (StatusCode, Json<CommandResponse>)> {
    if let Some(agent) = &state.agent {
        let address = crate::web_account::normalize_address(&request.address)
            .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
        if address != agent.config.url.trim_end_matches('/') {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "Агент уже подключён к другой сети. Несколько сетей пока не поддерживаются.",
            ));
        }
    }
    state
        .account
        .lock()
        .await
        .login(
            request,
            &local_public_key(&state.runtime)
                .map_err(|e| api_error(StatusCode::SERVICE_UNAVAILABLE, &e))?,
        )
        .await
        .map(Json)
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Activate {
    name: String,
}
async fn account_activate(
    State(state): State<ApiState>,
    Json(request): Json<Activate>,
) -> Result<Json<CommandResponse>, (StatusCode, Json<CommandResponse>)> {
    state
        .account
        .lock()
        .await
        .activate(request.name, &state.runtime)
        .await
        .map(|()| {
            Json(CommandResponse {
                message: "Сеть подключена".into(),
            })
        })
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))
}
async fn account_token(
    State(state): State<ApiState>,
) -> Result<Json<CommandResponse>, (StatusCode, Json<CommandResponse>)> {
    state
        .account
        .lock()
        .await
        .export()
        .map(|message| Json(CommandResponse { message }))
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum AccountDevice {
    RequestAccess {
        source_device_id: String,
        target_device_id: String,
        tcp: Vec<u16>,
        #[serde(default)]
        terminal: bool,
        #[serde(default)]
        files: bool,
    },
    DecideAccess {
        request_id: String,
        accept: bool,
    },
    Policy {
        device_id: String,
    },
    SavePolicy {
        device_id: String,
        base_revision: u64,
        permissions: portal_net::model::Permissions,
    },
    Rename {
        device_id: String,
        name: String,
    },
    Revoke {
        device_id: String,
    },
}
async fn account_device(
    State(state): State<ApiState>,
    Json(request): Json<AccountDevice>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<CommandResponse>)> {
    let client = state
        .account
        .lock()
        .await
        .client()
        .map_err(|e| api_error(StatusCode::BAD_REQUEST, &e))?;
    let result = match request {
        AccountDevice::RequestAccess {
            source_device_id,
            target_device_id,
            tcp,
            terminal,
            files,
        } => client
            .request_access(&portal_net::model::RequestAccess {
                source_device_id,
                target_device_id,
                tcp,
                terminal,
                files,
            })
            .await
            .and_then(|p| {
                serde_json::to_value(p)
                    .map_err(|_| portal_net::client::ClientError::InvalidResponse)
            }),
        AccountDevice::DecideAccess { request_id, accept } => client
            .decide_access(&request_id, accept)
            .await
            .and_then(|p| {
                serde_json::to_value(p)
                    .map_err(|_| portal_net::client::ClientError::InvalidResponse)
            }),
        AccountDevice::Policy { device_id } => {
            client.owner_policy(&device_id).await.and_then(|p| {
                serde_json::to_value(p)
                    .map_err(|_| portal_net::client::ClientError::InvalidResponse)
            })
        }
        AccountDevice::SavePolicy {
            device_id,
            base_revision,
            permissions,
        } => client
            .save_owner_policy(
                &device_id,
                &portal_net::model::PublishPolicy {
                    base_revision,
                    permissions,
                },
            )
            .await
            .and_then(|p| {
                serde_json::to_value(p)
                    .map_err(|_| portal_net::client::ClientError::InvalidResponse)
            }),
        AccountDevice::Rename { device_id, name } => {
            client.rename_device(&device_id, &name).await.and_then(|p| {
                serde_json::to_value(p)
                    .map_err(|_| portal_net::client::ClientError::InvalidResponse)
            })
        }
        AccountDevice::Revoke { device_id } => client
            .revoke_device(&device_id)
            .await
            .map(|()| serde_json::Value::Null),
    };
    result.map(Json).map_err(|e| match e {
        portal_net::client::ClientError::Http(409) => api_error(
            StatusCode::CONFLICT,
            "Конфликт изменений. Загрузите актуальную ревизию; ваши поля сохранены.",
        ),
        portal_net::client::ClientError::Http(404) | portal_net::client::ClientError::Http(403) => {
            api_error(
                StatusCode::FORBIDDEN,
                "Устройство недоступно этому аккаунту.",
            )
        }
        portal_net::client::ClientError::Unauthorized => api_error(
            StatusCode::BAD_REQUEST,
            "Токен пользователя отозван. Войдите с новым токеном.",
        ),
        _ => api_error(
            StatusCode::BAD_REQUEST,
            "Координатор не выполнил операцию. Проверьте ключ источника, порты и доступность сети.",
        ),
    })
}

async fn create_terminal_session(
    State(state): State<ApiState>,
    Json(request): Json<TerminalSessionRequest>,
) -> Result<Json<TerminalSessionResponse>, (StatusCode, Json<CommandResponse>)> {
    let agent = state
        .account
        .lock()
        .await
        .agent
        .clone()
        .or_else(|| state.agent.clone())
        .ok_or_else(|| {
            api_error(
                StatusCode::BAD_REQUEST,
                "терминал доступен только в управляемом режиме",
            )
        })?;
    if request.device_id.is_empty() || request.device_id.len() > 128 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "некорректный идентификатор устройства",
        ));
    }
    let user = request.user.unwrap_or_else(|| "portal".to_owned());
    if user.is_empty()
        || user.len() > 32
        || user
            .bytes()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.')))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "некорректное имя пользователя терминала",
        ));
    }
    if state.active_terminal_sessions.load(Ordering::Acquire)
        >= crate::terminal::session::MAX_SESSIONS
    {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "достигнут лимит одновременных терминальных сессий",
        ));
    }
    // Establish or verify the direct path before issuing a ticket. The ticket is
    // short lived and can be consumed exactly once by the WebSocket handshake.
    agent
        .connect(request.device_id.clone())
        .await
        .map_err(|e| api_error(StatusCode::BAD_GATEWAY, &e))?;
    let snapshot = state
        .runtime
        .lock()
        .map_err(|_| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "runtime state is unavailable",
            )
        })?
        .snapshot()
        .map_err(|e| api_error(StatusCode::SERVICE_UNAVAILABLE, &e))?;
    let peer = snapshot
        .peers
        .iter()
        .find(|peer| peer.device_id.as_deref() == Some(request.device_id.as_str()))
        .ok_or_else(|| {
            api_error(
                StatusCode::FORBIDDEN,
                "target device is absent from the active network map",
            )
        })?;
    if peer.terminal != Some(true) {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "terminal access is not granted for this device",
        ));
    }
    if peer.path != "direct" {
        return Err(api_error(
            StatusCode::BAD_GATEWAY,
            "target device has no available direct path",
        ));
    }
    let target = peer
        .allowed_ips
        .iter()
        .find_map(|value| value.split('/').next()?.parse::<std::net::IpAddr>().ok())
        .ok_or_else(|| {
            api_error(
                StatusCode::BAD_GATEWAY,
                "target device has no virtual address",
            )
        })?;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let ticket = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut sessions = state.terminal_sessions.lock().await;
    sessions.retain(|_, session| session.expires_at > Instant::now());
    if sessions.len() >= crate::terminal::session::MAX_SESSIONS {
        return Err(api_error(
            StatusCode::TOO_MANY_REQUESTS,
            "слишком много ожидающих терминальных сессий",
        ));
    }
    sessions.insert(
        ticket.clone(),
        TerminalTicket {
            target,
            port: snapshot
                .terminal
                .as_ref()
                .map(|terminal| terminal.port)
                .unwrap_or(2222),
            user,
            expires_at: Instant::now()
                + Duration::from_secs(crate::terminal::session::SESSION_TTL_SECONDS),
        },
    );
    drop(sessions);
    Ok(Json(TerminalSessionResponse {
        ticket,
        expires_in_seconds: crate::terminal::session::SESSION_TTL_SECONDS,
        status: "starting",
    }))
}

async fn terminal_websocket(
    State(state): State<ApiState>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| terminal_socket(socket, state))
}

async fn terminal_socket(mut socket: WebSocket, state: ApiState) {
    let Some(Ok(Message::Text(first))) = socket.recv().await else {
        return;
    };
    let request: serde_json::Value = match serde_json::from_str(&first) {
        Ok(value) => value,
        Err(_) => {
            let _ = socket
                .send(Message::Text(
                    r#"{"type":"error","message":"invalid session handshake"}"#.into(),
                ))
                .await;
            return;
        }
    };
    if request.get("type").and_then(|value| value.as_str()) != Some("open") {
        let _ = socket
            .send(Message::Text(
                r#"{"type":"error","message":"session handshake required"}"#.into(),
            ))
            .await;
        return;
    }
    let Some(ticket) = request.get("ticket").and_then(|value| value.as_str()) else {
        return;
    };
    let session = state.terminal_sessions.lock().await.remove(ticket);
    let Some(session) = session.filter(|session| session.expires_at > Instant::now()) else {
        let _ = socket
            .send(Message::Text(
                r#"{"type":"error","message":"terminal ticket expired or already used"}"#.into(),
            ))
            .await;
        return;
    };
    let host = match session.target {
        std::net::IpAddr::V4(address) => address.to_string(),
        std::net::IpAddr::V6(address) => format!("[{address}]"),
    };
    let mut child = match Command::new("ssh")
        .args([
            "-tt",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "ConnectTimeout=12",
            "-p",
            &session.port.to_string(),
            &format!("{}@{host}", session.user),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            let message = serde_json::json!({"type":"error", "message": format!("could not start ssh: {error}")}).to_string();
            let _ = socket.send(Message::Text(message.into())).await;
            return;
        }
    };
    let Some(mut stdin) = child.stdin.take() else {
        return;
    };
    let Some(mut stdout) = child.stdout.take() else {
        return;
    };
    let Some(mut stderr) = child.stderr.take() else {
        return;
    };
    if state
        .active_terminal_sessions
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < crate::terminal::session::MAX_SESSIONS).then_some(count + 1)
        })
        .is_err()
    {
        let _ = child.kill().await;
        let _ = socket
            .send(Message::Text(
                r#"{"type":"error","message":"terminal session limit reached"}"#.into(),
            ))
            .await;
        return;
    }
    let active_guard = state.active_terminal_sessions.clone();
    let _ = socket
        .send(Message::Text(
            r#"{"type":"status","status":"connected"}"#.into(),
        ))
        .await;
    let mut stdout_buffer = vec![0u8; crate::terminal::session::MAX_OUTPUT_FRAME];
    let mut stderr_buffer = vec![0u8; crate::terminal::session::MAX_STDERR_FRAME];
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut idle = Box::pin(tokio::time::sleep(Duration::from_secs(
        crate::terminal::session::IDLE_TIMEOUT_SECONDS,
    )));
    loop {
        tokio::select! {
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => { if bytes.len() > crate::terminal::session::MAX_INPUT_FRAME || stdin.write_all(&bytes).await.is_err() { break; } idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(crate::terminal::session::IDLE_TIMEOUT_SECONDS)); }
                    Some(Ok(Message::Text(text))) => {
                        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
                        match value.get("type").and_then(|value| value.as_str()) {
                            Some("input") => if let Some(data) = value.get("data").and_then(|value| value.as_str()) { if stdin.write_all(data.as_bytes()).await.is_err() { break; } idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(crate::terminal::session::IDLE_TIMEOUT_SECONDS)); },
                            Some("resize") => { /* ssh -tt carries the session; resize is an explicit protocol event. */ }
                            Some("close") => break,
                            _ => {}
                        }
                    }
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                    _ => {}
                }
            }
            result = stdout.read(&mut stdout_buffer), if stdout_open => {
                match result { Ok(0) => stdout_open = false, Ok(size) => { if socket.send(Message::Binary(stdout_buffer[..size].to_vec())).await.is_err() { break } idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(crate::terminal::session::IDLE_TIMEOUT_SECONDS)); }, Err(_) => break }
            }
            result = stderr.read(&mut stderr_buffer), if stderr_open => {
                match result { Ok(0) => stderr_open = false, Ok(size) => { let message = serde_json::json!({"type":"stderr", "data": String::from_utf8_lossy(&stderr_buffer[..size])}).to_string(); if socket.send(Message::Text(message.into())).await.is_err() { break; } idle.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(crate::terminal::session::IDLE_TIMEOUT_SECONDS)); }, Err(_) => break }
            }
            result = child.wait() => {
                let code = result.ok().and_then(|status| status.code()).unwrap_or(1);
                let message = serde_json::json!({"type":"exit", "status": code}).to_string();
                let _ = socket.send(Message::Text(message.into())).await;
                break;
            }
            _ = &mut idle => {
                let message = serde_json::json!({"type":"status", "status":"stale"}).to_string();
                let _ = socket.send(Message::Text(message.into())).await;
                break;
            }
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
    active_guard.fetch_sub(1, Ordering::AcqRel);
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

async fn map_javascript() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/map.js"),
    )
}

async fn xterm_javascript() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/xterm.js"),
    )
}

async fn xterm_stylesheet() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/xterm.css"),
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
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let headers = request.headers();
    let mut response = if !remote.ip().is_loopback() || !valid_host(headers) {
        api_error(StatusCode::FORBIDDEN, "request must target the local API").into_response()
    } else if !valid_origin(headers) {
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

/// Accept only loopback authorities, including a browser-facing SSH tunnel port.
fn valid_host(headers: &HeaderMap) -> bool {
    single_header(headers, HOST)
        .and_then(loopback_authority)
        .is_some()
}

/// The browser's origin must match Host, not the agent's internal listen port.
/// A forwarded port does not bypass authentication or permit cross-origin requests.
fn valid_origin(headers: &HeaderMap) -> bool {
    let Some(host) = single_header(headers, HOST).and_then(loopback_authority) else {
        return false;
    };
    if !headers.contains_key(ORIGIN) {
        return true; // Native CLI requests and same-origin GETs may omit Origin.
    }
    single_header(headers, ORIGIN)
        .and_then(|origin| origin.strip_prefix("http://"))
        .and_then(loopback_authority)
        == Some(host)
}

fn single_header(headers: &HeaderMap, name: axum::http::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}

/// Strict host allowlist prevents DNS rebinding; default HTTP port is normalized.
fn loopback_authority(authority: &str) -> Option<(&'static str, u16)> {
    let authority = authority.to_ascii_lowercase();
    for host in ["localhost", "127.0.0.1", "[::1]"] {
        let Some(suffix) = authority.strip_prefix(host) else {
            continue;
        };
        if suffix.is_empty() {
            return Some((host, 80));
        }
        let port = suffix.strip_prefix(':')?;
        if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let port = port.parse::<u16>().ok()?;
        return (port != 0).then_some((host, port));
    }
    None
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

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(host: &str, origin: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, host.parse().unwrap());
        if let Some(origin) = origin {
            headers.insert(ORIGIN, origin.parse().unwrap());
        }
        headers
    }

    #[test]
    fn forwarded_loopback_port_accepts_same_origin_and_still_requires_a_token() {
        for host in ["127.0.0.1:51822", "localhost:51822", "[::1]:51822"] {
            let mut headers = headers(host, Some(&format!("http://{host}")));
            assert!(valid_host(&headers));
            assert!(valid_origin(&headers));
            let token = "a".repeat(64);
            assert!(!valid_token(&headers, &token));
            headers.insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
            assert!(valid_token(&headers, &token));
            assert!(!valid_token(&headers, &"b".repeat(64)));
        }
        assert!(valid_origin(&headers("127.0.0.1:51822", None)));
        assert!(valid_origin(&headers(
            "LOCALHOST:80",
            Some("http://localhost")
        )));
        assert!(valid_origin(&headers(
            "127.0.0.1",
            Some("http://127.0.0.1:80")
        )));
    }

    #[test]
    fn foreign_rebinding_and_malformed_authorities_are_rejected() {
        for host in [
            "evil.example:51822",
            "localhost.evil.example:51822",
            "127.0.0.1.evil.example:51822",
            "192.0.2.1:51822",
            "localhost@evil.example:51822",
            "user@127.0.0.1:51822",
            "127.0.0.1:51822/path",
            "127.0.0.1:51822?x=1",
            "127.0.0.1:51822#x",
            "127.0.0.1:",
            "127.0.0.1:abc",
            "127.0.0.1:0",
            "127.0.0.1:65536",
            "http://127.0.0.1:51822",
            "::1:51822",
        ] {
            let headers = headers(host, Some(&format!("http://{host}")));
            assert!(!valid_host(&headers), "{host}");
            assert!(!valid_origin(&headers), "{host}");
        }
        assert!(!valid_host(&HeaderMap::new()));
    }

    #[test]
    fn origin_cannot_switch_ports_hosts_or_schemes_and_headers_cannot_be_ambiguous() {
        for origin in [
            "http://evil.example:51822",
            "http://127.0.0.1:51821",
            "http://localhost:51822",
            "https://127.0.0.1:51822",
            "http://127.0.0.1:51822/",
            "http://127.0.0.1:51822?x",
            "null",
        ] {
            assert!(
                !valid_origin(&headers("127.0.0.1:51822", Some(origin))),
                "{origin}"
            );
        }
        let mut duplicate_host = headers("127.0.0.1:51822", None);
        duplicate_host.append(HOST, "localhost:51822".parse().unwrap());
        assert!(!valid_host(&duplicate_host));
        assert!(!valid_origin(&duplicate_host));
        let mut duplicate_origin = headers("127.0.0.1:51822", Some("http://127.0.0.1:51822"));
        duplicate_origin.append(ORIGIN, "http://127.0.0.1:51822".parse().unwrap());
        assert!(!valid_origin(&duplicate_origin));
    }
}
