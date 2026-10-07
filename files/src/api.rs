use crate::models::*;
use crate::service::{DownloadTicket, SharedState};
use axum::extract::{ConnectInfo, DefaultBodyLimit, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::RngCore;
use std::net::SocketAddr;
use std::path::{Component, Path};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
const TICKET_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Clone)]
pub(crate) struct ApiState {
    pub downloads: Option<SharedState>,
    pub smb: Option<std::sync::Arc<crate::smb::SmbAccess>>,
}

pub(crate) fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/shares", get(list_shares))
        .route("/v1/smb/connections", post(prepare_smb_connection))
        .route("/v1/downloads", post(prepare_download))
        .route("/v1/download/:ticket", get(crate::service::http_download))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(axum::middleware::map_response(
            |mut response: Response| async move {
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    axum::http::HeaderValue::from_static("no-store"),
                );
                response
            },
        ))
        .with_state(state)
}

#[derive(Debug)]
pub(crate) struct ApiError(StatusCode, &'static str);
impl ApiError {
    fn forbidden(message: &'static str) -> Self {
        Self(StatusCode::FORBIDDEN, message)
    }
    fn bad_request(message: &'static str) -> Self {
        Self(StatusCode::BAD_REQUEST, message)
    }
    fn not_found(message: &'static str) -> Self {
        Self(StatusCode::NOT_FOUND, message)
    }
    fn busy(message: &'static str) -> Self {
        Self(StatusCode::TOO_MANY_REQUESTS, message)
    }
    fn internal(message: &'static str) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
    fn disabled(message: &'static str) -> Self {
        Self(StatusCode::NOT_IMPLEMENTED, message)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

async fn list_shares(
    State(api): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Json<ListSharesResponse> {
    let shares = api
        .smb
        .as_ref()
        .filter(|smb| smb.allowed_peers.contains(&peer.ip()))
        .map(|smb| vec![smb.share.clone()])
        .unwrap_or_default();
    Json(ListSharesResponse { shares })
}

async fn prepare_smb_connection(
    State(api): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<PrepareSmbConnectionRequest>,
) -> Result<Json<PrepareSmbConnectionResponse>, ApiError> {
    let smb = api
        .smb
        .as_ref()
        .ok_or_else(|| ApiError::disabled("SMB sharing is disabled"))?;
    if !smb.allowed_peers.contains(&peer.ip()) {
        return Err(ApiError::forbidden(
            "this peer does not have SMB permission",
        ));
    }
    if request.share_name != smb.share.name {
        return Err(ApiError::not_found("SMB share does not exist"));
    }
    Ok(Json(PrepareSmbConnectionResponse {
        share: smb.share.clone(),
        username: smb.username.clone(),
        password: smb.password.to_string(),
    }))
}

async fn prepare_download(
    State(api): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<PrepareDownloadRequest>,
) -> Result<Json<PrepareDownloadResponse>, ApiError> {
    let requester = peer.ip();
    let state = api
        .downloads
        .as_ref()
        .ok_or_else(|| ApiError::disabled("HTTP downloads are disabled"))?;
    if !state.allowed_downloaders.contains(&requester) {
        return Err(ApiError::forbidden(
            "this peer does not have file download permission",
        ));
    }
    let relative_path = Path::new(&request.path);
    if !is_safe_relative_path(relative_path) {
        return Err(ApiError::bad_request(
            "path must be relative and may not contain dot or parent components",
        ));
    }
    state.prune_expired().await;
    let permit = state
        .download_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::busy("file service has too many downloads"))?;
    let requested_path = state.root.join(relative_path);
    let canonical_path = tokio::fs::canonicalize(&requested_path)
        .await
        .map_err(|_| ApiError::not_found("file does not exist or cannot be accessed"))?;
    if !canonical_path.starts_with(state.root.as_path()) {
        return Err(ApiError::forbidden(
            "file path resolves outside the shared root",
        ));
    }

    // TODO: Use a cross-platform, race-safe directory-relative open (e.g. cap-std).
    // A file or parent directory can be replaced with a symlink between canonicalize
    // and open, allowing access outside the shared root. Path checks alone do not fix this.
    let file = tokio::fs::File::open(&canonical_path)
        .await
        .map_err(|_| ApiError::not_found("file does not exist or cannot be accessed"))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| ApiError::internal("could not inspect requested file"))?;
    if !metadata.is_file() {
        return Err(ApiError::bad_request(
            "requested path is not a regular file",
        ));
    }
    let file_name = canonical_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .ok_or_else(|| ApiError::bad_request("requested path has no file name"))?;
    let size_bytes = metadata.len();
    let expires = Instant::now() + TICKET_TTL;
    let expires_at_unix_seconds = SystemTime::now()
        .checked_add(TICKET_TTL)
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    let ticket_id = create_ticket_id();
    let download_url = format!("{}/v1/download/{ticket_id}", state.http_advertise);
    {
        let mut tickets = state.tickets.lock().await;
        tickets.insert(
            ticket_id,
            DownloadTicket {
                file,
                size_bytes,
                requester,
                expires,
                permit,
            },
        );
    }

    Ok(Json(PrepareDownloadResponse {
        download_url,
        file_name,
        size_bytes,
        expires_at_unix_seconds,
    }))
}

/// Accept only ordinary path components so callers cannot request parent or absolute paths.
fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Create an unguessable bearer ticket identifier for the one-use HTTP request.
fn create_ticket_id() -> String {
    let mut random = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> ApiState {
        ApiState {
            downloads: None,
            smb: Some(std::sync::Arc::new(crate::smb::SmbAccess {
                share: SmbShare {
                    name: "documents".into(),
                    host: "10.20.0.1".into(),
                    port: 1445,
                    read_only: true,
                },
                username: "reader".into(),
                password: zeroize::Zeroizing::new("secret".into()),
                allowed_peers: vec!["10.20.0.2".parse().unwrap()],
            })),
        }
    }
    fn peer(ip: &str) -> ConnectInfo<SocketAddr> {
        ConnectInfo(ip.parse().unwrap())
    }
    #[tokio::test]
    async fn smb_permissions_use_transport_ip_and_are_independent_of_downloads() {
        let api = state();
        assert_eq!(
            list_shares(State(api.clone()), peer("10.20.0.2:1234"))
                .await
                .0
                .shares
                .len(),
            1
        );
        assert!(
            list_shares(State(api.clone()), peer("10.20.0.3:1234"))
                .await
                .0
                .shares
                .is_empty()
        );
        let body = || {
            Json(PrepareSmbConnectionRequest {
                share_name: "documents".into(),
            })
        };
        let granted = prepare_smb_connection(State(api.clone()), peer("10.20.0.2:1234"), body())
            .await
            .unwrap()
            .0;
        assert_eq!(granted.password, "secret");
        assert_eq!(granted.share.port, 1445);
        let denied = prepare_smb_connection(State(api.clone()), peer("10.20.0.3:1234"), body())
            .await
            .err()
            .unwrap();
        assert_eq!(denied.0, StatusCode::FORBIDDEN);
        assert_eq!(
            prepare_smb_connection(
                State(api.clone()),
                peer("10.20.0.2:1234"),
                Json(PrepareSmbConnectionRequest {
                    share_name: "hidden".into()
                })
            )
            .await
            .err()
            .unwrap()
            .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            prepare_download(
                State(api),
                peer("10.20.0.2:1234"),
                Json(PrepareDownloadRequest {
                    path: "file".into()
                })
            )
            .await
            .err()
            .unwrap()
            .0,
            StatusCode::NOT_IMPLEMENTED
        );
    }
    #[tokio::test]
    async fn disabled_smb_returns_no_shares_or_credentials() {
        let api = ApiState {
            downloads: None,
            smb: None,
        };
        assert!(
            list_shares(State(api.clone()), peer("10.20.0.2:1234"))
                .await
                .0
                .shares
                .is_empty()
        );
        assert_eq!(
            prepare_smb_connection(
                State(api),
                peer("10.20.0.2:1234"),
                Json(PrepareSmbConnectionRequest {
                    share_name: "documents".into()
                })
            )
            .await
            .err()
            .unwrap()
            .0,
            StatusCode::NOT_IMPLEMENTED
        );
    }
}
