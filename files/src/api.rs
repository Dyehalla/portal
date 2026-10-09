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
    pub files: SharedState,
}

pub(crate) fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/resources", get(list_resources))
        .route("/v1/files/list", post(list_directory))
        .route("/v1/files/metadata", post(file_metadata))
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
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

async fn list_resources(
    State(api): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Json<ListResourcesResponse> {
    let resources = if api.files.allowed_downloaders.contains(&peer.ip()) {
        vec![FileResource {
            id: "files".into(),
            name: "Files".into(),
            read_only: true,
        }]
    } else {
        Vec::new()
    };
    Json(ListResourcesResponse { resources })
}

fn authorize(state: &SharedState, peer: SocketAddr) -> Result<(), ApiError> {
    if state.allowed_downloaders.contains(&peer.ip()) {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "this peer does not have file access permission",
        ))
    }
}

async fn resolve(state: &SharedState, path: &str) -> Result<std::path::PathBuf, ApiError> {
    if !path.is_empty() && !is_safe_relative_path(Path::new(path)) {
        return Err(ApiError::bad_request(
            "path must be relative and may not contain parent components",
        ));
    }
    let canonical = tokio::fs::canonicalize(state.root.join(path))
        .await
        .map_err(|_| ApiError::not_found("path does not exist or cannot be accessed"))?;
    if !canonical.starts_with(state.root.as_path()) {
        return Err(ApiError::forbidden("path resolves outside the shared root"));
    }
    // TODO: Directory traversal/metadata also need a cross-platform, race-safe relative open.
    // Canonicalize followed by filesystem access can race with symlink replacement.
    Ok(canonical)
}

fn entry(path: String, name: String, metadata: std::fs::Metadata) -> FileEntry {
    let kind = if metadata.file_type().is_symlink() {
        FileKind::Symlink
    } else if metadata.is_dir() {
        FileKind::Directory
    } else if metadata.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    };
    FileEntry {
        name,
        path,
        size_bytes: metadata.is_file().then_some(metadata.len()),
        kind,
        modified_at_unix_seconds: metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs()),
    }
}

async fn list_directory(
    State(api): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<ListDirectoryRequest>,
) -> Result<Json<ListDirectoryResponse>, ApiError> {
    authorize(&api.files, peer)?;
    if request.limit == 0 || request.limit > 1000 {
        return Err(ApiError::bad_request("limit must be between 1 and 1000"));
    }
    let path = resolve(&api.files, &request.path).await?;
    let mut directory = tokio::fs::read_dir(path)
        .await
        .map_err(|_| ApiError::bad_request("path is not an accessible directory"))?;
    let mut entries = Vec::new();
    while let Some(item) = directory
        .next_entry()
        .await
        .map_err(|_| ApiError::internal("could not read directory"))?
    {
        if entries.len() >= 10000 {
            return Err(ApiError::busy(
                "directory exceeds the 10000-entry browsing limit",
            ));
        }
        let name = item.file_name().into_string().map_err(|_| {
            ApiError::bad_request("directory contains a filename that is not UTF-8")
        })?;
        let relative = if request.path.is_empty() {
            name.clone()
        } else {
            format!("{}/{name}", request.path.trim_end_matches('/'))
        };
        // symlink_metadata does not follow the final link or expose its target metadata.
        let metadata = tokio::fs::symlink_metadata(item.path())
            .await
            .map_err(|_| ApiError::not_found("directory entry changed or cannot be accessed"))?;
        entries.push(entry(relative, name, metadata));
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let next = request.offset.saturating_add(request.limit);
    let next_offset = (next < entries.len()).then_some(next);
    let entries = entries
        .into_iter()
        .skip(request.offset)
        .take(request.limit)
        .collect();
    Ok(Json(ListDirectoryResponse {
        path: request.path,
        entries,
        next_offset,
    }))
}

async fn file_metadata(
    State(api): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<FilePathRequest>,
) -> Result<Json<FileEntry>, ApiError> {
    authorize(&api.files, peer)?;
    let path = resolve(&api.files, &request.path).await?;
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|_| ApiError::not_found("path cannot be accessed"))?;
    let name = Path::new(&request.path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Files")
        .to_owned();
    Ok(Json(entry(request.path, name, metadata)))
}

async fn prepare_download(
    State(api): State<ApiState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(request): Json<PrepareDownloadRequest>,
) -> Result<Json<PrepareDownloadResponse>, ApiError> {
    let requester = peer.ip();
    let state = &api.files;
    authorize(state, peer)?;
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
