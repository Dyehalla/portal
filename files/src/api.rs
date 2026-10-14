use crate::{models::*, service::SharedState};
use portal_net::{PeerKey, Request, Response};
use std::{
    path::{Component, Path},
    time::UNIX_EPOCH,
};

struct ApiError(u16, &'static str);
impl ApiError {
    fn forbidden(message: &'static str) -> Self {
        Self(403, message)
    }
    fn bad_request(message: &'static str) -> Self {
        Self(400, message)
    }
    fn not_found(message: &'static str) -> Self {
        Self(404, message)
    }
    fn busy(message: &'static str) -> Self {
        Self(429, message)
    }
    fn internal(message: &'static str) -> Self {
        Self(500, message)
    }
}
fn parse<T: serde::de::DeserializeOwned>(payload: serde_json::Value) -> Result<T, ApiError> {
    serde_json::from_value(payload)
        .map_err(|_| ApiError::bad_request("invalid operation parameters"))
}
pub(crate) async fn handle(state: SharedState, peer: PeerKey, request: Request) -> Response {
    let allowed = state.allowed_downloaders.contains(&peer);
    if request.operation == "resources" {
        return Response::json(&ListResourcesResponse {
            resources: if allowed {
                vec![FileResource {
                    id: "files".into(),
                    name: "Files".into(),
                    read_only: true,
                }]
            } else {
                Vec::new()
            },
        })
        .unwrap_or_else(|e| Response::error(500, &e));
    }
    if !allowed {
        return Response::error(403, "this peer does not have file access permission");
    }
    let result: Result<Response, ApiError> = async {
        match request.operation.as_str() {
            "list" => Response::json(&list_directory(&state, parse(request.payload)?).await?)
                .map_err(|_| ApiError::internal("could not encode directory")),
            "metadata" => Response::json(&file_metadata(&state, parse(request.payload)?).await?)
                .map_err(|_| ApiError::internal("could not encode metadata")),
            "download" => download(&state, parse(request.payload)?).await,
            _ => Err(ApiError(404, "unknown file operation")),
        }
    }
    .await;
    result.unwrap_or_else(|e| Response::error(e.0, e.1))
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
    state: &SharedState,
    request: ListDirectoryRequest,
) -> Result<ListDirectoryResponse, ApiError> {
    if request.limit == 0 || request.limit > 1000 {
        return Err(ApiError::bad_request("limit must be between 1 and 1000"));
    }
    let path = resolve(state, &request.path).await?;
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
    Ok(ListDirectoryResponse {
        path: request.path,
        entries,
        next_offset,
    })
}

async fn file_metadata(
    state: &SharedState,
    request: FilePathRequest,
) -> Result<FileEntry, ApiError> {
    let path = resolve(state, &request.path).await?;
    let metadata = tokio::fs::metadata(path)
        .await
        .map_err(|_| ApiError::not_found("path cannot be accessed"))?;
    let name = Path::new(&request.path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("Files")
        .to_owned();
    Ok(entry(request.path, name, metadata))
}

async fn download(state: &SharedState, request: FilePathRequest) -> Result<Response, ApiError> {
    if !is_safe_relative_path(Path::new(&request.path)) {
        return Err(ApiError::bad_request(
            "path must contain ordinary relative components",
        ));
    }
    let permit = state
        .download_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::busy("file service has too many downloads"))?;
    let path = resolve(state, &request.path).await?;
    // TODO: Use a cross-platform, race-safe relative open. Canonicalize and open
    // can race with replacement of a file or parent directory by a symlink.
    let file = tokio::fs::File::open(&path)
        .await
        .map_err(|_| ApiError::not_found("file cannot be opened"))?;
    let metadata = file
        .metadata()
        .await
        .map_err(|_| ApiError::internal("could not inspect file"))?;
    if !metadata.is_file() {
        return Err(ApiError::bad_request(
            "requested path is not a regular file",
        ));
    }
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| ApiError::bad_request("filename must be UTF-8"))?
        .to_owned();
    if name.len() > 1024 {
        return Err(ApiError::bad_request("filename is too long"));
    }
    Ok(Response::stream(
        crate::service::DownloadReader {
            file,
            _permit: permit,
        },
        metadata.len(),
        name,
    ))
}
fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty() && path.components().all(|c| matches!(c, Component::Normal(_)))
}
