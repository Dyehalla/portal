use crate::{models::*, service::SharedState};
use portal_net::{PeerKey, Request, Response};
use std::{
    path::{Component, Path},
    time::UNIX_EPOCH,
};

#[derive(Debug)]
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

fn relative_path(path: &str) -> Result<&Path, ApiError> {
    if !path.is_empty() && !is_safe_relative_path(Path::new(path)) {
        return Err(ApiError::bad_request(
            "path must be relative and may not contain parent components",
        ));
    }
    Ok(Path::new(if path.is_empty() { "." } else { path }))
}

fn access_error(error: std::io::Error) -> ApiError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        ApiError::forbidden("path is outside the shared root or access is denied")
    } else {
        ApiError::not_found("path does not exist or cannot be accessed")
    }
}

// cap-std operations are synchronous; keep filesystem work off Tokio's async workers.
async fn filesystem<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, ApiError> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|_| ApiError::internal("filesystem task failed"))?
}

fn entry(path: String, name: String, metadata: cap_std::fs::Metadata) -> FileEntry {
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
            .and_then(|time| time.into_std().duration_since(UNIX_EPOCH).ok())
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
    let state = state.clone();
    filesystem(move || list_page(&state, request)).await
}

fn list_page(
    state: &SharedState,
    request: ListDirectoryRequest,
) -> Result<ListDirectoryResponse, ApiError> {
    let directory = state
        .root
        .open_dir(relative_path(&request.path)?)
        .map_err(access_error)?;
    let mut entries = Vec::new();
    for item in directory.entries().map_err(access_error)? {
        let item = item.map_err(|_| ApiError::internal("could not read directory"))?;
        if entries.len() >= 10000 {
            return Err(ApiError::busy(
                "directory exceeds the 10000-entry browsing limit",
            ));
        }
        let name = item.file_name().into_string().map_err(|_| {
            ApiError::bad_request("directory contains a filename that is not UTF-8")
        })?;
        entries.push((name, item));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let next = request.offset.saturating_add(request.limit);
    let next_offset = (next < entries.len()).then_some(next);
    let entries = entries
        .into_iter()
        .skip(request.offset)
        .take(request.limit)
        .map(|(name, item)| {
            let relative = if request.path.is_empty() {
                name.clone()
            } else {
                format!("{}/{name}", request.path.trim_end_matches('/'))
            };
            // DirEntry retains the directory handle; metadata does not follow the final symlink.
            let metadata = item.metadata().map_err(access_error)?;
            Ok(entry(relative, name, metadata))
        })
        .collect::<Result<_, ApiError>>()?;
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
    let state = state.clone();
    filesystem(move || {
        let path = relative_path(&request.path)?;
        // cap-std resolves and inspects relative to the held root, including symlink traversal.
        let metadata = state.root.metadata(path).map_err(access_error)?;
        let name = Path::new(&request.path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("Files")
            .to_owned();
        Ok(entry(request.path, name, metadata))
    })
    .await
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
    let state = state.clone();
    let (file, length, name) = filesystem(move || open_download(&state, &request.path)).await?;
    Ok(Response::stream(
        crate::service::DownloadReader {
            file: tokio::fs::File::from_std(file),
            _permit: permit,
        },
        length,
        name,
    ))
}

fn open_download(
    state: &SharedState,
    path: &str,
) -> Result<(std::fs::File, u64, String), ApiError> {
    let path = relative_path(path)?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true);
    // A concurrently substituted FIFO must not block before we can inspect the handle.
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = state.root.open_with(path, &options).map_err(access_error)?;
    let metadata = file.metadata().map_err(access_error)?;
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
    Ok((file.into_std(), metadata.len(), name))
}
fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty() && path.components().all(|c| matches!(c, Component::Normal(_)))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{fs, io::Read, os::unix::fs::symlink, sync::Arc};

    #[tokio::test]
    async fn held_root_and_relative_opens_resist_path_replacement() {
        let root =
            std::env::temp_dir().join(format!("portal-files-race-{:032x}", rand::random::<u128>()));
        let share = root.join("share");
        let outside = root.join("outside");
        fs::create_dir_all(share.join("dir")).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(share.join("dir/data"), b"safe").unwrap();
        fs::write(outside.join("data"), b"secret outside the share").unwrap();
        let state = SharedState {
            root: Arc::new(
                cap_std::fs::Dir::open_ambient_dir(&share, cap_std::ambient_authority()).unwrap(),
            ),
            allowed_downloaders: Arc::new(Default::default()),
            download_slots: Arc::new(tokio::sync::Semaphore::new(1)),
        };
        // Only relative symlinks whose targets stay within the held root are accepted.
        symlink("dir/data", share.join("inside")).unwrap();
        symlink("../outside", share.join("escape")).unwrap();
        assert!(open_download(&state, "inside").is_ok());
        assert_eq!(open_download(&state, "escape/data").unwrap_err().0, 403);
        for path in ["../outside/data", "/etc/passwd"] {
            assert_eq!(open_download(&state, path).unwrap_err().0, 400);
        }

        let swapping_share = share.clone();
        let swapper = std::thread::spawn(move || {
            for _ in 0..1000 {
                fs::rename(swapping_share.join("dir"), swapping_share.join("parked")).unwrap();
                symlink("../outside", swapping_share.join("dir")).unwrap();
                std::thread::yield_now();
                fs::remove_file(swapping_share.join("dir")).unwrap();
                fs::rename(swapping_share.join("parked"), swapping_share.join("dir")).unwrap();
            }
        });
        for _ in 0..200 {
            if let Ok((mut file, size, _)) = open_download(&state, "dir/data") {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).unwrap();
                assert_eq!(contents, b"safe");
                assert_eq!(size, 4);
            }
            if let Ok(metadata) = file_metadata(
                &state,
                FilePathRequest {
                    path: "dir/data".into(),
                },
            )
            .await
            {
                assert_eq!(metadata.size_bytes, Some(4));
            }
        }
        swapper.join().unwrap();

        // Renaming the configured root and replacing its name cannot redirect the service.
        fs::rename(&share, root.join("held")).unwrap();
        symlink(&outside, &share).unwrap();
        let mut response = download(
            &state,
            FilePathRequest {
                path: "dir/data".into(),
            },
        )
        .await
        .unwrap();
        let mut bytes = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut response.body, &mut bytes)
            .await
            .unwrap();
        assert_eq!(bytes, b"safe");
        let listing = list_directory(
            &state,
            ListDirectoryRequest {
                path: "dir".into(),
                offset: 0,
                limit: 1,
            },
        )
        .await
        .unwrap();
        assert_eq!(listing.entries[0].name, "data");
        let metadata = file_metadata(
            &state,
            FilePathRequest {
                path: "dir/data".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(metadata.size_bytes, Some(4));
        drop(response);
        drop(state);
        fs::remove_dir_all(root).unwrap();
    }
}
