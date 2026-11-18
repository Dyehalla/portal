//! A small, sandboxed WebDAV service bound to Portal virtual addresses.
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode, header};
use axum::response::Response;
use axum::routing::any;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::io::ReaderStream;

use crate::FileServiceConfig;

const MAX_XML_BYTES: usize = 256 * 1024;

#[derive(Clone)]
struct ServiceState {
    config: FileServiceConfig,
}

pub(crate) struct FileServiceSupervisor {
    config: FileServiceConfig,
    tasks: Vec<JoinHandle<()>>,
    shutdown: Option<watch::Sender<bool>>,
    bound: Vec<std::net::IpAddr>,
    last_error: Option<String>,
}

impl FileServiceSupervisor {
    pub(crate) fn new(config: FileServiceConfig) -> Self {
        Self {
            config,
            tasks: Vec::new(),
            shutdown: None,
            bound: Vec::new(),
            last_error: None,
        }
    }

    pub(crate) fn listen_port(&self) -> u16 {
        self.config.listen_port
    }
    pub(crate) fn read_only(&self) -> bool {
        self.config.read_only
    }
    pub(crate) fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
    pub(crate) fn status(&self) -> &'static str {
        if !self.config.root_dir.is_dir() {
            return "error";
        }
        if self.tasks.is_empty() {
            "starting"
        } else {
            "connected"
        }
    }

    pub(crate) fn reconcile(&mut self, addresses: &[std::net::IpAddr]) -> Result<(), String> {
        if addresses.is_empty() || self.bound == addresses {
            return Ok(());
        }
        self.stop();
        if !self.config.root_dir.is_dir() {
            let message = format!(
                "file service root does not exist: {}",
                self.config.root_dir.display()
            );
            self.last_error = Some(message.clone());
            return Err(message);
        }
        let (shutdown, _) = watch::channel(false);
        let state = Arc::new(ServiceState {
            config: self.config.clone(),
        });
        let mut tasks = Vec::new();
        for address in addresses {
            let listener = std::net::TcpListener::bind(std::net::SocketAddr::new(
                *address,
                self.config.listen_port,
            ))
            .map_err(|e| {
                format!(
                    "could not bind file service on {address}:{}: {e}",
                    self.config.listen_port
                )
            })?;
            listener.set_nonblocking(true).map_err(|e| e.to_string())?;
            let listener = TcpListener::from_std(listener).map_err(|e| e.to_string())?;
            tasks.push(tokio::spawn(serve_listener(
                listener,
                state.clone(),
                shutdown.subscribe(),
            )));
        }
        self.shutdown = Some(shutdown);
        self.tasks = tasks;
        self.bound = addresses.to_vec();
        self.last_error = None;
        Ok(())
    }

    pub(crate) fn stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(true);
        }
        for task in self.tasks.drain(..) {
            task.abort();
        }
        self.bound.clear();
    }
}

impl Drop for FileServiceSupervisor {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn serve_listener(
    listener: TcpListener,
    state: Arc<ServiceState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let app = Router::new()
        .route("/{*path}", any(webdav))
        .with_state(state);
    let _ = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = shutdown.wait_for(|closed| *closed).await;
        })
        .await;
}

async fn webdav(
    axum::extract::State(state): axum::extract::State<Arc<ServiceState>>,
    request: Request,
) -> Response {
    let path = match request_path(request.uri().path()) {
        Ok(path) => path,
        Err(response) => return response,
    };
    let target = match safe_path(&state.config.root_dir, &path) {
        Ok(target) => target,
        Err(response) => return response,
    };
    let method = request.method().clone();
    match method {
        Method::OPTIONS => response(
            StatusCode::NO_CONTENT,
            "",
            [
                (
                    "allow",
                    "OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, MOVE, DELETE",
                ),
                ("dav", "1"),
            ],
        ),
        _ if method.as_str() == "PROPFIND" => propfind(&target, &path, request.headers()).await,
        Method::GET | Method::HEAD => {
            get_file(
                &target,
                request.headers(),
                method == Method::HEAD,
                state.config.max_file_size,
            )
            .await
        }
        Method::PUT => put_file(&target, request, &state.config).await,
        _ if method.as_str() == "MKCOL" => mutate_dir(&target, &state.config, true).await,
        Method::DELETE => delete_entry(&target, &state.config).await,
        _ if method.as_str() == "MOVE" => {
            move_entry(
                &target,
                request.headers(),
                &state.config.root_dir,
                &state.config,
            )
            .await
        }
        _ => response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed", []),
    }
}

fn request_path(value: &str) -> Result<PathBuf, Response> {
    let decoded = percent_decode(value)
        .ok_or_else(|| response(StatusCode::BAD_REQUEST, "invalid URL", []))?;
    let mut path = PathBuf::new();
    for component in decoded.trim_start_matches('/').split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." || component.contains('\0') {
            return Err(response(
                StatusCode::FORBIDDEN,
                "path escapes file root",
                [],
            ));
        }
        path.push(component);
    }
    Ok(path)
}

fn safe_path(root: &Path, relative: &Path) -> Result<PathBuf, Response> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(value) = component else {
            return Err(response(StatusCode::FORBIDDEN, "invalid path", []));
        };
        current.push(value);
        if let Ok(metadata) = std::fs::symlink_metadata(&current) {
            if metadata.file_type().is_symlink() {
                return Err(response(
                    StatusCode::FORBIDDEN,
                    "symbolic links are not allowed",
                    [],
                ));
            }
        }
    }
    Ok(current)
}

async fn propfind(target: &Path, relative: &Path, headers: &HeaderMap) -> Response {
    let depth = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0");
    if depth != "0" && depth != "1" {
        return response(StatusCode::BAD_REQUEST, "unsupported PROPFIND depth", []);
    }
    let metadata = match tokio::fs::metadata(target).await {
        Ok(value) => value,
        Err(_) => return response(StatusCode::NOT_FOUND, "not found", []),
    };
    let is_directory = metadata.is_dir();
    let mut entries = vec![(relative.to_path_buf(), metadata)];
    if depth == "1" && is_directory {
        let mut directory = match tokio::fs::read_dir(target).await {
            Ok(value) => value,
            Err(_) => return response(StatusCode::FORBIDDEN, "directory unavailable", []),
        };
        while let Ok(Some(entry)) = directory.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                if !metadata.file_type().is_symlink() {
                    entries.push((relative.join(entry.file_name()), metadata));
                }
            }
            if entries.len() > 4096 {
                return response(StatusCode::PAYLOAD_TOO_LARGE, "directory is too large", []);
            }
        }
    }
    let mut xml =
        String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?><d:multistatus xmlns:d=\"DAV:\">");
    for (path, metadata) in entries {
        let href = format!("/{}/", path.to_string_lossy().replace('\\', "/"));
        xml.push_str(&format!("<d:response><d:href>{}</d:href><d:propstat><d:prop><d:resourcetype>{}</d:resourcetype><d:getcontentlength>{}</d:getcontentlength></d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>", xml_escape(&href), if metadata.is_dir() { "<d:collection/>" } else { "" }, metadata.len()));
        if xml.len() > MAX_XML_BYTES {
            return response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "directory response is too large",
                [],
            );
        }
    }
    xml.push_str("</d:multistatus>");
    response(
        StatusCode::MULTI_STATUS,
        xml,
        [("content-type", "application/xml; charset=utf-8")],
    )
}

async fn get_file(target: &Path, _headers: &HeaderMap, head: bool, max_size: u64) -> Response {
    let metadata = match tokio::fs::metadata(target).await {
        Ok(value) => value,
        Err(_) => return response(StatusCode::NOT_FOUND, "not found", []),
    };
    if !metadata.is_file() {
        return response(StatusCode::CONFLICT, "not a file", []);
    }
    if metadata.len() > max_size {
        return response(StatusCode::PAYLOAD_TOO_LARGE, "file is too large", []);
    }
    let range = _headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| parse_range(value, metadata.len()));
    let (status, start, length) = range
        .map(|(start, length)| (StatusCode::PARTIAL_CONTENT, start, length))
        .unwrap_or((StatusCode::OK, 0, metadata.len()));
    let mut builder = Response::builder()
        .status(status)
        .header(header::CONTENT_LENGTH, length);
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, start + length - 1, metadata.len()),
        );
    }
    if head {
        return builder.body(Body::empty()).unwrap();
    }
    match tokio::fs::File::open(target).await {
        Ok(mut file) => {
            if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
                return response(StatusCode::RANGE_NOT_SATISFIABLE, "invalid range", []);
            }
            builder
                .body(Body::from_stream(ReaderStream::new(file.take(length))))
                .unwrap()
        }
        Err(_) => response(StatusCode::NOT_FOUND, "not found", []),
    }
}

fn parse_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let value = value.strip_prefix("bytes=")?;
    if value.contains(',') {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = if end.is_empty() {
        size.checked_sub(1)?
    } else {
        end.parse::<u64>().ok()?.min(size.saturating_sub(1))
    };
    (start <= end && start < size).then_some((start, end - start + 1))
}

async fn put_file(target: &Path, request: Request, config: &FileServiceConfig) -> Response {
    if config.read_only {
        return response(StatusCode::FORBIDDEN, "file service is read-only", []);
    }
    if let Some(parent) = target.parent() {
        if tokio::fs::create_dir_all(parent).await.is_err() {
            return response(StatusCode::CONFLICT, "parent directory unavailable", []);
        }
    }
    let temporary = target.with_extension(format!("portal-upload-{}", rand::random::<u64>()));
    let mut file = match tokio::fs::File::create(&temporary).await {
        Ok(value) => value,
        Err(_) => return response(StatusCode::FORBIDDEN, "cannot create file", []),
    };
    let mut size = 0u64;
    let mut stream = http_body_util::BodyExt::into_data_stream(request.into_body());
    use futures_util::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk: Bytes = match chunk {
            Ok(value) => value,
            Err(_) => {
                let _ = tokio::fs::remove_file(&temporary).await;
                return response(StatusCode::BAD_REQUEST, "upload failed", []);
            }
        };
        size = size.saturating_add(chunk.len() as u64);
        if size > config.max_file_size || file.write_all(&chunk).await.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
            return response(StatusCode::PAYLOAD_TOO_LARGE, "file is too large", []);
        }
    }
    if file.sync_all().await.is_err() || tokio::fs::rename(&temporary, target).await.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
        return response(StatusCode::INSUFFICIENT_STORAGE, "cannot commit upload", []);
    }
    response(StatusCode::CREATED, "", [])
}

async fn mutate_dir(target: &Path, config: &FileServiceConfig, create: bool) -> Response {
    if config.read_only {
        return response(StatusCode::FORBIDDEN, "file service is read-only", []);
    }
    if create && tokio::fs::create_dir(target).await.is_err() {
        return response(StatusCode::CONFLICT, "cannot create directory", []);
    }
    response(StatusCode::CREATED, "", [])
}

async fn delete_entry(target: &Path, config: &FileServiceConfig) -> Response {
    if config.read_only {
        return response(StatusCode::FORBIDDEN, "file service is read-only", []);
    }
    let result = match tokio::fs::metadata(target).await {
        Ok(metadata) if metadata.is_dir() => tokio::fs::remove_dir(target).await,
        Ok(_) => tokio::fs::remove_file(target).await,
        Err(_) => return response(StatusCode::NOT_FOUND, "not found", []),
    };
    if result.is_err() {
        response(StatusCode::CONFLICT, "directory must be empty", [])
    } else {
        response(StatusCode::NO_CONTENT, "", [])
    }
}

async fn move_entry(
    target: &Path,
    headers: &HeaderMap,
    root: &Path,
    config: &FileServiceConfig,
) -> Response {
    if config.read_only {
        return response(StatusCode::FORBIDDEN, "file service is read-only", []);
    }
    let destination = match headers
        .get("destination")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once("//").map(|(_, p)| p).or(Some(v)))
    {
        Some(value) => value
            .split_once('/')
            .map(|(_, p)| format!("/{p}"))
            .unwrap_or_else(|| value.to_owned()),
        None => return response(StatusCode::BAD_REQUEST, "destination is required", []),
    };
    let relative = match request_path(&destination) {
        Ok(value) => value,
        Err(response) => return response,
    };
    let destination = match safe_path(root, &relative) {
        Ok(value) => value,
        Err(response) => return response,
    };
    if tokio::fs::rename(target, destination).await.is_err() {
        response(StatusCode::CONFLICT, "cannot move entry", [])
    } else {
        response(StatusCode::CREATED, "", [])
    }
}

fn response(
    status: StatusCode,
    body: impl Into<Body>,
    headers: impl IntoIterator<Item = (&'static str, &'static str)>,
) -> Response {
    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
        .body(body.into())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn percent_decode(value: &str) -> Option<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let bytes_value = value.as_bytes();
    let mut index = 0;
    while index < bytes_value.len() {
        if bytes_value[index] == b'%' {
            if index + 2 >= bytes_value.len() {
                return None;
            }
            let high = (bytes_value[index + 1] as char).to_digit(16)?;
            let low = (bytes_value[index + 2] as char).to_digit(16)?;
            bytes.push((high * 16 + low) as u8);
            index += 3;
        } else {
            bytes.push(bytes_value[index]);
            index += 1;
        }
    }
    String::from_utf8(bytes).ok()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_relative_and_percent_decoded() {
        assert_eq!(request_path("/a%20b/c").unwrap(), PathBuf::from("a b/c"));
        assert!(request_path("/%2e%2e/etc").is_err());
        assert!(request_path("/%00").is_err());
    }

    #[test]
    fn symlinks_are_rejected_inside_the_root() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("outside"), b"secret").unwrap();
        std::os::unix::fs::symlink(
            directory.path().join("outside"),
            directory.path().join("link"),
        )
        .unwrap();
        assert!(safe_path(directory.path(), Path::new("link")).is_err());
    }
}
