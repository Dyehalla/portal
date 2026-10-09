use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::{Request as HttpRequest, StatusCode, Uri, header};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::io::AsyncWriteExt;

use crate::models::{PrepareDownloadRequest, PrepareDownloadResponse};

const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);

async fn network_wait<T>(future: impl Future<Output = T>, operation: &str) -> Result<T, String> {
    tokio::time::timeout(NETWORK_TIMEOUT, future)
        .await
        .map_err(|_| format!("{operation} timed out after 30 seconds"))
}

/// Negotiate a download over HTTP, stream it over HTTP, then atomically publish the completed file.
pub async fn download(peer_url: &str, remote_path: &str, output: &Path) -> Result<(), String> {
    let response: PrepareDownloadResponse = json_request(
        peer_url,
        "/v1/downloads",
        Some(&PrepareDownloadRequest {
            path: remote_path.to_owned(),
        }),
    )
    .await?;

    let uri = response
        .download_url
        .parse::<Uri>()
        .map_err(|error| format!("file service returned an invalid HTTP URL: {error}"))?;
    if uri.scheme_str() != Some("http") || uri.authority().is_none() {
        return Err("file service returned a URL that is not an absolute HTTP URL".into());
    }
    let peer = peer_uri(peer_url)?;
    if uri.scheme() != peer.scheme() || uri.authority() != peer.authority() {
        return Err("download URL must belong to the requested peer".into());
    }
    let client = http_client();
    let request = HttpRequest::get(uri)
        .body(Full::new(Bytes::new()))
        .map_err(|error| format!("could not create HTTP request: {error}"))?;
    let response_body = network_wait(client.request(request), "HTTP response")
        .await?
        .map_err(|error| format!("HTTP file transfer failed: {error}"))?;
    if response_body.status() != StatusCode::OK {
        return Err(format!(
            "HTTP file transfer failed with status {}",
            response_body.status()
        ));
    }
    if let Some(content_length) = response_body.headers().get(header::CONTENT_LENGTH) {
        let content_length = content_length
            .to_str()
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| "file service returned an invalid Content-Length".to_owned())?;
        if content_length != response.size_bytes {
            return Err(format!(
                "file size changed during negotiation: HTTP reported {} bytes, HTTP reported {content_length}",
                response.size_bytes
            ));
        }
    }

    save_download(
        response_body,
        output,
        response.size_bytes,
        response.file_name,
    )
    .await
}

async fn save_download(
    response_body: hyper::Response<hyper::body::Incoming>,
    output: &Path,
    size_bytes: u64,
    file_name: String,
) -> Result<(), String> {
    let (temporary_path, mut file) = create_temporary_file(output).await?;
    let result = async {
        let mut received_bytes = 0_u64;
        let mut body = response_body
            .into_body()
            .into_data_stream()
            .filter(|chunk| {
                std::future::ready(!chunk.as_ref().is_ok_and(|chunk| chunk.is_empty()))
            });
        while let Some(chunk) = network_wait(body.next(), "HTTP body progress").await? {
            let chunk =
                chunk.map_err(|error| format!("could not read HTTP response body: {error}"))?;
            received_bytes = received_bytes
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| "downloaded file size overflowed".to_owned())?;
            if received_bytes > size_bytes {
                return Err("HTTP file body exceeded the size announced over HTTP".into());
            }
            file.write_all(&chunk).await.map_err(|error| {
                format!("could not write {}: {error}", temporary_path.display())
            })?;
        }
        if received_bytes != size_bytes {
            return Err(format!(
                "incomplete download: received {received_bytes} of {} bytes",
                size_bytes
            ));
        }
        file.sync_all()
            .await
            .map_err(|error| format!("could not flush downloaded file: {error}"))?;
        drop(file);
        tokio::fs::rename(&temporary_path, output)
            .await
            .map_err(|error| {
                format!(
                    "could not move completed file to {}: {error}",
                    output.display()
                )
            })?;
        Ok::<(), String>(())
    }
    .await;
    if result.is_err() {
        let _ = tokio::fs::remove_file(&temporary_path).await;
    }
    result?;

    println!(
        "downloaded {} ({} bytes) to {}",
        file_name,
        size_bytes,
        output.display()
    );
    Ok(())
}

/// Create a unique partial file beside the destination for an atomic final rename.
async fn create_temporary_file(output: &Path) -> Result<(PathBuf, tokio::fs::File), String> {
    let parent = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = output
        .file_name()
        .ok_or_else(|| "--output must name a file".to_owned())?
        .to_string_lossy();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..16_u8 {
        let temporary_path = parent.join(format!(
            ".{name}.portal-partial-{}-{timestamp}-{attempt}",
            std::process::id()
        ));
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temporary_path).await {
            Ok(file) => return Ok((temporary_path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "could not create temporary download file beside {}: {error}",
                    output.display()
                ));
            }
        }
    }
    Err("could not allocate a unique temporary download file".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn stalled_network_operation_times_out() {
        let result = network_wait(std::future::pending::<()>(), "HTTP body progress").await;
        assert!(result.unwrap_err().contains("timed out"));
    }
}

type HttpClient = Client<portal_net::Connector, Full<Bytes>>;
fn http_client() -> HttpClient {
    Client::builder(TokioExecutor::new()).build(portal_net::Connector::default())
}
fn peer_uri(peer_url: &str) -> Result<Uri, String> {
    let uri = peer_url
        .parse::<Uri>()
        .map_err(|e| format!("invalid --peer URL: {e}"))?;
    if uri.scheme_str() != Some("http")
        || uri.authority().is_none()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        || uri.path() != "/"
        || uri.query().is_some()
    {
        return Err("--peer must be an HTTP origin, such as http://10.20.0.1:8080".into());
    }
    Ok(uri)
}

async fn json_request<T: serde::de::DeserializeOwned, B: serde::Serialize>(
    peer_url: &str,
    path: &str,
    body: Option<&B>,
) -> Result<T, String> {
    let origin = peer_uri(peer_url)?;
    let url = format!(
        "http://{}{path}",
        origin.authority().expect("validated authority")
    );
    let bytes = match body {
        Some(body) => serde_json::to_vec(body).map_err(|e| e.to_string())?,
        None => Vec::new(),
    };
    let request = HttpRequest::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(url)
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(bytes)))
        .map_err(|e| e.to_string())?;
    let client = http_client();
    network_wait(
        async {
            let response = client
                .request(request)
                .await
                .map_err(|e| format!("peer HTTP request failed: {e}"))?;
            if response.status() != StatusCode::OK {
                return Err(format!(
                    "peer HTTP request rejected with status {}",
                    response.status()
                ));
            }
            let mut body = response.into_body();
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|e| format!("could not read peer HTTP response: {e}"))?;
                if let Some(chunk) = frame.data_ref() {
                    if bytes.len() + chunk.len() > 1024 * 1024 {
                        return Err("peer JSON response exceeds 1 MiB".into());
                    }
                    bytes.extend_from_slice(chunk);
                }
            }
            serde_json::from_slice(&bytes).map_err(|_| "peer returned invalid JSON".to_owned())
        },
        "HTTP negotiation",
    )
    .await?
}

/// Discover resources visible to this tunnel peer.
pub async fn list_resources(
    peer_url: &str,
) -> Result<crate::models::ListResourcesResponse, String> {
    json_request::<_, ()>(peer_url, "/v1/resources", None).await
}
pub async fn list_directory(
    peer_url: &str,
    request: &crate::models::ListDirectoryRequest,
) -> Result<crate::models::ListDirectoryResponse, String> {
    json_request(peer_url, "/v1/files/list", Some(request)).await
}
pub async fn file_metadata(peer_url: &str, path: &str) -> Result<crate::models::FileEntry, String> {
    json_request(
        peer_url,
        "/v1/files/metadata",
        Some(&crate::models::FilePathRequest {
            path: path.to_owned(),
        }),
    )
    .await
}

/// Forward a local browser operation to a registered peer. No arbitrary URL/route is accepted.
/// Downloads are streamed through the runtime, keeping peer tickets out of browser requests.
pub async fn proxy_request(
    peer: std::net::SocketAddr,
    route: &str,
    body: &[u8],
) -> Result<axum::response::Response, String> {
    proxy_request_with_net(None, peer, route, body).await
}

pub async fn proxy_request_with_net(
    network: Option<portal_net::Net>,
    peer: std::net::SocketAddr,
    route: &str,
    body: &[u8],
) -> Result<axum::response::Response, String> {
    let origin = format!("http://{peer}");
    let path = match route {
        "resources" => "/v1/resources",
        "list" => "/v1/files/list",
        "metadata" => "/v1/files/metadata",
        "download" => "/v1/downloads",
        _ => return Err("unknown file operation".into()),
    };
    let request = HttpRequest::builder()
        .method(if route == "resources" { "GET" } else { "POST" })
        .uri(format!("{origin}{path}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|e| e.to_string())?;
    let client = Client::builder(TokioExecutor::new()).build(portal_net::Connector { network });
    let response = network_wait(client.request(request), "peer HTTP response")
        .await?
        .map_err(|e| format!("peer HTTP request failed: {e}"))?;
    if route != "download" || response.status() != StatusCode::OK {
        return bounded_proxy_response(response).await;
    }
    let bytes = read_json_body(response.into_body()).await?;
    let ticket: PrepareDownloadResponse =
        serde_json::from_slice(&bytes).map_err(|_| "peer returned invalid download parameters")?;
    let url = ticket
        .download_url
        .parse::<Uri>()
        .map_err(|_| "invalid peer download URL")?;
    if url.scheme_str() != Some("http") || url.authority() != peer_uri(&origin)?.authority() {
        return Err("download URL must belong to the requested peer".into());
    }
    let request = HttpRequest::get(url)
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let response = network_wait(client.request(request), "peer download response")
        .await?
        .map_err(|e| e.to_string())?;
    if response.status() != StatusCode::OK {
        return bounded_proxy_response(response).await;
    }
    let expected = ticket.size_bytes;
    let stream = futures_util::stream::unfold(
        (response.into_body().into_data_stream(), 0_u64, false),
        move |(mut body, received, done)| async move {
            if done {
                return None;
            }
            let result = network_wait(body.next(), "peer download progress").await;
            let (chunk, received, done) = match result {
                Ok(Some(Ok(chunk))) => {
                    let total = received.saturating_add(chunk.len() as u64);
                    if total > expected {
                        (
                            Err(std::io::Error::other("peer body exceeded advertised size")),
                            total,
                            true,
                        )
                    } else {
                        (Ok(chunk), total, false)
                    }
                }
                Ok(None) if received == expected => return None,
                Ok(None) => (
                    Err(std::io::Error::other("incomplete peer download")),
                    received,
                    true,
                ),
                Ok(Some(Err(error))) => (Err(std::io::Error::other(error)), received, true),
                Err(error) => (Err(std::io::Error::other(error)), received, true),
            };
            Some((chunk, (body, received, done)))
        },
    );
    let mut result = axum::response::Response::new(axum::body::Body::from_stream(stream));
    result.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/octet-stream"),
    );
    result.headers_mut().insert(
        header::CONTENT_LENGTH,
        http::HeaderValue::from_str(&expected.to_string()).map_err(|e| e.to_string())?,
    );
    // Encode UTF-8 filenames rather than interpolating untrusted characters into a header.
    let encoded: String = ticket
        .file_name
        .bytes()
        .map(|byte| format!("%{byte:02X}"))
        .collect();
    result.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        http::HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{encoded}"))
            .map_err(|e| e.to_string())?,
    );
    result.headers_mut().insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    Ok(result)
}

async fn read_json_body(mut body: hyper::body::Incoming) -> Result<Vec<u8>, String> {
    network_wait(
        async {
            let mut bytes = Vec::new();
            while let Some(frame) = body.frame().await {
                let frame = frame.map_err(|e| e.to_string())?;
                if let Some(chunk) = frame.data_ref() {
                    if bytes.len() + chunk.len() > 1024 * 1024 {
                        return Err("peer JSON response exceeds 1 MiB".into());
                    }
                    bytes.extend_from_slice(chunk);
                }
            }
            Ok(bytes)
        },
        "peer JSON body",
    )
    .await?
}
async fn bounded_proxy_response(
    response: hyper::Response<hyper::body::Incoming>,
) -> Result<axum::response::Response, String> {
    let status = response.status();
    let bytes = read_json_body(response.into_body()).await?;
    let mut response = axum::response::Response::new(axum::body::Body::from(bytes));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        http::HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    Ok(response)
}

/// Call the authenticated loopback API. Remote file requests are forwarded by the runtime's stack.
pub async fn local_request<B: serde::Serialize>(
    api: &str,
    token: &str,
    operation: &str,
    request: &B,
) -> Result<hyper::Response<hyper::body::Incoming>, String> {
    let origin = peer_uri(api)?;
    let host = origin
        .host()
        .ok_or("local API URL has no host")?
        .trim_matches(['[', ']']);
    if host != "localhost"
        && !host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    {
        return Err("--api must target loopback".into());
    }
    if !["resources", "list", "metadata", "download"].contains(&operation) {
        return Err("unknown file operation".into());
    }
    let request = HttpRequest::post(format!(
        "http://{}/api/v1/files/{operation}",
        origin.authority().unwrap()
    ))
    .header(header::CONTENT_TYPE, "application/json")
    .header(header::AUTHORIZATION, format!("Bearer {token}"))
    .body(Full::new(Bytes::from(
        serde_json::to_vec(request).map_err(|e| e.to_string())?,
    )))
    .map_err(|e| e.to_string())?;
    let response = network_wait(http_client().request(request), "local API response")
        .await?
        .map_err(|e| e.to_string())?;
    if response.status() != StatusCode::OK {
        return Err(format!(
            "file request rejected with status {}",
            response.status()
        ));
    }
    Ok(response)
}
pub async fn local_json<B: serde::Serialize, T: serde::de::DeserializeOwned>(
    api: &str,
    token: &str,
    operation: &str,
    request: &B,
) -> Result<T, String> {
    let response = local_request(api, token, operation, request).await?;
    let body = read_json_body(response.into_body()).await?;
    serde_json::from_slice(&body).map_err(|e| format!("local API returned invalid JSON: {e}"))
}
pub async fn local_download<B: serde::Serialize>(
    api: &str,
    token: &str,
    request: &B,
    path: &str,
    output: &Path,
) -> Result<(), String> {
    let response = local_request(api, token, "download", request).await?;
    let size = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.parse().ok())
        .ok_or("local API returned no valid Content-Length")?;
    save_download(response, output, size, path.to_owned()).await
}
