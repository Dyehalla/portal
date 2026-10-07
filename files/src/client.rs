use std::future::Future;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::{BodyExt, Full};
use hyper::{Request as HttpRequest, StatusCode, Uri, header};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use tokio::io::AsyncWriteExt;

use crate::models::{PrepareDownloadRequest, PrepareDownloadResponse};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
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
            if received_bytes > response.size_bytes {
                return Err("HTTP file body exceeded the size announced over HTTP".into());
            }
            file.write_all(&chunk).await.map_err(|error| {
                format!("could not write {}: {error}", temporary_path.display())
            })?;
        }
        if received_bytes != response.size_bytes {
            return Err(format!(
                "incomplete download: received {received_bytes} of {} bytes",
                response.size_bytes
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
        response.file_name,
        response.size_bytes,
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

type HttpClient = Client<HttpConnector, Full<Bytes>>;
fn http_client() -> HttpClient {
    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(CONNECT_TIMEOUT));
    Client::builder(TokioExecutor::new()).build(connector)
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
                    if bytes.len() + chunk.len() > 64 * 1024 {
                        return Err("peer JSON response exceeds 64 KiB".into());
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

/// Discover only the SMB shares that this tunnel peer is allowed to access.
pub async fn list_shares(peer_url: &str) -> Result<Vec<crate::models::SmbShare>, String> {
    let response: crate::models::ListSharesResponse =
        json_request::<_, ()>(peer_url, "/v1/shares", None).await?;
    Ok(response.shares)
}

/// Keep credentials out of Debug output and clear the client copy on drop.
pub struct SmbConnection {
    pub share: crate::models::SmbShare,
    pub username: String,
    pub password: zeroize::Zeroizing<String>,
}

/// Authorize a share and obtain its native SMB connection parameters over the tunnel.
pub async fn prepare_smb_connection(
    peer_url: &str,
    share_name: &str,
) -> Result<SmbConnection, String> {
    let response: crate::models::PrepareSmbConnectionResponse = json_request(
        peer_url,
        "/v1/smb/connections",
        Some(&crate::models::PrepareSmbConnectionRequest {
            share_name: share_name.to_owned(),
        }),
    )
    .await?;
    let password = zeroize::Zeroizing::new(response.password);
    let share = response.share;
    let endpoint = peer_url.parse::<Uri>().map_err(|_| "invalid HTTP URL")?;
    let host = share
        .host
        .parse::<std::net::IpAddr>()
        .map_err(|_| "invalid SMB host")?;
    let peer_host = endpoint
        .host()
        .ok_or("HTTP URL has no host")?
        .trim_matches(['[', ']']);
    if peer_host.parse::<std::net::IpAddr>().ok() != Some(host) {
        return Err("SMB host must match the requested peer's HTTP IP".into());
    }
    if share.name != share_name
        || share.port == 0
        || share.port > u32::from(u16::MAX)
        || !share
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        || response.username.is_empty()
        || response.username.len() > 64
        || !response
            .username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c))
        || password.is_empty()
        || password.chars().any(|c| c.is_control())
    {
        return Err("file service returned invalid SMB connection parameters".into());
    }
    Ok(SmbConnection {
        share,
        username: response.username,
        password,
    })
}

/// Open an interactive SMB client after negotiating credentials with the peer.
pub async fn open_smb(peer_url: &str, share_name: &str) -> Result<(), String> {
    let connection = prepare_smb_connection(peer_url, share_name).await?;
    crate::platform::open_smb(connection).await
}
