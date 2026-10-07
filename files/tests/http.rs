#![cfg(all(feature = "client", target_os = "linux"))]

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, StatusCode};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use portal_files::{FileService, FileServiceConfig};
use std::collections::HashSet;
use std::path::PathBuf;

struct TestDirectory(PathBuf);
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn client(source: &str) -> Client<HttpConnector, Full<Bytes>> {
    let mut connector = HttpConnector::new();
    connector.set_local_address(Some(source.parse().unwrap()));
    Client::builder(TokioExecutor::new()).build(connector)
}
fn request(url: &str, method: &str, body: &str) -> Request<Full<Bytes>> {
    Request::builder()
        .uri(url)
        .method(method)
        .header("Content-Type", "application/json")
        // Must not allow an unauthorized source to impersonate the authorized peer.
        .header("X-Forwarded-For", "127.0.0.1")
        .body(Full::new(Bytes::copy_from_slice(body.as_bytes())))
        .unwrap()
}

#[tokio::test]
#[ignore = "requires local TCP sockets"]
async fn http_download_negotiation_authorization_and_single_use() {
    let directory = TestDirectory(
        std::env::temp_dir().join(format!("portal-http-test-{:032x}", rand::random::<u128>())),
    );
    std::fs::create_dir(&directory.0).unwrap();
    let root = directory.0.join("share");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("hello.txt"), b"HTTP peer download\n").unwrap();
    let service = FileService::new(
        "127.0.0.1:0".parse().unwrap(),
        Some(FileServiceConfig {
            root,
            allowed_downloaders: HashSet::from(["127.0.0.1".parse().unwrap()]),
        }),
        None,
    )
    .await
    .unwrap();
    let address = service.http_addr();
    let origin = format!("http://{address}");
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(service.serve(async {
        let _ = stopped.await;
    }));
    let allowed = client("127.0.0.1");
    let denied = client("127.0.0.2");
    let url = format!("{origin}/v1/downloads");
    let response = denied
        .request(request(&url, "POST", r#"{"path":"hello.txt"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let response = allowed
        .request(request(&url, "POST", r#"{"path":"../hello.txt"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response = allowed
        .request(request(
            &url,
            "POST",
            r#"{"path":"hello.txt","peer":"127.0.0.1"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let response = allowed
        .request(request(
            &url,
            "POST",
            &format!(r#"{{"path":"{}"}}"#, "x".repeat(17000)),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let response = allowed
        .request(request(&url, "POST", r#"{"path":"hello.txt"}"#))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let ticket: portal_files::models::PrepareDownloadResponse =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(ticket.file_name, "hello.txt");
    assert_eq!(ticket.size_bytes, 19);
    let response = denied
        .request(request(&ticket.download_url, "GET", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = allowed
        .request(request(&ticket.download_url, "GET", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"HTTP peer download\n"
    );
    let response = allowed
        .request(request(&ticket.download_url, "GET", ""))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let output = directory.0.join("downloaded");
    portal_files::download(&origin, "hello.txt", &output)
        .await
        .unwrap();
    assert_eq!(std::fs::read(output).unwrap(), b"HTTP peer download\n");
    assert!(portal_files::list_shares(&origin).await.unwrap().is_empty());
    assert!(
        portal_files::prepare_smb_connection(&origin, "documents")
            .await
            .err()
            .unwrap()
            .contains("501")
    );
    drop(allowed);
    drop(denied);
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(7), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}
