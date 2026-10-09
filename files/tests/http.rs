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
        FileServiceConfig {
            root: root.clone(),
            allowed_downloaders: HashSet::from(["127.0.0.1".parse().unwrap()]),
        },
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
    let resources = portal_files::list_resources(&origin).await.unwrap();
    assert_eq!(resources.resources.len(), 1);
    assert!(resources.resources[0].read_only);
    let page = portal_files::list_directory(
        &origin,
        &portal_files::models::ListDirectoryRequest {
            path: String::new(),
            offset: 0,
            limit: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].name, "hello.txt");
    assert_eq!(page.entries[0].kind, portal_files::models::FileKind::File);
    let metadata = portal_files::file_metadata(&origin, "hello.txt")
        .await
        .unwrap();
    assert_eq!(metadata.size_bytes, Some(19));
    let response = denied
        .request(request(&format!("{origin}/v1/resources"), "GET", ""))
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let resources: portal_files::models::ListResourcesResponse =
        serde_json::from_slice(&body).unwrap();
    assert!(resources.resources.is_empty());
    let response = denied
        .request(request(
            &format!("{origin}/v1/files/list"),
            "POST",
            r#"{"path":""}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = allowed
        .request(request(
            &format!("{origin}/v1/files/metadata"),
            "POST",
            r#"{"path":"../hello.txt"}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let response =
        portal_files::proxy_request(address, "list", br#"{"path":"","limit":100,"offset":0}"#)
            .await
            .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = portal_files::proxy_request(address, "download", br#"{"path":"hello.txt"}"#)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "application/octet-stream"
    );
    assert!(
        response.headers()["content-disposition"]
            .to_str()
            .unwrap()
            .starts_with("attachment;")
    );
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        b"HTTP peer download\n"
    );
    let response = portal_files::proxy_request(address, "metadata", br#"{"path":"missing"}"#)
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    // Pagination, UTF-8 paths, and confinement are shared by direct and web-proxy clients.
    std::fs::create_dir(root.join("alpha")).unwrap();
    std::fs::write(root.join("пример.txt"), b"unicode filename").unwrap();
    let outside = directory.0.join("outside.txt");
    std::fs::write(&outside, b"private").unwrap();
    std::os::unix::fs::symlink(&outside, root.join("outside")).unwrap();
    let first = portal_files::list_directory(
        &origin,
        &portal_files::models::ListDirectoryRequest {
            path: String::new(),
            offset: 0,
            limit: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(first.next_offset, Some(2));
    assert_eq!(
        first.entries[0].kind,
        portal_files::models::FileKind::Directory
    );
    let second = portal_files::list_directory(
        &origin,
        &portal_files::models::ListDirectoryRequest {
            path: String::new(),
            offset: first.next_offset.unwrap(),
            limit: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(second.next_offset, None);
    assert_eq!(
        second.entries[0].kind,
        portal_files::models::FileKind::Symlink
    );
    assert_eq!(second.entries[1].name, "пример.txt");
    for route in ["/v1/files/metadata", "/v1/files/list", "/v1/downloads"] {
        let response = allowed
            .request(request(
                &format!("{origin}{route}"),
                "POST",
                r#"{"path":"outside"}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let big = vec![42u8; 300000];
    std::fs::write(root.join("big.bin"), &big).unwrap();
    let response = portal_files::proxy_request(address, "download", br#"{"path":"big.bin"}"#)
        .await
        .unwrap();
    assert_eq!(
        &response.into_body().collect().await.unwrap().to_bytes()[..],
        &big[..]
    );
    let response = allowed
        .request(request(
            &format!("{origin}/v1/files/list"),
            "POST",
            r#"{"path":"","limit":0}"#,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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
