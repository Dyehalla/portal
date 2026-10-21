use portal_files::{FileService, FileServiceConfig};
use portal_net::{Net, Registry, Request};
use std::{collections::HashSet, time::Duration};
use tokio::io::AsyncReadExt;

fn request(operation: &str, payload: serde_json::Value) -> Request {
    Request {
        service: "files".into(),
        operation: operation.into(),
        payload,
    }
}
#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn native_quic_files_streaming_and_key_authorization() {
    let root =
        std::env::temp_dir().join(format!("portal-quic-files-{:032x}", rand::random::<u128>()));
    std::fs::create_dir(&root).unwrap();
    let share = root.join("share");
    std::fs::create_dir(&share).unwrap();
    let payload = vec![42; 300000];
    std::fs::write(share.join("пример.bin"), &payload).unwrap();
    std::fs::write(root.join("outside"), b"private").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(root.join("outside"), share.join("escape")).unwrap();
    let a = Net::new(&[1; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    let b = Net::new(&[2; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    let c = Net::new(&[3; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    for net in [&a, &c] {
        net.upsert_peer(b.public_key(), Some(b.listen_addr().unwrap()), None)
            .unwrap();
        b.upsert_peer(net.public_key(), None, None).unwrap();
    }
    let file_service = FileService::new(FileServiceConfig {
        root: share,
        allowed_downloaders: HashSet::from([a.public_key()]),
    })
    .await
    .unwrap();
    let mut registry = Registry::default();
    registry.register(file_service.service()).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server_net = b.clone();
    let server = tokio::spawn(async move {
        server_net
            .serve(registry, async {
                let _ = stopped.await;
            })
            .await
    });
    tokio::task::yield_now().await;
    tokio::time::timeout(Duration::from_secs(20), async {
        let resources: portal_files::models::ListResourcesResponse = a.request(b.public_key(), request("resources", serde_json::json!({}))).await.unwrap().json().await.unwrap();
        assert_eq!(resources.resources.len(), 1);
        let denied: portal_files::models::ListResourcesResponse = c.request(b.public_key(), request("resources", serde_json::json!({}))).await.unwrap().json().await.unwrap();
        assert!(denied.resources.is_empty());
        let denied = c.request(b.public_key(), request("download", serde_json::json!({"path":"пример.bin"}))).await.unwrap();
        assert_eq!(denied.header.status, 403);
        let listing: portal_files::models::ListDirectoryResponse = a.request(b.public_key(), request("list", serde_json::json!({"path":"", "limit":1}))).await.unwrap().json().await.unwrap();
        assert_eq!(listing.entries.len(), 1);
        for path in ["../outside", "/etc/passwd"] {
            let response = a.request(b.public_key(), request("download", serde_json::json!({"path":path}))).await.unwrap(); assert_eq!(response.header.status, 400);
        }
        #[cfg(unix)] {
            let response = a.request(b.public_key(), request("download", serde_json::json!({"path":"escape"}))).await.unwrap(); assert_eq!(response.header.status, 403);
        }
        let response = a.request(b.public_key(), request("download", serde_json::json!({"path":"пример.bin", "peer":portal_net::encode_key(&a.public_key())}))).await.unwrap(); assert_eq!(response.header.status, 400);
        let mut response = a.request(b.public_key(), request("download", serde_json::json!({"path":"пример.bin"}))).await.unwrap();
        assert_eq!(response.header.length, payload.len() as u64);
        assert_eq!(response.header.file_name.as_deref(), Some("пример.bin"));
        let mut downloaded = Vec::new(); response.body.read_to_end(&mut downloaded).await.unwrap(); assert_eq!(downloaded, payload);
        let response = a.request(b.public_key(), request("list", serde_json::json!({"limit":0}))).await.unwrap(); assert_eq!(response.header.status, 400);
    }).await.unwrap();
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    a.shutdown().await;
    b.shutdown().await;
    c.shutdown().await;
    std::fs::remove_dir_all(root).unwrap();
}
