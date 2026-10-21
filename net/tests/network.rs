use portal_net::{Net, Registry, Request, Response, Service};
use std::{sync::Arc, time::Duration};
use tokio::sync::Notify;

fn request(operation: &str) -> Request {
    Request {
        service: "test".into(),
        operation: operation.into(),
        payload: serde_json::json!({}),
    }
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn authenticated_quic_streams_and_peer_revocation() {
    let a = Net::new(&[1; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    let b = Net::new(&[2; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    a.upsert_peer(b.public_key(), Some(b.listen_addr().unwrap()), None)
        .unwrap();
    b.upsert_peer(a.public_key(), None, None).unwrap();
    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mut registry = Registry::default();
    let (entry, exit) = (entered.clone(), release.clone());
    registry
        .register(Service::new("test", move |peer, req| {
            let (entry, exit) = (entry.clone(), exit.clone());
            async move {
                if req.operation == "truncated" {
                    return Response::stream(
                        std::io::Cursor::new(vec![1, 2, 3]),
                        10,
                        "test.bin".into(),
                    );
                }
                if req.operation == "slow" {
                    entry.notify_one();
                    exit.notified().await;
                }
                Response::json(&serde_json::json!({"peer": portal_net::encode_key(&peer)})).unwrap()
            }
        }))
        .unwrap();
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
    let client = a.clone();
    let key = b.public_key();
    let slow = tokio::spawn(async move {
        client
            .request(key, request("slow"))
            .await
            .unwrap()
            .json::<serde_json::Value>()
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), entered.notified())
        .await
        .unwrap();
    let reply = tokio::time::timeout(
        Duration::from_secs(2),
        a.request(b.public_key(), request("fast")),
    )
    .await
    .unwrap()
    .unwrap()
    .json::<serde_json::Value>()
    .await
    .unwrap();
    assert_eq!(reply["peer"], portal_net::encode_key(&a.public_key()));
    release.notify_one();
    slow.await.unwrap().unwrap();
    let mut truncated = a
        .request(b.public_key(), request("truncated"))
        .await
        .unwrap();
    let mut bytes = Vec::new();
    assert!(
        tokio::io::AsyncReadExt::read_to_end(&mut truncated.body, &mut bytes)
            .await
            .is_err()
    );
    // A registered endpoint must not be accepted as a different registered key.
    let wrong = portal_net::public_key(&[3; 32]);
    a.upsert_peer(wrong, Some(b.listen_addr().unwrap()), None)
        .unwrap();
    assert!(a.request(wrong, request("fast")).await.is_err());
    // Server rejection: unknown client identity cannot use a trusted server.
    let outsider = Net::new(&[4; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    outsider
        .upsert_peer(b.public_key(), Some(b.listen_addr().unwrap()), None)
        .unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(10),
            outsider.request(b.public_key(), request("fast"))
        )
        .await
        .unwrap()
        .is_err()
    );
    // Removing a peer closes established sessions too.
    b.remove_peer(&a.public_key()).unwrap();
    assert!(
        tokio::time::timeout(
            Duration::from_secs(10),
            a.request(b.public_key(), request("fast"))
        )
        .await
        .unwrap()
        .is_err()
    );
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    a.shutdown().await;
    b.shutdown().await;
    outsider.shutdown().await;
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn quic_ipv6_and_oversized_frame() {
    let a = Net::new(&[11; 32], Some("[::1]:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    let b = Net::new(&[12; 32], Some("[::1]:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    a.upsert_peer(b.public_key(), Some(b.listen_addr().unwrap()), None)
        .unwrap();
    b.upsert_peer(a.public_key(), None, None).unwrap();
    let mut registry = Registry::default();
    registry
        .register(Service::new("test", |_, _| async {
            Response::json(&true).unwrap()
        }))
        .unwrap();
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
    assert!(
        a.request(b.public_key(), request("fast"))
            .await
            .unwrap()
            .json::<bool>()
            .await
            .unwrap()
    );
    let mut large = request("fast");
    large.payload = serde_json::json!("x".repeat(17000));
    assert!(a.request(b.public_key(), large).await.is_err());
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn concurrent_connection_attempts_share_the_queue_and_handshake_budget() {
    // An open socket that never replies makes the handshake time out predictably.
    let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = Net::new(&[31; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    let key = portal_net::public_key(&[32; 32]);
    client
        .upsert_peer(key, Some(blackhole.local_addr().unwrap()), None)
        .unwrap();

    let net = client.clone();
    let first = tokio::spawn(async move { net.request(key, request("fast")).await });
    let mut packet = [0; 2048];
    tokio::time::timeout(Duration::from_secs(2), blackhole.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap();

    let mut queued = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let net = client.clone();
        queued.spawn(async move { net.request(key, request("fast")).await });
    }
    tokio::time::timeout(Duration::from_secs(13), async {
        // Release the lock halfway through the queued attempts' budgets. Their
        // handshakes must get only the remaining time, not a fresh ten seconds.
        tokio::time::sleep(Duration::from_secs(5)).await;
        first.abort();
        assert!(
            first
                .await
                .err()
                .expect("attempt must be cancelled")
                .is_cancelled()
        );
        while let Some(result) = queued.join_next().await {
            let error = result.unwrap().err().expect("blackhole must not respond");
            assert!(error.contains("timed out"), "unexpected error: {error}");
        }
    })
    .await
    .expect("queued connection attempts exceeded their shared ten-second budgets");
    client.shutdown().await;
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn service_timeout_returns_504_and_keeps_the_connection_usable() {
    let a = Net::new(&[33; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    let b = Net::new(&[34; 32], Some("127.0.0.1:0".parse().unwrap()), Vec::new())
        .await
        .unwrap();
    a.upsert_peer(b.public_key(), Some(b.listen_addr().unwrap()), None)
        .unwrap();
    b.upsert_peer(a.public_key(), None, None).unwrap();
    let mut registry = Registry::default();
    registry
        .register(Service::new("test", |_, req| async move {
            if req.operation == "stall" {
                std::future::pending::<()>().await;
            }
            Response::json(&true).unwrap()
        }))
        .unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let net = b.clone();
    let server = tokio::spawn(async move {
        net.serve_with_ready(
            registry,
            async {
                let _ = stopped.await;
            },
            move || {
                let _ = ready.send(());
            },
        )
        .await
    });
    started.await.unwrap();

    let mut response = tokio::time::timeout(
        Duration::from_secs(40),
        a.request(b.public_key(), request("stall")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.header.status, 504);
    let mut body = Vec::new();
    tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read_to_end(&mut response.body, &mut body),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"error": "service timed out"})
    );
    assert!(
        a.request(b.public_key(), request("fast"))
            .await
            .unwrap()
            .json::<bool>()
            .await
            .unwrap()
    );
    assert_eq!(a.stats(Some(&b.public_key())).unwrap().0, 1);

    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    a.shutdown().await;
    b.shutdown().await;
}
