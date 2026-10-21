use portal_net::{Net, Registry, RelayServerConfig, Request, Response, Service};
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[test]
fn relay_configuration_requires_public_addresses_or_explicit_loopback() {
    for endpoint in [
        "0.0.0.0:40000",
        "10.0.0.1:40000",
        "100.64.0.1:40000",
        "192.168.1.1:40000",
        "203.0.113.1:40000",
        "[::1]:40000",
        "[fd00::1]:40000",
    ] {
        let config = RelayServerConfig {
            listen: "0.0.0.0:40000".parse().unwrap(),
            public_endpoint: endpoint.parse().unwrap(),
            allowed_peers: Default::default(),
        };
        assert!(config.validate().is_err(), "accepted {endpoint}");
    }
    for endpoint in ["8.8.8.8:40000", "[2001:4860:4860::8888]:40000"] {
        assert!(
            RelayServerConfig {
                listen: "0.0.0.0:40000".parse().unwrap(),
                public_endpoint: endpoint.parse().unwrap(),
                allowed_peers: Default::default()
            }
            .validate()
            .is_ok()
        );
    }
    let loopback = "127.0.0.1:40000".parse().unwrap();
    assert!(
        RelayServerConfig {
            listen: loopback,
            public_endpoint: loopback,
            allowed_peers: Default::default()
        }
        .validate()
        .is_ok()
    );
    assert!(
        serde_json::from_value::<portal_net::RelayPeer>(serde_json::json!(
            "https://relay.example.com"
        ))
        .is_err()
    );
}

#[tokio::test]
#[ignore = "requires local TCP sockets"]
async fn relay_only_streaming_authentication_reload_and_revocation() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let listen = socket.local_addr().unwrap();
    drop(socket);
    let relay = Net::with_relay_server(
        &[50; 32],
        None,
        Vec::new(),
        Some(RelayServerConfig {
            listen,
            public_endpoint: listen,
            allowed_peers: [
                portal_net::public_key(&[51; 32]),
                portal_net::public_key(&[52; 32]),
            ]
            .into_iter()
            .collect(),
        }),
    )
    .await
    .unwrap();
    let url = relay.relay_server().unwrap();
    // Neither endpoint has an IP transport: every application packet must cross the relay.
    let a = Net::new(&[51; 32], None, vec![url.clone()]).await.unwrap();
    let b = Net::new(&[52; 32], None, vec![url.clone()]).await.unwrap();
    let outsider = Net::new(&[53; 32], None, vec![url.clone()]).await.unwrap();
    assert!(a.listen_addr().is_none());
    assert!(b.listen_addr().is_none());
    a.upsert_peer(b.public_key(), None, None).unwrap();
    b.upsert_peer(a.public_key(), None, None).unwrap();
    outsider
        .upsert_peer(b.public_key(), None, Some(url))
        .unwrap();

    let payload = vec![37; 300_000];
    for generation in 0..2 {
        let mut registry = Registry::default();
        let body = payload.clone();
        registry
            .register(Service::new("test", move |_, _| {
                let body = body.clone();
                async move {
                    let length = body.len() as u64;
                    Response::stream(std::io::Cursor::new(body), length, "relay.bin".into())
                }
            }))
            .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let (ready, started) = tokio::sync::oneshot::channel();
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
        let request = || Request {
            service: "test".into(),
            operation: "download".into(),
            payload: serde_json::json!({}),
        };
        tokio::time::timeout(Duration::from_secs(20), async {
            let mut response = a
                .request(b.public_key(), request())
                .await
                .unwrap_or_else(|e| panic!("generation {generation}: {e}"));
            assert_eq!(response.header.status, 200);
            let mut downloaded = Vec::new();
            response.body.read_to_end(&mut downloaded).await.unwrap();
            assert_eq!(downloaded, payload);
            assert_eq!(a.peer_path(&b.public_key()).unwrap(), "relay");
            assert!(outsider.request(b.public_key(), request()).await.is_err());
            // A repeated configuration keeps the established session.
            a.upsert_peer(b.public_key(), None, None).unwrap();
            assert_eq!(a.stats(Some(&b.public_key())).unwrap().0, 1);
            if generation == 1 {
                b.remove_peer(&a.public_key()).unwrap();
                assert!(a.request(b.public_key(), request()).await.is_err());
            }
        })
        .await
        .unwrap();
        stop.send(()).unwrap();
        server.await.unwrap().unwrap();
        // Stopping the host sends CONNECTION_CLOSE through the relay. Wait until
        // the remote observes it before testing replacement of its cached connection.
        tokio::time::timeout(Duration::from_secs(5), async {
            while a.stats(Some(&b.public_key())).unwrap().0 != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
    a.shutdown().await;
    b.shutdown().await;
    outsider.shutdown().await;
    relay.shutdown().await;
}

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn direct_path_is_preferred_and_survives_relay_revocation() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let listen = socket.local_addr().unwrap();
    drop(socket);
    let a_key = portal_net::public_key(&[61; 32]);
    let b_key = portal_net::public_key(&[62; 32]);
    let relay = Net::with_relay_server(
        &[60; 32],
        None,
        Vec::new(),
        Some(RelayServerConfig {
            listen,
            public_endpoint: listen,
            allowed_peers: [a_key, b_key].into_iter().collect(),
        }),
    )
    .await
    .unwrap();
    let via = relay.relay_server().unwrap();
    let a = Net::new(
        &[61; 32],
        Some("127.0.0.1:0".parse().unwrap()),
        vec![via.clone()],
    )
    .await
    .unwrap();
    let b = Net::new(&[62; 32], Some("127.0.0.1:0".parse().unwrap()), vec![via])
        .await
        .unwrap();
    a.upsert_peer(b_key, b.listen_addr(), None).unwrap();
    b.upsert_peer(a_key, a.listen_addr(), None).unwrap();
    let mut registry = Registry::default();
    registry
        .register(Service::new("test", |_, _| async {
            Response::json(&serde_json::json!({"ok":true})).unwrap()
        }))
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn({
        let b = b.clone();
        async move {
            b.serve(registry, async {
                let _ = stopped.await;
            })
            .await
        }
    });
    let request = || Request {
        service: "test".into(),
        operation: "ping".into(),
        payload: serde_json::json!({}),
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        a.request(b_key, request()).await.unwrap().header.status,
        200
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        while a.peer_path(&b_key).unwrap() != "direct" {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    relay.set_relay_allowed(a_key, false).unwrap();
    assert_eq!(
        a.request(b_key, request()).await.unwrap().header.status,
        200
    );
    assert_eq!(a.peer_path(&b_key).unwrap(), "direct");
    stop.send(()).unwrap();
    server.await.unwrap().unwrap();
    a.shutdown().await;
    b.shutdown().await;
    relay.shutdown().await;
}
