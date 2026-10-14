use super::*;

#[tokio::test]
#[ignore = "requires local UDP sockets"]
async fn peer_update_cannot_adopt_an_old_handshake() {
    let a = Net::new(&[41; 32], "127.0.0.1:0".parse().unwrap()).unwrap();
    let b = Net::new(&[42; 32], "127.0.0.1:0".parse().unwrap()).unwrap();
    let key = b.public_key();
    a.upsert_peer(key, Some(b.listen_addr())).unwrap();
    b.upsert_peer(a.public_key(), None).unwrap();
    b.inner
        .endpoint
        .set_server_config(Some(b.inner.server.clone()));

    let old_peer = a.inner.peers.read().unwrap().get(&key).unwrap().clone();
    let config = tls::client(
        a.inner.cert.clone(),
        a.inner.key.clone_key(),
        key,
        a.inner.peers.clone(),
    )
    .unwrap();
    let outgoing = a
        .inner
        .endpoint
        .connect_with(config, b.listen_addr(), "portal")
        .unwrap();
    let (connection, incoming) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(outgoing, async {
            b.inner.endpoint.accept().await.unwrap().await
        })
    })
    .await
    .unwrap();
    let connection = connection.unwrap();
    let _incoming = incoming.unwrap();

    // Force the update between handshake completion and connection registration.
    a.upsert_peer(key, None).unwrap();
    assert_eq!(
        a.track(key, connection.clone(), Some(&old_peer))
            .unwrap_err(),
        "peer changed during handshake"
    );
    assert_eq!(a.stats(Some(&key)).unwrap().0, 0);
    connection.close(0u32.into(), b"stale handshake");

    // The opposite ordering must let the update close an already registered session.
    a.upsert_peer(key, Some(b.listen_addr())).unwrap();
    let (connection, incoming) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(a.connect(key), async {
            b.inner.endpoint.accept().await.unwrap().await
        })
    })
    .await
    .unwrap();
    let connection = connection.unwrap();
    let _incoming = incoming.unwrap();
    assert_eq!(a.stats(Some(&key)).unwrap().0, 1);
    a.upsert_peer(key, None).unwrap();
    assert!(connection.close_reason().is_some());
    assert_eq!(a.stats(Some(&key)).unwrap().0, 0);

    a.shutdown();
    b.shutdown();
}
