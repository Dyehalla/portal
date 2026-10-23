use crate::{Coordinator, config::Config};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use std::{fs, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    time::timeout,
};
use tower::ServiceExt;

struct Fixture {
    directory: TempDir,
    config: Config,
    certificate: rustls::pki_types::CertificateDer<'static>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = directory.path().join("cert.pem");
        let key_path = directory.path().join("key.pem");
        fs::write(&cert_path, certified.cert.pem()).unwrap();
        fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();
        let config: Config = serde_json::from_value(json!({
            "listen":"127.0.0.1:0",
            "state_dir": directory.path().join("state"),
            "tls": {"cert_file":cert_path, "key_file":key_path}
        }))
        .unwrap();
        Self {
            directory,
            config,
            certificate: certified.cert.der().clone(),
        }
    }

    async fn open(&self) -> Coordinator {
        Coordinator::open(self.config.clone()).await.unwrap()
    }

    fn admin_token(&self) -> String {
        fs::read_to_string(self.config.state_dir.join("admin.token"))
            .unwrap()
            .trim()
            .to_owned()
    }
}

async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Value,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let body = if body.is_null() {
        Body::empty()
    } else {
        builder = builder.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&body).unwrap())
    };
    let response = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    assert_eq!(response.headers()["cache-control"], "no-store");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4 * 1024 * 1024)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()))
    };
    (status, value)
}

async fn user(app: &Router, name: &str) -> Value {
    let (status, body) = request(app, "POST", "/api/v1/users", None, json!({"name":name})).await;
    assert_eq!(status, StatusCode::CREATED);
    body
}

fn token(value: &Value) -> &str {
    value["access_token"].as_str().unwrap()
}
fn id(value: &Value) -> &str {
    value["device"]["id"].as_str().unwrap()
}

async fn device(app: &Router, owner_token: &str, key_seed: u8) -> Value {
    let key = x25519_dalek::x25519([key_seed; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
    let key: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let (status, body) = request(
        app,
        "POST",
        "/api/v1/devices",
        Some(owner_token),
        json!({"name":format!("device-{key_seed}"),"public_key":key}),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    body
}

async fn map(app: &Router, device: &Value) -> Value {
    let (status, body) = request(
        app,
        "GET",
        "/api/v1/network-map",
        Some(token(device)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body
}

fn tcp_permissions(source: &Value, ports: &[u16]) -> Value {
    json!({(source["device"]["public_key"].as_str().unwrap()): {"tcp": ports}})
}

async fn publish(
    app: &Router,
    target: &Value,
    base_revision: u64,
    permissions: Value,
) -> (StatusCode, Value) {
    request(
        app,
        "PUT",
        "/api/v1/device/policy",
        Some(token(target)),
        json!({"base_revision":base_revision,"permissions":permissions}),
    )
    .await
}

fn poll_uri(map: &Value, seconds: u64) -> String {
    format!(
        "/api/v1/network-map?after={}&generation={}&wait_seconds={seconds}",
        map["revision"],
        map["generation"].as_str().unwrap()
    )
}

async fn pending_poll(
    app: &Router,
    device: &Value,
    snapshot: &Value,
) -> tokio::task::JoinHandle<(StatusCode, Value)> {
    let app = app.clone();
    let credential = token(device).to_owned();
    let uri = poll_uri(snapshot, 25);
    let mut task =
        tokio::spawn(
            async move { request(&app, "GET", &uri, Some(&credential), Value::Null).await },
        );
    assert!(
        timeout(Duration::from_millis(80), &mut task).await.is_err(),
        "unchanged map must wait"
    );
    task
}

#[tokio::test]
async fn bootstrap_admin_is_persistent_and_has_no_access_to_foreign_devices() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let admin = fixture.admin_token();
    let (status, initial_admin) =
        request(&app, "GET", "/api/v1/me", Some(&admin), Value::Null).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(initial_admin["name"], "admin");
    assert_eq!(initial_admin["is_admin"], true);
    let (status, _) = request(&app, "POST", "/api/v1/users", None, json!({"name":"ADMIN"})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    let alice = user(&app, "alice").await;
    assert_eq!(alice["user"]["is_admin"], false);
    let alice_device = device(&app, token(&alice), 1).await;
    let admin_device = device(&app, &admin, 2).await;
    assert!(
        map(&app, &admin_device).await["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/v1/devices/{}", id(&alice_device)),
        Some(&admin),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let before = map(&app, &alice_device).await;
    assert!(
        Coordinator::open(fixture.config.clone()).await.is_err(),
        "state directory must have a single writer"
    );
    drop(app);
    drop(coordinator);
    let reopened = fixture.open().await;
    assert_eq!(fixture.admin_token(), admin);
    let app = reopened.test_router();
    let (_, restored_admin) = request(&app, "GET", "/api/v1/me", Some(&admin), Value::Null).await;
    assert_eq!(initial_admin, restored_admin);
    let after = map(&app, &alice_device).await;
    for field in [
        "network_id",
        "generation",
        "revision",
        "device",
        "policy",
        "peers",
    ] {
        assert_eq!(before[field], after[field], "persistent field {field}");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&fixture.config.state_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        for path in ["admin.token", "network.sqlite3"] {
            assert_eq!(
                fs::metadata(fixture.config.state_dir.join(path))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
}

#[tokio::test]
async fn permissions_are_explicit_per_source_and_destination_without_owner_inheritance() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let bob = user(&app, "bob").await;
    let a1 = device(&app, token(&alice), 3).await;
    let a2 = device(&app, token(&alice), 4).await;
    let server = device(&app, token(&bob), 5).await;
    let phone = device(&app, token(&bob), 6).await;
    for d in [&a1, &a2, &server, &phone] {
        assert!(map(&app, d).await["peers"].as_array().unwrap().is_empty());
    }
    let (status, policy) = publish(&app, &server, 0, tcp_permissions(&a1, &[443, 80, 80])).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(policy["revision"], 1);
    let key = a1["device"]["public_key"].as_str().unwrap();
    assert_eq!(policy["permissions"][key]["tcp"], json!([80, 443]));
    let a_map = map(&app, &a1).await;
    assert_eq!(a_map["protocol_version"], 2);
    assert_eq!(a_map["peers"].as_array().unwrap().len(), 1);
    assert_eq!(a_map["peers"][0]["device"]["id"], id(&server));
    assert_eq!(a_map["peers"][0]["incoming"]["tcp"], json!([]));
    assert_eq!(a_map["peers"][0]["outgoing"]["tcp"], json!([80, 443]));
    assert!(a_map["peers"][0].get("allow_same_owner").is_none());
    let b_map = map(&app, &server).await;
    assert_eq!(b_map["peers"].as_array().unwrap().len(), 1);
    assert_eq!(b_map["peers"][0]["device"]["id"], id(&a1));
    assert_eq!(b_map["peers"][0]["incoming"]["tcp"], json!([80, 443]));
    assert_eq!(b_map["peers"][0]["outgoing"]["tcp"], json!([]));
    assert!(map(&app, &a2).await["peers"].as_array().unwrap().is_empty());
    assert!(
        map(&app, &phone).await["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let a3 = device(&app, token(&alice), 7).await;
    assert!(map(&app, &a3).await["peers"].as_array().unwrap().is_empty());
    assert_eq!(
        map(&app, &server).await["peers"].as_array().unwrap().len(),
        1
    );

    // A UI bulk action is a snapshot of concrete keys; ports can differ for each key.
    let mut copied = tcp_permissions(&a1, &[80, 443]);
    copied
        .as_object_mut()
        .unwrap()
        .extend(tcp_permissions(&a2, &[22]).as_object().unwrap().clone());
    assert_eq!(
        publish(&app, &server, 1, copied.clone()).await.0,
        StatusCode::OK
    );
    let b_map = map(&app, &server).await;
    assert_eq!(b_map["peers"].as_array().unwrap().len(), 2);
    assert_eq!(
        map(&app, &a2).await["peers"][0]["outgoing"]["tcp"],
        json!([22])
    );
    assert!(map(&app, &a3).await["peers"].as_array().unwrap().is_empty());
    let unchanged = publish(&app, &server, 2, copied).await;
    assert_eq!(unchanged.1["revision"], 2);
    assert_eq!(map(&app, &server).await["revision"], b_map["revision"]);
    assert_eq!(
        publish(&app, &server, 1, json!({})).await.0,
        StatusCode::CONFLICT
    );
    let poll = pending_poll(&app, &a1, &map(&app, &a1).await).await;
    assert_eq!(
        publish(&app, &server, 2, tcp_permissions(&a2, &[22]))
            .await
            .0,
        StatusCode::OK
    );
    let (status, withdrawn) = timeout(Duration::from_secs(2), poll)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert!(withdrawn["peers"].as_array().unwrap().is_empty());
    assert_eq!(
        map(&app, &a2).await["peers"][0]["outgoing"]["tcp"],
        json!([22])
    );
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/v1/devices/{}", id(&a2)),
            Some(token(&alice)),
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert!(
        map(&app, &server).await["peers"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn long_poll_observes_updates_revocation_and_cancellation() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let a1 = device(&app, token(&alice), 8).await;
    let a2 = device(&app, token(&alice), 9).await;
    assert_eq!(
        publish(&app, &a2, 0, tcp_permissions(&a1, &[22])).await.0,
        StatusCode::OK
    );
    let current = map(&app, &a1).await;
    let poll = pending_poll(&app, &a1, &current).await;
    let (status, _) = request(
        &app,
        "PUT",
        "/api/v1/device/endpoints",
        Some(token(&a2)),
        json!({"endpoints":["198.51.100.1:51820"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, updated) = timeout(Duration::from_secs(2), poll)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert!(updated["revision"].as_u64().unwrap() > current["revision"].as_u64().unwrap());
    assert_eq!(
        updated["peers"][0]["device"]["endpoints"][0],
        "198.51.100.1:51820"
    );
    let poll = pending_poll(&app, &a1, &updated).await;
    let (status, _) = request(
        &app,
        "GET",
        &poll_uri(&updated, 25),
        Some(token(&a1)),
        Value::Null,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "one pending poll per token"
    );
    poll.abort();
    let _ = poll.await;
    let poll = pending_poll(&app, &a1, &updated).await;
    let (status, _) = request(
        &app,
        "DELETE",
        &format!("/api/v1/devices/{}", id(&a1)),
        Some(token(&alice)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = timeout(Duration::from_secs(2), poll)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(map(&app, &a2).await["peers"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn unchanged_map_renews_lease_and_wrong_cursor_resynchronizes() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let a = device(&app, token(&alice), 10).await;
    let before = map(&app, &a).await;
    let (status, after) = timeout(
        Duration::from_secs(3),
        request(
            &app,
            "GET",
            &poll_uri(&before, 1),
            Some(token(&a)),
            Value::Null,
        ),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(before["revision"], after["revision"]);
    assert!(after["expires_at"].as_u64().unwrap() > before["expires_at"].as_u64().unwrap());
    for uri in [
        "/api/v1/network-map?after=999999&generation=other",
        "/api/v1/network-map?after=0",
    ] {
        let (status, snapshot) = timeout(
            Duration::from_millis(500),
            request(&app, "GET", uri, Some(token(&a)), Value::Null),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(snapshot["revision"], after["revision"]);
    }
}

#[tokio::test]
async fn authentication_and_validation_do_not_allow_foreign_mutations() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let bob = user(&app, "bob").await;
    let a = device(&app, token(&alice), 11).await;
    let b = device(&app, token(&bob), 12).await;
    let before = map(&app, &a).await;
    let cases = [
        (
            "GET",
            "/api/v1/me".to_owned(),
            Some(token(&a)),
            Value::Null,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "GET",
            "/api/v1/network-map".to_owned(),
            Some(token(&alice)),
            Value::Null,
            StatusCode::UNAUTHORIZED,
        ),
        (
            "PUT",
            "/api/v1/device/policy".to_owned(),
            Some(token(&alice)),
            json!({"base_revision":0,"permissions":{}}),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "DELETE",
            format!("/api/v1/devices/{}", id(&b)),
            Some(token(&alice)),
            Value::Null,
            StatusCode::NOT_FOUND,
        ),
        (
            "POST",
            format!("/api/v1/devices/{}/token", id(&b)),
            Some(token(&alice)),
            Value::Null,
            StatusCode::NOT_FOUND,
        ),
        (
            "PUT",
            "/api/v1/device/endpoints".to_owned(),
            Some(token(&a)),
            json!({"endpoints":["0.0.0.0:0"]}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "PUT",
            "/api/v1/device/policy".to_owned(),
            Some(token(&a)),
            json!({"base_revision":0,"permissions":tcp_permissions(&b, &[0])}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "PUT",
            "/api/v1/device/policy".to_owned(),
            Some(token(&a)),
            json!({"base_revision":0,"permissions":{"unknown":{"tcp":[80]}}}),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "/api/v1/devices".to_owned(),
            Some(token(&alice)),
            json!({"name":"forged","public_key":a["device"]["public_key"],"owner_user_id":bob["user"]["id"]}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "POST",
            "/api/v1/users".to_owned(),
            None,
            json!({"name":"evil","is_admin":true}),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "GET",
            "/api/v1/me".to_owned(),
            None,
            Value::Null,
            StatusCode::UNAUTHORIZED,
        ),
    ];
    for (method, uri, credential, body, expected) in cases {
        let (status, _) = request(&app, method, &uri, credential, body).await;
        assert_eq!(status, expected, "{method} {uri}");
    }
    for key in ["00".repeat(32), "ff".repeat(32), "not-a-key".into()] {
        let (status, _) = request(
            &app,
            "POST",
            "/api/v1/devices",
            Some(token(&alice)),
            json!({"name":"invalid","public_key":key}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/devices",
        Some(token(&alice)),
        json!({"name":"duplicate","public_key":a["device"]["public_key"]}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, _) = request(
        &app,
        "POST",
        "/api/v1/users",
        None,
        json!({"name":"x".repeat(65536)}),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(before["revision"], map(&app, &a).await["revision"]);
    let (status, found) = request(
        &app,
        "GET",
        "/api/v1/users?name=BOB",
        Some(token(&alice)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(found["id"], bob["user"]["id"]);
}

#[tokio::test]
async fn token_rotation_invalidates_waiters_and_preserves_device_identity() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let a = device(&app, token(&alice), 13).await;
    let current = map(&app, &a).await;
    let poll = pending_poll(&app, &a, &current).await;
    let (status, new_token) = request(
        &app,
        "POST",
        &format!("/api/v1/devices/{}/token", id(&a)),
        Some(token(&alice)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        timeout(Duration::from_secs(2), poll)
            .await
            .unwrap()
            .unwrap()
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        request(&app, "GET", "/api/v1/device", Some(token(&a)), Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, restored) = request(
        &app,
        "GET",
        "/api/v1/device",
        Some(token(&new_token)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(restored, a["device"]);
}

#[tokio::test]
async fn pool_exhaustion_rolls_back_and_configuration_changes_are_rejected() {
    let mut fixture = Fixture::new();
    fixture.config.ipv4_network = "10.77.0.0/30".parse().unwrap();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let a = device(&app, token(&alice), 14).await;
    let b = device(&app, token(&alice), 15).await;
    assert_ne!(a["device"]["ipv4"], b["device"]["ipv4"]);
    assert_ne!(a["device"]["ipv6"], b["device"]["ipv6"]);
    let before = map(&app, &a).await;
    let key = x25519_dalek::x25519([16; 32], x25519_dalek::X25519_BASEPOINT_BYTES);
    let key: String = key.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/devices",
            Some(token(&alice)),
            json!({"name":"overflow","public_key":key})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(before["revision"], map(&app, &a).await["revision"]);
    drop(app);
    drop(coordinator);
    fixture.config.ipv4_network = "10.78.0.0/30".parse().unwrap();
    assert!(Coordinator::open(fixture.config.clone()).await.is_err());
    fixture.config.ipv4_network = "10.77.0.0/30".parse().unwrap();
    let coordinator = fixture.open().await;
    assert_eq!(
        map(&coordinator.test_router(), &a).await["device"],
        a["device"]
    );
}

#[tokio::test]
async fn policy_and_revocation_survive_restart_and_missing_admin_secret_is_not_replaced() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let bob = user(&app, "bob").await;
    let a = device(&app, token(&alice), 17).await;
    let b = device(&app, token(&bob), 18).await;
    request(
        &app,
        "PUT",
        "/api/v1/device/policy",
        Some(token(&b)),
        json!({"base_revision":0,"permissions":tcp_permissions(&a, &[22])}),
    )
    .await;
    let before = map(&app, &a).await;
    assert_eq!(before["peers"].as_array().unwrap().len(), 1);
    drop(app);
    drop(coordinator);
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let after = map(&app, &a).await;
    assert_eq!(before["peers"], after["peers"]);
    assert_eq!(before["revision"], after["revision"]);
    request(
        &app,
        "DELETE",
        &format!("/api/v1/devices/{}", id(&b)),
        Some(token(&bob)),
        Value::Null,
    )
    .await;
    drop(app);
    drop(coordinator);
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    assert!(map(&app, &a).await["peers"].as_array().unwrap().is_empty());
    assert_eq!(
        request(&app, "GET", "/api/v1/device", Some(token(&b)), Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    drop(app);
    drop(coordinator);
    fs::remove_file(fixture.config.state_dir.join("admin.token")).unwrap();
    assert!(Coordinator::open(fixture.config.clone()).await.is_err());
    assert!(!fixture.config.state_dir.join("admin.token").exists());
}

async fn https_request(
    address: std::net::SocketAddr,
    roots: rustls::RootCertStore,
    method: &str,
    path: &str,
    body: &str,
) -> (u16, Value) {
    https_authorized_request(address, roots, method, path, body, None).await
}

async fn https_authorized_request(
    address: std::net::SocketAddr,
    roots: rustls::RootCertStore,
    method: &str,
    path: &str,
    body: &str,
    credential: Option<&str>,
) -> (u16, Value) {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let stream = TcpStream::connect(address).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
            stream,
        )
        .await
        .unwrap();
    let authorization = credential
        .map(|value| format!("Authorization: Bearer {value}\r\n"))
        .unwrap_or_default();
    tls.write_all(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{authorization}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    let mut reader = BufReader::new(tls);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    let status = line.split_whitespace().nth(1).unwrap().parse().unwrap();
    let mut length = None;
    loop {
        line.clear();
        reader.read_line(&mut line).await.unwrap();
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = Some(value.trim().parse::<usize>().unwrap());
        }
    }
    let mut bytes = vec![0; length.unwrap()];
    reader.read_exact(&mut bytes).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn real_https_validates_certificate_serves_api_and_rejects_plaintext() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let handle = axum_server::Handle::new();
    let server = tokio::spawn(coordinator.serve(handle.clone()));
    let address = match timeout(Duration::from_secs(3), handle.listening())
        .await
        .unwrap()
    {
        Some(address) => address,
        None => panic!("HTTPS listener failed: {:?}", server.await.unwrap()),
    };
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fixture.certificate.clone()).unwrap();
    let (status, health) = timeout(
        Duration::from_secs(3),
        https_request(address, roots.clone(), "GET", "/health", ""),
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(health["status"], "ok");
    let (status, user) = https_request(
        address,
        roots,
        "POST",
        "/api/v1/users",
        r#"{"name":"alice"}"#,
    )
    .await;
    assert_eq!(status, 201);
    assert_eq!(user["user"]["is_admin"], false);
    let untrusted = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    let stream = TcpStream::connect(address).await.unwrap();
    assert!(
        tokio_rustls::TlsConnector::from(Arc::new(untrusted))
            .connect(
                rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                stream
            )
            .await
            .is_err()
    );
    let mut plain = TcpStream::connect(address).await.unwrap();
    plain
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    let mut reply = [0; 8];
    if let Ok(Ok(length)) = timeout(Duration::from_secs(1), plain.read(&mut reply)).await {
        assert!(!reply[..length].starts_with(b"HTTP/"));
    }
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[test]
fn configuration_requires_tls_and_resolves_relative_paths() {
    let fixture = Fixture::new();
    let path = fixture.directory.path().join("coordinator.json");
    fs::write(&path, r#"{"listen":"127.0.0.1:8443","state_dir":"state","tls":{"cert_file":"cert.pem","key_file":"key.pem"}}"#).unwrap();
    let config = Config::load(&path).unwrap();
    assert_eq!(config.state_dir, fixture.config.state_dir);
    assert_eq!(config.tls.cert_file, fixture.config.tls.cert_file);
    fs::write(&path, r#"{"listen":"127.0.0.1:8443","state_dir":"state"}"#).unwrap();
    assert!(Config::load(&path).is_err());
}

#[tokio::test]
async fn peer_permission_validation_is_atomic_and_empty_ports_do_not_grant_access() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let a = device(&app, token(&alice), 30).await;
    let b = device(&app, token(&alice), 31).await;
    let b_key = b["device"]["public_key"].as_str().unwrap();
    let (status, policy) = publish(
        &app,
        &a,
        0,
        json!({(b_key.to_uppercase()):{"tcp":[65535,443,22,443]}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(policy["permissions"][b_key]["tcp"], json!([22, 443, 65535]));
    let before = map(&app, &a).await;
    let unknown_key: String = x25519_dalek::x25519([44; 32], x25519_dalek::X25519_BASEPOINT_BYTES)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    for invalid in [
        tcp_permissions(&b, &[0]),
        tcp_permissions(&a, &[80]),
        json!({"invalid-key":{"tcp":[80]}}),
        json!({(unknown_key):{"tcp":[80]}}),
        json!({(b_key):{"tcp":[80]}, (b_key.to_uppercase()):{"tcp":[443]}}),
        tcp_permissions(&b, &[80; 1025]),
    ] {
        assert_eq!(
            publish(&app, &a, 1, invalid).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    for invalid_body in [
        json!({"base_revision":1,"rules":[]}),
        json!({"base_revision":1,"permissions":{(b_key):{"tcp":[80],"udp":[53]}}}),
        json!({"base_revision":1,"permissions":{(b_key):{"tcp":[65536]}}}),
    ] {
        assert_eq!(
            request(
                &app,
                "PUT",
                "/api/v1/device/policy",
                Some(token(&a)),
                invalid_body
            )
            .await
            .0,
            StatusCode::UNPROCESSABLE_ENTITY
        );
    }
    let unchanged = map(&app, &a).await;
    assert_eq!(before["revision"], unchanged["revision"]);
    assert_eq!(before["policy"], unchanged["policy"]);
    assert_eq!(
        publish(&app, &a, 1, tcp_permissions(&b, &[])).await.1["permissions"],
        json!({})
    );
    assert!(map(&app, &a).await["peers"].as_array().unwrap().is_empty());
    request(
        &app,
        "DELETE",
        &format!("/api/v1/devices/{}", id(&b)),
        Some(token(&alice)),
        Value::Null,
    )
    .await;
    assert_eq!(
        publish(&app, &a, 2, tcp_permissions(&b, &[80])).await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn migration_preserves_identities_but_archives_user_grants_without_expanding_them() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let bob = user(&app, "bob").await;
    let a = device(&app, token(&alice), 32).await;
    let b = device(&app, token(&bob), 33).await;
    let before = map(&app, &a).await;
    let admin = fixture.admin_token();
    drop(app);
    drop(coordinator);
    let old_rules = json!([{"source_user_id":alice["user"]["id"],"traffic":{"protocol":"tcp","ports":[{"start":22,"end":22}]}}]).to_string();
    {
        let db =
            rusqlite::Connection::open(fixture.config.state_dir.join("network.sqlite3")).unwrap();
        // Reproduce the previous on-disk schema and a previously confirmed user-wide grant.
        db.execute_batch(
            "ALTER TABLE users ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE devices DROP COLUMN permissions;
            ALTER TABLE devices ADD COLUMN policy TEXT NOT NULL DEFAULT '[]';
            PRAGMA user_version=2;",
        )
        .unwrap();
        db.execute(
            "UPDATE devices SET policy=?,policy_revision=5 WHERE id=?",
            rusqlite::params![old_rules, id(&b)],
        )
        .unwrap();
    }
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    assert_eq!(fixture.admin_token(), admin);
    let after = map(&app, &a).await;
    assert_eq!(before["network_id"], after["network_id"]);
    assert_ne!(before["generation"], after["generation"]);
    assert!(after["revision"].as_u64().unwrap() > before["revision"].as_u64().unwrap());
    assert_eq!(after["device"], a["device"]);
    assert!(after["peers"].as_array().unwrap().is_empty());
    let b_map = map(&app, &b).await;
    assert_eq!(b_map["policy"]["permissions"], json!({}));
    assert_eq!(b_map["policy"]["revision"], 6);
    assert_eq!(
        publish(&app, &b, 6, tcp_permissions(&a, &[22])).await.0,
        StatusCode::OK
    );
    drop(app);
    drop(coordinator);
    {
        let db =
            rusqlite::Connection::open(fixture.config.state_dir.join("network.sqlite3")).unwrap();
        let archive: Value = serde_json::from_slice(
            &fs::read(fixture.config.state_dir.join("legacy-user-policies.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(archive[id(&b)], old_rules);
        let has_column: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name='legacy_user_policy')",
            [],|row|row.get(0)).unwrap();
        assert!(!has_column);
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            4
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(fixture.config.state_dir.join("legacy-user-policies.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    let coordinator = fixture.open().await;
    let restored = map(&coordinator.test_router(), &a).await;
    assert_eq!(restored["generation"], after["generation"]);
    assert_eq!(restored["peers"].as_array().unwrap().len(), 1);
}

async fn set_endpoints(app: &Router, d: &Value, endpoint: &str) {
    assert_eq!(
        request(
            app,
            "PUT",
            "/api/v1/device/endpoints",
            Some(token(d)),
            json!({"endpoints":[endpoint]})
        )
        .await
        .0,
        StatusCode::OK
    );
}

async fn p2p_pair(app: &Router) -> (Value, Value, Value, Value) {
    let alice = user(app, "alice").await;
    let bob = user(app, "bob").await;
    let a = device(app, token(&alice), 50).await;
    let b = device(app, token(&bob), 51).await;
    set_endpoints(app, &a, "198.51.100.10:51820").await;
    set_endpoints(app, &b, "198.51.100.20:51820").await;
    assert_eq!(
        publish(app, &b, 0, tcp_permissions(&a, &[80, 443])).await.0,
        StatusCode::OK
    );
    (alice, bob, a, b)
}

async fn start_connection(
    app: &Router,
    a: &Value,
    b: &Value,
) -> tokio::task::JoinHandle<(StatusCode, Value)> {
    let app = app.clone();
    let credential = token(a).to_owned();
    let target = id(b).to_owned();
    let mut task = tokio::spawn(async move {
        request(
            &app,
            "POST",
            "/api/v1/p2p/requests",
            Some(&credential),
            json!({"peer_device_id":target}),
        )
        .await
    });
    assert!(
        timeout(Duration::from_millis(80), &mut task).await.is_err(),
        "request must wait for the destination agent"
    );
    task
}

async fn incoming(app: &Router, d: &Value) -> Value {
    let (status, body) = request(
        app,
        "GET",
        "/api/v1/p2p/requests?wait_seconds=0",
        Some(token(d)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    body
}

async fn respond(app: &Router, d: &Value, offer: &Value, accept: bool) -> (StatusCode, Value) {
    request(
        app,
        "POST",
        &format!(
            "/api/v1/p2p/requests/{}/response",
            offer["request_id"].as_str().unwrap()
        ),
        Some(token(d)),
        json!({"accept":accept}),
    )
    .await
}

#[tokio::test]
async fn p2p_notifies_target_and_waits_for_ack_before_returning_peer_information() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (_, bob, a, b) = p2p_pair(&app).await;
    let c = device(&app, token(&bob), 52).await;
    let before = map(&app, &a).await;
    let poll_app = app.clone();
    let target_token = token(&b).to_owned();
    let mut poll = tokio::spawn(async move {
        request(
            &poll_app,
            "GET",
            "/api/v1/p2p/requests",
            Some(&target_token),
            Value::Null,
        )
        .await
    });
    assert!(timeout(Duration::from_millis(80), &mut poll).await.is_err());
    let connecting = start_connection(&app, &a, &b).await;
    let (status, offers) = timeout(Duration::from_secs(2), poll)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(offers["requests"].as_array().unwrap().len(), 1);
    let offer = &offers["requests"][0];
    assert_eq!(offer["peer"]["id"], id(&a));
    assert_eq!(offer["peer"]["public_key"], a["device"]["public_key"]);
    assert_eq!(offer["peer"]["endpoints"], json!(["198.51.100.10:51820"]));
    assert_eq!(offer["permissions"]["tcp"], json!([80, 443]));
    assert!(
        !connecting.is_finished(),
        "queueing/delivery alone is not a successful rendezvous"
    );
    assert_eq!(
        respond(&app, &c, offer, true).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        respond(&app, &bob, offer, true).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, confirmed) = respond(&app, &b, offer, true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(confirmed["peer"]["id"], id(&a));
    let (status, ready) = timeout(Duration::from_secs(2), connecting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["request_id"], offer["request_id"]);
    assert_eq!(ready["peer"]["id"], id(&b));
    assert_eq!(ready["peer"]["public_key"], b["device"]["public_key"]);
    assert_eq!(ready["peer"]["endpoints"], json!(["198.51.100.20:51820"]));
    assert_eq!(ready["permissions"]["tcp"], json!([80, 443]));
    assert_eq!(ready["network_id"], before["network_id"]);
    assert_eq!(ready["target_policy_revision"], 1);
    assert_eq!(before["revision"], map(&app, &a).await["revision"]);
    assert!(
        map(&app, &a).await["policy"]["permissions"]
            .as_object()
            .unwrap()
            .is_empty()
    );
    assert!(
        incoming(&app, &b).await["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        respond(&app, &b, offer, true).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn p2p_rejects_missing_permissions_candidates_and_forged_identity() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (alice, _, a, b) = p2p_pair(&app).await;
    for (credential, target, status) in [
        (token(&alice), id(&b), StatusCode::UNAUTHORIZED),
        (token(&a), id(&a), StatusCode::BAD_REQUEST),
        (token(&b), id(&a), StatusCode::FORBIDDEN),
        (token(&a), "unknown", StatusCode::NOT_FOUND),
    ] {
        assert_eq!(
            request(
                &app,
                "POST",
                "/api/v1/p2p/requests",
                Some(credential),
                json!({"peer_device_id":target})
            )
            .await
            .0,
            status
        );
    }
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/p2p/requests",
            Some(token(&a)),
            json!({"peer_device_id":id(&b),"source_device_id":id(&b)})
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    request(
        &app,
        "PUT",
        "/api/v1/device/endpoints",
        Some(token(&a)),
        json!({"endpoints":[]}),
    )
    .await;
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/p2p/requests",
            Some(token(&a)),
            json!({"peer_device_id":id(&b)})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    set_endpoints(&app, &a, "198.51.100.10:51820").await;
    request(
        &app,
        "PUT",
        "/api/v1/device/endpoints",
        Some(token(&b)),
        json!({"endpoints":[]}),
    )
    .await;
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/p2p/requests",
            Some(token(&a)),
            json!({"peer_device_id":id(&b)})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    set_endpoints(&app, &b, "198.51.100.20:51820").await;
    assert_eq!(publish(&app, &b, 1, json!({})).await.0, StatusCode::OK);
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/p2p/requests",
            Some(token(&a)),
            json!({"peer_device_id":id(&b)})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(
        incoming(&app, &b).await["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn p2p_decline_redelivery_and_cancellation_release_pending_requests() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (_, _, a, b) = p2p_pair(&app).await;
    let task = start_connection(&app, &a, &b).await;
    let offers = incoming(&app, &b).await;
    assert_eq!(
        incoming(&app, &b).await,
        offers,
        "unacknowledged offers are redelivered"
    );
    assert_eq!(
        respond(&app, &b, &offers["requests"][0], false).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .0,
        StatusCode::FORBIDDEN
    );
    let task = start_connection(&app, &a, &b).await;
    let offer = incoming(&app, &b).await["requests"][0].clone();
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/p2p/requests",
            Some(token(&a)),
            json!({"peer_device_id":id(&b)})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    task.abort();
    let _ = task.await;
    assert!(
        incoming(&app, &b).await["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        respond(&app, &b, &offer, true).await.0,
        StatusCode::NOT_FOUND
    );
    let task = start_connection(&app, &a, &b).await;
    task.abort();
    let _ = task.await;
}

#[tokio::test]
async fn p2p_uses_fresh_candidates_when_delivering_and_acknowledging() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (_, _, a, b) = p2p_pair(&app).await;
    let task = start_connection(&app, &a, &b).await;
    set_endpoints(&app, &a, "198.51.100.11:51821").await;
    let offers = incoming(&app, &b).await;
    assert_eq!(
        offers["requests"][0]["peer"]["endpoints"],
        json!(["198.51.100.11:51821"])
    );
    set_endpoints(&app, &a, "198.51.100.12:51822").await;
    set_endpoints(&app, &b, "198.51.100.21:51823").await;
    let (status, confirmed) = respond(&app, &b, &offers["requests"][0], true).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        confirmed["peer"]["endpoints"],
        json!(["198.51.100.12:51822"])
    );
    let (status, ready) = timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(ready["peer"]["endpoints"], json!(["198.51.100.21:51823"]));
}

#[tokio::test]
async fn p2p_inflight_request_is_cancelled_when_access_or_identity_is_revoked() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (alice, bob, a, b) = p2p_pair(&app).await;
    let task = start_connection(&app, &a, &b).await;
    let offer = incoming(&app, &b).await["requests"][0].clone();
    assert_eq!(publish(&app, &b, 1, json!({})).await.0, StatusCode::OK);
    assert_eq!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        respond(&app, &b, &offer, true).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        publish(&app, &b, 2, tcp_permissions(&a, &[443])).await.0,
        StatusCode::OK
    );
    let task = start_connection(&app, &a, &b).await;
    let (status, new_credential) = request(
        &app,
        "POST",
        &format!("/api/v1/devices/{}/token", id(&a)),
        Some(token(&alice)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .0,
        StatusCode::UNAUTHORIZED
    );
    let new_a = json!({"device":a["device"],"access_token":new_credential["access_token"]});
    let task = start_connection(&app, &new_a, &b).await;
    assert_eq!(
        request(
            &app,
            "DELETE",
            &format!("/api/v1/devices/{}", id(&b)),
            Some(token(&bob)),
            Value::Null
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn p2p_incoming_poll_reauthenticates_and_limits_duplicate_waiters() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (_, bob, _, b) = p2p_pair(&app).await;
    let poll_app = app.clone();
    let target_token = token(&b).to_owned();
    let mut poll = tokio::spawn(async move {
        request(
            &poll_app,
            "GET",
            "/api/v1/p2p/requests",
            Some(&target_token),
            Value::Null,
        )
        .await
    });
    assert!(timeout(Duration::from_millis(80), &mut poll).await.is_err());
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/p2p/requests",
            Some(token(&b)),
            Value::Null
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let (status, new_token) = request(
        &app,
        "POST",
        &format!("/api/v1/devices/{}/token", id(&b)),
        Some(token(&bob)),
        Value::Null,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        timeout(Duration::from_secs(2), poll)
            .await
            .unwrap()
            .unwrap()
            .0,
        StatusCode::UNAUTHORIZED
    );
    let new_b = json!({"device":b["device"],"access_token":new_token["access_token"]});
    assert!(
        incoming(&app, &new_b).await["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        request(
            &app,
            "GET",
            "/api/v1/p2p/requests?wait_seconds=26",
            Some(token(&new_b)),
            Value::Null
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn p2p_pending_request_capacity_is_bounded_per_source() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (alice, _, a, b) = p2p_pair(&app).await;
    let mut targets = vec![b];
    for seed in 53..57 {
        let d = device(&app, token(&alice), seed).await;
        set_endpoints(&app, &d, "198.51.100.30:51820").await;
        assert_eq!(
            publish(&app, &d, 0, tcp_permissions(&a, &[443])).await.0,
            StatusCode::OK
        );
        targets.push(d);
    }
    let mut tasks = Vec::new();
    for target in &targets[..4] {
        tasks.push(start_connection(&app, &a, target).await);
    }
    assert_eq!(
        request(
            &app,
            "POST",
            "/api/v1/p2p/requests",
            Some(token(&a)),
            json!({"peer_device_id":id(&targets[4])})
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    for task in tasks {
        task.abort();
        let _ = task.await;
    }
    assert!(
        incoming(&app, &targets[0]).await["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn p2p_offline_peer_times_out_and_leaves_no_deliverable_signal() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (_, _, a, b) = p2p_pair(&app).await;
    let (status, body) = timeout(
        Duration::from_secs(12),
        request(
            &app,
            "POST",
            "/api/v1/p2p/requests",
            Some(token(&a)),
            json!({"peer_device_id":id(&b)}),
        ),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
    assert!(body["error"].as_str().unwrap().contains("expired"));
    assert!(
        incoming(&app, &b).await["requests"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn real_https_p2p_request_delivery_and_response() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let (_, _, a, b) = p2p_pair(&app).await;
    let handle = axum_server::Handle::new();
    let server = tokio::spawn(coordinator.serve(handle.clone()));
    let address = timeout(Duration::from_secs(3), handle.listening())
        .await
        .unwrap()
        .expect("HTTPS listener");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(fixture.certificate.clone()).unwrap();
    let source_roots = roots.clone();
    let source_token = token(&a).to_owned();
    let target_id = id(&b).to_owned();
    let task = tokio::spawn(async move {
        https_authorized_request(
            address,
            source_roots,
            "POST",
            "/api/v1/p2p/requests",
            &json!({"peer_device_id":target_id}).to_string(),
            Some(&source_token),
        )
        .await
    });
    let (status, offers) = timeout(
        Duration::from_secs(3),
        https_authorized_request(
            address,
            roots.clone(),
            "GET",
            "/api/v1/p2p/requests",
            "",
            Some(token(&b)),
        ),
    )
    .await
    .unwrap();
    assert_eq!(status, 200);
    assert_eq!(
        offers["requests"][0]["peer"]["public_key"],
        a["device"]["public_key"]
    );
    assert!(!task.is_finished());
    let uri = format!(
        "/api/v1/p2p/requests/{}/response",
        offers["requests"][0]["request_id"].as_str().unwrap()
    );
    let (status, confirmed) = https_authorized_request(
        address,
        roots,
        "POST",
        &uri,
        r#"{"accept":true}"#,
        Some(token(&b)),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(confirmed["peer"]["id"], id(&a));
    let (status, ready) = timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(ready["peer"]["public_key"], b["device"]["public_key"]);
    assert_eq!(ready["request_id"], offers["requests"][0]["request_id"]);
    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn auth_extractor_rejects_ambiguous_headers_and_poll_bounds_are_shared() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let a = device(&app, token(&alice), 60).await;
    for authorization in [
        "Bearer invalid".to_owned(),
        format!("Basic {}", token(&alice)),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/me")
                    .header("authorization", authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/me")
                .header("authorization", format!("Bearer {}", token(&alice)))
                .header("authorization", format!("Bearer {}", token(&alice)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for route in ["network-map", "p2p/requests"] {
        assert_eq!(
            request(
                &app,
                "GET",
                &format!("/api/v1/{route}?wait_seconds=26"),
                Some(token(&a)),
                Value::Null
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        let (status, _) = timeout(
            Duration::from_secs(1),
            request(
                &app,
                "GET",
                &format!("/api/v1/{route}?wait_seconds=0"),
                Some(token(&a)),
                Value::Null,
            ),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn map_uses_configured_lease_and_legacy_schema_upgrade_preserves_current_permissions() {
    let mut fixture = Fixture::new();
    fixture.config.lease_seconds = 30;
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    let a = device(&app, token(&alice), 61).await;
    let b = device(&app, token(&alice), 62).await;
    assert_eq!(
        publish(&app, &b, 0, tcp_permissions(&a, &[443])).await.0,
        StatusCode::OK
    );
    let before = map(&app, &a).await;
    assert_eq!(
        before["expires_at"].as_u64().unwrap() - before["generated_at"].as_u64().unwrap(),
        30
    );
    drop(app);
    drop(coordinator);
    {
        let db =
            rusqlite::Connection::open(fixture.config.state_dir.join("network.sqlite3")).unwrap();
        db.execute_batch(
            "ALTER TABLE users ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE devices ADD COLUMN legacy_user_policy TEXT NOT NULL DEFAULT '[]';
            PRAGMA user_version=3;",
        )
        .unwrap();
    }
    let coordinator = fixture.open().await;
    let after = map(&coordinator.test_router(), &a).await;
    for field in ["device", "peers", "policy", "generation", "revision"] {
        assert_eq!(before[field], after[field], "migration preserves {field}");
    }
    assert!(
        fixture
            .config
            .state_dir
            .join("legacy-user-policies.json")
            .is_file()
    );
}

#[tokio::test]
async fn removing_unused_account_flag_never_reactivates_a_disabled_user() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    let app = coordinator.test_router();
    let alice = user(&app, "alice").await;
    drop(app);
    drop(coordinator);
    {
        let db =
            rusqlite::Connection::open(fixture.config.state_dir.join("network.sqlite3")).unwrap();
        db.execute_batch("ALTER TABLE users ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0; PRAGMA user_version=3;").unwrap();
        db.execute(
            "UPDATE users SET revoked=1 WHERE id=?",
            [alice["user"]["id"].as_str().unwrap()],
        )
        .unwrap();
    }
    let error = Coordinator::open(fixture.config.clone())
        .await
        .err()
        .expect("disabled account prevents implicit migration");
    assert!(error.contains("disabled accounts"));
    let db = rusqlite::Connection::open(fixture.config.state_dir.join("network.sqlite3")).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        db.query_row(
            "SELECT revoked FROM users WHERE id=?",
            [alice["user"]["id"].as_str().unwrap()],
            |r| r.get::<_, u32>(0)
        )
        .unwrap(),
        1
    );
}

#[tokio::test]
async fn migration_does_not_overwrite_a_conflicting_policy_archive() {
    let fixture = Fixture::new();
    let coordinator = fixture.open().await;
    drop(coordinator);
    {
        let db =
            rusqlite::Connection::open(fixture.config.state_dir.join("network.sqlite3")).unwrap();
        db.execute_batch(
            "ALTER TABLE users ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
            ALTER TABLE devices ADD COLUMN legacy_user_policy TEXT NOT NULL DEFAULT '[]';
            PRAGMA user_version=3;",
        )
        .unwrap();
    }
    let archive = fixture.config.state_dir.join("legacy-user-policies.json");
    use std::io::Write;
    let mut file = crate::credentials::create_private(&archive).unwrap();
    file.write_all(b"previous archive\n").unwrap();
    drop(file);
    assert!(Coordinator::open(fixture.config.clone()).await.is_err());
    assert_eq!(fs::read(&archive).unwrap(), b"previous archive\n");
    {
        let db =
            rusqlite::Connection::open(fixture.config.state_dir.join("network.sqlite3")).unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u32>(0))
                .unwrap(),
            3
        );
        let has_archive:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('devices') WHERE name='legacy_user_policy')",[],|r|r.get(0)).unwrap();
        assert!(has_archive);
    }
    // An identical archive left by an interrupted migration can be reused safely.
    fs::write(&archive, b"{}\n").unwrap();
    let _coordinator = fixture.open().await;
    assert_eq!(fs::read(&archive).unwrap(), b"{}\n");
}
