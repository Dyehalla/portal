use portal::{Device, DeviceConfig, PeerConfig};
use portal_net::Net;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn device(key: u8) -> Device {
    let mut config = DeviceConfig::new([key; 32], "127.0.0.1:0".parse().unwrap());
    config.dual_stack = false;
    config.workers = 1;
    Device::new(config).unwrap()
}
fn peer(device: &Device, other: &Device, address: &str) {
    device
        .upsert_peer(PeerConfig {
            public_key: other.public_key(),
            preshared_key: None,
            endpoint: Some(other.listen_addr()),
            persistent_keepalive: None,
            allowed_ips: vec![address.parse().unwrap()],
        })
        .unwrap();
}
async fn round_trip(ipv6: bool) {
    let mut a = device(1);
    let mut b = device(2);
    let (a_ip, b_ip, prefix) = if ipv6 {
        ("fd00::1", "fd00::2", 128)
    } else {
        ("10.150.0.1", "10.150.0.2", 32)
    };
    peer(&a, &b, &format!("{b_ip}/{prefix}"));
    peer(&b, &a, &format!("{a_ip}/{prefix}"));
    let a_net = Net::new(a.packet_port(), vec![(a_ip.parse().unwrap(), prefix)], 1420).unwrap();
    let b_net = Net::new(b.packet_port(), vec![(b_ip.parse().unwrap(), prefix)], 1420).unwrap();
    let remote = std::net::SocketAddr::new(b_ip.parse().unwrap(), 8080);
    let mut listener = b_net.listen(remote).unwrap();
    assert!(b_net.listen(remote).is_err());
    let payload = vec![42u8; 300000];
    let expected = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, source) = listener.accept().await.unwrap();
        assert_eq!(source.ip().to_string(), a_ip);
        let mut received = vec![0; expected.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, expected);
        stream.write_all(b"complete").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut stream = a_net.connect(remote).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut received = Vec::new();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"complete");
        server.await.unwrap();
    })
    .await
    .expect("TCP round-trip timed out");
    a_net.shutdown();
    b_net.shutdown();
    a.shutdown().unwrap();
    b.shutdown().unwrap();
}
#[tokio::test]
#[ignore = "requires local UDP sockets; no root or TUN"]
async fn wireguard_userspace_tcp_ipv4() {
    round_trip(false).await;
}
#[tokio::test]
#[ignore = "requires local UDP sockets; no root or TUN"]
async fn wireguard_userspace_tcp_ipv6() {
    round_trip(true).await;
}
