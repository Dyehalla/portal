#![cfg(all(feature = "client", target_os = "linux"))]

use http_body_util::BodyExt;
use portal::{Device, DeviceConfig, PeerConfig};
use portal_files::{FileService, FileServiceConfig, proxy_request_with_net};
use portal_net::Net;
use std::{collections::HashSet, time::Duration};

#[tokio::test]
#[ignore = "requires local UDP sockets; no root or TUN"]
async fn file_http_over_wireguard_userspace_stack() {
    let root =
        std::env::temp_dir().join(format!("portal-net-files-{:032x}", rand::random::<u128>()));
    std::fs::create_dir(&root).unwrap();
    let payload = vec![42; 300000];
    std::fs::write(root.join("data.bin"), &payload).unwrap();
    let mut devices = Vec::new();
    for key in [1, 2] {
        let mut config = DeviceConfig::new([key; 32], "127.0.0.1:0".parse().unwrap());
        config.dual_stack = false;
        config.workers = 1;
        devices.push(Device::new(config).unwrap());
    }
    let ips = ["10.151.0.1", "10.151.0.2"];
    for i in 0..2 {
        devices[i]
            .upsert_peer(PeerConfig {
                public_key: devices[1 - i].public_key(),
                preshared_key: None,
                endpoint: Some(devices[1 - i].listen_addr()),
                persistent_keepalive: None,
                allowed_ips: vec![format!("{}/32", ips[1 - i]).parse().unwrap()],
            })
            .unwrap();
    }
    let networks: Vec<_> = devices
        .iter()
        .zip(ips)
        .map(|(device, ip)| {
            Net::new(device.packet_port(), vec![(ip.parse().unwrap(), 32)], 1420).unwrap()
        })
        .collect();
    let address = "10.151.0.2:8080".parse().unwrap();
    let service = FileService::new_virtual(
        networks[1].clone(),
        address,
        FileServiceConfig {
            root: root.clone(),
            allowed_downloaders: HashSet::from([ips[0].parse().unwrap()]),
        },
    )
    .await
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(service.serve(async {
        let _ = stopped.await;
    }));
    tokio::time::timeout(Duration::from_secs(20), async {
        let response = proxy_request_with_net(
            Some(networks[0].clone()),
            address,
            "list",
            br#"{"path":""}"#,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let listing: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(listing["entries"][0]["name"], "data.bin");
        let response = proxy_request_with_net(
            Some(networks[0].clone()),
            address,
            "download",
            br#"{"path":"data.bin"}"#,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["content-length"], "300000");
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            payload.as_slice()
        );
    })
    .await
    .expect("userspace file HTTP timed out");
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(7), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    for network in networks {
        network.shutdown();
    }
    for device in &mut devices {
        device.shutdown().unwrap();
    }
    std::fs::remove_dir_all(root).unwrap();
}
