//! Structured local API view. Credentials and private configuration stay out of it.
use serde::Serialize;
use std::net::SocketAddr;

#[derive(Serialize)]
pub(crate) struct Snapshot {
    pub mode: &'static str,
    pub healthy: bool,
    pub interface: Interface,
    pub network: Option<Network>,
    pub peers: Vec<Peer>,
    pub stats: Stats,
}

#[derive(Serialize)]
pub(crate) struct Interface {
    pub name: String,
    pub listen: SocketAddr,
    pub public_key: String,
    pub addresses: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct Network {
    pub device_id: String,
    pub device_name: String,
    pub network_id: String,
    pub revision: u64,
    pub policy_revision: u64,
    pub policy_pending: bool,
    pub coordinator_connected: bool,
    pub lease_active: bool,
    pub lease_remaining_seconds: u64,
}

#[derive(Serialize)]
pub(crate) struct Peer {
    pub public_key: String,
    pub device_id: Option<String>,
    pub name: Option<String>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<String>,
    pub keepalive_seconds: Option<u64>,
    /// None denotes ordinary WireGuard mode, where Portal TCP ACLs do not apply.
    pub incoming_tcp: Option<Vec<u16>>,
    pub outgoing_tcp: Option<Vec<u16>>,
    pub traffic: Option<Traffic>,
}

#[derive(Serialize)]
pub(crate) struct Traffic {
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
}

#[derive(Serialize)]
pub(crate) struct Stats {
    pub received_udp_packets: u64,
    pub received_tun_packets: u64,
    pub dropped_packets: u64,
    pub timer_send_errors: u64,
    pub udp_send_errors: u64,
}
