use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

fn is_false(value: &bool) -> bool {
    !*value
}

pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    pub is_admin: bool,
    pub created_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub owner_user_id: String,
    pub name: String,
    pub public_key: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    pub endpoints: Vec<SocketAddr>,
    pub created_at: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterUser {
    pub name: String,
}

// Credentials deliberately do not implement Debug.
#[derive(Serialize, Deserialize)]
pub struct RegisteredUser {
    pub user: User,
    pub access_token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDevice {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Serialize, Deserialize)]
pub struct RegisteredDevice {
    pub device: Device,
    pub access_token: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEndpoints {
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Serialize, Deserialize)]
pub struct IssuedToken {
    pub access_token: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPermissions {
    /// Allowed TCP destination ports on the device publishing this policy.
    pub tcp: Vec<u16>,
    /// Permit the Portal SSH terminal service on the destination device.
    #[serde(default, skip_serializing_if = "is_false")]
    pub terminal: bool,
}

pub type Permissions = BTreeMap<String, PeerPermissions>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DevicePolicy {
    pub revision: u64,
    pub permissions: Permissions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DesiredPolicy {
    pub revision: u64,
    pub permissions: Permissions,
    pub applied_revision: u64,
}

/// Published by the destination agent only after applying its local policy.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishPolicy {
    pub base_revision: u64,
    pub permissions: Permissions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peer {
    pub device: Device,
    pub policy_revision: u64,
    /// Peer -> this device; destination ports belong to this device.
    pub incoming: PeerPermissions,
    /// This device -> peer; destination ports belong to the peer.
    pub outgoing: PeerPermissions,
}

/// Discovery service owned by this coordinator. Empty endpoints use the HTTPS
/// origin's resolved IP addresses with this UDP port (including wildcard binds).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StunService {
    pub port: u16,
    #[serde(default)]
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkMap {
    pub protocol_version: u32,
    pub network_id: String,
    pub generation: String,
    pub revision: u64,
    pub generated_at: u64,
    pub expires_at: u64,
    #[serde(default)]
    pub stun: Option<StunService>,
    pub user: User,
    pub device: Device,
    pub policy: DevicePolicy,
    pub peers: Vec<Peer>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestConnection {
    pub peer_device_id: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RespondConnection {
    pub accept: bool,
}

/// A temporary rendezvous signal, not a WireGuard session or a new access grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConnectionInfo {
    pub request_id: String,
    pub protocol_version: u32,
    pub network_id: String,
    pub generation: String,
    pub revision: u64,
    pub peer: Device,
    /// Existing permissions for the direction requester -> destination.
    pub permissions: PeerPermissions,
    pub target_policy_revision: u64,
    pub expires_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IncomingConnections {
    pub requests: Vec<ConnectionInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissions_have_stable_json_order_independent_of_insertion_order() {
        let mut permissions = Permissions::new();
        permissions.insert(
            "b".into(),
            PeerPermissions {
                tcp: vec![443],
                terminal: false,
            },
        );
        permissions.insert(
            "a".into(),
            PeerPermissions {
                tcp: vec![80],
                terminal: false,
            },
        );
        assert_eq!(
            serde_json::to_string(&permissions).unwrap(),
            r#"{"a":{"tcp":[80]},"b":{"tcp":[443]}}"#
        );
    }
}

/// Human approval of TCP access; separate from automatic P2P rendezvous.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestAccess {
    pub source_device_id: String,
    pub target_device_id: String,
    pub tcp: Vec<u16>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub terminal: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideAccess {
    pub accept: bool,
}
#[derive(Serialize, Deserialize)]
pub struct AccessRequest {
    pub id: String,
    pub source: Device,
    pub target: Device,
    pub requester_name: String,
    pub tcp: Vec<u16>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub terminal: bool,
    pub status: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub policy_revision: Option<u64>,
}
