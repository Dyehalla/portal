//! Embeddable userspace WireGuard devices.
//!
//! A [`Device`] owns one virtual interface, one UDP listen port, its peer
//! registry and a configurable group of packet workers.

mod access;
mod device;
mod platform;
mod runtime;

pub use access::{AccessControl, AccessRules, PeerAccess};
pub use device::{
    AllowedIp, AllowedIpParseError, Device, DeviceConfig, DeviceError, DeviceStats, PeerConfig,
    PeerKey, PeerStats,
};
