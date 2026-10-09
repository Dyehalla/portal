//! Embeddable userspace WireGuard devices.
//!
//! A [`Device`] owns an internal IP packet channel, one UDP listen port, its peer
//! registry and a configurable group of packet workers.

mod device;
mod platform;
mod runtime;

pub use device::{
    AllowedIp, AllowedIpParseError, Device, DeviceConfig, DeviceError, DeviceStats, PeerConfig,
    PeerKey, PeerStats,
};

pub use platform::PacketPort;
