//! Userspace WireGuard datapath with a high-level device lifecycle API.

mod datapath;
mod device;
mod index_table;
mod platform;
mod protocol;
mod ring;

#[cfg(target_os = "linux")]
mod engine;

pub use device::{AllowedIp, ControlError, PeerKey, PeerStats};

#[cfg(target_os = "linux")]
pub use engine::{Engine, EngineBuilder, EngineError, EngineHandle, PeerConfig};
