#[cfg(target_os = "linux")]
mod api;
mod config;
#[cfg(target_os = "linux")]
mod peer_services;
mod platform;
#[cfg(target_os = "linux")]
mod service;

pub use config::{InterfaceAddress, RuntimeConfig, SecretKey, load_config};

#[cfg(target_os = "linux")]
/// Start the configured WireGuard device and local HTTP API until shutdown.
pub fn run(config: RuntimeConfig) -> Result<(), String> {
    service::run_device(config)
}

#[cfg(not(target_os = "linux"))]
/// Report that the runtime backend is not implemented for this operating system.
pub fn run(_config: RuntimeConfig) -> Result<(), String> {
    Err("portal runtime currently supports Linux only".into())
}
