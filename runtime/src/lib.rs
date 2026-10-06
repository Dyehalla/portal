mod config;
#[cfg(target_os = "linux")]
mod control;
mod platform;
#[cfg(target_os = "linux")]
mod service;

pub use config::{InterfaceAddress, RuntimeConfig, SecretKey};

#[cfg(target_os = "linux")]
/// Start the configured WireGuard device and serve local control requests until shutdown.
pub fn run(config: RuntimeConfig) -> Result<(), String> {
    service::run_device(config)
}

#[cfg(not(target_os = "linux"))]
/// Report that the runtime backend is not implemented for this operating system.
pub fn run(_config: RuntimeConfig) -> Result<(), String> {
    Err("portal runtime currently supports Linux only".into())
}

#[cfg(target_os = "linux")]
/// Create a private key file with restrictive permissions and return its public key.
pub fn create_key_file(path: &std::path::Path) -> Result<portal::PeerKey, String> {
    platform::linux::create_key_file(path)
}

#[cfg(not(target_os = "linux"))]
/// Report that secure key-file creation is currently supported only on Linux.
pub fn create_key_file(_path: &std::path::Path) -> Result<portal::PeerKey, String> {
    Err("portal runtime currently supports Linux only".into())
}

#[cfg(target_os = "linux")]
/// Check that a name is valid for a Linux TUN interface.
pub fn validate_interface_name(name: &str) -> Result<(), String> {
    platform::linux::validate_interface_name(name)
}

#[cfg(not(target_os = "linux"))]
/// Report that interface-name validation currently requires the Linux backend.
pub fn validate_interface_name(_name: &str) -> Result<(), String> {
    Err("portal runtime currently supports Linux only".into())
}
