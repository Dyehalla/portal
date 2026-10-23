#[cfg(target_os = "linux")]
mod api;
mod config;
#[cfg(target_os = "linux")]
mod managed;
mod platform;
#[cfg(target_os = "linux")]
mod private_file;
#[cfg(target_os = "linux")]
mod runtime;
#[cfg(target_os = "linux")]
mod snapshot;

pub use config::{FileConfig, InterfaceAddress, ManagedConfig, RuntimeConfig, SecretKey, defaults};

#[cfg(target_os = "linux")]
/// Enroll a device over verified HTTPS and persist its private device credentials.
pub fn enroll(
    config: ManagedConfig,
    private_key: SecretKey,
    user_token_file: &std::path::Path,
) -> Result<String, String> {
    let executor = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    executor.block_on(managed::enroll(config, private_key, user_token_file))
}

#[cfg(not(target_os = "linux"))]
pub fn enroll(
    _config: ManagedConfig,
    _private_key: SecretKey,
    _user_token_file: &std::path::Path,
) -> Result<String, String> {
    Err("portal runtime currently supports Linux only".into())
}

#[cfg(target_os = "linux")]
/// Start the configured WireGuard device and local HTTP API until shutdown.
pub fn run(config: RuntimeConfig) -> Result<(), String> {
    runtime::run_device(config)
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
