use portal::AllowedIp;

use crate::InterfaceAddress;

#[cfg(target_os = "linux")]
pub(crate) mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::LinuxPlatform;

/// Host networking operations required by the runtime manager.
pub(crate) trait HostPlatform: Send + Sync + 'static {
    /// Install host signal handlers used to request a clean runtime shutdown.
    fn install_signal_handlers(&self);
    /// Return whether the host has requested that the runtime stop.
    fn stop_requested(&self) -> bool;
    /// Refuse startup if an interface with this name already exists.
    fn ensure_interface_absent(&self, name: &str) -> Result<(), String>;
    /// Set the MTU on the runtime's virtual interface.
    fn set_mtu(&self, name: &str, mtu: u32) -> Result<(), String>;
    /// Assign one IPv4 or IPv6 address to the virtual interface.
    fn add_interface_address(&self, name: &str, address: InterfaceAddress) -> Result<(), String>;
    /// Bring the virtual interface up after its configuration is applied.
    fn set_interface_up(&self, name: &str) -> Result<(), String>;
    /// Remove runtime-owned addresses and bring the interface down during cleanup.
    fn cleanup_interface(
        &self,
        name: &str,
        addresses: &[InterfaceAddress],
        link_up: bool,
    ) -> Result<(), String>;
    /// Add a host route and report whether this runtime created it.
    fn ensure_host_route(&self, interface: &str, route: AllowedIp) -> Result<bool, String>;
    /// Remove a host route previously owned by this runtime.
    fn delete_host_route(&self, interface: &str, route: AllowedIp) -> Result<(), String>;
}
