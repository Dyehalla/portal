#[cfg(target_os = "linux")]
pub(crate) mod linux;

#[cfg(target_os = "linux")]
pub(crate) use linux::LinuxPlatform;

/// Host lifecycle operations required by the runtime manager.
pub(crate) trait HostPlatform: Send + Sync + 'static {
    /// Install host signal handlers used to request a clean runtime shutdown.
    fn install_signal_handlers(&self);
    /// Return whether the host has requested that the runtime stop.
    fn stop_requested(&self) -> bool;
}
