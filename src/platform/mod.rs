#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
#[path = "macos/event.rs"]
pub mod event;

#[cfg(target_os = "macos")]
#[path = "macos/event_loop.rs"]
pub mod event_loop;

#[cfg(target_os = "macos")]
#[path = "macos/tun.rs"]
pub mod tun;

#[cfg(target_os = "windows")]
#[path = "windows/event.rs"]
pub mod event;

#[cfg(target_os = "windows")]
#[path = "windows/event_loop.rs"]
pub mod event_loop;

#[cfg(target_os = "windows")]
#[path = "windows/tun.rs"]
pub mod tun;
