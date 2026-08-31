#[cfg(target_os = "linux")]
#[path = "linux/event.rs"]
pub mod event;

#[cfg(target_os = "linux")]
#[path = "linux/worker.rs"]
pub mod worker;

#[cfg(target_os = "linux")]
#[path = "linux/socket.rs"]
pub mod socket;

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
