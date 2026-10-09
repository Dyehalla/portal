use std::sync::atomic::{AtomicBool, Ordering};

use super::HostPlatform;

pub(crate) mod api_token;

pub(crate) struct LinuxPlatform;

static STOP: AtomicBool = AtomicBool::new(false);

// Signal-safe callback that asks the runtime loop to stop and release host resources.
extern "C" fn request_stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}

impl HostPlatform for LinuxPlatform {
    // Reset the shutdown flag and register handlers for terminal and service-manager signals.
    fn install_signal_handlers(&self) {
        STOP.store(false, Ordering::Release);
        unsafe {
            libc::signal(
                libc::SIGINT,
                request_stop as *const () as libc::sighandler_t,
            );
            libc::signal(
                libc::SIGTERM,
                request_stop as *const () as libc::sighandler_t,
            );
        }
    }

    // Read the flag set by the SIGINT or SIGTERM handler.
    fn stop_requested(&self) -> bool {
        STOP.load(Ordering::Acquire)
    }
}
