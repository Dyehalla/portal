//! Linux thread and eventfd adapter for the portable datapath worker.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::thread::JoinHandle;

use arc_swap::ArcSwap;

use crate::datapath::pipeline::{CompletionNotifier, DispatcherPort};
use crate::datapath::worker::Worker;
use crate::device::{DeviceSnapshot, TunnelConfig};
use crate::index_table::{IndexTable, WorkerId};

/// Linux dispatcher endpoints plus the descriptor used by epoll for wakeups.
pub struct WorkerPort {
    pub queues: DispatcherPort,
    pub completion_fd: Arc<OwnedFd>,
}

/// Spawns the portable worker core with Linux eventfd notification.
pub struct WorkerSpawner;

impl WorkerSpawner {
    /// Starts a worker and returns its dispatcher-facing queues and wake fd.
    pub fn spawn(
        id: WorkerId,
        configs: Vec<TunnelConfig>,
        indices: Arc<IndexTable>,
        snapshot: Arc<ArcSwap<DeviceSnapshot>>,
        ring_capacity: usize,
    ) -> io::Result<(WorkerPort, JoinHandle<io::Result<()>>)> {
        let raw_fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let completion_fd = Arc::new(unsafe { OwnedFd::from_raw_fd(raw_fd) });
        let notifier = Arc::new(EventFdNotifier(Arc::clone(&completion_fd)));
        let (queues, thread) = Worker::spawn(
            id,
            configs,
            indices,
            snapshot,
            ring_capacity,
            notifier,
        )?;
        Ok((WorkerPort { queues, completion_fd }, thread))
    }
}

struct EventFdNotifier(Arc<OwnedFd>);

impl CompletionNotifier for EventFdNotifier {
    fn notify(&self) {
        let value = 1u64;
        unsafe {
            libc::write(
                self.0.as_raw_fd(),
                (&value as *const u64).cast(),
                std::mem::size_of::<u64>(),
            );
        }
    }
}
