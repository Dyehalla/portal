//! Linux-specific I/O and worker wakeup adapters.

mod dispatch;
mod event;
mod socket;
mod worker;

pub(crate) use dispatch::{DispatchCommand, DispatchSource};
pub(crate) use socket::TunSocket;
pub(crate) use worker::{WorkerPort, WorkerSpawner};
