//! Compile-time platform selection and the shared platform adapter API.
//!
//! Application modules depend on the names re-exported here. Platform-specific
//! implementations stay private behind `backend` and must expose this same
//! set of types and operations when another backend is added.

#[cfg(target_os = "linux")]
#[path = "linux/mod.rs"]
mod backend;

#[cfg(target_os = "linux")]
pub(crate) use backend::{DispatchCommand, DispatchSource, TunSocket, WorkerPort, WorkerSpawner};
