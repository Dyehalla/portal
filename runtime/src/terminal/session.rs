//! Browser terminal session limits and wire-level constants.
//!
//! The local API owns the WebSocket task, while this module keeps the PTY
//! session contract next to the SSH service lifecycle. Keeping limits here
//! prevents browser supplied frames from growing without bound.

pub(crate) const MAX_INPUT_FRAME: usize = 64 * 1024;
pub(crate) const MAX_OUTPUT_FRAME: usize = 16 * 1024;
pub(crate) const MAX_STDERR_FRAME: usize = 8 * 1024;
pub(crate) const SESSION_TTL_SECONDS: u64 = 30;
pub(crate) const MAX_SESSIONS: usize = 8;
pub(crate) const IDLE_TIMEOUT_SECONDS: u64 = 900;
