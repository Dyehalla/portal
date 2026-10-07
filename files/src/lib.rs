mod api;
#[cfg(feature = "client")]
mod client;
pub mod models;
mod platform;
mod service;
mod smb;
pub use smb::SmbConfig;

#[cfg(feature = "client")]
pub use client::{SmbConnection, download, list_shares, open_smb, prepare_smb_connection};
pub use service::{FileService, FileServiceConfig};
