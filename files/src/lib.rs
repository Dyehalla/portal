#[cfg(feature = "client")]
mod client;
mod grpc;
mod platform;
mod service;
mod smb;
pub use smb::SmbConfig;

pub mod rpc {
    tonic::include_proto!("portal.files.v1");
}

#[cfg(feature = "client")]
pub use client::{SmbConnection, download, list_shares, open_smb, prepare_smb_connection};
pub use grpc::FileTransferRpc;
pub use service::{FileService, FileServiceConfig};
