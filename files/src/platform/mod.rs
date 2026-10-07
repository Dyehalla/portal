#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::smb::SmbService;

#[cfg(all(feature = "client", unix))]
mod smb_client;
#[cfg(all(feature = "client", unix))]
pub(crate) use smb_client::open_smb;

#[cfg(all(feature = "client", not(unix)))]
pub(crate) async fn open_smb(_connection: crate::SmbConnection) -> Result<(), String> {
    Err("opening SMB with smbclient is currently supported on Unix; use prepare_smb_connection with a native client".into())
}
