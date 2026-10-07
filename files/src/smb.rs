use std::net::IpAddr;
use std::path::PathBuf;

/// One read-only Samba share managed by this runtime.
pub struct SmbConfig {
    pub root: PathBuf,
    pub name: String,
    pub listen: IpAddr,
    /// Unix/SMB account; defaults to the calling user (the sudo caller when available).
    pub user: Option<String>,
    /// Keep Samba privileged; requires an already privileged runtime.
    pub as_root: bool,
    /// Defaults to 1445 without root, or 445 with `as_root`.
    pub port: Option<u16>,
    pub password_file: PathBuf,
    pub allowed_peers: Vec<IpAddr>,
}

/// Connection metadata and credentials shared only with authorized tunnel peers.
pub(crate) struct SmbAccess {
    pub share: crate::models::SmbShare,
    pub username: String,
    pub password: zeroize::Zeroizing<String>,
    pub allowed_peers: Vec<IpAddr>,
}
