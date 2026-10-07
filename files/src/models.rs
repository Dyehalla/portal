use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareDownloadRequest {
    pub path: String,
}
#[derive(Serialize, Deserialize)]
pub struct PrepareDownloadResponse {
    pub download_url: String,
    pub file_name: String,
    pub size_bytes: u64,
    pub expires_at_unix_seconds: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SmbShare {
    pub name: String,
    pub host: String,
    pub port: u32,
    pub read_only: bool,
}
#[derive(Serialize, Deserialize)]
pub struct ListSharesResponse {
    pub shares: Vec<SmbShare>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareSmbConnectionRequest {
    pub share_name: String,
}
// Deliberately no Debug: contains credentials.
#[derive(Serialize, Deserialize)]
pub struct PrepareSmbConnectionResponse {
    pub share: SmbShare,
    pub username: String,
    pub password: String,
}
