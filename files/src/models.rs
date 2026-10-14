use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileResource {
    pub id: String,
    pub name: String,
    pub read_only: bool,
}
#[derive(Serialize, Deserialize)]
pub struct ListResourcesResponse {
    pub resources: Vec<FileResource>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Directory,
    Symlink,
    Other,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub path: String,
    pub kind: FileKind,
    pub size_bytes: Option<u64>,
    pub modified_at_unix_seconds: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilePathRequest {
    #[serde(default)]
    pub path: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListDirectoryRequest {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub offset: usize,
    #[serde(default = "default_page_size")]
    pub limit: usize,
}
pub fn default_page_size() -> usize {
    100
}
#[derive(Serialize, Deserialize)]
pub struct ListDirectoryResponse {
    pub path: String,
    pub entries: Vec<FileEntry>,
    pub next_offset: Option<usize>,
}
