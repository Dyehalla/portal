use portal_net::{PeerKey, Service};
use std::{
    collections::HashSet,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
};

pub struct FileServiceConfig {
    pub root: PathBuf,
    pub allowed_downloaders: HashSet<PeerKey>,
}
#[derive(Clone)]
pub(crate) struct SharedState {
    pub root: Arc<PathBuf>,
    pub allowed_downloaders: Arc<HashSet<PeerKey>>,
    pub download_slots: Arc<Semaphore>,
}
#[derive(Clone)]
pub struct FileService {
    state: SharedState,
}
impl FileService {
    pub async fn new(config: FileServiceConfig) -> Result<Self, String> {
        let root = tokio::fs::canonicalize(&config.root)
            .await
            .map_err(|e| format!("could not resolve file root {}: {e}", config.root.display()))?;
        if !tokio::fs::metadata(&root)
            .await
            .map_err(|e| e.to_string())?
            .is_dir()
        {
            return Err("file root must be a directory".into());
        }
        if config.allowed_downloaders.is_empty() {
            return Err("at least one reader key is required".into());
        }
        Ok(Self {
            state: SharedState {
                root: Arc::new(root),
                allowed_downloaders: Arc::new(config.allowed_downloaders),
                download_slots: Arc::new(Semaphore::new(128)),
            },
        })
    }
    pub fn service(&self) -> Service {
        let state = self.state.clone();
        Service::new("files", move |peer, request| {
            crate::api::handle(state.clone(), peer, request)
        })
    }
}
pub(crate) struct DownloadReader {
    pub file: tokio::fs::File,
    pub _permit: OwnedSemaphorePermit,
}
impl AsyncRead for DownloadReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}
