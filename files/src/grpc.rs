use std::path::{Component, Path};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rand::RngCore;

use crate::rpc::file_transfer_server::{FileTransfer, FileTransferServer};
use crate::rpc::{PrepareDownloadRequest, PrepareDownloadResponse};
use crate::service::{DownloadTicket, SharedState};
use tonic::{Request, Response as GrpcResponse, Status};

const TICKET_TTL: Duration = Duration::from_secs(5 * 60);

pub struct FileTransferRpc {
    state: Option<SharedState>,
    smb: Option<std::sync::Arc<crate::smb::SmbAccess>>,
}

/// Build the file-transfer gRPC endpoint for registration with the shared server.
pub(super) fn server(
    state: Option<SharedState>,
    smb: Option<std::sync::Arc<crate::smb::SmbAccess>>,
) -> FileTransferServer<FileTransferRpc> {
    FileTransferServer::new(FileTransferRpc { state, smb })
}

#[tonic::async_trait]
impl FileTransfer for FileTransferRpc {
    async fn list_shares(
        &self,
        request: Request<crate::rpc::ListSharesRequest>,
    ) -> Result<GrpcResponse<crate::rpc::ListSharesResponse>, Status> {
        let peer = peer_address(&request)?;
        let shares = self
            .smb
            .as_ref()
            .filter(|smb| smb.allowed_peers.contains(&peer))
            .map(|smb| vec![smb.share.clone()])
            .unwrap_or_default();
        Ok(GrpcResponse::new(crate::rpc::ListSharesResponse { shares }))
    }

    async fn prepare_smb_connection(
        &self,
        request: Request<crate::rpc::PrepareSmbConnectionRequest>,
    ) -> Result<GrpcResponse<crate::rpc::PrepareSmbConnectionResponse>, Status> {
        let peer = peer_address(&request)?;
        let smb = self
            .smb
            .as_ref()
            .ok_or_else(|| Status::unimplemented("SMB sharing is disabled"))?;
        if !smb.allowed_peers.contains(&peer) {
            return Err(Status::permission_denied(
                "this peer does not have SMB permission",
            ));
        }
        if request.into_inner().share_name != smb.share.name {
            return Err(Status::not_found("SMB share does not exist"));
        }
        Ok(GrpcResponse::new(
            crate::rpc::PrepareSmbConnectionResponse {
                share: Some(smb.share.clone()),
                username: smb.username.clone(),
                password: smb.password.to_string(),
            },
        ))
    }

    /// Check the caller's download grant, resolve the requested file, and issue a one-use ticket.
    async fn prepare_download(
        &self,
        request: Request<PrepareDownloadRequest>,
    ) -> Result<GrpcResponse<PrepareDownloadResponse>, Status> {
        let requester = peer_address(&request)?;
        let state = self
            .state
            .as_ref()
            .ok_or_else(|| Status::unimplemented("HTTP downloads are disabled"))?;
        if !state.allowed_downloaders.contains(&requester) {
            return Err(Status::permission_denied(
                "this peer does not have file download permission",
            ));
        }

        let request = request.into_inner();
        let relative_path = Path::new(&request.path);
        if !is_safe_relative_path(relative_path) {
            return Err(Status::invalid_argument(
                "path must be relative and may not contain dot or parent components",
            ));
        }
        state.prune_expired().await;
        let permit = state
            .download_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("file service has too many downloads"))?;
        let requested_path = state.root.join(relative_path);
        let canonical_path = tokio::fs::canonicalize(&requested_path)
            .await
            .map_err(|_| Status::not_found("file does not exist or cannot be accessed"))?;
        if !canonical_path.starts_with(state.root.as_path()) {
            return Err(Status::permission_denied(
                "file path resolves outside the shared root",
            ));
        }

        // TODO: Use a cross-platform, race-safe directory-relative open (e.g. cap-std).
        // A file or parent directory can be replaced with a symlink between canonicalize
        // and open, allowing access outside the shared root. Path checks alone do not fix this.
        let file = tokio::fs::File::open(&canonical_path)
            .await
            .map_err(|_| Status::not_found("file does not exist or cannot be accessed"))?;
        let metadata = file
            .metadata()
            .await
            .map_err(|_| Status::internal("could not inspect requested file"))?;
        if !metadata.is_file() {
            return Err(Status::invalid_argument(
                "requested path is not a regular file",
            ));
        }
        let file_name = canonical_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .ok_or_else(|| Status::invalid_argument("requested path has no file name"))?;
        let size_bytes = metadata.len();
        let expires = Instant::now() + TICKET_TTL;
        let expires_at_unix_seconds = SystemTime::now()
            .checked_add(TICKET_TTL)
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        let ticket_id = create_ticket_id();
        let download_url = format!("{}/v1/download/{ticket_id}", state.http_advertise);
        {
            let mut tickets = state.tickets.lock().await;
            tickets.insert(
                ticket_id,
                DownloadTicket {
                    file,
                    size_bytes,
                    requester,
                    expires,
                    permit,
                },
            );
        }

        Ok(GrpcResponse::new(PrepareDownloadResponse {
            download_url,
            file_name,
            size_bytes,
            expires_at_unix_seconds,
        }))
    }
}

/// Accept only ordinary path components so callers cannot request parent or absolute paths.
fn is_safe_relative_path(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Create an unguessable bearer ticket identifier for the one-use HTTP request.
fn create_ticket_id() -> String {
    let mut random = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let mut encoded = String::with_capacity(random.len() * 2);
    for byte in random {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

fn peer_address<T>(request: &Request<T>) -> Result<std::net::IpAddr, Status> {
    request
        .remote_addr()
        .map(|address| address.ip())
        .ok_or_else(|| Status::permission_denied("peer address is unavailable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{ListSharesRequest, PrepareSmbConnectionRequest, SmbShare};

    fn rpc() -> FileTransferRpc {
        FileTransferRpc {
            state: None,
            smb: Some(std::sync::Arc::new(crate::smb::SmbAccess {
                share: SmbShare {
                    name: "documents".into(),
                    host: "10.20.0.1".into(),
                    port: 1445,
                    read_only: true,
                },
                username: "reader".into(),
                password: zeroize::Zeroizing::new("secret".into()),
                allowed_peers: vec!["10.20.0.2".parse().unwrap()],
            })),
        }
    }

    fn request<T>(body: T, peer: &str) -> Request<T> {
        let mut request = Request::new(body);
        request
            .extensions_mut()
            .insert(tonic::transport::server::TcpConnectInfo {
                local_addr: Some("10.20.0.1:50051".parse().unwrap()),
                remote_addr: Some(peer.parse().unwrap()),
            });
        request
    }

    #[tokio::test]
    async fn smb_grants_are_independent_of_downloads_and_bound_to_transport_peer() {
        let rpc = rpc();
        let allowed = rpc
            .list_shares(request(ListSharesRequest {}, "10.20.0.2:1234"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(allowed.shares.len(), 1);
        assert!(
            rpc.list_shares(request(ListSharesRequest {}, "10.20.0.3:1234"))
                .await
                .unwrap()
                .into_inner()
                .shares
                .is_empty()
        );
        let body = || PrepareSmbConnectionRequest {
            share_name: "documents".into(),
        };
        let granted = rpc
            .prepare_smb_connection(request(body(), "10.20.0.2:1234"))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(granted.username, "reader");
        assert_eq!(granted.password, "secret");
        assert_eq!(granted.share.unwrap().port, 1445);
        assert_eq!(
            rpc.prepare_smb_connection(request(body(), "10.20.0.3:1234"))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            rpc.prepare_smb_connection(Request::new(body()))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            rpc.prepare_smb_connection(request(
                PrepareSmbConnectionRequest {
                    share_name: "hidden".into()
                },
                "10.20.0.2:1234"
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            rpc.prepare_download(request(
                PrepareDownloadRequest {
                    path: "hello.txt".into()
                },
                "10.20.0.2:1234"
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unimplemented
        );
    }

    #[tokio::test]
    async fn disabled_smb_exposes_no_shares_or_credentials() {
        let rpc = FileTransferRpc {
            state: None,
            smb: None,
        };
        assert!(
            rpc.list_shares(request(ListSharesRequest {}, "10.20.0.2:1234"))
                .await
                .unwrap()
                .into_inner()
                .shares
                .is_empty()
        );
        assert_eq!(
            rpc.prepare_smb_connection(request(
                PrepareSmbConnectionRequest {
                    share_name: "documents".into()
                },
                "10.20.0.2:1234"
            ))
            .await
            .unwrap_err()
            .code(),
            tonic::Code::Unimplemented
        );
    }
}
