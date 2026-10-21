use crate::{ALPN, Net, PeerKey, io_error};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

const REQUEST_LIMIT: usize = 16 * 1024;
const HEADER_LIMIT: usize = 4096;
const JSON_LIMIT: usize = 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);
// Allow the service deadline to expire and its 504 response to reach the client.
const RESPONSE_HEADER_TIMEOUT: Duration = SERVICE_TIMEOUT.saturating_add(IO_TIMEOUT);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub service: String,
    pub operation: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}
impl Request {
    /// Check the encoded QUIC frame size before attempting network IO.
    pub fn validate_size(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() > REQUEST_LIMIT {
            return Err("request exceeds the 16 KiB QUIC frame limit".into());
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeader {
    pub status: u16,
    pub length: u64,
    pub file_name: Option<String>,
}
pub struct Response {
    pub header: ResponseHeader,
    pub body: Pin<Box<dyn AsyncRead + Send>>,
}
impl Response {
    pub fn json(value: &impl Serialize) -> Result<Self, String> {
        let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
        if bytes.len() > JSON_LIMIT {
            return Err("JSON response exceeds 1 MiB".into());
        }
        Ok(Self::bytes(200, bytes))
    }
    pub fn error(status: u16, message: &str) -> Self {
        Self::bytes(
            status,
            serde_json::to_vec(&serde_json::json!({"error": message})).expect("JSON string"),
        )
    }
    fn bytes(status: u16, bytes: Vec<u8>) -> Self {
        Self {
            header: ResponseHeader {
                status,
                length: bytes.len() as u64,
                file_name: None,
            },
            body: Box::pin(std::io::Cursor::new(bytes)),
        }
    }
    pub fn stream(reader: impl AsyncRead + Send + 'static, length: u64, file_name: String) -> Self {
        Self {
            header: ResponseHeader {
                status: 200,
                length,
                file_name: Some(file_name),
            },
            body: Box::pin(reader),
        }
    }
}
type ServiceFuture = Pin<Box<dyn Future<Output = Response> + Send>>;
#[derive(Clone)]
pub struct Service {
    name: String,
    handler: Arc<dyn Fn(PeerKey, Request) -> ServiceFuture + Send + Sync>,
}
impl Service {
    pub fn new<F, Fut>(name: impl Into<String>, handler: F) -> Self
    where
        F: Fn(PeerKey, Request) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        Self {
            name: name.into(),
            handler: Arc::new(move |peer, request| Box::pin(handler(peer, request))),
        }
    }
}
#[derive(Default, Clone)]
pub struct Registry {
    services: HashMap<String, Service>,
}
impl Registry {
    pub fn register(&mut self, service: Service) -> Result<(), String> {
        if service.name.is_empty()
            || service.name.len() > 64
            || self.services.contains_key(&service.name)
        {
            return Err("invalid or duplicate service name".into());
        }
        self.services.insert(service.name.clone(), service);
        Ok(())
    }
}
async fn write_frame(
    writer: &mut SendStream,
    value: &impl Serialize,
    limit: usize,
) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("frame exceeds protocol limit".into());
    }
    tokio::time::timeout(IO_TIMEOUT, async {
        writer
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        writer.write_all(&bytes).await.map_err(|e| e.to_string())
    })
    .await
    .map_err(|_| "frame write timed out")?
}
async fn read_frame<T: serde::de::DeserializeOwned>(
    reader: &mut RecvStream,
    limit: usize,
    timeout: Duration,
) -> Result<T, String> {
    tokio::time::timeout(timeout, async {
        let mut size = [0; 4];
        reader
            .read_exact(&mut size)
            .await
            .map_err(|e| e.to_string())?;
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 || size > limit {
            return Err("frame exceeds protocol limit".into());
        }
        let mut bytes = vec![0; size];
        reader
            .read_exact(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        serde_json::from_slice(&bytes).map_err(|_| "invalid protocol JSON".into())
    })
    .await
    .map_err(|_| "frame read timed out")?
}

pub struct IncomingResponse {
    pub header: ResponseHeader,
    pub body: IncomingBody,
}
pub struct IncomingBody {
    recv: RecvStream,
    remaining: u64,
    connection: Connection,
}
impl AsyncRead for IncomingBody {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.remaining == 0 {
            let mut byte = [0];
            let mut probe = ReadBuf::new(&mut byte);
            return match Pin::new(&mut self.recv).poll_read(cx, &mut probe) {
                Poll::Ready(Ok(())) if probe.filled().is_empty() => Poll::Ready(Ok(())),
                Poll::Ready(Ok(())) => {
                    Poll::Ready(Err(io::Error::other("response exceeded announced size")))
                }
                other => other,
            };
        }
        let limit = buf
            .remaining()
            .min(self.remaining.min(usize::MAX as u64) as usize);
        let mut part = ReadBuf::new(&mut buf.initialize_unfilled()[..limit]);
        match Pin::new(&mut self.recv).poll_read(cx, &mut part) {
            Poll::Ready(Ok(())) => {
                let read = part.filled().len();
                if read == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "incomplete response",
                    )));
                }
                buf.advance(read);
                self.remaining -= read as u64;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl Drop for IncomingBody {
    fn drop(&mut self) {
        let _ = self.recv.stop(0u32.into());
        let _ = &self.connection;
    }
}
impl IncomingResponse {
    pub async fn json<T: serde::de::DeserializeOwned>(mut self) -> Result<T, String> {
        if self.header.length > JSON_LIMIT as u64 {
            return Err("JSON response exceeds 1 MiB".into());
        }
        let mut bytes = Vec::new();
        tokio::time::timeout(IO_TIMEOUT, self.body.read_to_end(&mut bytes))
            .await
            .map_err(|_| "JSON response timed out")?
            .map_err(|e| e.to_string())?;
        if self.header.status != 200 {
            return Err(format!(
                "peer returned {}: {}",
                self.header.status,
                String::from_utf8_lossy(&bytes)
            ));
        }
        serde_json::from_slice(&bytes).map_err(|_| "invalid peer JSON".into())
    }
}
impl Net {
    pub async fn request(
        &self,
        peer: PeerKey,
        request: Request,
    ) -> Result<IncomingResponse, String> {
        request.validate_size()?;
        let connection = self.connect(peer).await?;
        let (mut send, mut recv) =
            tokio::time::timeout(Duration::from_secs(10), connection.open_bi())
                .await
                .map_err(|_| "QUIC stream open timed out")?
                .map_err(|e| e.to_string())?;
        write_frame(&mut send, &request, REQUEST_LIMIT).await?;
        send.finish().map_err(|e| e.to_string())?;
        let header: ResponseHeader =
            read_frame(&mut recv, HEADER_LIMIT, RESPONSE_HEADER_TIMEOUT).await?;
        if !(200..=599).contains(&header.status)
            || header
                .file_name
                .as_ref()
                .is_some_and(|name| name.len() > 1024)
        {
            return Err("invalid response header".into());
        }
        if header.file_name.is_none() && header.length > JSON_LIMIT as u64 {
            return Err("JSON response exceeds 1 MiB".into());
        }
        Ok(IncomingResponse {
            body: IncomingBody {
                recv,
                remaining: header.length,
                connection,
            },
            header,
        })
    }
    pub async fn serve(
        &self,
        registry: Registry,
        shutdown: impl Future<Output = ()> + Send,
    ) -> Result<(), String> {
        self.serve_with_ready(registry, shutdown, || {}).await
    }
    /// Notify the owner only after the endpoint starts accepting service connections.
    pub async fn serve_with_ready(
        &self,
        registry: Registry,
        shutdown: impl Future<Output = ()> + Send,
        ready: impl FnOnce() + Send,
    ) -> Result<(), String> {
        self.health()?;
        if self.inner.serving.swap(true, Ordering::AcqRel) {
            return Err("QUIC service host already running".into());
        }
        struct Serving(Net);
        impl Drop for Serving {
            fn drop(&mut self) {
                self.0.inner.endpoint.set_alpns(Vec::new());
                self.0.inner.serving.store(false, Ordering::Release);
            }
        }
        let _guard = Serving(self.clone());
        self.inner.endpoint.set_alpns(vec![ALPN.to_vec()]);
        ready();
        let registry = Arc::new(registry);
        let slots = Arc::new(tokio::sync::Semaphore::new(128));
        let requests = Arc::new(tokio::sync::Semaphore::new(256));
        let mut tasks = tokio::task::JoinSet::new();
        tokio::pin!(shutdown);
        let result = loop {
            tokio::select! {
                _ = &mut shutdown => break Ok(()),
                incoming = self.inner.endpoint.accept() => {
                    let Some(incoming) = incoming else { break Err("QUIC endpoint stopped".into()); };
                    let Ok(slot) = slots.clone().try_acquire_owned() else { incoming.refuse(); continue; };
                    let net = self.clone(); let registry = registry.clone(); let requests = requests.clone();
                    tasks.spawn(async move {
                        let _slot = slot;
                        let Ok(Ok(connection)) = tokio::time::timeout(Duration::from_secs(10), incoming).await else { return; };
                        struct Close(Connection);
                        impl Drop for Close { fn drop(&mut self) { self.0.close(0u32.into(), b"service stopped"); } }
                        let _close = Close(connection.clone());
                        // Iroh exposes the identity authenticated by the completed TLS handshake.
                        let key = *connection.remote_id().as_bytes();
                        if net.track(key, connection.clone(), None).is_err() { return; }
                        let mut streams = tokio::task::JoinSet::new();
                        loop {
                            tokio::select! {
                                accepted = connection.accept_bi() => {
                                    let Ok((send, recv)) = accepted else { break; };
                                    let Ok(slot) = requests.clone().try_acquire_owned() else { let mut send = send; let mut recv = recv; let _ = send.reset(1u32.into()); let _ = recv.stop(1u32.into()); continue; };
                                    let registry = registry.clone(); let net = net.clone();
                                    streams.spawn(async move { let _slot = slot; let _ = serve_request(net, registry, key, send, recv).await; });
                                }
                                Some(_) = streams.join_next(), if !streams.is_empty() => {}
                            }
                        }
                        streams.abort_all();
                        while streams.join_next().await.is_some() {}
                    });
                }
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}
async fn serve_request(
    net: Net,
    registry: Arc<Registry>,
    peer: PeerKey,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), String> {
    let request: Request = read_frame(&mut recv, REQUEST_LIMIT, IO_TIMEOUT).await?;
    // A request is exactly one frame; no unbounded upload body is accepted by this protocol version.
    let mut trailing = [0];
    let extra = tokio::time::timeout(Duration::from_secs(10), recv.read(&mut trailing))
        .await
        .map_err(|_| "request did not finish")?
        .map_err(|e| e.to_string())?;
    if extra.is_some() {
        return Err("unexpected request body".into());
    }
    let mut response = if !net.has_peer(&peer) {
        Response::error(403, "peer revoked")
    } else if let Some(service) = registry.services.get(&request.service) {
        match tokio::time::timeout(SERVICE_TIMEOUT, (service.handler)(peer, request)).await {
            Ok(response) => response,
            Err(_) => Response::error(504, "service timed out"),
        }
    } else {
        Response::error(404, "unknown service")
    };
    write_frame(&mut send, &response.header, HEADER_LIMIT).await?;
    let mut remaining = response.header.length;
    let mut buffer = vec![0; 64 * 1024];
    while remaining > 0 {
        let size = buffer.len().min(remaining.min(usize::MAX as u64) as usize);
        let n = tokio::time::timeout(IO_TIMEOUT, response.body.read(&mut buffer[..size]))
            .await
            .map_err(|_| "response body stalled")?
            .map_err(io_error)
            .map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("response body ended early".into());
        }
        tokio::time::timeout(IO_TIMEOUT, send.write_all(&buffer[..n]))
            .await
            .map_err(|_| "response write stalled")?
            .map_err(|e| e.to_string())?;
        remaining -= n as u64;
    }
    send.finish().map_err(|e| e.to_string())?;
    Ok(())
}
