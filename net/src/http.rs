use super::{Net, TcpListener};
use hyper::Uri;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tower::{Service, ServiceExt};

pub async fn serve_http(
    mut listener: TcpListener,
    router: axum::Router,
    shutdown: impl Future<Output = ()> + Send,
) -> io::Result<()> {
    tokio::pin!(shutdown);
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, remote) = accepted?;
                let router = router.clone();
                tasks.spawn(async move {
                    let service = hyper::service::service_fn(move |mut request| {
                        request.extensions_mut().insert(axum::extract::ConnectInfo(remote));
                        router.clone().oneshot(request)
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
    // Closing service sessions cancels pending IO without waiting on remote peers.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}
pub struct Connection(Box<dyn Stream>);
impl AsyncRead for Connection {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_read(cx, buf)
    }
}
impl AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.0).poll_shutdown(cx)
    }
}
impl hyper_util::client::legacy::connect::Connection for Connection {
    fn connected(&self) -> hyper_util::client::legacy::connect::Connected {
        hyper_util::client::legacy::connect::Connected::new()
    }
}
#[derive(Clone, Default)]
pub struct Connector {
    pub network: Option<Net>,
}
impl Service<Uri> for Connector {
    type Response = TokioIo<Connection>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;
    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, uri: Uri) -> Self::Future {
        let network = self.network.clone();
        Box::pin(async move {
            if uri.scheme_str() != Some("http") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "only HTTP transport is supported",
                ));
            }
            let host = uri
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing host"))?
                .trim_matches(['[', ']']);
            let port = uri.port_u16().unwrap_or(80);
            let stream: Box<dyn Stream> = match network {
                Some(net) => {
                    let ip = host.parse().map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "virtual connections require an IP address",
                        )
                    })?;
                    Box::new(net.connect(std::net::SocketAddr::new(ip, port)).await?)
                }
                None => Box::new(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        tokio::net::TcpStream::connect((host, port)),
                    )
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out")
                    })??,
                ),
            };
            Ok(TokioIo::new(Connection(stream)))
        })
    }
}
