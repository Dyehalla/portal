use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::codegen::Service;
use tonic::server::NamedService;
use tonic::service::{Routes, RoutesBuilder};
use tonic::transport::Server;

/// Collect peer-facing RPC handlers and bind their shared gRPC listener.
pub(crate) struct GrpcServer {
    address: SocketAddr,
    routes: RoutesBuilder,
    service_count: usize,
}

/// Own a bound gRPC listener and the routes that runtime registered on it.
pub(crate) struct BoundGrpcServer {
    listener: TcpListener,
    routes: Routes,
    address: SocketAddr,
}

impl GrpcServer {
    /// Create a gRPC server builder for the requested peer-facing address.
    pub(crate) fn new(address: SocketAddr) -> Self {
        Self {
            address,
            routes: Routes::builder(),
            service_count: 0,
        }
    }

    /// Register a tonic service so it shares this server's listener with other runtime services.
    pub(crate) fn add_service<S>(&mut self, service: S)
    where
        S: Service<
                tonic::codegen::http::Request<tonic::body::BoxBody>,
                Response = tonic::codegen::http::Response<tonic::body::BoxBody>,
                Error = Infallible,
            > + NamedService
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
    {
        self.routes.add_service(service);
        self.service_count += 1;
    }

    /// Bind the listener before startup completes and capture its actual local address.
    pub(crate) async fn bind(self) -> Result<BoundGrpcServer, String> {
        if self.service_count == 0 {
            return Err("cannot start gRPC server without any registered services".into());
        }
        let listener = TcpListener::bind(self.address)
            .await
            .map_err(|error| format!("could not bind gRPC listener {}: {error}", self.address))?;
        let address = listener
            .local_addr()
            .map_err(|error| format!("could not inspect gRPC listener: {error}"))?;

        Ok(BoundGrpcServer {
            listener,
            routes: self.routes.routes(),
            address,
        })
    }
}

impl BoundGrpcServer {
    /// Return the address selected for the bound gRPC listener.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.address
    }

    /// Serve every registered RPC until runtime asks tonic to shut down gracefully.
    pub(crate) async fn serve_with_shutdown<F>(self, shutdown: F) -> Result<(), String>
    where
        F: Future<Output = ()>,
    {
        Server::builder()
            .add_routes(self.routes)
            .serve_with_incoming_shutdown(TcpListenerStream::new(self.listener), shutdown)
            .await
            .map_err(|error| format!("gRPC server failed: {error}"))
    }
}
