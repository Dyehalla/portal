use std::{future::Future, net::SocketAddr, pin::Pin};

/// Context shared with each service during startup.
#[derive(Clone)]
pub struct ServiceContext {
    pub network: portal_net::Net,
    pub http_address: SocketAddr,
}

pub(crate) type ServiceTask = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
type ServiceStartup = Pin<Box<dyn Future<Output = Result<ServiceRoutes, String>> + Send>>;
type ServiceFactory = Box<dyn FnOnce(ServiceContext) -> ServiceStartup + Send>;

/// A service supplies routes; the runtime owns its listener and tasks.
pub struct ServiceRoutes {
    pub(crate) router: axum::Router,
    pub(crate) background: Option<ServiceTask>,
}
impl ServiceRoutes {
    pub fn new(router: axum::Router) -> Self {
        Self {
            router,
            background: None,
        }
    }
    /// A background task must run until cancelled; early completion stops the host.
    pub fn with_background(
        mut self,
        task: impl Future<Output = Result<(), String>> + Send + 'static,
    ) -> Self {
        self.background = Some(Box::pin(task));
        self
    }
}

/// Register a built-in or application-provided service without changing the host.
pub struct ServiceRegistration {
    pub(crate) name: String,
    pub(crate) factory: ServiceFactory,
}
impl ServiceRegistration {
    pub fn new<F, Fut>(name: impl Into<String>, factory: F) -> Self
    where
        F: FnOnce(ServiceContext) -> Fut + Send + 'static,
        Fut: Future<Output = Result<ServiceRoutes, String>> + Send + 'static,
    {
        Self {
            name: name.into(),
            factory: Box::new(move |context| Box::pin(factory(context))),
        }
    }

    pub fn files(config: portal_files::FileServiceConfig) -> Self {
        Self::new("files", move |context| async move {
            let files = portal_files::FileRoutes::new(context.http_address, config).await?;
            Ok(ServiceRoutes::new(files.router()).with_background(files.maintain()))
        })
    }
}
