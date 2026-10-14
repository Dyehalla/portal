use std::{future::Future, pin::Pin};

/// Context shared with each service during startup.
#[derive(Clone)]
pub struct ServiceContext {
    pub network: portal_net::Net,
}

pub(crate) type ServiceTask = Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;
type ServiceStartup = Pin<Box<dyn Future<Output = Result<ServiceImplementation, String>> + Send>>;
type ServiceFactory = Box<dyn FnOnce(ServiceContext) -> ServiceStartup + Send>;

/// A service supplies a native QUIC operation handler; the runtime owns the endpoint and tasks.
pub struct ServiceImplementation {
    pub(crate) service: portal_net::Service,
    pub(crate) background: Option<ServiceTask>,
}
impl ServiceImplementation {
    pub fn new(service: portal_net::Service) -> Self {
        Self {
            service,
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
        Fut: Future<Output = Result<ServiceImplementation, String>> + Send + 'static,
    {
        Self {
            name: name.into(),
            factory: Box::new(move |context| Box::pin(factory(context))),
        }
    }

    pub fn files(config: portal_files::FileServiceConfig) -> Self {
        Self::new("files", move |context| async move {
            let _ = context;
            let files = portal_files::FileService::new(config).await?;
            Ok(ServiceImplementation::new(files.service()))
        })
    }
}
