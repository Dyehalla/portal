use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Client, Method, StatusCode, Url, header};
use serde::{Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use crate::model::*;

const MAX_RESPONSE: usize = 4 * 1024 * 1024;

#[derive(Clone)]
pub struct CoordinatorClient {
    http: Client,
    base: Url,
    token: Arc<Zeroizing<String>>,
}

#[derive(Debug)]
pub enum ClientError {
    Unauthorized,
    Http(u16),
    Transport,
    Tls,
    Timeout,
    InvalidResponse,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => f.write_str("coordinator rejected device credentials"),
            Self::Http(code) => write!(f, "coordinator returned HTTP {code}"),
            Self::Transport => f.write_str("coordinator HTTPS request failed"),
            Self::Tls => f.write_str("coordinator TLS certificate was not accepted"),
            Self::Timeout => f.write_str("coordinator request timed out"),
            Self::InvalidResponse => f.write_str("invalid or oversized coordinator response"),
        }
    }
}
impl std::error::Error for ClientError {}

/// Validate and canonicalize an origin without constructing a TLS client.
pub fn coordinator_origin(address: &str) -> Result<String, String> {
    let base = Url::parse(address).map_err(|_| "invalid coordinator URL")?;
    if base.scheme() != "https"
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
        || base.path() != "/"
    {
        return Err(
            "coordinator URL must be an HTTPS origin without credentials, path, query or fragment"
                .into(),
        );
    }
    Ok(base.origin().ascii_serialization())
}

impl CoordinatorClient {
    pub fn new(address: &str, token: String, ca_file: Option<&Path>) -> Result<Self, String> {
        let token = Zeroizing::new(token);
        let base =
            Url::parse(&coordinator_origin(address)?).map_err(|_| "invalid coordinator URL")?;
        if !(token.starts_with("dev_") || token.starts_with("usr_"))
            || token.len() != 68
            || !token.as_bytes()[4..].iter().all(u8::is_ascii_hexdigit)
        {
            return Err("invalid coordinator token format".into());
        }
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut builder = Client::builder()
            .https_only(true)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(35));
        if let Some(path) = ca_file {
            let pem =
                std::fs::read(path).map_err(|e| format!("could not read coordinator CA: {e}"))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|_| "invalid coordinator CA PEM")?;
            if certs.is_empty() {
                return Err("coordinator CA file is empty".into());
            }
            builder = builder.tls_certs_only(certs);
        }
        Ok(Self {
            http: builder
                .build()
                .map_err(|_| "could not create coordinator HTTPS client")?,
            base,
            token: Arc::new(token),
        })
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<T, ClientError> {
        let bytes = Zeroizing::new(self.send(method, path, body).await?);
        serde_json::from_slice(&bytes).map_err(|_| ClientError::InvalidResponse)
    }

    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&impl Serialize>,
    ) -> Result<Vec<u8>, ClientError> {
        let url = self
            .base
            .join(path)
            .map_err(|_| ClientError::InvalidResponse)?;
        let mut auth = header::HeaderValue::from_str(&format!("Bearer {}", self.token.as_str()))
            .map_err(|_| ClientError::InvalidResponse)?;
        auth.set_sensitive(true);
        let mut request = self
            .http
            .request(method, url)
            .header(header::AUTHORIZATION, auth);
        if let Some(body) = body {
            request = request.json(body);
        }
        let mut response = request.send().await.map_err(|error| {
            if error.is_timeout() {
                return ClientError::Timeout;
            }
            use std::error::Error;
            let mut source = error.source();
            while let Some(cause) = source {
                if cause.downcast_ref::<rustls::Error>().is_some()
                    || cause
                        .downcast_ref::<std::io::Error>()
                        .and_then(|e| e.get_ref())
                        .is_some_and(|e| e.is::<rustls::Error>())
                {
                    return ClientError::Tls;
                }
                source = cause
                    .downcast_ref::<std::io::Error>()
                    .and_then(|e| {
                        e.get_ref()
                            .map(|inner| inner as &(dyn std::error::Error + 'static))
                    })
                    .or_else(|| cause.source());
            }
            ClientError::Transport
        })?;
        match response.status() {
            StatusCode::UNAUTHORIZED => return Err(ClientError::Unauthorized),
            status if !status.is_success() => return Err(ClientError::Http(status.as_u16())),
            _ => {}
        }
        if response
            .content_length()
            .is_some_and(|n| n > MAX_RESPONSE as u64)
        {
            return Err(ClientError::InvalidResponse);
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| ClientError::Transport)? {
            if bytes.len() + chunk.len() > MAX_RESPONSE {
                return Err(ClientError::InvalidResponse);
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Host from the authenticated HTTPS origin, for automatic STUN discovery.
    pub fn coordinator_host(&self) -> String {
        self.base
            .host_str()
            .expect("validated origin")
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned()
    }

    pub async fn register_user(&self, name: &str) -> Result<RegisteredUser, ClientError> {
        self.request(
            Method::POST,
            "/api/v1/registration",
            Some(&RegisterUser { name: name.into() }),
        )
        .await
    }

    pub async fn desired_policy(&self) -> Result<Option<DesiredPolicy>, ClientError> {
        self.request(Method::GET, "/api/v1/device/desired-policy", None::<&()>)
            .await
    }
    pub async fn acknowledge_policy(&self, revision: u64) -> Result<DesiredPolicy, ClientError> {
        self.request(
            Method::POST,
            "/api/v1/device/policy-ack",
            Some(&serde_json::json!({"revision":revision})),
        )
        .await
    }
    pub async fn owner_policy(&self, id: &str) -> Result<DesiredPolicy, ClientError> {
        Self::validate_id(id)?;
        self.request(
            Method::GET,
            &format!("/api/v1/devices/{id}/policy"),
            None::<&()>,
        )
        .await
    }
    pub async fn save_owner_policy(
        &self,
        id: &str,
        request: &PublishPolicy,
    ) -> Result<DesiredPolicy, ClientError> {
        Self::validate_id(id)?;
        self.request(
            Method::PUT,
            &format!("/api/v1/devices/{id}/policy"),
            Some(request),
        )
        .await
    }
    pub async fn rename_device(&self, id: &str, name: &str) -> Result<Device, ClientError> {
        Self::validate_id(id)?;
        self.request(
            Method::PUT,
            &format!("/api/v1/devices/{id}/name"),
            Some(&RegisterUser { name: name.into() }),
        )
        .await
    }
    pub async fn revoke_device(&self, id: &str) -> Result<(), ClientError> {
        Self::validate_id(id)?;
        self.send(
            Method::DELETE,
            &format!("/api/v1/devices/{id}"),
            None::<&()>,
        )
        .await
        .map(|_| ())
    }
    fn validate_id(id: &str) -> Result<(), ClientError> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(ClientError::InvalidResponse);
        }
        Ok(())
    }

    pub async fn me(&self) -> Result<User, ClientError> {
        self.request(Method::GET, "/api/v1/me", None::<&()>).await
    }

    pub async fn access_requests(&self) -> Result<Vec<AccessRequest>, ClientError> {
        self.request(Method::GET, "/api/v1/access-requests", None::<&()>)
            .await
    }
    pub async fn request_access(
        &self,
        request: &RequestAccess,
    ) -> Result<AccessRequest, ClientError> {
        self.request(Method::POST, "/api/v1/access-requests", Some(request))
            .await
    }
    pub async fn decide_access(
        &self,
        id: &str,
        accept: bool,
    ) -> Result<AccessRequest, ClientError> {
        Self::validate_id(id)?;
        self.request(
            Method::POST,
            &format!("/api/v1/access-requests/{id}/response"),
            Some(&DecideAccess { accept }),
        )
        .await
    }
    pub async fn devices(&self) -> Result<Vec<Device>, ClientError> {
        self.request(Method::GET, "/api/v1/devices", None::<&()>)
            .await
    }

    pub async fn enroll_device(
        &self,
        device: &RegisterDevice,
        access_token: &str,
    ) -> Result<RegisteredDevice, ClientError> {
        self.request(
            Method::POST,
            "/api/v1/enrollment",
            Some(&serde_json::json!({"device":device,"access_token":access_token})),
        )
        .await
    }

    pub async fn register_device(
        &self,
        request: &RegisterDevice,
    ) -> Result<RegisteredDevice, ClientError> {
        self.request(Method::POST, "/api/v1/devices", Some(request))
            .await
    }

    pub async fn network_map(
        &self,
        previous: Option<&NetworkMap>,
    ) -> Result<NetworkMap, ClientError> {
        let mut url = self
            .base
            .join("/api/v1/network-map")
            .expect("constant path");
        if let Some(map) = previous {
            url.query_pairs_mut()
                .append_pair("after", &map.revision.to_string())
                .append_pair("generation", &map.generation)
                .append_pair("wait_seconds", "25");
        }
        self.request(
            Method::GET,
            &format!(
                "{}{}",
                url.path(),
                url.query().map(|q| format!("?{q}")).unwrap_or_default()
            ),
            None::<&()>,
        )
        .await
    }

    pub async fn endpoints(
        &self,
        endpoints: Vec<std::net::SocketAddr>,
    ) -> Result<Device, ClientError> {
        self.request(
            Method::PUT,
            "/api/v1/device/endpoints",
            Some(&UpdateEndpoints { endpoints }),
        )
        .await
    }

    pub async fn publish_policy(
        &self,
        request: &PublishPolicy,
    ) -> Result<DevicePolicy, ClientError> {
        self.request(Method::PUT, "/api/v1/device/policy", Some(request))
            .await
    }

    pub async fn incoming(&self) -> Result<IncomingConnections, ClientError> {
        self.request(
            Method::GET,
            "/api/v1/p2p/requests?wait_seconds=25",
            None::<&()>,
        )
        .await
    }

    pub async fn connect(&self, peer_device_id: String) -> Result<ConnectionInfo, ClientError> {
        self.request(
            Method::POST,
            "/api/v1/p2p/requests",
            Some(&RequestConnection { peer_device_id }),
        )
        .await
    }

    pub async fn respond(
        &self,
        id: &str,
        accept: bool,
    ) -> Result<Option<ConnectionInfo>, ClientError> {
        if id.is_empty()
            || id.len() > 128
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(ClientError::InvalidResponse);
        }
        let body = self
            .send(
                Method::POST,
                &format!("/api/v1/p2p/requests/{id}/response"),
                Some(&RespondConnection { accept }),
            )
            .await?;
        if accept {
            serde_json::from_slice(&body)
                .map(Some)
                .map_err(|_| ClientError::InvalidResponse)
        } else {
            Ok(None)
        }
    }
}
