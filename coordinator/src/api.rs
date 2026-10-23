use crate::{
    config::Config,
    credentials::{self, Credential},
    database::Database,
    error::{Error, Result},
    models::*,
    poll::{KeyedLimiter, WaitUntilChange},
    signaling::Signaling,
    store::Store,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, FromRequestParts, Path, Query, Request, State},
    http::{HeaderValue, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post, put},
};
use axum_server::{Handle, tls_rustls::RustlsConfig};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use tokio::sync::Semaphore;

#[derive(Clone)]
struct ApiState {
    db: Database,
    lease_seconds: u64,
    requests: Arc<Semaphore>,
    map_polls: KeyedLimiter,
    incoming_polls: KeyedLimiter,
    signaling: Signaling,
}

impl ApiState {
    async fn call<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.db.call(operation).await
    }

    async fn network_map(&self, credential: Credential) -> Result<NetworkMap> {
        let lease_seconds = self.lease_seconds;
        self.call(move |store| store.network_map(credential, lease_seconds))
            .await
    }
}

#[derive(Clone, Copy)]
struct Auth(Credential);

#[axum::async_trait]
impl FromRequestParts<ApiState> for Auth {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, _state: &ApiState) -> Result<Self> {
        credentials::from_headers(&parts.headers).map(Self)
    }
}

/// One coordinator process owns one network. Packet forwarding belongs to agents.
pub struct Coordinator {
    listen: std::net::SocketAddr,
    tls: RustlsConfig,
    state: ApiState,
}

impl Coordinator {
    pub async fn open(config: Config) -> std::result::Result<Self, String> {
        config.validate()?;
        // Validate TLS before initializing persistent state or creating the admin account.
        let tls = RustlsConfig::from_pem_file(&config.tls.cert_file, &config.tls.key_file)
            .await
            .map_err(|e| format!("could not load coordinator TLS certificate/key: {e}"))?;
        let store_config = config.clone();
        let db =
            tokio::task::spawn_blocking(move || Store::open(&store_config).and_then(Database::new))
                .await
                .map_err(|_| "coordinator initialization failed".to_owned())??;
        let state = ApiState {
            db,
            lease_seconds: config.lease_seconds,
            requests: Arc::new(Semaphore::new(512)),
            map_polls: KeyedLimiter::new(256),
            incoming_polls: KeyedLimiter::new(128),
            signaling: Signaling::new(),
        };
        Ok(Self {
            listen: config.listen,
            tls,
            state,
        })
    }

    fn router(&self) -> Router {
        Router::new()
            .route("/health", get(health))
            .route("/api/v1/users", post(register_user).get(find_user))
            .route("/api/v1/me", get(me))
            .route("/api/v1/devices", post(register_device).get(devices))
            .route("/api/v1/devices/:id", axum::routing::delete(revoke_device))
            .route("/api/v1/devices/:id/token", post(rotate_device_token))
            .route("/api/v1/device", get(own_device))
            .route("/api/v1/device/endpoints", put(update_endpoints))
            .route("/api/v1/device/policy", put(publish_policy))
            .route("/api/v1/network-map", get(network_map))
            .route(
                "/api/v1/p2p/requests",
                post(request_connection).get(incoming_connections),
            )
            .route(
                "/api/v1/p2p/requests/:id/response",
                post(respond_connection),
            )
            .layer(DefaultBodyLimit::max(64 * 1024))
            .layer(middleware::from_fn_with_state(
                self.state.clone(),
                limit_requests,
            ))
            .with_state(self.state.clone())
    }

    /// Only compiled into the unit-test harness; production exposes TLS serving only.
    #[cfg(test)]
    pub(crate) fn test_router(&self) -> Router {
        self.router()
    }

    pub async fn serve(self, handle: Handle<std::net::SocketAddr>) -> std::io::Result<()> {
        axum_server::bind_rustls(self.listen, self.tls.clone())
            .handle(handle)
            .serve(self.router().into_make_service())
            .await
    }
}

async fn limit_requests(State(state): State<ApiState>, request: Request, next: Next) -> Response {
    let mut response = match state.requests.try_acquire() {
        Ok(_permit) => next.run(request).await,
        Err(_) => Error::busy().into_response(),
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn health(State(state): State<ApiState>) -> Result<Json<serde_json::Value>> {
    state.call(|store| store.revision()).await?;
    Ok(Json(
        serde_json::json!({"status":"ok", "protocol_version":PROTOCOL_VERSION}),
    ))
}

async fn register_user(
    State(state): State<ApiState>,
    Json(request): Json<RegisterUser>,
) -> Result<(StatusCode, Json<RegisteredUser>)> {
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .call(move |store| store.register_user(request))
                .await?,
        ),
    ))
}

async fn me(State(state): State<ApiState>, Auth(credential): Auth) -> Result<Json<User>> {
    Ok(Json(state.call(move |store| store.me(credential)).await?))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FindUser {
    name: String,
}

async fn find_user(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Query(query): Query<FindUser>,
) -> Result<Json<User>> {
    Ok(Json(
        state
            .call(move |store| store.find_user(credential, &query.name))
            .await?,
    ))
}

async fn register_device(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Json(request): Json<RegisterDevice>,
) -> Result<(StatusCode, Json<RegisteredDevice>)> {
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .call(move |store| store.register_device(credential, request))
                .await?,
        ),
    ))
}

async fn devices(
    State(state): State<ApiState>,
    Auth(credential): Auth,
) -> Result<Json<Vec<Device>>> {
    Ok(Json(
        state.call(move |store| store.devices(credential)).await?,
    ))
}

async fn own_device(State(state): State<ApiState>, Auth(credential): Auth) -> Result<Json<Device>> {
    Ok(Json(
        state
            .call(move |store| store.own_device(credential))
            .await?,
    ))
}

async fn revoke_device(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    state
        .call(move |store| store.revoke_device(credential, &id))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn rotate_device_token(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Path(id): Path<String>,
) -> Result<Json<IssuedToken>> {
    Ok(Json(
        state
            .call(move |store| store.rotate_device_token(credential, &id))
            .await?,
    ))
}

async fn update_endpoints(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Json(request): Json<UpdateEndpoints>,
) -> Result<Json<Device>> {
    Ok(Json(
        state
            .call(move |store| store.update_endpoints(credential, request))
            .await?,
    ))
}

async fn publish_policy(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Json(request): Json<PublishPolicy>,
) -> Result<Json<DevicePolicy>> {
    Ok(Json(
        state
            .call(move |store| store.publish_policy(credential, request))
            .await?,
    ))
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapQuery {
    after: Option<u64>,
    generation: Option<String>,
    wait_seconds: Option<u64>,
}

async fn network_map(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Query(query): Query<MapQuery>,
) -> Result<Json<NetworkMap>> {
    let mut wait = WaitUntilChange::new(
        query.wait_seconds,
        Duration::from_secs(state.lease_seconds / 2),
        state.db.subscribe(),
        None,
    )?;
    let snapshot = state.network_map(credential).await?;
    if wait.expired()
        || query.after != Some(snapshot.revision)
        || query.generation.as_deref() != Some(snapshot.generation.as_str())
    {
        return Ok(Json(snapshot));
    }
    let _permit = state.map_polls.acquire(credential.hash)?;
    Ok(Json(wait.recheck(|| state.network_map(credential)).await?))
}

async fn request_connection(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Json(request): Json<RequestConnection>,
) -> Result<Json<ConnectionInfo>> {
    let mut changes = state.db.subscribe();
    changes.borrow_and_update();
    let target_id = request.peer_device_id;
    let destination = target_id.clone();
    let context = state
        .call(move |store| store.prepare_connection(credential, &destination))
        .await?;
    let mut ticket = state.signaling.request(&context, credential)?;
    loop {
        let accepted = tokio::select! {
            result = &mut ticket.response => Some(result.map_err(|_| Error::internal())??),
            result = changes.changed() => {
                result.map_err(|_| Error::internal())?;
                None
            }
            _ = tokio::time::sleep_until(ticket.info.deadline) => return Err(Error::timeout()),
        };
        let destination = target_id.clone();
        // Revalidate on every registry/policy change and immediately before returning success.
        let context = state
            .call(move |store| store.prepare_connection(credential, &destination))
            .await?;
        if tokio::time::Instant::now() >= ticket.info.deadline {
            return Err(Error::timeout());
        }
        match accepted {
            Some(true) => {
                return Ok(Json(
                    context.for_requester(&ticket.info.id, ticket.info.expires_at),
                ));
            }
            Some(false) => return Err(Error::forbidden("peer declined the connection request")),
            None => {}
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IncomingQuery {
    wait_seconds: Option<u64>,
}

async fn incoming_connections(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Query(query): Query<IncomingQuery>,
) -> Result<Json<IncomingConnections>> {
    let mut wait = WaitUntilChange::new(
        query.wait_seconds,
        Duration::from_secs(25),
        state.db.subscribe(),
        Some(state.signaling.subscribe()),
    )?;
    let _permit = state.incoming_polls.acquire(credential.hash)?;
    let mut target = state
        .call(move |store| store.own_device(credential))
        .await?;
    loop {
        let mut requests = Vec::new();
        for pending in state.signaling.incoming(&target.id)? {
            let source_credential = pending.requester_credential;
            let target_id = pending.target_id.clone();
            match state
                .call(move |store| {
                    store.answer_connection(credential, source_credential, &target_id)
                })
                .await
            {
                Ok(context) => {
                    if tokio::time::Instant::now() < pending.deadline {
                        requests.push(context.for_target(&pending.id, pending.expires_at));
                    }
                }
                Err(error) => state.signaling.fail(&pending.id, error),
            }
        }
        // A changed credential must not receive signals from a previously authenticated poll.
        state
            .call(move |store| store.own_device(credential))
            .await?;
        if !requests.is_empty() || wait.expired() {
            return Ok(Json(IncomingConnections { requests }));
        }
        target = wait
            .recheck(|| state.call(move |store| store.own_device(credential)))
            .await?;
    }
}

async fn respond_connection(
    State(state): State<ApiState>,
    Auth(credential): Auth,
    Path(id): Path<String>,
    Json(response): Json<RespondConnection>,
) -> Result<Response> {
    let pending = state.signaling.get(&id)?;
    let target_id = pending.target_id.clone();
    let context = state
        .call(move |store| {
            store.answer_connection(credential, pending.requester_credential, &target_id)
        })
        .await?;
    state
        .signaling
        .respond(&id, &context.target.id, response.accept)?;
    if response.accept {
        Ok(Json(context.for_target(&id, pending.expires_at)).into_response())
    } else {
        Ok(StatusCode::NO_CONTENT.into_response())
    }
}
