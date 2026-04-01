use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Redirect},
    routing::{delete, get, post},
    Json, Router,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, Key};
use base64::{engine::general_purpose, Engine as _};
use clap::Parser;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, RedirectUrl, Scope,
};
use serde::{Deserialize, Serialize};
use ssh_broker_proto::sshbroker::v1::{
    credential_service_client::CredentialServiceClient, session_service_client::SessionServiceClient, CloseSessionRequest, DeleteCredentialRequest, ExecRequest,
    ListCredentialsRequest, OpenSessionRequest,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tower::service_fn;
use tower_http::{cors::CorsLayer, services::ServeDir, trace::TraceLayer};
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Clone, Parser)]
#[command(name = "ssh-broker-ui", about = "UI service for ssh-broker (separate process; talks to broker over gRPC)")]
struct Args {
    /// HTTP bind address for the UI service.
    #[arg(long, env = "SSH_BROKER_UI_HTTP_ADDR", default_value = "127.0.0.1:8080")]
    http_addr: SocketAddr,

    /// Directory containing built UI static assets (e.g. ui-web/dist). If missing, only /api is served.
    #[arg(long, env = "SSH_BROKER_UI_STATIC_DIR", default_value = "ui-web/dist")]
    static_dir: PathBuf,

    /// Connect to broker via Unix domain socket (local mode).
    #[arg(long, env = "SSH_BROKER_UI_BROKER_UDS")]
    broker_uds: Option<PathBuf>,

    /// Connect to broker via TCP address, e.g. https://broker.example.com:7443 or http://127.0.0.1:7443.
    #[arg(long, env = "SSH_BROKER_UI_BROKER_ADDR", default_value = "http://127.0.0.1:7443")]
    broker_addr: String,

    /// mTLS: client certificate PEM (for remote broker).
    #[arg(long, env = "SSH_BROKER_UI_TLS_CERT")]
    tls_cert_path: Option<PathBuf>,
    /// mTLS: client private key PEM (for remote broker).
    #[arg(long, env = "SSH_BROKER_UI_TLS_KEY")]
    tls_key_path: Option<PathBuf>,
    /// mTLS: broker CA root PEM (for remote broker).
    #[arg(long, env = "SSH_BROKER_UI_TLS_CA")]
    tls_ca_path: Option<PathBuf>,

    /// Auth mode: "none" or "oidc".
    #[arg(long, env = "SSH_BROKER_UI_AUTH_MODE", default_value = "none")]
    auth_mode: String,

    /// 64-byte cookie key, base64 encoded (used to encrypt/sign cookies).
    /// Generate with: `openssl rand -base64 64`
    #[arg(long, env = "SSH_BROKER_UI_COOKIE_KEY_B64")]
    cookie_key_b64: Option<String>,

    /// OIDC issuer URL (required when auth_mode=oidc), e.g. https://accounts.google.com
    #[arg(long, env = "SSH_BROKER_UI_OIDC_ISSUER")]
    oidc_issuer: Option<String>,
    /// OIDC client id (required when auth_mode=oidc)
    #[arg(long, env = "SSH_BROKER_UI_OIDC_CLIENT_ID")]
    oidc_client_id: Option<String>,
    /// OIDC client secret (required when auth_mode=oidc)
    #[arg(long, env = "SSH_BROKER_UI_OIDC_CLIENT_SECRET")]
    oidc_client_secret: Option<String>,
    /// OIDC redirect URL (required when auth_mode=oidc), must point to /auth/callback
    #[arg(long, env = "SSH_BROKER_UI_OIDC_REDIRECT_URL")]
    oidc_redirect_url: Option<String>,

    #[arg(long, env = "RUST_LOG", default_value = "info")]
    log_filter: String,
}

#[derive(Clone)]
struct AppState {
    broker: Broker,
    auth: Auth,
    static_dir: PathBuf,
}

#[derive(Clone)]
struct Broker {
    channel: Channel,
}

#[derive(Clone)]
struct Auth {
    mode: AuthMode,
}

#[derive(Clone)]
enum AuthMode {
    None,
    Oidc {
        client: Arc<CoreClient>,
        cookie_key: Key,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct User {
    sub: String,
}

const COOKIE_USER: &str = "ssh_broker_ui_user";
const COOKIE_STATE: &str = "ssh_broker_ui_oidc_state";
const COOKIE_NONCE: &str = "ssh_broker_ui_oidc_nonce";

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(args.log_filter.clone())
        .init();

    let channel = connect_broker(&args).await?;
    let auth = init_auth(&args).await?;

    let state = AppState {
        broker: Broker { channel },
        auth,
        static_dir: args.static_dir.clone(),
    };

    let api = Router::new()
        .route("/health", get(api_health))
        .route("/credentials", get(api_list_credentials))
        .route("/credentials/:id", delete(api_delete_credential))
        .route("/sessions/open", post(api_open_session))
        .route("/sessions/exec", post(api_exec))
        .route("/sessions/close", post(api_close_session));

    let api = Router::new()
        .nest("/api", api)
        .layer(middleware::from_fn_with_state(state.clone(), require_auth_mw));

    let auth_routes = Router::new()
        .route("/auth/login", get(auth_login))
        .route("/auth/callback", get(auth_callback))
        .route("/auth/logout", get(auth_logout));

    let app = Router::new()
        .merge(auth_routes)
        .merge(api)
        .nest_service("/", ServeDir::new(&state.static_dir))
        .fallback(static_not_found)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    info!(addr = %args.http_addr, "ssh-broker-ui listening");
    let listener = tokio::net::TcpListener::bind(args.http_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn connect_broker(args: &Args) -> Result<Channel> {
    if let Some(uds) = &args.broker_uds {
        #[cfg(not(unix))]
        {
            let _ = uds;
            return Err(anyhow!("broker_uds is only supported on Unix platforms"));
        }
        #[cfg(unix)]
        {
            use tokio::net::UnixStream;
            use axum::http::Uri;

            let uds_path = uds.clone();
            // The URI is unused by the connector, but required by tonic.
            let endpoint = Endpoint::try_from("http://[::]:50051")?;
            let channel = endpoint
                .connect_with_connector(service_fn(move |_: Uri| UnixStream::connect(uds_path.clone())))
                .await
                .context("connect to broker over UDS")?;
            return Ok(channel);
        }
    }

    let mut endpoint = Endpoint::try_from(args.broker_addr.clone())?;
    if let (Some(cert_path), Some(key_path), Some(ca_path)) = (&args.tls_cert_path, &args.tls_key_path, &args.tls_ca_path) {
        let cert = tokio::fs::read(cert_path).await?;
        let key = tokio::fs::read(key_path).await?;
        let ca = tokio::fs::read(ca_path).await?;
        let tls = ClientTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(cert, key))
            .ca_certificate(tonic::transport::Certificate::from_pem(ca));
        endpoint = endpoint.tls_config(tls)?;
    }
    endpoint.connect().await.context("connect to broker over TCP")
}

async fn init_auth(args: &Args) -> Result<Auth> {
    match args.auth_mode.as_str() {
        "none" => Ok(Auth { mode: AuthMode::None }),
        "oidc" => {
            let issuer = args.oidc_issuer.clone().ok_or_else(|| anyhow!("missing SSH_BROKER_UI_OIDC_ISSUER"))?;
            let client_id = args
                .oidc_client_id
                .clone()
                .ok_or_else(|| anyhow!("missing SSH_BROKER_UI_OIDC_CLIENT_ID"))?;
            let client_secret = args
                .oidc_client_secret
                .clone()
                .ok_or_else(|| anyhow!("missing SSH_BROKER_UI_OIDC_CLIENT_SECRET"))?;
            let redirect_url = args
                .oidc_redirect_url
                .clone()
                .ok_or_else(|| anyhow!("missing SSH_BROKER_UI_OIDC_REDIRECT_URL"))?;
            let cookie_key_b64 = args
                .cookie_key_b64
                .clone()
                .ok_or_else(|| anyhow!("missing SSH_BROKER_UI_COOKIE_KEY_B64 (required for oidc mode)"))?;

            let key_bytes = general_purpose::STANDARD
                .decode(cookie_key_b64.trim())
                .context("decode cookie key base64")?;
            let cookie_key = Key::from(&key_bytes);

            let provider_metadata = CoreProviderMetadata::discover_async(IssuerUrl::new(issuer)?, async_http_client)
                .await
                .context("OIDC discovery")?;

            let client = CoreClient::from_provider_metadata(
                provider_metadata,
                ClientId::new(client_id),
                Some(ClientSecret::new(client_secret)),
            )
            .set_redirect_uri(RedirectUrl::new(redirect_url)?);

            Ok(Auth {
                mode: AuthMode::Oidc {
                    client: Arc::new(client),
                    cookie_key,
                },
            })
        }
        other => Err(anyhow!("unknown auth_mode: {other} (use 'none' or 'oidc')")),
    }
}

async fn require_auth_mw(State(state): State<AppState>, jar: CookieJar, req: axum::http::Request<axum::body::Body>, next: middleware::Next) -> axum::response::Response {
    match &state.auth.mode {
        AuthMode::None => next.run(req).await,
        AuthMode::Oidc { cookie_key, .. } => {
            let private = jar.private(cookie_key);
            if private.get(COOKIE_USER).is_some() {
                next.run(req).await
            } else {
                Redirect::to("/auth/login").into_response()
            }
        }
    }
}

async fn auth_login(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    match &state.auth.mode {
        AuthMode::None => Redirect::to("/").into_response(),
        AuthMode::Oidc { client, cookie_key } => {
            let state_token = CsrfToken::new(Uuid::new_v4().to_string());
            let nonce = Nonce::new(Uuid::new_v4().to_string());

            let (auth_url, _csrf_state, _nonce) = client
                .authorize_url(|| state_token.clone(), || nonce.clone())
                .add_scope(Scope::new("openid".to_string()))
                .add_scope(Scope::new("profile".to_string()))
                .add_scope(Scope::new("email".to_string()))
                .url();

            let jar = jar
                .private(cookie_key)
                .add(Cookie::new(COOKIE_STATE, state_token.secret().clone()))
                .add(Cookie::new(COOKIE_NONCE, nonce.secret().clone()));

            (jar, Redirect::to(auth_url.as_str())).into_response()
        }
    }
}

#[derive(Debug, Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

async fn auth_callback(State(state): State<AppState>, jar: CookieJar, axum::extract::Query(q): axum::extract::Query<CallbackQuery>) -> impl IntoResponse {
    match &state.auth.mode {
        AuthMode::None => Redirect::to("/").into_response(),
        AuthMode::Oidc { client, cookie_key } => {
            let private = jar.private(cookie_key);
            let expected_state = match private.get(COOKIE_STATE).map(|c| c.value().to_string()) {
                Some(s) => s,
                None => return (StatusCode::UNAUTHORIZED, "missing oidc state").into_response(),
            };
            let expected_nonce = match private.get(COOKIE_NONCE).map(|c| c.value().to_string()) {
                Some(s) => s,
                None => return (StatusCode::UNAUTHORIZED, "missing oidc nonce").into_response(),
            };
            if q.state != expected_state {
                return (StatusCode::UNAUTHORIZED, "oidc state mismatch").into_response();
            }

            let token = match client
                .exchange_code(AuthorizationCode::new(q.code))
                .request_async(async_http_client)
                .await
            {
                Ok(t) => t,
                Err(e) => return (StatusCode::UNAUTHORIZED, format!("token exchange failed: {e}")).into_response(),
            };

            let id_token = match token.extra_fields().id_token() {
                Some(t) => t,
                None => return (StatusCode::UNAUTHORIZED, "missing id_token").into_response(),
            };

            let verifier = client.id_token_verifier();
            let claims = match id_token.claims(&verifier, &Nonce::new(expected_nonce)) {
                Ok(c) => c,
                Err(e) => return (StatusCode::UNAUTHORIZED, format!("id_token verify failed: {e}")).into_response(),
            };

            let user = User {
                sub: claims.subject().as_str().to_string(),
            };
            let user_json = match serde_json::to_string(&user) {
                Ok(s) => s,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            };

            let jar = jar
                .private(cookie_key)
                .remove(Cookie::new(COOKIE_STATE, ""))
                .remove(Cookie::new(COOKIE_NONCE, ""))
                .add(Cookie::new(COOKIE_USER, user_json));

            (jar, Redirect::to("/")).into_response()
        }
    }
}

async fn auth_logout(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    match &state.auth.mode {
        AuthMode::None => Redirect::to("/").into_response(),
        AuthMode::Oidc { cookie_key, .. } => {
            let jar = jar.private(cookie_key).remove(Cookie::new(COOKIE_USER, ""));
            (jar, Redirect::to("/")).into_response()
        }
    }
}

async fn api_health() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn api_list_credentials(State(state): State<AppState>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = CredentialServiceClient::new(state.broker.channel.clone());
    let resp = client
        .list_credentials(ListCredentialsRequest {})
        .await
        .map_err(ApiError::grpc)?
        .into_inner();
    Ok(Json(serde_json::json!({ "credentials": resp.credentials })))
}

async fn api_delete_credential(State(state): State<AppState>, AxumPath(id): AxumPath<String>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = CredentialServiceClient::new(state.broker.channel.clone());
    client
        .delete_credential(DeleteCredentialRequest { credential_id: id })
        .await
        .map_err(ApiError::grpc)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
struct OpenSessionBody {
    credential_id: String,
    host: String,
    #[serde(default)]
    port: u32,
    #[serde(default)]
    username_override: String,
}

async fn api_open_session(State(state): State<AppState>, Json(body): Json<OpenSessionBody>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = SessionServiceClient::new(state.broker.channel.clone());
    let resp = client
        .open_session(OpenSessionRequest {
            credential_id: body.credential_id,
            host: body.host,
            port: if body.port == 0 { 22 } else { body.port },
            username_override: body.username_override,
        })
        .await
        .map_err(ApiError::grpc)?
        .into_inner();
    Ok(Json(serde_json::json!({ "session_id": resp.session_id })))
}

#[derive(Debug, Deserialize)]
struct ExecBody {
    session_id: String,
    command: String,
    #[serde(default)]
    timeout_ms: u32,
}

async fn api_exec(State(state): State<AppState>, Json(body): Json<ExecBody>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = SessionServiceClient::new(state.broker.channel.clone());
    let resp = client
        .exec(ExecRequest {
            session_id: body.session_id,
            command: body.command,
            timeout_ms: body.timeout_ms,
        })
        .await
        .map_err(ApiError::grpc)?
        .into_inner();
    Ok(Json(serde_json::json!({
        "exit_code": resp.exit_code,
        "stdout_b64": general_purpose::STANDARD.encode(resp.stdout),
        "stderr_b64": general_purpose::STANDARD.encode(resp.stderr),
    })))
}

#[derive(Debug, Deserialize)]
struct CloseBody {
    session_id: String,
}

async fn api_close_session(State(state): State<AppState>, Json(body): Json<CloseBody>) -> Result<Json<serde_json::Value>, ApiError> {
    let mut client = SessionServiceClient::new(state.broker.channel.clone());
    client
        .close_session(CloseSessionRequest { session_id: body.session_id })
        .await
        .map_err(ApiError::grpc)?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn static_not_found(State(state): State<AppState>) -> impl IntoResponse {
    // If the UI isn't built yet, be explicit.
    if !state.static_dir.exists() {
        return (StatusCode::NOT_FOUND, "UI not built (expected ui-web/dist)").into_response();
    }
    (StatusCode::NOT_FOUND, "not found").into_response()
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn grpc(e: tonic::Status) -> Self {
        let status = match e.code() {
            tonic::Code::NotFound => StatusCode::NOT_FOUND,
            tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
            tonic::Code::Unauthenticated | tonic::Code::PermissionDenied => StatusCode::UNAUTHORIZED,
            tonic::Code::ResourceExhausted => StatusCode::TOO_MANY_REQUESTS,
            tonic::Code::FailedPrecondition => StatusCode::PRECONDITION_FAILED,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: e.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let mut resp = Json(serde_json::json!({ "error": self.message })).into_response();
        *resp.status_mut() = self.status;
        resp
    }
}
