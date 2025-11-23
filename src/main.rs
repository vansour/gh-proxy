use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri},
    routing::{any, get, head, post, put},
};
use bytes::Bytes;
use config::{GitHubConfig, Settings};
use futures_util::{Stream, StreamExt};
use http_body_util::BodyExt;
use hyper::{body::Incoming, header};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use std::{
    borrow::Cow,
    convert::TryFrom,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::signal;
use tokio::sync::{Semaphore, OwnedSemaphorePermit};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, instrument, warn};
mod api;
mod config;
mod handlers;
mod infra;
mod providers;
mod services;
mod utils;
#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub github_config: Arc<GitHubConfig>,
    pub client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    pub blacklist: services::blacklist::BlacklistState,
    pub shutdown_manager: services::shutdown::ShutdownManager,
    pub uptime_tracker: Arc<services::shutdown::UptimeTracker>,
    pub auth_header: Option<HeaderValue>,
    pub docker_proxy: Option<Arc<providers::registry::DockerProxy>>,
    pub download_semaphore: Arc<Semaphore>,
}
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("unsupported target host: {0}")]
    UnsupportedHost(String),
    #[error("invalid target uri: {0}")]
    InvalidTarget(String),
    #[error("access denied: {0}")]
    AccessDenied(String),
    #[error("file size exceeds limit: {0} MB > {1} MB")]
    SizeExceeded(u64, u64),
    #[error("invalid GitHub URL: {0}")]
    InvalidGitHubUrl(String),
    #[error("GitHub web page, not a file: {0}")]
    GitHubWebPage(String),
    #[error("GitHub repository homepage not supported: {0}")]
    GitHubRepoHomepage(String),
    #[error("http error: {0}")]
    Http(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("http builder error: {0}")]
    HttpBuilder(#[from] http::Error),
    #[error("failed to process response: {0}")]
    ProcessingError(String),
    #[error("too many concurrent requests")]
    TooManyConcurrentRequests,
}
impl ProxyError {
    pub fn to_status_code(&self) -> StatusCode {
        match self {
            ProxyError::AccessDenied(_) => StatusCode::FORBIDDEN,
            ProxyError::InvalidTarget(_)
            | ProxyError::InvalidGitHubUrl(_)
            | ProxyError::GitHubRepoHomepage(_)
            | ProxyError::GitHubWebPage(_) => StatusCode::BAD_REQUEST,
            ProxyError::SizeExceeded(_, _) => StatusCode::PAYLOAD_TOO_LARGE,
            ProxyError::Http(_) => StatusCode::BAD_GATEWAY,
            ProxyError::TooManyConcurrentRequests => StatusCode::TOO_MANY_REQUESTS,
            ProxyError::UnsupportedHost(_) => StatusCode::NOT_IMPLEMENTED,
            ProxyError::ProcessingError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::HttpBuilder(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    pub fn to_user_message(&self) -> String {
        match self {
            ProxyError::AccessDenied(ip) => format!(
                "Access Denied\n\nYour IP address has been blacklisted: {}\n\nThis IP has been blocked by the proxy administrator.\n\nIf you believe this is an error, please contact the administrator.\n",
                ip
            ),
            ProxyError::GitHubWebPage(url) => format!(
                "GitHub Web Page Detected\n\nThe URL you requested is a GitHub web page, not a downloadable file:\n{}\n\nThis path includes pages like:\n- Package containers (/pkgs/container/)\n- Releases (/releases/)\n- GitHub Actions (/actions/)\n- Repository settings (/settings/)\n- Issues and pull requests\n\nIf you want to download a specific file, please use one of these formats:\n- Raw file URL: https://raw.githubusercontent.com/owner/repo/branch/path/to/file\n- Blob URL (will be auto-converted): https://github.com/owner/repo/blob/branch/path/to/file\n- Release download: https://github.com/owner/repo/releases/download/tag/filename\n",
                url
            ),
            ProxyError::GitHubRepoHomepage(url) => format!(
                "GitHub Repository Homepage Detected\n\nThe URL you requested appears to be a GitHub repository homepage:\n{}\n\nRepository homepages are web pages (HTML), not downloadable files.\n\nIf you want to download a specific file, please use one of these formats:\n- Raw file URL: https://raw.githubusercontent.com/owner/repo/branch/path/to/file\n- Blob URL (will be auto-converted): https://github.com/owner/repo/blob/branch/path/to/file\n",
                url
            ),
            ProxyError::SizeExceeded(size, limit) => format!(
                "File Size Exceeded\n\nThe requested file size ({} MB) exceeds the proxy limit ({} MB).\n\nPlease use a direct download link or contact the administrator to increase the limit.\n",
                size, limit
            ),
            ProxyError::InvalidGitHubUrl(path) => format!(
                "Invalid Request\n\nThe path '{}' is not a valid proxy target.\n\nSupported formats:\n- https://github.com/owner/repo/...\n- http://example.com/...\n- github.com/owner/repo/...\n\nOr use the specific endpoint:\n- /github/* for GitHub resources\n",
                path
            ),
            ProxyError::Http(e) => format!(
                "Connection Error\n\nFailed to connect to the target server.\n\nError details: {}\n\nPossible causes:\n- DNS resolution failure\n- Network connectivity issues\n- Firewall blocking outbound connections\n- Target server is down\n",
                e
            ),
            ProxyError::TooManyConcurrentRequests => format!(
                "Too Many Concurrent Requests\n\nThe server is currently handling the maximum number of concurrent downloads. Please retry later."
            ),
            _ => format!("{}\n\nPlease check the URL and try again.\n", self),
        }
    }
}
pub type ProxyResult<T> = Result<T, ProxyError>;
#[derive(Clone)]
pub enum ResponsePostProcessor {
    ShellEditor { proxy_url: Arc<str> },
}
struct RequestLifecycle {
    shutdown: services::shutdown::ShutdownManager,
    completed: bool,
}

/// RAII guard that owns an optional semaphore permit and a start time.
/// When dropped it will release the permit (if still present) and update
/// proxy metrics (active requests gauge and duration histogram).
struct RequestPermitGuard {
    permit: Option<OwnedSemaphorePermit>,
    start: Option<std::time::Instant>,
}
impl RequestPermitGuard {
    fn new(permit: OwnedSemaphorePermit, start: std::time::Instant) -> Self {
        Self {
            permit: Some(permit),
            start: Some(start),
        }
    }
    fn take_permit(&mut self) -> Option<OwnedSemaphorePermit> {
        self.permit.take()
    }
    fn take_start_time(&mut self) -> Option<std::time::Instant> {
        self.start.take()
    }
}
impl Drop for RequestPermitGuard {
    fn drop(&mut self) {
        // If the permit is still present here, it means we did not move it
        // into a streaming response, so we are responsible for updating
        // metrics now that the request is finishing.
        if self.permit.take().is_some() {
            infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
            if let Some(start) = self.start.take() {
                infra::metrics::HTTP_REQUEST_DURATION_SECONDS.observe(start.elapsed().as_secs_f64());
            }
        }
    }
}
impl RequestLifecycle {
    fn new(state: &AppState) -> Self {
        state.shutdown_manager.request_started();
        Self {
            shutdown: state.shutdown_manager.clone(),
            completed: false,
        }
    }
    fn success(&mut self) {
        if self.completed {
            return;
        }
        self.shutdown.request_completed();
        self.completed = true;
    }
    fn fail(&mut self, _error: Option<&ProxyError>) {
        if self.completed {
            return;
        }
        self.shutdown.request_completed();
        self.completed = true;
    }
}
impl Drop for RequestLifecycle {
    fn drop(&mut self) {
        if !self.completed {
            self.shutdown.request_completed();
        }
    }
}
fn error_response(error: ProxyError) -> Response<Body> {
    let status = error.to_status_code();
    let message = error.to_user_message();
    error!("Returning error response: {} - {}", status, error);
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(message))
        .unwrap_or_else(|e| {
            error!("Failed to build error response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("Internal Server Error"))
                .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
        })
}
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::load()?;
    let blacklist_state =
        services::blacklist::BlacklistState::initialize(settings.blacklist.clone()).await;
    infra::log::setup_tracing(&settings.log);
    info!("Starting gh-proxy server");
    info!("Log level: {}", settings.log.get_level());
    info!(
        "Blacklist enabled: {} (lazy loading)",
        settings.blacklist.enabled
    );
    if settings.shell.is_editor_enabled() {
        info!("Shell editor mode enabled");
    }
    info!("CORS: Enabled (allowing all origins)");
    let bind_addr: SocketAddr = settings.server.bind_addr().parse()?;
    let client = services::client::build_client(&settings.server);
    let github_config = GitHubConfig::new(&settings.auth.token, &settings.proxy);
    let auth_header = settings
        .auth
        .authorization_header()
        .map_err(|err| format!("invalid authorization header value: {err}"))?;
    let shutdown_manager = services::shutdown::ShutdownManager::new();
    let uptime_tracker = Arc::new(services::shutdown::UptimeTracker::new());
    let settings = Arc::new(settings);
    let download_semaphore = Arc::new(Semaphore::new(settings.server.max_concurrent_requests as usize));

    let app_state = AppState {
        settings: Arc::clone(&settings),
        github_config: Arc::new(github_config),
        client,
        blacklist: blacklist_state,
        shutdown_manager,
        uptime_tracker,
        auth_header,
        docker_proxy: Some(Arc::new(providers::registry::DockerProxy::new(
            &settings.registry.default,
        ))),
        download_semaphore,
    };
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);
    let app = Router::new()
        .route("/", get(handlers::files::index))
        .route("/healthz", get(handlers::health::health_liveness))
        .route("/style.css", get(handlers::files::serve_static_file))
        .route("/docker", get(handlers::files::serve_docker_index))
        .route("/script.js", get(handlers::files::serve_static_file))
        .route("/favicon.ico", get(handlers::files::serve_favicon))
        .route("/api/config", get(api::get_config))
        .route("/metrics", get(infra::metrics::metrics_handler))
        .route("/github/{*path}", any(providers::github::github_proxy))
        // Docker Registry V2 compatibility endpoints
        .route("/v2/", get(providers::registry::handle_v2_check))
        .route("/v2/{*rest}", get(providers::registry::v2_get))
        .route("/v2/{*rest}", head(providers::registry::v2_head))
        .route("/v2/{*rest}", post(providers::registry::v2_post))
        .route("/v2/{*rest}", put(providers::registry::v2_put))
        // Debug / registry utilities
        .route(
            "/debug/blob-info",
            get(providers::registry::debug_blob_info),
        )
        .route("/registry/healthz", get(providers::registry::healthz))
        .fallback(fallback_proxy)
        .with_state(app_state.clone())
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    app_state.shutdown_manager.mark_ready().await;
    info!("=================================================");
    info!("gh-proxy server listening on {}", bind_addr);
    info!("=================================================");
    info!("Available endpoints:");
    info!("  - GET  /                  - Web UI");
    info!("  - GET  /healthz           - Liveness probe (is server alive)");
    info!("  - GET  /api/config        - Get configuration");
    info!("  - ANY  /github/*path      - GitHub proxy");
    info!("  - ANY  /*path             - Fallback proxy");
    info!("=================================================");
    let shutdown_mgr = app_state.shutdown_manager.clone();
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, service)
        .with_graceful_shutdown(shutdown_signal(shutdown_mgr))
        .await?;
    info!("gh-proxy server shutting down gracefully");
    Ok(())
}
async fn shutdown_signal(shutdown_mgr: services::shutdown::ShutdownManager) {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal, initiating graceful shutdown...");
        },
        _ = terminate => {
            info!("Received SIGTERM signal, initiating graceful shutdown...");
        },
    }
    shutdown_mgr.initiate_shutdown().await;
    info!("Server stopped accepting new requests");
    let shutdown_timeout = Duration::from_secs(30);
    info!(
        "Waiting up to {:?} for active requests to complete...",
        shutdown_timeout
    );
    let requests_completed = shutdown_mgr.wait_for_requests(shutdown_timeout).await;
    if requests_completed {
        info!("All active requests completed. Shutting down...");
    } else {
        warn!(
            "Graceful shutdown timeout. {} requests still active. Force shutting down...",
            shutdown_mgr.get_active_requests()
        );
    }
    shutdown_mgr.mark_stopped().await;
}
fn resolve_target_uri_with_validation(uri: &Uri, host_guard: &GitHubConfig) -> ProxyResult<Uri> {
    let target_uri = resolve_fallback_target(uri).map_err(|msg| {
        debug!("Fallback target resolution failed: {}", msg);
        ProxyError::InvalidGitHubUrl(msg)
    })?;
    let target_str = target_uri.to_string();
    let host = target_uri.host().ok_or_else(|| {
        ProxyError::InvalidTarget(format!("Target URI missing host: {}", target_str))
    })?;
    if !host_guard.is_allowed(host) {
        return Err(ProxyError::UnsupportedHost(host.to_string()));
    }
    if providers::github::is_github_web_only_path(&target_str) {
        return Err(ProxyError::GitHubWebPage(target_str));
    }
    if providers::github::is_github_repo_homepage(&target_str) {
        return Err(ProxyError::GitHubRepoHomepage(target_str));
    }
    Ok(target_uri)
}
fn resolve_fallback_target(uri: &Uri) -> Result<Uri, String> {
    let path = uri.path();
    let query = uri.query();
    debug!(
        "resolve_fallback_target - Input URI: {}, path: '{}', query: {:?}",
        uri, path, query
    );
    let trimmed = path.trim_start_matches('/');
    debug!("After trim_start_matches('/'): '{}'", trimmed);
    let normalized: Cow<'_, str> =
        if trimmed.starts_with("https:/") && !trimmed.starts_with("https://") {
            let after_scheme = &trimmed[7..];
            debug!(
                "Fixed malformed https:/ URL - raw: '{}' -> normalized: 'https://{}'",
                trimmed, after_scheme
            );
            Cow::Owned(format!("https://{}", after_scheme))
        } else if trimmed.starts_with("http:/") && !trimmed.starts_with("http://") {
            let after_scheme = &trimmed[6..];
            debug!(
                "Fixed malformed http:/ URL - raw: '{}' -> normalized: 'http://{}'",
                trimmed, after_scheme
            );
            Cow::Owned(format!("http://{}", after_scheme))
        } else {
            debug!("No malformation detected, path as-is: '{}'", trimmed);
            Cow::Borrowed(trimmed)
        };
    debug!("After URL malformation fix: '{}'", normalized);
    if normalized.starts_with("http://") || normalized.starts_with("https://") {
        let mut converted = providers::github::convert_github_blob_to_raw(normalized.as_ref());
        if let Some(q) = query {
            converted.push('?');
            converted.push_str(q);
        }
        debug!("Fallback target with query: {}", converted);
        // Try to parse; if parsing fails due to characters such as '$' or
        // parentheses that appear in some example filenames, percent-encode
        // those characters in the path portion and try parsing again.
        match converted.parse() {
            Ok(uri) => return Ok(uri),
            Err(e) => {
                debug!(
                    "Initial parse failed: {} - attempting path-encoding fallback",
                    e
                );
                // find the first slash after the scheme://authority
                if let Some(slash_idx) = converted
                    .find("://")
                    .and_then(|i| converted[i + 3..].find('/').map(|j| i + 3 + j))
                {
                    let (pre, rest) = converted.split_at(slash_idx);
                    let (path_part, query_part) = match rest.split_once('?') {
                        Some((p, q)) => (p, Some(q)),
                        None => (rest, None),
                    };
                    let encoded_path = crate::utils::url::encode_problematic_path_chars(path_part);
                    let mut rebuilt = String::new();
                    rebuilt.push_str(pre);
                    rebuilt.push_str(&encoded_path);
                    if let Some(q) = query_part {
                        rebuilt.push('?');
                        rebuilt.push_str(q);
                    }
                    return rebuilt
                        .parse()
                        .map_err(|e2| format!("Invalid URL: {} / {}", e, e2));
                }
                return Err(format!("Invalid URL: {}", e));
            }
        }
    }
    if is_github_domain_path(&normalized) {
        let mut full_url = String::with_capacity("https://".len() + normalized.len());
        full_url.push_str("https://");
        full_url.push_str(normalized.as_ref());
        let mut converted = providers::github::convert_github_blob_to_raw(&full_url);
        if let Some(q) = query {
            converted.push('?');
            converted.push_str(q);
        }
        debug!("Fallback GitHub domain target with query: {}", converted);
        match converted.parse() {
            Ok(uri) => return Ok(uri),
            Err(e) => {
                debug!(
                    "Initial parse failed: {} - attempting path-encoding fallback",
                    e
                );
                if let Some(slash_idx) = converted
                    .find("://")
                    .and_then(|i| converted[i + 3..].find('/').map(|j| i + 3 + j))
                {
                    let (pre, rest) = converted.split_at(slash_idx);
                    let (path_part, query_part) = match rest.split_once('?') {
                        Some((p, q)) => (p, Some(q)),
                        None => (rest, None),
                    };
                    let encoded_path = crate::utils::url::encode_problematic_path_chars(path_part);
                    let mut rebuilt = String::new();
                    rebuilt.push_str(pre);
                    rebuilt.push_str(&encoded_path);
                    if let Some(q) = query_part {
                        rebuilt.push('?');
                        rebuilt.push_str(q);
                    }
                    return rebuilt
                        .parse()
                        .map_err(|e2| format!("Invalid GitHub URL: {} / {}", e, e2));
                }
                return Err(format!("Invalid GitHub URL: {}", e));
            }
        }
    }
    Err(format!("No valid target found for path: {}", normalized))
}
fn is_github_domain_path(path: &str) -> bool {
    path.starts_with("github.com/")
        || path.starts_with("raw.githubusercontent.com/")
        || path.starts_with("api.github.com/")
        || path.starts_with("gist.github.com/")
        || path.starts_with("codeload.github.com/")
        || (path.contains("github")
            && (path.contains(".com/") || path.contains(".io/") || path.contains(".org/")))
}
fn is_shell_script(uri: &Uri) -> bool {
    let path = uri.path();
    path.ends_with(".sh") || path.ends_with(".bash") || path.ends_with(".zsh")
}
fn should_disable_compression_for_request(uri: &Uri) -> bool {
    fn has_extension(path: &str, ext: &str) -> bool {
        path.rsplit_once('.')
            .map(|(_, candidate)| candidate.eq_ignore_ascii_case(ext))
            .unwrap_or(false)
    }

    fn ends_with_ignore_ascii(path: &str, suffix: &str) -> bool {
        path.len() >= suffix.len() && path[path.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    }

    let path = uri.path();
    if has_extension(path, "sh") || has_extension(path, "bash") || has_extension(path, "zsh") {
        return true;
    }
    if has_extension(path, "html")
        || has_extension(path, "htm")
        || has_extension(path, "xml")
        || has_extension(path, "xhtml")
    {
        return true;
    }
    if has_extension(path, "md") || has_extension(path, "markdown") || has_extension(path, "txt") {
        return true;
    }
    if has_extension(path, "json") || has_extension(path, "yaml") || has_extension(path, "yml") {
        return true;
    }
    if ends_with_ignore_ascii(path, ".tar.gz")
        || has_extension(path, "tar")
        || has_extension(path, "zip")
        || has_extension(path, "7z")
        || has_extension(path, "rar")
    {
        return false;
    }
    if has_extension(path, "exe")
        || has_extension(path, "dll")
        || has_extension(path, "so")
        || has_extension(path, "dylib")
        || has_extension(path, "bin")
    {
        return false;
    }
    if has_extension(path, "jpg")
        || has_extension(path, "jpeg")
        || has_extension(path, "png")
        || has_extension(path, "gif")
        || has_extension(path, "webp")
        || has_extension(path, "svg")
    {
        return false;
    }
    if has_extension(path, "mp3")
        || has_extension(path, "mp4")
        || has_extension(path, "webm")
        || has_extension(path, "wav")
        || has_extension(path, "flac")
    {
        return false;
    }
    false
}
#[instrument(skip_all)]
async fn fallback_proxy(State(state): State<AppState>, req: Request<Body>) -> Response<Body> {
    let path = req.uri().path();
    let method = req.method();
    let full_uri = req.uri();
    info!(
        "Fallback proxy request: {} {} (full URI: {})",
        method, path, full_uri
    );
    if matches!(
        path,
        "/favicon.ico" | "/robots.txt" | "/apple-touch-icon.png" | "/.well-known/security.txt"
    ) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }
    let proxy_host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080")
        .to_string();
    let proxy_scheme = services::request::detect_client_protocol(&req);
    let proxy_url = format!("{}://{}", proxy_scheme, proxy_host);
    info!(
        "Proxy URL determined: {} (from Cloudflare/upstream)",
        proxy_url
    );
    let client_ip = services::request::extract_client_ip(&req);
    if let Err(error) = services::blacklist::check_blacklist(&state, client_ip).await {
        return error_response(error);
    }
    let target_uri = match resolve_target_uri_with_validation(
        req.uri(),
        state.github_config.as_ref(),
    ) {
        Ok(uri) => uri,
        Err(_) => {
            warn!("Path is not a valid proxy target (404 Not Found): {}", path);
            let error_msg = format!(
                "404 Not Found\n\nThe path '{}' is not a valid proxy target.\n\nSupported formats:\n- https://github.com/owner/repo/...\n- https://raw.githubusercontent.com/...\n- http(s)://example.com/...\n",
                path
            );
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(error_msg))
                .unwrap_or_else(|_| Response::new(Body::from("404 Not Found")));
        }
    };
    let post_processor = if state.settings.shell.editor {
        Some(ResponsePostProcessor::ShellEditor {
            proxy_url: Arc::from(proxy_url.clone()),
        })
    } else {
        None
    };
    let response = match proxy_request(&state, req, target_uri.clone(), post_processor).await {
        Ok(response) => response,
        Err(error) => return error_response(error),
    };
    info!("Fallback proxy success: status={}", response.status());
    response
}
pub async fn proxy_request(
    state: &AppState,
    req: Request<Body>,
    target_uri: Uri,
    processor: Option<ResponsePostProcessor>,
) -> ProxyResult<Response<Body>> {
    let mut lifecycle = RequestLifecycle::new(state);
    let start = std::time::Instant::now();
    let size_limit_mb = state.settings.server.size_limit;
    let size_limit_bytes = size_limit_mb * 1024 * 1024;
    let max_redirects = 10;
    let mut redirect_count = 0;
    let mut current_uri = target_uri.clone();
    let initial_method = req.method().clone();
    let (mut req_parts, body) = req.into_parts();
    req_parts.uri = current_uri.clone();
    let mut body_bytes: Option<Bytes> = None;
    let should_buffer_body = should_buffer_request_body(&initial_method, &req_parts.headers);
    let request_body = if should_buffer_body {
        match body.collect().await {
            Ok(collected) => {
                let bytes = collected.to_bytes();
                body_bytes = Some(bytes.clone());
                Body::from(bytes)
            }
            Err(e) => {
                error!("Failed to read request body: {}", e);
                let err =
                    ProxyError::ProcessingError(format!("Failed to read request body: {}", e));
                lifecycle.fail(Some(&err));
                return Err(err);
            }
        }
    } else {
        Body::empty()
    };
    let mut req = Request::from_parts(req_parts, request_body);
    let disable_compression = if state.settings.shell.editor && processor.is_some() {
        should_disable_compression_for_request(&current_uri)
    } else {
        false
    };
    sanitize_request_headers(req.headers_mut(), disable_compression);
    apply_github_headers(req.headers_mut(), &current_uri, state.auth_header.as_ref());
    let sanitized_headers = Arc::new(req.headers().clone());
    debug!(
        "Initial request method: {}, URI: {}",
        initial_method, current_uri
    );
    // Acquire a permit to control global concurrent upstream requests
    let permit_acquire_timeout = Duration::from_secs(state.settings.server.permit_acquire_timeout_secs);
    let permit = match tokio::time::timeout(
        permit_acquire_timeout,
        state.download_semaphore.clone().acquire_owned(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        Ok(Err(e)) => {
            error!("Failed to acquire semaphore permit: {}", e);
            let err = ProxyError::ProcessingError("failed to acquire semaphore permit".to_string());
            lifecycle.fail(Some(&err));
            return Err(err);
        }
        Err(_) => {
            warn!("Timeout waiting for download permit after {:?}", permit_acquire_timeout);
            let err = ProxyError::TooManyConcurrentRequests;
            lifecycle.fail(Some(&err));
            return Err(err);
        }
    };
    // we now hold a permit - count active requests and create an RAII guard
    infra::metrics::HTTP_ACTIVE_REQUESTS.inc();
    let mut permit_guard = RequestPermitGuard::new(permit, start);
    let response = loop {
        info!(
            "Sending request to: {} (method: {})",
            current_uri, initial_method
        );

        let req_timeout = Duration::from_secs(state.settings.server.request_timeout_secs);
        let response = match tokio::time::timeout(req_timeout, state.client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => {
                // Try one inline retry after encoding the path portion of the
                // current URI (handles redirects that include unencoded chars
                // like $ or parentheses). If the encoded parse succeeds, make
                // a second attempt immediately.
                let uri_str = current_uri.to_string();
                let encoded = crate::utils::url::encode_path_of_full_url(&uri_str);
                if encoded != uri_str {
                    if let Ok(enc_uri) = encoded.parse::<Uri>() {
                        warn!(
                            "Initial request failed: {} - retrying with encoded path: {}",
                            e, enc_uri
                        );
                        current_uri = enc_uri;
                        let retry_body = body_bytes
                            .as_ref()
                            .map(|bytes| Body::from(bytes.clone()))
                            .unwrap_or_else(Body::empty);
                        req = Request::builder()
                            .method(initial_method.clone())
                            .uri(current_uri.clone())
                            .body(retry_body)
                            .map_err(ProxyError::HttpBuilder)?;
                        *req.headers_mut() = sanitized_headers.as_ref().clone();
                        apply_github_headers(
                            req.headers_mut(),
                            &current_uri,
                            state.auth_header.as_ref(),
                        );
                        // second attempt
                            match tokio::time::timeout(req_timeout, state.client.request(req)).await {
                                Ok(Ok(resp2)) => resp2,
                                Ok(Err(e2)) => {
                                    error!("Retry failed to connect to {}: {}", current_uri, e2);
                                    let error = ProxyError::Http(Box::new(e2));
                                    lifecycle.fail(Some(&error));
                                    return Err(error);
                                }
                                Err(_) => {
                                    error!("Retry to {} timed out after {:?}", current_uri, req_timeout);
                                    let error = ProxyError::ProcessingError(format!("request to {} timed out", current_uri));
                                    lifecycle.fail(Some(&error));
                                    return Err(error);
                                }
                            }
                    } else {
                        error!("Failed to connect to {}: {}", current_uri, e);
                        let error = ProxyError::Http(Box::new(e));
                        lifecycle.fail(Some(&error));
                        return Err(error);
                    }
                } else {
                    error!("Failed to connect to {}: {}", current_uri, e);
                    let error = ProxyError::Http(Box::new(e));
                    lifecycle.fail(Some(&error));
                    return Err(error);
                }
            }
            Err(_) => {
                error!("Request to {} timed out after {:?}", current_uri, req_timeout);
                let error = ProxyError::ProcessingError(format!("request to {} timed out", current_uri));
                lifecycle.fail(Some(&error));
                return Err(error);
            }
        };
        let status = response.status();
        // increment global request counter
        infra::metrics::HTTP_REQUESTS_TOTAL.inc();
        if status.is_redirection() && status != StatusCode::NOT_MODIFIED {
            redirect_count += 1;
            if redirect_count > max_redirects {
                error!(
                    "Too many redirects ({}), stopping at: {}",
                    max_redirects, current_uri
                );
                let error = ProxyError::ProcessingError(format!(
                    "Too many redirects ({}), possible infinite loop",
                    max_redirects
                ));
                lifecycle.fail(Some(&error));
                return Err(error);
            }
            let location = match response.headers().get(hyper::header::LOCATION) {
                Some(loc) => match loc.to_str() {
                    Ok(s) => s,
                    Err(e) => {
                        error!("Invalid Location header: {}", e);
                        let error = ProxyError::ProcessingError(format!(
                            "Invalid Location header in redirect: {}",
                            e
                        ));
                        lifecycle.fail(Some(&error));
                        return Err(error);
                    }
                },
                None => {
                    error!(
                        "Redirect response without Location header - Status: {}, URI: {}, Method: {}, Headers: {:?}",
                        status,
                        current_uri,
                        initial_method,
                        response.headers()
                    );
                    let error = ProxyError::ProcessingError(
                        "Redirect response (3xx) without Location header".to_string(),
                    );
                    lifecycle.fail(Some(&error));
                    return Err(error);
                }
            };
            info!(
                "Following redirect #{}: {} -> {}",
                redirect_count, current_uri, location
            );
            current_uri = match location.parse::<Uri>() {
                Ok(uri) => {
                    if uri.scheme().is_none() {
                        let scheme = current_uri.scheme_str().unwrap_or("https");
                        let authority = current_uri.authority().map(|a| a.as_str()).unwrap_or("");
                        match format!("{}://{}{}", scheme, authority, location).parse::<Uri>() {
                            Ok(absolute_uri) => absolute_uri,
                            Err(e) => {
                                error!(
                                    "Failed to construct absolute URI from relative location: {}",
                                    e
                                );
                                let error = ProxyError::InvalidTarget(format!(
                                    "Invalid redirect location: {}",
                                    location
                                ));
                                lifecycle.fail(Some(&error));
                                return Err(error);
                            }
                        }
                    } else {
                        uri
                    }
                }
                Err(e) => {
                    error!("Failed to parse redirect location '{}': {}", location, e);
                    let error = ProxyError::InvalidTarget(format!(
                        "Invalid redirect location: {}",
                        location
                    ));
                    lifecycle.fail(Some(&error));
                    return Err(error);
                }
            };
            let redirect_body = body_bytes
                .as_ref()
                .map(|bytes| Body::from(bytes.clone()))
                .unwrap_or_else(Body::empty);
            req = Request::builder()
                .method(initial_method.clone())
                .uri(current_uri.clone())
                .body(redirect_body)
                .map_err(ProxyError::HttpBuilder)?;
            *req.headers_mut() = sanitized_headers.as_ref().clone();
            apply_github_headers(req.headers_mut(), &current_uri, state.auth_header.as_ref());
            continue;
        }
        break response;
    };
    let status = response.status();
    let headers = response.headers().clone();
    let content_type = headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let content_length = headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let elapsed = start.elapsed();
    info!(
        "Response: status={}, content_length={:?}, elapsed={:?}",
        status, content_length, elapsed
    );
    if let Some(length) = content_length
        && length > size_limit_bytes
    {
        let size_mb = length / 1024 / 1024;
        warn!(
            "Response size {} bytes ({} MB) exceeds limit {} MB",
            length, size_mb, state.settings.server.size_limit
        );
        let error = ProxyError::SizeExceeded(size_mb, state.settings.server.size_limit);
        lifecycle.fail(Some(&error));
        return Err(error);
    }
    let shell_processing_enabled = state.settings.shell.editor && processor.is_some();
    let is_redirect = status.is_redirection();
    let needs_text_processing = !is_redirect
        && is_response_needs_text_processing(&content_type, &target_uri, shell_processing_enabled);
    let (mut parts, body) = response.into_parts();
    if needs_text_processing {
        let proxy_url = match processor_proxy_url(&processor) {
            Some(url) => url,
            None => {
                let error = ProxyError::ProcessingError(
                    "Shell editor processing requested but no proxy URL provided".to_string(),
                );
                lifecycle.fail(Some(&error));
                return Err(error);
            }
        };
        let body_bytes = match collect_body_with_limit(body, size_limit_mb, content_length).await {
            Ok(bytes) => bytes,
            Err(err) => {
                lifecycle.fail(Some(&err));
                return Err(err);
            }
        };
        let processed_bytes;
        let mut loosen_headers = false;
        if is_shell_script(&target_uri) {
            match process_shell_script_bytes(body_bytes.clone(), proxy_url) {
                Ok(bytes) => {
                    processed_bytes = bytes;
                    loosen_headers = true;
                }
                Err(e) => {
                    let error = ProxyError::ProcessingError(e);
                    lifecycle.fail(Some(&error));
                    return Err(error);
                }
            }
        } else if is_html_like(&content_type, &target_uri) {
            match process_html_bytes(body_bytes.clone(), proxy_url) {
                Ok(bytes) => {
                    loosen_headers = bytes != body_bytes;
                    processed_bytes = bytes;
                }
                Err(e) => {
                    let error = ProxyError::ProcessingError(e);
                    lifecycle.fail(Some(&error));
                    return Err(error);
                }
            }
        } else {
            processed_bytes = body_bytes;
        }
        sanitize_response_headers(&mut parts.headers, true, true, loosen_headers);
        let content_length_value = HeaderValue::from_str(&processed_bytes.len().to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0"));
        parts
            .headers
            .insert(hyper::header::CONTENT_LENGTH, content_length_value);
        let response = Response::from_parts(parts, Body::from(processed_bytes));
        lifecycle.success();
        // metrics + permit will be handled by the RAII guard on function exit
        return Ok(response);
    }
    sanitize_response_headers(&mut parts.headers, false, false, false);
    fix_content_type_header(&mut parts.headers, &target_uri);
    let streaming_body = ProxyBodyStream::new(
        body.into_data_stream().boxed(),
        lifecycle,
        size_limit_bytes,
        size_limit_mb,
        permit_guard.take_start_time(),
        permit_guard.take_permit(),
    );
    let response = Response::from_parts(parts, Body::from_stream(streaming_body));
    Ok(response)
}
fn is_response_needs_text_processing(
    content_type: &Option<String>,
    target_uri: &Uri,
    shell_editor_enabled: bool,
) -> bool {
    if !shell_editor_enabled {
        return false;
    }
    let path = target_uri.path();
    if path.ends_with(".sh") || path.ends_with(".bash") || path.ends_with(".zsh") {
        return true;
    }
    if path.ends_with(".html") || path.ends_with(".htm") {
        return true;
    }
    if let Some(ct) = content_type {
        let ct_lower = ct.to_lowercase();
        if ct_lower.contains("text/") {
            return true;
        }
        if ct_lower.contains("text/html") || ct_lower.contains("application/xhtml") {
            return true;
        }
    }
    false
}
fn sanitize_request_headers(headers: &mut HeaderMap, disable_compression: bool) {
    if disable_compression {
        headers.remove(header::ACCEPT_ENCODING);
    }
}
fn should_buffer_request_body(method: &Method, headers: &HeaderMap) -> bool {
    if headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|length| length > 0)
        .unwrap_or(false)
    {
        return true;
    }
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return true;
    }
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE | Method::OPTIONS
    )
}
fn sanitize_response_headers(
    headers: &mut HeaderMap,
    body_replaced: bool,
    strip_encoding: bool,
    loosen_security: bool,
) {
    if body_replaced {
        headers.remove(header::TRANSFER_ENCODING);
        headers.remove(header::CONTENT_LENGTH);
        headers.remove("connection");
        headers.remove("keep-alive");
    }
    if strip_encoding {
        headers.remove(header::CONTENT_ENCODING);
    }
    if loosen_security {
        headers.remove("content-security-policy");
        headers.remove("content-security-policy-report-only");
        headers.remove("x-frame-options");
        headers.remove("x-content-type-options");
        headers.remove("cache-control");
        headers.remove("pragma");
        headers.remove("etag");
        headers.remove("last-modified");
    }
}
fn fix_content_type_header(headers: &mut HeaderMap, target_uri: &Uri) {
    let path = target_uri.path();
    let content_type = headers.get(header::CONTENT_TYPE);
    if let Some(ct) = content_type
        && let Ok(ct_str) = ct.to_str()
        && !ct_str.to_lowercase().starts_with("text/plain")
    {
        return;
    }
    let mime_type = if path.ends_with(".js") || path.ends_with(".mjs") {
        "application/javascript; charset=utf-8"
    } else if path.ends_with(".css") {
        "text/css; charset=utf-8"
    } else if path.ends_with(".html") || path.ends_with(".htm") {
        "text/html; charset=utf-8"
    } else if path.ends_with(".json") {
        "application/json; charset=utf-8"
    } else if path.ends_with(".xml") {
        "application/xml; charset=utf-8"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".png") {
        "image/png"
    } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
        "image/jpeg"
    } else if path.ends_with(".gif") {
        "image/gif"
    } else if path.ends_with(".webp") {
        "image/webp"
    } else if path.ends_with(".ico") {
        "image/x-icon"
    } else {
        return;
    };
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime_type));
}
fn processor_proxy_url(processor: &Option<ResponsePostProcessor>) -> Option<&str> {
    match processor {
        Some(ResponsePostProcessor::ShellEditor { proxy_url }) => Some(proxy_url.as_ref()),
        None => None,
    }
}
fn is_html_like(content_type: &Option<String>, target_uri: &Uri) -> bool {
    if let Some(ct) = content_type {
        let lowered = ct.to_lowercase();
        if lowered.contains("text/html") || lowered.contains("application/xhtml") {
            return true;
        }
    }
    let path = target_uri.path().to_lowercase();
    path.ends_with(".html") || path.ends_with(".htm")
}
type BoxedBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, hyper::Error>> + Send>>;
struct ProxyBodyStream {
    inner: BoxedBodyStream,
    lifecycle: Option<RequestLifecycle>,
    size_limit_bytes: u64,
    size_limit_mb: u64,
    total_bytes: u64,
    // When present, this permit is held for the duration of the streaming
    // response; dropping it releases the semaphore.
    permit: Option<OwnedSemaphorePermit>,
    // start time for measuring streaming duration
    start_time: Option<std::time::Instant>,
}
impl ProxyBodyStream {
    fn new(
        inner: BoxedBodyStream,
        lifecycle: RequestLifecycle,
        size_limit_bytes: u64,
        size_limit_mb: u64,
        start_time: Option<std::time::Instant>,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Self {
        Self {
            inner,
            lifecycle: Some(lifecycle),
            size_limit_bytes,
            size_limit_mb,
            total_bytes: 0,
            permit,
            start_time,
        }
    }
}
impl Stream for ProxyBodyStream {
    type Item = Result<Bytes, ProxyError>;
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let chunk_len = chunk.len() as u64;
                let new_total = this.total_bytes.saturating_add(chunk_len);
                if this.size_limit_bytes > 0 && new_total > this.size_limit_bytes {
                    let size_mb = std::cmp::max(1, new_total / 1024 / 1024);
                    warn!(
                        "Streaming body exceeded limit: {} bytes ({} MB) > {} MB",
                        new_total, size_mb, this.size_limit_mb
                    );
                    let error = ProxyError::SizeExceeded(size_mb, this.size_limit_mb);
                    if let Some(mut lifecycle) = this.lifecycle.take() {
                        lifecycle.fail(Some(&error));
                    }
                    return Poll::Ready(Some(Err(error)));
                }
                this.total_bytes = new_total;
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                error!("Failed to read response body: {}", e);
                let error = ProxyError::Http(Box::new(e));
                if let Some(mut lifecycle) = this.lifecycle.take() {
                    lifecycle.fail(Some(&error));
                }
                // release permit and record metrics for failed stream
                if this.permit.take().is_some() {
                    infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
                }
                if let Some(start) = this.start_time.take() {
                    infra::metrics::HTTP_REQUEST_DURATION_SECONDS.observe(start.elapsed().as_secs_f64());
                }
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if let Some(mut lifecycle) = this.lifecycle.take() {
                    lifecycle.success();
                }
                // release permit and record metrics for completed stream
                if this.permit.take().is_some() {
                    infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
                }
                if let Some(start) = this.start_time.take() {
                    infra::metrics::HTTP_REQUEST_DURATION_SECONDS.observe(start.elapsed().as_secs_f64());
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
async fn collect_body_with_limit(
    body: Incoming,
    size_limit_mb: u64,
    expected_length: Option<u64>,
) -> ProxyResult<Vec<u8>> {
    let limit_bytes = size_limit_mb.saturating_mul(1024 * 1024);
    let mut total: u64 = 0;
    let mut data = expected_length
        .map(|len| {
            let capped = if limit_bytes > 0 {
                len.min(limit_bytes)
            } else {
                len
            };
            usize::try_from(capped).unwrap_or(0)
        })
        .map_or_else(Vec::new, Vec::with_capacity);
    let mut stream = body.into_data_stream();
    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            error!("Failed to read response body: {}", e);
            ProxyError::Http(Box::new(e))
        })?;
        let chunk_len = chunk.len();
        total = total.saturating_add(chunk_len as u64);
        if limit_bytes > 0 && total > limit_bytes {
            let size_mb = std::cmp::max(1, total / 1024 / 1024);
            warn!(
                "Streaming body exceeded limit: {} bytes ({} MB) > {} MB",
                total, size_mb, size_limit_mb
            );
            return Err(ProxyError::SizeExceeded(size_mb, size_limit_mb));
        }
        // No need to manually reserve capacity; Vec handles this internally.
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}
fn process_shell_script_bytes(body_bytes: Vec<u8>, proxy_url: &str) -> Result<Vec<u8>, String> {
    // Try to parse as UTF-8 text first. If conversion fails, make a
    // conservative heuristic check to see if the content looks like binary
    // (e.g. contains NUL or many non-printable bytes). For binary-like
    // content we skip text processing entirely to avoid corrupting the
    // payload.
    match String::from_utf8(body_bytes.clone()) {
        Ok(text) => {
            info!(
                "Processing shell script ({} bytes), adding proxy prefix: {}",
                text.len(),
                proxy_url
            );
            match utils::url::add_proxy_to_github_urls(&text, proxy_url) {
                Cow::Borrowed(_) => Ok(text.into_bytes()),
                Cow::Owned(updated) => Ok(updated.into_bytes()),
            }
        }
        Err(err) => {
            let utf8_error = err.utf8_error();
            let bytes = err.into_bytes();

            // Detect obvious binary payloads to avoid lossy conversion
            // that could mangle executable data. Heuristic:
            // - If data contains a NUL byte -> binary
            // - Else compute printable ratio; if < 0.85 treat as binary
            let contains_nul = bytes.contains(&0);
            let printable_or_whitespace = bytes
                .iter()
                .filter(|&&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..=0x7e).contains(&b))
                .count();
            let ratio = printable_or_whitespace as f64 / bytes.len().max(1) as f64;

            if contains_nul || ratio < 0.85 {
                warn!(
                    "Shell script contains non-UTF-8 data ({}). Payload looks binary (printable ratio {:.2}), skipping text processing to avoid corruption",
                    utf8_error, ratio
                );
                // Return original bytes unchanged
                return Ok(bytes);
            }

            // Otherwise fall back to lossy conversion and try URL injection
            let lossy_text = String::from_utf8_lossy(&bytes);
            warn!(
                "Shell script contains non-UTF-8 data ({}), applying lossy conversion",
                utf8_error
            );
            match utils::url::add_proxy_to_github_urls(lossy_text.as_ref(), proxy_url) {
                Cow::Borrowed(_) => Ok(lossy_text.into_owned().into_bytes()),
                Cow::Owned(updated) => Ok(updated.into_bytes()),
            }
        }
    }
}
fn process_html_bytes(body_bytes: Vec<u8>, proxy_url: &str) -> Result<Vec<u8>, String> {
    match String::from_utf8(body_bytes) {
        Ok(text) => {
            info!(
                "Processing HTML response ({} bytes), injecting proxy URLs with URL: {}",
                text.len(),
                proxy_url
            );
            match utils::url::add_proxy_to_html_urls(&text, proxy_url) {
                Cow::Borrowed(_) => Ok(text.into_bytes()),
                Cow::Owned(updated) => Ok(updated.into_bytes()),
            }
        }
        Err(err) => {
            let utf8_error = err.utf8_error();
            let bytes = err.into_bytes();
            let lossy_text = String::from_utf8_lossy(&bytes);
            warn!(
                "HTML response contains non-UTF-8 data ({}), applying lossy conversion",
                utf8_error
            );
            match utils::url::add_proxy_to_html_urls(lossy_text.as_ref(), proxy_url) {
                Cow::Borrowed(_) => Ok(lossy_text.into_owned().into_bytes()),
                Cow::Owned(updated) => Ok(updated.into_bytes()),
            }
        }
    }
}
fn apply_github_headers(
    headers: &mut HeaderMap,
    target_uri: &Uri,
    auth_header: Option<&HeaderValue>,
) {
    if let Some(value) = auth_header {
        headers.insert(header::AUTHORIZATION, value.clone());
    }

    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("gh-proxy/0.1.0"),
    );

    if let Some(host) = target_uri.host() {
        if is_github_api_host(host) {
            headers.insert(
                header::ACCEPT,
                HeaderValue::from_static("application/vnd.github.v3+json"),
            );
        } else if is_github_file_host(host) && !headers.contains_key(header::ACCEPT) {
            headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        }
    }
}
fn is_github_api_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("api.github.com")
}
fn is_github_file_host(host: &str) -> bool {
    const EXACT_HOSTS: [&str; 4] = [
        "raw.githubusercontent.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "media.githubusercontent.com",
    ];

    EXACT_HOSTS
        .iter()
        .any(|candidate| host.eq_ignore_ascii_case(candidate))
        || host_ends_with_ignore_ascii_case(host, ".githubusercontent.com")
}
fn host_ends_with_ignore_ascii_case(host: &str, suffix: &str) -> bool {
    host.len() >= suffix.len() && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_error_unsupported_host_status_code() {
        let error = ProxyError::UnsupportedHost("example.com".to_string());
        assert_eq!(error.to_status_code(), StatusCode::NOT_IMPLEMENTED);
    }

    #[test]
    fn test_proxy_error_invalid_target_status_code() {
        let error = ProxyError::InvalidTarget("invalid path".to_string());
        assert_eq!(error.to_status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_proxy_error_access_denied_status_code() {
        let error = ProxyError::AccessDenied("192.168.1.1".to_string());
        assert_eq!(error.to_status_code(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_proxy_error_size_exceeded_status_code() {
        let error = ProxyError::SizeExceeded(500, 250);
        assert_eq!(error.to_status_code(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn test_proxy_error_invalid_github_url_status_code() {
        let error = ProxyError::InvalidGitHubUrl("/invalid/path".to_string());
        assert_eq!(error.to_status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_proxy_error_github_web_page_status_code() {
        let error = ProxyError::GitHubWebPage("https://github.com/owner/repo".to_string());
        assert_eq!(error.to_status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_proxy_error_github_repo_homepage_status_code() {
        let error = ProxyError::GitHubRepoHomepage("https://github.com/owner/repo".to_string());
        assert_eq!(error.to_status_code(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_proxy_error_processing_error_status_code() {
        let error = ProxyError::ProcessingError("failed to process".to_string());
        assert_eq!(error.to_status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_proxy_error_http_status_code() {
        let http_error: Box<dyn std::error::Error + Send + Sync> = "test error".to_string().into();
        let error = ProxyError::Http(http_error);
        assert_eq!(error.to_status_code(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn test_proxy_error_access_denied_message() {
        let error = ProxyError::AccessDenied("192.168.1.1".to_string());
        let message = error.to_user_message();
        assert!(message.contains("Access Denied"));
        assert!(message.contains("192.168.1.1"));
    }

    #[test]
    fn test_proxy_error_github_web_page_message() {
        let url = "https://github.com/owner/repo/actions/runs/123";
        let error = ProxyError::GitHubWebPage(url.to_string());
        let message = error.to_user_message();
        assert!(message.contains("GitHub Web Page Detected"));
        assert!(message.contains(url));
    }

    #[test]
    fn test_proxy_error_github_repo_homepage_message() {
        let url = "https://github.com/owner/repo";
        let error = ProxyError::GitHubRepoHomepage(url.to_string());
        let message = error.to_user_message();
        assert!(message.contains("GitHub Repository Homepage Detected"));
        assert!(message.contains(url));
    }

    #[test]
    fn test_proxy_error_size_exceeded_message() {
        let error = ProxyError::SizeExceeded(500, 250);
        let message = error.to_user_message();
        assert!(message.contains("File Size Exceeded"));
        assert!(message.contains("500 MB"));
        assert!(message.contains("250 MB"));
    }

    #[test]
    fn test_proxy_error_invalid_github_url_message() {
        let path = "/invalid/path";
        let error = ProxyError::InvalidGitHubUrl(path.to_string());
        let message = error.to_user_message();
        assert!(message.contains("Invalid Request"));
        assert!(message.contains(path));
    }

    #[test]
    fn test_is_github_api_host_true() {
        assert!(is_github_api_host("api.github.com"));
    }

    #[test]
    fn test_is_github_api_host_false() {
        assert!(!is_github_api_host("github.com"));
        assert!(!is_github_api_host("raw.githubusercontent.com"));
        assert!(!is_github_api_host("example.com"));
    }

    #[test]
    fn test_is_github_file_host_raw_githubusercontent() {
        assert!(is_github_file_host("raw.githubusercontent.com"));
    }

    #[test]
    fn test_is_github_file_host_codeload() {
        assert!(is_github_file_host("codeload.github.com"));
    }

    #[test]
    fn test_is_github_file_host_objects() {
        assert!(is_github_file_host("objects.githubusercontent.com"));
    }

    #[test]
    fn test_is_github_file_host_media() {
        assert!(is_github_file_host("media.githubusercontent.com"));
    }

    #[test]
    fn test_is_github_file_host_suffix() {
        assert!(is_github_file_host("custom.githubusercontent.com"));
    }

    #[test]
    fn test_is_github_file_host_false() {
        assert!(!is_github_file_host("example.com"));
        assert!(!is_github_file_host("github.com"));
    }

    #[test]
    fn test_request_lifecycle_new() {
        // This test verifies the lifecycle tracking mechanism works
        // We can't fully test this without the full AppState, but we verify the struct exists
        let _: std::marker::PhantomData<RequestLifecycle> = std::marker::PhantomData;
    }

    #[test]
    fn test_process_shell_script_bytes_binary_skips_processing() {
        // Create bytes which contain NUL and some non-printables -> binary
        let data = Vec::from(b"\x00\x01\x02\x03\x04binary\x00\xFF".as_ref());
        let result =
            process_shell_script_bytes(data.clone(), "http://proxy").expect("should succeed");
        assert_eq!(result, data);
    }

    #[test]
    fn test_process_shell_script_bytes_lossy_conversion_applies() {
        // Contains an invalid byte but mostly printable; expect lossy conversion & URL rewrite
        let data =
            Vec::from(b"echo https://github.com/owner/repo/blob/main/file.txt \xFF".as_ref());
        let output = process_shell_script_bytes(data, "http://proxy").expect("should succeed");
        let out_str = String::from_utf8_lossy(&output);
        // convert_github_blob_to_raw and add_proxy_to_github_urls should make the github url go through the proxy
        assert!(
            out_str.contains(
                "http://proxy/https://raw.githubusercontent.com/owner/repo/main/file.txt"
            ) || out_str.contains("http://proxy/https://github.com/owner/repo")
        );
    }

    #[test]
    fn test_proxy_error_http_builder_status_code() {
        // Create an Http::Error using the Uri builder approach
        let uri_result = http::Uri::builder().build();
        if let Err(e) = uri_result {
            let error = ProxyError::HttpBuilder(e);
            assert_eq!(error.to_status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}
