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
use hyper::header;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use std::{
    borrow::Cow,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::signal;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, warn};

use crate::services::text_processor::TextReplacementStream;

// Use Jemalloc for better memory management on Linux
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

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
    pub shutdown_manager: services::shutdown::ShutdownManager,
    pub uptime_tracker: Arc<services::shutdown::UptimeTracker>,
    pub auth_header: Option<HeaderValue>,
    pub docker_proxy: Option<Arc<providers::registry::DockerProxy>>,
    pub download_semaphore: Arc<Semaphore>,
    pub cloudflare_service: Arc<services::cloudflare::CloudflareService>,
    pub ip_info_service: Arc<services::ipinfo::IpInfoService>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("unsupported target host: {0}")]
    UnsupportedHost(String),
    #[error("invalid target uri: {0}")]
    InvalidTarget(String),
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
            ProxyError::TooManyConcurrentRequests =>
                "Too Many Concurrent Requests\n\nThe server is currently handling the maximum number of concurrent downloads. Please retry later.".to_string(),
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
        if self.permit.take().is_some() {
            infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
            if let Some(start) = self.start.take() {
                infra::metrics::HTTP_REQUEST_DURATION_SECONDS
                    .observe(start.elapsed().as_secs_f64());
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
    infra::log::setup_tracing(&settings.log);
    info!("Starting gh-proxy server");
    info!("Log level: {}", settings.log.get_level());
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
    let download_semaphore = Arc::new(Semaphore::new(
        settings.server.max_concurrent_requests as usize,
    ));

    // Initialize Cloudflare Service
    let cloudflare_service = Arc::new(services::cloudflare::CloudflareService::new(
        settings.cloudflare.clone(),
    ));
    if cloudflare_service.is_enabled() {
        info!("Cloudflare analytics integration enabled");
    }

    // Initialize IP Info Service
    let ip_info_service = Arc::new(services::ipinfo::IpInfoService::new(
        settings.ipinfo.token.clone(),
    ));

    let app_state = AppState {
        settings: Arc::clone(&settings),
        github_config: Arc::new(github_config),
        client,
        shutdown_manager,
        uptime_tracker,
        auth_header,
        docker_proxy: Some(Arc::new(providers::registry::DockerProxy::new(
            &settings.registry.default,
        ))),
        download_semaphore,
        cloudflare_service,
        ip_info_service,
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
        .route("/api/stats", get(api::get_stats))
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
        .fallback(proxy_handler) // Renamed from fallback_proxy
        .with_state(app_state.clone())
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    app_state.shutdown_manager.mark_ready().await;
    info!("=================================================");
    info!("gh-proxy server listening on {}", bind_addr);
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
    let shutdown_timeout = Duration::from_secs(30);
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

// ... (resolve_target_uri_with_validation, resolve_fallback_target, is_github_domain_path, should_disable_compression_for_request kept same) ...
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
    let trimmed = path.trim_start_matches('/');
    let normalized: Cow<'_, str> =
        if trimmed.starts_with("https:/") && !trimmed.starts_with("https://") {
            Cow::Owned(format!("https://{}", &trimmed[7..]))
        } else if trimmed.starts_with("http:/") && !trimmed.starts_with("http://") {
            Cow::Owned(format!("http://{}", &trimmed[6..]))
        } else {
            Cow::Borrowed(trimmed)
        };

    if normalized.starts_with("http://") || normalized.starts_with("https://") {
        let mut converted = providers::github::convert_github_blob_to_raw(normalized.as_ref());
        if let Some(q) = query {
            converted.push('?');
            converted.push_str(q);
        }
        match converted.parse::<Uri>() {
            Ok(uri) => return Ok(uri),
            Err(_) => {
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
                    return rebuilt.parse::<Uri>().map_err(|e| e.to_string());
                }
                return Err("Invalid URL".to_string());
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
        return converted.parse::<Uri>().map_err(|e| e.to_string());
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

fn should_disable_compression_for_request(uri: &Uri) -> bool {
    fn has_extension(path: &str, ext: &str) -> bool {
        path.rsplit_once('.')
            .map(|(_, candidate)| candidate.eq_ignore_ascii_case(ext))
            .unwrap_or(false)
    }
    let path = uri.path();
    if has_extension(path, "sh") || has_extension(path, "bash") || has_extension(path, "zsh") {
        return true;
    }
    if has_extension(path, "html") || has_extension(path, "htm") || has_extension(path, "xml") {
        return true;
    }
    if has_extension(path, "md") || has_extension(path, "markdown") || has_extension(path, "txt") {
        return true;
    }
    if has_extension(path, "json") || has_extension(path, "yaml") || has_extension(path, "yml") {
        return true;
    }
    false
}

/// Helper to get the real client IP (e.g. from Cloudflare header)
fn get_client_ip(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .and_then(|h| h.to_str().ok())
        .or_else(|| {
            headers
                .get("x-forwarded-for")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.split(',').next()) // Take the first IP if multiple
        })
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

// Renamed from fallback_proxy and removed instrumentation
async fn proxy_handler(State(state): State<AppState>, req: Request<Body>) -> Response<Body> {
    let path = req.uri().path();
    if matches!(
        path,
        "/favicon.ico" | "/robots.txt" | "/apple-touch-icon.png" | "/.well-known/security.txt"
    ) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    }
    let proxy_host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080")
        .to_string();
    let client_ip = get_client_ip(req.headers());
    let proxy_scheme = services::request::detect_client_protocol(&req);
    let proxy_url = format!("{}://{}", proxy_scheme, proxy_host);

    // Fetch AS Name asynchronously
    let as_name = state
        .ip_info_service
        .get_as_name(&client_ip)
        .await
        .unwrap_or_default();
    let as_info = if as_name.is_empty() {
        String::new()
    } else {
        format!(" ({})", as_name)
    };

    let target_uri =
        match resolve_target_uri_with_validation(req.uri(), state.github_config.as_ref()) {
            Ok(uri) => uri,
            Err(_) => {
                info!("Invalid target [IP: {}{}]: {}", client_ip, as_info, path);
                let error_msg = format!("404 Not Found\n\nInvalid target: {}\n", path);
                return Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from(error_msg))
                    .unwrap();
            }
        };

    let post_processor = if state.settings.shell.editor {
        Some(ResponsePostProcessor::ShellEditor {
            proxy_url: Arc::from(proxy_url.clone()),
        })
    } else {
        None
    };

    // Determine if we are likely to stream/edit based on extension (heuristic for logging)
    let streaming_tag =
        if state.settings.shell.editor && should_disable_compression_for_request(&target_uri) {
            " [streaming]"
        } else {
            ""
        };

    info!(
        "Proxying request [IP: {}{}] -> {}{}",
        client_ip, as_info, target_uri, streaming_tag
    );

    match proxy_request(&state, req, target_uri, post_processor).await {
        Ok(response) => response,
        Err(error) => {
            warn!("Proxy error [IP: {}{}]: {}", client_ip, as_info, error);
            error_response(error)
        }
    }
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
    let mut current_uri = target_uri.clone();
    let initial_method = req.method().clone();

    let (mut req_parts, body) = req.into_parts();
    req_parts.uri = current_uri.clone();

    // Body buffering logic kept for small request bodies (POST/PUT), but responses will be streamed
    let mut body_bytes: Option<Bytes> = None;
    let should_buffer = should_buffer_request_body(&initial_method, &req_parts.headers);
    let request_body = if should_buffer {
        match body.collect().await {
            Ok(c) => {
                let b = c.to_bytes();
                body_bytes = Some(b.clone());
                Body::from(b)
            }
            Err(e) => return Err(ProxyError::ProcessingError(e.to_string())),
        }
    } else {
        Body::empty()
    };

    let mut req = Request::from_parts(req_parts, request_body);

    // Disable compression if we might edit the response
    let disable_compression = if state.settings.shell.editor && processor.is_some() {
        should_disable_compression_for_request(&current_uri)
    } else {
        false
    };
    sanitize_request_headers(req.headers_mut(), disable_compression);
    apply_github_headers(req.headers_mut(), &current_uri, state.auth_header.as_ref());
    let sanitized_headers = Arc::new(req.headers().clone());

    let permit = state
        .download_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ProxyError::TooManyConcurrentRequests)?;
    infra::metrics::HTTP_ACTIVE_REQUESTS.inc();
    let mut permit_guard = RequestPermitGuard::new(permit, start);

    // Request loop (redirects)
    let response = loop {
        let req_timeout = Duration::from_secs(state.settings.server.request_timeout_secs);
        let response = match tokio::time::timeout(req_timeout, state.client.request(req)).await {
            Ok(Ok(resp)) => resp,
            Ok(Err(e)) => return Err(ProxyError::Http(Box::new(e))),
            Err(_) => return Err(ProxyError::ProcessingError("Request timeout".to_string())),
        };

        if response.status().is_redirection() {
            let location = response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok());
            // Basic redirect handling with collapsible_if fix (nightly) or just nested (stable)
            #[allow(clippy::collapsible_if)]
            if let Some(loc) = location {
                if let Ok(new_uri) = loc.parse::<Uri>() {
                    current_uri = new_uri;
                    let retry_body = body_bytes
                        .as_ref()
                        .map(|b| Body::from(b.clone()))
                        .unwrap_or(Body::empty());
                    req = Request::builder()
                        .method(initial_method.clone())
                        .uri(current_uri.clone())
                        .body(retry_body)
                        .unwrap();
                    *req.headers_mut() = sanitized_headers.as_ref().clone();
                    apply_github_headers(
                        req.headers_mut(),
                        &current_uri,
                        state.auth_header.as_ref(),
                    );
                    continue;
                }
            }
            break response;
        }
        break response;
    };

    let status = response.status();
    infra::metrics::HTTP_REQUESTS_TOTAL.inc();

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());
    let content_length = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());

    if let Some(len) = content_length
        && len > size_limit_bytes
    {
        let error = ProxyError::SizeExceeded(len / 1024 / 1024, size_limit_mb);
        lifecycle.fail(Some(&error));
        return Err(error);
    }

    let (mut parts, body) = response.into_parts();
    let shell_processing_enabled = state.settings.shell.editor && processor.is_some();
    let needs_text_processing = !status.is_redirection()
        && is_response_needs_text_processing(&content_type, &target_uri, shell_processing_enabled);

    if needs_text_processing {
        // Log "Applying..." is removed as requested by user
        let proxy_url = processor_proxy_url(&processor).unwrap();

        sanitize_response_headers(&mut parts.headers, true, true, true);
        fix_content_type_header(&mut parts.headers, &target_uri);
        parts.headers.remove(header::CONTENT_LENGTH);

        let body_stream = body
            .into_data_stream()
            .map(|res| res.map_err(std::io::Error::other));
        let processed_stream = TextReplacementStream::new(body_stream, proxy_url);

        let wrapped_stream =
            processed_stream.map(|res| res.map_err(|e| ProxyError::ProcessingError(e.to_string())));

        let streaming_body = ProxyBodyStream::new(
            Box::pin(wrapped_stream),
            lifecycle,
            size_limit_bytes,
            size_limit_mb,
            permit_guard.take_start_time(),
            permit_guard.take_permit(),
        );

        return Ok(Response::from_parts(
            parts,
            Body::from_stream(streaming_body),
        ));
    }

    sanitize_response_headers(&mut parts.headers, false, false, false);
    fix_content_type_header(&mut parts.headers, &target_uri);

    let streaming_body = ProxyBodyStream::new(
        body.into_data_stream()
            .map(|r| r.map_err(|e| ProxyError::Http(Box::new(e))))
            .boxed(),
        lifecycle,
        size_limit_bytes,
        size_limit_mb,
        permit_guard.take_start_time(),
        permit_guard.take_permit(),
    );

    Ok(Response::from_parts(
        parts,
        Body::from_stream(streaming_body),
    ))
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
    if headers.contains_key(header::CONTENT_LENGTH)
        || headers.contains_key(header::TRANSFER_ENCODING)
    {
        return true;
    }
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
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
    }
}

fn fix_content_type_header(headers: &mut HeaderMap, target_uri: &Uri) {
    if headers.contains_key(header::CONTENT_TYPE) {
        return;
    }
    let path = target_uri.path();
    let mime = if path.ends_with(".html") {
        "text/html"
    } else {
        "text/plain"
    };
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
}

fn processor_proxy_url(processor: &Option<ResponsePostProcessor>) -> Option<&str> {
    match processor {
        Some(ResponsePostProcessor::ShellEditor { proxy_url }) => Some(proxy_url.as_ref()),
        None => None,
    }
}

fn apply_github_headers(headers: &mut HeaderMap, _uri: &Uri, auth: Option<&HeaderValue>) {
    if let Some(a) = auth {
        headers.insert(header::AUTHORIZATION, a.clone());
    }
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static("gh-proxy/1.1.0"),
    );
}

type BoxedBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, ProxyError>> + Send>>;

struct ProxyBodyStream {
    inner: BoxedBodyStream,
    lifecycle: Option<RequestLifecycle>,
    size_limit_bytes: u64,
    size_limit_mb: u64,
    total_bytes: u64,
    permit: Option<OwnedSemaphorePermit>,
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
                infra::metrics::BYTES_TRANSFERRED_TOTAL.inc_by(chunk_len);

                if this.size_limit_bytes > 0 && new_total > this.size_limit_bytes {
                    let error =
                        ProxyError::SizeExceeded(new_total / 1024 / 1024, this.size_limit_mb);
                    if let Some(mut lifecycle) = this.lifecycle.take() {
                        lifecycle.fail(Some(&error));
                    }
                    return Poll::Ready(Some(Err(error)));
                }
                this.total_bytes = new_total;
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                if let Some(mut lifecycle) = this.lifecycle.take() {
                    lifecycle.fail(Some(&e));
                }
                if this.permit.take().is_some() {
                    infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
                }
                if let Some(start) = this.start_time.take() {
                    infra::metrics::HTTP_REQUEST_DURATION_SECONDS
                        .observe(start.elapsed().as_secs_f64());
                }
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                if let Some(mut lifecycle) = this.lifecycle.take() {
                    lifecycle.success();
                }
                if this.permit.take().is_some() {
                    infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
                }
                if let Some(start) = this.start_time.take() {
                    infra::metrics::HTTP_REQUEST_DURATION_SECONDS
                        .observe(start.elapsed().as_secs_f64());
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
