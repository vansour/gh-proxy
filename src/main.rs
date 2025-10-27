use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, Method, Response, StatusCode, Uri},
    routing::{any, get},
};
use bytes::Bytes;
use config::{AuthConfig, GitHubConfig, Settings};
use futures_util::{Stream, StreamExt};
use http_body_util::BodyExt;
use hyper::{body::Incoming, header};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use tokio::signal;
use tokio::sync::OnceCell;
use tower_http::cors::{Any, CorsLayer};
use tracing::{debug, error, info, instrument, warn};

mod api;
mod config;
mod github;
mod handlers;
mod services;
mod shutdown;
mod utils;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub github_config: Arc<GitHubConfig>,
    pub client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    /// Blacklist cache with hot reload support (Arc<OnceCell<Arc<RwLock<BlacklistCache>>>>)
    pub blacklist_cache:
        Arc<OnceCell<Arc<tokio::sync::RwLock<services::blacklist::BlacklistCache>>>>,
    /// Graceful shutdown manager
    pub shutdown_manager: shutdown::ShutdownManager,
    /// Server uptime tracker
    pub uptime_tracker: Arc<shutdown::UptimeTracker>,
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
}

impl ProxyError {
    /// Convert ProxyError to HTTP status code
    pub fn to_status_code(&self) -> StatusCode {
        match self {
            ProxyError::AccessDenied(_) => StatusCode::FORBIDDEN,
            ProxyError::InvalidTarget(_)
            | ProxyError::InvalidGitHubUrl(_)
            | ProxyError::GitHubRepoHomepage(_)
            | ProxyError::GitHubWebPage(_) => StatusCode::BAD_REQUEST,
            ProxyError::SizeExceeded(_, _) => StatusCode::PAYLOAD_TOO_LARGE,
            ProxyError::Http(_) => StatusCode::BAD_GATEWAY,
            ProxyError::UnsupportedHost(_) => StatusCode::NOT_IMPLEMENTED,
            ProxyError::ProcessingError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ProxyError::HttpBuilder(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Convert ProxyError to user-friendly error message
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
    shutdown: shutdown::ShutdownManager,
    completed: bool,
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

/// Convert ProxyError to HTTP Response
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
                .unwrap_or_else(|_| {
                    // This should never happen, but if it does, return a basic response
                    Response::new(Body::from("Internal Server Error"))
                })
        })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::load()?;

    // Setup tracing with log configuration
    setup_tracing(&settings.log);

    // Log configuration info
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

    // Create shutdown manager and uptime tracker
    let shutdown_manager = shutdown::ShutdownManager::new();
    let uptime_tracker = Arc::new(shutdown::UptimeTracker::new());
    let app_state = AppState {
        settings: Arc::new(settings),
        github_config: Arc::new(github_config),
        client,
        blacklist_cache: Arc::new(OnceCell::new()),
        shutdown_manager,
        uptime_tracker,
    };

    // 配置 CORS - 允许跨域访问
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers(Any);

    let app = Router::new()
        .route("/", get(handlers::static_files::index))
        .route("/healthz", get(handlers::health::health_liveness))
        .route("/readyz", get(handlers::health::health_readiness))
        .route("/style.css", get(handlers::static_files::serve_static_file))
        .route("/script.js", get(handlers::static_files::serve_static_file))
        .route("/favicon.ico", get(handlers::static_files::serve_favicon))
        .route("/api/config", get(api::get_config))
        .route("/github/{*path}", any(github::github_proxy))
        .fallback(fallback_proxy)
        .with_state(app_state.clone())
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;

    // Mark server as ready before binding
    app_state.shutdown_manager.mark_ready().await;

    info!("=================================================");
    info!("gh-proxy server listening on {}", bind_addr);
    info!("=================================================");
    info!("Available endpoints:");
    info!("  - GET  /                  - Web UI");
    info!("  - GET  /healthz           - Liveness probe (is server alive)");
    info!("  - GET  /readyz            - Readiness probe (is server ready)");
    info!("  - GET  /api/config        - Get configuration");
    info!("  - ANY  /github/*path      - GitHub proxy");
    info!("  - ANY  /*path             - Fallback proxy");
    info!("=================================================");

    // Create a shutdown manager instance for the shutdown signal handler
    let shutdown_mgr = app_state.shutdown_manager.clone();

    let service = app.into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, service)
        .with_graceful_shutdown(shutdown_signal(shutdown_mgr))
        .await?;

    info!("gh-proxy server shutting down gracefully");
    Ok(())
}

async fn shutdown_signal(shutdown_mgr: shutdown::ShutdownManager) {
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

    // Wait for signal
    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C signal, initiating graceful shutdown...");
        },
        _ = terminate => {
            info!("Received SIGTERM signal, initiating graceful shutdown...");
        },
    }

    // Initiate graceful shutdown
    shutdown_mgr.initiate_shutdown().await;
    info!("Server stopped accepting new requests");

    // Wait for active requests to complete (max 30 seconds)
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

    // Mark server as stopped
    shutdown_mgr.mark_stopped().await;
}

/// Resolve the target URI for fallback proxy
fn resolve_target_uri_with_validation(uri: &Uri, host_guard: &GitHubConfig) -> ProxyResult<Uri> {
    let target_uri = resolve_fallback_target(uri).map_err(|msg| {
        // Log at debug level instead of error for probe requests
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

    // Check if it's a non-downloadable GitHub web path (pkgs, releases, etc.)
    if github::is_github_web_only_path(&target_str) {
        return Err(ProxyError::GitHubWebPage(target_str));
    }

    // Check if it's a GitHub repository homepage
    if github::is_github_repo_homepage(&target_str) {
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

    // Remove leading slash
    let path = path.trim_start_matches('/');
    debug!("After trim_start_matches('/'): '{}'", path);

    // Fix common URL malformation: https:/ -> https://
    // This handles cases where "https://domain" becomes "https:/domain" due to path normalization
    let path = if path.starts_with("https:/") && !path.starts_with("https://") {
        // Extract the part after "https:/" and ensure double slash
        let after_scheme = &path[7..]; // Skip "https:/"
        debug!(
            "Fixed malformed https:/ URL - raw: '{}' -> normalized: 'https://{}'",
            path, after_scheme
        );
        format!("https://{}", after_scheme)
    } else if path.starts_with("http:/") && !path.starts_with("http://") {
        // Extract the part after "http:/" and ensure double slash
        let after_scheme = &path[6..]; // Skip "http:/"
        debug!(
            "Fixed malformed http:/ URL - raw: '{}' -> normalized: 'http://{}'",
            path, after_scheme
        );
        format!("http://{}", after_scheme)
    } else {
        debug!("No malformation detected, path as-is: '{}'", path);
        path.to_string()
    };
    debug!("After URL malformation fix: '{}'", path);

    if path.starts_with("http://") || path.starts_with("https://") {
        let converted = github::convert_github_blob_to_raw(&path);
        // Reconstruct URI with query parameters
        let uri_with_query = if let Some(q) = query {
            format!("{}?{}", converted, q)
        } else {
            converted
        };
        debug!("Fallback target with query: {}", uri_with_query);
        return uri_with_query
            .parse()
            .map_err(|e| format!("Invalid URL: {}", e));
    }

    // Check for GitHub domain paths (github.com/..., api.github.com/..., etc.)
    if is_github_domain_path(&path) {
        let full_url = format!("https://{}", path);
        let converted = github::convert_github_blob_to_raw(&full_url);
        // Reconstruct URI with query parameters
        let uri_with_query = if let Some(q) = query {
            format!("{}?{}", converted, q)
        } else {
            converted
        };
        debug!(
            "Fallback GitHub domain target with query: {}",
            uri_with_query
        );
        return uri_with_query
            .parse()
            .map_err(|e| format!("Invalid GitHub URL: {}", e));
    }

    Err(format!("No valid target found for path: {}", path))
}

/// Check if a path starts with a GitHub domain
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

/// Determine if compression should be disabled for a specific request URI.
/// Compression should only be disabled for text content that we need to rewrite
/// (shell scripts, HTML, markdown files, etc.), to preserve performance for
/// binary downloads (archives, executables, etc.).
fn should_disable_compression_for_request(uri: &Uri) -> bool {
    let path = uri.path().to_lowercase();

    // Shell scripts - definitely need text processing
    if path.ends_with(".sh") || path.ends_with(".bash") || path.ends_with(".zsh") {
        return true;
    }

    // HTML/XML files that might contain URLs
    if path.ends_with(".html")
        || path.ends_with(".htm")
        || path.ends_with(".xml")
        || path.ends_with(".xhtml")
    {
        return true;
    }

    // Markdown and documentation files
    if path.ends_with(".md") || path.ends_with(".markdown") || path.ends_with(".txt") {
        return true;
    }

    // JSON and YAML configuration files that might contain GitHub URLs
    if path.ends_with(".json") || path.ends_with(".yaml") || path.ends_with(".yml") {
        return true;
    }

    // Binary archives - should NOT disable compression (keep full compression benefits)
    if path.ends_with(".tar.gz")
        || path.ends_with(".tar")
        || path.ends_with(".zip")
        || path.ends_with(".7z")
        || path.ends_with(".rar")
    {
        return false;
    }

    // Executables and binaries - should NOT disable compression
    if path.ends_with(".exe")
        || path.ends_with(".dll")
        || path.ends_with(".so")
        || path.ends_with(".dylib")
        || path.ends_with(".bin")
    {
        return false;
    }

    // Images - should NOT disable compression (serve pre-compressed format)
    if path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".png")
        || path.ends_with(".gif")
        || path.ends_with(".webp")
        || path.ends_with(".svg")
    {
        return false;
    }

    // Audio/Video - should NOT disable compression
    if path.ends_with(".mp3")
        || path.ends_with(".mp4")
        || path.ends_with(".webm")
        || path.ends_with(".wav")
        || path.ends_with(".flac")
    {
        return false;
    }

    // For unknown file types, don't disable compression unless we're certain
    // we need to rewrite the content
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

    // Ignore browser requests for favicon and other common static assets
    if matches!(
        path,
        "/favicon.ico" | "/robots.txt" | "/apple-touch-icon.png" | "/.well-known/security.txt"
    ) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }

    // Get the Host header for proxy URL generation
    let proxy_host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080")
        .to_string();

    // Determine the protocol based on the request
    // Priority: cf-visitor (Cloudflare) > X-Forwarded-Proto > URI scheme > heuristics > default
    let proxy_scheme = services::request::detect_client_protocol(&req);

    let proxy_url = format!("{}://{}", proxy_scheme, proxy_host);
    info!(
        "Proxy URL determined: {} (from Cloudflare/upstream)",
        proxy_url
    );

    let client_ip = services::request::extract_client_ip(&req);

    // Check blacklist (lazy loaded)
    if let Err(error) = services::blacklist::check_blacklist(&state, client_ip).await {
        return error_response(error);
    }

    // Resolve target URI
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

/// Core proxy request handler with streaming support
///
/// This function implements efficient proxying with:
/// - Connection pool reuse (via shared hyper::Client)
/// - Stream forwarding with backpressure handling
/// - Zero-copy body forwarding for binary content
/// - Selective in-memory buffering for text processing only
/// - Automatic redirect following (3xx responses)
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

    // Follow redirects automatically (max 10 redirects to prevent infinite loops)
    let max_redirects = 10;
    let mut redirect_count = 0;
    let mut current_uri = target_uri.clone();

    // Store initial request info for redirect handling
    let initial_method = req.method().clone();
    let initial_headers = req.headers().clone();

    // Collect the original request body so it can be reused for redirects
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

    // Sanitize and modify headers
    // Only disable compression if shell editor is enabled AND the target is likely to contain
    // text that needs rewriting (shell scripts, HTML, markdown, etc.)
    let disable_compression = if state.settings.shell.editor && processor.is_some() {
        should_disable_compression_for_request(&current_uri)
    } else {
        false
    };
    sanitize_request_headers(req.headers_mut(), disable_compression);

    apply_github_headers(req.headers_mut(), &current_uri, &state.settings.auth);

    debug!(
        "Initial request method: {}, URI: {}",
        initial_method, current_uri
    );

    let response = loop {
        info!(
            "Sending request to: {} (method: {})",
            current_uri, initial_method
        );

        // Send request using the shared client (connection pooling)
        let response = match state.client.request(req).await {
            Ok(resp) => resp,
            Err(e) => {
                error!("Failed to connect to {}: {}", current_uri, e);
                let error = ProxyError::Http(Box::new(e));
                lifecycle.fail(Some(&error));
                return Err(error);
            }
        };

        let status = response.status();

        // Handle redirects automatically
        // Note: 304 Not Modified is technically a 3xx status but is NOT a redirect
        // It should be returned as-is without requiring a Location header
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

            // Get the Location header for the redirect
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

            // Parse the new location
            current_uri = match location.parse::<Uri>() {
                Ok(uri) => {
                    // Handle relative URLs by combining with the current URI
                    if uri.scheme().is_none() {
                        // Relative URL - construct absolute URL
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

            // Create a new request for the redirect (reuse method and headers from initial request)
            let redirect_body = body_bytes
                .as_ref()
                .map(|bytes| Body::from(bytes.clone()))
                .unwrap_or_else(Body::empty);

            req = Request::builder()
                .method(initial_method.clone())
                .uri(current_uri.clone())
                .body(redirect_body)
                .map_err(ProxyError::HttpBuilder)?;

            // Copy headers from initial request
            *req.headers_mut() = initial_headers.clone();

            // Sanitize and modify headers for the redirect request
            sanitize_request_headers(req.headers_mut(), disable_compression);
            apply_github_headers(req.headers_mut(), &current_uri, &state.settings.auth);

            // Continue to follow the redirect
            continue;
        }

        // Not a redirect, return the response
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

    // Check response size limit BEFORE processing when length is known
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

    // Never perform text processing on redirect responses (3xx status codes)
    // These responses typically have minimal or empty bodies and must preserve their
    // Location header and other redirect-related information
    let is_redirect = status.is_redirection();
    let needs_text_processing = !is_redirect
        && is_response_needs_text_processing(&content_type, &target_uri, shell_processing_enabled);

    // Get response body
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

        let body_bytes = match collect_body_with_limit(body, size_limit_mb).await {
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
        if loosen_headers {
            apply_processed_body_cache_headers(&mut parts.headers, &processed_bytes);
        }
        let content_length_value = HeaderValue::from_str(&processed_bytes.len().to_string())
            .unwrap_or_else(|_| HeaderValue::from_static("0"));
        parts
            .headers
            .insert(hyper::header::CONTENT_LENGTH, content_length_value);

        let response = Response::from_parts(parts, Body::from(processed_bytes));
        lifecycle.success();
        return Ok(response);
    }

    sanitize_response_headers(&mut parts.headers, false, false, false);

    // Fix Content-Type for common file extensions if it's missing or incorrect
    fix_content_type_header(&mut parts.headers, &target_uri);

    // Apply Cloudflare CDN optimization headers for cacheable responses
    apply_cloudflare_cache_headers(&mut parts.headers, status, &target_uri);

    let streaming_body = ProxyBodyStream::new(
        body.into_data_stream().boxed(),
        lifecycle,
        size_limit_bytes,
        size_limit_mb,
    );

    let response = Response::from_parts(parts, Body::from_stream(streaming_body));
    Ok(response)
}

/// Determine if a response needs text processing (URL injection, modification)
fn is_response_needs_text_processing(
    content_type: &Option<String>,
    target_uri: &Uri,
    shell_editor_enabled: bool,
) -> bool {
    if !shell_editor_enabled {
        return false;
    }

    let path = target_uri.path();

    // Shell scripts always need processing
    if path.ends_with(".sh") || path.ends_with(".bash") || path.ends_with(".zsh") {
        return true;
    }

    // HTML files need processing
    if path.ends_with(".html") || path.ends_with(".htm") {
        return true;
    }

    // Check content type
    if let Some(ct) = content_type {
        let ct_lower = ct.to_lowercase();

        // Text files
        if ct_lower.contains("text/") {
            return true;
        }

        // HTML
        if ct_lower.contains("text/html") || ct_lower.contains("application/xhtml") {
            return true;
        }
    }

    false
}

fn sanitize_request_headers(headers: &mut HeaderMap, disable_compression: bool) {
    if disable_compression {
        // Remove compression-related headers from the request
        headers.remove(header::ACCEPT_ENCODING);
    }

    // IMPORTANT: Preserve Range and Accept-Ranges headers for Cloudflare
    // These enable efficient streaming and resumable downloads at the edge
    // Never remove these headers - they're essential for large file downloads
    // and Cloudflare's partial content caching strategy
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
        // Remove Content-Security-Policy headers that block script execution
        headers.remove("content-security-policy");
        headers.remove("content-security-policy-report-only");

        // Remove X-Frame-Options to allow embedding
        headers.remove("x-frame-options");

        // Remove other restrictive headers that interfere with inline assets
        headers.remove("x-content-type-options");
        headers.remove("cache-control");
        headers.remove("pragma");
        headers.remove("etag");
        headers.remove("last-modified");
    }

    // IMPORTANT: Keep Location header for redirects (3xx responses)
    // The Location header should be preserved as-is for proper redirect handling
}

/// Applies Cloudflare CDN optimization headers for successful 200 responses
/// - Adds Cache-Control with s-maxage for edge node caching
/// - Preserves ETag/Last-Modified for cache revalidation
/// - Keeps Accept-Ranges for range requests
/// - Maintains Accept-Encoding for compression
fn apply_cloudflare_cache_headers(headers: &mut HeaderMap, status: StatusCode, target_uri: &Uri) {
    if status != StatusCode::OK && status != StatusCode::PARTIAL_CONTENT {
        return;
    }

    let path = target_uri.path();

    // Determine cache duration based on content type
    let cache_control = if is_small_file(path) {
        // Small files (HTML, CSS, JS): long cache
        "public, max-age=2592000, s-maxage=31536000, stale-while-revalidate=604800"
    } else if is_archive_file(path) || is_release_asset(path) {
        // Archives and release assets: very long cache (they're immutable by version)
        "public, max-age=31536000, s-maxage=31536000, immutable"
    } else if is_source_file(path) {
        // Source code files: moderate cache
        "public, max-age=604800, s-maxage=2592000, stale-while-revalidate=86400"
    } else {
        // Default: reasonable cache for other content
        "public, max-age=3600, s-maxage=86400, stale-while-revalidate=3600"
    };

    // Only set Cache-Control if not already present (preserve original if needed)
    if !headers.contains_key(header::CACHE_CONTROL)
        && let Ok(value) = HeaderValue::from_str(cache_control)
    {
        headers.insert(header::CACHE_CONTROL, value);
    }

    // Ensure ETag is present for cache revalidation (if not already present)
    if !headers.contains_key(header::ETAG)
        && let Some(content_length) = headers.get(header::CONTENT_LENGTH)
        && let Ok(length_str) = content_length.to_str()
    {
        // Generate weak ETag from content length and last modified
        let last_modified = headers
            .get(header::LAST_MODIFIED)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("0");
        let etag = format!(
            "W/\"{}-{}\"",
            length_str.replace("\"", ""),
            last_modified.replace("\"", "").replace(" ", "")
        );
        if let Ok(value) = HeaderValue::from_str(&etag) {
            headers.insert(header::ETAG, value);
        }
    }

    // Ensure Range support headers are present for large file downloads
    if is_large_file(path) && !headers.contains_key("Accept-Ranges") {
        headers.insert("Accept-Ranges", HeaderValue::from_static("bytes"));
    }
}

fn is_small_file(path: &str) -> bool {
    path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".html")
        || path.ends_with(".htm")
        || path.ends_with(".json")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
}

fn is_archive_file(path: &str) -> bool {
    path.ends_with(".zip")
        || path.ends_with(".tar.gz")
        || path.ends_with(".tgz")
        || path.ends_with(".tar")
}

fn is_release_asset(path: &str) -> bool {
    // Release assets are typically in /releases/download/v*/
    path.contains("/releases/download/")
}

fn is_source_file(path: &str) -> bool {
    path.ends_with(".rs")
        || path.ends_with(".go")
        || path.ends_with(".py")
        || path.ends_with(".js")
        || path.ends_with(".ts")
        || path.ends_with(".java")
        || path.ends_with(".cpp")
        || path.ends_with(".c")
        || path.ends_with(".h")
}

fn is_large_file(path: &str) -> bool {
    is_archive_file(path) || is_release_asset(path) || path.ends_with(".iso")
}

const PROCESSED_RESPONSE_CACHE_CONTROL: &str = "public, max-age=300, stale-while-revalidate=60";

fn apply_processed_body_cache_headers(headers: &mut HeaderMap, body: &[u8]) {
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(PROCESSED_RESPONSE_CACHE_CONTROL),
    );

    let mut hasher = DefaultHasher::new();
    body.hash(&mut hasher);
    let digest = hasher.finish();
    let etag_value = format!("\"ghp-{digest:x}\"");
    match HeaderValue::from_str(&etag_value) {
        Ok(value) => {
            headers.insert(header::ETAG, value);
        }
        Err(error) => {
            warn!("Failed to set processed response ETag: {}", error);
        }
    }
}

fn fix_content_type_header(headers: &mut HeaderMap, target_uri: &Uri) {
    let path = target_uri.path();
    let content_type = headers.get(header::CONTENT_TYPE);

    // If Content-Type is already set and not text/plain, don't override
    if let Some(ct) = content_type
        && let Ok(ct_str) = ct.to_str()
        && !ct_str.to_lowercase().starts_with("text/plain")
    {
        return;
    }

    // Determine MIME type based on file extension
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
        return; // Don't set if we can't determine
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
}

impl ProxyBodyStream {
    fn new(
        inner: BoxedBodyStream,
        lifecycle: RequestLifecycle,
        size_limit_bytes: u64,
        size_limit_mb: u64,
    ) -> Self {
        Self {
            inner,
            lifecycle: Some(lifecycle),
            size_limit_bytes,
            size_limit_mb,
            total_bytes: 0,
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
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                if let Some(mut lifecycle) = this.lifecycle.take() {
                    lifecycle.success();
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn collect_body_with_limit(body: Incoming, size_limit_mb: u64) -> ProxyResult<Vec<u8>> {
    let limit_bytes = size_limit_mb.saturating_mul(1024 * 1024);
    let mut total: u64 = 0;
    let mut data = Vec::new();
    let mut stream = body.into_data_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            error!("Failed to read response body: {}", e);
            ProxyError::Http(Box::new(e))
        })?;

        total = total.saturating_add(chunk.len() as u64);
        if total > limit_bytes {
            let size_mb = std::cmp::max(1, total / 1024 / 1024);
            warn!(
                "Streaming body exceeded limit: {} bytes ({} MB) > {} MB",
                total, size_mb, size_limit_mb
            );
            return Err(ProxyError::SizeExceeded(size_mb, size_limit_mb));
        }

        data.extend_from_slice(&chunk);
    }

    Ok(data)
}

fn process_shell_script_bytes(body_bytes: Vec<u8>, proxy_url: &str) -> Result<Vec<u8>, String> {
    match String::from_utf8(body_bytes) {
        Ok(text) => {
            info!(
                "Processing shell script ({} bytes), adding proxy prefix: {}",
                text.len(),
                proxy_url
            );
            Ok(utils::url::add_proxy_to_github_urls(&text, proxy_url).into_bytes())
        }
        Err(err) => {
            let utf8_error = err.utf8_error();
            let bytes = err.into_bytes();
            let lossy_text = String::from_utf8_lossy(&bytes);
            warn!(
                "Shell script contains non-UTF-8 data ({}), applying lossy conversion",
                utf8_error
            );
            Ok(utils::url::add_proxy_to_github_urls(&lossy_text, proxy_url).into_bytes())
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
            Ok(utils::url::add_proxy_to_html_urls(&text, proxy_url).into_bytes())
        }
        Err(err) => {
            let utf8_error = err.utf8_error();
            let bytes = err.into_bytes();
            let lossy_text = String::from_utf8_lossy(&bytes);
            warn!(
                "HTML response contains non-UTF-8 data ({}), applying lossy conversion",
                utf8_error
            );
            Ok(utils::url::add_proxy_to_html_urls(&lossy_text, proxy_url).into_bytes())
        }
    }
}

fn apply_github_headers(headers: &mut HeaderMap, target_uri: &Uri, auth: &AuthConfig) {
    // Add GitHub token if available
    if auth.has_token()
        && let Ok(value) = HeaderValue::from_str(&format!("token {}", auth.token))
    {
        headers.insert(header::AUTHORIZATION, value);
    }

    // Add User-Agent
    if let Ok(value) = HeaderValue::from_str("gh-proxy/0.1.0") {
        headers.insert(header::USER_AGENT, value);
    }

    if let Some(host) = target_uri.host().map(|h| h.to_ascii_lowercase()) {
        if is_github_api_host(&host) {
            headers.insert(
                header::ACCEPT,
                HeaderValue::from_static("application/vnd.github.v3+json"),
            );
        } else if is_github_file_host(&host) && !headers.contains_key(header::ACCEPT) {
            headers.insert(header::ACCEPT, HeaderValue::from_static("*/*"));
        }
    }
}

fn is_github_api_host(host: &str) -> bool {
    matches!(host, "api.github.com")
}

fn is_github_file_host(host: &str) -> bool {
    matches!(
        host,
        "raw.githubusercontent.com"
            | "codeload.github.com"
            | "objects.githubusercontent.com"
            | "media.githubusercontent.com"
    ) || host.ends_with(".githubusercontent.com")
}

/// Build CORS layer based on security configuration
fn setup_tracing(log_config: &config::LogConfig) {
    use std::fs;
    use std::path::Path;
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_config.get_level()));

    // Create stdout layer (logs to console)
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false);

    // Create file layer with rotation if log file is specified
    let log_file_path = log_config.log_file_path.trim();

    if !log_file_path.is_empty() && log_file_path != "/dev/null" {
        // Ensure the log directory exists
        if let Some(parent) = Path::new(log_file_path).parent()
            && !parent.as_os_str().is_empty()
        {
            match fs::create_dir_all(parent) {
                Ok(_) => {
                    eprintln!("Log directory created/verified: {}", parent.display());
                }
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to create log directory '{}': {}",
                        parent.display(),
                        e
                    );
                }
            }
        }

        // Extract directory and file name for rotation
        if let Some(parent) = Path::new(log_file_path).parent() {
            let file_name = Path::new(log_file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("gh-proxy.log");

            // Create a non-blocking writer with daily rotation
            // The rotation is based on date, not file size
            let file_appender = tracing_appender::rolling::daily(parent, file_name);
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

            // Important: Keep the guard alive for the entire program lifetime
            // Using Box::leak to prevent dropping the guard
            let _ = Box::leak(Box::new(guard));

            let file_layer = fmt::layer()
                .with_writer(non_blocking)
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false);

            // Combine both layers (stdout + file)
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .with(file_layer)
                .init();

            eprintln!(
                "Logging initialized: console + file logging to {} (daily rotation, max size: {} MB per file)",
                log_file_path, log_config.max_log_size
            );
        } else {
            // If parent directory cannot be determined, fall back to stdout only
            tracing_subscriber::registry()
                .with(filter)
                .with(stdout_layer)
                .init();

            eprintln!(
                "Warning: Could not determine log directory from path '{}', using console only",
                log_file_path
            );
        }
    } else {
        // If no log file is specified, use stdout only
        tracing_subscriber::registry()
            .with(filter)
            .with(stdout_layer)
            .init();

        eprintln!("Logging initialized: console only");
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use config::{ProxyConfig, ServerConfig};

    #[test]
    fn detects_html_like_content_type() {
        let uri: Uri = "https://example.com/index.html".parse().unwrap();
        let content_type = Some("text/html; charset=utf-8".to_string());
        assert!(is_response_needs_text_processing(&content_type, &uri, true));
    }

    #[test]
    fn skips_processing_when_shell_disabled() {
        let uri: Uri = "https://example.com/index.html".parse().unwrap();
        let content_type = Some("text/html; charset=utf-8".to_string());
        assert!(!is_response_needs_text_processing(
            &content_type,
            &uri,
            false
        ));
    }

    // ============================================================================
    // Integration tests for resolve_fallback_target with query parameters
    // ============================================================================

    #[test]
    fn test_resolve_fallback_target_raw_url_with_query() {
        // Test that query parameters are preserved when resolving fallback target
        // Note: resolve_fallback_target is called with proxy paths like /https://...
        let uri: Uri = "/https://raw.githubusercontent.com/owner/repo/main/file.txt?token=abc123"
            .parse()
            .unwrap();
        let result = resolve_fallback_target(&uri).expect("Should parse valid URL");
        assert_eq!(result.host(), Some("raw.githubusercontent.com"));
        assert_eq!(result.path(), "/owner/repo/main/file.txt");
        assert_eq!(result.query(), Some("token=abc123"));
    }

    #[test]
    fn test_resolve_fallback_target_github_url_with_query() {
        // Test that query parameters are preserved for GitHub URLs
        // When accessed through proxy, the URL looks like /raw.githubusercontent.com/owner/repo/main/README.md?v=1
        let uri: Uri = "/raw.githubusercontent.com/owner/repo/main/README.md?v=1&format=json"
            .parse()
            .unwrap();
        let result = resolve_fallback_target(&uri).expect("Should parse valid URL");
        assert_eq!(result.host(), Some("raw.githubusercontent.com"));
        assert_eq!(result.query(), Some("v=1&format=json"));
    }

    #[test]
    fn test_resolve_fallback_target_blob_url_with_query() {
        // Test blob URLs with query parameters
        // Through proxy: /github.com/owner/repo/blob/main/file.js?plain=1&ts=4
        let uri: Uri = "/github.com/owner/repo/blob/main/file.js?plain=1&ts=4"
            .parse()
            .unwrap();
        let result = resolve_fallback_target(&uri).expect("Should parse valid URL");
        assert_eq!(result.host(), Some("raw.githubusercontent.com"));
        assert_eq!(result.path(), "/owner/repo/main/file.js");
        assert_eq!(result.query(), Some("plain=1&ts=4"));
    }

    #[test]
    fn test_resolve_fallback_target_with_complex_query() {
        // Test with multiple query parameters and special characters
        // Through proxy: /api.github.com/repos/owner/repo/contents/file.txt?ref=main...
        let uri: Uri = "/api.github.com/repos/owner/repo/contents/file.txt?ref=main&client_id=123&client_secret=secret"
            .parse()
            .unwrap();
        let result = resolve_fallback_target(&uri).expect("Should parse valid URL");
        assert_eq!(
            result.query(),
            Some("ref=main&client_id=123&client_secret=secret")
        );
    }

    #[test]
    fn test_resolve_fallback_target_without_query() {
        // Test URL without query parameters should work normally
        // Through proxy: /raw.githubusercontent.com/owner/repo/main/file.txt
        let uri: Uri = "/raw.githubusercontent.com/owner/repo/main/file.txt"
            .parse()
            .unwrap();
        let result = resolve_fallback_target(&uri).expect("Should parse valid URL");
        assert_eq!(result.host(), Some("raw.githubusercontent.com"));
        assert_eq!(result.query(), None);
    }

    #[test]
    fn test_resolve_fallback_target_malformed_https_url() {
        // Test fix for malformed https:/ URL
        let uri: Uri = "/https:/raw.githubusercontent.com/owner/repo/main/file.txt"
            .parse()
            .unwrap();
        let result = resolve_fallback_target(&uri).expect("Should handle malformed URLs");
        assert_eq!(result.host(), Some("raw.githubusercontent.com"));
    }

    // ============================================================================
    // Tests for github::resolve_github_target path resolution
    // These tests use a mock AppState to avoid requiring full configuration setup
    // ============================================================================

    fn create_mock_app_state() -> AppState {
        AppState {
            settings: Arc::new(config::Settings {
                server: ServerConfig::default(),
                proxy: ProxyConfig::default(),
                shell: config::ShellConfig::default(),
                log: config::LogConfig::default(),
                auth: config::AuthConfig::default(),
                blacklist: config::BlacklistConfig::default(),
            }),
            github_config: Arc::new(GitHubConfig::new("", &ProxyConfig::default())),
            client: services::client::build_client(&ServerConfig::default()),
            blacklist_cache: Arc::new(OnceCell::new()),
            shutdown_manager: shutdown::ShutdownManager::new(),
            uptime_tracker: Arc::new(shutdown::UptimeTracker::new()),
        }
    }

    #[test]
    fn test_github_path_raw_file() {
        // Test /github/owner/repo/branch/path/to/file
        let state = create_mock_app_state();
        let result = github::resolve_github_target(&state, "owner/repo/main/README.md", None)
            .expect("Should resolve raw file path");

        assert_eq!(result.host(), Some("raw.githubusercontent.com"));
        assert_eq!(result.path(), "/owner/repo/main/README.md");
    }

    #[test]
    fn test_github_path_with_query_params() {
        // Test /github/ path with query parameters
        let state = create_mock_app_state();
        let result = github::resolve_github_target(
            &state,
            "owner/repo/main/file.txt",
            Some("token=abc123&ref=develop".to_string()),
        )
        .expect("Should resolve with query params");

        assert_eq!(result.host(), Some("raw.githubusercontent.com"));
        assert_eq!(result.query(), Some("token=abc123&ref=develop"));
    }

    #[test]
    fn test_github_path_zipball() {
        // Test zipball archive path resolution
        let state = create_mock_app_state();
        let result = github::resolve_github_target(&state, "owner/repo/zipball/v1.0.0", None)
            .expect("Should resolve zipball path");

        // zipball should use codeload.github.com
        assert_eq!(result.host(), Some("codeload.github.com"));
        assert_eq!(result.path(), "/owner/repo/zipball/v1.0.0");
    }

    #[test]
    fn test_github_path_release_download() {
        // Test release download path
        let state = create_mock_app_state();
        let result = github::resolve_github_target(
            &state,
            "owner/repo/releases/download/v1.0.0/app.zip",
            None,
        )
        .expect("Should resolve release download path");

        // Release downloads should use github.com
        assert_eq!(result.host(), Some("github.com"));
        assert_eq!(
            result.path(),
            "/owner/repo/releases/download/v1.0.0/app.zip"
        );
    }

    #[test]
    fn test_github_path_tarball() {
        // Test tarball archive path
        let state = create_mock_app_state();
        let result = github::resolve_github_target(&state, "owner/repo/tarball/main", None)
            .expect("Should resolve tarball path");

        assert_eq!(result.host(), Some("codeload.github.com"));
        assert_eq!(result.path(), "/owner/repo/tarball/main");
    }

    #[test]
    fn test_github_path_tar_gz() {
        // Test tar.gz archive path
        let state = create_mock_app_state();
        let result =
            github::resolve_github_target(&state, "owner/repo/tar.gz/refs/tags/v2.0.0", None)
                .expect("Should resolve tar.gz path");

        assert_eq!(result.host(), Some("codeload.github.com"));
        assert_eq!(result.path(), "/owner/repo/tar.gz/refs/tags/v2.0.0");
    }

    #[test]
    fn test_github_path_release_download_with_query() {
        // Test release download with query parameters
        let state = create_mock_app_state();
        let result = github::resolve_github_target(
            &state,
            "owner/repo/releases/download/v1.0.0/app-x64.exe",
            Some("redirect=false".to_string()),
        )
        .expect("Should resolve with query params");

        assert_eq!(result.host(), Some("github.com"));
        assert_eq!(result.query(), Some("redirect=false"));
    }

    #[test]
    fn test_github_path_invalid_empty() {
        // Test invalid path (empty)
        let state = create_mock_app_state();
        let result = github::resolve_github_target(&state, "", None);

        assert!(result.is_err());
    }

    #[test]
    fn test_github_path_zip_format() {
        // Test zip archive format (should use codeload)
        let state = create_mock_app_state();
        let result = github::resolve_github_target(&state, "owner/repo/zip/main", None)
            .expect("Should resolve zip path");

        assert_eq!(result.host(), Some("codeload.github.com"));
        assert_eq!(result.path(), "/owner/repo/zip/main");
    }

    // ============================================================================
    // Tests for Cloudflare CDN optimization headers
    // ============================================================================

    #[test]
    fn test_cloudflare_cache_headers_for_small_files() {
        // Test that small files (JS, CSS) get long cache headers
        let mut headers = HeaderMap::new();
        let uri: Uri = "/owner/repo/main/script.js".parse().unwrap();
        apply_cloudflare_cache_headers(&mut headers, StatusCode::OK, &uri);

        let cache_control = headers
            .get(header::CACHE_CONTROL)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        assert!(cache_control.contains("max-age=2592000"));
        assert!(cache_control.contains("s-maxage=31536000"));
    }

    #[test]
    fn test_cloudflare_cache_headers_for_archives() {
        // Test that archive files get immutable cache headers
        let mut headers = HeaderMap::new();
        let uri: Uri = "/owner/repo/releases/download/v1.0.0/app.zip"
            .parse()
            .unwrap();
        apply_cloudflare_cache_headers(&mut headers, StatusCode::OK, &uri);

        let cache_control = headers
            .get(header::CACHE_CONTROL)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        assert!(cache_control.contains("immutable"));
        assert!(cache_control.contains("max-age=31536000"));
    }

    #[test]
    fn test_cloudflare_cache_headers_only_for_200() {
        // Test that cache headers are not applied to non-200 responses
        let mut headers = HeaderMap::new();
        let uri: Uri = "/owner/repo/main/script.js".parse().unwrap();
        apply_cloudflare_cache_headers(&mut headers, StatusCode::NOT_FOUND, &uri);

        assert!(!headers.contains_key(header::CACHE_CONTROL));
    }

    #[test]
    fn test_detect_client_protocol_from_cf_visitor() {
        // Test Cloudflare cf-visitor header detection
        let (mut parts, _) = Request::builder()
            .uri("http://example.com/")
            .method("GET")
            .body(Body::empty())
            .unwrap()
            .into_parts();

        parts.headers.insert(
            "cf-visitor",
            HeaderValue::from_static(r#"{"scheme":"https"}"#),
        );
        let req = Request::from_parts(parts, Body::empty());

        let protocol = services::request::detect_client_protocol(&req);
        assert_eq!(protocol, "https");
    }

    #[test]
    fn test_detect_client_protocol_from_x_forwarded() {
        // Test X-Forwarded-Proto fallback detection
        let (mut parts, _) = Request::builder()
            .uri("http://example.com/")
            .method("GET")
            .body(Body::empty())
            .unwrap()
            .into_parts();

        parts
            .headers
            .insert("x-forwarded-proto", HeaderValue::from_static("https"));
        let req = Request::from_parts(parts, Body::empty());

        let protocol = services::request::detect_client_protocol(&req);
        assert_eq!(protocol, "https");
    }

    #[test]
    fn test_extract_client_ip_from_cf_connecting_ip() {
        // Test Cloudflare cf-connecting-ip header priority
        let (mut parts, _) = Request::builder()
            .uri("http://example.com/")
            .method("GET")
            .body(Body::empty())
            .unwrap()
            .into_parts();

        parts
            .headers
            .insert("cf-connecting-ip", HeaderValue::from_static("192.0.2.100"));
        parts
            .headers
            .insert("x-forwarded-for", HeaderValue::from_static("10.0.0.1"));
        let req = Request::from_parts(parts, Body::empty());

        let ip = services::request::extract_client_ip(&req);
        // cf-connecting-ip should take priority
        assert_eq!(ip, Some("192.0.2.100".to_string()));
    }

    #[test]
    fn test_preserve_range_headers_in_request() {
        // Test that Range and Accept-Ranges headers are preserved for range requests
        // This ensures Cloudflare can do partial content caching and resumable downloads
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1023"));
        headers.insert("accept-encoding", HeaderValue::from_static("gzip"));

        let headers_before = headers.clone();
        sanitize_request_headers(&mut headers, false);

        // Range header should be preserved
        assert_eq!(
            headers.get(header::RANGE),
            headers_before.get(header::RANGE)
        );
        // Accept-Encoding should be preserved when compression not disabled
        assert_eq!(
            headers.get("accept-encoding"),
            headers_before.get("accept-encoding")
        );
    }
}
