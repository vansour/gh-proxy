use std::{convert::Infallible, net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderValue, Response, StatusCode, Uri},
    routing::{any, get},
    Router,
};
use config::{AuthConfig, GitHubConfig, ServerConfig, Settings};
use hyper::header;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use tokio::signal;
use tokio::sync::OnceCell;
use tower::service_fn;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, instrument, warn};

mod api;
mod config;
mod docker;
mod github;

#[derive(Clone)]
pub struct AppState {
    pub settings: Arc<Settings>,
    pub github_config: Arc<GitHubConfig>,
    pub client: Client<hyper_rustls::HttpsConnector<HttpConnector>, Body>,
    /// Lazily loaded blacklist cache
    pub blacklist_cache: Arc<OnceCell<Vec<String>>>,
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
            | ProxyError::GitHubRepoHomepage(_) => StatusCode::BAD_REQUEST,
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
            ProxyError::GitHubRepoHomepage(url) => format!(
                "GitHub Repository Homepage Detected\n\nThe URL you requested appears to be a GitHub repository homepage:\n{}\n\nRepository homepages are web pages (HTML), not downloadable files.\n\nIf you want to download a specific file, please use one of these formats:\n- Raw file URL: https://raw.githubusercontent.com/owner/repo/branch/path/to/file\n- Blob URL (will be auto-converted): https://github.com/owner/repo/blob/branch/path/to/file\n",
                url
            ),
            ProxyError::SizeExceeded(size, limit) => format!(
                "File Size Exceeded\n\nThe requested file size ({} MB) exceeds the proxy limit ({} MB).\n\nPlease use a direct download link or contact the administrator to increase the limit.\n",
                size, limit
            ),
            ProxyError::InvalidGitHubUrl(path) => format!(
                "Invalid Request\n\nThe path '{}' is not a valid proxy target.\n\nSupported formats:\n- https://github.com/owner/repo/...\n- http://example.com/...\n- github.com/owner/repo/...\n\nOr use specific endpoints:\n- /github/* for GitHub resources\n- /docker/* for Docker images\n",
                path
            ),
            _ => format!("{}\n\nPlease check the URL and try again.\n", self),
        }
    }
}

pub type ProxyResult<T> = Result<T, ProxyError>;

#[derive(Debug, Clone, Copy)]
pub enum ProxyKind {
    GitHub,
    Docker,
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
                .unwrap()
        })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = Settings::load()?;

    // Setup tracing with log configuration
    setup_tracing(&settings.log);

    // Log configuration info
    info!("Starting gh-proxy server");
    info!("Log level: {}", settings.log.get_level());
    info!("Docker proxy enabled: {}", settings.docker.enabled);
    info!(
        "Blacklist enabled: {} (lazy loading)",
        settings.blacklist.enabled
    );
    if settings.shell.is_editor_enabled() {
        info!("Shell editor mode enabled");
    }
    info!(
        "Connection pool: max_idle={}, idle_timeout={}s",
        settings.server.max_idle_connections, settings.server.pool_idle_timeout
    );
    info!("CORS: Enabled (allowing all origins)");

    let bind_addr: SocketAddr = settings.server.bind_addr().parse()?;
    let client = build_client(&settings.server);

    let github_config = GitHubConfig::new(&settings.auth.token);

    let app_state = AppState {
        settings: Arc::new(settings),
        github_config: Arc::new(github_config),
        client,
        blacklist_cache: Arc::new(OnceCell::new()),
    };

    let fallback_state = app_state.clone();
    let fallback_service = service_fn(move |req: Request<Body>| {
        let state = fallback_state.clone();
        async move { Ok::<_, Infallible>(fallback_proxy(state, req).await) }
    });

    // 配置 CORS - 允许跨域访问
    let cors = CorsLayer::new()
        .allow_origin(Any) // 允许任何来源，生产环境建议限制具体域名
        .allow_methods(Any) // 允许所有HTTP方法
        .allow_headers(Any) // 允许所有请求头
        .expose_headers(Any); // 暴露所有响应头

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/style.css", get(serve_static_file))
        .route("/app.js", get(serve_static_file))
        .route("/gh-proxy.png", get(serve_static_file))
        .route("/api/config", get(api::get_config))
        .route("/v2", any(docker::docker_v2_root))
        .route("/v2/{*path}", any(docker::docker_v2_proxy))
        .route("/github/{*path}", any(github::github_proxy))
        .route("/docker/{*path}", any(docker::docker_proxy))
        .with_state(app_state)
        .fallback_service(fallback_service)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    info!("=================================================");
    info!("gh-proxy server listening on {}", bind_addr);
    info!("=================================================");
    info!("Available endpoints:");
    info!("  - GET  /                  - Web UI");
    info!("  - GET  /healthz           - Health check");
    info!("  - GET  /api/config        - Get configuration");
    info!("  - ANY  /v2                - Docker Registry v2 API root");
    info!("  - ANY  /v2/*path          - Docker Registry v2 API");
    info!("  - ANY  /github/*path      - GitHub proxy");
    info!("  - ANY  /docker/*path      - Docker registry proxy");
    info!("  - ANY  /*path             - Fallback proxy");
    info!("=================================================");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("gh-proxy server shutting down gracefully");
    Ok(())
}

fn build_client(
    server: &ServerConfig,
) -> Client<hyper_rustls::HttpsConnector<HttpConnector>, Body> {
    let mut http_connector = HttpConnector::new();

    // Configure connection pool
    http_connector.set_keepalive(Some(server.pool_idle_timeout()));
    http_connector.set_nodelay(true);

    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(http_connector);

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(server.pool_idle_timeout())
        .pool_max_idle_per_host(server.max_idle_connections)
        .build(connector)
}

async fn shutdown_signal() {
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
            info!("Received Ctrl+C signal, shutting down...");
        },
        _ = terminate => {
            info!("Received termination signal, shutting down...");
        },
    }
}

async fn index() -> impl axum::response::IntoResponse {
    let html = std::fs::read_to_string("/app/web/index.html").unwrap_or_else(|_| {
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>gh-proxy</title>
</head>
<body>
    <h1>gh-proxy - GitHub & Docker Proxy</h1>
    <p>Web UI not available. Please check the installation.</p>
</body>
</html>"#
            .to_string()
    });

    // Set Content-Type with UTF-8 charset explicitly
    (
        [(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

async fn serve_static_file(uri: axum::http::Uri) -> Response<Body> {
    let path = uri.path().trim_start_matches('/');
    let file_path = format!("/app/web/{}", path);

    let content_type = match path {
        "style.css" => "text/css; charset=utf-8",
        "app.js" => "application/javascript; charset=utf-8",
        "gh-proxy.png" => "image/png",
        _ => "text/plain; charset=utf-8",
    };

    match std::fs::read(&file_path) {
        Ok(content) => Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, content_type)
            .body(Body::from(content))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("File not found"))
            .unwrap(),
    }
}

async fn health() -> StatusCode {
    info!("Health check request");
    StatusCode::OK
}

/// Load blacklist lazily (only once, on first use)
async fn load_blacklist_lazy(state: &AppState) -> &Vec<String> {
    state
        .blacklist_cache
        .get_or_init(|| async {
            match state.settings.blacklist.load_blacklist() {
                Ok(list) => {
                    info!("Loaded {} blacklist entries (lazy)", list.len());
                    list
                }
                Err(e) => {
                    warn!("Failed to load blacklist: {}", e);
                    Vec::new()
                }
            }
        })
        .await
}

/// Check if an IP matches any blacklist rule
fn is_ip_blacklisted(ip: &str, blacklist: &[String]) -> bool {
    use config::BlacklistConfig;

    for rule in blacklist.iter() {
        if BlacklistConfig::ip_matches_rule(ip, rule) {
            return true;
        }
    }
    false
}

/// Check if the client IP is blacklisted
async fn check_blacklist(state: &AppState, client_ip: Option<String>) -> ProxyResult<()> {
    if !state.settings.blacklist.enabled {
        return Ok(());
    }

    if let Some(client_ip) = client_ip {
        let blacklist = load_blacklist_lazy(state).await;

        if is_ip_blacklisted(&client_ip, blacklist) {
            warn!("Blocked request from blacklisted IP: {}", client_ip);
            return Err(ProxyError::AccessDenied(client_ip));
        }
    }

    Ok(())
}

/// Resolve the target URI for fallback proxy
fn resolve_target_uri_with_validation(uri: &Uri) -> ProxyResult<Uri> {
    let target_uri =
        resolve_fallback_target(uri).map_err(|msg| ProxyError::InvalidGitHubUrl(msg))?;

    // Check if it's a GitHub repository homepage
    if github::is_github_repo_homepage(target_uri.to_string().as_str()) {
        return Err(ProxyError::GitHubRepoHomepage(target_uri.to_string()));
    }

    Ok(target_uri)
}

/// Handle shell script processing if enabled
async fn handle_shell_script(
    state: &AppState,
    response: Response<Body>,
    target_uri: &Uri,
    proxy_host: &str,
) -> ProxyResult<Response<Body>> {
    if !state.settings.shell.editor || !is_shell_script(target_uri) {
        return Ok(response);
    }

    process_shell_script_response(response, proxy_host)
        .await
        .map_err(|e| ProxyError::ProcessingError(e))
}

#[instrument(skip_all)]
async fn fallback_proxy(state: AppState, req: Request<Body>) -> Response<Body> {
    let path = req.uri().path();
    info!("Fallback proxy request: {} {}", req.method(), path);

    // Get the Host header for proxy URL generation
    let proxy_host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080")
        .to_string();

    let client_ip = extract_client_ip(&req);

    // Check blacklist (lazy loaded)
    if let Err(error) = check_blacklist(&state, client_ip).await {
        return error_response(error);
    }

    // Resolve target URI
    let target_uri = match resolve_target_uri_with_validation(req.uri()) {
        Ok(uri) => uri,
        Err(error) => return error_response(error),
    };

    // Proxy request
    let response = match proxy_request(&state, req, target_uri.clone(), ProxyKind::GitHub).await {
        Ok(response) => response,
        Err(error) => return error_response(error),
    };

    info!("Fallback proxy success: status={}", response.status());

    // Handle shell script processing
    match handle_shell_script(&state, response, &target_uri, &proxy_host).await {
        Ok(processed_response) => {
            if state.settings.shell.editor && is_shell_script(&target_uri) {
                info!("Shell script processed with proxy prefixes");
            }
            processed_response
        }
        Err(error) => error_response(error),
    }
}

fn resolve_fallback_target(uri: &Uri) -> Result<Uri, String> {
    let path = uri.path();

    // Remove leading slash
    let path = path.trim_start_matches('/');

    // Fix common URL malformation: https:/ -> https://
    // This handles cases where a single slash is missing in the URL
    let path = if path.starts_with("https:/") && !path.starts_with("https://") {
        format!("https://{}", &path[7..])
    } else if path.starts_with("http:/") && !path.starts_with("http://") {
        format!("http://{}", &path[6..])
    } else {
        path.to_string()
    };

    // Check if it's a full URL (http:// or https://)
    if path.starts_with("http://") || path.starts_with("https://") {
        // Convert GitHub blob URLs to raw URLs
        let converted = github::convert_github_blob_to_raw(&path);
        return converted.parse().map_err(|e| format!("Invalid URL: {}", e));
    }

    // Check if it's a GitHub URL pattern
    if path.starts_with("github.com/") || path.starts_with("raw.githubusercontent.com/") {
        let full_url = format!("https://{}", path);
        // Convert GitHub blob URLs to raw URLs
        let converted = github::convert_github_blob_to_raw(&full_url);
        return converted
            .parse()
            .map_err(|e| format!("Invalid GitHub URL: {}", e));
    }

    Err(path)
}

fn is_shell_script(uri: &Uri) -> bool {
    let path = uri.path();
    path.ends_with(".sh") || path.ends_with(".bash") || path.ends_with(".zsh")
}

async fn process_shell_script_response(
    response: Response<Body>,
    proxy_host: &str,
) -> Result<Response<Body>, String> {
    use http_body_util::BodyExt;

    // Get the response status and headers
    let (parts, body) = response.into_parts();

    // Read the body
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?
        .to_bytes();

    // Try to convert to string, if it fails, return the original bytes
    let content = match String::from_utf8(body_bytes.to_vec()) {
        Ok(text) => {
            info!(
                "Processing shell script ({}  bytes), adding proxy prefix: {}",
                text.len(),
                proxy_host
            );
            // Replace GitHub URLs with proxied versions
            let result = add_proxy_to_github_urls(&text, proxy_host);
            info!("Result: {} bytes", result.len());
            result
        }
        Err(e) => {
            warn!(
                "Shell script contains non-UTF-8 data, skipping processing: {}",
                e
            );
            // Return the original bytes as-is
            return Ok(Response::from_parts(parts, Body::from(body_bytes)));
        }
    };

    // Build the response with the modified content
    // Must update Content-Length header since we modified the content
    let mut response = Response::from_parts(parts, Body::from(content.clone()));

    // Update Content-Length to match the new body size
    response.headers_mut().insert(
        hyper::header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from_str(&content.len().to_string())
            .unwrap_or(hyper::header::HeaderValue::from_static("0")),
    );

    Ok(response)
}

fn add_proxy_to_github_urls(content: &str, proxy_host: &str) -> String {
    use regex::Regex;

    // Determine the protocol based on proxy_host or default to https
    let proxy_url = if proxy_host.starts_with("http://") || proxy_host.starts_with("https://") {
        proxy_host.to_string()
    } else if proxy_host.starts_with("localhost") || proxy_host.contains("127.0.0.1") {
        format!("http://{}", proxy_host)
    } else {
        format!("https://{}", proxy_host)
    };

    // Pattern 1: raw.githubusercontent.com URLs
    let raw_pattern = Regex::new(r"(https?://raw\.githubusercontent\.com/[^\s]+)").unwrap();

    // Pattern 2: github.com raw/blob/releases URLs
    let github_pattern =
        Regex::new(r"(https?://github\.com/[^/\s]+/[^/\s]+/(?:raw|blob|releases)/[^\s]+)").unwrap();

    // Process line-by-line but preserve all original line endings
    let mut result = String::with_capacity(content.len() + 1024);

    for line in content.lines() {
        let mut processed_line = line.to_string();

        // Only process lines that look like download commands or variable assignments
        // Skip lines inside echo statements or other string contexts
        let should_process = line.trim_start().starts_with("wget ")
            || line.trim_start().starts_with("curl ")
            || (line.contains("=") && (line.contains("http://") || line.contains("https://")))
            || line.trim_start().starts_with("URL=")
            || line.trim_start().starts_with("url=");

        if should_process {
            // Replace raw.githubusercontent.com URLs
            processed_line = raw_pattern
                .replace_all(&processed_line, |caps: &regex::Captures| {
                    let url = &caps[1];
                    if url.contains(proxy_host) {
                        url.to_string()
                    } else {
                        format!("{}/{}", proxy_url, url)
                    }
                })
                .to_string();

            // Replace github.com URLs
            processed_line = github_pattern
                .replace_all(&processed_line, |caps: &regex::Captures| {
                    let url = &caps[1];
                    if url.contains(proxy_host) {
                        url.to_string()
                    } else {
                        format!("{}/{}", proxy_url, url)
                    }
                })
                .to_string();
        }

        result.push_str(&processed_line);
        result.push('\n');
    }

    // Remove the trailing newline if the original didn't have one
    if !content.ends_with('\n') && result.ends_with('\n') {
        result.pop();
    }

    result
}

/// Core proxy request handler
pub async fn proxy_request(
    state: &AppState,
    mut req: Request<Body>,
    target_uri: Uri,
    proxy_kind: ProxyKind,
) -> ProxyResult<Response<Body>> {
    use http_body_util::BodyExt;

    let start = std::time::Instant::now();

    // Update request URI
    *req.uri_mut() = target_uri.clone();

    // Sanitize and modify headers
    sanitize_request_headers(req.headers_mut());

    match proxy_kind {
        ProxyKind::GitHub => {
            apply_github_headers(req.headers_mut(), &state.settings.auth);
        }
        ProxyKind::Docker => {
            // Docker headers are already set by caller if needed
        }
    }

    info!("Sending request to: {}", target_uri);

    // Send request
    let response = state
        .client
        .request(req)
        .await
        .map_err(|e| ProxyError::Http(Box::new(e)))?;

    let status = response.status();
    let headers = response.headers().clone();
    let elapsed = start.elapsed();

    info!("Response: status={}, elapsed={:?}", status, elapsed);

    // Check response size limit
    if let Some(content_length) = headers.get(header::CONTENT_LENGTH) {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<u64>() {
                let limit_bytes = state.settings.server.size_limit * 1024 * 1024;
                if length > limit_bytes {
                    let size_mb = length / 1024 / 1024;
                    warn!(
                        "Response size {} bytes ({} MB) exceeds limit {} MB",
                        length, size_mb, state.settings.server.size_limit
                    );
                    return Err(ProxyError::SizeExceeded(
                        size_mb,
                        state.settings.server.size_limit,
                    ));
                }
            }
        }
    }

    // Convert hyper response to axum response
    let (mut parts, body) = response.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| ProxyError::Http(Box::new(e)))?
        .to_bytes();

    // Remove restrictive security headers that may block content display
    sanitize_response_headers(&mut parts.headers);

    let response = Response::from_parts(parts, Body::from(body_bytes));
    Ok(response)
}

fn sanitize_response_headers(headers: &mut HeaderMap) {
    // Remove Content-Security-Policy headers that block script execution
    headers.remove("content-security-policy");
    headers.remove("content-security-policy-report-only");

    // Remove X-Frame-Options to allow embedding
    headers.remove("x-frame-options");

    // Remove other restrictive headers
    headers.remove("x-content-type-options");
}

fn sanitize_request_headers(headers: &mut HeaderMap) {
    // Remove hop-by-hop headers
    headers.remove(header::CONNECTION);
    headers.remove(header::PROXY_AUTHENTICATE);
    headers.remove(header::PROXY_AUTHORIZATION);
    headers.remove(header::TE);
    headers.remove(header::TRAILER);
    headers.remove(header::TRANSFER_ENCODING);
    headers.remove(header::UPGRADE);
    headers.remove("keep-alive");
}

fn apply_github_headers(headers: &mut HeaderMap, auth: &AuthConfig) {
    // Add GitHub token if available
    if auth.has_token() {
        if let Ok(value) = HeaderValue::from_str(&format!("token {}", auth.token)) {
            headers.insert(header::AUTHORIZATION, value);
        }
    }

    // Add User-Agent
    if let Ok(value) = HeaderValue::from_str("gh-proxy/0.1.0") {
        headers.insert(header::USER_AGENT, value);
    }

    // Add Accept header for GitHub API
    if let Ok(value) = HeaderValue::from_str("application/vnd.github.v3+json") {
        headers.insert(header::ACCEPT, value);
    }
}

/// Extract client IP from request headers
fn extract_client_ip(req: &Request<Body>) -> Option<String> {
    // Try X-Forwarded-For header first (for proxied requests)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP in the chain
            if let Some(ip) = xff_str.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
    }

    // Try X-Real-IP header
    if let Some(xri) = req.headers().get("x-real-ip") {
        if let Ok(ip) = xri.to_str() {
            return Some(ip.trim().to_string());
        }
    }

    // TODO: Extract from connection info if available
    // For now, return None if no headers present
    None
}

fn setup_tracing(log_config: &config::LogConfig) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_config.get_level()));

    // Create stdout layer only (logs to console, captured by Docker logs)
    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false);

    tracing_subscriber::registry()
        .with(filter)
        .with(stdout_layer)
        .init();

    eprintln!("Logging initialized: console only (Docker logs)");
}
