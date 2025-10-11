use std::{net::SocketAddr, sync::Arc};

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, Request, Response, StatusCode, Uri},
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
}

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("unsupported target host: {0}")]
    UnsupportedHost(String),
    #[error("invalid target uri: {0}")]
    InvalidTarget(String),
    #[error("http error: {0}")]
    Http(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("http builder error: {0}")]
    HttpBuilder(#[from] http::Error),
}

pub type ProxyResult<T> = Result<T, ProxyError>;

#[derive(Debug, Clone, Copy)]
pub enum ProxyKind {
    GitHub,
    Docker,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let settings = Settings::load()?;
    
    // Setup tracing with log configuration
    setup_tracing(&settings.log);

    // Log configuration info
    info!("Starting gh-proxy server");
    info!("Log level: {}", settings.log.get_level());
    info!("Log file: {}", settings.log.log_file_path);
    info!("Max log size: {} MB ({} bytes)", 
          settings.log.max_log_size, 
          settings.log.max_log_size_bytes());
    info!("Docker proxy enabled: {}", settings.docker.enabled);
    info!("Blacklist enabled: {}", settings.blacklist.enabled);
    if settings.shell.is_editor_enabled() {
        info!("Shell editor mode enabled");
    }
    
    // Load blacklist if enabled
    if settings.blacklist.enabled {
        match settings.blacklist.load_blacklist() {
            Ok(list) => info!("Loaded {} blacklist entries", list.len()),
            Err(e) => warn!("Failed to load blacklist: {}", e),
        }
    }

    let bind_addr: SocketAddr = settings.server.bind_addr().parse()?;
    let client = build_client(&settings.server);

    let github_config = GitHubConfig::new(&settings.auth.token);

    let app_state = AppState {
        settings: Arc::new(settings),
        github_config: Arc::new(github_config),
        client,
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/healthz", get(health))
        .route("/style.css", get(serve_static_file))
        .route("/app.js", get(serve_static_file))
        .route("/api/config", get(api::get_config))
        .route("/v2", any(docker::docker_v2_root))
        .route("/v2/*path", any(docker::docker_v2_proxy))
        .route("/github/*path", any(github::github_proxy))
        .route("/docker/*path", any(docker::docker_proxy))
        .fallback(any(fallback_proxy))
        .with_state(app_state);

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
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(server.request_timeout())
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
    let html = std::fs::read_to_string("/app/web/index.html")
        .unwrap_or_else(|_| {
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
</html>"#.to_string()
        });
    
    // Set Content-Type with UTF-8 charset explicitly
    (
        [(hyper::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html
    )
}

async fn serve_static_file(uri: axum::http::Uri) -> impl axum::response::IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let file_path = format!("/app/web/{}", path);
    
    let (content_type, charset) = match path {
        "style.css" => ("text/css", "; charset=utf-8"),
        "app.js" => ("application/javascript", "; charset=utf-8"),
        _ => ("text/plain", "; charset=utf-8"),
    };
    
    match std::fs::read_to_string(&file_path) {
        Ok(content) => (
            StatusCode::OK,
            [(hyper::header::CONTENT_TYPE, format!("{}{}", content_type, charset))],
            content
        ),
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8".to_string())],
            "File not found".to_string()
        ),
    }
}

async fn health() -> StatusCode {
    info!("Health check request");
    StatusCode::OK
}

#[instrument(skip_all)]
async fn fallback_proxy(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let path = req.uri().path();
    
    // Get the Host header for proxy URL generation
    let proxy_host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost:8080")
        .to_string();
    
    info!("Fallback proxy request: {} {}", req.method(), path);

    // Check if blacklist is enabled
    if state.settings.blacklist.enabled {
        if state.settings.blacklist.is_blacklisted(path) {
            warn!("Blocked request to blacklisted path: {}", path);
            let error_msg = format!(
                "Access Denied\n\nThe requested path is blacklisted: {}\n\nThis path has been blocked by the proxy administrator.\n",
                path
            );
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(error_msg))
                .unwrap());
        }
    }

    let target_uri = match resolve_fallback_target(req.uri()) {
        Ok(uri) => {
            // Check if it's a GitHub repository homepage
            if github::is_github_repo_homepage(uri.to_string().as_str()) {
                let error_msg = format!(
                    "GitHub Repository Homepage Detected\n\nThe URL you requested appears to be a GitHub repository homepage:\n{}\n\nRepository homepages are web pages (HTML), not downloadable files.\n\nIf you want to download a specific file, please use one of these formats:\n- Raw file URL: https://raw.githubusercontent.com/owner/repo/branch/path/to/file\n- Blob URL (will be auto-converted): https://github.com/owner/repo/blob/branch/path/to/file\n- Direct proxy: {}/github/owner/repo/branch/path/to/file\n",
                    uri, req.uri().authority().map(|a| a.as_str()).unwrap_or("proxy")
                );
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Body::from(error_msg))
                    .unwrap());
            }
            uri
        }
        Err(msg) => {
            warn!("Failed to resolve target: {}", msg);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(msg))
                .unwrap());
        }
    };

    match proxy_request(&state, req, target_uri.clone(), ProxyKind::GitHub).await {
        Ok(response) => {
            info!("Fallback proxy success: status={}", response.status());
            
            // Check if shell editor is enabled and this is a shell script
            if state.settings.shell.editor && is_shell_script(&target_uri) {
                // Process the response body to add proxy prefix to GitHub URLs
                match process_shell_script_response(response, &proxy_host).await {
                    Ok(processed_response) => {
                        info!("Shell script processed with proxy prefixes");
                        Ok(processed_response)
                    }
                    Err(e) => {
                        warn!("Failed to process shell script: {}", e);
                        // Return error but don't fail completely
                        let error_msg = format!(
                            "Script Processing Error\n\nFailed to process shell script.\n\nError: {}\n",
                            e
                        );
                        Ok(Response::builder()
                            .status(StatusCode::INTERNAL_SERVER_ERROR)
                            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                            .body(Body::from(error_msg))
                            .unwrap())
                    }
                }
            } else {
                Ok(response)
            }
        }
        Err(err) => {
            error!("Fallback proxy failure: {}", err);
            let error_msg = format!(
                "Proxy Error\n\nFailed to fetch the requested resource.\n\nError: {}\n\nPlease check:\n- The URL is correct and accessible\n- The target server is available\n",
                err
            );
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(error_msg))
                .unwrap())
        }
    }
}

fn resolve_fallback_target(uri: &Uri) -> Result<Uri, String> {
    let path = uri.path();
    
    // Remove leading slash
    let path = path.trim_start_matches('/');
    
    // Check if it's a full URL (http:// or https://)
    if path.starts_with("http://") || path.starts_with("https://") {
        // Convert GitHub blob URLs to raw URLs
        let converted = github::convert_github_blob_to_raw(path);
        return converted.parse().map_err(|e| format!("Invalid URL: {}", e));
    }
    
    // Check if it's a GitHub URL pattern
    if path.starts_with("github.com/") || path.starts_with("raw.githubusercontent.com/") {
        let full_url = format!("https://{}", path);
        // Convert GitHub blob URLs to raw URLs
        let converted = github::convert_github_blob_to_raw(&full_url);
        return converted.parse().map_err(|e| format!("Invalid GitHub URL: {}", e));
    }
    
    Err(format!(
        "Invalid Request\n\nThe path '{}' is not a valid proxy target.\n\nSupported formats:\n- https://github.com/owner/repo/...\n- http://example.com/...\n- github.com/owner/repo/...\n\nOr use specific endpoints:\n- /github/* for GitHub resources\n- /docker/* for Docker images\n",
        path
    ))
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
            info!("Processing shell script ({}  bytes), adding proxy prefix: {}", text.len(), proxy_host);
            // Replace GitHub URLs with proxied versions
            let result = add_proxy_to_github_urls(&text, proxy_host);
            info!("Result: {} bytes", result.len());
            result
        }
        Err(e) => {
            warn!("Shell script contains non-UTF-8 data, skipping processing: {}", e);
            // Return the original bytes as-is
            return Ok(Response::from_parts(
                parts,
                Body::from(body_bytes),
            ));
        }
    };
    
    // Build the response with the modified content
    // Must update Content-Length header since we modified the content
    let mut response = Response::from_parts(
        parts,
        Body::from(content.clone()),
    );
    
    // Update Content-Length to match the new body size
    response.headers_mut().insert(
        hyper::header::CONTENT_LENGTH,
        hyper::header::HeaderValue::from_str(&content.len().to_string())
            .unwrap_or(hyper::header::HeaderValue::from_static("0"))
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
    let raw_pattern = Regex::new(
        r"(https?://raw\.githubusercontent\.com/[^\s]+)"
    ).unwrap();
    
    // Pattern 2: github.com raw/blob/releases URLs
    let github_pattern = Regex::new(
        r"(https?://github\.com/[^/\s]+/[^/\s]+/(?:raw|blob|releases)/[^\s]+)"
    ).unwrap();
    
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
            processed_line = raw_pattern.replace_all(&processed_line, |caps: &regex::Captures| {
                let url = &caps[1];
                if url.contains(proxy_host) {
                    url.to_string()
                } else {
                    format!("{}/{}", proxy_url, url)
                }
            }).to_string();
            
            // Replace github.com URLs
            processed_line = github_pattern.replace_all(&processed_line, |caps: &regex::Captures| {
                let url = &caps[1];
                if url.contains(proxy_host) {
                    url.to_string()
                } else {
                    format!("{}/{}", proxy_url, url)
                }
            }).to_string();
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

    info!(
        "Response: status={}, elapsed={:?}",
        status, elapsed
    );

    // Check response size limit
    if let Some(content_length) = headers.get(header::CONTENT_LENGTH) {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(length) = length_str.parse::<u64>() {
                let limit_bytes = state.settings.server.size_limit * 1024 * 1024;
                if length > limit_bytes {
                    warn!(
                        "Response size {} bytes exceeds limit {} bytes",
                        length, limit_bytes
                    );
                    return Err(ProxyError::InvalidTarget(format!(
                        "Response size exceeds limit: {} MB > {} MB",
                        length / 1024 / 1024,
                        state.settings.server.size_limit
                    )));
                }
            }
        }
    }

    // Convert hyper response to axum response
    let (mut parts, body) = response.into_parts();
    let body_bytes = body.collect().await
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

// Dual writer for logging to both stdout and file
struct DualWriter {
    stdout: std::io::Stdout,
    file: std::fs::File,
}

impl DualWriter {
    fn new(log_path: &str) -> std::io::Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(log_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
            
        Ok(Self {
            stdout: std::io::stdout(),
            file,
        })
    }
}

impl std::io::Write for DualWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stdout.write_all(buf)?;
        self.file.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.stdout.flush()?;
        self.file.flush()?;
        Ok(())
    }
}

// Newtype wrapper for DualWriter to implement MakeWriter
struct DualWriterFactory {
    inner: std::sync::Arc<std::sync::Mutex<DualWriter>>,
}

impl DualWriterFactory {
    fn new(log_path: &str) -> std::io::Result<Self> {
        let writer = DualWriter::new(log_path)?;
        Ok(Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new(writer)),
        })
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DualWriterFactory {
    type Writer = DualWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        DualWriterGuard {
            inner: self.inner.clone(),
        }
    }
}

struct DualWriterGuard {
    inner: std::sync::Arc<std::sync::Mutex<DualWriter>>,
}

impl std::io::Write for DualWriterGuard {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.lock().unwrap().flush()
    }
}

fn setup_tracing(log_config: &config::LogConfig) {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_config.get_level()));

    let log_path = log_config.log_file_path.clone();
    
    // Try to create dual writer factory, fallback to stdout only on error
    match DualWriterFactory::new(&log_path) {
        Ok(factory) => {
            let fmt_layer = fmt::layer()
                .with_writer(factory)
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false)
                .with_ansi(false); // Disable ANSI colors for file output
            
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
                
            eprintln!("Logging initialized: console + file ({})", log_config.log_file_path);
        }
        Err(e) => {
            // Fallback to stdout only
            let fmt_layer = fmt::layer()
                .with_target(false)
                .with_thread_ids(false)
                .with_thread_names(false);
            
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt_layer)
                .init();
                
            eprintln!("Warning: Failed to open log file: {}. Logging to console only.", e);
        }
    }
}
