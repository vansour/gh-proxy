//! Error types and error response handling.

use axum::body::Body;
use axum::http::{Response, StatusCode};
use hyper::header;
use tracing::error;

/// Errors that can occur during proxy operations.
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
    /// Convert error to appropriate HTTP status code.
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

    /// Convert error to user-friendly message.
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

/// Result type alias for proxy operations.
pub type ProxyResult<T> = Result<T, ProxyError>;

/// Build an error response from a ProxyError.
pub fn error_response(error: ProxyError) -> Response<Body> {
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
