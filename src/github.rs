use std::str::FromStr;

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{Response, StatusCode, Uri},
};
use hyper::header;
use hyper::http::uri::{Authority, PathAndQuery};
use tracing::{error, info, instrument, warn};

use crate::{AppState, ProxyError, ProxyKind, ProxyResult};

/// GitHub proxy handler for /github/* routes
#[instrument(skip_all, fields(path = %path))]
pub async fn github_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    info!("GitHub proxy request: {} {}", req.method(), path);

    match resolve_github_target(&state, &path) {
        Ok(target_uri) => {
            info!("Resolved GitHub target: {}", target_uri);
            match crate::proxy_request(&state, req, target_uri, ProxyKind::GitHub).await {
                Ok(response) => {
                    info!("GitHub proxy success: status={}", response.status());
                    Ok(response)
                }
                Err(err) => {
                    error!("GitHub proxy failure: {}", err);
                    Err(StatusCode::BAD_GATEWAY)
                }
            }
        }
        Err(ProxyError::InvalidTarget(msg)) => {
            warn!("Invalid GitHub target: {}", msg);
            let error_msg = format!(
                "Invalid GitHub Request\n\n{}\n\nPlease use one of these formats:\n\
                - /github/owner/repo/path/to/file\n\
                - Direct GitHub URLs\n",
                msg
            );
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(error_msg))
                .unwrap())
        }
        Err(err) => {
            error!("GitHub target resolution error: {}", err);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

/// Resolve GitHub target URI from path
pub fn resolve_github_target(_state: &AppState, path: &str) -> ProxyResult<Uri> {
    let path = path.trim_start_matches('/');

    if path.is_empty() {
        return Err(ProxyError::InvalidTarget(
            "Path cannot be empty".to_string(),
        ));
    }

    // Build raw.githubusercontent.com URL
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() < 3 {
        return Err(ProxyError::InvalidTarget(
            "Path must contain at least owner/repo/branch".to_string(),
        ));
    }

    let owner = parts[0];
    let repo = parts[1];
    let branch = parts[2];
    let file_path = if parts.len() > 3 { parts[3] } else { "" };

    let target_path = if file_path.is_empty() {
        format!("/{}/{}/{}", owner, repo, branch)
    } else {
        format!("/{}/{}/{}/{}", owner, repo, branch, file_path)
    };

    let authority = Authority::from_static("raw.githubusercontent.com");
    let path_and_query = PathAndQuery::from_str(&target_path)
        .map_err(|e| ProxyError::InvalidTarget(format!("Invalid path: {}", e)))?;

    Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| ProxyError::InvalidTarget(format!("Failed to build URI: {}", e)))
}

/// Convert GitHub blob URL to raw URL
pub fn convert_github_blob_to_raw(url: &str) -> String {
    // Convert github.com/owner/repo/blob/branch/file to raw.githubusercontent.com/owner/repo/branch/file
    if url.contains("github.com") && url.contains("/blob/") {
        url.replace("github.com", "raw.githubusercontent.com")
            .replace("/blob/", "/")
    } else {
        url.to_string()
    }
}

/// Check if URL is a GitHub repository homepage
pub fn is_github_repo_homepage(url: &str) -> bool {
    // Match patterns like:
    // - https://github.com/owner/repo
    // - https://github.com/owner/repo/
    // But NOT:
    // - https://github.com/owner/repo/blob/...
    // - https://github.com/owner/repo/raw/...
    // - https://github.com/owner/repo/tree/...
    if !url.contains("github.com/") {
        return false;
    }

    let after_github = url.split("github.com/").nth(1).unwrap_or("");
    let parts: Vec<&str> = after_github.trim_end_matches('/').split('/').collect();

    // Should have exactly 2 parts (owner/repo) and no more
    parts.len() == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_blob_to_raw() {
        let blob_url = "https://github.com/owner/repo/blob/main/README.md";
        let raw_url = convert_github_blob_to_raw(blob_url);
        assert_eq!(
            raw_url,
            "https://raw.githubusercontent.com/owner/repo/main/README.md"
        );
    }

    #[test]
    fn test_is_repo_homepage() {
        assert!(is_github_repo_homepage("https://github.com/owner/repo"));
        assert!(is_github_repo_homepage("https://github.com/owner/repo/"));
        assert!(!is_github_repo_homepage(
            "https://github.com/owner/repo/blob/main/file.txt"
        ));
        assert!(!is_github_repo_homepage(
            "https://github.com/owner/repo/tree/main"
        ));
        assert!(!is_github_repo_homepage("https://example.com"));
    }
}
