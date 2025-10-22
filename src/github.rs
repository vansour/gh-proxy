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
            match crate::proxy_request(&state, req, target_uri, ProxyKind::GitHub, None).await {
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
            let response = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(error_msg))
                .unwrap_or_else(|e| {
                    error!("Failed to build GitHub error response: {}", e);
                    Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .body(Body::from("Internal Server Error"))
                        .unwrap_or_else(|_| Response::new(Body::from("Internal Server Error")))
                });
            Ok(response)
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

    // Build raw.githubusercontent.com URL (or appropriate raw domain)
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

    // Use raw.githubusercontent.com as the default raw content domain
    // This works with all GitHub domains (github.com, enterprise domains, etc.)
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
/// Supports any GitHub domain including custom enterprise domains
pub fn convert_github_blob_to_raw(url: &str) -> String {
    // Convert github.com/owner/repo/blob/branch/file to raw.githubusercontent.com/owner/repo/branch/file
    // Also support other GitHub domains like api.github.com, custom.github.com, etc.

    if !url.contains("/blob/") {
        return url.to_string();
    }

    // Handle standard github.com domain - convert to raw.githubusercontent.com
    if url.contains("://github.com/") && url.contains("/blob/") {
        return url
            .replace("://github.com/", "://raw.githubusercontent.com/")
            .replace("/blob/", "/");
    }

    // For other GitHub domains (api.github.com, custom domains, etc.)
    // Just remove /blob/ path segment without changing the domain
    if url.contains("/blob/") {
        return url.replace("/blob/", "/");
    }

    url.to_string()
}

/// Check if URL is a non-downloadable GitHub web page path
/// These paths return HTML pages that should not be proxied as file downloads
pub fn is_github_web_only_path(url: &str) -> bool {
    // API paths (api.github.com) should NOT be blocked - they are data endpoints
    if url.contains("api.github.com") {
        return false;
    }

    // Paths that are web pages, not file downloads:
    // - /pkgs/container/... (package pages)
    // - /releases/... (releases page, but NOT /releases/download/)
    // - /actions/... (GitHub Actions)
    // - /settings/... (repository settings)
    // - /security/... (security settings)
    // - /projects/... (project boards)
    // - /wiki/... (wiki pages)
    // - /discussions/... (discussions)
    // - /issues/... (issues page)
    // - /pulls/... (pull requests page)
    // - /search (search results)

    // Check for /releases/download/ first - this is a file download, not a web page
    if url.contains("/releases/download/") {
        return false;
    }

    let web_only_patterns = [
        "/pkgs/",
        "/releases/",
        "/actions/",
        "/settings/",
        "/security/",
        "/projects/",
        "/wiki/",
        "/discussions/",
        "/issues",
        "/pulls",
        "/search",
        "/notifications",
        "/network",
        "/graphs",
        "/deployments",
        "/branches",
        "/tags",
    ];

    for pattern in &web_only_patterns {
        if url.contains(pattern) {
            return true;
        }
    }

    false
}

/// Check if URL is a GitHub repository homepage
pub fn is_github_repo_homepage(url: &str) -> bool {
    // Match patterns like:
    // - https://github.com/owner/repo
    // - https://github.com/owner/repo/
    // - https://custom.github.com/owner/repo
    // But NOT:
    // - https://github.com/owner/repo/blob/...
    // - https://github.com/owner/repo/raw/...
    // - https://github.com/owner/repo/tree/...
    // - https://api.github.com/repos/... (API endpoints)

    // API paths (api.github.com) are never repository homepages
    if url.contains("api.github.com") {
        return false;
    }

    // Check if URL contains any GitHub domain
    let github_domain_check = url.contains("github.com")
        || url.contains("githubusercontent.com")
        || (url.contains("github")
            && (url.contains(".com") || url.contains(".io") || url.contains(".org")));

    if !github_domain_check {
        return false;
    }

    // Extract the part after the domain
    let after_domain = if let Some(pos) = url.find("github.com") {
        url.split_at(pos + "github.com".len()).1
    } else if let Some(pos) = url.find("githubusercontent.com") {
        url.split_at(pos + "githubusercontent.com".len()).1
    } else {
        // For other GitHub domains, find the first '/' after the domain
        if let Some(slash_pos) = url.find("://") {
            if let Some(next_slash) = url[slash_pos + 3..].find('/') {
                &url[slash_pos + 3 + next_slash..]
            } else {
                ""
            }
        } else {
            return false;
        }
    };

    let after_domain = after_domain.trim_start_matches('/').trim_end_matches('/');
    let parts: Vec<&str> = after_domain.split('/').collect();

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
    fn test_convert_blob_to_raw_other_domains() {
        // Test other GitHub domains
        let blob_url = "https://api.github.com/owner/repo/blob/main/file.txt";
        let raw_url = convert_github_blob_to_raw(blob_url);
        assert_eq!(raw_url, "https://api.github.com/owner/repo/main/file.txt");
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

    #[test]
    fn test_is_repo_homepage_other_domains() {
        // Test with other GitHub domains
        assert!(!is_github_repo_homepage(
            "https://api.github.com/owner/repo"
        ));
        assert!(!is_github_repo_homepage(
            "https://api.github.com/owner/repo/"
        ));
        assert!(!is_github_repo_homepage(
            "https://api.github.com/owner/repo/blob/main/file.txt"
        ));
    }
}
