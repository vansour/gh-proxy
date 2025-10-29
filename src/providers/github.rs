use crate::{AppState, ProxyError, ProxyResult};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{Response, StatusCode, Uri},
};
use hyper::header;
use hyper::http::uri::{Authority, PathAndQuery};
use std::str::FromStr;
use tracing::{error, info, instrument, warn};
#[instrument(skip_all, fields(path = %path))]
pub async fn github_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    info!("GitHub proxy request: {} {}", req.method(), path);
    let query = req.uri().query().map(|q| q.to_string());
    match resolve_github_target(&state, &path, query) {
        Ok(target_uri) => {
            info!("Resolved GitHub target: {}", target_uri);
            match crate::proxy_request(&state, req, target_uri, None).await {
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
fn detect_github_domain(path: &str) -> &'static str {
    if path.contains("/releases/download/") {
        return "github.com";
    }
    if path.contains("/zipball/")
        || path.contains("/tarball/")
        || path.contains("/tar.gz/")
        || path.contains("/zip/")
    {
        return "codeload.github.com";
    }
    "raw.githubusercontent.com"
}
pub fn resolve_github_target(
    _state: &AppState,
    path: &str,
    query: Option<String>,
) -> ProxyResult<Uri> {
    let path = path.trim_start_matches('/');
    if path.is_empty() {
        return Err(ProxyError::InvalidTarget(
            "Path cannot be empty".to_string(),
        ));
    }
    let parts: Vec<&str> = path.splitn(4, '/').collect();
    if parts.len() < 2 {
        return Err(ProxyError::InvalidTarget(
            "Path must contain at least owner/repo".to_string(),
        ));
    }
    let owner = parts[0];
    let repo = parts[1];
    let domain = detect_github_domain(path);
    let target_path = format!("/{}", path);
    let path_with_query = if let Some(q) = query {
        format!("{}?{}", target_path, q)
    } else {
        target_path
    };
    let authority = match domain {
        "github.com" => Authority::from_static("github.com"),
        "codeload.github.com" => Authority::from_static("codeload.github.com"),
        "raw.githubusercontent.com" => Authority::from_static("raw.githubusercontent.com"),
        _ => Authority::from_static("raw.githubusercontent.com"),
    };
    let path_and_query = PathAndQuery::from_str(&path_with_query)
        .map_err(|e| ProxyError::InvalidTarget(format!("Invalid path: {}", e)))?;
    info!(
        "GitHub target resolution - owner: {}, repo: {}, domain: {}, path: {}",
        owner, repo, domain, path_with_query
    );
    Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| ProxyError::InvalidTarget(format!("Failed to build URI: {}", e)))
}
pub fn convert_github_blob_to_raw(url: &str) -> String {
    if !url.contains("/blob/") {
        return url.to_string();
    }
    if url.contains("://github.com/") && url.contains("/blob/") {
        return url
            .replace("://github.com/", "://raw.githubusercontent.com/")
            .replace("/blob/", "/");
    }
    if url.contains("/blob/") {
        return url.replace("/blob/", "/");
    }
    url.to_string()
}
pub fn is_github_web_only_path(url: &str) -> bool {
    if url.contains("api.github.com") {
        return false;
    }
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
pub fn is_github_repo_homepage(url: &str) -> bool {
    if url.contains("api.github.com") {
        return false;
    }
    let github_domain_check = url.contains("github.com")
        || url.contains("githubusercontent.com")
        || (url.contains("github")
            && (url.contains(".com") || url.contains(".io") || url.contains(".org")));
    if !github_domain_check {
        return false;
    }
    let after_domain = if let Some(pos) = url.find("github.com") {
        url.split_at(pos + "github.com".len()).1
    } else if let Some(pos) = url.find("githubusercontent.com") {
        url.split_at(pos + "githubusercontent.com".len()).1
    } else if let Some(slash_pos) = url.find("://") {
        if let Some(next_slash) = url[slash_pos + 3..].find('/') {
            &url[slash_pos + 3 + next_slash..]
        } else {
            ""
        }
    } else {
        return false;
    };
    let after_domain = after_domain.trim_start_matches('/').trim_end_matches('/');
    let parts: Vec<&str> = after_domain.split('/').collect();
    parts.len() == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_github_domain_releases() {
        assert_eq!(
            detect_github_domain("owner/repo/releases/download/v1.0/file.tar.gz"),
            "github.com"
        );
    }

    #[test]
    fn test_detect_github_domain_archive() {
        assert_eq!(
            detect_github_domain("owner/repo/zipball/main"),
            "codeload.github.com"
        );
        assert_eq!(
            detect_github_domain("owner/repo/tarball/main"),
            "codeload.github.com"
        );
        assert_eq!(
            detect_github_domain("owner/repo/tar.gz/main"),
            "codeload.github.com"
        );
        assert_eq!(
            detect_github_domain("owner/repo/zip/main"),
            "codeload.github.com"
        );
    }

    #[test]
    fn test_detect_github_domain_default() {
        assert_eq!(
            detect_github_domain("owner/repo/file.txt"),
            "raw.githubusercontent.com"
        );
    }

    #[test]
    fn test_convert_github_blob_to_raw() {
        let url = "https://github.com/owner/repo/blob/main/file.txt";
        let result = convert_github_blob_to_raw(url);
        assert_eq!(
            result,
            "https://raw.githubusercontent.com/owner/repo/main/file.txt"
        );
    }

    #[test]
    fn test_convert_github_blob_to_raw_no_blob() {
        let url = "https://github.com/owner/repo/raw/main/file.txt";
        let result = convert_github_blob_to_raw(url);
        assert_eq!(result, url);
    }

    #[test]
    fn test_convert_github_blob_to_raw_generic_blob() {
        let url = "https://example.com/blob/main/file.txt";
        let result = convert_github_blob_to_raw(url);
        assert_eq!(result, "https://example.com/main/file.txt");
    }

    #[test]
    fn test_is_github_web_only_path_releases() {
        assert!(is_github_web_only_path("/releases/tag/v1.0"));
        assert!(is_github_web_only_path("/releases/"));
    }

    #[test]
    fn test_is_github_web_only_path_download() {
        // /releases/download/ is NOT a web-only path
        assert!(!is_github_web_only_path(
            "/releases/download/v1.0/file.tar.gz"
        ));
    }

    #[test]
    fn test_is_github_web_only_path_api() {
        assert!(!is_github_web_only_path("api.github.com/repos/owner/repo"));
    }

    #[test]
    fn test_is_github_web_only_path_actions() {
        assert!(is_github_web_only_path("/actions/runs/123"));
    }

    #[test]
    fn test_is_github_web_only_path_issues() {
        assert!(is_github_web_only_path("/issues/123"));
    }

    #[test]
    fn test_is_github_web_only_path_file() {
        assert!(!is_github_web_only_path("/owner/repo/file.txt"));
    }

    #[test]
    fn test_is_github_repo_homepage_two_parts() {
        assert!(is_github_repo_homepage("https://github.com/owner/repo"));
        assert!(is_github_repo_homepage("github.com/owner/repo"));
    }

    #[test]
    fn test_is_github_repo_homepage_file_path() {
        assert!(!is_github_repo_homepage(
            "https://github.com/owner/repo/blob/main/file.txt"
        ));
        assert!(!is_github_repo_homepage(
            "https://github.com/owner/repo/tree/main"
        ));
    }

    #[test]
    fn test_is_github_repo_homepage_api() {
        assert!(!is_github_repo_homepage("api.github.com/repos/owner/repo"));
    }

    #[test]
    fn test_is_github_repo_homepage_raw_github() {
        assert!(!is_github_repo_homepage(
            "https://raw.githubusercontent.com/owner/repo/main/file.txt"
        ));
    }

    #[test]
    fn test_is_github_repo_homepage_non_github() {
        assert!(!is_github_repo_homepage("https://example.com/owner/repo"));
    }
}
