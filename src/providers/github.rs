use crate::{AppState, ProxyError, ProxyResult};
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{Response, StatusCode, Uri},
};
use hyper::header;
use hyper::http::uri::{Authority, PathAndQuery};
use std::{borrow::Cow, str::FromStr};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GithubDomain {
    GithubCom,
    Codeload,
    RawUserContent,
}

impl GithubDomain {
    const fn as_str(self) -> &'static str {
        match self {
            GithubDomain::GithubCom => "github.com",
            GithubDomain::Codeload => "codeload.github.com",
            GithubDomain::RawUserContent => "raw.githubusercontent.com",
        }
    }

    fn authority(self) -> Authority {
        match self {
            GithubDomain::GithubCom => Authority::from_static("github.com"),
            GithubDomain::Codeload => Authority::from_static("codeload.github.com"),
            GithubDomain::RawUserContent => Authority::from_static("raw.githubusercontent.com"),
        }
    }
}

fn detect_github_domain(path: &str) -> GithubDomain {
    if path.contains("/releases/download/") {
        return GithubDomain::GithubCom;
    }
    if path.contains("/zipball/")
        || path.contains("/tarball/")
        || path.contains("/tar.gz/")
        || path.contains("/zip/")
    {
        return GithubDomain::Codeload;
    }
    GithubDomain::RawUserContent
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
    let (owner, remainder) = path.split_once('/').ok_or_else(|| {
        ProxyError::InvalidTarget("Path must contain at least owner/repo".to_string())
    })?;
    if owner.is_empty() {
        return Err(ProxyError::InvalidTarget(
            "Repository owner cannot be empty".to_string(),
        ));
    }
    let (repo, _rest) = remainder
        .split_once('/')
        .map(|(repo, rest)| (repo, Some(rest)))
        .unwrap_or((remainder, None));
    if repo.is_empty() {
        return Err(ProxyError::InvalidTarget(
            "Repository name cannot be empty".to_string(),
        ));
    }
    let domain = detect_github_domain(path);
    let query_str = query.as_deref();
    let mut path_with_query =
        String::with_capacity(1 + path.len() + query_str.map(|q| 1 + q.len()).unwrap_or(0));
    path_with_query.push('/');
    path_with_query.push_str(path);
    if let Some(q) = query_str {
        path_with_query.push('?');
        path_with_query.push_str(q);
    }
    let path_and_query = PathAndQuery::from_str(&path_with_query)
        .map_err(|e| ProxyError::InvalidTarget(format!("Invalid path: {}", e)))?;
    info!(
        "GitHub target resolution - owner: {}, repo: {}, domain: {}, path: {}",
        owner,
        repo,
        domain.as_str(),
        path_and_query
    );
    Uri::builder()
        .scheme("https")
        .authority(domain.authority())
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

    let normalized = if url.starts_with("http://") || url.starts_with("https://") {
        Cow::Borrowed(url)
    } else {
        Cow::Owned(format!("https://{}", url))
    };

    let parsed = match Uri::from_str(normalized.as_ref()) {
        Ok(uri) => uri,
        Err(_) => return false,
    };

    let host = parsed
        .authority()
        .map(|authority| authority.host())
        .unwrap_or("");

    if host.is_empty() {
        return false;
    }

    let is_github_domain = host.contains("github.com")
        || host.contains("githubusercontent.com")
        || (host.contains("github")
            && (host.ends_with(".com") || host.ends_with(".io") || host.ends_with(".org")));

    if !is_github_domain {
        return false;
    }

    let segments: Vec<_> = parsed
        .path_and_query()
        .map(|path_and_query| path_and_query.path())
        .unwrap_or("/")
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    segments.len() == 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_github_domain_releases() {
        assert_eq!(
            detect_github_domain("owner/repo/releases/download/v1.0/file.tar.gz"),
            GithubDomain::GithubCom
        );
    }

    #[test]
    fn test_detect_github_domain_archive() {
        assert_eq!(
            detect_github_domain("owner/repo/zipball/main"),
            GithubDomain::Codeload
        );
        assert_eq!(
            detect_github_domain("owner/repo/tarball/main"),
            GithubDomain::Codeload
        );
        assert_eq!(
            detect_github_domain("owner/repo/tar.gz/main"),
            GithubDomain::Codeload
        );
        assert_eq!(
            detect_github_domain("owner/repo/zip/main"),
            GithubDomain::Codeload
        );
    }

    #[test]
    fn test_detect_github_domain_default() {
        assert_eq!(
            detect_github_domain("owner/repo/file.txt"),
            GithubDomain::RawUserContent
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
