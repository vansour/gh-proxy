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

/// Convert GitHub raw paths from new format to the format supported by raw.githubusercontent.com.
///
/// GitHub now supports URLs like:
/// - github.com/owner/repo/raw/refs/heads/branch/path/to/file
/// - github.com/owner/repo/raw/refs/tags/tag/path/to/file
///
/// But raw.githubusercontent.com expects:
/// - raw.githubusercontent.com/owner/repo/branch/path/to/file
/// - raw.githubusercontent.com/owner/repo/tag/path/to/file
fn normalize_github_raw_path(path: &str) -> std::borrow::Cow<'_, str> {
    // Patterns to normalize:
    // /raw/refs/heads/<branch>/... -> /<branch>/...
    // /raw/refs/tags/<tag>/... -> /<tag>/...
    // /raw/<branch>/... -> /<branch>/... (already correct for raw.githubusercontent.com)

    if let Some(idx) = path.find("/raw/refs/heads/") {
        let before = &path[..idx];
        let after = &path[idx + "/raw/refs/heads/".len()..];
        return std::borrow::Cow::Owned(format!("{}/{}", before, after));
    }

    if let Some(idx) = path.find("/raw/refs/tags/") {
        let before = &path[..idx];
        let after = &path[idx + "/raw/refs/tags/".len()..];
        return std::borrow::Cow::Owned(format!("{}/{}", before, after));
    }

    // Handle /raw/<branch>/... format - remove the /raw/ prefix
    if let Some(idx) = path.find("/raw/") {
        // Make sure it's not already processed (not /refs/)
        let after_raw = &path[idx + "/raw/".len()..];
        if !after_raw.starts_with("refs/") {
            let before = &path[..idx];
            return std::borrow::Cow::Owned(format!("{}/{}", before, after_raw));
        }
    }

    std::borrow::Cow::Borrowed(path)
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

    // Normalize raw paths for raw.githubusercontent.com
    let normalized_path = if domain == GithubDomain::RawUserContent {
        normalize_github_raw_path(path)
    } else {
        std::borrow::Cow::Borrowed(path)
    };

    let query_str = query.as_deref();
    let mut path_with_query = String::with_capacity(
        1 + normalized_path.len() + query_str.map(|q| 1 + q.len()).unwrap_or(0),
    );
    path_with_query.push('/');
    path_with_query.push_str(&normalized_path);
    if let Some(q) = query_str {
        path_with_query.push('?');
        path_with_query.push_str(q);
    }

    let path_and_query = match PathAndQuery::from_str(&path_with_query) {
        Ok(v) => v,
        Err(_) => {
            use crate::utils::url::encode_problematic_path_chars;
            let (p, q) = match path_with_query.split_once('?') {
                Some((pp, qq)) => (pp, Some(qq)),
                None => (path_with_query.as_str(), None),
            };
            let encoded_path = encode_problematic_path_chars(p);
            let mut rebuilt = String::new();
            rebuilt.push_str(&encoded_path);
            if let Some(qs) = q {
                rebuilt.push('?');
                rebuilt.push_str(qs);
            }
            PathAndQuery::from_str(&rebuilt)
                .map_err(|e| ProxyError::InvalidTarget(format!("Invalid path: {}", e)))?
        }
    };
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
    let mut result = url.to_string();

    // Handle /blob/ URLs
    if result.contains("/blob/") {
        if result.contains("://github.com/") {
            result = result
                .replace("://github.com/", "://raw.githubusercontent.com/")
                .replace("/blob/", "/");
        } else {
            result = result.replace("/blob/", "/");
        }
    }

    // Handle /raw/refs/heads/ URLs (new GitHub format)
    // e.g., github.com/owner/repo/raw/refs/heads/main/file -> raw.githubusercontent.com/owner/repo/main/file
    if result.contains("/raw/refs/heads/") {
        if result.contains("://github.com/") {
            result = result.replace("://github.com/", "://raw.githubusercontent.com/");
        }
        result = result.replace("/raw/refs/heads/", "/");
    }

    // Handle /raw/refs/tags/ URLs
    if result.contains("/raw/refs/tags/") {
        if result.contains("://github.com/") {
            result = result.replace("://github.com/", "://raw.githubusercontent.com/");
        }
        result = result.replace("/raw/refs/tags/", "/");
    }

    // Handle simple /raw/ URLs (e.g., github.com/owner/repo/raw/main/file)
    if result.contains("://github.com/") && result.contains("/raw/") {
        result = result
            .replace("://github.com/", "://raw.githubusercontent.com/")
            .replace("/raw/", "/");
    }

    result
}

pub fn is_github_web_only_path(url: &str) -> bool {
    if url.contains("api.github.com") {
        return false;
    }
    if url.contains("/releases/download/") {
        return false;
    }
    // Support common variant: /releases/<tag-or-latest>/download/<file>
    if url
        .find("/releases/")
        .map(|idx| url[idx + "/releases/".len()..].contains("/download/"))
        .unwrap_or(false)
    {
        return false;
    }

    // Explicit check for paths ending with /releases or /tags (without trailing slash)
    if url.ends_with("/releases") || url.ends_with("/tags") {
        return true;
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
    fn test_normalize_github_raw_path_refs_heads() {
        let path = "vansour/clash/raw/refs/heads/main/clash.yaml";
        let result = normalize_github_raw_path(path);
        assert_eq!(result, "vansour/clash/main/clash.yaml");
    }

    #[test]
    fn test_normalize_github_raw_path_refs_tags() {
        let path = "owner/repo/raw/refs/tags/v1.0.0/file.txt";
        let result = normalize_github_raw_path(path);
        assert_eq!(result, "owner/repo/v1.0.0/file.txt");
    }

    #[test]
    fn test_normalize_github_raw_path_simple_raw() {
        let path = "owner/repo/raw/main/path/to/file.txt";
        let result = normalize_github_raw_path(path);
        assert_eq!(result, "owner/repo/main/path/to/file.txt");
    }

    #[test]
    fn test_normalize_github_raw_path_no_raw() {
        let path = "owner/repo/main/file.txt";
        let result = normalize_github_raw_path(path);
        assert_eq!(result, "owner/repo/main/file.txt");
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
    fn test_convert_github_raw_refs_heads_to_raw() {
        let url = "https://github.com/vansour/clash/raw/refs/heads/main/clash.yaml";
        let result = convert_github_blob_to_raw(url);
        assert_eq!(
            result,
            "https://raw.githubusercontent.com/vansour/clash/main/clash.yaml"
        );
    }

    #[test]
    fn test_convert_github_raw_refs_tags_to_raw() {
        let url = "https://github.com/owner/repo/raw/refs/tags/v1.0.0/file.txt";
        let result = convert_github_blob_to_raw(url);
        assert_eq!(
            result,
            "https://raw.githubusercontent.com/owner/repo/v1.0.0/file.txt"
        );
    }

    #[test]
    fn test_convert_github_simple_raw_to_raw() {
        let url = "https://github.com/owner/repo/raw/main/file.txt";
        let result = convert_github_blob_to_raw(url);
        assert_eq!(
            result,
            "https://raw.githubusercontent.com/owner/repo/main/file.txt"
        );
    }
}
