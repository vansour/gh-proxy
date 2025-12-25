//! URL resolution and validation for proxy targets.

use axum::http::Uri;
use std::borrow::Cow;
use tracing::debug;

use crate::config::GitHubConfig;
use crate::errors::{ProxyError, ProxyResult};
use crate::providers::github;

/// Resolve and validate target URI from request.
pub fn resolve_target_uri_with_validation(
    uri: &Uri,
    host_guard: &GitHubConfig,
) -> ProxyResult<Uri> {
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
    if github::is_github_web_only_path(&target_str) {
        return Err(ProxyError::GitHubWebPage(target_str));
    }
    if github::is_github_repo_homepage(&target_str) {
        return Err(ProxyError::GitHubRepoHomepage(target_str));
    }
    Ok(target_uri)
}

/// Resolve fallback target from URI path.
pub fn resolve_fallback_target(uri: &Uri) -> Result<Uri, String> {
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
        let mut converted = github::convert_github_blob_to_raw(normalized.as_ref());
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
        let mut converted = github::convert_github_blob_to_raw(&full_url);
        if let Some(q) = query {
            converted.push('?');
            converted.push_str(q);
        }
        return converted.parse::<Uri>().map_err(|e| e.to_string());
    }
    Err(format!("No valid target found for path: {}", normalized))
}

/// Check if path looks like a GitHub domain path.
pub fn is_github_domain_path(path: &str) -> bool {
    path.starts_with("github.com/")
        || path.starts_with("raw.githubusercontent.com/")
        || path.starts_with("api.github.com/")
        || path.starts_with("gist.github.com/")
        || path.starts_with("codeload.github.com/")
        || (path.contains("github")
            && (path.contains(".com/") || path.contains(".io/") || path.contains(".org/")))
}

/// Check if compression should be disabled for this request (for text editing).
pub fn should_disable_compression_for_request(uri: &Uri) -> bool {
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
