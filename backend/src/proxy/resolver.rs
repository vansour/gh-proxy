//! URL resolution and validation for proxy targets.

use axum::http::Uri;
use hyper::http::uri::PathAndQuery;
use std::borrow::Cow;
use std::str::FromStr;
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
    validate_target_uri(target_uri, host_guard)
}

/// Validate an already resolved target URI against policy.
pub fn validate_target_uri(target_uri: Uri, host_guard: &GitHubConfig) -> ProxyResult<Uri> {
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

/// Resolve a redirect location against the current target and validate it.
pub fn resolve_redirect_uri(
    current_uri: &Uri,
    location: &str,
    host_guard: &GitHubConfig,
) -> ProxyResult<Uri> {
    let location = location.trim();
    if location.is_empty() {
        return Err(ProxyError::InvalidTarget(
            "redirect location cannot be empty".to_string(),
        ));
    }

    let target_uri = if location.starts_with("http://") || location.starts_with("https://") {
        parse_target_uri(location)?
    } else if location.starts_with("//") {
        let scheme = current_uri.scheme_str().unwrap_or("https");
        parse_target_uri(&format!("{}:{}", scheme, location))?
    } else {
        let scheme = current_uri.scheme_str().unwrap_or("https");
        let authority = current_uri.authority().ok_or_else(|| {
            ProxyError::InvalidTarget("current URI missing authority for redirect".to_string())
        })?;
        let path_and_query = resolve_relative_path_and_query(current_uri, location)?;

        Uri::builder()
            .scheme(scheme)
            .authority(authority.as_str())
            .path_and_query(path_and_query)
            .build()
            .map_err(|err| ProxyError::InvalidTarget(format!("invalid redirect URI: {}", err)))?
    };

    validate_target_uri(target_uri, host_guard)
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
        return parse_target_uri(&converted).map_err(|err| err.to_string());
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
        return parse_target_uri(&converted).map_err(|err| err.to_string());
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

fn parse_target_uri(raw: &str) -> ProxyResult<Uri> {
    match raw.parse::<Uri>() {
        Ok(uri) => Ok(uri),
        Err(_) => {
            if let Some(slash_idx) = raw
                .find("://")
                .and_then(|idx| raw[idx + 3..].find('/').map(|offset| idx + 3 + offset))
            {
                let (prefix, rest) = raw.split_at(slash_idx);
                let (path_part, query_part) = match rest.split_once('?') {
                    Some((path, query)) => (path, Some(query)),
                    None => (rest, None),
                };
                let encoded_path = crate::utils::url::encode_problematic_path_chars(path_part);
                let mut rebuilt = String::new();
                rebuilt.push_str(prefix);
                rebuilt.push_str(&encoded_path);
                if let Some(query) = query_part {
                    rebuilt.push('?');
                    rebuilt.push_str(query);
                }
                rebuilt.parse::<Uri>().map_err(|err| {
                    ProxyError::InvalidTarget(format!("invalid URL '{}': {}", raw, err))
                })
            } else {
                Err(ProxyError::InvalidTarget(format!("invalid URL '{}'", raw)))
            }
        }
    }
}

fn resolve_relative_path_and_query(current_uri: &Uri, location: &str) -> ProxyResult<PathAndQuery> {
    if location.starts_with('/') {
        return parse_path_and_query(location);
    }

    if location.starts_with('?') {
        return parse_path_and_query(&format!("{}{}", current_uri.path(), location));
    }

    let location_without_fragment = location.split('#').next().unwrap_or(location);
    let (relative_path, query_suffix) = match location_without_fragment.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (location_without_fragment, None),
    };

    let base_dir = current_uri
        .path()
        .rsplit_once('/')
        .map(|(prefix, _)| {
            if prefix.is_empty() {
                "/".to_string()
            } else {
                format!("{}/", prefix)
            }
        })
        .unwrap_or_else(|| "/".to_string());
    let mut resolved_path = normalize_relative_path(&base_dir, relative_path);
    if let Some(query) = query_suffix {
        resolved_path.push('?');
        resolved_path.push_str(query);
    }

    parse_path_and_query(&resolved_path)
}

fn normalize_relative_path(base_dir: &str, relative_path: &str) -> String {
    let mut segments: Vec<&str> = base_dir
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();

    for segment in relative_path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            value => segments.push(value),
        }
    }

    if segments.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", segments.join("/"))
    }
}

fn parse_path_and_query(raw: &str) -> ProxyResult<PathAndQuery> {
    let path = if raw.is_empty() { "/" } else { raw };
    match PathAndQuery::from_str(path) {
        Ok(value) => Ok(value),
        Err(_) => {
            let (path_part, query_part) = match path.split_once('?') {
                Some((path, query)) => (path, Some(query)),
                None => (path, None),
            };
            let encoded_path = crate::utils::url::encode_problematic_path_chars(path_part);
            let mut rebuilt = encoded_path.into_owned();
            if let Some(query) = query_part {
                rebuilt.push('?');
                rebuilt.push_str(query);
            }
            PathAndQuery::from_str(&rebuilt).map_err(|err| {
                ProxyError::InvalidTarget(format!("invalid redirect path '{}': {}", raw, err))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;

    #[test]
    fn resolve_redirect_uri_supports_relative_paths() {
        let guard = GitHubConfig::new(
            "",
            &ProxyConfig {
                allowed_hosts: vec!["example.com".to_string()],
            },
        );
        let current = Uri::from_static("https://example.com/releases/download/v1/file.txt");

        let redirect = resolve_redirect_uri(&current, "../other.txt?download=1", &guard)
            .expect("resolve relative redirect");

        assert_eq!(
            redirect.to_string(),
            "https://example.com/releases/download/other.txt?download=1"
        );
    }

    #[test]
    fn resolve_redirect_uri_rejects_unsupported_hosts() {
        let guard = GitHubConfig::new("", &ProxyConfig::default());
        let current =
            Uri::from_static("https://github.com/owner/repo/releases/download/v1/file.txt");

        let error = resolve_redirect_uri(&current, "https://example.com/file.txt", &guard)
            .expect_err("unsupported host should be rejected");

        assert!(matches!(error, ProxyError::UnsupportedHost(host) if host == "example.com"));
    }
}
