use super::parse_target_uri;
use axum::http::Uri;
use hyper::http::uri::PathAndQuery;
use std::str::FromStr;

use crate::config::GitHubConfig;
use crate::errors::{ProxyError, ProxyResult};

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

    super::validate::validate_target_uri(target_uri, host_guard)
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
