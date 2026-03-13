use crate::errors::{ProxyError, ProxyResult};
use axum::http::Uri;
use hyper::http::uri::{Authority, PathAndQuery};
use std::borrow::Cow;
use std::str::FromStr;
use tracing::info;

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

fn normalize_github_raw_path(path: &str) -> Cow<'_, str> {
    if let Some(idx) = path.find("/raw/refs/heads/") {
        let before = &path[..idx];
        let after = &path[idx + "/raw/refs/heads/".len()..];
        return Cow::Owned(format!("{}/{}", before, after));
    }

    if let Some(idx) = path.find("/raw/refs/tags/") {
        let before = &path[..idx];
        let after = &path[idx + "/raw/refs/tags/".len()..];
        return Cow::Owned(format!("{}/{}", before, after));
    }

    if let Some(idx) = path.find("/raw/") {
        let after_raw = &path[idx + "/raw/".len()..];
        if !after_raw.starts_with("refs/") {
            let before = &path[..idx];
            return Cow::Owned(format!("{}/{}", before, after_raw));
        }
    }

    Cow::Borrowed(path)
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

pub fn resolve_github_target(path: &str, query: Option<&str>) -> ProxyResult<Uri> {
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

    let (repo, rest) = remainder.split_once('/').ok_or_else(|| {
        ProxyError::InvalidTarget(
            "Path must include a file path or download path after owner/repo".to_string(),
        )
    })?;
    if repo.is_empty() {
        return Err(ProxyError::InvalidTarget(
            "Repository name cannot be empty".to_string(),
        ));
    }
    if rest.is_empty() {
        return Err(ProxyError::InvalidTarget(
            "Path after owner/repo cannot be empty".to_string(),
        ));
    }

    let domain = detect_github_domain(path);
    let normalized_path = if domain == GithubDomain::RawUserContent {
        normalize_github_raw_path(path)
    } else {
        Cow::Borrowed(path)
    };

    let mut path_with_query = String::with_capacity(
        1 + normalized_path.len() + query.map(|value| 1 + value.len()).unwrap_or(0),
    );
    path_with_query.push('/');
    path_with_query.push_str(&normalized_path);
    if let Some(query) = query {
        path_with_query.push('?');
        path_with_query.push_str(query);
    }

    let path_and_query = match PathAndQuery::from_str(&path_with_query) {
        Ok(value) => value,
        Err(_) => {
            use crate::utils::url::encode_problematic_path_chars;

            let (path_part, query_part) = match path_with_query.split_once('?') {
                Some((path, query)) => (path, Some(query)),
                None => (path_with_query.as_str(), None),
            };
            let encoded_path = encode_problematic_path_chars(path_part);
            let mut rebuilt = String::new();
            rebuilt.push_str(&encoded_path);
            if let Some(query) = query_part {
                rebuilt.push('?');
                rebuilt.push_str(query);
            }
            PathAndQuery::from_str(&rebuilt)
                .map_err(|err| ProxyError::InvalidTarget(format!("Invalid path: {}", err)))?
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
        .map_err(|err| ProxyError::InvalidTarget(format!("Failed to build URI: {}", err)))
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
    fn test_resolve_github_target_rejects_repo_homepage_style_path() {
        let error =
            resolve_github_target("owner/repo", None).expect_err("repo homepage path should fail");

        assert!(matches!(error, ProxyError::InvalidTarget(_)));
        assert!(error.to_string().contains("file path"));
    }
}
