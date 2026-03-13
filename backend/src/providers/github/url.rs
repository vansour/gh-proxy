use axum::http::Uri;
use std::borrow::Cow;
use std::str::FromStr;

pub fn convert_github_blob_to_raw(url: &str) -> String {
    let mut result = url.to_string();

    if result.contains("/blob/") {
        if result.contains("://github.com/") {
            result = result
                .replace("://github.com/", "://raw.githubusercontent.com/")
                .replace("/blob/", "/");
        } else {
            result = result.replace("/blob/", "/");
        }
    }

    if result.contains("/raw/refs/heads/") {
        if result.contains("://github.com/") {
            result = result.replace("://github.com/", "://raw.githubusercontent.com/");
        }
        result = result.replace("/raw/refs/heads/", "/");
    }

    if result.contains("/raw/refs/tags/") {
        if result.contains("://github.com/") {
            result = result.replace("://github.com/", "://raw.githubusercontent.com/");
        }
        result = result.replace("/raw/refs/tags/", "/");
    }

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
    if url
        .find("/releases/")
        .map(|idx| url[idx + "/releases/".len()..].contains("/download/"))
        .unwrap_or(false)
    {
        return false;
    }

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
