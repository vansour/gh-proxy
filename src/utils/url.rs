use crate::utils::regex as regex_utils;
/// URL and proxy handling utilities
/// Provides URL validation, transformation, and proxy URL rewriting
use regex::Captures;

/// Add proxy URL prefix to GitHub URLs in plain text
pub fn add_proxy_to_github_urls(content: &str, proxy_url: &str) -> String {
    // proxy_url should already have the protocol (e.g., "https://example.com" or "http://example.com")
    // If not, add https as default
    let proxy_url = if proxy_url.starts_with("http://") || proxy_url.starts_with("https://") {
        proxy_url.to_string()
    } else {
        format!("https://{}", proxy_url)
    };

    let mut result = content.to_string();

    // Replace raw.githubusercontent.com URLs using lazy-initialized pattern
    result = regex_utils::get_raw_pattern()
        .replace_all(&result, |caps: &Captures| {
            let url = &caps[0];
            if url.contains(&proxy_url) || url.contains("localhost") || url.contains("127.0.0.1") {
                // Already proxied
                url.to_string()
            } else {
                // Wrap with proxy URL
                format!("{}/{}", proxy_url, url)
            }
        })
        .to_string();

    // Replace github.com URLs using lazy-initialized pattern
    result = regex_utils::get_github_pattern()
        .replace_all(&result, |caps: &Captures| {
            let url = &caps[0];
            if url.contains(&proxy_url) || url.contains("localhost") || url.contains("127.0.0.1") {
                // Already proxied
                url.to_string()
            } else {
                // Wrap with proxy URL
                format!("{}/{}", proxy_url, url)
            }
        })
        .to_string();

    result
}

/// Add proxy URL prefix to GitHub URLs in HTML content
pub fn add_proxy_to_html_urls(content: &str, proxy_url: &str) -> String {
    // proxy_url should already have the protocol (e.g., "https://example.com" or "http://example.com")
    // If not, add https as default
    let proxy_url = if proxy_url.starts_with("http://") || proxy_url.starts_with("https://") {
        proxy_url.to_string()
    } else {
        format!("https://{}", proxy_url)
    };

    let mut result = content.to_string();

    // Replace all GitHub URLs with proxied versions using lazy-initialized pattern
    result = regex_utils::get_link_pattern()
        .replace_all(&result, |caps: &Captures| {
            let url = &caps[1];
            if url.contains(&proxy_url) || url.contains("localhost") || url.contains("127.0.0.1") {
                // Already proxied, don't double-proxy
                url.to_string()
            } else {
                // Wrap with proxy URL
                format!("{}/{}", proxy_url, url)
            }
        })
        .to_string();

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_proxy_to_github_urls() {
        let input = "https://github.com/owner/repo";
        let result = add_proxy_to_github_urls(input, "https://proxy.com");
        assert!(result.contains("proxy.com"));
    }

    #[test]
    fn test_already_proxied_url() {
        let input = "https://proxy.com/https://github.com/owner/repo";
        let result = add_proxy_to_github_urls(input, "https://proxy.com");
        // Should not double-proxy
        assert_eq!(
            result
                .matches("https://proxy.com/https://github.com")
                .count(),
            1
        );
    }
}
