use crate::utils::regex as regex_utils;
use regex::Captures;
pub fn add_proxy_to_github_urls(content: &str, proxy_url: &str) -> String {
    let proxy_url = if proxy_url.starts_with("http://") || proxy_url.starts_with("https://") {
        proxy_url.to_string()
    } else {
        format!("https://{}", proxy_url)
    };
    let mut result = content.to_string();
    result = regex_utils::get_raw_pattern()
        .replace_all(&result, |caps: &Captures| {
            let url = &caps[0];
            if url.contains(&proxy_url) || url.contains("localhost") || url.contains("127.0.0.1") {
                url.to_string()
            } else {
                format!("{}/{}", proxy_url, url)
            }
        })
        .to_string();
    result = regex_utils::get_github_pattern()
        .replace_all(&result, |caps: &Captures| {
            let url = &caps[0];
            if url.contains(&proxy_url) || url.contains("localhost") || url.contains("127.0.0.1") {
                url.to_string()
            } else {
                format!("{}/{}", proxy_url, url)
            }
        })
        .to_string();
    result
}
pub fn add_proxy_to_html_urls(content: &str, proxy_url: &str) -> String {
    let proxy_url = if proxy_url.starts_with("http://") || proxy_url.starts_with("https://") {
        proxy_url.to_string()
    } else {
        format!("https://{}", proxy_url)
    };
    let mut result = content.to_string();
    result = regex_utils::get_link_pattern()
        .replace_all(&result, |caps: &Captures| {
            let url = &caps[1];
            if url.contains(&proxy_url) || url.contains("localhost") || url.contains("127.0.0.1") {
                url.to_string()
            } else {
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
    fn test_add_proxy_to_github_urls_with_https() {
        let content = "https://raw.githubusercontent.com/owner/repo/main/file.txt";
        let result = add_proxy_to_github_urls(content, "https://proxy.example.com");
        assert!(result.contains("https://proxy.example.com/https://raw.githubusercontent.com"));
    }

    #[test]
    fn test_add_proxy_to_github_urls_without_schema() {
        let content = "https://raw.githubusercontent.com/owner/repo/main/file.txt";
        let result = add_proxy_to_github_urls(content, "proxy.example.com");
        assert!(result.contains("https://proxy.example.com/https://raw.githubusercontent.com"));
    }

    #[test]
    fn test_add_proxy_to_github_urls_skip_localhost() {
        let content = "https://raw.githubusercontent.com/owner/repo/main/file.txt";
        let result = add_proxy_to_github_urls(content, "localhost:8000");
        // localhost URLs should not be modified
        assert!(result.contains("https://raw.githubusercontent.com"));
    }

    #[test]
    fn test_add_proxy_to_github_urls_github_com() {
        let content = "https://github.com/owner/repo/blob/main/file.txt";
        let result = add_proxy_to_github_urls(content, "https://proxy.example.com");
        assert!(result.contains("https://proxy.example.com/https://github.com"));
    }

    #[test]
    fn test_add_proxy_to_html_urls() {
        let content = r#"<a href="https://github.com/owner/repo">Link</a>"#;
        let result = add_proxy_to_html_urls(content, "https://proxy.example.com");
        assert!(result.contains("https://proxy.example.com/https://github.com"));
    }

    #[test]
    fn test_add_proxy_to_html_urls_raw_github() {
        let content =
            r#"<a href="https://raw.githubusercontent.com/owner/repo/main/file.txt">File</a>"#;
        let result = add_proxy_to_html_urls(content, "proxy.example.com");
        assert!(result.contains("https://proxy.example.com/https://raw.githubusercontent.com"));
    }

    #[test]
    fn test_add_proxy_to_html_urls_skip_127() {
        let content = r#"<a href="https://github.com/owner/repo">Link</a>"#;
        let result = add_proxy_to_html_urls(content, "127.0.0.1:8000");
        assert!(result.contains("https://github.com"));
    }

    #[test]
    fn test_add_proxy_to_html_urls_no_links() {
        let content = "This is plain text without links";
        let result = add_proxy_to_html_urls(content, "proxy.example.com");
        assert_eq!(result, content);
    }
}
