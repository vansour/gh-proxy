use crate::utils::regex as regex_utils;
use regex::Regex;
use std::borrow::Cow;

fn normalize_proxy_url(proxy_url: &str) -> Cow<'_, str> {
    if proxy_url.starts_with("http://") || proxy_url.starts_with("https://") {
        Cow::Borrowed(proxy_url)
    } else {
        Cow::Owned(format!("https://{}", proxy_url))
    }
}

pub fn add_proxy_to_github_urls<'a>(content: &'a str, proxy_url: &str) -> Cow<'a, str> {
    let proxy_url = normalize_proxy_url(proxy_url);
    let proxy_url_str = proxy_url.as_ref();
    match rewrite_with_regex(regex_utils::get_raw_pattern(), content, proxy_url_str) {
        Cow::Borrowed(original) => {
            rewrite_with_regex(regex_utils::get_github_pattern(), original, proxy_url_str)
        }
        Cow::Owned(owned) => {
            match rewrite_with_regex(regex_utils::get_github_pattern(), &owned, proxy_url_str) {
                Cow::Borrowed(_) => Cow::Owned(owned),
                Cow::Owned(updated) => Cow::Owned(updated),
            }
        }
    }
}

pub fn add_proxy_to_html_urls<'a>(content: &'a str, proxy_url: &str) -> Cow<'a, str> {
    let proxy_url = normalize_proxy_url(proxy_url);
    let proxy_url_str = proxy_url.as_ref();
    rewrite_with_regex(regex_utils::get_link_pattern(), content, proxy_url_str)
}

/// Percent-encode a small set of characters that commonly appear unencoded in
/// example URLs (like shell expansion snippets) and are rejected by strict URI
/// parsers. This purposely only encodes a small set of known-problematic
/// characters so we don't double-encode existing percent-encoded values.
pub fn encode_problematic_path_chars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '$' => out.push_str("%24"),
            '(' => out.push_str("%28"),
            ')' => out.push_str("%29"),
            ' ' => out.push_str("%20"),
            _ => out.push(ch),
        }
    }
    out
}

/// Given a full URL string like `https://example.com/a/b c`, percent-encode the
/// path portion (everything starting at the first '/' after authority). This is a
/// conservative helper used when a request fails and we want to retry with the
/// path portion encoded. Returns owned string; if no path portion exists the
/// original string is returned.
pub fn encode_path_of_full_url(url: &str) -> String {
    if let Some(idx) = url.find("://") {
        // find next slash after scheme://
        if let Some(slash_idx) = url[idx + 3..].find('/').map(|i| idx + 3 + i) {
            let (pre, rest) = url.split_at(slash_idx);
            // rest begins with '/'
            let (path, query_part) = match rest.split_once('?') {
                Some((p, q)) => (p, Some(q)),
                None => (rest, None),
            };
            let encoded_path = encode_problematic_path_chars(path);
            let mut rebuilt = String::with_capacity(url.len());
            rebuilt.push_str(pre);
            rebuilt.push_str(&encoded_path);
            if let Some(q) = query_part {
                rebuilt.push('?');
                rebuilt.push_str(q);
            }
            return rebuilt;
        }
    }
    // no authority/path found - return original
    url.to_string()
}

/// Rewrites URLs in `content` that match the given `regex` by prepending `proxy_url` to them.
///
/// # Parameters
/// - `regex`: The regular expression used to find URLs to rewrite.
/// - `content`: The input string containing URLs. The returned value may borrow from this string.
/// - `proxy_url`: The proxy URL to prepend to matched URLs.
///
/// # Return
/// Returns a `Cow<'a, str>`:
/// - If no URLs are rewritten, returns `Cow::Borrowed(content)`.
/// - If any URLs are rewritten, returns `Cow::Owned(String)` with the modified content.
///
/// # Lifetimes
/// The returned value borrows from `content` unless rewriting occurs, in which case an owned `String` is returned.
fn rewrite_with_regex<'a>(regex: &Regex, content: &'a str, proxy_url: &str) -> Cow<'a, str> {
    let mut buffer: Option<String> = None;
    let mut last = 0;
    for mat in regex.find_iter(content) {
        let url = mat.as_str();
        let should_rewrite =
            !url.contains(proxy_url) && !url.contains("localhost") && !url.contains("127.0.0.1");
        match buffer.as_mut() {
            Some(output) => {
                output.push_str(&content[last..mat.start()]);
                if should_rewrite {
                    output.push_str(proxy_url);
                    output.push('/');
                    output.push_str(url);
                } else {
                    output.push_str(url);
                }
            }
            None if should_rewrite => {
                let mut output = String::with_capacity(content.len() + proxy_url.len() + 1);
                output.push_str(&content[..mat.start()]);
                output.push_str(proxy_url);
                output.push('/');
                output.push_str(url);
                buffer = Some(output);
            }
            None => {}
        }
        last = mat.end();
    }
    match buffer {
        Some(mut output) => {
            output.push_str(&content[last..]);
            Cow::Owned(output)
        }
        None => Cow::Borrowed(content),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_proxy_to_github_urls_with_https() {
        let content = "https://raw.githubusercontent.com/owner/repo/main/file.txt";
        let result = add_proxy_to_github_urls(content, "https://proxy.example.com");
        assert!(
            result
                .as_ref()
                .contains("https://proxy.example.com/https://raw.githubusercontent.com")
        );
    }

    #[test]
    fn test_add_proxy_to_github_urls_without_schema() {
        let content = "https://raw.githubusercontent.com/owner/repo/main/file.txt";
        let result = add_proxy_to_github_urls(content, "proxy.example.com");
        assert!(
            result
                .as_ref()
                .contains("https://proxy.example.com/https://raw.githubusercontent.com")
        );
    }

    #[test]
    fn test_add_proxy_to_github_urls_skip_localhost() {
        let content = "https://raw.githubusercontent.com/owner/repo/main/file.txt";
        let result = add_proxy_to_github_urls(content, "localhost:8000");
        // localhost URLs should not be modified
        assert!(
            result
                .as_ref()
                .contains("https://raw.githubusercontent.com")
        );
    }

    #[test]
    fn test_add_proxy_to_github_urls_github_com() {
        let content = "https://github.com/owner/repo/blob/main/file.txt";
        let result = add_proxy_to_github_urls(content, "https://proxy.example.com");
        assert!(
            result
                .as_ref()
                .contains("https://proxy.example.com/https://github.com")
        );
    }

    #[test]
    fn test_add_proxy_to_html_urls() {
        let content = r#"<a href="https://github.com/owner/repo">Link</a>"#;
        let result = add_proxy_to_html_urls(content, "https://proxy.example.com");
        assert!(
            result
                .as_ref()
                .contains("https://proxy.example.com/https://github.com")
        );
    }

    #[test]
    fn test_add_proxy_to_html_urls_raw_github() {
        let content =
            r#"<a href="https://raw.githubusercontent.com/owner/repo/main/file.txt">File</a>"#;
        let result = add_proxy_to_html_urls(content, "proxy.example.com");
        assert!(
            result
                .as_ref()
                .contains("https://proxy.example.com/https://raw.githubusercontent.com")
        );
    }

    #[test]
    fn test_add_proxy_to_html_urls_skip_127() {
        let content = r#"<a href="https://github.com/owner/repo">Link</a>"#;
        let result = add_proxy_to_html_urls(content, "127.0.0.1:8000");
        assert!(result.as_ref().contains("https://github.com"));
    }

    #[test]
    fn test_add_proxy_to_html_urls_no_links() {
        let content = "This is plain text without links";
        let result = add_proxy_to_html_urls(content, "proxy.example.com");
        assert_eq!(result.as_ref(), content);
    }

    #[test]
    fn test_encode_path_of_full_url_encodes_special_chars() {
        let input = "https://github.com/owner/repo/releases/download/25.9.1/Miniforge3-$(uname)-file (x).sh";
        let encoded = encode_path_of_full_url(input);
        assert!(encoded.contains("%24%28uname%29"));
        assert!(encoded.contains("%20%28x%29"));
    }
}
