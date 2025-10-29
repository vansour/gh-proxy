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
