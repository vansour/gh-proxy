/// Static file and content caching with lazy initialization
/// Reduces disk I/O by caching frequently accessed files in memory
use std::sync::OnceLock;

static INDEX_HTML: OnceLock<String> = OnceLock::new();
static FAVICON_ICO: OnceLock<Vec<u8>> = OnceLock::new();
static INDEX_HTML_ETAG: OnceLock<String> = OnceLock::new();
#[allow(dead_code)]
static FAVICON_ETAG: OnceLock<String> = OnceLock::new();

/// Generate a simple ETag from content hash
fn calculate_etag(data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    data.hash(&mut hasher);
    let hash = hasher.finish();
    format!("\"{}\"", hash)
}

/// Get cached index.html content, loading from disk on first access
pub fn get_index_html() -> &'static String {
    INDEX_HTML.get_or_init(|| match std::fs::read_to_string("/app/web/index.html") {
        Ok(content) => content,
        Err(_) => r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>gh-proxy</title>
</head>
<body>
    <h1>gh-proxy - GitHub Proxy</h1>
    <p>Web UI not available. Please check the installation.</p>
</body>
</html>"#
            .to_string(),
    })
}

/// Get cached index.html ETag
pub fn get_index_html_etag() -> &'static String {
    INDEX_HTML_ETAG.get_or_init(|| {
        let html = get_index_html();
        calculate_etag(html.as_bytes())
    })
}

/// Get cached favicon content, loading from disk on first access
pub fn get_favicon() -> &'static Vec<u8> {
    FAVICON_ICO.get_or_init(|| match std::fs::read("/app/web/favicon.ico") {
        Ok(content) => content,
        Err(_) => Vec::new(),
    })
}

/// Get cached favicon ETag
#[allow(dead_code)]
pub fn get_favicon_etag() -> &'static String {
    FAVICON_ETAG.get_or_init(|| {
        let favicon = get_favicon();
        calculate_etag(favicon)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_index_html_cache() {
        let html1 = get_index_html();
        let html2 = get_index_html();
        // Should return the same reference (cached)
        assert_eq!(html1.as_ptr(), html2.as_ptr());
    }

    #[test]
    fn test_favicon_cache() {
        let favicon1 = get_favicon();
        let favicon2 = get_favicon();
        // Should return the same reference (cached)
        assert_eq!(favicon1.as_ptr(), favicon2.as_ptr());
    }

    #[test]
    fn test_etag_consistency() {
        let etag1 = get_index_html_etag();
        let etag2 = get_index_html_etag();
        assert_eq!(etag1, etag2);
    }
}
