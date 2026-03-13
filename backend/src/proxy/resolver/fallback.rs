use super::parse_target_uri;
use axum::http::Uri;
use std::borrow::Cow;

use crate::providers::github;

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
        if let Some(query) = query {
            converted.push('?');
            converted.push_str(query);
        }
        return parse_target_uri(&converted).map_err(|err| err.to_string());
    }
    if is_github_domain_path(&normalized) {
        let mut full_url = String::with_capacity("https://".len() + normalized.len());
        full_url.push_str("https://");
        full_url.push_str(normalized.as_ref());
        let mut converted = github::convert_github_blob_to_raw(&full_url);
        if let Some(query) = query {
            converted.push('?');
            converted.push_str(query);
        }
        return parse_target_uri(&converted).map_err(|err| err.to_string());
    }

    Err(format!("No valid target found for path: {}", normalized))
}

fn is_github_domain_path(path: &str) -> bool {
    path.starts_with("github.com/")
        || path.starts_with("raw.githubusercontent.com/")
        || path.starts_with("api.github.com/")
        || path.starts_with("gist.github.com/")
        || path.starts_with("codeload.github.com/")
        || (path.contains("github")
            && (path.contains(".com/") || path.contains(".io/") || path.contains(".org/")))
}
