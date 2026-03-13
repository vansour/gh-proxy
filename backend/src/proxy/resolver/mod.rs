//! URL resolution and validation for proxy targets.

mod compression;
mod fallback;
mod redirect;
mod validate;

use axum::http::Uri;

use crate::errors::{ProxyError, ProxyResult};

pub use compression::should_disable_compression_for_request;
pub use fallback::resolve_fallback_target;
pub use redirect::resolve_redirect_uri;
pub use validate::{resolve_target_uri_with_validation, validate_target_uri};

pub(super) fn parse_target_uri(raw: &str) -> ProxyResult<Uri> {
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
