use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, Uri};
use hyper::header;

use crate::cache::key::{CacheKey, request_variant_key};

/// Requests with Range semantics must bypass the shared response cache.
pub(super) fn should_bypass_cache(headers: &HeaderMap) -> bool {
    headers.contains_key(header::RANGE)
}

/// Generate cache key from request.
pub(super) fn generate_cache_key(req: &Request<Body>, target_uri: &Uri) -> CacheKey {
    let host = target_uri.host().unwrap_or("unknown");
    let path = target_uri.path();
    let query = target_uri.query();
    let variant_key = request_variant_key(req.headers());

    if path.contains("/github/") || host.contains("github") {
        CacheKey::github_variant(host, path, query, variant_key)
    } else if let Some(rest) = path.strip_prefix("/v2/") {
        match crate::providers::registry::parse_v2_path(rest) {
            crate::providers::registry::V2Endpoint::Blob { name, digest } => {
                CacheKey::docker_blob_for(host, &name, &digest)
            }
            crate::providers::registry::V2Endpoint::Manifest { name, reference } => {
                CacheKey::docker_manifest_for(host, &name, &reference)
            }
            _ => CacheKey::generic_variant(req.method().as_str(), host, path, query, variant_key),
        }
    } else {
        CacheKey::generic_variant(req.method().as_str(), host, path, query, variant_key)
    }
}
