//! Response cache

use crate::cache::config::CacheConfig;
use crate::cache::key::CacheKey;
use crate::cache::metrics::CacheMetricsCounter;
use crate::cache::utils::{generate_etag, is_response_cacheable};
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use http_body_util::BodyExt;
use std::time::{Duration, Instant};
use tracing::warn;

/// Cached response
#[derive(Clone)]
pub struct CachedResponse {
    /// Status code
    pub status: StatusCode,
    /// Response headers (without hop-by-hop headers)
    pub headers: HeaderMap,
    /// Response body
    pub body: Bytes,
    /// Cache time
    pub cached_at: Instant,
    /// TTL
    pub ttl: Duration,
    /// Cache key
    pub key: CacheKey,
}

impl CachedResponse {
    /// Create a new cached response
    pub fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        ttl: Duration,
        key: CacheKey,
    ) -> Self {
        Self {
            status,
            headers,
            body,
            cached_at: Instant::now(),
            ttl,
            key,
        }
    }

    /// Create cached response from HTTP response
    pub async fn from_response(
        response: axum::http::Response<Body>,
        config: &CacheConfig,
        key: CacheKey,
        metrics: &CacheMetricsCounter,
    ) -> Option<Self> {
        let status = response.status();
        let headers = response.headers().clone();

        let limited_body = http_body_util::Limited::new(
            response.into_body(),
            (config.max_object_size + 1) as usize,
        );
        let body = match BodyExt::collect(limited_body).await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => return None,
        };

        Self::from_buffered_parts(status, headers, body, config, key, metrics)
    }

    /// Create cached response from already buffered response parts
    pub fn from_buffered_parts(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        config: &CacheConfig,
        key: CacheKey,
        metrics: &CacheMetricsCounter,
    ) -> Option<Self> {
        // Check if cacheable
        if !is_response_cacheable(status.as_u16(), &headers, config) {
            return None;
        }

        // Check size limits
        let content_length = headers
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok());

        if let Some(len) = content_length
            && (len < config.min_object_size as usize || len > config.max_object_size as usize)
        {
            return None;
        }

        // Check size again
        let body_len = body.len();
        if body_len < config.min_object_size as usize || body_len > config.max_object_size as usize
        {
            return None;
        }

        // Calculate TTL
        let ttl = crate::cache::utils::calculate_ttl(&headers, config, &key.path);

        // Add ETag (if missing)
        let mut headers = headers;
        if !headers.contains_key("etag")
            && let Ok(etag) = generate_etag(&body).parse()
        {
            headers.insert("etag", etag);
        }

        // Record metrics
        metrics.record_object_size(body_len as u64);
        metrics.record_ttl(ttl.as_secs());

        Some(Self::new(status, headers, body, ttl, key))
    }

    /// Check if cache is expired
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    /// Check if cache is stale (10% TTL or 1 minute, whichever is smaller)
    pub fn is_stale(&self) -> bool {
        let threshold = self.ttl.min(Duration::from_secs(60)) / 10;
        self.cached_at.elapsed() + threshold > self.ttl
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.cached_at.elapsed())
    }

    /// Convert to HTTP response
    pub fn to_response(&self) -> axum::http::Response<Body> {
        let mut response = axum::http::Response::builder()
            .status(self.status)
            .body(Body::from(self.body.clone()))
            .unwrap_or_else(|err| {
                warn!("Failed to build cached response body: {}", err);
                axum::http::Response::new(Body::from(self.body.clone()))
            });

        // Set response headers
        for (name, value) in &self.headers {
            // Skip hop-by-hop headers
            let name_str = name.as_str();
            if matches!(
                name_str,
                "connection"
                    | "keep-alive"
                    | "transfer-encoding"
                    | "upgrade"
                    | "proxy-authenticate"
                    | "proxy-authorization"
                    | "te"
                    | "trailers"
            ) {
                continue;
            }

            // Update age header
            if name_str == "age" {
                let age = self.cached_at.elapsed().as_secs().to_string();
                if let Ok(age_value) = age.parse() {
                    response.headers_mut().insert(name, age_value);
                }
                continue;
            }

            response.headers_mut().insert(name, value.clone());
        }

        // Add age header
        let age = self.cached_at.elapsed().as_secs().to_string();
        if let Ok(age_value) = age.parse() {
            response.headers_mut().insert("age", age_value);
        }

        // Add X-Cache header
        if let Ok(value) = "HIT from gh-proxy (L1)".parse() {
            response.headers_mut().insert("X-Cache", value);
        }

        response
    }

    /// Check if matches conditional request
    pub fn matches_conditional(&self, headers: &HeaderMap) -> bool {
        // If-None-Match
        if let Some(if_none_match) = headers.get("if-none-match")
            && let Ok(if_none_match_str) = if_none_match.to_str()
            && let Some(etag) = self.headers.get("etag")
            && let Ok(etag_str) = etag.to_str()
            && (if_none_match_str == etag_str || if_none_match_str == "*")
        {
            return true;
        }

        false
    }

    /// Get cache size
    pub fn size(&self) -> usize {
        let header_size = self
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len() + 4) // +4 for ": \r\n"
            .sum::<usize>();
        self.body.len() + header_size
    }
}

/// Cache result
pub enum CacheResult {
    /// Cache hit
    Hit(Box<CachedResponse>),
    /// Cache miss
    Miss,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_response_expiry() {
        let key = CacheKey::generic("GET", "example.com", "/test", None);
        let response = CachedResponse::new(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("test"),
            Duration::from_secs(60),
            key,
        );
        assert!(!response.is_expired());
        assert!(!response.is_stale());
    }

    #[test]
    fn test_matches_conditional() {
        let key = CacheKey::generic("GET", "example.com", "/test", None);
        let mut headers = HeaderMap::new();
        headers.insert("etag", "\"abc123\"".parse().unwrap());

        let response = CachedResponse::new(
            StatusCode::OK,
            headers,
            Bytes::from("test"),
            Duration::from_secs(60),
            key,
        );

        let mut if_none_match = HeaderMap::new();
        if_none_match.insert("if-none-match", "\"abc123\"".parse().unwrap());
        assert!(response.matches_conditional(&if_none_match));

        let mut if_none_match = HeaderMap::new();
        if_none_match.insert("if-none-match", "\"different\"".parse().unwrap());
        assert!(!response.matches_conditional(&if_none_match));
    }
}
