use super::CachedResponse;
use crate::cache::config::CacheConfig;
use crate::cache::key::CacheKey;
use crate::cache::metrics::CacheMetricsCounter;
use crate::cache::utils::{calculate_ttl, generate_etag, is_response_cacheable};
use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use http_body_util::BodyExt;

impl CachedResponse {
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

    pub fn from_buffered_parts(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        config: &CacheConfig,
        key: CacheKey,
        metrics: &CacheMetricsCounter,
    ) -> Option<Self> {
        if !is_response_cacheable(status.as_u16(), &headers, config) {
            return None;
        }

        let content_length = headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<usize>().ok());

        if let Some(len) = content_length
            && (len < config.min_object_size as usize || len > config.max_object_size as usize)
        {
            return None;
        }

        let body_len = body.len();
        if body_len < config.min_object_size as usize || body_len > config.max_object_size as usize
        {
            return None;
        }

        let ttl = calculate_ttl(&headers, config, &key.path);

        let mut headers = headers;
        if !headers.contains_key("etag")
            && let Ok(etag) = generate_etag(&body).parse()
        {
            headers.insert("etag", etag);
        }

        metrics.record_object_size(body_len as u64);
        metrics.record_ttl(ttl.as_secs());

        Some(Self::new(status, headers, body, ttl, key))
    }
}
