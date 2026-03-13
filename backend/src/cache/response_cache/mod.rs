//! Response cache

mod build;
mod http;

use axum::http::{HeaderMap, StatusCode};
use bytes::Bytes;
use std::time::{Duration, Instant};

use crate::cache::key::CacheKey;

#[derive(Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub cached_at: Instant,
    pub ttl: Duration,
    pub key: CacheKey,
}

impl CachedResponse {
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

    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    pub fn is_stale(&self) -> bool {
        let threshold = self.ttl.min(Duration::from_secs(60)) / 10;
        self.cached_at.elapsed() + threshold > self.ttl
    }

    pub fn remaining_ttl(&self) -> Duration {
        self.ttl.saturating_sub(self.cached_at.elapsed())
    }

    pub fn matches_conditional(&self, headers: &HeaderMap) -> bool {
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

    pub fn size(&self) -> usize {
        let header_size = self
            .headers
            .iter()
            .map(|(name, value)| name.as_str().len() + value.len() + 4)
            .sum::<usize>();
        self.body.len() + header_size
    }
}

pub enum CacheResult {
    Hit(Box<CachedResponse>),
    Miss,
}

#[cfg(test)]
mod tests;
