//! Cache manager

pub use crate::cache::response_cache::CacheResult;

use crate::cache::config::{CacheConfig, CacheStrategy};
use crate::cache::key::CacheKey;
use crate::cache::key::CacheKeyKind;
use crate::cache::metrics::CacheMetricsCounter;
use crate::cache::response_cache::CachedResponse;
use crate::cache::utils::build_cdn_cache_headers;
use axum::http::StatusCode;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

/// Cache manager
pub struct CacheManager {
    /// L1 cache (in-memory)
    l1_cache: Cache<CacheKey, Arc<CachedResponse>>,
    /// Cache configuration
    config: CacheConfig,
    /// Cache metrics
    metrics: CacheMetricsCounter,
    /// Total size tracking
    total_size: Arc<parking_lot::RwLock<u64>>,
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new(config: CacheConfig) -> Self {
        let strategy = config.strategy;
        let max_size = config.max_size_bytes;

        let cache = Cache::builder()
            .max_capacity(if strategy == CacheStrategy::Disabled {
                0
            } else {
                max_size
            })
            .weigher(|_key, value: &Arc<CachedResponse>| -> u32 { value.size() as u32 })
            .time_to_idle(Duration::from_secs(config.max_ttl_secs * 2))
            .eviction_listener(|_key, _value, cause| {
                tracing::debug!("Cache entry evicted: {:?}", cause);
                // eviction_listener is a callback, can't access metrics here
            })
            .build();

        let total_size = Arc::new(parking_lot::RwLock::new(0));

        // Start statistics task
        let total_size_clone = total_size.clone();
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let size = cache_clone.weighted_size();
                *total_size_clone.write() = size;

                // Update Prometheus metrics
                crate::cache::metrics::CACHE_OBJECTS.set(cache_clone.entry_count() as i64);
                crate::cache::metrics::CACHE_SIZE_BYTES.set(size as i64);
            }
        });

        Self {
            l1_cache: cache,
            config,
            metrics: CacheMetricsCounter::new(),
            total_size,
        }
    }

    /// Get cache
    pub async fn get(&self, key: &CacheKey) -> CacheResult {
        if self.config.strategy == CacheStrategy::Disabled {
            return CacheResult::Miss;
        }

        let kind = key.kind.as_str();
        match self.l1_cache.get(key).await {
            Some(cached) => {
                // Check if expired
                if cached.is_expired() {
                    tracing::debug!("Cache entry expired: {}", key);
                    self.l1_cache.invalidate(key).await;
                    self.metrics.increment_misses(kind);
                    return CacheResult::Miss;
                }

                // L1 hit
                self.metrics.increment_hits("l1", kind);
                CacheResult::Hit(Box::new(cached.as_ref().clone()))
            }
            None => {
                self.metrics.increment_misses(kind);
                CacheResult::Miss
            }
        }
    }

    /// Set cache
    pub async fn set(&self, key: CacheKey, response: CachedResponse) {
        if self.config.strategy == CacheStrategy::Disabled {
            return;
        }

        let size = response.size() as u64;

        // Check cache capacity
        let current_size = *self.total_size.read();
        if current_size + size > self.config.max_size_bytes {
            tracing::debug!(
                "Cache at capacity ({} bytes + {} bytes > {} bytes), evicting...",
                current_size,
                size,
                self.config.max_size_bytes
            );
            // moka will evict automatically
        }

        self.l1_cache.insert(key, Arc::new(response)).await;
    }

    /// Invalidate cache entry
    pub async fn invalidate(&self, key: &CacheKey) {
        self.l1_cache.invalidate(key).await;
    }

    /// Invalidate all cache
    pub async fn invalidate_all(&self) {
        self.l1_cache.invalidate_all();
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        self.l1_cache.run_pending_tasks().await;

        let entry_count = self.l1_cache.entry_count();
        let weighted_size = self.l1_cache.weighted_size();
        *self.total_size.write() = weighted_size;
        crate::cache::metrics::CACHE_OBJECTS.set(entry_count as i64);
        crate::cache::metrics::CACHE_SIZE_BYTES.set(weighted_size as i64);

        CacheStats {
            entry_count,
            weighted_size,
            hit_rate: self.metrics.hit_rate(),
        }
    }

    /// Check if path is cacheable
    pub fn is_cacheable(&self, path: &str) -> bool {
        self.config.is_cacheable(path)
    }

    /// Check if the incoming request should participate in proxy caching.
    pub fn should_cache_request(&self, key: &CacheKey, request_path: &str) -> bool {
        if self.config.strategy == CacheStrategy::Disabled || self.config.is_bypassed(request_path)
        {
            return false;
        }

        if self.config.is_cacheable(request_path) {
            return true;
        }

        matches!(
            key.kind,
            CacheKeyKind::GithubFile | CacheKeyKind::DockerBlob | CacheKeyKind::DockerManifest
        )
    }

    /// Build cache response headers (including CDN)
    pub fn build_cache_headers(
        &self,
        content_type: &str,
        status: StatusCode,
        response_cacheable: bool,
    ) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
        let is_cachable = (200..300).contains(&status.as_u16())
            && self.config.strategy != CacheStrategy::Disabled
            && response_cacheable;
        build_cdn_cache_headers(&self.config, content_type, is_cachable)
    }

    /// Get configuration
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Get metrics
    pub fn metrics(&self) -> &CacheMetricsCounter {
        &self.metrics
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    /// Number of cache entries
    pub entry_count: u64,
    /// Weighted size (bytes)
    pub weighted_size: u64,
    /// Hit rate
    pub hit_rate: f64,
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_set_get() {
        let manager = CacheManager::new(CacheConfig::default());

        let key = CacheKey::generic("GET", "example.com", "/test", None);
        let response = CachedResponse::new(
            StatusCode::OK,
            axum::http::HeaderMap::new(),
            bytes::Bytes::from("test"),
            Duration::from_secs(60),
            key.clone(),
        );

        manager.set(key.clone(), response).await;

        match manager.get(&key).await {
            CacheResult::Hit(cached) => {
                assert_eq!(cached.body, bytes::Bytes::from("test"));
            }
            CacheResult::Miss => panic!("Expected cache hit"),
        }
    }

    #[tokio::test]
    async fn test_cache_invalidation() {
        let manager = CacheManager::new(CacheConfig::default());

        let key = CacheKey::generic("GET", "example.com", "/test", None);
        let response = CachedResponse::new(
            StatusCode::OK,
            axum::http::HeaderMap::new(),
            bytes::Bytes::from("test"),
            Duration::from_secs(60),
            key.clone(),
        );

        manager.set(key.clone(), response).await;
        assert!(matches!(manager.get(&key).await, CacheResult::Hit(_)));

        manager.invalidate(&key).await;
        assert!(matches!(manager.get(&key).await, CacheResult::Miss));
    }

    #[tokio::test]
    async fn test_disabled_cache() {
        let manager = CacheManager::new(CacheConfig {
            strategy: CacheStrategy::Disabled,
            ..CacheConfig::default()
        });

        let key = CacheKey::generic("GET", "example.com", "/test", None);
        let response = CachedResponse::new(
            StatusCode::OK,
            axum::http::HeaderMap::new(),
            bytes::Bytes::from("test"),
            Duration::from_secs(60),
            key.clone(),
        );

        manager.set(key.clone(), response).await;

        // Always miss when disabled
        assert!(matches!(manager.get(&key).await, CacheResult::Miss));
    }
}
