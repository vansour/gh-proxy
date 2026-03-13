//! Cache manager

mod runtime;

pub use crate::cache::response_cache::CacheResult;

use crate::cache::config::{CacheConfig, CacheStrategy};
use crate::cache::key::{CacheKey, CacheKeyKind};
use crate::cache::metrics::CacheMetricsCounter;
use crate::cache::response_cache::CachedResponse;
use crate::cache::utils::build_cdn_cache_headers;
use axum::http::StatusCode;
use dashmap::{DashMap, mapref::entry::Entry};
use moka::future::Cache;
use std::sync::Arc;
use tokio::sync::Notify;

type L1Cache = Cache<CacheKey, Arc<CachedResponse>>;
type InflightFills = DashMap<CacheKey, Arc<Notify>>;

pub enum CacheReservation {
    Hit(Box<CachedResponse>),
    Fill(CacheFillGuard),
}

pub struct CacheFillGuard {
    state: CacheFillGuardState,
}

enum CacheFillGuardState {
    Active {
        key: CacheKey,
        inflight_fills: Arc<InflightFills>,
        notify: Arc<Notify>,
        metrics: CacheMetricsCounter,
    },
    Noop,
}

impl CacheFillGuard {
    fn new(
        key: CacheKey,
        inflight_fills: Arc<InflightFills>,
        notify: Arc<Notify>,
        metrics: CacheMetricsCounter,
    ) -> Self {
        Self {
            state: CacheFillGuardState::Active {
                key,
                inflight_fills,
                notify,
                metrics,
            },
        }
    }

    fn noop() -> Self {
        Self {
            state: CacheFillGuardState::Noop,
        }
    }
}

impl Drop for CacheFillGuard {
    fn drop(&mut self) {
        if let CacheFillGuardState::Active {
            key,
            inflight_fills,
            notify,
            metrics,
        } = &self.state
        {
            inflight_fills.remove(key);
            metrics.decrement_fills_in_flight();
            notify.notify_waiters();
        }
    }
}

pub struct CacheManager {
    l1_cache: L1Cache,
    config: CacheConfig,
    metrics: CacheMetricsCounter,
    total_size: Arc<parking_lot::RwLock<u64>>,
    inflight_fills: Arc<InflightFills>,
}

impl CacheManager {
    pub fn new(config: CacheConfig) -> Self {
        let metrics = CacheMetricsCounter::new();
        let l1_cache = runtime::build_l1_cache(&config, metrics.clone());
        let total_size = Arc::new(parking_lot::RwLock::new(0));
        runtime::spawn_statistics_task(l1_cache.clone(), Arc::clone(&total_size));

        Self {
            l1_cache,
            config,
            metrics,
            total_size,
            inflight_fills: Arc::new(DashMap::new()),
        }
    }

    async fn lookup(&self, key: &CacheKey) -> Option<Arc<CachedResponse>> {
        let cached = self.l1_cache.get(key).await?;
        if cached.is_expired() {
            tracing::debug!("Cache entry expired: {}", key);
            self.l1_cache.invalidate(key).await;
            return None;
        }

        Some(cached)
    }

    pub async fn get(&self, key: &CacheKey) -> CacheResult {
        if self.config.strategy == CacheStrategy::Disabled {
            return CacheResult::Miss;
        }

        let kind = key.kind.as_str();
        match self.lookup(key).await {
            Some(cached) => {
                self.metrics.increment_hits("l1", kind);
                CacheResult::Hit(Box::new(cached.as_ref().clone()))
            }
            None => {
                self.metrics.increment_misses(kind);
                CacheResult::Miss
            }
        }
    }

    pub async fn get_or_reserve_fill(&self, key: &CacheKey) -> CacheReservation {
        if self.config.strategy == CacheStrategy::Disabled {
            return CacheReservation::Fill(CacheFillGuard::noop());
        }

        let kind = key.kind.as_str();

        loop {
            if let Some(cached) = self.lookup(key).await {
                self.metrics.increment_hits("l1", kind);
                return CacheReservation::Hit(Box::new(cached.as_ref().clone()));
            }

            let waiter = match self.inflight_fills.entry(key.clone()) {
                Entry::Vacant(entry) => {
                    let notify = Arc::new(Notify::new());
                    entry.insert(Arc::clone(&notify));
                    self.metrics.increment_misses(kind);
                    self.metrics.increment_fills_in_flight();
                    return CacheReservation::Fill(CacheFillGuard::new(
                        key.clone(),
                        Arc::clone(&self.inflight_fills),
                        notify,
                        self.metrics.clone(),
                    ));
                }
                Entry::Occupied(entry) => {
                    self.metrics.increment_coalesced(kind);
                    Arc::clone(entry.get())
                }
            };

            waiter.notified().await;
        }
    }

    pub async fn set(&self, key: CacheKey, response: CachedResponse) {
        if self.config.strategy == CacheStrategy::Disabled {
            return;
        }

        let size = response.size() as u64;
        let current_size = *self.total_size.read();
        if current_size + size > self.config.max_size_bytes {
            tracing::debug!(
                "Cache at capacity ({} bytes + {} bytes > {} bytes), evicting...",
                current_size,
                size,
                self.config.max_size_bytes
            );
        }

        self.l1_cache.insert(key, Arc::new(response)).await;
    }

    pub async fn invalidate(&self, key: &CacheKey) {
        self.l1_cache.invalidate(key).await;
    }

    pub async fn invalidate_all(&self) {
        self.l1_cache.invalidate_all();
    }

    pub async fn stats(&self) -> CacheStats {
        let (entry_count, weighted_size) =
            runtime::refresh_cache_metrics(&self.l1_cache, &self.total_size).await;

        CacheStats {
            entry_count,
            weighted_size,
            hit_rate: self.metrics.hit_rate(),
        }
    }

    pub fn is_cacheable(&self, path: &str) -> bool {
        self.config.is_cacheable(path)
    }

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

    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    pub fn metrics(&self) -> &CacheMetricsCounter {
        &self.metrics
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub entry_count: u64,
    pub weighted_size: u64,
    pub hit_rate: f64,
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new(CacheConfig::default())
    }
}

#[cfg(test)]
mod tests;
