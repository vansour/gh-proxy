//! Cache metrics

use once_cell::sync::Lazy;
use parking_lot::RwLock;
use prometheus::{
    Histogram, IntCounter, IntCounterVec, IntGauge, register_histogram, register_int_counter,
    register_int_counter_vec, register_int_gauge,
};
use std::sync::Arc;

/// Cache hit statistics
pub static CACHE_HITS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_cache_hits_total",
        "Total cache hits by level",
        &["level", "kind"]
    )
    .expect("failed to register gh_proxy_cache_hits_total")
});

/// Cache miss statistics
pub static CACHE_MISSES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_cache_misses_total",
        "Total cache misses by kind",
        &["kind"]
    )
    .expect("failed to register gh_proxy_cache_misses_total")
});

/// Cache object count
pub static CACHE_OBJECTS: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!("gh_proxy_cache_objects", "Number of objects in cache")
        .expect("failed to register gh_proxy_cache_objects")
});

/// Cache size (bytes)
pub static CACHE_SIZE_BYTES: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "gh_proxy_cache_size_bytes",
        "Total size of cached objects in bytes"
    )
    .expect("failed to register gh_proxy_cache_size_bytes")
});

/// Cache eviction count
pub static CACHE_EVICTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    register_int_counter!("gh_proxy_cache_evictions_total", "Total cache evictions")
        .expect("failed to register gh_proxy_cache_evictions_total")
});

/// Requests that waited on an in-flight cache fill instead of fetching upstream.
pub static CACHE_COALESCED_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    register_int_counter_vec!(
        "gh_proxy_cache_coalesced_total",
        "Total requests coalesced behind an in-flight cache fill",
        &["kind"]
    )
    .expect("failed to register gh_proxy_cache_coalesced_total")
});

/// Number of cache fills currently in flight.
pub static CACHE_FILLS_IN_FLIGHT: Lazy<IntGauge> = Lazy::new(|| {
    register_int_gauge!(
        "gh_proxy_cache_fills_in_flight",
        "Number of cache fills currently in flight"
    )
    .expect("failed to register gh_proxy_cache_fills_in_flight")
});

/// Cache TTL statistics
pub static CACHE_TTL_SECONDS: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "gh_proxy_cache_ttl_seconds",
        "Cache TTL in seconds",
        vec![60.0, 300.0, 900.0, 3600.0, 7200.0, 86400.0]
    )
    .expect("failed to register gh_proxy_cache_ttl_seconds")
});

/// Cache object size statistics
pub static CACHE_OBJECT_SIZE_BYTES: Lazy<Histogram> = Lazy::new(|| {
    register_histogram!(
        "gh_proxy_cache_object_size_bytes",
        "Size of cached objects in bytes",
        vec![
            1024.0,
            10240.0,
            102400.0,
            1048576.0,
            10485760.0,
            104857600.0,
        ]
    )
    .expect("failed to register gh_proxy_cache_object_size_bytes")
});

/// Cache metrics
#[derive(Debug, Default)]
pub struct CacheMetrics {
    /// Memory cache hit count
    memory_hits: u64,
    /// Cache miss count
    misses: u64,
    /// Eviction count
    evictions: u64,
    /// Requests coalesced behind an in-flight fill
    coalesced: u64,
}

impl CacheMetrics {
    /// Record L1 (memory) cache hit
    pub fn record_l1_hit(kind: &str) {
        CACHE_HITS_TOTAL.with_label_values(&["l1", kind]).inc();
    }

    /// Record cache miss
    pub fn record_miss(kind: &str) {
        CACHE_MISSES_TOTAL.with_label_values(&[kind]).inc();
    }

    /// Record cache eviction
    pub fn record_eviction() {
        CACHE_EVICTIONS_TOTAL.inc();
    }

    /// Record a coalesced cache request
    pub fn record_coalesced(kind: &str) {
        CACHE_COALESCED_TOTAL.with_label_values(&[kind]).inc();
    }

    /// Record cache object size
    pub fn record_object_size(size: u64) {
        CACHE_OBJECT_SIZE_BYTES.observe(size as f64);
    }

    /// Record TTL
    pub fn record_ttl(ttl_secs: u64) {
        CACHE_TTL_SECONDS.observe(ttl_secs as f64);
    }

    /// Get hit rate
    pub fn hit_rate(&self) -> f64 {
        let total = self.memory_hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.memory_hits as f64 / total as f64
        }
    }
}

/// Thread-safe cache metrics counter
#[derive(Debug, Default, Clone)]
pub struct CacheMetricsCounter {
    inner: Arc<RwLock<CacheMetrics>>,
}

impl CacheMetricsCounter {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(CacheMetrics::default())),
        }
    }

    pub fn increment_hits(&self, level: &str, kind: &str) {
        CacheMetrics::record_l1_hit(kind);
        let mut metrics = self.inner.write();
        if level == "l1" {
            metrics.memory_hits += 1;
        }
    }

    pub fn increment_misses(&self, kind: &str) {
        CacheMetrics::record_miss(kind);
        self.inner.write().misses += 1;
    }

    pub fn increment_evictions(&self) {
        CacheMetrics::record_eviction();
        self.inner.write().evictions += 1;
    }

    pub fn increment_coalesced(&self, kind: &str) {
        CacheMetrics::record_coalesced(kind);
        self.inner.write().coalesced += 1;
    }

    pub fn increment_fills_in_flight(&self) {
        CACHE_FILLS_IN_FLIGHT.inc();
    }

    pub fn decrement_fills_in_flight(&self) {
        CACHE_FILLS_IN_FLIGHT.dec();
    }

    pub fn hit_rate(&self) -> f64 {
        self.inner.read().hit_rate()
    }

    pub fn stats(&self) -> (u64, u64, u64, u64) {
        let metrics = self.inner.read();
        (
            metrics.memory_hits,
            metrics.misses,
            metrics.evictions,
            metrics.coalesced,
        )
    }

    pub fn record_object_size(&self, size: u64) {
        CacheMetrics::record_object_size(size);
    }

    pub fn record_ttl(&self, ttl_secs: u64) {
        CacheMetrics::record_ttl(ttl_secs);
    }
}

pub fn init_metrics() {
    let _ = &*CACHE_HITS_TOTAL;
    let _ = &*CACHE_MISSES_TOTAL;
    let _ = &*CACHE_OBJECTS;
    let _ = &*CACHE_SIZE_BYTES;
    let _ = &*CACHE_EVICTIONS_TOTAL;
    let _ = &*CACHE_COALESCED_TOTAL;
    let _ = &*CACHE_FILLS_IN_FLIGHT;
    let _ = &*CACHE_TTL_SECONDS;
    let _ = &*CACHE_OBJECT_SIZE_BYTES;

    for kind in ["gh", "manifest", "blob", "generic"] {
        let _ = CACHE_HITS_TOTAL.with_label_values(&["l1", kind]).get();
        let _ = CACHE_MISSES_TOTAL.with_label_values(&[kind]).get();
        let _ = CACHE_COALESCED_TOTAL.with_label_values(&[kind]).get();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hit_rate() {
        let mut metrics = CacheMetrics::default();
        assert_eq!(metrics.hit_rate(), 0.0);

        metrics.memory_hits = 10;
        metrics.misses = 5;
        assert_eq!(metrics.hit_rate(), 0.6666666666666666);
    }
}
