use super::L1Cache;
use crate::cache::config::{CacheConfig, CacheStrategy};
use crate::cache::metrics::CacheMetricsCounter;
use crate::cache::response_cache::CachedResponse;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;

pub(super) fn build_l1_cache(config: &CacheConfig, metrics: CacheMetricsCounter) -> L1Cache {
    let strategy = config.strategy;
    let max_size = config.max_size_bytes;

    Cache::builder()
        .max_capacity(if strategy == CacheStrategy::Disabled {
            0
        } else {
            max_size
        })
        .weigher(|_key, value: &Arc<CachedResponse>| -> u32 { value.size() as u32 })
        .time_to_idle(Duration::from_secs(config.max_ttl_secs * 2))
        .eviction_listener(move |_key, _value, cause| {
            tracing::debug!("Cache entry evicted: {:?}", cause);
            metrics.increment_evictions();
        })
        .build()
}

pub(super) fn spawn_statistics_task(cache: L1Cache, total_size: Arc<parking_lot::RwLock<u64>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            update_metrics(&cache, &total_size);
        }
    });
}

pub(super) async fn refresh_cache_metrics(
    cache: &L1Cache,
    total_size: &Arc<parking_lot::RwLock<u64>>,
) -> (u64, u64) {
    cache.run_pending_tasks().await;
    let entry_count = cache.entry_count();
    let weighted_size = update_metrics(cache, total_size);
    (entry_count, weighted_size)
}

fn update_metrics(
    cache: &Cache<crate::cache::key::CacheKey, Arc<CachedResponse>>,
    total_size: &Arc<parking_lot::RwLock<u64>>,
) -> u64 {
    let size = cache.weighted_size();
    *total_size.write() = size;
    crate::cache::metrics::CACHE_OBJECTS.set(cache.entry_count() as i64);
    crate::cache::metrics::CACHE_SIZE_BYTES.set(size as i64);
    size
}
