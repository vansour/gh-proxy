use crate::cache::metrics::{self as cache_metrics};
use crate::infra::metrics;
use crate::state::AppState;
use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    pub server: ServerStats,
    pub cache: CacheStats,
    pub requests: RequestStats,
    pub errors: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStats {
    pub total_requests: u64,
    pub active_requests: i64,
    pub bytes_transferred: u64,
    pub uptime_secs: u64,
    pub rate_limit_cache_size: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheStats {
    pub strategy: String,
    pub entry_count: u64,
    pub weighted_size: u64,
    pub hit_rate: f64,
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub coalesced: u64,
    pub fills_in_flight: i64,
    pub by_kind: BTreeMap<String, CacheKindStats>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct CacheKindStats {
    pub hits: u64,
    pub misses: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestStats {
    pub by_status: BTreeMap<String, u64>,
    pub by_type: BTreeMap<String, u64>,
    pub by_method: BTreeMap<String, u64>,
}

pub(crate) fn cache_strategy_name(strategy: crate::cache::config::CacheStrategy) -> &'static str {
    match strategy {
        crate::cache::config::CacheStrategy::Disabled => "disabled",
        crate::cache::config::CacheStrategy::MemoryOnly => "memory_only",
        crate::cache::config::CacheStrategy::MemoryWithCdn => "memory_with_cdn",
    }
}

pub async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let server_stats = ServerStats {
        total_requests: metrics::HTTP_REQUESTS_TOTAL.get(),
        active_requests: metrics::HTTP_ACTIVE_REQUESTS.get(),
        bytes_transferred: metrics::BYTES_TRANSFERRED_TOTAL.get(),
        uptime_secs: state.uptime_tracker.uptime_secs(),
        rate_limit_cache_size: state.rate_limiter.cache_size(),
    };
    let cache_stats = state.cache_manager.stats().await;
    let (hits, misses, evictions, coalesced) = state.cache_manager.metrics().stats();

    let mut by_kind = BTreeMap::new();
    for kind in ["gh", "manifest", "blob", "generic"] {
        let hits_for_kind = cache_metrics::CACHE_HITS_TOTAL
            .with_label_values(&["l1", kind])
            .get();
        let misses_for_kind = cache_metrics::CACHE_MISSES_TOTAL
            .with_label_values(&[kind])
            .get();
        if hits_for_kind > 0 || misses_for_kind > 0 {
            by_kind.insert(
                kind.to_string(),
                CacheKindStats {
                    hits: hits_for_kind,
                    misses: misses_for_kind,
                },
            );
        }
    }

    Json(StatsResponse {
        server: server_stats,
        cache: CacheStats {
            strategy: cache_strategy_name(state.settings.cache.strategy).to_string(),
            entry_count: cache_stats.entry_count,
            weighted_size: cache_stats.weighted_size,
            hit_rate: cache_stats.hit_rate,
            hits,
            misses,
            evictions,
            coalesced,
            fills_in_flight: cache_metrics::CACHE_FILLS_IN_FLIGHT.get(),
            by_kind,
        },
        requests: RequestStats {
            by_status: metrics::snapshot_request_statuses(),
            by_type: metrics::snapshot_request_types(),
            by_method: metrics::snapshot_request_methods(),
        },
        errors: metrics::snapshot_error_counts(),
    })
}
