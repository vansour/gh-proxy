//! API endpoints for configuration and statistics.

use crate::cache::metrics::{self as cache_metrics};
use crate::infra::metrics;
use crate::state::AppState;
use axum::{extract::State, response::Json};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Configuration API
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigResponse {
    pub server: ServerInfo,
    pub shell: ShellInfo,
    pub debug: DebugInfo,
    pub registry: RegistryInfo,
    pub proxy: ProxyInfo,
    pub cache: CacheInfo,
    pub rate_limit: RateLimitInfo,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub max_concurrent_requests: u32,
    pub request_timeout_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShellInfo {
    pub editor: bool,
    #[serde(rename = "publicBaseUrl")]
    pub public_base_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DebugInfo {
    pub endpoints_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryInfo {
    pub default: String,
    pub allowed_hosts: Vec<String>,
    pub readiness_depends_on_registry: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyInfo {
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheInfo {
    pub strategy: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RateLimitInfo {
    pub window_secs: u64,
    pub max_requests: u32,
}

/// Get the status-safe public runtime summary used by the same-origin dashboard.
pub async fn get_config(State(state): State<AppState>) -> Json<ConfigResponse> {
    Json(ConfigResponse {
        server: ServerInfo {
            max_concurrent_requests: state.settings.server.max_concurrent_requests,
            request_timeout_secs: state.settings.server.request_timeout_secs,
        },
        shell: ShellInfo {
            editor: state.settings.shell.editor,
            public_base_url: state.settings.shell.public_base_url.clone(),
        },
        debug: DebugInfo {
            endpoints_enabled: state.settings.debug.endpoints_enabled,
        },
        registry: RegistryInfo {
            default: state.settings.registry.default.clone(),
            allowed_hosts: state.settings.registry.allowed_hosts.clone(),
            readiness_depends_on_registry: state.settings.registry.readiness_depends_on_registry,
        },
        proxy: ProxyInfo {
            allowed_hosts: state.settings.proxy.allowed_hosts.clone(),
        },
        cache: CacheInfo {
            strategy: cache_strategy_name(state.settings.cache.strategy).to_string(),
        },
        rate_limit: RateLimitInfo {
            window_secs: state.settings.rate_limit.window_secs,
            max_requests: state.settings.rate_limit.max_requests,
        },
    })
}

// ============================================================================
// Statistics API
// ============================================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsResponse {
    /// Server-side metrics
    pub server: ServerStats,
    /// Cache metrics
    pub cache: CacheStats,
    /// Request breakdowns
    pub requests: RequestStats,
    /// Error counters by type
    pub errors: BTreeMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerStats {
    /// Total requests processed
    pub total_requests: u64,
    /// Currently active requests
    pub active_requests: i64,
    /// Total bytes transferred
    pub bytes_transferred: u64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Rate limiter cache size
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
    /// Hit/Miss breakdowns by kind
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

fn cache_strategy_name(strategy: crate::cache::config::CacheStrategy) -> &'static str {
    match strategy {
        crate::cache::config::CacheStrategy::Disabled => "disabled",
        crate::cache::config::CacheStrategy::MemoryOnly => "memory_only",
        crate::cache::config::CacheStrategy::MemoryWithCdn => "memory_with_cdn",
    }
}

/// Get server and CDN statistics
pub async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let server_stats = ServerStats {
        total_requests: metrics::HTTP_REQUESTS_TOTAL.get(),
        active_requests: metrics::HTTP_ACTIVE_REQUESTS.get(),
        bytes_transferred: metrics::BYTES_TRANSFERRED_TOTAL.get(),
        uptime_secs: state.uptime_tracker.uptime_secs(),
        rate_limit_cache_size: state.rate_limiter.cache_size(),
    };
    let cache_stats = state.cache_manager.stats().await;
    let (hits, misses, evictions) = state.cache_manager.metrics().stats();

    // Snapshot cache kind metrics from Prometheus
    let mut by_kind = BTreeMap::new();
    for kind in ["gh", "manifest", "blob", "generic"] {
        let h = cache_metrics::CACHE_HITS_TOTAL
            .with_label_values(&["l1", kind])
            .get();
        let m = cache_metrics::CACHE_MISSES_TOTAL
            .with_label_values(&[kind])
            .get();
        if h > 0 || m > 0 {
            by_kind.insert(kind.to_string(), CacheKindStats { hits: h, misses: m });
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
