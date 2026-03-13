use crate::utils::constants::cache;
use crate::{services::request::ops_endpoint_access_allowed, state::AppState};
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use once_cell::sync::Lazy;
use prometheus::{Encoder, TextEncoder};
use std::net::SocketAddr;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;

struct MetricsCache {
    output: String,
    last_update: Instant,
}

static METRICS_CACHE: Lazy<RwLock<MetricsCache>> = Lazy::new(|| {
    RwLock::new(MetricsCache {
        output: String::new(),
        last_update: Instant::now(),
    })
});

fn read_lock<T>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(|poisoned| {
        tracing::warn!("Metrics cache read lock was poisoned; recovering state");
        poisoned.into_inner()
    })
}

fn write_lock<T>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(|poisoned| {
        tracing::warn!("Metrics cache write lock was poisoned; recovering state");
        poisoned.into_inner()
    })
}

pub async fn metrics_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> axum::response::Response {
    if !ops_endpoint_access_allowed(addr, state.settings.debug.metrics_enabled) {
        return (
            StatusCode::NOT_FOUND,
            [("content-type", "text/plain; charset=utf-8")],
            "Metrics endpoint is disabled.\n",
        )
            .into_response();
    }

    super::init_metrics();
    crate::cache::metrics::init_metrics();
    super::update_uptime(state.uptime_tracker.uptime_secs());

    #[cfg(not(target_env = "msvc"))]
    super::update_memory_metrics();

    {
        let cache = read_lock(&METRICS_CACHE);
        if cache.last_update.elapsed() < cache::METRICS_CACHE_TTL && !cache.output.is_empty() {
            return (
                StatusCode::OK,
                [("content-type", "text/plain; version=0.0.4")],
                cache.output.clone(),
            )
                .into_response();
        }
    }

    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::with_capacity(8192);
    encoder
        .encode(&metric_families, &mut buffer)
        .unwrap_or_default();
    let body = String::from_utf8_lossy(&buffer).to_string();

    let mut cache = write_lock(&METRICS_CACHE);
    cache.output = body.clone();
    cache.last_update = Instant::now();

    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{read_lock, write_lock};
    use std::sync::{Arc, RwLock};

    #[test]
    fn poisoned_metrics_read_lock_recovers() {
        let lock = Arc::new(RwLock::new(5u64));
        let poisoned = Arc::clone(&lock);

        let _ = std::thread::spawn(move || {
            let _guard = poisoned.write().expect("lock for poisoning");
            panic!("poison the rwlock");
        })
        .join();

        assert_eq!(*read_lock(&lock), 5);
    }

    #[test]
    fn poisoned_metrics_write_lock_recovers() {
        let lock = Arc::new(RwLock::new(5u64));
        let poisoned = Arc::clone(&lock);

        let _ = std::thread::spawn(move || {
            let _guard = poisoned.write().expect("lock for poisoning");
            panic!("poison the rwlock");
        })
        .join();

        *write_lock(&lock) = 8;
        assert_eq!(*read_lock(&lock), 8);
    }
}
