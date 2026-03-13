use super::{CacheManager, CacheReservation, CacheResult};
use crate::cache::config::{CacheConfig, CacheStrategy};
use crate::cache::key::CacheKey;
use crate::cache::response_cache::CachedResponse;
use axum::http::StatusCode;
use std::sync::Arc;
use std::time::Duration;

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

    assert!(matches!(manager.get(&key).await, CacheResult::Miss));
}

#[tokio::test]
async fn test_get_or_reserve_fill_coalesces_waiters() {
    let manager = Arc::new(CacheManager::new(CacheConfig::default()));
    let key = CacheKey::generic("GET", "example.com", "/test", None);

    let fill_guard = match manager.get_or_reserve_fill(&key).await {
        CacheReservation::Fill(guard) => guard,
        CacheReservation::Hit(_) => panic!("expected initial cache miss"),
    };

    let waiter_manager = Arc::clone(&manager);
    let waiter_key = key.clone();
    let waiter = tokio::spawn(async move {
        match waiter_manager.get_or_reserve_fill(&waiter_key).await {
            CacheReservation::Hit(cached) => cached.body,
            CacheReservation::Fill(_) => panic!("waiter should observe cached response"),
        }
    });

    let response = CachedResponse::new(
        StatusCode::OK,
        axum::http::HeaderMap::new(),
        bytes::Bytes::from("test"),
        Duration::from_secs(60),
        key.clone(),
    );
    manager.set(key, response).await;
    drop(fill_guard);

    let body = waiter.await.expect("waiter join");
    assert_eq!(body, bytes::Bytes::from("test"));
}
