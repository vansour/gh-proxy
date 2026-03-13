use super::{RateLimiter, entry::RateLimitEntry};
use std::sync::Arc;
use std::time::Instant;

#[test]
fn test_rate_limiter_allows_within_limit() {
    let limiter = RateLimiter::new(5, 60);

    for _ in 0..5 {
        assert!(limiter.check_and_increment("192.168.1.1"));
    }
}

#[test]
fn test_rate_limiter_blocks_over_limit() {
    let limiter = RateLimiter::new(3, 60);

    assert!(limiter.check_and_increment("192.168.1.1"));
    assert!(limiter.check_and_increment("192.168.1.1"));
    assert!(limiter.check_and_increment("192.168.1.1"));
    assert!(!limiter.check_and_increment("192.168.1.1"));
}

#[test]
fn test_rate_limiter_separate_ips() {
    let limiter = RateLimiter::new(2, 60);

    assert!(limiter.check_and_increment("192.168.1.1"));
    assert!(limiter.check_and_increment("192.168.1.1"));
    assert!(!limiter.check_and_increment("192.168.1.1"));
    assert!(limiter.check_and_increment("192.168.1.2"));
}

#[test]
fn test_remaining_requests() {
    let limiter = RateLimiter::new(10, 60);

    assert_eq!(limiter.remaining("192.168.1.1"), 10);

    limiter.check_and_increment("192.168.1.1");
    assert_eq!(limiter.remaining("192.168.1.1"), 9);
}

#[test]
fn poisoned_rate_limit_entry_lock_recovers() {
    let entry = Arc::new(RateLimitEntry::new());
    let poisoned = Arc::clone(&entry);

    let _ = std::thread::spawn(move || {
        let _guard = poisoned.requests.lock().expect("lock for poisoning");
        panic!("poison the mutex");
    })
    .join();

    entry.cleanup_old_requests(Instant::now());
    assert!(entry.check_and_add(Instant::now(), 1));
}
