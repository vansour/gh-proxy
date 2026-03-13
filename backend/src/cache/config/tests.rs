use super::{CacheConfig, CacheStrategy};
use std::time::Duration;

#[test]
fn test_matches_pattern() {
    let config = CacheConfig::default();

    assert!(super::pattern::matches_pattern("/github/test", "/github/*"));
    assert!(super::pattern::matches_pattern(
        "/v2/test/blobs/abc123",
        "/v2/*/blobs/*"
    ));
    assert!(!super::pattern::matches_pattern("/api/config", "/github/*"));
    assert!(config.max_ttl() >= Duration::from_secs(config.default_ttl_secs));
}

#[test]
fn test_is_cacheable() {
    let config = CacheConfig::default();

    assert!(config.is_cacheable("/github/owner/repo/main/file.txt"));
    assert!(config.is_cacheable("/v2/test/blobs/sha256:abc123"));
    assert!(config.is_cacheable("/v2/test/manifests/latest"));
    assert!(!config.is_cacheable("/api/config"));
    assert!(!config.is_cacheable("/metrics"));
}

#[test]
fn test_get_ttl_for_content_type() {
    let config = CacheConfig::default();

    let image_ttl = config.get_ttl_for_content_type("image/png");
    assert_eq!(image_ttl, Duration::from_secs(86400));

    let text_ttl = config.get_ttl_for_content_type("text/plain");
    assert_eq!(text_ttl, Duration::from_secs(3600));
}

#[test]
fn test_validate() {
    let config = CacheConfig::default();
    assert!(config.validate().is_ok());

    let config = CacheConfig {
        max_size_bytes: 1024 * 1024,
        ..CacheConfig::default()
    };
    assert!(config.validate().is_err());

    let config = CacheConfig {
        max_ttl_secs: 60,
        ..CacheConfig::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_legacy_aliases_deserialize() {
    let config: CacheConfig = toml::from_str(
        r#"
strategy = "memory_only"
maxSizeBytes = 104857600
defaultTtlSecs = 120
maxTtlSecs = 600
minObjectSize = 128
maxObjectSize = 1048576
cacheablePatterns = ["/github/*"]
bypassPatterns = ["/metrics"]
"#,
    )
    .expect("legacy aliases should deserialize");

    assert_eq!(config.strategy, CacheStrategy::MemoryOnly);
    assert_eq!(config.max_size_bytes, 104_857_600);
    assert_eq!(config.default_ttl_secs, 120);
    assert_eq!(config.max_ttl_secs, 600);
    assert_eq!(config.min_object_size, 128);
    assert_eq!(config.max_object_size, 1_048_576);
    assert_eq!(config.cacheable_patterns, vec!["/github/*".to_string()]);
    assert_eq!(config.bypass_patterns, vec!["/metrics".to_string()]);
}
