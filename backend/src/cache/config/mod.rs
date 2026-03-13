//! 缓存配置

mod pattern;
mod strategy;

pub use strategy::CacheStrategy;

use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    pub strategy: CacheStrategy,
    #[serde(alias = "maxSizeBytes")]
    pub max_size_bytes: u64,
    #[serde(alias = "defaultTtlSecs")]
    pub default_ttl_secs: u64,
    #[serde(alias = "maxTtlSecs")]
    pub max_ttl_secs: u64,
    #[serde(alias = "minObjectSize")]
    pub min_object_size: u64,
    #[serde(alias = "maxObjectSize")]
    pub max_object_size: u64,
    #[serde(alias = "cacheablePatterns")]
    pub cacheable_patterns: Vec<String>,
    #[serde(alias = "bypassPatterns")]
    pub bypass_patterns: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            strategy: CacheStrategy::default(),
            max_size_bytes: 512 * 1024 * 1024,
            default_ttl_secs: 3600,
            max_ttl_secs: 86400,
            min_object_size: 1024,
            max_object_size: 100 * 1024 * 1024,
            cacheable_patterns: vec![
                "/github/*".to_string(),
                "/v2/*/blobs/*".to_string(),
                "/v2/*/manifests/*".to_string(),
            ],
            bypass_patterns: vec![
                "/api/*".to_string(),
                "/metrics".to_string(),
                "/healthz".to_string(),
                "/readyz".to_string(),
            ],
        }
    }
}

impl CacheConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_size_bytes < 10 * 1024 * 1024 {
            return Err("max_size_bytes must be at least 10MB".to_string());
        }
        if self.default_ttl_secs > self.max_ttl_secs {
            return Err("default_ttl_secs cannot exceed max_ttl_secs".to_string());
        }
        if self.min_object_size >= self.max_object_size {
            return Err("min_object_size must be less than max_object_size".to_string());
        }
        Ok(())
    }

    pub fn default_ttl(&self) -> Duration {
        Duration::from_secs(self.default_ttl_secs)
    }

    pub fn max_ttl(&self) -> Duration {
        Duration::from_secs(self.max_ttl_secs)
    }

    pub fn is_cacheable(&self, path: &str) -> bool {
        if self.is_bypassed(path) {
            return false;
        }

        self.cacheable_patterns
            .iter()
            .any(|pattern| pattern::matches_pattern(path, pattern))
    }

    pub fn is_bypassed(&self, path: &str) -> bool {
        self.bypass_patterns
            .iter()
            .any(|pattern| pattern::matches_pattern(path, pattern))
    }

    pub fn get_ttl_for_content_type(&self, content_type: &str) -> Duration {
        let content_type = content_type.to_lowercase();

        if content_type.contains("image/")
            || content_type.contains("video/")
            || content_type.contains("font/")
            || content_type.contains("application/octet-stream")
        {
            Duration::from_secs(86400)
        } else if content_type.contains("text/css")
            || content_type.contains("application/javascript")
            || content_type.contains("application/json")
        {
            Duration::from_secs(43200)
        } else if content_type.contains("text/") {
            Duration::from_secs(3600)
        } else {
            self.default_ttl()
        }
    }
}

#[cfg(test)]
mod tests;
