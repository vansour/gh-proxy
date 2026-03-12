//! 缓存配置

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// 缓存策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheStrategy {
    /// 完全禁用缓存
    Disabled,
    /// 仅使用内存缓存
    MemoryOnly,
    /// 内存 + CDN 缓存
    #[default]
    MemoryWithCdn,
}

/// 缓存配置
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct CacheConfig {
    /// 缓存策略
    pub strategy: CacheStrategy,

    /// 最大缓存大小（字节）
    #[serde(alias = "maxSizeBytes")]
    pub max_size_bytes: u64,

    /// 默认 TTL（秒）
    #[serde(alias = "defaultTtlSecs")]
    pub default_ttl_secs: u64,

    /// 最大 TTL（秒）
    #[serde(alias = "maxTtlSecs")]
    pub max_ttl_secs: u64,

    /// 最小缓存对象大小（字节）
    #[serde(alias = "minObjectSize")]
    pub min_object_size: u64,

    /// 最大缓存对象大小（字节）
    #[serde(alias = "maxObjectSize")]
    pub max_object_size: u64,

    /// 可缓存的路径模式
    #[serde(alias = "cacheablePatterns")]
    pub cacheable_patterns: Vec<String>,

    /// 不可缓存的路径模式
    #[serde(alias = "bypassPatterns")]
    pub bypass_patterns: Vec<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            strategy: CacheStrategy::default(),
            max_size_bytes: 512 * 1024 * 1024,  // 512MB
            default_ttl_secs: 3600,             // 1 小时
            max_ttl_secs: 86400,                // 24 小时
            min_object_size: 1024,              // 1KB
            max_object_size: 100 * 1024 * 1024, // 100MB
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
    /// 验证配置
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

    /// 获取默认 TTL
    pub fn default_ttl(&self) -> Duration {
        Duration::from_secs(self.default_ttl_secs)
    }

    /// 获取最大 TTL
    pub fn max_ttl(&self) -> Duration {
        Duration::from_secs(self.max_ttl_secs)
    }

    /// 检查路径是否可缓存
    pub fn is_cacheable(&self, path: &str) -> bool {
        if self.is_bypassed(path) {
            return false;
        }

        // 检查是否在可缓存列表中
        for pattern in &self.cacheable_patterns {
            if self.matches_pattern(path, pattern) {
                return true;
            }
        }

        // 默认不缓存
        false
    }

    /// 检查路径是否明确绕过缓存
    pub fn is_bypassed(&self, path: &str) -> bool {
        for pattern in &self.bypass_patterns {
            if self.matches_pattern(path, pattern) {
                return true;
            }
        }

        false
    }

    /// 简单的模式匹配（支持 * 通配符）
    fn matches_pattern(&self, path: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        // Split pattern by * and check that path contains all parts in order
        let parts: Vec<&str> = pattern.split('*').collect();

        // If no * in pattern, do exact match
        if parts.len() == 1 {
            return path == pattern;
        }

        // Check that path starts with first part
        if !parts[0].is_empty() && !path.starts_with(parts[0]) {
            return false;
        }

        // Check that path ends with last part
        if !parts.last().unwrap().is_empty() && !path.ends_with(parts.last().unwrap()) {
            return false;
        }

        // Check that path contains all middle parts in order
        let mut search_start = parts[0].len();
        for part in &parts[1..parts.len() - 1] {
            if !part.is_empty() {
                if let Some(pos) = path[search_start..].find(part) {
                    search_start += pos + part.len();
                } else {
                    return false;
                }
            }
        }

        true
    }

    /// 根据 Content-Type 获取 TTL
    pub fn get_ttl_for_content_type(&self, content_type: &str) -> Duration {
        let ct = content_type.to_lowercase();

        // 静态资源：24小时
        if ct.contains("image/")
            || ct.contains("video/")
            || ct.contains("font/")
            || ct.contains("application/octet-stream")
        {
            Duration::from_secs(86400)
        }
        // CSS/JS：12小时
        else if ct.contains("text/css")
            || ct.contains("application/javascript")
            || ct.contains("application/json")
        {
            Duration::from_secs(43200)
        }
        // 其他文本内容：1小时
        else if ct.contains("text/") {
            Duration::from_secs(3600)
        }
        // 默认
        else {
            self.default_ttl()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_matches_pattern() {
        let config = CacheConfig::default();

        assert!(config.matches_pattern("/github/test", "/github/*"));
        assert!(config.matches_pattern("/v2/test/blobs/abc123", "/v2/*/blobs/*"));
        assert!(!config.matches_pattern("/api/config", "/github/*"));
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

        // 有效配置
        assert!(config.validate().is_ok());

        // 无效：max_size_bytes 太小
        let config = CacheConfig {
            max_size_bytes: 1024 * 1024,
            ..CacheConfig::default()
        };
        assert!(config.validate().is_err());

        // 无效：default_ttl 超过 max_ttl
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
}
