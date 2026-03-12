//! 缓存键

use axum::http::{HeaderMap, header};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

/// 缓存键种类
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheKeyKind {
    /// GitHub 文件
    GithubFile,
    /// Docker Manifest
    DockerManifest,
    /// Docker Blob
    DockerBlob,
    /// 通用响应
    Generic,
}

impl CacheKeyKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            CacheKeyKind::GithubFile => "gh",
            CacheKeyKind::DockerManifest => "manifest",
            CacheKeyKind::DockerBlob => "blob",
            CacheKeyKind::Generic => "generic",
        }
    }
}

impl fmt::Display for CacheKeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 缓存键
#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct CacheKey {
    pub kind: CacheKeyKind,
    pub host: String,
    pub path: String,
    /// 查询字符串（可选，用于区分不同参数的请求）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// 请求变体键（用于隔离 Accept 影响的缓存对象）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_key: Option<u64>,
}

impl CacheKey {
    /// 创建 GitHub 文件缓存键
    pub fn github(host: &str, path: &str, query: Option<&str>) -> Self {
        Self::github_variant(host, path, query, None)
    }

    /// 创建 GitHub 文件缓存键（带请求变体）
    pub fn github_variant(
        host: &str,
        path: &str,
        query: Option<&str>,
        variant_key: Option<u64>,
    ) -> Self {
        Self {
            kind: CacheKeyKind::GithubFile,
            host: host.to_lowercase(),
            path: path.to_string(),
            query: query.map(String::from),
            variant_key,
        }
    }

    /// 创建 Docker Manifest 缓存键
    pub fn docker_manifest(name: &str, reference: &str) -> Self {
        Self::docker_manifest_for("registry", name, reference)
    }

    /// 创建 Docker Manifest 缓存键（带 registry host）
    pub fn docker_manifest_for(host: &str, name: &str, reference: &str) -> Self {
        Self {
            kind: CacheKeyKind::DockerManifest,
            host: host.to_lowercase(),
            path: format!("{}/{}", name, reference),
            query: None,
            variant_key: None,
        }
    }

    /// 创建 Docker Blob 缓存键
    pub fn docker_blob(name: &str, digest: &str) -> Self {
        Self::docker_blob_for("registry", name, digest)
    }

    /// 创建 Docker Blob 缓存键（带 registry host）
    pub fn docker_blob_for(host: &str, name: &str, digest: &str) -> Self {
        Self {
            kind: CacheKeyKind::DockerBlob,
            host: host.to_lowercase(),
            path: format!("{}/{}", name, digest),
            query: None,
            variant_key: None,
        }
    }

    /// 创建通用缓存键
    pub fn generic(method: &str, host: &str, path: &str, query: Option<&str>) -> Self {
        Self::generic_variant(method, host, path, query, None)
    }

    /// 创建通用缓存键（带请求变体）
    pub fn generic_variant(
        method: &str,
        host: &str,
        path: &str,
        query: Option<&str>,
        variant_key: Option<u64>,
    ) -> Self {
        Self {
            kind: CacheKeyKind::Generic,
            host: host.to_lowercase(),
            path: format!("{} {}", method, path),
            query: query.map(String::from),
            variant_key,
        }
    }

    /// 转换为字符串（用于存储）
    pub fn to_cache_str(&self) -> String {
        let mut value = match &self.query {
            Some(q) => format!("{}:{}:{}?{}", self.kind, self.host, self.path, q),
            None => format!("{}:{}:{}", self.kind, self.host, self.path),
        };
        if let Some(variant_key) = self.variant_key {
            value.push_str(&format!("#v={:016x}", variant_key));
        }
        value
    }

    /// 从字符串解析缓存键
    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 3 {
            return None;
        }

        let kind_str = *parts.first()?;
        let kind = match kind_str {
            "gh" => CacheKeyKind::GithubFile,
            "manifest" => CacheKeyKind::DockerManifest,
            "blob" => CacheKeyKind::DockerBlob,
            "generic" => CacheKeyKind::Generic,
            _ => return None,
        };

        let host = parts.get(1)?.to_string();
        let rest = parts[2..].join(":");
        let (rest, variant_key) = match rest.rsplit_once("#v=") {
            Some((base, raw_variant))
                if !raw_variant.is_empty()
                    && raw_variant.chars().all(|ch| ch.is_ascii_hexdigit()) =>
            {
                (base.to_string(), u64::from_str_radix(raw_variant, 16).ok())
            }
            _ => (rest, None),
        };

        let (path, query) = if let Some(q_pos) = rest.find('?') {
            let p = &rest[..q_pos];
            let q = &rest[q_pos + 1..];
            (p.to_string(), Some(q.to_string()))
        } else {
            (rest, None)
        };

        Some(CacheKey {
            kind,
            host,
            path,
            query,
            variant_key,
        })
    }
}

fn normalized_header_values(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    let values = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::trim))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    if values.is_empty() {
        None
    } else {
        Some(values.join(","))
    }
}

/// 计算会影响缓存对象变体的请求头摘要。
pub fn request_variant_key(headers: &HeaderMap) -> Option<u64> {
    let mut hasher = DefaultHasher::new();
    let mut has_values = false;

    for (name, value) in [("accept", normalized_header_values(headers, header::ACCEPT))] {
        if let Some(value) = value {
            has_values = true;
            name.hash(&mut hasher);
            value.hash(&mut hasher);
        }
    }

    has_values.then(|| hasher.finish())
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_cache_str().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_key_github() {
        let key = CacheKey::github("github.com", "/owner/repo/main/file.txt", Some("raw=true"));

        let s = key.to_cache_str();
        assert!(s.contains("gh"));
        assert!(s.contains("github.com"));

        let parsed = CacheKey::from_string(&s).unwrap();
        assert_eq!(parsed.kind, CacheKeyKind::GithubFile);
        assert_eq!(parsed.host, "github.com");
        assert_eq!(parsed.query, Some("raw=true".to_string()));
        assert_eq!(parsed.variant_key, None);
    }

    #[test]
    fn test_cache_key_docker() {
        let key = CacheKey::docker_manifest("nginx", "latest");

        let s = key.to_cache_str();
        assert!(s.contains("manifest"));
        assert!(s.contains("nginx/latest"));

        let parsed = CacheKey::from_string(&s).unwrap();
        assert_eq!(parsed.kind, CacheKeyKind::DockerManifest);
        assert_eq!(parsed.variant_key, None);
    }

    #[test]
    fn test_cache_key_round_trips_variant_key() {
        let key = CacheKey::generic_variant(
            "GET",
            "example.com",
            "/download",
            Some("raw=1"),
            Some(0xdead_beef_u64),
        );

        let parsed = CacheKey::from_string(&key.to_cache_str()).unwrap();

        assert_eq!(parsed.variant_key, Some(0xdead_beef_u64));
        assert_eq!(parsed.query, Some("raw=1".to_string()));
    }

    #[test]
    fn test_request_variant_key_depends_on_accept_only() {
        let mut json_headers = HeaderMap::new();
        json_headers.insert(header::ACCEPT, "application/json".parse().unwrap());
        json_headers.insert(header::USER_AGENT, "curl/8.0".parse().unwrap());
        json_headers.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let mut text_headers = HeaderMap::new();
        text_headers.insert(header::ACCEPT, "text/plain".parse().unwrap());
        text_headers.insert(header::USER_AGENT, "other-agent".parse().unwrap());
        text_headers.insert(header::ACCEPT_ENCODING, "br".parse().unwrap());

        assert_ne!(
            request_variant_key(&json_headers),
            request_variant_key(&text_headers)
        );
    }

    #[test]
    fn test_request_variant_key_ignores_user_agent_and_accept_encoding() {
        let mut first = HeaderMap::new();
        first.insert(header::ACCEPT, "application/json".parse().unwrap());
        first.insert(header::USER_AGENT, "curl/8.0".parse().unwrap());
        first.insert(header::ACCEPT_ENCODING, "gzip".parse().unwrap());

        let mut second = HeaderMap::new();
        second.insert(header::ACCEPT, "application/json".parse().unwrap());
        second.insert(header::USER_AGENT, "browser".parse().unwrap());
        second.insert(header::ACCEPT_ENCODING, "br".parse().unwrap());

        assert_eq!(request_variant_key(&first), request_variant_key(&second));
    }

    #[test]
    fn test_request_variant_key_is_none_when_no_vary_headers_exist() {
        let headers = HeaderMap::new();

        assert_eq!(request_variant_key(&headers), None);
    }
}
