//! 缓存键

mod kind;
mod variant;

use serde::{Deserialize, Serialize};
use std::fmt;

pub use kind::CacheKeyKind;
pub use variant::request_variant_key;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Deserialize, Serialize)]
pub struct CacheKey {
    pub kind: CacheKeyKind,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_key: Option<u64>,
}

impl CacheKey {
    pub fn github(host: &str, path: &str, query: Option<&str>) -> Self {
        Self::github_variant(host, path, query, None)
    }

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

    pub fn docker_manifest(name: &str, reference: &str) -> Self {
        Self::docker_manifest_for("registry", name, reference)
    }

    pub fn docker_manifest_for(host: &str, name: &str, reference: &str) -> Self {
        Self {
            kind: CacheKeyKind::DockerManifest,
            host: host.to_lowercase(),
            path: format!("{}/{}", name, reference),
            query: None,
            variant_key: None,
        }
    }

    pub fn docker_blob(name: &str, digest: &str) -> Self {
        Self::docker_blob_for("registry", name, digest)
    }

    pub fn docker_blob_for(host: &str, name: &str, digest: &str) -> Self {
        Self {
            kind: CacheKeyKind::DockerBlob,
            host: host.to_lowercase(),
            path: format!("{}/{}", name, digest),
            query: None,
            variant_key: None,
        }
    }

    pub fn generic(method: &str, host: &str, path: &str, query: Option<&str>) -> Self {
        Self::generic_variant(method, host, path, query, None)
    }

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

    pub fn to_cache_str(&self) -> String {
        let mut value = match &self.query {
            Some(query) => format!("{}:{}:{}?{}", self.kind, self.host, self.path, query),
            None => format!("{}:{}:{}", self.kind, self.host, self.path),
        };
        if let Some(variant_key) = self.variant_key {
            value.push_str(&format!("#v={:016x}", variant_key));
        }
        value
    }

    pub fn from_string(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 3 {
            return None;
        }

        let kind = CacheKeyKind::from_cache_prefix(parts.first()?)?;
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

        let (path, query) = if let Some(query_pos) = rest.find('?') {
            let path = &rest[..query_pos];
            let query = &rest[query_pos + 1..];
            (path.to_string(), Some(query.to_string()))
        } else {
            (rest, None)
        };

        Some(Self {
            kind,
            host,
            path,
            query,
            variant_key,
        })
    }
}

impl fmt::Display for CacheKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.to_cache_str().fmt(f)
    }
}
