use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheKeyKind {
    GithubFile,
    DockerManifest,
    DockerBlob,
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

    pub(crate) fn from_cache_prefix(value: &str) -> Option<Self> {
        match value {
            "gh" => Some(CacheKeyKind::GithubFile),
            "manifest" => Some(CacheKeyKind::DockerManifest),
            "blob" => Some(CacheKeyKind::DockerBlob),
            "generic" => Some(CacheKeyKind::Generic),
            _ => None,
        }
    }
}

impl fmt::Display for CacheKeyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
