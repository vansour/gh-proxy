use crate::config::{HostPattern, RegistryConfig};
use crate::state::HyperClient;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

mod auth;
mod operations;
mod resolve;

const TOKEN_CACHE_MAX_SIZE: usize = 1000;
const REGISTRY_HEALTH_CACHE_TTL_SECS: u64 = 5;

#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct CachedRegistryHealth {
    healthy: bool,
    expires_at: Instant,
}

pub struct DockerProxy {
    client: HyperClient,
    registry_url: String,
    allowed_hosts: Vec<HostPattern>,
    token_cache: Arc<RwLock<HashMap<String, CachedToken>>>,
    health_cache: Arc<RwLock<Option<CachedRegistryHealth>>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl DockerProxy {
    pub fn new(client: HyperClient, registry: &RegistryConfig) -> Self {
        let mut registry_url = registry.default.to_string();
        if !registry_url.starts_with("http://") && !registry_url.starts_with("https://") {
            registry_url = format!("https://{}", registry_url);
        }

        Self {
            client,
            registry_url,
            allowed_hosts: registry.host_patterns(),
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            health_cache: Arc::new(RwLock::new(None)),
        }
    }
}

pub(crate) fn registry_host_label(registry_url: &str) -> String {
    registry_url
        .parse::<hyper::Uri>()
        .ok()
        .and_then(|uri| uri.host().map(|host| host.to_ascii_lowercase()))
        .unwrap_or_else(|| registry_url.to_ascii_lowercase())
}
