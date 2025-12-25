//! IP information service using ipinfo.io API.

use crate::services::client::{HttpError, get_json};
use crate::state::HyperClient;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::error;

#[derive(Debug, Clone)]
struct CacheEntry {
    as_name: String,
    expires_at: Instant,
}

pub struct IpInfoService {
    client: HyperClient,
    token: String,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

#[derive(Deserialize, Debug)]
struct IpInfoResponse {
    #[serde(default)]
    as_name: String,
}

impl IpInfoService {
    pub fn new(client: HyperClient, token: String) -> Self {
        Self {
            client,
            token,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn get_as_name(&self, ip: &str) -> Option<String> {
        if self.token.is_empty() {
            return None;
        }

        // 1. Check Cache
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(ip)
                && entry.expires_at > Instant::now()
            {
                return Some(entry.as_name.clone());
            }
        }

        // 2. Fetch using hyper
        let url = format!("https://api.ipinfo.io/lite/{}?token={}", ip, self.token);

        match get_json::<IpInfoResponse>(
            &self.client,
            &url,
            None,
            3, // 3 second timeout
        )
        .await
        {
            Ok(info) => {
                let name = if info.as_name.is_empty() {
                    "Unknown".to_string()
                } else {
                    info.as_name
                };

                // Cache for 1 hour
                let mut cache = self.cache.write().await;
                cache.insert(
                    ip.to_string(),
                    CacheEntry {
                        as_name: name.clone(),
                        expires_at: Instant::now() + Duration::from_secs(3600),
                    },
                );
                Some(name)
            }
            Err(HttpError(e)) => {
                // Don't spam logs for API failures
                if !e.contains("timeout") {
                    error!("Failed to fetch IP info for {}: {}", ip, e);
                }
                None
            }
        }
    }
}
