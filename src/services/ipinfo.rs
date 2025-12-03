use reqwest::Client;
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
    client: Client,
    token: String,
    // Cache: IP -> (AS Name, Expiration)
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

#[derive(Deserialize, Debug)]
struct IpInfoResponse {
    #[serde(default)]
    as_name: String,
}

impl IpInfoService {
    pub fn new(token: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(3)) // Fast timeout
                .build()
                .unwrap_or_default(),
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

        // 2. Fetch
        let url = format!("https://api.ipinfo.io/lite/{}?token={}", ip, self.token);
        match self.client.get(&url).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<IpInfoResponse>().await {
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
                        Err(e) => {
                            error!("Failed to parse IP info for {}: {}", ip, e);
                            None
                        }
                    }
                } else {
                    None
                }
            }
            Err(_e) => {
                // Fixed: prefix with _ to suppress unused variable warning
                // Don't log error to avoid spam if API is down/slow
                // error!("Failed to fetch IP info: {}", e);
                None
            }
        }
    }
}
