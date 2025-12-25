//! Cloudflare analytics service.

use crate::config::CloudflareConfig;
use crate::services::client::{HttpError, post_json};
use crate::state::HyperClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudflareStats {
    pub requests: u64,
    pub bytes: u64,
    pub cached_requests: u64,
    pub cached_bytes: u64,
}

#[derive(Debug)]
struct CachedStats {
    data: CloudflareStats,
    last_updated: Instant,
    force_refresh: bool,
}

impl Default for CachedStats {
    fn default() -> Self {
        Self {
            data: CloudflareStats::default(),
            last_updated: Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap(),
            force_refresh: true,
        }
    }
}

pub struct CloudflareService {
    client: HyperClient,
    config: CloudflareConfig,
    cache: Arc<RwLock<CachedStats>>,
}

#[derive(Serialize)]
struct GraphqlQuery {
    query: String,
}

#[derive(Deserialize)]
struct GraphqlResponse {
    data: Option<Data>,
    errors: Option<Vec<GraphqlError>>,
}

#[derive(Deserialize)]
struct GraphqlError {
    message: String,
}

#[derive(Deserialize)]
struct Data {
    viewer: Viewer,
}

#[derive(Deserialize)]
struct Viewer {
    zones: Vec<Zone>,
}

#[derive(Deserialize)]
struct Zone {
    #[serde(rename = "httpRequests1dGroups")]
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    sum: Sum,
}

#[derive(Deserialize, Debug)]
struct Sum {
    requests: u64,
    bytes: u64,
    #[serde(rename = "cachedRequests")]
    cached_requests: Option<u64>,
    #[serde(rename = "cachedBytes")]
    cached_bytes: Option<u64>,
}

impl CloudflareService {
    pub fn new(client: HyperClient, config: CloudflareConfig) -> Self {
        Self {
            client,
            config,
            cache: Arc::new(RwLock::new(CachedStats::default())),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.config.is_enabled()
    }

    pub async fn get_stats(&self) -> Option<CloudflareStats> {
        if !self.is_enabled() {
            return None;
        }

        // 1. Check cache (Read)
        {
            let cache = self.cache.read().await;
            if !cache.force_refresh && cache.last_updated.elapsed() < Duration::from_secs(600) {
                return Some(cache.data.clone());
            }
        }

        // 2. Update (Write)
        let mut cache = self.cache.write().await;
        if !cache.force_refresh && cache.last_updated.elapsed() < Duration::from_secs(600) {
            return Some(cache.data.clone());
        }

        match self.fetch_from_api().await {
            Ok(stats) => {
                info!(
                    "Updated Cloudflare stats: {} reqs ({} cached), {} bytes ({} cached)",
                    stats.requests, stats.cached_requests, stats.bytes, stats.cached_bytes
                );
                cache.data = stats.clone();
                cache.last_updated = Instant::now();
                cache.force_refresh = false;
                Some(stats)
            }
            Err(e) => {
                error!("Failed to fetch Cloudflare stats: {}", e);
                Some(cache.data.clone())
            }
        }
    }

    async fn fetch_from_api(&self) -> Result<CloudflareStats, String> {
        let zone_id = &self.config.zone_id;
        let query = format!(
            r#"
            query {{
              viewer {{
                zones(filter: {{zoneTag: "{zone_id}"}}) {{
                  httpRequests1dGroups(limit: 30, filter: {{date_geq: "{date}"}}) {{
                    sum {{
                      requests
                      bytes
                      cachedRequests
                      cachedBytes
                    }}
                  }}
                }}
              }}
            }}
        "#,
            zone_id = zone_id,
            date = (chrono::Utc::now() - chrono::Duration::days(30)).format("%Y-%m-%d")
        );

        let payload = GraphqlQuery { query };
        let auth_header = format!("Bearer {}", self.config.api_token);

        let result: Result<GraphqlResponse, HttpError> = post_json(
            &self.client,
            "https://api.cloudflare.com/client/v4/graphql",
            &payload,
            Some(vec![("Authorization", &auth_header)]),
            15,
        )
        .await;

        let body = result.map_err(|e| e.0)?;

        debug!("Cloudflare GraphQL Response received");

        if let Some(errors) = body.errors
            && !errors.is_empty()
        {
            return Err(errors[0].message.clone());
        }

        let groups = body
            .data
            .and_then(|d| d.viewer.zones.into_iter().next())
            .map(|z| z.groups)
            .unwrap_or_default();

        let mut total_reqs = 0;
        let mut total_bytes = 0;
        let mut total_cached_reqs = 0;
        let mut total_cached_bytes = 0;

        for g in groups {
            total_reqs += g.sum.requests;
            total_bytes += g.sum.bytes;
            total_cached_reqs += g.sum.cached_requests.unwrap_or(0);
            total_cached_bytes += g.sum.cached_bytes.unwrap_or(0);
        }

        Ok(CloudflareStats {
            requests: total_reqs,
            bytes: total_bytes,
            cached_requests: total_cached_reqs,
            cached_bytes: total_cached_bytes,
        })
    }
}
