use crate::config::CloudflareConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{error, info};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CloudflareStats {
    pub requests: u64,
    pub bytes: u64,
    pub cached_requests: u64, // 新增：缓存请求数
    pub cached_bytes: u64,    // 新增：缓存字节数
}

#[derive(Debug)]
struct CachedStats {
    data: CloudflareStats,
    last_updated: Instant,
}

impl Default for CachedStats {
    fn default() -> Self {
        Self {
            data: CloudflareStats::default(),
            last_updated: Instant::now()
                .checked_sub(Duration::from_secs(3600))
                .unwrap(),
        }
    }
}

pub struct CloudflareService {
    client: Client,
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

#[derive(Deserialize)]
struct Sum {
    requests: u64,
    bytes: u64,
    cached_requests: Option<u64>, // GraphQL 字段
    cached_bytes: Option<u64>,    // GraphQL 字段
}

impl CloudflareService {
    pub fn new(config: CloudflareConfig) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
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

        {
            let cache = self.cache.read().await;
            if cache.last_updated.elapsed() < Duration::from_secs(300) {
                return Some(cache.data.clone());
            }
        }

        let mut cache = self.cache.write().await;
        if cache.last_updated.elapsed() < Duration::from_secs(300) {
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
        // Fetch last 30 days
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

        let resp = self
            .client
            .post("https://api.cloudflare.com/client/v4/graphql")
            .header("Authorization", format!("Bearer {}", self.config.api_token))
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            return Err(format!("API returned status {}", resp.status()));
        }

        let body: GraphqlResponse = resp.json().await.map_err(|e| e.to_string())?;

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
