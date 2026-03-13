use std::time::{Duration, Instant};

use crate::infra;
use crate::services::client::head_request;

use super::super::{
    CachedRegistryHealth, DockerProxy, REGISTRY_HEALTH_CACHE_TTL_SECS, registry_host_label,
};

impl DockerProxy {
    pub async fn check_registry_health(&self) -> bool {
        if let Some(cached) = *self.health_cache.read().await
            && cached.expires_at > Instant::now()
        {
            return cached.healthy;
        }

        let url = format!("{}/v2/", self.registry_url);
        let registry_host = registry_host_label(&self.registry_url);
        let start = Instant::now();
        let healthy = match head_request(&self.client, &url, None, 5).await {
            Ok((status, _)) => {
                infra::metrics::record_registry_upstream_request(
                    "health",
                    &registry_host,
                    Some(status.as_u16()),
                    start.elapsed().as_secs_f64(),
                );
                status.is_success() || status == hyper::StatusCode::UNAUTHORIZED
            }
            Err(error) => {
                infra::metrics::record_registry_upstream_request(
                    "health",
                    &registry_host,
                    None,
                    start.elapsed().as_secs_f64(),
                );
                tracing::warn!("Registry health check failed: {}", error.0);
                false
            }
        };

        *self.health_cache.write().await = Some(CachedRegistryHealth {
            healthy,
            expires_at: Instant::now() + Duration::from_secs(REGISTRY_HEALTH_CACHE_TTL_SECS),
        });

        healthy
    }
}
