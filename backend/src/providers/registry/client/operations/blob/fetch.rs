use crate::infra;
use crate::providers::registry::client::{DockerProxy, registry_host_label};
use std::time::Instant;

impl DockerProxy {
    pub async fn get_blob(
        &self,
        name: &str,
        digest: &str,
    ) -> Result<hyper::Response<hyper::body::Incoming>, String> {
        let digest = self.normalize_reference_or_digest(digest);
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
        let url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        let registry_host = registry_host_label(&registry_url);
        tracing::info!(registry = %registry_url, image = %image_name, digest = %digest, "Fetching blob");

        let start = Instant::now();
        match self
            .fetch_streaming_with_auth(hyper::Method::GET, &url, None)
            .await
        {
            Ok(response) => {
                infra::metrics::record_registry_upstream_request(
                    "blob_get",
                    &registry_host,
                    Some(response.status().as_u16()),
                    start.elapsed().as_secs_f64(),
                );
                Ok(response)
            }
            Err(error) => {
                infra::metrics::record_registry_upstream_request(
                    "blob_get",
                    &registry_host,
                    None,
                    start.elapsed().as_secs_f64(),
                );
                Err(error.0)
            }
        }
    }

    pub async fn head_blob(&self, name: &str, digest: &str) -> Result<u64, String> {
        let digest = self.normalize_reference_or_digest(digest);
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
        let url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        let registry_host = registry_host_label(&registry_url);
        tracing::info!(registry = %registry_url, image = %image_name, digest = %digest, "HEAD blob");

        let start = Instant::now();
        let (status, headers) = match self.head_with_auth(&url, None).await {
            Ok(result) => {
                infra::metrics::record_registry_upstream_request(
                    "blob_head",
                    &registry_host,
                    Some(result.0.as_u16()),
                    start.elapsed().as_secs_f64(),
                );
                result
            }
            Err(error) => {
                infra::metrics::record_registry_upstream_request(
                    "blob_head",
                    &registry_host,
                    None,
                    start.elapsed().as_secs_f64(),
                );
                return Err(error.0);
            }
        };

        if !status.is_success() {
            return Err(format!("blob not found: {}", status));
        }

        let content_length = headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(content_length)
    }
}
