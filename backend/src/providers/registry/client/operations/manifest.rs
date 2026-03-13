use crate::services::client::HttpError;
use std::time::Instant;

use super::super::{DockerProxy, registry_host_label};
use crate::infra;

fn manifest_accept_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json",
        ),
        (
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        ),
        ("Accept", "application/vnd.oci.image.manifest.v1+json"),
        ("Accept", "application/vnd.oci.image.index.v1+json"),
    ]
}

pub(super) async fn fetch_manifest_with_accept(
    proxy: &DockerProxy,
    registry_url: &str,
    image_name: &str,
    reference: &str,
    method: hyper::Method,
    accept_headers: Option<Vec<(&'static str, &'static str)>>,
) -> Result<(hyper::StatusCode, hyper::HeaderMap, bytes::Bytes), HttpError> {
    let url = format!("{}/v2/{}/manifests/{}", registry_url, image_name, reference);
    proxy
        .fetch_with_auth(
            method,
            &url,
            accept_headers.or_else(|| Some(manifest_accept_headers())),
        )
        .await
}

impl DockerProxy {
    pub async fn get_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<(String, String), String> {
        let reference = self.normalize_reference_or_digest(reference);
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
        let registry_host = registry_host_label(&registry_url);
        tracing::info!(registry = %registry_url, image = %image_name, reference = %reference, "Fetching manifest");

        let start = Instant::now();
        let (status, headers, body) = fetch_manifest_with_accept(
            self,
            &registry_url,
            &image_name,
            &reference,
            hyper::Method::GET,
            None,
        )
        .await
        .map_err(|error| error.0)?;
        infra::metrics::record_registry_upstream_request(
            "manifest_get",
            &registry_host,
            Some(status.as_u16()),
            start.elapsed().as_secs_f64(),
        );

        if !status.is_success() {
            return Err(format!("manifest not found: {}", status));
        }

        let content_type = headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        Ok((content_type, String::from_utf8_lossy(&body).to_string()))
    }

    pub async fn head_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<(String, u64), String> {
        let reference = self.normalize_reference_or_digest(reference);
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
        let url = format!("{}/v2/{}/manifests/{}", registry_url, image_name, reference);
        let registry_host = registry_host_label(&registry_url);
        tracing::info!(registry = %registry_url, image = %image_name, reference = %reference, "HEAD manifest");

        let headers: Vec<(String, String)> = manifest_accept_headers()
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();

        let start = Instant::now();
        let (status, resp_headers) = self
            .head_with_auth(
                &url,
                Some(
                    headers
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect(),
                ),
            )
            .await
            .map_err(|error| error.0)?;
        infra::metrics::record_registry_upstream_request(
            "manifest_head",
            &registry_host,
            Some(status.as_u16()),
            start.elapsed().as_secs_f64(),
        );

        if !status.is_success() {
            return Err(format!("manifest not found: {}", status));
        }

        let content_type = resp_headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let content_length = resp_headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);

        Ok((content_type, content_length))
    }
}
