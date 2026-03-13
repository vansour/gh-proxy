use crate::providers::registry::client::DockerProxy;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use serde_json::Value as JsonValue;

use super::super::manifest::fetch_manifest_with_accept;

impl DockerProxy {
    pub async fn debug_blob_info(
        &self,
        name: &str,
        digest: &str,
        reference: &str,
    ) -> Result<(u64, u64), String> {
        let digest = self.normalize_reference_or_digest(digest);
        let reference = self.normalize_reference_or_digest(reference);
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;

        let (status, _, manifest_body) = fetch_manifest_with_accept(
            self,
            &registry_url,
            &image_name,
            &reference,
            hyper::Method::GET,
            Some(vec![
                (
                    "Accept",
                    "application/vnd.docker.distribution.manifest.v2+json",
                ),
                (
                    "Accept",
                    "application/vnd.docker.distribution.manifest.list.v2+json",
                ),
            ]),
        )
        .await
        .map_err(|error| error.0)?;

        if !status.is_success() {
            return Err(format!("manifest not found: {}", status));
        }

        let manifest_json: JsonValue =
            serde_json::from_slice(&manifest_body).map_err(|error| error.to_string())?;

        let mut manifest_size = 0u64;
        if let Some(layers) = manifest_json
            .get("layers")
            .and_then(|value| value.as_array())
        {
            for layer in layers {
                if let Some(layer_digest) = layer.get("digest").and_then(|value| value.as_str())
                    && layer_digest == digest
                {
                    if let Some(size) = layer.get("size").and_then(|value| value.as_u64()) {
                        manifest_size = size;
                    }
                    break;
                }
            }
        }

        let blob_url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        let response = self
            .fetch_streaming_with_auth(hyper::Method::GET, &blob_url, None)
            .await
            .map_err(|error| error.0)?;

        if !response.status().is_success() {
            return Err(format!("blob not found: {}", response.status()));
        }

        let mut stream = response.into_body().into_data_stream();
        let mut actual_size = 0u64;
        while let Some(chunk_result) = stream.next().await {
            let bytes = chunk_result.map_err(|error| error.to_string())?;
            actual_size += bytes.len() as u64;
        }

        Ok((manifest_size, actual_size))
    }
}
