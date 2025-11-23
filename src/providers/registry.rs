use crate::AppState;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use reqwest::Method;
use serde_json::Value as JsonValue;
// Arc not required in this module directly

pub struct DockerProxy {
    client: reqwest::Client,
    registry_url: String,
}

impl DockerProxy {
    pub fn new(default_registry: &str) -> Self {
        let mut registry_url = default_registry.to_string();
        if !registry_url.starts_with("http://") && !registry_url.starts_with("https://") {
            registry_url = format!("https://{}", registry_url);
        }

        let client = reqwest::Client::builder()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!("Failed to build custom client, using default: {}", e);
                reqwest::Client::new()
            });

        Self {
            client,
            registry_url,
        }
    }

    fn split_registry_and_name(&self, name: &str) -> (String, String) {
        if let Some(pos) = name.find('/') {
            let first = &name[..pos];
            if first.contains('.') || first.contains(':') {
                let registry_url = format!("https://{}", first);
                let rest = &name[pos + 1..];
                return (registry_url, rest.to_string());
            }
        }
        (self.registry_url.clone(), self.normalize_image_name(name))
    }

    fn normalize_image_name(&self, name: &str) -> String {
        if name.contains('/') {
            name.to_string()
        } else {
            format!("library/{}", name)
        }
    }

    async fn fetch_with_auth(
        &self,
        method: Method,
        url: &str,
        extra_headers: Option<Vec<(&str, &str)>>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut req = self.client.request(method, url);
        if let Some(hs) = &extra_headers {
            for (k, v) in hs.iter() {
                req = req.header(*k, *v);
            }
        }
        req.send().await
    }

    pub async fn get_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<(String, String), String> {
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let url = format!("{}/v2/{}/manifests/{}", registry_url, image_name, reference);
        tracing::info!(registry = %registry_url, image = %image_name, reference = %reference, "Fetching manifest");

        let response = self
            .fetch_with_auth(
                Method::GET,
                &url,
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
            .map_err(|e| e.to_string())?;

        if !response.status().is_success() {
            return Err(format!("manifest not found: {}", response.status()));
        }

        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let body = response.text().await.map_err(|e| e.to_string())?;
        Ok((content_type, body))
    }

    pub async fn head_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<(String, u64), String> {
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let url = format!("{}/v2/{}/manifests/{}", registry_url, image_name, reference);
        tracing::info!(registry = %registry_url, image = %image_name, reference = %reference, "HEAD manifest");

        let response = self
            .fetch_with_auth(
                Method::HEAD,
                &url,
                Some(vec![(
                    "Accept",
                    "application/vnd.docker.distribution.manifest.v2+json",
                )]),
            )
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("manifest not found: {}", response.status()));
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let content_length = response
            .headers()
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Ok((content_type, content_length))
    }

    pub async fn get_blob(&self, name: &str, digest: &str) -> Result<reqwest::Response, String> {
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        tracing::info!(registry = %registry_url, image = %image_name, digest = %digest, "Fetching blob");
        self.fetch_with_auth(Method::GET, &url, None)
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn head_blob(&self, name: &str, digest: &str) -> Result<u64, String> {
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        tracing::info!(registry = %registry_url, image = %image_name, digest = %digest, "HEAD blob");
        let response = self
            .fetch_with_auth(Method::HEAD, &url, None)
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("blob not found: {}", response.status()));
        }
        let content_length = response
            .headers()
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        Ok(content_length)
    }

    pub async fn debug_blob_info(
        &self,
        name: &str,
        digest: &str,
        reference: &str,
    ) -> Result<(u64, u64), String> {
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let manifest_url = format!("{}/v2/{}/manifests/{}", registry_url, image_name, reference);

        let manifest_resp = self
            .fetch_with_auth(
                Method::GET,
                &manifest_url,
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
            .map_err(|e| e.to_string())?;
        if !manifest_resp.status().is_success() {
            return Err(format!("manifest not found: {}", manifest_resp.status()));
        }
        let manifest_json: JsonValue = manifest_resp.json().await.map_err(|e| e.to_string())?;
        let mut manifest_size = 0u64;
        if let Some(layers) = manifest_json.get("layers").and_then(|v| v.as_array()) {
            for layer in layers {
                if let Some(d) = layer.get("digest").and_then(|v| v.as_str())
                    && d == digest
                {
                    if let Some(s) = layer.get("size").and_then(|v| v.as_u64()) {
                        manifest_size = s;
                    }
                    break;
                }
            }
        }

        let blob_url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        let blob_resp = self
            .fetch_with_auth(Method::GET, &blob_url, None)
            .await
            .map_err(|e| e.to_string())?;
        if !blob_resp.status().is_success() {
            return Err(format!("blob not found: {}", blob_resp.status()));
        }

        let mut stream = blob_resp.bytes_stream();
        use futures_util::StreamExt;
        let mut actual_size: u64 = 0;
        while let Some(chunk_result) = stream.next().await {
            let bytes = chunk_result.map_err(|e| e.to_string())?;
            actual_size += bytes.len() as u64;
        }
        Ok((manifest_size, actual_size))
    }

    pub async fn check_registry_health(&self) -> bool {
        let url = format!("{}/v2/", self.registry_url);
        match self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
        {
            Ok(resp) => {
                let status = resp.status();
                status.is_success() || status == reqwest::StatusCode::UNAUTHORIZED
            }
            Err(e) => {
                tracing::warn!("Registry health check failed: {}", e);
                false
            }
        }
    }

    pub fn get_registry_url(&self) -> &str {
        &self.registry_url
    }
}

// ----- Routing helpers copied from docker-proxy router.rs (lightweight) -----
#[derive(Debug, PartialEq)]
pub enum V2Endpoint {
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    BlobUploadInit { name: String },
    BlobUploadComplete { name: String, uuid: String },
    Unknown,
}

pub fn parse_v2_path(rest: &str) -> V2Endpoint {
    let parts: Vec<&str> = rest.split('/').collect();
    if let Some(i) = parts.iter().position(|&p| p == "manifests")
        && i + 1 < parts.len()
    {
        let name = parts[..i].join("/");
        let reference = parts[i + 1].to_string();
        return V2Endpoint::Manifest { name, reference };
    }
    if let Some(i) = parts.iter().position(|&p| p == "blobs") {
        if i + 2 < parts.len() && parts[i + 1] == "uploads" {
            let name = parts[..i].join("/");
            let uuid = parts[i + 2].to_string();
            return V2Endpoint::BlobUploadComplete { name, uuid };
        }
        if i + 1 < parts.len() && parts[i + 1] == "uploads" && i + 2 == parts.len() {
            let name = parts[..i].join("/");
            return V2Endpoint::BlobUploadInit { name };
        }
        if i + 1 < parts.len() {
            let name = parts[..i].join("/");
            let digest = parts[i + 1].to_string();
            return V2Endpoint::Blob { name, digest };
        }
    }
    V2Endpoint::Unknown
}

// ----- HTTP handlers -----
pub async fn handle_v2_check() -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    if let Ok(value) = "registry/2.0".parse() {
        headers.insert("Docker-Distribution-Api-Version", value);
    }
    (StatusCode::OK, headers)
}

pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    use serde_json::json;
    let version = env!("CARGO_PKG_VERSION");
    let registry = match &state.docker_proxy {
        Some(p) => p.get_registry_url().to_string(),
        None => "disabled".to_string(),
    };
    let healthy = match &state.docker_proxy {
        Some(p) => p.check_registry_health().await,
        None => false,
    };
    let status = if healthy { "healthy" } else { "degraded" };
    let http_status = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_secs();
    let resp = json!({"status": status, "version": version, "registry": {"url": registry, "healthy": healthy}, "timestamp": ts}).to_string();
    (
        http_status,
        [(header::CONTENT_TYPE, "application/json")],
        resp,
    )
}

pub async fn debug_blob_info(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    use serde_json::json;
    let proxy = match &state.docker_proxy {
        Some(p) => p,
        None => {
            return (StatusCode::NOT_IMPLEMENTED, "Docker support not configured").into_response();
        }
    };
    let name = match params.get("name") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return (StatusCode::BAD_REQUEST, "missing 'name' query parameter").into_response(),
    };
    let digest = match params.get("digest") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return (StatusCode::BAD_REQUEST, "missing 'digest' query parameter").into_response(),
    };
    let reference = params
        .get("reference")
        .cloned()
        .unwrap_or_else(|| "latest".to_string());

    match proxy.debug_blob_info(&name, &digest, &reference).await {
        Ok((manifest_size, actual_size)) => {
            let body = json!({"name": name, "reference": reference, "digest": digest, "manifest_size": manifest_size, "actual_blob_size": actual_size, "size_diff": (actual_size as i64 - manifest_size as i64)}).to_string();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("debug_blob_info error: {}", e);
            (StatusCode::BAD_GATEWAY, format!("debug error: {}", e)).into_response()
        }
    }
}

async fn get_manifest(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let proxy = match &state.docker_proxy {
        Some(p) => p,
        None => return (StatusCode::NOT_IMPLEMENTED, "Docker disabled").into_response(),
    };
    match proxy.get_manifest(&name, &reference).await {
        Ok((content_type, body)) => {
            let mut headers = HeaderMap::new();
            let ct_value = content_type
                .parse()
                .unwrap_or_else(|_| HeaderValue::from_static("application/json"));
            headers.insert(header::CONTENT_TYPE, ct_value);
            (StatusCode::OK, headers, body).into_response()
        }
        Err(e) => {
            tracing::error!("Error getting manifest: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", e)).into_response()
        }
    }
}

async fn head_manifest(
    State(state): State<AppState>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    let proxy = match &state.docker_proxy {
        Some(p) => p,
        None => return (StatusCode::NOT_IMPLEMENTED, "Docker disabled").into_response(),
    };
    match proxy.head_manifest(&name, &reference).await {
        Ok((content_type, content_length)) => {
            let mut headers = HeaderMap::new();
            let ct_value = content_type
                .parse()
                .unwrap_or_else(|_| HeaderValue::from_static("application/json"));
            headers.insert(header::CONTENT_TYPE, ct_value);
            if let Ok(cl_value) = content_length.to_string().parse() {
                headers.insert(header::CONTENT_LENGTH, cl_value);
            }
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => {
            tracing::error!("Error heading manifest: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", e)).into_response()
        }
    }
}

async fn get_blob(
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> impl IntoResponse {
    let proxy = match &state.docker_proxy {
        Some(p) => p,
        None => return (StatusCode::NOT_IMPLEMENTED, "Docker disabled").into_response(),
    };
    match proxy.get_blob(&name, &digest).await {
        Ok(upstream_resp) => {
            let status = axum::http::StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::OK);
            let mut headers = HeaderMap::new();
            for (key, value) in upstream_resp.headers().iter() {
                let key_str = key.as_str();
                if key_str.eq_ignore_ascii_case("connection")
                    || key_str.eq_ignore_ascii_case("transfer-encoding")
                    || key_str.eq_ignore_ascii_case("upgrade")
                {
                    continue;
                }
                if let Ok(ax_key) = axum::http::HeaderName::from_bytes(key_str.as_bytes())
                    && let Ok(ax_val) = axum::http::HeaderValue::from_bytes(value.as_bytes())
                {
                    headers.insert(ax_key, ax_val);
                }
            }
            let stream = upstream_resp.bytes_stream();
            let body = Body::from_stream(stream);
            (status, headers, body).into_response()
        }
        Err(e) => {
            tracing::error!("Error getting blob: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                format!("Upstream blob error: {}", e),
            )
                .into_response()
        }
    }
}

async fn head_blob(
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> impl IntoResponse {
    let proxy = match &state.docker_proxy {
        Some(p) => p,
        None => return (StatusCode::NOT_IMPLEMENTED, "Docker disabled").into_response(),
    };
    match proxy.head_blob(&name, &digest).await {
        Ok(content_length) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (header::CONTENT_LENGTH, content_length.to_string().as_str()),
            ],
        )
            .into_response(),
        Err(e) => {
            tracing::error!("Error heading blob: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", e)).into_response()
        }
    }
}

async fn initiate_blob_upload(_state: State<AppState>, Path(_name): Path<String>) -> Response {
    // Upload not supported in this integration yet
    (StatusCode::METHOD_NOT_ALLOWED, "Upload not supported").into_response()
}

async fn complete_blob_upload() -> impl IntoResponse {
    (StatusCode::CREATED, "Upload complete")
}

pub async fn v2_get(State(state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::Manifest { name, reference } => {
            get_manifest(State(state), Path((name, reference))).await
        }
        V2Endpoint::Blob { name, digest } => get_blob(State(state), Path((name, digest)))
            .await
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn v2_head(State(state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::Manifest { name, reference } => {
            head_manifest(State(state), Path((name, reference))).await
        }
        V2Endpoint::Blob { name, digest } => head_blob(State(state), Path((name, digest)))
            .await
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn v2_post(State(state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::BlobUploadInit { name } => initiate_blob_upload(State(state), Path(name)).await,
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn v2_put(State(_state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::BlobUploadComplete { .. } => complete_blob_upload().await.into_response(),
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_manifest() {
        let ep = parse_v2_path("library/ubuntu/manifests/latest");
        assert_eq!(
            ep,
            V2Endpoint::Manifest {
                name: "library/ubuntu".to_string(),
                reference: "latest".to_string()
            }
        );
    }
}
