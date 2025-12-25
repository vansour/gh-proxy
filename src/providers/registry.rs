//! Docker Registry V2 proxy implementation using hyper client.

use crate::services::client::{HttpError, get_bytes, get_json, head_request, request_streaming};
use crate::state::{AppState, HyperClient};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Maximum number of tokens to cache (LRU eviction when exceeded)
const TOKEN_CACHE_MAX_SIZE: usize = 1000;

// Token cache entry
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

pub struct DockerProxy {
    client: HyperClient,
    registry_url: String,
    token_cache: Arc<RwLock<HashMap<String, CachedToken>>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl DockerProxy {
    pub fn new(client: HyperClient, default_registry: &str) -> Self {
        let mut registry_url = default_registry.to_string();
        if !registry_url.starts_with("http://") && !registry_url.starts_with("https://") {
            registry_url = format!("https://{}", registry_url);
        }

        Self {
            client,
            registry_url,
            token_cache: Arc::new(RwLock::new(HashMap::new())),
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

    fn normalize_reference_or_digest(&self, value: &str) -> String {
        if value.starts_with("sha256-") && value.len() > 64 {
            return value.replacen("sha256-", "sha256:", 1);
        }
        value.to_string()
    }

    async fn fetch_with_auth(
        &self,
        _method: hyper::Method,
        url: &str,
        extra_headers: Option<Vec<(&str, &str)>>,
    ) -> Result<(hyper::StatusCode, hyper::HeaderMap, Bytes), HttpError> {
        let headers: Option<Vec<(String, String)>> = extra_headers.as_ref().map(|h| {
            h.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        });

        // First attempt
        let (status, resp_headers, body) = get_bytes(&self.client, url, extra_headers, 60).await?;

        // If upstream requires registry authentication, handle Bearer challenge
        if status == hyper::StatusCode::UNAUTHORIZED
            && let Some(www_auth) = resp_headers.get("www-authenticate")
            && let Ok(www_str) = www_auth.to_str()
            && www_str.to_lowercase().starts_with("bearer")
        {
            if let Ok(token) = self.request_bearer_token(www_str).await {
                // Retry with authorization
                let mut auth_headers: Vec<(String, String)> =
                    headers.unwrap_or_default().into_iter().collect();
                auth_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));

                return get_bytes(
                    &self.client,
                    url,
                    Some(
                        auth_headers
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.as_str()))
                            .collect(),
                    ),
                    60,
                )
                .await;
            } else {
                tracing::warn!("Failed to retrieve bearer token for challenge: {}", www_str);
            }
        }

        Ok((status, resp_headers, body))
    }

    async fn fetch_streaming_with_auth(
        &self,
        method: hyper::Method,
        url: &str,
        extra_headers: Option<Vec<(&str, &str)>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, HttpError> {
        let headers: Option<Vec<(String, String)>> = extra_headers.as_ref().map(|h| {
            h.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        });

        // First attempt
        let response =
            request_streaming(&self.client, method.clone(), url, headers.clone(), 60).await?;

        // If upstream requires registry authentication, handle Bearer challenge
        if response.status() == hyper::StatusCode::UNAUTHORIZED
            && let Some(www_auth) = response.headers().get("www-authenticate")
            && let Ok(www_str) = www_auth.to_str()
            && www_str.to_lowercase().starts_with("bearer")
            && let Ok(token) = self.request_bearer_token(www_str).await
        {
            // Retry with authorization
            let mut auth_headers: Vec<(String, String)> =
                headers.unwrap_or_default().into_iter().collect();
            auth_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));

            return request_streaming(&self.client, method, url, Some(auth_headers), 60).await;
        }

        Ok(response)
    }

    async fn request_bearer_token(&self, www_authenticate_header: &str) -> Result<String, String> {
        fn parse_kv_pairs(s: &str) -> HashMap<String, String> {
            let mut m = HashMap::new();
            for pair in s.split(',') {
                if let Some((k, v)) = pair.split_once('=') {
                    let key = k.trim().trim_matches('"').to_ascii_lowercase();
                    let value = v.trim().trim_matches('"').to_string();
                    m.insert(key, value);
                }
            }
            m
        }

        let trimmed = www_authenticate_header.trim();
        let rest = match trimmed.find(char::is_whitespace) {
            Some(i) => &trimmed[i..],
            None => "",
        }
        .trim();

        let pairs = parse_kv_pairs(rest);
        let realm = match pairs.get("realm") {
            Some(r) => r.clone(),
            None => return Err("WWW-Authenticate header missing realm".to_string()),
        };
        let service = pairs.get("service").cloned().unwrap_or_default();
        let scope = pairs.get("scope").cloned().unwrap_or_default();

        let cache_key = format!("{}|{}|{}", realm, service, scope);

        // Check cache
        {
            let cache = self.token_cache.read().await;
            if let Some(entry) = cache.get(&cache_key)
                && entry.expires_at > Instant::now()
            {
                tracing::debug!("Token cache hit for scope: {}", scope);
                return Ok(entry.token.clone());
            }
        }

        // Fetch from upstream
        tracing::debug!("Token cache miss, fetching for scope: {}", scope);

        let mut token_url = realm.clone();
        let mut first_param = true;
        if !service.is_empty() {
            token_url.push_str(if first_param { "?" } else { "&" });
            token_url.push_str("service=");
            token_url.push_str(&urlencoding::encode(&service));
            first_param = false;
        }
        if !scope.is_empty() {
            token_url.push_str(if first_param { "?" } else { "&" });
            token_url.push_str("scope=");
            token_url.push_str(&urlencoding::encode(&scope));
        }

        let token_resp: TokenResponse = get_json(&self.client, &token_url, None, 10)
            .await
            .map_err(|e| e.0)?;

        let token = token_resp
            .token
            .or(token_resp.access_token)
            .ok_or_else(|| "token not found in token response".to_string())?;

        let expires_in_secs = token_resp
            .expires_in
            .unwrap_or(60)
            .saturating_sub(10)
            .max(10);
        let expires_at = Instant::now() + Duration::from_secs(expires_in_secs);

        // Update cache with LRU eviction
        {
            let mut cache = self.token_cache.write().await;

            // Clean up expired entries first
            let now = Instant::now();
            cache.retain(|_, v| v.expires_at > now);

            // If still too large, remove oldest entries (simple LRU: by earliest expiry)
            if cache.len() >= TOKEN_CACHE_MAX_SIZE {
                let to_remove = cache.len() - TOKEN_CACHE_MAX_SIZE + 1;
                let mut entries: Vec<_> = cache
                    .iter()
                    .map(|(k, v)| (k.clone(), v.expires_at))
                    .collect();
                entries.sort_by_key(|(_, exp)| *exp);
                for (key, _) in entries.into_iter().take(to_remove) {
                    cache.remove(&key);
                }
            }

            cache.insert(
                cache_key,
                CachedToken {
                    token: token.clone(),
                    expires_at,
                },
            );
        }

        Ok(token)
    }

    pub async fn get_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<(String, String), String> {
        let reference = self.normalize_reference_or_digest(reference);
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let url = format!("{}/v2/{}/manifests/{}", registry_url, image_name, reference);
        tracing::info!(registry = %registry_url, image = %image_name, reference = %reference, "Fetching manifest");

        let (status, headers, body) = self
            .fetch_with_auth(
                hyper::Method::GET,
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
                    ("Accept", "application/vnd.oci.image.manifest.v1+json"),
                    ("Accept", "application/vnd.oci.image.index.v1+json"),
                ]),
            )
            .await
            .map_err(|e| e.0)?;

        if !status.is_success() {
            return Err(format!("manifest not found: {}", status));
        }

        let content_type = headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        let body_str = String::from_utf8_lossy(&body).to_string();
        Ok((content_type, body_str))
    }

    pub async fn head_manifest(
        &self,
        name: &str,
        reference: &str,
    ) -> Result<(String, u64), String> {
        let reference = self.normalize_reference_or_digest(reference);
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let url = format!("{}/v2/{}/manifests/{}", registry_url, image_name, reference);
        tracing::info!(registry = %registry_url, image = %image_name, reference = %reference, "HEAD manifest");

        let headers: Vec<(String, String)> = vec![
            (
                "Accept".to_string(),
                "application/vnd.docker.distribution.manifest.v2+json".to_string(),
            ),
            (
                "Accept".to_string(),
                "application/vnd.docker.distribution.manifest.list.v2+json".to_string(),
            ),
            (
                "Accept".to_string(),
                "application/vnd.oci.image.manifest.v1+json".to_string(),
            ),
            (
                "Accept".to_string(),
                "application/vnd.oci.image.index.v1+json".to_string(),
            ),
        ];

        let (status, resp_headers) = head_request(
            &self.client,
            &url,
            Some(
                headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect(),
            ),
            60,
        )
        .await
        .map_err(|e| e.0)?;

        if !status.is_success() {
            return Err(format!("manifest not found: {}", status));
        }

        let content_type = resp_headers
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let content_length = resp_headers
            .get("content-length")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        Ok((content_type, content_length))
    }

    pub async fn get_blob(
        &self,
        name: &str,
        digest: &str,
    ) -> Result<hyper::Response<hyper::body::Incoming>, String> {
        let digest = self.normalize_reference_or_digest(digest);
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        tracing::info!(registry = %registry_url, image = %image_name, digest = %digest, "Fetching blob");

        self.fetch_streaming_with_auth(hyper::Method::GET, &url, None)
            .await
            .map_err(|e| e.0)
    }

    pub async fn head_blob(&self, name: &str, digest: &str) -> Result<u64, String> {
        let digest = self.normalize_reference_or_digest(digest);
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        tracing::info!(registry = %registry_url, image = %image_name, digest = %digest, "HEAD blob");

        let (status, headers) = head_request(&self.client, &url, None, 60)
            .await
            .map_err(|e| e.0)?;

        if !status.is_success() {
            return Err(format!("blob not found: {}", status));
        }

        let content_length = headers
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
        let digest = self.normalize_reference_or_digest(digest);
        let reference = self.normalize_reference_or_digest(reference);
        let (registry_url, image_name) = self.split_registry_and_name(name);
        let manifest_url = format!("{}/v2/{}/manifests/{}", registry_url, image_name, reference);

        let (status, _, manifest_body) = self
            .fetch_with_auth(
                hyper::Method::GET,
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
            .map_err(|e| e.0)?;

        if !status.is_success() {
            return Err(format!("manifest not found: {}", status));
        }

        let manifest_json: JsonValue =
            serde_json::from_slice(&manifest_body).map_err(|e| e.to_string())?;

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
        let response = self
            .fetch_streaming_with_auth(hyper::Method::GET, &blob_url, None)
            .await
            .map_err(|e| e.0)?;

        if !response.status().is_success() {
            return Err(format!("blob not found: {}", response.status()));
        }

        let mut stream = response.into_body().into_data_stream();
        let mut actual_size: u64 = 0;
        while let Some(chunk_result) = stream.next().await {
            let bytes = chunk_result.map_err(|e| e.to_string())?;
            actual_size += bytes.len() as u64;
        }

        Ok((manifest_size, actual_size))
    }

    pub async fn check_registry_health(&self) -> bool {
        let url = format!("{}/v2/", self.registry_url);
        match head_request(&self.client, &url, None, 5).await {
            Ok((status, _)) => status.is_success() || status == hyper::StatusCode::UNAUTHORIZED,
            Err(e) => {
                tracing::warn!("Registry health check failed: {}", e.0);
                false
            }
        }
    }

    pub fn get_registry_url(&self) -> &str {
        &self.registry_url
    }
}

// ----- Routing helpers -----
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
    axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>,
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
            let stream = upstream_resp.into_body().into_data_stream();
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
