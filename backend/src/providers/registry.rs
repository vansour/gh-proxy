//! Docker Registry V2 proxy implementation using hyper client.

use crate::cache::key::CacheKey;
use crate::cache::response_cache::{CacheResult, CachedResponse};
use crate::cache::utils::is_response_cacheable;
use crate::config::{HostPattern, RegistryConfig};
use crate::errors::ProxyError;
use crate::infra;
use crate::middleware::{RequestLifecycle, RequestPermitGuard, mark_response_duration_recorded};
use crate::proxy::headers::add_vary_header;
use crate::proxy::stream::ProxyBodyStream;
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
const REGISTRY_HEALTH_CACHE_TTL_SECS: u64 = 5;

// Token cache entry
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy)]
struct CachedRegistryHealth {
    healthy: bool,
    expires_at: Instant,
}

pub struct DockerProxy {
    client: HyperClient,
    registry_url: String,
    allowed_hosts: Vec<HostPattern>,
    token_cache: Arc<RwLock<HashMap<String, CachedToken>>>,
    health_cache: Arc<RwLock<Option<CachedRegistryHealth>>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

impl DockerProxy {
    pub fn new(client: HyperClient, registry: &RegistryConfig) -> Self {
        let mut registry_url = registry.default.to_string();
        if !registry_url.starts_with("http://") && !registry_url.starts_with("https://") {
            registry_url = format!("https://{}", registry_url);
        }

        Self {
            client,
            registry_url,
            allowed_hosts: registry.host_patterns(),
            token_cache: Arc::new(RwLock::new(HashMap::new())),
            health_cache: Arc::new(RwLock::new(None)),
        }
    }

    fn cloned_headers(extra_headers: Option<Vec<(&str, &str)>>) -> Option<Vec<(String, String)>> {
        extra_headers.as_ref().map(|headers| {
            headers
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect()
        })
    }

    async fn bearer_token_from_challenge(&self, headers: &hyper::HeaderMap) -> Option<String> {
        let www_auth = headers.get("www-authenticate")?;
        let challenge = www_auth.to_str().ok()?;
        if !challenge.to_ascii_lowercase().starts_with("bearer") {
            tracing::warn!(
                "Registry authentication challenge is not bearer-based: {}",
                challenge
            );
            return None;
        }

        self.request_bearer_token(challenge).await.ok()
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

    fn is_allowed_registry_host(&self, registry_url: &str) -> bool {
        let host = registry_url
            .parse::<hyper::Uri>()
            .ok()
            .and_then(|uri| uri.host().map(|host| host.to_ascii_lowercase()));

        host.map(|host| {
            self.allowed_hosts
                .iter()
                .any(|pattern| pattern.matches(&host))
        })
        .unwrap_or(false)
    }

    pub(crate) fn resolve_registry_and_name(&self, name: &str) -> Result<(String, String), String> {
        let (registry_url, image_name) = self.split_registry_and_name(name);
        if !self.is_allowed_registry_host(&registry_url) {
            let host = registry_url
                .parse::<hyper::Uri>()
                .ok()
                .and_then(|uri| uri.host().map(str::to_string))
                .unwrap_or(registry_url.clone());
            return Err(format!("registry host '{}' is not allowed", host));
        }
        Ok((registry_url, image_name))
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
        let headers = Self::cloned_headers(extra_headers.clone());

        // First attempt
        let (status, resp_headers, body) = get_bytes(&self.client, url, extra_headers, 60).await?;

        // If upstream requires registry authentication, handle Bearer challenge
        if status == hyper::StatusCode::UNAUTHORIZED
            && let Some(token) = self.bearer_token_from_challenge(&resp_headers).await
        {
            let mut auth_headers = headers.unwrap_or_default();
            auth_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));

            return get_bytes(
                &self.client,
                url,
                Some(
                    auth_headers
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect(),
                ),
                60,
            )
            .await;
        }

        Ok((status, resp_headers, body))
    }

    async fn fetch_streaming_with_auth(
        &self,
        method: hyper::Method,
        url: &str,
        extra_headers: Option<Vec<(&str, &str)>>,
    ) -> Result<hyper::Response<hyper::body::Incoming>, HttpError> {
        let headers = Self::cloned_headers(extra_headers);

        // First attempt
        let response =
            request_streaming(&self.client, method.clone(), url, headers.clone(), 60).await?;

        // If upstream requires registry authentication, handle Bearer challenge
        if response.status() == hyper::StatusCode::UNAUTHORIZED
            && let Some(token) = self.bearer_token_from_challenge(response.headers()).await
        {
            // Retry with authorization
            let mut auth_headers = headers.unwrap_or_default();
            auth_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));

            return request_streaming(&self.client, method, url, Some(auth_headers), 60).await;
        }

        Ok(response)
    }

    async fn head_with_auth(
        &self,
        url: &str,
        extra_headers: Option<Vec<(&str, &str)>>,
    ) -> Result<(hyper::StatusCode, hyper::HeaderMap), HttpError> {
        let headers = Self::cloned_headers(extra_headers.clone());
        let (status, resp_headers) = head_request(&self.client, url, extra_headers, 60).await?;

        if status == hyper::StatusCode::UNAUTHORIZED
            && let Some(token) = self.bearer_token_from_challenge(&resp_headers).await
        {
            let mut auth_headers = headers.unwrap_or_default();
            auth_headers.push(("Authorization".to_string(), format!("Bearer {}", token)));

            return head_request(
                &self.client,
                url,
                Some(
                    auth_headers
                        .iter()
                        .map(|(key, value)| (key.as_str(), value.as_str()))
                        .collect(),
                ),
                60,
            )
            .await;
        }

        Ok((status, resp_headers))
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
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
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
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
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
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
        let url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        tracing::info!(registry = %registry_url, image = %image_name, digest = %digest, "Fetching blob");

        self.fetch_streaming_with_auth(hyper::Method::GET, &url, None)
            .await
            .map_err(|e| e.0)
    }

    pub async fn head_blob(&self, name: &str, digest: &str) -> Result<u64, String> {
        let digest = self.normalize_reference_or_digest(digest);
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
        let url = format!("{}/v2/{}/blobs/{}", registry_url, image_name, digest);
        tracing::info!(registry = %registry_url, image = %image_name, digest = %digest, "HEAD blob");

        let (status, headers) = self.head_with_auth(&url, None).await.map_err(|e| e.0)?;

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
        let (registry_url, image_name) = self.resolve_registry_and_name(name)?;
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
        if let Some(cached) = *self.health_cache.read().await
            && cached.expires_at > Instant::now()
        {
            return cached.healthy;
        }

        let url = format!("{}/v2/", self.registry_url);
        let healthy = match head_request(&self.client, &url, None, 5).await {
            Ok((status, _)) => status.is_success() || status == hyper::StatusCode::UNAUTHORIZED,
            Err(e) => {
                tracing::warn!("Registry health check failed: {}", e.0);
                false
            }
        };

        *self.health_cache.write().await = Some(CachedRegistryHealth {
            healthy,
            expires_at: Instant::now() + Duration::from_secs(REGISTRY_HEALTH_CACHE_TTL_SECS),
        });

        healthy
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
    let parts: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
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
        if i + 1 < parts.len() && parts[i + 1] == "uploads" {
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

async fn begin_registry_request(
    state: &AppState,
) -> Result<(RequestLifecycle, RequestPermitGuard), Response> {
    let lifecycle = RequestLifecycle::new(&state.shutdown_manager);
    let permit = match state.download_semaphore.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                "Registry proxy is shutting down",
            )
                .into_response());
        }
    };

    infra::metrics::HTTP_ACTIVE_REQUESTS.inc();
    Ok((
        lifecycle,
        RequestPermitGuard::new(permit, std::time::Instant::now()),
    ))
}

fn registry_cache_host(registry_url: &str) -> String {
    registry_url
        .parse::<hyper::Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_string))
        .unwrap_or_else(|| registry_url.to_string())
}

fn manifest_cache_key(
    proxy: &DockerProxy,
    name: &str,
    reference: &str,
) -> Result<CacheKey, String> {
    let reference = proxy.normalize_reference_or_digest(reference);
    let (registry_url, image_name) = proxy.resolve_registry_and_name(name)?;
    Ok(CacheKey::docker_manifest_for(
        &registry_cache_host(&registry_url),
        &image_name,
        &reference,
    ))
}

fn blob_cache_key(proxy: &DockerProxy, name: &str, digest: &str) -> Result<CacheKey, String> {
    let digest = proxy.normalize_reference_or_digest(digest);
    let (registry_url, image_name) = proxy.resolve_registry_and_name(name)?;
    Ok(CacheKey::docker_blob_for(
        &registry_cache_host(&registry_url),
        &image_name,
        &digest,
    ))
}

fn cache_hit_response(cached: CachedResponse, head_only: bool) -> Response {
    let mut response = cached.to_response();
    if head_only {
        *response.body_mut() = Body::empty();
    }
    response
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
    if !state.settings.debug.endpoints_enabled {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            "Debug endpoints are disabled.\n",
        )
            .into_response();
    }

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
        Some(p) => Arc::clone(p),
        None => return (StatusCode::NOT_IMPLEMENTED, "Docker disabled").into_response(),
    };
    let request_path = format!("/v2/{}/manifests/{}", name, reference);
    let cache_key = match manifest_cache_key(&proxy, &name, &reference) {
        Ok(cache_key) => cache_key,
        Err(error) => {
            return (
                StatusCode::FORBIDDEN,
                format!("Registry Host Not Allowed\n\n{}\n", error),
            )
                .into_response();
        }
    };

    match state.cache_manager.get(&cache_key).await {
        CacheResult::Hit(cached) => return cache_hit_response(*cached, false),
        CacheResult::Miss => {}
    }

    let (mut lifecycle, permit_guard) = match begin_registry_request(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    match proxy.get_manifest(&name, &reference).await {
        Ok((content_type, body)) => {
            let mut headers = HeaderMap::new();
            let ct_value = content_type
                .parse()
                .unwrap_or_else(|_| HeaderValue::from_static("application/json"));
            headers.insert(header::CONTENT_TYPE, ct_value);
            let body_bytes = Bytes::from(body.into_bytes());
            if let Ok(cl_value) = body_bytes.len().to_string().parse() {
                headers.insert(header::CONTENT_LENGTH, cl_value);
            }

            let response_cacheable = state
                .cache_manager
                .should_cache_request(&cache_key, &request_path)
                && is_response_cacheable(
                    StatusCode::OK.as_u16(),
                    &headers,
                    state.cache_manager.config(),
                );
            for (name, value) in state.cache_manager.build_cache_headers(
                &content_type,
                StatusCode::OK,
                response_cacheable,
            ) {
                headers.insert(name, value);
            }
            add_vary_header(&mut headers);

            if let Some(cached) = CachedResponse::from_buffered_parts(
                StatusCode::OK,
                headers.clone(),
                body_bytes.clone(),
                state.cache_manager.config(),
                cache_key.clone(),
                state.cache_manager.metrics(),
            ) {
                headers = cached.headers.clone();
                state.cache_manager.set(cache_key, cached).await;
            }

            infra::metrics::BYTES_TRANSFERRED_TOTAL.inc_by(body_bytes.len() as u64);
            lifecycle.success();
            drop(permit_guard);

            (StatusCode::OK, headers, Body::from(body_bytes)).into_response()
        }
        Err(e) => {
            lifecycle.fail(None);
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
        Some(p) => Arc::clone(p),
        None => return (StatusCode::NOT_IMPLEMENTED, "Docker disabled").into_response(),
    };
    let cache_key = match manifest_cache_key(&proxy, &name, &reference) {
        Ok(cache_key) => cache_key,
        Err(error) => {
            return (
                StatusCode::FORBIDDEN,
                format!("Registry Host Not Allowed\n\n{}\n", error),
            )
                .into_response();
        }
    };
    match state.cache_manager.get(&cache_key).await {
        CacheResult::Hit(cached) => return cache_hit_response(*cached, true),
        CacheResult::Miss => {}
    }

    let (mut lifecycle, permit_guard) = match begin_registry_request(&state).await {
        Ok(context) => context,
        Err(response) => return response,
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
            lifecycle.success();
            drop(permit_guard);
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => {
            lifecycle.fail(None);
            tracing::error!("Error heading manifest: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", e)).into_response()
        }
    }
}

async fn get_blob(
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let proxy = match &state.docker_proxy {
        Some(p) => Arc::clone(p),
        None => return (StatusCode::NOT_IMPLEMENTED, "Docker disabled").into_response(),
    };
    let request_path = format!("/v2/{}/blobs/{}", name, digest);
    let cache_key = match blob_cache_key(&proxy, &name, &digest) {
        Ok(cache_key) => cache_key,
        Err(error) => {
            return (
                StatusCode::FORBIDDEN,
                format!("Registry Host Not Allowed\n\n{}\n", error),
            )
                .into_response();
        }
    };

    match state.cache_manager.get(&cache_key).await {
        CacheResult::Hit(cached) => return cache_hit_response(*cached, false),
        CacheResult::Miss => {}
    }

    let (lifecycle, mut permit_guard) = match begin_registry_request(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    match proxy.get_blob(&name, &digest).await {
        Ok(hyper_resp) => {
            let status = hyper_resp.status();
            let mut response = Response::new(Body::empty());
            *response.status_mut() = status;
            for (name, value) in hyper_resp.headers() {
                if let Ok(name) = header::HeaderName::try_from(name.as_str())
                    && let Ok(value) = HeaderValue::try_from(value.as_bytes())
                {
                    response.headers_mut().insert(name, value);
                }
            }

            let content_length = response
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok());
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("application/octet-stream")
                .to_string();
            let response_cacheable = state
                .cache_manager
                .should_cache_request(&cache_key, &request_path)
                && is_response_cacheable(
                    status.as_u16(),
                    response.headers(),
                    state.cache_manager.config(),
                );
            for (name, value) in
                state
                    .cache_manager
                    .build_cache_headers(&content_type, status, response_cacheable)
            {
                response.headers_mut().insert(name, value);
            }
            add_vary_header(response.headers_mut());

            let should_buffer_for_cache = response_cacheable
                && content_length
                    .map(|len| {
                        let cache_config = state.cache_manager.config();
                        len >= cache_config.min_object_size && len <= cache_config.max_object_size
                    })
                    .unwrap_or(false);

            if should_buffer_for_cache {
                let body_bytes = match BodyExt::collect(http_body_util::Limited::new(
                    Body::from_stream(
                        hyper_resp
                            .into_body()
                            .into_data_stream()
                            .map(|r| r.map_err(std::io::Error::other)),
                    ),
                    (state.cache_manager.config().max_object_size + 1) as usize,
                ))
                .await
                {
                    Ok(collected) => collected.to_bytes(),
                    Err(err) => {
                        tracing::error!("Failed to buffer registry blob for cache: {}", err);
                        return (
                            StatusCode::BAD_GATEWAY,
                            format!("Error: failed to read blob response: {}", err),
                        )
                            .into_response();
                    }
                };

                if let Some(cached) = CachedResponse::from_buffered_parts(
                    status,
                    response.headers().clone(),
                    body_bytes.clone(),
                    state.cache_manager.config(),
                    cache_key,
                    state.cache_manager.metrics(),
                ) {
                    *response.headers_mut() = cached.headers.clone();
                    state.cache_manager.set(cached.key.clone(), cached).await;
                }

                infra::metrics::BYTES_TRANSFERRED_TOTAL.inc_by(body_bytes.len() as u64);
                let mut lifecycle = lifecycle;
                lifecycle.success();
                drop(permit_guard);
                *response.body_mut() = Body::from(body_bytes);
                return response;
            }

            let streaming_body = ProxyBodyStream::new(
                hyper_resp
                    .into_body()
                    .into_data_stream()
                    .map(|r| r.map_err(|e| ProxyError::Http(Box::new(e))))
                    .boxed(),
                lifecycle,
                0,
                0,
                permit_guard.take_start_time(),
                permit_guard.take_permit(),
                false,
            );
            *response.body_mut() = Body::from_stream(streaming_body);
            mark_response_duration_recorded(&mut response);
            response
        }
        Err(e) => {
            // The permit guard drops here, releasing the active request slot.
            tracing::error!("Error getting blob: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", e)).into_response()
        }
    }
}

async fn head_blob(
    State(state): State<AppState>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    let proxy = match &state.docker_proxy {
        Some(p) => Arc::clone(p),
        None => return (StatusCode::NOT_IMPLEMENTED, "Docker disabled").into_response(),
    };
    let cache_key = match blob_cache_key(&proxy, &name, &digest) {
        Ok(cache_key) => cache_key,
        Err(error) => {
            return (
                StatusCode::FORBIDDEN,
                format!("Registry Host Not Allowed\n\n{}\n", error),
            )
                .into_response();
        }
    };
    match state.cache_manager.get(&cache_key).await {
        CacheResult::Hit(cached) => return cache_hit_response(*cached, true),
        CacheResult::Miss => {}
    }

    let (mut lifecycle, permit_guard) = match begin_registry_request(&state).await {
        Ok(context) => context,
        Err(response) => return response,
    };

    match proxy.head_blob(&name, &digest).await {
        Ok(size) => {
            let mut headers = HeaderMap::new();
            if let Ok(cl_value) = size.to_string().parse() {
                headers.insert(header::CONTENT_LENGTH, cl_value);
            }
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            lifecycle.success();
            drop(permit_guard);
            (StatusCode::OK, headers).into_response()
        }
        Err(e) => {
            lifecycle.fail(None);
            tracing::error!("Error heading blob: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Error: {}", e)).into_response()
        }
    }
}

async fn initiate_blob_upload(_state: State<AppState>, Path(_name): Path<String>) -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "Read-only registry proxy: push is not supported",
    )
        .into_response()
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
        V2Endpoint::BlobUploadComplete { .. } => (
            StatusCode::METHOD_NOT_ALLOWED,
            "Read-only registry proxy: push is not supported",
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

pub async fn v2_patch(State(_state): State<AppState>, Path(rest): Path<String>) -> Response {
    match parse_v2_path(&rest) {
        V2Endpoint::BlobUploadInit { .. } | V2Endpoint::BlobUploadComplete { .. } => (
            StatusCode::METHOD_NOT_ALLOWED,
            "Read-only registry proxy: push is not supported",
        )
            .into_response(),
        _ => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PoolConfig, RegistryConfig, ServerConfig};
    use crate::services::client::build_client;

    fn test_proxy(default: &str, allowed_hosts: Vec<&str>) -> DockerProxy {
        let mut registry = RegistryConfig {
            default: default.to_string(),
            allowed_hosts: allowed_hosts.into_iter().map(str::to_string).collect(),
            readiness_depends_on_registry: false,
        };
        registry
            .validate()
            .expect("registry config should validate for tests");

        let client = build_client(&ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            size_limit: 32,
            request_timeout_secs: 5,
            max_concurrent_requests: 8,
            request_size_limit: 4,
            pool: PoolConfig::default(),
        });

        DockerProxy::new(client, &registry)
    }

    #[test]
    fn resolve_registry_and_name_uses_default_registry_for_library_image() {
        let proxy = test_proxy("registry-1.docker.io", vec![]);

        let (registry_url, image_name) = proxy
            .resolve_registry_and_name("nginx")
            .expect("default registry should be allowed");

        assert_eq!(registry_url, "https://registry-1.docker.io");
        assert_eq!(image_name, "library/nginx");
    }

    #[test]
    fn resolve_registry_and_name_allows_explicit_registry_host_from_allowlist() {
        let proxy = test_proxy("registry-1.docker.io", vec!["ghcr.io"]);

        let (registry_url, image_name) = proxy
            .resolve_registry_and_name("ghcr.io/openai/gh-proxy")
            .expect("allowlisted registry should resolve");

        assert_eq!(registry_url, "https://ghcr.io");
        assert_eq!(image_name, "openai/gh-proxy");
    }

    #[test]
    fn resolve_registry_and_name_allows_wildcard_registry_host() {
        let proxy = test_proxy("registry-1.docker.io", vec!["*.example.internal"]);

        let (registry_url, image_name) = proxy
            .resolve_registry_and_name("mirror.team.example.internal/org/image")
            .expect("wildcard registry should resolve");

        assert_eq!(registry_url, "https://mirror.team.example.internal");
        assert_eq!(image_name, "org/image");
    }

    #[test]
    fn resolve_registry_and_name_rejects_disallowed_explicit_registry_host() {
        let proxy = test_proxy("registry-1.docker.io", vec!["ghcr.io"]);

        let error = proxy
            .resolve_registry_and_name("evil.example.com/ns/image")
            .expect_err("non-allowlisted registry should be rejected");

        assert!(error.contains("evil.example.com"));
        assert!(error.contains("not allowed"));
    }

    #[test]
    fn manifest_cache_key_uses_explicit_registry_host_and_normalized_digest() {
        let proxy = test_proxy("registry-1.docker.io", vec!["ghcr.io"]);
        let raw_digest = "sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let key = manifest_cache_key(&proxy, "ghcr.io/openai/gh-proxy", raw_digest)
            .expect("cache key should be created");

        assert_eq!(
            key,
            CacheKey::docker_manifest_for(
                "ghcr.io",
                "openai/gh-proxy",
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
        );
    }
}
