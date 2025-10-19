use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, Response, StatusCode, Uri},
};
use http_body_util::BodyExt;
use hyper::header;
use hyper::http::uri::{Authority, PathAndQuery};
use tokio::sync::RwLock;
use tracing::{error, info, instrument, warn};

use crate::config::DockerConfig;
use crate::{AppState, ProxyError, ProxyKind, ProxyResult};

/// Token cache entry with expiration time
#[derive(Clone, Debug)]
struct TokenCacheEntry {
    token: String,
    /// Token expiration time in seconds since UNIX_EPOCH
    expires_at: u64,
}

impl TokenCacheEntry {
    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() >= self.expires_at)
            .unwrap_or(true)
    }

    fn from_json(token_json: &serde_json::Value) -> Option<Self> {
        let token = token_json.get("token")?.as_str()?.to_string();
        let expires_in = token_json
            .get("expires_in")
            .and_then(|v| v.as_u64())
            .unwrap_or(3600); // Default 1 hour if not specified

        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() + expires_in)
            .unwrap_or(0);

        Some(TokenCacheEntry { token, expires_at })
    }
}

/// Docker registry token cache
pub struct RegistryTokenCache {
    /// Cache key format: "registry:repo"
    tokens: Arc<RwLock<std::collections::HashMap<String, TokenCacheEntry>>>,
}

impl RegistryTokenCache {
    pub fn new() -> Self {
        Self {
            tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Get cached token if it exists and is not expired
    async fn get(&self, cache_key: &str) -> Option<String> {
        let tokens = self.tokens.read().await;
        if let Some(entry) = tokens.get(cache_key) {
            if !entry.is_expired() {
                info!("Token cache hit for: {}", cache_key);
                return Some(entry.token.clone());
            }
        }
        None
    }

    /// Store token in cache
    async fn set(&self, cache_key: String, entry: TokenCacheEntry) {
        let mut tokens = self.tokens.write().await;
        tokens.insert(cache_key, entry);
    }
}

impl Default for RegistryTokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for RegistryTokenCache {
    fn clone(&self) -> Self {
        Self {
            tokens: Arc::clone(&self.tokens),
        }
    }
}

/// Docker v2 root handler for /v2 endpoint
#[instrument(skip_all)]
pub async fn docker_v2_root(
    State(state): State<AppState>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    info!("Docker v2 root request: {}", req.method());

    if !state.settings.docker.enabled {
        warn!("Docker proxy is disabled in configuration");
        return Err(StatusCode::FORBIDDEN);
    }

    // Check authentication if required
    if state.settings.docker.auth {
        if !verify_docker_auth(req.headers(), &state.settings.docker) {
            warn!("Docker authentication failed for v2 root");
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Forward to registry-1.docker.io/v2/
    let target_uri = Uri::from_static("https://registry-1.docker.io/v2/");
    info!("Proxying v2 root to: {}", target_uri);

    match crate::proxy_request(&state, req, target_uri.clone(), ProxyKind::Docker).await {
        Ok(response) => {
            // Handle 401 Unauthorized response
            if response.status() == StatusCode::UNAUTHORIZED {
                info!("Received 401 from registry, attempting to get token for root v2 endpoint");

                // Try to get generic token
                if let Some(token) =
                    get_generic_registry_token(&state, "registry-1.docker.io").await
                {
                    info!("Successfully obtained token, retrying request");

                    // Rebuild request with token
                    let mut retry_req = Request::builder()
                        .method("GET")
                        .uri(target_uri.clone())
                        .body(Body::empty())
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    retry_req.headers_mut().insert(
                        header::AUTHORIZATION,
                        format!("Bearer {}", token).parse().unwrap(),
                    );

                    match crate::proxy_request(&state, retry_req, target_uri, ProxyKind::Docker)
                        .await
                    {
                        Ok(retry_response) => {
                            info!(
                                "Docker v2 root retry success: status={}",
                                retry_response.status()
                            );
                            return Ok(retry_response);
                        }
                        Err(err) => {
                            error!("Docker v2 root retry failure: {}", err);
                        }
                    }
                } else {
                    warn!("Failed to obtain token for root endpoint");
                }
            }

            info!("Docker v2 root response: status={}", response.status());
            Ok(response)
        }
        Err(err) => {
            error!("Docker v2 root failure: {}", err);
            Err(StatusCode::BAD_GATEWAY)
        }
    }
}

/// Docker v2 proxy handler for /v2/* routes
#[instrument(skip_all, fields(path = %path))]
pub async fn docker_v2_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    mut req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    info!("Docker v2 proxy request: {} /v2/{}", req.method(), path);

    if !state.settings.docker.enabled {
        warn!("Docker proxy is disabled in configuration");
        return Err(StatusCode::FORBIDDEN);
    }

    // Check authentication if required (for proxy auth, not Docker Hub auth)
    if state.settings.docker.auth {
        if !verify_docker_auth(req.headers(), &state.settings.docker) {
            warn!("Docker authentication failed for v2 path: {}", path);
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    // Detect if the path starts with a registry domain (e.g., ghcr.io, gcr.io, etc.)
    let known_registries = [
        ("ghcr.io", "ghcr.io"),
        ("gcr.io", "gcr.io"),
        ("registry.k8s.io", "registry.k8s.io"),
        ("k8s.gcr.io", "k8s.gcr.io"),
        ("nvcr.io", "nvcr.io"),
        ("quay.io", "quay.io"),
        ("mcr.microsoft.com", "mcr.microsoft.com"),
        ("docker.elastic.co", "docker.elastic.co"),
    ];

    let (target_registry, normalized_path) = if let Some((prefix, registry)) = known_registries
        .iter()
        .find(|(prefix, _)| path.starts_with(&format!("{}/", prefix)))
    {
        // Extract the path after the registry prefix
        let remaining_path = path.strip_prefix(&format!("{}/", prefix)).unwrap();
        info!(
            "Detected registry: {} for path: {}",
            registry, remaining_path
        );
        (registry.to_string(), remaining_path.to_string())
    } else {
        // Default to Docker Hub, normalize the path
        let normalized = normalize_docker_path(&path);
        ("registry-1.docker.io".to_string(), normalized)
    };

    info!(
        "Target registry: {}, normalized path: /v2/{}",
        target_registry, normalized_path
    );

    // Get anonymous token for registries that require authentication
    if let Some(token) = get_registry_token(&state, &target_registry, &normalized_path).await {
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", token).parse().unwrap(),
        );
    }

    // Build the target URI with the detected registry
    let target_path = format!("/v2/{}", normalized_path);
    let target_uri = Uri::builder()
        .scheme("https")
        .authority(target_registry.as_str())
        .path_and_query(target_path.as_str())
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let target_uri_str = target_uri.to_string();
    info!("Proxying to registry: {}", target_uri_str);

    match crate::proxy_request(&state, req, target_uri.clone(), ProxyKind::Docker).await {
        Ok(response) => {
            // Handle 401 Unauthorized response with retry
            if response.status() == StatusCode::UNAUTHORIZED {
                info!("Received 401 from registry, attempting to get token");

                if let Some(token) =
                    get_registry_token(&state, &target_registry, &normalized_path).await
                {
                    info!("Successfully obtained token, retrying request");

                    // Rebuild request with token
                    let mut retry_req = Request::builder()
                        .method("GET")
                        .uri(target_uri.clone())
                        .body(Body::empty())
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

                    retry_req.headers_mut().insert(
                        header::AUTHORIZATION,
                        format!("Bearer {}", token).parse().unwrap(),
                    );

                    match crate::proxy_request(&state, retry_req, target_uri, ProxyKind::Docker)
                        .await
                    {
                        Ok(retry_response) => {
                            info!(
                                "Docker v2 proxy retry success: status={}",
                                retry_response.status()
                            );
                            return Ok(retry_response);
                        }
                        Err(err) => {
                            error!("Docker v2 proxy retry failure: {}", err);
                        }
                    }
                } else {
                    warn!("Failed to obtain token for retry");
                }
            }

            info!("Docker v2 proxy response: status={}", response.status());
            Ok(response)
        }
        Err(err) => {
            error!("Docker v2 proxy failure: {}", err);
            let error_msg = format!(
                "Docker Registry Proxy Error\n\nFailed to fetch resource from {}.\n\nTarget: {}\nError: {}\n\nPlease check:\n- The image exists on the registry\n- The image name is correct\n- The registry is accessible\n",
                target_registry, target_uri_str, err
            );
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(error_msg))
                .unwrap())
        }
    }
}

/// Docker proxy handler for /docker/* routes
#[instrument(skip_all, fields(path = %path))]
pub async fn docker_proxy(
    State(state): State<AppState>,
    Path(path): Path<String>,
    req: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    info!("Docker proxy request: {} {}", req.method(), path);

    if !state.settings.docker.enabled {
        warn!("Docker proxy is disabled");
        return Err(StatusCode::FORBIDDEN);
    }

    if state.settings.docker.auth && !verify_docker_auth(req.headers(), &state.settings.docker) {
        warn!("Docker authentication failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    match resolve_docker_target(&state, &path) {
        Ok(target_uri) => {
            info!("Resolved Docker target: {}", target_uri);
            match crate::proxy_request(&state, req, target_uri, ProxyKind::Docker).await {
                Ok(response) => {
                    info!("Docker proxy success: status={}", response.status());
                    Ok(response)
                }
                Err(err) => {
                    error!("Docker proxy failure: {}", err);
                    Err(StatusCode::BAD_GATEWAY)
                }
            }
        }
        Err(err) => {
            error!("Docker target resolution error: {}", err);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

/// Normalize Docker path: add "library/" prefix for single-component image names
fn normalize_docker_path(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() >= 2 && !parts[0].contains('.') && parts[0] != "library" {
        // Check if this looks like a single-name image (e.g., "nginx/manifests/latest")
        // and the first part is not a domain and not already "library"
        if parts[1] == "manifests" || parts[1] == "blobs" {
            // This is a single-component image name, add "library/" prefix
            format!("library/{}", path)
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    }
}

/// Get a generic token for a registry (when repo is not known)
/// Used for root v2 endpoint checks
async fn get_generic_registry_token(state: &AppState, registry: &str) -> Option<String> {
    // Use a generic public image for token retrieval
    get_registry_token(state, registry, "library/alpine/manifests/latest").await
}

/// Get anonymous token for registry authentication with caching and timeout resilience
async fn get_registry_token(state: &AppState, registry: &str, path: &str) -> Option<String> {
    // Parse the image name from path to get the scope
    let repo = if path.contains("manifests") || path.contains("blobs") {
        // Extract repository name from path like "library/nginx/manifests/latest" or "sky22333/hubproxy/manifests/latest"
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() >= 2 {
            Some(format!("{}/{}", parts[0], parts[1]))
        } else {
            None
        }
    } else {
        None
    };

    let repo = repo?;

    let (auth_url, service_name, timeout_duration) = match registry {
        "registry-1.docker.io" => (
            format!(
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{}:pull",
                repo
            ),
            "Docker Hub",
            Duration::from_secs(5), // Shorter timeout for timeout-prone services
        ),
        "ghcr.io" => (
            format!("https://ghcr.io/token?scope=repository:{}:pull", repo),
            "GitHub Container Registry",
            Duration::from_secs(10),
        ),
        "gcr.io" => {
            // GCR (Google Container Registry) - 公共镜像通常不需要认证
            // 私有镜像需要 gcloud 认证,这里跳过
            return None;
        }
        "registry.k8s.io" => {
            // Kubernetes Registry - 公共镜像,尝试无认证访问
            return None;
        }
        "k8s.gcr.io" => {
            // 旧的 Kubernetes Registry - 公共镜像,尝试无认证访问
            return None;
        }
        "quay.io" => (
            format!(
                "https://quay.io/v2/auth?service=quay.io&scope=repository:{}:pull",
                repo
            ),
            "Quay.io",
            Duration::from_secs(10),
        ),
        "nvcr.io" => {
            // NVIDIA Container Registry
            // 公共镜像可以通过特殊令牌访问
            (
                format!(
                    "https://authn.nvidia.com/token?service=nvcr.io&scope=repository:{}:pull",
                    repo
                ),
                "NVIDIA Container Registry",
                Duration::from_secs(10),
            )
        }
        "mcr.microsoft.com" => {
            // Microsoft Container Registry - 公共镜像,通常不需要认证
            return None;
        }
        "docker.elastic.co" => {
            // Elastic Container Registry - 公共镜像,通常不需要认证
            return None;
        }
        _ => return None,
    };

    let cache_key = format!("{}:{}", registry, repo);

    // Try to get from cache first
    if let Some(cached_token) = state.docker_token_cache.get(&cache_key).await {
        return Some(cached_token);
    }

    info!(
        "Requesting {} anonymous token for repository: {}",
        service_name, repo
    );

    let token_uri = auth_url.parse::<Uri>().ok()?;
    let token_req = Request::builder()
        .method("GET")
        .uri(token_uri)
        .body(Body::empty())
        .ok()?;

    // Use timeout to prevent hanging on network-unreachable services
    match tokio::time::timeout(timeout_duration, state.client.request(token_req)).await {
        Ok(Ok(token_resp)) => {
            if token_resp.status().is_success() {
                match token_resp.into_body().collect().await {
                    Ok(collected_body) => {
                        let body_bytes = collected_body.to_bytes();
                        if let Ok(token_json) =
                            serde_json::from_slice::<serde_json::Value>(&body_bytes)
                        {
                            if let Some(entry) = TokenCacheEntry::from_json(&token_json) {
                                let token = entry.token.clone();
                                // Store in cache
                                state.docker_token_cache.set(cache_key, entry).await;
                                info!(
                                    "Successfully obtained {} anonymous token (cached)",
                                    service_name
                                );
                                return Some(token);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read {} token response body: {}", service_name, e);
                    }
                }
            } else {
                warn!(
                    "{} token request failed with status: {}",
                    service_name,
                    token_resp.status()
                );
            }
        }
        Ok(Err(e)) => {
            warn!("Failed to get {} token: {}", service_name, e);
        }
        Err(_) => {
            warn!(
                "{} token request timed out after {:?} (network unreachable or too slow)",
                service_name, timeout_duration
            );
        }
    }

    // Fallback: For public images, allow unauthenticated access when token service is unreachable
    if registry == "registry-1.docker.io" {
        info!(
            "Token request failed for Docker Hub, attempting unauthenticated access for public image: {}",
            repo
        );
        // Return None to attempt unauthenticated access
        // The registry will return 401 if authentication is actually required
        return None;
    }

    None
}

/// Resolve Docker target URI from path
pub fn resolve_docker_target(state: &AppState, path: &str) -> ProxyResult<Uri> {
    let path = path.trim_start_matches('/');

    if path.is_empty() {
        return Err(ProxyError::InvalidTarget(
            "Path cannot be empty".to_string(),
        ));
    }

    // Parse registry/image/tag
    let parts: Vec<&str> = path.splitn(2, '/').collect();
    if parts.is_empty() {
        return Err(ProxyError::InvalidTarget("Invalid Docker path".to_string()));
    }

    let registry_host = parts[0];

    // Check if this registry is allowed
    if !state.settings.docker.is_allowed_registry(registry_host) {
        return Err(ProxyError::UnsupportedHost(format!(
            "Registry {} is not in allowed list",
            registry_host
        )));
    }

    let remaining_path = if parts.len() > 1 {
        parts[1]
    } else {
        return Err(ProxyError::InvalidTarget(
            "Image path is required after registry".to_string(),
        ));
    };

    // Build target URL: https://registry/v2/image/path
    let target_path = format!("/v2/{}", remaining_path);
    let authority = Authority::try_from(registry_host)
        .map_err(|e| ProxyError::InvalidTarget(format!("Invalid registry: {}", e)))?;
    let path_and_query = PathAndQuery::from_str(&target_path)
        .map_err(|e| ProxyError::InvalidTarget(format!("Invalid path: {}", e)))?;

    Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path_and_query)
        .build()
        .map_err(|e| ProxyError::InvalidTarget(format!("Failed to build URI: {}", e)))
}

/// Verify Docker authentication
pub fn verify_docker_auth(headers: &HeaderMap, docker_config: &DockerConfig) -> bool {
    if !docker_config.auth {
        return true;
    }

    if let Some(auth_header) = headers.get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(credentials) = auth_str.strip_prefix("Basic ") {
                use base64::Engine;
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(credentials) {
                    if let Ok(creds_str) = String::from_utf8(decoded) {
                        if let Some((username, password)) = creds_str.split_once(':') {
                            return docker_config.verify_auth(username, password);
                        }
                    }
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_docker_path() {
        assert_eq!(
            normalize_docker_path("nginx/manifests/latest"),
            "library/nginx/manifests/latest"
        );
        assert_eq!(
            normalize_docker_path("library/nginx/manifests/latest"),
            "library/nginx/manifests/latest"
        );
        assert_eq!(
            normalize_docker_path("myuser/myimage/manifests/latest"),
            "myuser/myimage/manifests/latest"
        );
        assert_eq!(
            normalize_docker_path("ghcr.io/user/image/manifests/latest"),
            "ghcr.io/user/image/manifests/latest"
        );
    }
}
