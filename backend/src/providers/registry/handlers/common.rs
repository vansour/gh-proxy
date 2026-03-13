use crate::cache::key::CacheKey;
use crate::cache::response_cache::CachedResponse;
use crate::infra;
use crate::middleware::{RequestLifecycle, RequestPermitGuard};
use crate::providers::registry::DockerProxy;
use crate::state::AppState;
use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub(super) async fn begin_registry_request(
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

pub(super) fn manifest_cache_key(
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

pub(super) fn blob_cache_key(
    proxy: &DockerProxy,
    name: &str,
    digest: &str,
) -> Result<CacheKey, String> {
    let digest = proxy.normalize_reference_or_digest(digest);
    let (registry_url, image_name) = proxy.resolve_registry_and_name(name)?;
    Ok(CacheKey::docker_blob_for(
        &registry_cache_host(&registry_url),
        &image_name,
        &digest,
    ))
}

pub(super) fn cache_hit_response(cached: CachedResponse, head_only: bool) -> Response {
    let mut response = cached.to_response();
    if head_only {
        *response.body_mut() = Body::empty();
    }
    response
}

pub(super) fn registry_host_not_allowed_response(error: String) -> Response {
    (
        StatusCode::FORBIDDEN,
        format!("Registry Host Not Allowed\n\n{}\n", error),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::manifest_cache_key;
    use crate::cache::key::CacheKey;
    use crate::config::{PoolConfig, RegistryConfig, ServerConfig};
    use crate::providers::registry::DockerProxy;
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
