use super::DockerProxy;

impl DockerProxy {
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

    pub(crate) fn normalize_reference_or_digest(&self, value: &str) -> String {
        if value.starts_with("sha256-") && value.len() > 64 {
            return value.replacen("sha256-", "sha256:", 1);
        }
        value.to_string()
    }

    pub fn get_registry_url(&self) -> &str {
        &self.registry_url
    }
}

#[cfg(test)]
mod tests {
    use super::DockerProxy;
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
}
