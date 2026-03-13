use super::*;

#[test]
fn server_validate_rejects_zero_runtime_limits() {
    let config = ServerConfig {
        size_limit: 64,
        request_timeout_secs: 0,
        max_concurrent_requests: 16,
        request_size_limit: 8,
        ..ServerConfig::default()
    };

    let error = config.validate().expect_err("zero timeout should fail");
    assert!(error.to_string().contains("server.request_timeout_secs"));
}

#[test]
fn registry_validate_rejects_empty_default() {
    let mut config = RegistryConfig {
        default: "   ".to_string(),
        ..RegistryConfig::default()
    };

    let error = config
        .validate()
        .expect_err("empty registry default should fail");
    assert!(error.to_string().contains("registry.default"));
}

#[test]
fn registry_validate_adds_default_host_to_allowed_hosts() {
    let mut config = RegistryConfig {
        default: "https://ghcr.io".to_string(),
        allowed_hosts: vec![],
        readiness_depends_on_registry: false,
    };

    config.validate().expect("registry config should validate");

    assert!(config.allowed_hosts.iter().any(|host| host == "ghcr.io"));
}

#[test]
fn proxy_validate_normalizes_and_deduplicates_allowed_hosts() {
    let mut config = ProxyConfig {
        allowed_hosts: vec![
            " HTTPS://GitHub.COM/owner/repo ".to_string(),
            "github.com".to_string(),
            ".GitHubUserContent.com".to_string(),
            "*.githubusercontent.com".to_string(),
            "   ".to_string(),
        ],
    };

    config.validate().expect("proxy config should validate");

    assert_eq!(
        config.allowed_hosts,
        vec![
            "github.com".to_string(),
            "*.githubusercontent.com".to_string()
        ]
    );
}

#[test]
fn registry_validate_normalizes_default_origin_and_deduplicates_allowed_hosts() {
    let mut config = RegistryConfig {
        default: " HTTPS://GHCR.IO/v2/ ".to_string(),
        allowed_hosts: vec![
            "ghcr.io".to_string(),
            "https://ghcr.io/token".to_string(),
            ".Example.com".to_string(),
            "*.example.com".to_string(),
        ],
        readiness_depends_on_registry: false,
    };

    config.validate().expect("registry config should validate");

    assert_eq!(config.default, "https://ghcr.io".to_string());
    assert_eq!(
        config.allowed_hosts,
        vec!["ghcr.io".to_string(), "*.example.com".to_string()]
    );
}

#[test]
fn registry_validate_rejects_wildcard_default() {
    let mut config = RegistryConfig {
        default: "*.example.com".to_string(),
        ..RegistryConfig::default()
    };

    let error = config.validate().expect_err("wildcard default should fail");
    assert!(error.to_string().contains("registry.default"));
    assert!(error.to_string().contains("wildcards"));
}

#[test]
fn settings_support_legacy_aliases() {
    let mut settings: Settings = toml::from_str(
        r#"
[server]
sizeLimit = 64
requestTimeoutSecs = 12
maxConcurrentRequests = 20
requestSizeLimit = 8

[server.pool]
idleTimeoutSecs = 30
maxIdlePerHost = 16
http2StreamWindowSize = 1048576
http2ConnectionWindowSize = 4194304

[registry]
defaultRegistry = "registry-1.docker.io"
allowedHosts = ["ghcr.io"]
readinessDependsOnRegistry = true

[ingress]
authHeaderName = "x-origin-auth"
authHeaderValue = "secret"

[debug]
endpointsEnabled = true
metricsEnabled = true

[rate_limit]
windowSecs = 30
maxRequests = 50
"#,
    )
    .expect("legacy aliases should deserialize");

    settings.validate().expect("settings should validate");
    assert_eq!(settings.server.size_limit, 64);
    assert_eq!(settings.server.request_timeout_secs, 12);
    assert_eq!(settings.server.max_concurrent_requests, 20);
    assert_eq!(settings.server.request_size_limit, 8);
    assert_eq!(settings.server.pool.idle_timeout_secs, 30);
    assert_eq!(settings.server.pool.max_idle_per_host, 16);
    assert_eq!(settings.server.pool.http2_stream_window_size, 1_048_576);
    assert_eq!(settings.server.pool.http2_connection_window_size, 4_194_304);
    assert_eq!(settings.registry.default, "registry-1.docker.io");
    assert_eq!(
        settings.registry.allowed_hosts,
        vec!["ghcr.io".to_string(), "registry-1.docker.io".to_string()]
    );
    assert!(settings.registry.readiness_depends_on_registry);
    assert_eq!(settings.ingress.auth_header_name, "x-origin-auth");
    assert_eq!(settings.ingress.auth_header_value, "secret");
    assert!(settings.debug.endpoints_enabled);
    assert!(settings.debug.metrics_enabled);
    assert_eq!(settings.rate_limit.window_secs, 30);
    assert_eq!(settings.rate_limit.max_requests, 50);
}

#[test]
fn ingress_validate_rejects_invalid_header_name() {
    let mut ingress = IngressConfig {
        auth_header_name: "bad header".to_string(),
        auth_header_value: "secret".to_string(),
    };

    let error = ingress
        .validate()
        .expect_err("invalid ingress header name should fail");
    assert!(error.to_string().contains("ingress.auth_header_name"));
}
