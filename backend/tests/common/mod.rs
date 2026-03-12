//! Common test utilities

use axum::Router;
use axum::body::Body;
use gh_proxy::cache::config::{CacheConfig, CacheStrategy};
use gh_proxy::cache::manager::CacheManager;
use gh_proxy::config::{
    AuthConfig, DebugConfig, GitHubConfig, IngressConfig, LogConfig, ProxyConfig, RateLimitConfig,
    RegistryConfig, ServerConfig, Settings, ShellConfig,
};
use gh_proxy::middleware::RateLimiter;
use gh_proxy::providers::registry::DockerProxy;
use gh_proxy::services::client::{build_client, get_bytes};
use gh_proxy::services::shutdown::{ShutdownManager, UptimeTracker};
use gh_proxy::{AppState, router};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

pub fn setup() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
}

pub struct TestServer {
    pub base_url: String,
    handle: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub fn test_settings() -> Settings {
    Settings {
        server: ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 0,
            size_limit: 32,
            request_timeout_secs: 5,
            max_concurrent_requests: 16,
            request_size_limit: 4,
            pool: Default::default(),
        },
        shell: ShellConfig {
            editor: false,
            public_base_url: String::new(),
        },
        ingress: IngressConfig::default(),
        debug: DebugConfig {
            endpoints_enabled: false,
            metrics_enabled: false,
        },
        log: LogConfig {
            level: "error".to_string(),
        },
        auth: AuthConfig {
            token: String::new(),
        },
        registry: RegistryConfig::default(),
        proxy: ProxyConfig {
            allowed_hosts: vec!["127.0.0.1".to_string(), "localhost".to_string()],
        },
        cache: CacheConfig {
            strategy: CacheStrategy::MemoryOnly,
            ..CacheConfig::default()
        },
        rate_limit: RateLimitConfig {
            window_secs: 60,
            max_requests: 100,
        },
    }
}

pub fn build_state(mut settings: Settings) -> AppState {
    settings.validate().expect("test settings should validate");

    let client = build_client(&settings.server);
    let github_config = GitHubConfig::new(&settings.auth.token, &settings.proxy);
    let auth_header = settings
        .auth
        .authorization_header()
        .expect("test auth header should be valid");
    let settings = Arc::new(settings);

    AppState {
        settings: Arc::clone(&settings),
        github_config: Arc::new(github_config),
        client: client.clone(),
        shutdown_manager: ShutdownManager::new(),
        uptime_tracker: Arc::new(UptimeTracker::new()),
        auth_header,
        docker_proxy: Some(Arc::new(DockerProxy::new(client, &settings.registry))),
        download_semaphore: Arc::new(Semaphore::new(
            settings.server.max_concurrent_requests as usize,
        )),
        rate_limiter: Arc::new(RateLimiter::new(
            settings.rate_limit.max_requests,
            settings.rate_limit.window_secs,
        )),
        cache_manager: Arc::new(CacheManager::new(settings.cache.clone())),
    }
}

pub async fn spawn_app(state: AppState) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test app");
    let addr = listener.local_addr().expect("test app addr");
    let app = router::create_router(state.clone());
    state.shutdown_manager.mark_ready().await;

    let handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("test app serve");
    });

    TestServer {
        base_url: format!("http://{}", addr),
        handle,
    }
}

pub async fn spawn_mock(router: Router) -> TestServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock app");
    let addr = listener.local_addr().expect("mock addr");

    let handle = tokio::spawn(async move {
        axum::serve(listener, router.into_make_service())
            .await
            .expect("mock serve");
    });

    TestServer {
        base_url: format!("http://{}", addr),
        handle,
    }
}

pub async fn get(url: &str) -> (hyper::StatusCode, hyper::HeaderMap, bytes::Bytes) {
    let client = build_client(&ServerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        size_limit: 32,
        request_timeout_secs: 5,
        max_concurrent_requests: 8,
        request_size_limit: 4,
        pool: Default::default(),
    });

    get_bytes(&client, url, None, 5).await.expect("GET request")
}

pub async fn request(
    method: hyper::Method,
    url: &str,
) -> (hyper::StatusCode, hyper::HeaderMap, bytes::Bytes) {
    request_with_headers(method, url, &[]).await
}

pub async fn request_with_headers(
    method: hyper::Method,
    url: &str,
    headers: &[(&str, &str)],
) -> (hyper::StatusCode, hyper::HeaderMap, bytes::Bytes) {
    let client = build_client(&ServerConfig {
        host: "127.0.0.1".to_string(),
        port: 0,
        size_limit: 32,
        request_timeout_secs: 5,
        max_concurrent_requests: 8,
        request_size_limit: 4,
        pool: Default::default(),
    });

    let uri: hyper::Uri = url.parse().expect("request URI");
    let mut builder = hyper::Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Body::empty()).expect("request build");

    let response = client.request(request).await.expect("request send");
    let status = response.status();
    let headers = response.headers().clone();
    let body = http_body_util::BodyExt::collect(response.into_body())
        .await
        .expect("read response body")
        .to_bytes();

    (status, headers, body)
}
