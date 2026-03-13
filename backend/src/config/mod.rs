mod auth;
mod debug;
mod error;
mod host_pattern;
mod ingress;
mod log;
mod proxy;
mod rate_limit;
mod registry;
mod server;
mod settings;
mod shell;

pub use auth::AuthConfig;
pub use debug::DebugConfig;
pub use error::ConfigError;
pub use host_pattern::HostPattern;
pub use ingress::IngressConfig;
pub use log::LogConfig;
pub use proxy::{GitHubConfig, ProxyConfig};
pub use rate_limit::RateLimitConfig;
pub use registry::RegistryConfig;
pub use server::{PoolConfig, ServerConfig};
pub use settings::{Settings, default_config_path};
pub use shell::ShellConfig;

#[cfg(test)]
mod tests;
