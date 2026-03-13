use super::host_pattern::normalize_host_pattern_list;
use super::{ConfigError, HostPattern};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    #[serde(alias = "allowedHosts")]
    pub allowed_hosts: Vec<String>,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            allowed_hosts: vec![
                "github.com".to_string(),
                "*.github.com".to_string(),
                "githubusercontent.com".to_string(),
                "*.githubusercontent.com".to_string(),
            ],
        }
    }
}

impl ProxyConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        self.allowed_hosts =
            normalize_host_pattern_list(&self.allowed_hosts, "proxy.allowed_hosts")?;
        Ok(())
    }

    pub(crate) fn host_patterns(&self) -> Vec<HostPattern> {
        self.allowed_hosts
            .iter()
            .map(|pattern| HostPattern::parse(pattern).expect("validated pattern became invalid"))
            .collect()
    }
}

pub struct GitHubConfig {
    pub default_host: String,
    allowed_hosts: Vec<HostPattern>,
}

impl GitHubConfig {
    pub fn new(_auth_token: &str, proxy: &ProxyConfig) -> Self {
        Self {
            default_host: "github.com".to_string(),
            allowed_hosts: proxy.host_patterns(),
        }
    }

    pub fn is_allowed(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        self.allowed_hosts
            .iter()
            .any(|pattern| pattern.matches(&host))
    }
}
