use super::host_pattern::normalize_host_pattern_list;
use super::{ConfigError, HostPattern};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RegistryConfig {
    #[serde(alias = "defaultRegistry")]
    pub default: String,
    #[serde(alias = "allowedHosts")]
    pub allowed_hosts: Vec<String>,
    #[serde(alias = "readinessDependsOnRegistry")]
    pub readiness_depends_on_registry: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            default: "registry-1.docker.io".to_string(),
            allowed_hosts: vec!["registry-1.docker.io".to_string()],
            readiness_depends_on_registry: false,
        }
    }
}

impl RegistryConfig {
    pub fn validate(&mut self) -> Result<(), ConfigError> {
        if self.default.trim().is_empty() {
            return Err(ConfigError::Validation(
                "registry.default must not be empty".to_string(),
            ));
        }

        self.default = normalize_registry_default(&self.default).map_err(|err| {
            ConfigError::Validation(format!("registry.default is invalid: {}", err))
        })?;

        let default_host_pattern = HostPattern::parse(&self.default).map_err(|err| {
            ConfigError::Validation(format!("registry.default is invalid: {}", err))
        })?;
        let default_host = default_host_pattern.value().to_string();

        let mut normalized =
            normalize_host_pattern_list(&self.allowed_hosts, "registry.allowed_hosts")?;
        if !normalized.iter().any(|entry| entry == &default_host) {
            normalized.push(default_host);
        }
        self.allowed_hosts = normalized;

        Ok(())
    }

    pub(crate) fn host_patterns(&self) -> Vec<HostPattern> {
        self.allowed_hosts
            .iter()
            .map(|pattern| HostPattern::parse(pattern).expect("validated pattern became invalid"))
            .collect()
    }
}

fn normalize_registry_default(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("value cannot be empty".to_string());
    }

    let host_pattern = HostPattern::parse(value)?;
    if !host_pattern.is_exact() {
        return Err("wildcards are not allowed".to_string());
    }

    let has_scheme = value.contains("://");
    let parse_target = if has_scheme {
        value.to_string()
    } else {
        format!("https://{}", value)
    };

    let uri: http::Uri = parse_target
        .parse()
        .map_err(|err| format!("must be a host or absolute http(s) URL: {}", err))?;
    let host = uri
        .host()
        .ok_or_else(|| "host is required".to_string())?
        .to_ascii_lowercase();
    let authority = format_host_authority(&host, uri.port_u16());

    if has_scheme {
        let scheme = uri
            .scheme_str()
            .ok_or_else(|| "scheme is required".to_string())?;
        if !matches!(scheme, "http" | "https") {
            return Err("scheme must be http or https".to_string());
        }
        Ok(format!("{}://{}", scheme.to_ascii_lowercase(), authority))
    } else {
        Ok(authority)
    }
}

fn format_host_authority(host: &str, port: Option<u16>) -> String {
    let host = if host.contains(':') {
        format!("[{}]", host)
    } else {
        host.to_string()
    };

    match port {
        Some(port) => format!("{}:{}", host, port),
        None => host,
    }
}
