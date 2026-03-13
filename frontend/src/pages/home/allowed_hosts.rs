const DEFAULT_ALLOWED_HOSTS: [&str; 4] = [
    "github.com",
    "*.github.com",
    "githubusercontent.com",
    "*.githubusercontent.com",
];

pub(super) fn default_allowed_hosts() -> Vec<String> {
    DEFAULT_ALLOWED_HOSTS
        .iter()
        .map(|host| (*host).to_string())
        .collect()
}

pub(super) fn is_allowed_host(host: &str, allowed_hosts: &[String]) -> bool {
    let host = host.trim().trim_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }

    allowed_hosts
        .iter()
        .filter_map(|pattern| parse_allowed_host_pattern(pattern))
        .any(|pattern| pattern.matches(&host))
}

pub(super) fn looks_like_allowed_host_prefix(input: &str, allowed_hosts: &[String]) -> bool {
    let trimmed = input.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return false;
    }

    let candidate = trimmed.split(['/', '?', '#']).next().unwrap_or_default();
    let host = if candidate.starts_with('[') {
        candidate
            .strip_prefix('[')
            .and_then(|value| value.split_once(']'))
            .map(|(value, _)| value)
            .unwrap_or(candidate)
    } else {
        candidate
            .split_once(':')
            .map(|(value, _)| value)
            .unwrap_or(candidate)
    };

    is_allowed_host(host, allowed_hosts)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum AllowedHostKind {
    Exact,
    Suffix,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AllowedHostPattern {
    pub(super) value: String,
    pub(super) kind: AllowedHostKind,
    pub(super) suffix: Option<String>,
}

impl AllowedHostPattern {
    fn matches(&self, host: &str) -> bool {
        match self.kind {
            AllowedHostKind::Exact => host == self.value,
            AllowedHostKind::Suffix => {
                host == self.value
                    || self
                        .suffix
                        .as_ref()
                        .map(|suffix| host.ends_with(suffix))
                        .unwrap_or(false)
            }
        }
    }
}

pub(super) fn parse_allowed_host_pattern(raw: &str) -> Option<AllowedHostPattern> {
    let mut pattern = raw.trim();
    if pattern.is_empty() {
        return None;
    }

    if let Some((_, suffix)) = pattern.split_once("://") {
        pattern = suffix;
    }
    if let Some((host, _)) = pattern.split_once('/') {
        pattern = host;
    }
    if pattern.starts_with('[') {
        let closing = pattern.find(']')?;
        pattern = &pattern[1..closing];
    } else if let Some((host, _)) = pattern.split_once(':') {
        pattern = host;
    }

    pattern = pattern.trim();
    let is_suffix = pattern.starts_with("*.") || pattern.starts_with('.');
    let host = pattern
        .strip_prefix("*.")
        .or_else(|| pattern.strip_prefix('.'))
        .unwrap_or(pattern)
        .trim_matches('.');
    if host.is_empty() || host.contains('*') {
        return None;
    }

    let value = host.to_ascii_lowercase();
    let kind = if is_suffix {
        AllowedHostKind::Suffix
    } else {
        AllowedHostKind::Exact
    };
    let suffix = is_suffix.then(|| format!(".{}", value));
    Some(AllowedHostPattern {
        value,
        kind,
        suffix,
    })
}
