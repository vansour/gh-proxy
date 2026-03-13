use super::ConfigError;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct HostPattern {
    value: String,
    kind: HostPatternKind,
    suffix: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostPatternKind {
    Exact,
    Suffix,
}

impl HostPattern {
    pub(crate) fn parse(raw: &str) -> Result<Self, String> {
        let mut pattern = raw.trim();
        if pattern.is_empty() {
            return Err("value cannot be empty".to_string());
        }
        if let Some(idx) = pattern.find("://") {
            pattern = &pattern[idx + 3..];
        }
        if let Some((host_part, _)) = pattern.split_once('/') {
            pattern = host_part;
        }
        if pattern.starts_with('[') {
            let closing = pattern
                .find(']')
                .ok_or_else(|| "missing closing ']' for IPv6 literal".to_string())?;
            pattern = &pattern[1..closing];
        } else if let Some((host, _)) = pattern.split_once(':') {
            pattern = host;
        }
        pattern = pattern.trim();

        let (kind, host) = if let Some(stripped) = pattern.strip_prefix("*.") {
            (HostPatternKind::Suffix, stripped)
        } else if let Some(stripped) = pattern.strip_prefix('.') {
            (HostPatternKind::Suffix, stripped)
        } else {
            (HostPatternKind::Exact, pattern)
        };

        let host = host.trim_matches('.');
        if host.is_empty() {
            return Err("resolved host is empty".to_string());
        }
        if host.contains('*') {
            return Err("wildcards must use to '*.example.com' form".to_string());
        }

        let value = host.to_ascii_lowercase();
        let suffix = match kind {
            HostPatternKind::Exact => None,
            HostPatternKind::Suffix => Some(format!(".{}", value)),
        };

        Ok(Self {
            value,
            kind,
            suffix,
        })
    }

    fn canonical_pattern(&self) -> String {
        match self.kind {
            HostPatternKind::Exact => self.value.clone(),
            HostPatternKind::Suffix => format!("*.{}", self.value),
        }
    }

    pub(crate) fn matches(&self, host: &str) -> bool {
        match self.kind {
            HostPatternKind::Exact => host == self.value,
            HostPatternKind::Suffix => {
                host == self.value
                    || self
                        .suffix
                        .as_ref()
                        .map(|suffix| host.ends_with(suffix))
                        .unwrap_or(false)
            }
        }
    }

    pub(crate) fn is_exact(&self) -> bool {
        self.kind == HostPatternKind::Exact
    }

    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

pub(crate) fn normalize_host_pattern_list(
    entries: &[String],
    field_name: &str,
) -> Result<Vec<String>, ConfigError> {
    let mut normalized = Vec::with_capacity(entries.len());
    let mut seen = HashSet::with_capacity(entries.len());

    for entry in entries {
        let pattern = entry.trim();
        if pattern.is_empty() {
            continue;
        }

        let parsed = HostPattern::parse(pattern).map_err(|err| {
            ConfigError::Validation(format!(
                "{} entry '{}' is invalid: {}",
                field_name, entry, err
            ))
        })?;
        let canonical = parsed.canonical_pattern();

        if seen.insert(canonical.clone()) {
            normalized.push(canonical);
        }
    }

    Ok(normalized)
}
