// Centralized regex pattern management with lazy initialization
// This ensures regex patterns are compiled only once and reused across requests

use regex::Regex;
use std::sync::OnceLock;

static RAW_PATTERN: OnceLock<Regex> = OnceLock::new();
static GITHUB_PATTERN: OnceLock<Regex> = OnceLock::new();
static LINK_PATTERN: OnceLock<Regex> = OnceLock::new();

/// Get the compiled regex pattern for raw.githubusercontent.com URLs
pub fn get_raw_pattern() -> &'static Regex {
    RAW_PATTERN.get_or_init(|| {
        Regex::new(r#"https?://raw\.githubusercontent\.com/[^\s"'<>]++"#)
            .expect("Failed to compile raw pattern regex")
    })
}

/// Get the compiled regex pattern for github.com URLs
pub fn get_github_pattern() -> &'static Regex {
    GITHUB_PATTERN.get_or_init(|| {
        Regex::new(r#"https?://github\.com/[^\s"'<>]++"#)
            .expect("Failed to compile github pattern regex")
    })
}

/// Get the compiled regex pattern for link extraction
pub fn get_link_pattern() -> &'static Regex {
    LINK_PATTERN.get_or_init(|| {
        Regex::new(r#"(https?://(raw\.githubusercontent\.com|github\.com)/[^\s"'<>]+)"#)
            .expect("Failed to compile link pattern regex")
    })
}
