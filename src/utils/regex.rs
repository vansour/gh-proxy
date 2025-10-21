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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_raw_pattern() {
        let pattern = get_raw_pattern();
        assert!(pattern.is_match("https://raw.githubusercontent.com/owner/repo/branch/file.rs"));
    }

    #[test]
    fn test_github_pattern() {
        let pattern = get_github_pattern();
        assert!(pattern.is_match("https://github.com/owner/repo/blob/branch/file.rs"));
    }

    #[test]
    fn test_link_pattern() {
        let pattern = get_link_pattern();
        let text = "Check https://raw.githubusercontent.com/owner/repo/branch/file";
        assert!(pattern.is_match(text));
    }
}
