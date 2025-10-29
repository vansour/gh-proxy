use regex::Regex;
use std::sync::OnceLock;
static RAW_PATTERN: OnceLock<Regex> = OnceLock::new();
static GITHUB_PATTERN: OnceLock<Regex> = OnceLock::new();
static LINK_PATTERN: OnceLock<Regex> = OnceLock::new();
pub fn get_raw_pattern() -> &'static Regex {
    RAW_PATTERN.get_or_init(|| {
        Regex::new(r#"https?://raw\.githubusercontent\.com/[^\s"'<>]++"#)
            .expect("Failed to compile raw pattern regex")
    })
}
pub fn get_github_pattern() -> &'static Regex {
    GITHUB_PATTERN.get_or_init(|| {
        Regex::new(r#"https?://github\.com/[^\s"'<>]++"#)
            .expect("Failed to compile github pattern regex")
    })
}
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
    fn test_get_raw_pattern() {
        let pattern = get_raw_pattern();
        assert!(pattern.is_match("https://raw.githubusercontent.com/owner/repo/main/file.txt"));
        assert!(pattern.is_match("http://raw.githubusercontent.com/owner/repo/main/file.txt"));
        assert!(!pattern.is_match("https://github.com/owner/repo/main/file.txt"));
    }

    #[test]
    fn test_get_github_pattern() {
        let pattern = get_github_pattern();
        assert!(pattern.is_match("https://github.com/owner/repo/blob/main/file.txt"));
        assert!(pattern.is_match("http://github.com/owner/repo/blob/main/file.txt"));
        assert!(!pattern.is_match("https://raw.githubusercontent.com/owner/repo/main/file.txt"));
    }

    #[test]
    fn test_get_link_pattern() {
        let pattern = get_link_pattern();
        assert!(pattern.is_match("https://raw.githubusercontent.com/owner/repo/main/file.txt"));
        assert!(pattern.is_match("https://github.com/owner/repo/blob/main/file.txt"));
        assert!(!pattern.is_match("https://example.com/path"));
    }

    #[test]
    fn test_raw_pattern_capture() {
        let pattern = get_raw_pattern();
        let text = "Visit https://raw.githubusercontent.com/owner/repo/main/file.txt for details";
        let captures = pattern.find(text);
        assert!(captures.is_some());
        let captured = captures.unwrap();
        assert_eq!(
            captured.as_str(),
            "https://raw.githubusercontent.com/owner/repo/main/file.txt"
        );
    }

    #[test]
    fn test_github_pattern_capture() {
        let pattern = get_github_pattern();
        let text = "Go to https://github.com/owner/repo for more";
        let captures = pattern.find(text);
        assert!(captures.is_some());
        let captured = captures.unwrap();
        assert_eq!(captured.as_str(), "https://github.com/owner/repo");
    }

    #[test]
    fn test_pattern_excludes_invalid_chars() {
        let pattern = get_raw_pattern();
        let text = "Check https://raw.githubusercontent.com/owner/repo/main/file.txt\"";
        let captures = pattern.find(text);
        assert!(captures.is_some());
        let captured = captures.unwrap();
        // Should not include the trailing quote
        assert!(!captured.as_str().ends_with('"'));
    }
}
