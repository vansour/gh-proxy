use aho_corasick::AhoCorasick;
use regex::bytes::Regex;
use std::sync::OnceLock;

const BASE_PATTERNS: &[&str] = &[
    "https://github.com",
    "http://github.com",
    "https://raw.githubusercontent.com",
    "http://raw.githubusercontent.com",
    "https://gist.github.com",
    "http://gist.github.com",
    "https://assets-cdn.github.com",
    "http://assets-cdn.github.com",
    "https://avatars.githubusercontent.com",
    "http://avatars.githubusercontent.com",
    "https://avatars0.githubusercontent.com",
    "http://avatars0.githubusercontent.com",
    "https://avatars1.githubusercontent.com",
    "http://avatars1.githubusercontent.com",
    "https://avatars2.githubusercontent.com",
    "http://avatars2.githubusercontent.com",
    "https://avatars3.githubusercontent.com",
    "http://avatars3.githubusercontent.com",
    "https://media.githubusercontent.com",
    "http://media.githubusercontent.com",
    "https://codeload.github.com",
    "http://codeload.github.com",
    "https://objects.githubusercontent.com",
    "http://objects.githubusercontent.com",
];

static PROXY_PREFIX_REGEX: OnceLock<Regex> = OnceLock::new();
static BASE_PATTERN_MATCHER: OnceLock<AhoCorasick> = OnceLock::new();
static BASE_PATTERN_MAX_LEN: OnceLock<usize> = OnceLock::new();

pub(super) fn get_proxy_prefix_regex() -> &'static Regex {
    PROXY_PREFIX_REGEX.get_or_init(|| {
        Regex::new(r"https?://[a-zA-Z0-9\.\-]+(:[0-9]+)?/$").expect("Invalid regex")
    })
}

pub(super) fn get_base_pattern_matcher() -> &'static AhoCorasick {
    BASE_PATTERN_MATCHER.get_or_init(|| {
        AhoCorasick::new(BASE_PATTERNS).expect("failed to build GitHub URL matcher")
    })
}

pub(super) fn max_base_pattern_len() -> usize {
    *BASE_PATTERN_MAX_LEN.get_or_init(|| {
        BASE_PATTERNS
            .iter()
            .map(|pattern| pattern.len())
            .max()
            .unwrap_or(0)
    })
}
