use aho_corasick::AhoCorasick;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{Stream, ready};
use regex::bytes::Regex;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

/// Patterns to match for GitHub URLs that need proxying
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

/// Regular expression to detect generic proxy prefixes ending with '/'
/// Matches: http(s)://domain[:port]/ at the end of the byte slice.
static PROXY_PREFIX_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_proxy_prefix_regex() -> &'static Regex {
    PROXY_PREFIX_REGEX.get_or_init(|| {
        // Pattern explanation:
        // https?://  -> Match http:// or https://
        // [a-zA-Z0-9\.\-]+ -> Match domain (alphanumeric, dot, hyphen)
        // (:[0-9]+)? -> Optional port
        // / -> Must end with a slash
        // $ -> Anchor to the end of the text
        Regex::new(r"https?://[a-zA-Z0-9\.\-]+(:[0-9]+)?/$").expect("Invalid regex")
    })
}

/// A stream wrapper that performs on-the-fly string injection.
pub struct TextReplacementStream<S> {
    inner: S,
    /// Efficient buffer that supports O(1) splitting from the front
    buffer: BytesMut,
    /// The Aho-Corasick automaton for multi-pattern search
    ac: AhoCorasick,
    /// The proxy prefix to inject (e.g., "https://ghproxy.com/")
    proxy_prefix: Arc<str>,
    /// Maximum length of any pattern (for buffer safety margin)
    max_pattern_len: usize,
    /// State: Have we finished reading the inner stream?
    inner_done: bool,
}

impl<S> TextReplacementStream<S> {
    pub fn new(inner: S, proxy_url: &str) -> Self {
        // Ensure regex is compiled
        let _ = get_proxy_prefix_regex();

        // Normalize proxy URL to ensure it ends with '/'
        let mut prefix = proxy_url.to_string();
        if !prefix.ends_with('/') {
            prefix.push('/');
        }

        // Build patterns:
        // 0..N: Base patterns (needs proxying)
        // N..2N: Exclusion patterns (already proxied by US -> prefix + base)
        // Aho-Corasick matches leftmost-longest. If the text is "https://our-proxy/https://github.com",
        // it matches the exclusion pattern (longer) starting at 0, instead of the base pattern starting later.
        let mut patterns = Vec::with_capacity(BASE_PATTERNS.len() * 2);
        for &p in BASE_PATTERNS {
            patterns.push(p.to_string());
        }
        for &p in BASE_PATTERNS {
            patterns.push(format!("{}{}", prefix, p));
        }

        let ac = AhoCorasick::new(&patterns).expect("Failed to build Aho-Corasick automaton");
        let max_len = patterns.iter().map(|p| p.len()).max().unwrap_or(0);

        Self {
            inner,
            buffer: BytesMut::with_capacity(16 * 1024), // 16KB initial buffer for better performance
            ac,
            proxy_prefix: Arc::from(prefix),
            max_pattern_len: max_len,
            inner_done: false,
        }
    }
}

impl<S, E> Stream for TextReplacementStream<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
{
    type Item = Result<Bytes, E>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            // 1. Process data in buffer
            if !self.buffer.is_empty() {
                let search_limit = if self.inner_done {
                    self.buffer.len()
                } else {
                    self.buffer.len().saturating_sub(self.max_pattern_len - 1)
                };

                // Need more data to scan safely?
                if search_limit > 0 || (self.inner_done && !self.buffer.is_empty()) {
                    // Check matches in the safe window
                    let input_slice = &self.buffer[..search_limit];

                    if let Some(mat) = self.ac.find(input_slice) {
                        let start = mat.start();
                        let end = mat.end();
                        let pattern_id = mat.pattern();

                        // 使用 .as_usize() 将 PatternID 转换为 usize 以进行比较
                        if pattern_id.as_usize() >= BASE_PATTERNS.len() {
                            // Case A: Exclusion pattern found (already proxied by US).
                            // e.g. found "https://gh-proxy.top/https://github.com"
                            // Just output exactly what we found (prefix + url).

                            let chunk = self.buffer.split_to(end);
                            return Poll::Ready(Some(Ok(chunk.freeze())));
                        } else {
                            // Case B: Base pattern found (e.g. "https://github.com").
                            // We need to check if it's prefixed by ANOTHER proxy (e.g. "https://gh-proxy.net/").

                            // Look back up to 256 bytes for a URL prefix
                            let lookback_limit = 256;
                            let check_start = start.saturating_sub(lookback_limit);
                            let prefix_check_slice = &self.buffer[check_start..start];

                            let mut other_proxy_len = 0;
                            // Regex matches http(s)://.../ at the END of the slice
                            if let Some(m) = get_proxy_prefix_regex().find(prefix_check_slice) {
                                // Important: the match must end exactly at the boundary of 'start'
                                if m.end() == prefix_check_slice.len() {
                                    other_proxy_len = m.len();
                                }
                            }

                            // 1. Output everything before the (potential) other proxy
                            let pre_match_len = start - other_proxy_len;
                            let pre_match = self.buffer.split_to(pre_match_len);

                            // 2. Discard the other proxy string if it exists
                            if other_proxy_len > 0 {
                                let _ = self.buffer.split_to(other_proxy_len);
                            }

                            // 3. Extract the GitHub URL itself (the match)
                            // Note: split_to consumes from front, so after previous splits, the match is at 0.
                            let match_part = self.buffer.split_to(end - start);

                            // 4. Combine: Pre-match + OUR Proxy + GitHub URL
                            let mut chunk = BytesMut::with_capacity(
                                pre_match.len() + self.proxy_prefix.len() + match_part.len(),
                            );
                            chunk.put(pre_match);
                            chunk.put(self.proxy_prefix.as_bytes());
                            chunk.put(match_part);

                            return Poll::Ready(Some(Ok(chunk.freeze())));
                        }
                    } else {
                        // No match found in the safe zone.
                        // We can flush the safe zone to downstream to keep memory usage low.
                        if search_limit > 0 {
                            // O(1) split
                            let chunk = self.buffer.split_to(search_limit);
                            return Poll::Ready(Some(Ok(chunk.freeze())));
                        }
                    }
                }
            }

            if self.inner_done && self.buffer.is_empty() {
                return Poll::Ready(None);
            }
            // If we reach here, buffer is not empty but search_limit is 0.
            // This shouldn't happen if logic above is correct for inner_done=true.

            // 2. Read more data
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(bytes)) => {
                    self.buffer.extend_from_slice(&bytes);
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => {
                    self.inner_done = true;
                }
            }
        }
    }
}
