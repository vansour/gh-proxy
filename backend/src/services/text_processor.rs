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
static BASE_PATTERN_MATCHER: OnceLock<AhoCorasick> = OnceLock::new();
static BASE_PATTERN_MAX_LEN: OnceLock<usize> = OnceLock::new();

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

fn get_base_pattern_matcher() -> &'static AhoCorasick {
    BASE_PATTERN_MATCHER.get_or_init(|| {
        AhoCorasick::new(BASE_PATTERNS).expect("failed to build GitHub URL matcher")
    })
}

fn max_base_pattern_len() -> usize {
    *BASE_PATTERN_MAX_LEN.get_or_init(|| {
        BASE_PATTERNS
            .iter()
            .map(|pattern| pattern.len())
            .max()
            .unwrap_or(0)
    })
}

/// A stream wrapper that performs on-the-fly string injection.
pub struct TextReplacementStream<S> {
    inner: S,
    /// Efficient buffer that supports O(1) splitting from the front
    buffer: BytesMut,
    /// The Aho-Corasick automaton for multi-pattern search
    ac: &'static AhoCorasick,
    /// The proxy prefix to inject (e.g., "https://ghproxy.com/")
    proxy_prefix: Arc<str>,
    /// Maximum length of a GitHub URL pattern
    base_pattern_len: usize,
    /// Maximum length of any match context (for buffer safety margin)
    max_context_len: usize,
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
        let base_pattern_len = max_base_pattern_len();
        let max_prefix_lookback = 256.max(prefix.len());

        Self {
            inner,
            buffer: BytesMut::with_capacity(16 * 1024), // 16KB initial buffer for better performance
            ac: get_base_pattern_matcher(),
            proxy_prefix: Arc::from(prefix),
            base_pattern_len,
            max_context_len: base_pattern_len + max_prefix_lookback,
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
                let flush_limit = if self.inner_done {
                    self.buffer.len()
                } else {
                    self.buffer
                        .len()
                        .saturating_sub(self.max_context_len.saturating_sub(1))
                };
                let search_limit = if self.inner_done {
                    self.buffer.len()
                } else {
                    self.buffer
                        .len()
                        .saturating_sub(self.base_pattern_len.saturating_sub(1))
                };

                // Need more data to scan safely?
                if search_limit > 0 || (self.inner_done && !self.buffer.is_empty()) {
                    // Check matches in the safe window
                    let input_slice = &self.buffer[..search_limit];

                    if let Some(mat) = self.ac.find(input_slice) {
                        let start = mat.start();
                        let end = mat.end();
                        let lookback_limit = 256.max(self.proxy_prefix.len());
                        let check_start = start.saturating_sub(lookback_limit);
                        let prefix_check_slice = &self.buffer[check_start..start];

                        if prefix_check_slice.ends_with(self.proxy_prefix.as_bytes()) {
                            // Already proxied by this instance. Keep the original bytes untouched.
                            let chunk = self.buffer.split_to(end);
                            return Poll::Ready(Some(Ok(chunk.freeze())));
                        }

                        let mut other_proxy_len = 0;
                        // Regex matches http(s)://.../ at the END of the slice
                        if let Some(m) = get_proxy_prefix_regex().find(prefix_check_slice)
                            && m.end() == prefix_check_slice.len()
                        {
                            other_proxy_len = m.len();
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
                    } else {
                        // No match found in the searchable window.
                        // Flush only the bytes that cannot participate in a future prefixed match.
                        if flush_limit > 0 {
                            // O(1) split
                            let chunk = self.buffer.split_to(flush_limit);
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

#[cfg(test)]
mod tests {
    use super::TextReplacementStream;
    use bytes::{Bytes, BytesMut};
    use futures_util::{StreamExt, stream};

    async fn render(chunks: &[&str], proxy_url: &str) -> String {
        let input =
            stream::iter(chunks.iter().map(|chunk| {
                Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(chunk.as_bytes()))
            }));
        let mut stream = TextReplacementStream::new(input, proxy_url);
        let mut output = BytesMut::new();

        while let Some(chunk) = stream.next().await {
            output.extend_from_slice(&chunk.expect("stream chunk"));
        }

        String::from_utf8(output.to_vec()).expect("utf8 output")
    }

    #[tokio::test]
    async fn replaces_github_urls_with_current_proxy() {
        let output = render(
            &["curl -L https://github.com/owner/repo/releases/download/v1.0.0/app.tgz"],
            "https://gh-proxy.example.com",
        )
        .await;

        assert_eq!(
            output,
            "curl -L https://gh-proxy.example.com/https://github.com/owner/repo/releases/download/v1.0.0/app.tgz"
        );
    }

    #[tokio::test]
    async fn preserves_urls_already_proxied_by_current_instance_across_chunks() {
        let output = render(
            &[
                "prefix https://gh-proxy.example",
                ".com/https://github.com/owner/repo/blob/main/README.md suffix",
            ],
            "https://gh-proxy.example.com",
        )
        .await;

        assert_eq!(
            output,
            "prefix https://gh-proxy.example.com/https://github.com/owner/repo/blob/main/README.md suffix"
        );
    }

    #[tokio::test]
    async fn rewrites_other_proxy_prefix_to_current_proxy() {
        let output = render(
            &[
                "wget https://old-proxy.example/",
                "https://raw.githubusercontent.com/owner/repo/main/file.txt",
            ],
            "https://gh-proxy.example.com",
        )
        .await;

        assert_eq!(
            output,
            "wget https://gh-proxy.example.com/https://raw.githubusercontent.com/owner/repo/main/file.txt"
        );
    }
}
