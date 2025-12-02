use aho_corasick::AhoCorasick;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{Stream, ready};
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

/// Patterns to match for GitHub URLs that need proxying
const PATTERNS: &[&str] = &[
    "https://github.com",
    "http://github.com",
    "https://raw.githubusercontent.com",
    "http://raw.githubusercontent.com",
    "https://gist.github.com",
    "http://gist.github.com",
];

/// Global Aho-Corasick automaton to avoid rebuilding it for every request.
static AC_AUTOMATON: OnceLock<AhoCorasick> = OnceLock::new();

fn get_automaton() -> &'static AhoCorasick {
    AC_AUTOMATON
        .get_or_init(|| AhoCorasick::new(PATTERNS).expect("Failed to build Aho-Corasick automaton"))
}

/// A stream wrapper that performs on-the-fly string injection.
pub struct TextReplacementStream<S> {
    inner: S,
    /// Efficient buffer that supports O(1) splitting from the front
    buffer: BytesMut,
    /// The proxy prefix to inject (e.g., "https://ghproxy.com/")
    proxy_prefix: Arc<str>,
    /// Maximum length of any pattern (for buffer safety margin)
    max_pattern_len: usize,
    /// State: Have we finished reading the inner stream?
    inner_done: bool,
}

impl<S> TextReplacementStream<S> {
    pub fn new(inner: S, proxy_url: &str) -> Self {
        // Ensure automaton is initialized
        let _ = get_automaton();

        let max_len = PATTERNS.iter().map(|p| p.len()).max().unwrap_or(0);

        let mut prefix = proxy_url.to_string();
        if !prefix.ends_with('/') {
            prefix.push('/');
        }

        Self {
            inner,
            buffer: BytesMut::with_capacity(8 * 1024), // Start with 8KB
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
                    let ac = get_automaton();
                    // Check matches in the safe window
                    let input_slice = &self.buffer[..search_limit];

                    if let Some(mat) = ac.find(input_slice) {
                        let start = mat.start();
                        let end = mat.end();

                        // Construct output: [Pre-match] + [Prefix] + [Match]
                        // Note: We leave [Match] (e.g., "https://github.com") in the output stream, just prefixed.

                        // O(1) split: Take everything up to the match start
                        let pre_match = self.buffer.split_to(start);

                        // We also need to split the match itself to append it after prefix
                        // split_to modifies `self.buffer`, so indices are relative to current head.
                        // After split_to(start), the match is now at 0.
                        let match_part = self.buffer.split_to(end - start);

                        // Combine into a single Bytes object to yield
                        // We reserve space for prefix + match part
                        let mut chunk = BytesMut::with_capacity(
                            pre_match.len() + self.proxy_prefix.len() + match_part.len(),
                        );
                        chunk.put(pre_match);
                        chunk.put(self.proxy_prefix.as_bytes());
                        chunk.put(match_part);

                        return Poll::Ready(Some(Ok(chunk.freeze())));
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

            if self.inner_done {
                // If we are done and buffer is empty, we are finished.
                if self.buffer.is_empty() {
                    return Poll::Ready(None);
                }
                // If buffer not empty but search_limit was 0 (should correspond to the logic above),
                // the `search_limit` logic handles the final flush when `inner_done` is true.
                // So if we reach here, it implies we processed everything possible.
            }

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
