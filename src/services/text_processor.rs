use aho_corasick::AhoCorasick;
use bytes::Bytes;
use futures_util::{Stream, ready};
use std::pin::Pin;
use std::sync::Arc;
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

/// A stream wrapper that performs on-the-fly string injection.
/// It searches for GitHub URLs and prepends the proxy URL to them.
pub struct TextReplacementStream<S> {
    inner: S,
    /// Internal buffer to handle matches crossing chunk boundaries
    buffer: Vec<u8>,
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
        // Construct the automaton. Match longest to prefer https over http if they overlap (though they share start).
        // Aho-Corasick matches are typically leftmost-longest by default configuration or distinct.
        let ac = AhoCorasick::new(PATTERNS).expect("Failed to build Aho-Corasick automaton");
        let max_len = PATTERNS.iter().map(|p| p.len()).max().unwrap_or(0);

        // Normalize proxy URL to ensure it ends with '/' if needed, or matches the expected injection format.
        // The original logic was `proxy_url + "/" + url`.
        // e.g. "https://ghproxy.com" -> "https://ghproxy.com/"
        let mut prefix = proxy_url.to_string();
        if !prefix.ends_with('/') {
            prefix.push('/');
        }

        Self {
            inner,
            buffer: Vec::with_capacity(8 * 1024), // Start with 8KB
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
            // 1. If we have data in the buffer, try to process and yield it
            if !self.buffer.is_empty() {
                // Determine the "safe" zone to scan.
                // We must leave `max_pattern_len - 1` bytes at the end UNLESS stream is done,
                // because a partial match might start there and continue in the next chunk.
                let search_limit = if self.inner_done {
                    self.buffer.len()
                } else {
                    self.buffer.len().saturating_sub(self.max_pattern_len - 1)
                };

                // If we don't have enough data to scan safely, and inner is not done, we must read more.
                if search_limit == 0 && !self.inner_done {
                    // fallthrough to read from inner
                } else {
                    // Try to find a match within [0..search_limit]
                    // We use `find` which returns the first match.
                    let input_slice = &self.buffer[..search_limit];

                    if let Some(mat) = self.ac.find(input_slice) {
                        let start = mat.start();
                        // Found a match!
                        // We need to yield:
                        // 1. Everything before the match
                        // 2. The proxy prefix
                        // 3. The match itself (we don't consume/remove the match, we just prefix it)
                        // Wait, if we keep the match in the buffer, we will find it again next loop!
                        // We must CONSUME the buffer up to the end of the match (or at least past the start).

                        // Output logic:
                        // Chunk 1: buffer[..start] (The text before the link)
                        // Chunk 2: proxy_prefix
                        // Chunk 3: buffer[start..end] (The link prefix itself, e.g. "https://github.com")

                        // To be efficient with chunks, we combine [Pre] + [Proxy] + [Match] ?
                        // Or just yield one by one. Yielding small chunks is fine for `Bytes`.
                        // Let's create a combined buffer to yield one nice chunk if possible, or sequence them.
                        // Since `poll_next` yields one item, let's construct one `Bytes` object containing the processed data up to the end of the match.

                        let mut output =
                            Vec::with_capacity(start + self.proxy_prefix.len() + mat.len());
                        output.extend_from_slice(&self.buffer[..start]);
                        output.extend_from_slice(self.proxy_prefix.as_bytes());
                        output.extend_from_slice(&self.buffer[start..mat.end()]);

                        // Remove processed data from internal buffer
                        // drain is O(N), but necessary. Using a circular buffer is complex for this P3.
                        // Optimization: If `start` is large, this is fine.
                        self.buffer.drain(..mat.end());

                        return Poll::Ready(Some(Ok(Bytes::from(output))));
                    } else {
                        // No match in the safe zone.
                        // We can safely flush everything in the safe zone to downstream,
                        // keeping only the "tail" (potential partial match).

                        if search_limit > 0 {
                            let chunk = self.buffer.drain(..search_limit).collect::<Vec<u8>>();
                            return Poll::Ready(Some(Ok(Bytes::from(chunk))));
                        }

                        // If search_limit is 0 (buffer small) and inner is done, flushing the rest.
                        if self.inner_done && !self.buffer.is_empty() {
                            let chunk = std::mem::take(&mut self.buffer);
                            return Poll::Ready(Some(Ok(Bytes::from(chunk))));
                        }
                    }
                }
            }

            if self.inner_done {
                return Poll::Ready(None);
            }

            // 2. Read more data from inner stream
            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(bytes)) => {
                    // Heuristic: If buffer grows too large without processing, it might be a memory DoS or just a huge block of binary.
                    // But here we flush regularly. The buffer only grows if we don't find matches but `search_limit` is 0?
                    // No, `search_limit` grows as buffer grows. The tail is constant size.
                    self.buffer.extend_from_slice(&bytes);
                }
                Some(Err(e)) => return Poll::Ready(Some(Err(e))),
                None => {
                    self.inner_done = true;
                    // Loop again to flush remaining buffer
                }
            }
        }
    }
}
