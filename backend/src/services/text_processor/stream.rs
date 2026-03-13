use super::patterns::{get_base_pattern_matcher, get_proxy_prefix_regex, max_base_pattern_len};
use aho_corasick::AhoCorasick;
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::{Stream, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

pub struct TextReplacementStream<S> {
    inner: S,
    buffer: BytesMut,
    ac: &'static AhoCorasick,
    proxy_prefix: Arc<str>,
    base_pattern_len: usize,
    max_context_len: usize,
    inner_done: bool,
}

impl<S> TextReplacementStream<S> {
    pub fn new(inner: S, proxy_url: &str) -> Self {
        let _ = get_proxy_prefix_regex();

        let mut prefix = proxy_url.to_string();
        if !prefix.ends_with('/') {
            prefix.push('/');
        }
        let base_pattern_len = max_base_pattern_len();
        let max_prefix_lookback = 256.max(prefix.len());

        Self {
            inner,
            buffer: BytesMut::with_capacity(16 * 1024),
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

                if search_limit > 0 || (self.inner_done && !self.buffer.is_empty()) {
                    let input_slice = &self.buffer[..search_limit];

                    if let Some(mat) = self.ac.find(input_slice) {
                        let start = mat.start();
                        let end = mat.end();
                        let lookback_limit = 256.max(self.proxy_prefix.len());
                        let check_start = start.saturating_sub(lookback_limit);
                        let prefix_check_slice = &self.buffer[check_start..start];

                        if prefix_check_slice.ends_with(self.proxy_prefix.as_bytes()) {
                            let chunk = self.buffer.split_to(end);
                            return Poll::Ready(Some(Ok(chunk.freeze())));
                        }

                        let mut other_proxy_len = 0;
                        if let Some(matched) = get_proxy_prefix_regex().find(prefix_check_slice)
                            && matched.end() == prefix_check_slice.len()
                        {
                            other_proxy_len = matched.len();
                        }

                        let pre_match_len = start - other_proxy_len;
                        let pre_match = self.buffer.split_to(pre_match_len);

                        if other_proxy_len > 0 {
                            let _ = self.buffer.split_to(other_proxy_len);
                        }

                        let match_part = self.buffer.split_to(end - start);

                        let mut chunk = BytesMut::with_capacity(
                            pre_match.len() + self.proxy_prefix.len() + match_part.len(),
                        );
                        chunk.put(pre_match);
                        chunk.put(self.proxy_prefix.as_bytes());
                        chunk.put(match_part);

                        return Poll::Ready(Some(Ok(chunk.freeze())));
                    } else if flush_limit > 0 {
                        let chunk = self.buffer.split_to(flush_limit);
                        return Poll::Ready(Some(Ok(chunk.freeze())));
                    }
                }
            }

            if self.inner_done && self.buffer.is_empty() {
                return Poll::Ready(None);
            }

            match ready!(Pin::new(&mut self.inner).poll_next(cx)) {
                Some(Ok(bytes)) => {
                    self.buffer.extend_from_slice(&bytes);
                }
                Some(Err(error)) => return Poll::Ready(Some(Err(error))),
                None => {
                    self.inner_done = true;
                }
            }
        }
    }
}
