//! Streaming body wrapper with size limits and metrics.

use bytes::Bytes;
use futures_util::Stream;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::OwnedSemaphorePermit;

use crate::errors::ProxyError;
use crate::infra;
use crate::middleware::RequestLifecycle;

/// Type alias for boxed body stream.
pub type BoxedBodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, ProxyError>> + Send>>;

/// 统一的缓冲区大小：256KB
const UNIFIED_BUFFER_SIZE: usize = 256 * 1024;

/// Streaming body wrapper that enforces size limits and tracks metrics.
pub struct ProxyBodyStream {
    inner: BoxedBodyStream,
    lifecycle: Option<RequestLifecycle>,
    size_limit_bytes: u64,
    size_limit_mb: u64,
    total_bytes: u64,
    permit: Option<OwnedSemaphorePermit>,
    start_time: Option<std::time::Instant>,
    /// Buffer for partial chunk
    buffer: Option<Bytes>,
}

impl ProxyBodyStream {
    /// Create a new streaming body wrapper.
    pub fn new(
        inner: BoxedBodyStream,
        lifecycle: RequestLifecycle,
        size_limit_bytes: u64,
        size_limit_mb: u64,
        start_time: Option<std::time::Instant>,
        permit: Option<OwnedSemaphorePermit>,
        _deprecated_chunk_transfer: bool, // 保持参数列表兼容
    ) -> Self {
        Self {
            inner,
            lifecycle: Some(lifecycle),
            size_limit_bytes,
            size_limit_mb,
            total_bytes: 0,
            permit,
            start_time,
            buffer: None,
        }
    }
}

impl Stream for ProxyBodyStream {
    type Item = Result<Bytes, ProxyError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        if let Some(buffered) = this.buffer.take() {
            let chunk_len = buffered.len() as u64;
            let new_total = this.total_bytes.saturating_add(chunk_len);
            infra::metrics::BYTES_TRANSFERRED_TOTAL.inc_by(chunk_len);

            if this.size_limit_bytes > 0 && new_total > this.size_limit_bytes {
                let error = ProxyError::SizeExceeded(new_total / 1024 / 1024, this.size_limit_mb);
                if let Some(mut lifecycle) = this.lifecycle.take() {
                    lifecycle.fail(Some(&error));
                }
                return Poll::Ready(Some(Err(error)));
            }
            this.total_bytes = new_total;
            return Poll::Ready(Some(Ok(buffered)));
        }

        match this.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(mut chunk))) => {
                // 统一使用 256KB 切分，不再区分 CDN 模式
                if chunk.len() > UNIFIED_BUFFER_SIZE {
                    let remaining = chunk.split_off(UNIFIED_BUFFER_SIZE);
                    this.buffer = Some(remaining);
                }

                let chunk_len = chunk.len() as u64;
                let new_total = this.total_bytes.saturating_add(chunk_len);
                infra::metrics::BYTES_TRANSFERRED_TOTAL.inc_by(chunk_len);

                if this.size_limit_bytes > 0 && new_total > this.size_limit_bytes {
                    let error =
                        ProxyError::SizeExceeded(new_total / 1024 / 1024, this.size_limit_mb);
                    if let Some(mut lifecycle) = this.lifecycle.take() {
                        lifecycle.fail(Some(&error));
                    }
                    return Poll::Ready(Some(Err(error)));
                }
                this.total_bytes = new_total;
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                if let Some(mut lifecycle) = this.lifecycle.take() {
                    lifecycle.fail(Some(&e));
                }
                if this.permit.take().is_some() {
                    infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
                }
                if let Some(start) = this.start_time.take() {
                    infra::metrics::HTTP_REQUEST_DURATION_SECONDS
                        .observe(start.elapsed().as_secs_f64());
                }
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                if let Some(mut lifecycle) = this.lifecycle.take() {
                    lifecycle.success();
                }
                if this.permit.take().is_some() {
                    infra::metrics::HTTP_ACTIVE_REQUESTS.dec();
                }
                if let Some(start) = this.start_time.take() {
                    infra::metrics::HTTP_REQUEST_DURATION_SECONDS
                        .observe(start.elapsed().as_secs_f64());
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
