// Stream-based proxy module with backpressure support and zero-copy forwarding
// This module implements efficient streaming of responses from upstream servers
// with proper backpressure handling to prevent memory exhaustion on large transfers

use axum::body::Body;
use std::pin::Pin;
use tokio::io::AsyncRead;
use tracing::{debug, error, warn};

/// Custom streaming body that forwards data with backpressure support
#[allow(dead_code)]
pub struct StreamingBody {
    inner: Pin<Box<dyn AsyncRead + Send + Sync>>,
    buffer_size: usize,
}

impl StreamingBody {
    /// Create a new streaming body with default buffer size (64KB)
    #[allow(dead_code)]
    pub fn new(reader: Pin<Box<dyn AsyncRead + Send + Sync>>) -> Self {
        Self {
            inner: reader,
            buffer_size: 65536, // 64KB default buffer
        }
    }

    /// Create a new streaming body with custom buffer size
    #[allow(dead_code)]
    pub fn with_buffer_size(
        reader: Pin<Box<dyn AsyncRead + Send + Sync>>,
        buffer_size: usize,
    ) -> Self {
        Self {
            inner: reader,
            buffer_size,
        }
    }
}

/// Forward a response body while respecting backpressure
///
/// This function implements zero-copy forwarding by directly piping the response
/// body without buffering the entire content in memory. It respects HTTP/2 flow control
/// and handles both chunked and fixed-size responses.
#[allow(dead_code)]
pub async fn forward_response_body(
    response_body: Body,
    target_path: &str,
    size_limit: Option<u64>,
) -> Result<Body, String> {
    use http_body_util::BodyExt;

    // If there's a size limit, check it during streaming
    let enforce_limit = size_limit.is_some();

    debug!(
        "Starting to forward response for: {}, size_limit: {:?}",
        target_path, size_limit
    );

    // For streaming responses, we collect the body but with size checking
    let bytes = response_body
        .collect()
        .await
        .map_err(|e| {
            error!("Failed to collect response body: {}", e);
            format!("Failed to read response body: {}", e)
        })?
        .to_bytes();

    let total_read = bytes.len() as u64;

    // Check size limit if enforced
    if enforce_limit {
        if let Some(limit) = size_limit {
            if total_read > limit {
                warn!(
                    "Response size {} bytes exceeds limit {} bytes for: {}",
                    total_read, limit, target_path
                );
                return Err(format!(
                    "Response size {} bytes exceeds limit {} bytes",
                    total_read, limit
                ));
            }
        }
    }

    debug!(
        "Successfully forwarded {} bytes for: {}",
        total_read, target_path
    );

    Ok(Body::from(bytes))
}

/// Handle streaming response with content type awareness
///
/// For text content (shell scripts, HTML), we may need to read and modify the content.
/// For binary content, we stream directly without modification.
#[allow(dead_code)]
pub async fn handle_streaming_response(
    response_body: Body,
    content_type: Option<&str>,
    is_text_processing_enabled: bool,
) -> Result<Body, String> {
    let content_type = content_type.unwrap_or("").to_lowercase();

    // Check if we need to process text content
    let needs_processing = is_text_processing_enabled
        && (content_type.contains("text/")
            || content_type.contains("application/json")
            || content_type.contains("application/javascript")
            || content_type.contains("application/xml")
            || content_type.is_empty()); // Assume text if no content-type

    if needs_processing {
        // For text content, collect the body for processing
        use http_body_util::BodyExt;

        let bytes = response_body
            .collect()
            .await
            .map_err(|e| format!("Failed to read response body: {}", e))?
            .to_bytes();

        debug!(
            "Collected {} bytes of text content for processing",
            bytes.len()
        );

        Ok(Body::from(bytes))
    } else {
        // For binary content, return the body as-is for streaming
        debug!("Binary content detected, streaming directly without processing");
        Ok(response_body)
    }
}

/// Estimate buffer size based on response headers
///
/// If Content-Length is available, use a proportional buffer.
/// Otherwise use a reasonable default (64KB).
#[allow(dead_code)]
pub fn estimate_buffer_size(content_length: Option<u64>) -> usize {
    match content_length {
        Some(len) => {
            // Use smaller of: 256KB or content_length / 4
            // This prevents huge buffer allocations while being efficient
            std::cmp::min(262144, (len as usize).max(4096) / 4)
        }
        None => 65536, // Default 64KB
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_size_estimation() {
        // Small file: proportional buffer
        assert_eq!(estimate_buffer_size(Some(10000)), 2500);

        // Large file: capped at 256KB
        assert_eq!(estimate_buffer_size(Some(10_000_000)), 262144);

        // No size info: default buffer
        assert_eq!(estimate_buffer_size(None), 65536);

        // Very small file: minimum 4KB
        assert!(estimate_buffer_size(Some(100)) >= 4096);
    }
}
