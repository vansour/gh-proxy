/// Request processing utilities
/// Extracts and processes request information
use axum::extract::Request;

/// Extract client IP from request headers or connection info
pub fn extract_client_ip(req: &Request<axum::body::Body>) -> Option<String> {
    // Try X-Forwarded-For header first (for proxied requests)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP in the chain
            if let Some(ip) = xff_str.split(',').next() {
                return Some(ip.trim().to_string());
            }
        }
    }

    // Try X-Real-IP header
    if let Some(xri) = req.headers().get("x-real-ip") {
        if let Ok(ip) = xri.to_str() {
            return Some(ip.trim().to_string());
        }
    }

    // TODO: Extract from connection info if available
    // For now, return None if no headers present
    None
}
