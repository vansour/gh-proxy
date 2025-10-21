/// Request processing utilities
/// Extracts and processes request information
use axum::extract::Request;
use tracing::debug;

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

/// Determine the proxy URL scheme (http or https) based on request headers
#[allow(dead_code)]
pub fn determine_proxy_scheme(req: &Request<axum::body::Body>) -> String {
    use hyper::header;

    // Priority: X-Forwarded-Proto > URI scheme > heuristics > default
    if let Some(forwarded) = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
    {
        debug!("Using scheme from X-Forwarded-Proto: {}", forwarded);
        return forwarded.to_string();
    }

    if let Some(scheme) = req.uri().scheme_str() {
        debug!("Using scheme from URI: {}", scheme);
        return scheme.to_string();
    }

    // Heuristic: if Host header contains localhost or specific dev ports
    if let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        if host.starts_with("localhost")
            || host.starts_with("127.0.0.1")
            || host.ends_with(":3000")
            || host.ends_with(":5000")
        {
            debug!("Using http for local/dev host: {}", host);
            return "http".to_string();
        }
    }

    debug!("Using https for remote connection");
    "https".to_string()
}
