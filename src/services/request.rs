/// Request processing utilities
/// Extracts and processes request information
use std::net::{IpAddr, SocketAddr};

use axum::extract::{Request, connect_info::ConnectInfo};

/// Extract client IP from request headers or connection info
/// Priority order for IP detection (Cloudflare-first):
/// 1. cf-connecting-ip (Cloudflare connecting IP)
/// 2. X-Forwarded-For (proxy chain)
/// 3. Forwarded header (RFC 7239)
/// 4. True-Client-IP (Akamai/Cloudflare fallback)
/// 5. X-Real-IP (nginx/common proxy)
/// 6. Connection info (fallback)
pub fn extract_client_ip(req: &Request<axum::body::Body>) -> Option<String> {
    // Try Cloudflare's connecting IP header first (most reliable when behind CF)
    if let Some(cf) = req.headers().get("cf-connecting-ip")
        && let Ok(ip) = cf.to_str()
        && let Some(addr) = parse_ip_literal(ip)
    {
        return Some(addr.to_string());
    }

    // Try X-Forwarded-For header (for proxied requests from proxy chains)
    if let Some(xff) = req.headers().get("x-forwarded-for")
        && let Ok(xff_str) = xff.to_str()
    {
        for candidate in xff_str.split(',') {
            if let Some(ip) = parse_ip_literal(candidate) {
                return Some(ip.to_string());
            }
        }
    }

    // Try standardized Forwarded header (e.g. for=192.0.2.43)
    if let Some(forwarded) = req.headers().get("forwarded")
        && let Ok(forwarded_str) = forwarded.to_str()
    {
        for entry in forwarded_str.split(',') {
            for part in entry.split(';') {
                let part = part.trim();
                if let Some(raw_ip) = part.strip_prefix("for=")
                    && let Some(ip) = parse_ip_literal(raw_ip)
                {
                    return Some(ip.to_string());
                }
            }
        }
    }

    // Try Akamai/Cloudflare True-Client-IP header as fallback
    if let Some(true_client) = req.headers().get("true-client-ip")
        && let Ok(ip) = true_client.to_str()
        && let Some(addr) = parse_ip_literal(ip)
    {
        return Some(addr.to_string());
    }

    // Try X-Real-IP header (nginx/reverse proxy)
    if let Some(xri) = req.headers().get("x-real-ip")
        && let Ok(ip) = xri.to_str()
        && let Some(addr) = parse_ip_literal(ip)
    {
        return Some(addr.to_string());
    }

    // Fallback to connection info injected by axum
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return Some(addr.ip().to_string());
    }

    None
}

/// Detect the request protocol/scheme with Cloudflare awareness
/// Priority order:
/// 1. cf-visitor header (Cloudflare protocol indicator: {"scheme":"https"})
/// 2. X-Forwarded-Proto header
/// 3. URI scheme (if present)
/// 4. Heuristics (check host/port)
pub fn detect_client_protocol(req: &Request<axum::body::Body>) -> String {
    // Try Cloudflare's cf-visitor header first
    if let Some(cf_visitor) = req.headers().get("cf-visitor")
        && let Ok(visitor_str) = cf_visitor.to_str()
    {
        // cf-visitor is JSON like: {"scheme":"https"}
        if visitor_str.contains("\"scheme\":\"https\"") {
            return "https".to_string();
        } else if visitor_str.contains("\"scheme\":\"http\"") {
            return "http".to_string();
        }
    }

    // Try X-Forwarded-Proto header
    if let Some(forwarded) = req.headers().get("x-forwarded-proto")
        && let Ok(proto) = forwarded.to_str()
    {
        let proto_lower = proto.trim().to_lowercase();
        if proto_lower == "https" || proto_lower == "http" {
            return proto_lower;
        }
    }

    // Try URI scheme
    if let Some(scheme) = req.uri().scheme_str() {
        let scheme_lower = scheme.to_lowercase();
        if scheme_lower == "https" || scheme_lower == "http" {
            return scheme_lower;
        }
    }

    // Heuristics: check Host header and connection info
    if let Some(host) = req.headers().get("host")
        && let Ok(host_str) = host.to_str()
        && (host_str.starts_with("localhost")
            || host_str.contains("127.0.0.1")
            || host_str.ends_with(":80")
            || host_str.ends_with(":8080")
            || host_str.ends_with(":3000")
            || host_str.ends_with(":5000"))
    {
        return "http".to_string();
    }

    // Default to https for remote connections
    "https".to_string()
}

fn parse_ip_literal(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');

    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }

    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Some(addr.ip());
    }

    // Forwarded header may wrap IPv6 addresses in brackets without a port.
    if let Some(stripped) = value.strip_prefix('[')
        && let Some(rest) = stripped.strip_suffix(']')
        && let Ok(ip) = rest.parse::<IpAddr>()
    {
        return Some(ip);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;

    fn request_with_header(name: &str, value: &str) -> Request<Body> {
        Request::builder()
            .uri("/")
            .header(name, value)
            .body(Body::empty())
            .unwrap()
    }

    #[test]
    fn extracts_first_xff_ip() {
        let req = request_with_header(
            "x-forwarded-for",
            "203.0.113.5, 70.41.3.18, 150.172.238.178",
        );

        assert_eq!(extract_client_ip(&req), Some("203.0.113.5".into()));
    }

    #[test]
    fn parses_forwarded_header() {
        let req = request_with_header(
            "forwarded",
            "for=\"[2001:db8:cafe::17]:4711\";proto=https;by=203.0.113.43",
        );

        assert_eq!(extract_client_ip(&req), Some("2001:db8:cafe::17".into()));
    }

    #[test]
    fn falls_back_to_connect_info() {
        let mut req = Request::builder().uri("/").body(Body::empty()).unwrap();

        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 8080))));

        assert_eq!(extract_client_ip(&req), Some("127.0.0.1".into()));
    }
}
