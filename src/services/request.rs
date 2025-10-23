/// Request processing utilities
/// Extracts and processes request information
use std::net::{IpAddr, SocketAddr};

use axum::extract::{Request, connect_info::ConnectInfo};

/// Extract client IP from request headers or connection info
pub fn extract_client_ip(req: &Request<axum::body::Body>) -> Option<String> {
    // Try X-Forwarded-For header first (for proxied requests)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            for candidate in xff_str.split(',') {
                if let Some(ip) = parse_ip_literal(candidate) {
                    return Some(ip.to_string());
                }
            }
        }
    }

    // Try standardized Forwarded header (e.g. for=192.0.2.43)
    if let Some(forwarded) = req.headers().get("forwarded") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            for entry in forwarded_str.split(',') {
                for part in entry.split(';') {
                    let part = part.trim();
                    if let Some(raw_ip) = part.strip_prefix("for=") {
                        if let Some(ip) = parse_ip_literal(raw_ip) {
                            return Some(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    // Try Cloudflare's connecting IP header
    if let Some(cf) = req.headers().get("cf-connecting-ip") {
        if let Ok(ip) = cf.to_str() {
            if let Some(addr) = parse_ip_literal(ip) {
                return Some(addr.to_string());
            }
        }
    }

    // Try Akamai/Cloudflare True-Client-IP header
    if let Some(true_client) = req.headers().get("true-client-ip") {
        if let Ok(ip) = true_client.to_str() {
            if let Some(addr) = parse_ip_literal(ip) {
                return Some(addr.to_string());
            }
        }
    }

    // Try X-Real-IP header
    if let Some(xri) = req.headers().get("x-real-ip") {
        if let Ok(ip) = xri.to_str() {
            if let Some(addr) = parse_ip_literal(ip) {
                return Some(addr.to_string());
            }
        }
    }

    // Fallback to connection info injected by axum
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return Some(addr.ip().to_string());
    }

    None
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
    if let Some(stripped) = value.strip_prefix('[') {
        if let Some(rest) = stripped.strip_suffix(']') {
            if let Ok(ip) = rest.parse::<IpAddr>() {
                return Some(ip);
            }
        }
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
