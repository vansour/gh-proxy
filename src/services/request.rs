use axum::extract::{Request, connect_info::ConnectInfo};
use std::net::{IpAddr, SocketAddr};
pub fn extract_client_ip(req: &Request<axum::body::Body>) -> Option<String> {
    if let Some(cf) = req.headers().get("cf-connecting-ip")
        && let Ok(ip) = cf.to_str()
        && let Some(addr) = parse_ip_literal(ip)
    {
        return Some(addr.to_string());
    }
    if let Some(xff) = req.headers().get("x-forwarded-for")
        && let Ok(xff_str) = xff.to_str()
    {
        for candidate in xff_str.split(',') {
            if let Some(ip) = parse_ip_literal(candidate) {
                return Some(ip.to_string());
            }
        }
    }
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
    if let Some(true_client) = req.headers().get("true-client-ip")
        && let Ok(ip) = true_client.to_str()
        && let Some(addr) = parse_ip_literal(ip)
    {
        return Some(addr.to_string());
    }
    if let Some(xri) = req.headers().get("x-real-ip")
        && let Ok(ip) = xri.to_str()
        && let Some(addr) = parse_ip_literal(ip)
    {
        return Some(addr.to_string());
    }
    if let Some(ConnectInfo(addr)) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return Some(addr.ip().to_string());
    }
    None
}
pub fn detect_client_protocol(req: &Request<axum::body::Body>) -> String {
    if let Some(cf_visitor) = req.headers().get("cf-visitor")
        && let Ok(visitor_str) = cf_visitor.to_str()
    {
        if visitor_str.contains("\"scheme\":\"https\"") {
            return "https".to_string();
        } else if visitor_str.contains("\"scheme\":\"http\"") {
            return "http".to_string();
        }
    }
    if let Some(forwarded) = req.headers().get("x-forwarded-proto")
        && let Ok(proto) = forwarded.to_str()
    {
        let proto_lower = proto.trim().to_lowercase();
        if proto_lower == "https" || proto_lower == "http" {
            return proto_lower;
        }
    }
    if let Some(scheme) = req.uri().scheme_str() {
        let scheme_lower = scheme.to_lowercase();
        if scheme_lower == "https" || scheme_lower == "http" {
            return scheme_lower;
        }
    }
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

    #[test]
    fn test_parse_ip_literal_ipv4() {
        assert_eq!(
            parse_ip_literal("192.168.1.1"),
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_parse_ip_literal_ipv6() {
        assert_eq!(
            parse_ip_literal("::1"),
            Some("::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_parse_ip_literal_with_quotes() {
        assert_eq!(
            parse_ip_literal("\"192.168.1.1\""),
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_parse_ip_literal_with_whitespace() {
        assert_eq!(
            parse_ip_literal("  192.168.1.1  "),
            Some("192.168.1.1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_parse_ip_literal_ipv6_bracket() {
        assert_eq!(
            parse_ip_literal("[::1]"),
            Some("::1".parse::<IpAddr>().unwrap())
        );
    }

    #[test]
    fn test_parse_ip_literal_socket_addr() {
        let result = parse_ip_literal("192.168.1.1:8080");
        assert_eq!(result, Some("192.168.1.1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn test_parse_ip_literal_invalid() {
        assert_eq!(parse_ip_literal("not-an-ip"), None);
        assert_eq!(parse_ip_literal("invalid.address.value"), None);
    }

    #[test]
    fn test_detect_client_protocol_defaults_to_https() {
        use axum::body::Body;
        use axum::http::Request;

        let req = Request::builder()
            .method("GET")
            .uri("https://example.com/")
            .body(Body::empty())
            .unwrap();

        // Without special headers or localhost pattern, should return https as default
        let protocol = detect_client_protocol(&req);
        assert_eq!(protocol, "https");
    }

    #[test]
    fn test_detect_client_protocol_localhost_returns_http() {
        use axum::body::Body;
        use axum::http::Request;

        let req = Request::builder()
            .method("GET")
            .uri("http://localhost:3000/")
            .header("host", "localhost:3000")
            .body(Body::empty())
            .unwrap();

        let protocol = detect_client_protocol(&req);
        assert_eq!(protocol, "http");
    }

    #[test]
    fn test_detect_client_protocol_127_0_0_1() {
        use axum::body::Body;
        use axum::http::Request;

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("host", "127.0.0.1:8080")
            .body(Body::empty())
            .unwrap();

        let protocol = detect_client_protocol(&req);
        assert_eq!(protocol, "http");
    }

    #[test]
    fn test_detect_client_protocol_x_forwarded_proto() {
        use axum::body::Body;
        use axum::http::Request;

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap();

        let protocol = detect_client_protocol(&req);
        assert_eq!(protocol, "https");
    }

    #[test]
    fn test_detect_client_protocol_cf_visitor() {
        use axum::body::Body;
        use axum::http::Request;

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("cf-visitor", "{\"scheme\":\"https\"}")
            .body(Body::empty())
            .unwrap();

        let protocol = detect_client_protocol(&req);
        assert_eq!(protocol, "https");
    }

    #[test]
    fn test_detect_client_protocol_cf_visitor_http() {
        use axum::body::Body;
        use axum::http::Request;

        let req = Request::builder()
            .method("GET")
            .uri("http://example.com/")
            .header("cf-visitor", "{\"scheme\":\"http\"}")
            .body(Body::empty())
            .unwrap();

        let protocol = detect_client_protocol(&req);
        assert_eq!(protocol, "http");
    }
}
