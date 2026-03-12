use axum::http::{HeaderMap, Request, Uri, header};
use http::uri::Authority;
use std::net::{IpAddr, SocketAddr};

pub fn detect_client_protocol<B>(req: &Request<B>) -> &'static str {
    if let Some(cf_visitor) = req.headers().get("cf-visitor")
        && let Ok(visitor_str) = cf_visitor.to_str()
    {
        if visitor_str.contains("\"scheme\":\"https\"") {
            return "https";
        } else if visitor_str.contains("\"scheme\":\"http\"") {
            return "http";
        }
    }

    if let Some(forwarded) = req.headers().get("x-forwarded-proto")
        && let Ok(proto) = forwarded.to_str()
    {
        let proto = proto.trim();
        if proto.eq_ignore_ascii_case("https") {
            return "https";
        }
        if proto.eq_ignore_ascii_case("http") {
            return "http";
        }
    }

    if let Some(scheme) = req.uri().scheme_str() {
        if scheme.eq_ignore_ascii_case("https") {
            return "https";
        }
        if scheme.eq_ignore_ascii_case("http") {
            return "http";
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
        return "http";
    }

    "https"
}

pub fn normalize_public_base_url(raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("value cannot be empty".to_string());
    }

    let uri: Uri = value
        .parse()
        .map_err(|err| format!("must be an absolute http(s) URL: {}", err))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "scheme is required".to_string())?;
    if !matches!(scheme, "http" | "https") {
        return Err("scheme must be http or https".to_string());
    }
    let authority = uri
        .authority()
        .ok_or_else(|| "host is required".to_string())?;
    if uri.path() != "/" {
        return Err("path must be empty or '/'".to_string());
    }
    if uri.query().is_some() {
        return Err("query is not allowed".to_string());
    }

    Ok(format!("{}://{}", scheme, authority.as_str()))
}

pub fn derive_public_base_url<B>(req: &Request<B>, configured: &str) -> Option<String> {
    let configured = configured.trim();
    if !configured.is_empty() {
        return normalize_public_base_url(configured).ok();
    }

    let authority = request_authority(req)?;
    if !is_local_authority(&authority) {
        return None;
    }

    Some(format!(
        "{}://{}",
        detect_client_protocol(req),
        authority.as_str()
    ))
}

pub fn ingress_host_allowed<B>(req: &Request<B>, addr: SocketAddr, configured: &str) -> bool {
    if addr.ip().is_loopback() {
        return true;
    }

    let configured = configured.trim();
    if configured.is_empty() {
        return true;
    }

    let Some(actual) = request_authority(req) else {
        return false;
    };
    let Ok((scheme, expected)) = parse_public_base_url(configured) else {
        return false;
    };

    authority_matches_public(&actual, &expected, &scheme)
}

pub fn ops_endpoint_access_allowed(addr: SocketAddr, explicitly_enabled: bool) -> bool {
    explicitly_enabled || addr.ip().is_loopback()
}

pub fn origin_auth_allowed(
    headers: &HeaderMap,
    addr: SocketAddr,
    header_name: &str,
    expected_value: &str,
) -> bool {
    if addr.ip().is_loopback() || expected_value.is_empty() {
        return true;
    }

    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        == Some(expected_value)
}

pub fn trust_client_identity_headers(addr: Option<SocketAddr>, origin_auth_enabled: bool) -> bool {
    origin_auth_enabled || addr.map(|addr| addr.ip().is_loopback()).unwrap_or(false)
}

pub fn detect_client_ip<B>(
    req: &Request<B>,
    addr: Option<SocketAddr>,
    trust_forwarded_headers: bool,
) -> String {
    detect_client_ip_from_headers(req.headers(), addr, trust_forwarded_headers)
}

pub fn detect_client_ip_from_headers(
    headers: &HeaderMap,
    addr: Option<SocketAddr>,
    trust_forwarded_headers: bool,
) -> String {
    let forwarded_ip = trust_forwarded_headers
        .then(|| {
            header_ip(headers, "cf-connecting-ip")
                .or_else(|| first_x_forwarded_for_ip(headers))
                .or_else(|| header_ip(headers, "x-real-ip"))
                .or_else(|| forwarded_for_ip(headers))
        })
        .flatten();

    forwarded_ip
        .or_else(|| addr.map(|addr| addr.ip()))
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

pub fn detect_client_country<B>(req: &Request<B>, trust_forwarded_headers: bool) -> Option<String> {
    detect_client_country_from_headers(req.headers(), trust_forwarded_headers)
}

pub fn detect_client_country_from_headers(
    headers: &HeaderMap,
    trust_forwarded_headers: bool,
) -> Option<String> {
    if !trust_forwarded_headers {
        return None;
    }

    headers
        .get("cf-ipcountry")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn header_ip(headers: &HeaderMap, name: &str) -> Option<IpAddr> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(parse_ip)
}

fn first_x_forwarded_for_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').find_map(parse_ip))
}

fn forwarded_for_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("forwarded")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_forwarded_for)
}

fn parse_ip(value: &str) -> Option<IpAddr> {
    value.trim().parse().ok()
}

fn parse_forwarded_for(value: &str) -> Option<IpAddr> {
    for entry in value.split(',') {
        for param in entry.split(';') {
            let Some((name, raw_value)) = param.trim().split_once('=') else {
                continue;
            };
            if !name.trim().eq_ignore_ascii_case("for") {
                continue;
            }

            let candidate = raw_value.trim().trim_matches('"');
            let host = if let Some(rest) = candidate.strip_prefix('[') {
                rest.split(']').next()
            } else if let Some((host, port)) = candidate.rsplit_once(':') {
                if port.chars().all(|ch| ch.is_ascii_digit()) {
                    Some(host)
                } else {
                    Some(candidate)
                }
            } else {
                Some(candidate)
            };

            if let Some(ip) = host.and_then(parse_ip) {
                return Some(ip);
            }
        }
    }

    None
}

fn request_authority<B>(req: &Request<B>) -> Option<Authority> {
    req.headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
}

fn parse_public_base_url(raw: &str) -> Result<(String, Authority), String> {
    let normalized = normalize_public_base_url(raw)?;
    let uri: Uri = normalized
        .parse()
        .map_err(|err| format!("must be an absolute http(s) URL: {}", err))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "scheme is required".to_string())?
        .to_string();
    let authority = uri
        .authority()
        .cloned()
        .ok_or_else(|| "host is required".to_string())?;

    Ok((scheme, authority))
}

fn authority_matches_public(actual: &Authority, expected: &Authority, scheme: &str) -> bool {
    if !actual.host().eq_ignore_ascii_case(expected.host()) {
        return false;
    }

    match (expected.port_u16(), actual.port_u16()) {
        (Some(expected_port), Some(actual_port)) => expected_port == actual_port,
        (Some(_), None) => false,
        (None, None) => true,
        (None, Some(actual_port)) => default_port_for_scheme(scheme) == Some(actual_port),
    }
}

fn default_port_for_scheme(scheme: &str) -> Option<u16> {
    match scheme {
        "http" => Some(80),
        "https" => Some(443),
        _ => None,
    }
}

fn is_local_authority(authority: &Authority) -> bool {
    matches!(
        authority.host(),
        "localhost" | "127.0.0.1" | "::1" | "[::1]"
    )
}

#[cfg(test)]
mod tests {
    use super::{
        derive_public_base_url, detect_client_country_from_headers, detect_client_ip,
        detect_client_ip_from_headers, detect_client_protocol, ingress_host_allowed,
        normalize_public_base_url, ops_endpoint_access_allowed, origin_auth_allowed,
        trust_client_identity_headers,
    };
    use axum::{
        body::Body,
        http::{HeaderMap, Request},
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

    #[test]
    fn detect_client_protocol_prefers_cf_visitor() {
        let req = Request::builder()
            .uri("/https://github.com/openai/gpt")
            .header("cf-visitor", r#"{"scheme":"https"}"#)
            .header("x-forwarded-proto", "http")
            .body(Body::empty())
            .expect("request");

        assert_eq!(detect_client_protocol(&req), "https");
    }

    #[test]
    fn detect_client_protocol_accepts_forwarded_proto_case_insensitively() {
        let req = Request::builder()
            .uri("/https://github.com/openai/gpt")
            .header("x-forwarded-proto", "HTTP")
            .body(Body::empty())
            .expect("request");

        assert_eq!(detect_client_protocol(&req), "http");
    }

    #[test]
    fn detect_client_protocol_falls_back_to_http_for_localhost() {
        let req = Request::builder()
            .uri("/https://github.com/openai/gpt")
            .header("host", "localhost:8080")
            .body(Body::empty())
            .expect("request");

        assert_eq!(detect_client_protocol(&req), "http");
    }

    #[test]
    fn detect_client_ip_prefers_cf_connecting_ip() {
        let req = Request::builder()
            .uri("/https://github.com/openai/gpt")
            .header("cf-connecting-ip", "198.51.100.7")
            .header("x-forwarded-for", "203.0.113.1, 203.0.113.2")
            .body(Body::empty())
            .expect("request");

        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080));
        assert_eq!(detect_client_ip(&req, Some(addr), true), "198.51.100.7");
    }

    #[test]
    fn detect_client_ip_falls_back_to_forwarded_headers_and_socket() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "203.0.113.8, 203.0.113.9".parse().unwrap(),
        );
        assert_eq!(
            detect_client_ip_from_headers(&headers, None, true),
            "203.0.113.8".to_string()
        );

        headers.clear();
        headers.insert(
            "forwarded",
            "for=\"[2001:db8:cafe::17]:4711\";proto=https"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            detect_client_ip_from_headers(&headers, None, true),
            "2001:db8:cafe::17".to_string()
        );

        headers.clear();
        headers.insert("cf-connecting-ip", "not-an-ip".parse().unwrap());
        let socket_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let addr = SocketAddr::new(socket_ip, 8080);
        assert_eq!(
            detect_client_ip_from_headers(&headers, Some(addr), true),
            "127.0.0.1"
        );
    }

    #[test]
    fn detect_client_country_reads_cloudflare_country() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-ipcountry", "US".parse().unwrap());

        assert_eq!(
            detect_client_country_from_headers(&headers, true),
            Some("US".to_string())
        );
    }

    #[test]
    fn detect_client_identity_headers_are_ignored_when_source_is_untrusted() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "198.51.100.7".parse().unwrap());
        headers.insert(
            "x-forwarded-for",
            "203.0.113.8, 203.0.113.9".parse().unwrap(),
        );
        headers.insert("cf-ipcountry", "US".parse().unwrap());
        let socket_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
        let addr = SocketAddr::new(socket_ip, 8443);

        assert_eq!(
            detect_client_ip_from_headers(&headers, Some(addr), false),
            "192.0.2.44"
        );
        assert_eq!(detect_client_country_from_headers(&headers, false), None);
    }

    #[test]
    fn normalize_public_base_url_accepts_origin_only() {
        assert_eq!(
            normalize_public_base_url("https://proxy.example.com/").unwrap(),
            "https://proxy.example.com"
        );
        assert_eq!(
            normalize_public_base_url("http://proxy.example.com:8443").unwrap(),
            "http://proxy.example.com:8443"
        );
    }

    #[test]
    fn normalize_public_base_url_rejects_paths_and_queries() {
        assert!(normalize_public_base_url("https://proxy.example.com/app").is_err());
        assert!(normalize_public_base_url("https://proxy.example.com/?x=1").is_err());
        assert!(normalize_public_base_url("ftp://proxy.example.com").is_err());
    }

    #[test]
    fn derive_public_base_url_prefers_configured_value() {
        let req = Request::builder()
            .uri("/https://github.com/openai/gpt")
            .header("host", "evil.example")
            .body(Body::empty())
            .expect("request");

        assert_eq!(
            derive_public_base_url(&req, "https://proxy.example.com").as_deref(),
            Some("https://proxy.example.com")
        );
    }

    #[test]
    fn derive_public_base_url_only_auto_derives_for_localhost() {
        let local_req = Request::builder()
            .uri("/https://github.com/openai/gpt")
            .header("host", "localhost:8080")
            .body(Body::empty())
            .expect("request");
        assert_eq!(
            derive_public_base_url(&local_req, "").as_deref(),
            Some("http://localhost:8080")
        );

        let remote_req = Request::builder()
            .uri("/https://github.com/openai/gpt")
            .header("host", "edge.example.com")
            .header("cf-visitor", r#"{"scheme":"https"}"#)
            .body(Body::empty())
            .expect("request");
        assert_eq!(derive_public_base_url(&remote_req, ""), None);
    }

    #[test]
    fn ingress_host_allowed_accepts_loopback_and_configured_public_host() {
        let loopback_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let req = Request::builder()
            .uri("/api/config")
            .header("host", "evil.example")
            .body(Body::empty())
            .expect("request");
        assert!(ingress_host_allowed(
            &req,
            loopback_addr,
            "https://proxy.example.com"
        ));

        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 443));
        let req = Request::builder()
            .uri("/api/config")
            .header("host", "proxy.example.com:443")
            .body(Body::empty())
            .expect("request");
        assert!(ingress_host_allowed(
            &req,
            remote_addr,
            "https://proxy.example.com"
        ));
    }

    #[test]
    fn ingress_host_allowed_rejects_unexpected_remote_host() {
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 443));
        let req = Request::builder()
            .uri("/api/config")
            .header("host", "evil.example")
            .body(Body::empty())
            .expect("request");

        assert!(!ingress_host_allowed(
            &req,
            remote_addr,
            "https://proxy.example.com"
        ));
    }

    #[test]
    fn ops_endpoint_access_only_allows_loopback_when_disabled() {
        let loopback_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9090));
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 9090));

        assert!(ops_endpoint_access_allowed(loopback_addr, false));
        assert!(!ops_endpoint_access_allowed(remote_addr, false));
        assert!(ops_endpoint_access_allowed(remote_addr, true));
    }

    #[test]
    fn origin_auth_allowed_only_bypasses_for_loopback_or_matching_secret() {
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 443));
        let loopback_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let mut headers = HeaderMap::new();

        assert!(!origin_auth_allowed(
            &headers,
            remote_addr,
            "x-gh-proxy-origin-auth",
            "secret"
        ));

        headers.insert("x-gh-proxy-origin-auth", "secret".parse().unwrap());
        assert!(origin_auth_allowed(
            &headers,
            remote_addr,
            "x-gh-proxy-origin-auth",
            "secret"
        ));
        assert!(origin_auth_allowed(
            &HeaderMap::new(),
            loopback_addr,
            "x-gh-proxy-origin-auth",
            "secret"
        ));
        assert!(origin_auth_allowed(
            &HeaderMap::new(),
            remote_addr,
            "x-gh-proxy-origin-auth",
            ""
        ));
    }

    #[test]
    fn trust_client_identity_headers_requires_loopback_or_origin_auth() {
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 10), 443));
        let loopback_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));

        assert!(trust_client_identity_headers(Some(loopback_addr), false));
        assert!(trust_client_identity_headers(Some(remote_addr), true));
        assert!(!trust_client_identity_headers(Some(remote_addr), false));
        assert!(!trust_client_identity_headers(None, false));
    }
}
