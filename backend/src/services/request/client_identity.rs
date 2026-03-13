use axum::http::{HeaderMap, Request};
use std::net::{IpAddr, SocketAddr};

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
