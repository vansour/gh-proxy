use axum::http::{HeaderMap, Request};
use std::net::SocketAddr;

use super::public_url::{parse_public_base_url, request_authority};

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

fn authority_matches_public(
    actual: &http::uri::Authority,
    expected: &http::uri::Authority,
    scheme: &str,
) -> bool {
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
