use axum::http::{Request, Uri, header};
use http::uri::Authority;

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

pub(super) fn request_authority<B>(req: &Request<B>) -> Option<Authority> {
    req.headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse().ok())
}

pub(super) fn parse_public_base_url(raw: &str) -> Result<(String, Authority), String> {
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

fn is_local_authority(authority: &Authority) -> bool {
    matches!(
        authority.host(),
        "localhost" | "127.0.0.1" | "::1" | "[::1]"
    )
}
