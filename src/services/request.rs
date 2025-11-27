use axum::extract::Request;
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
