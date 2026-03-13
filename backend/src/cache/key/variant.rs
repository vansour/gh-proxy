use axum::http::{HeaderMap, header};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

fn normalized_header_values(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    let values = headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::trim))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    if values.is_empty() {
        None
    } else {
        Some(values.join(","))
    }
}

pub fn request_variant_key(headers: &HeaderMap) -> Option<u64> {
    let mut hasher = DefaultHasher::new();
    let mut has_values = false;

    for (name, value) in [("accept", normalized_header_values(headers, header::ACCEPT))] {
        if let Some(value) = value {
            has_values = true;
            name.hash(&mut hasher);
            value.hash(&mut hasher);
        }
    }

    has_values.then(|| hasher.finish())
}
