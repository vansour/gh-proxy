use axum::http::{HeaderMap, HeaderValue};
use hyper::header;
use std::collections::BTreeSet;

pub fn add_vary_header(headers: &mut HeaderMap) {
    let Some(value) = merged_vary_header_value(headers.get(header::VARY)) else {
        return;
    };

    headers.insert(header::VARY, value);
}

fn merged_vary_header_value(existing: Option<&HeaderValue>) -> Option<HeaderValue> {
    if let Some(existing) = existing
        && let Ok(existing) = existing.to_str()
        && existing.split(',').map(str::trim).any(|token| token == "*")
    {
        return Some(HeaderValue::from_static("*"));
    }

    let mut tokens = BTreeSet::new();
    if let Some(existing) = existing
        && let Ok(existing) = existing.to_str()
    {
        for token in existing
            .split(',')
            .map(str::trim)
            .filter(|token| !token.is_empty())
        {
            tokens.insert(token.to_ascii_lowercase());
        }
    }

    tokens.insert("accept".to_string());

    let merged = tokens
        .into_iter()
        .map(|token| match token.as_str() {
            "accept" => "Accept".to_string(),
            _ => token,
        })
        .collect::<Vec<_>>()
        .join(", ");

    HeaderValue::from_str(&merged).ok()
}

#[cfg(test)]
mod tests {
    use super::add_vary_header;
    use axum::http::{HeaderMap, HeaderValue};
    use hyper::header;

    #[test]
    fn add_vary_header_merges_existing_tokens_without_overwriting() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));

        add_vary_header(&mut headers);

        assert_eq!(
            headers
                .get(header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("Accept, origin")
        );
    }

    #[test]
    fn add_vary_header_preserves_vary_star() {
        let mut headers = HeaderMap::new();
        headers.insert(header::VARY, HeaderValue::from_static("*"));

        add_vary_header(&mut headers);

        assert_eq!(
            headers
                .get(header::VARY)
                .and_then(|value| value.to_str().ok()),
            Some("*")
        );
    }
}
