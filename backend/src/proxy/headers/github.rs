use axum::http::{HeaderMap, HeaderValue, Uri};
use hyper::header;

pub fn apply_github_headers(headers: &mut HeaderMap, uri: &Uri, auth: Option<&HeaderValue>) {
    headers.remove(header::AUTHORIZATION);

    if let Some(auth) = auth
        && should_forward_github_auth(uri)
    {
        headers.insert(header::AUTHORIZATION, auth.clone());
    }
    headers.insert(
        header::USER_AGENT,
        HeaderValue::from_static(concat!("gh-proxy/", env!("CARGO_PKG_VERSION"))),
    );
}

fn should_forward_github_auth(uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };

    matches!(
        host,
        "github.com"
            | "api.github.com"
            | "raw.githubusercontent.com"
            | "codeload.github.com"
            | "gist.github.com"
    ) || host.ends_with(".github.com")
}

#[cfg(test)]
mod tests {
    use super::apply_github_headers;
    use axum::http::{HeaderMap, HeaderValue, Uri};
    use hyper::header;

    #[test]
    fn apply_github_headers_only_forwards_auth_to_safe_hosts() {
        let auth = HeaderValue::from_static("token secret");
        let mut github_headers = HeaderMap::new();
        apply_github_headers(
            &mut github_headers,
            &Uri::from_static("https://github.com/owner/repo/blob/main/file.txt"),
            Some(&auth),
        );
        assert_eq!(
            github_headers
                .get(header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok()),
            Some("token secret")
        );

        let mut asset_headers = HeaderMap::new();
        apply_github_headers(
            &mut asset_headers,
            &Uri::from_static(
                "https://objects.githubusercontent.com/github-production-release-asset",
            ),
            Some(&auth),
        );
        assert!(!asset_headers.contains_key(header::AUTHORIZATION));
    }
}
