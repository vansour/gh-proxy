use super::TextReplacementStream;
use bytes::{Bytes, BytesMut};
use futures_util::{StreamExt, stream};

async fn render(chunks: &[&str], proxy_url: &str) -> String {
    let input = stream::iter(
        chunks
            .iter()
            .map(|chunk| Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(chunk.as_bytes()))),
    );
    let mut stream = TextReplacementStream::new(input, proxy_url);
    let mut output = BytesMut::new();

    while let Some(chunk) = stream.next().await {
        output.extend_from_slice(&chunk.expect("stream chunk"));
    }

    String::from_utf8(output.to_vec()).expect("utf8 output")
}

#[tokio::test]
async fn replaces_github_urls_with_current_proxy() {
    let output = render(
        &["curl -L https://github.com/owner/repo/releases/download/v1.0.0/app.tgz"],
        "https://gh-proxy.example.com",
    )
    .await;

    assert_eq!(
        output,
        "curl -L https://gh-proxy.example.com/https://github.com/owner/repo/releases/download/v1.0.0/app.tgz"
    );
}

#[tokio::test]
async fn preserves_urls_already_proxied_by_current_instance_across_chunks() {
    let output = render(
        &[
            "prefix https://gh-proxy.example",
            ".com/https://github.com/owner/repo/blob/main/README.md suffix",
        ],
        "https://gh-proxy.example.com",
    )
    .await;

    assert_eq!(
        output,
        "prefix https://gh-proxy.example.com/https://github.com/owner/repo/blob/main/README.md suffix"
    );
}

#[tokio::test]
async fn rewrites_other_proxy_prefix_to_current_proxy() {
    let output = render(
        &[
            "wget https://old-proxy.example/",
            "https://raw.githubusercontent.com/owner/repo/main/file.txt",
        ],
        "https://gh-proxy.example.com",
    )
    .await;

    assert_eq!(
        output,
        "wget https://gh-proxy.example.com/https://raw.githubusercontent.com/owner/repo/main/file.txt"
    );
}
