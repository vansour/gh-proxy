use crate::components::LinkFormat;

use super::normalize::normalize_github_resource;

#[derive(Clone, Debug)]
pub(super) struct GeneratedOutput {
    pub(super) text: String,
    pub(super) is_url: bool,
}

pub(super) fn build_output(
    raw_input: &str,
    format: LinkFormat,
    allowed_hosts: &[String],
    origin: &str,
    host: &str,
) -> Result<GeneratedOutput, String> {
    if format == LinkFormat::Docker {
        return build_docker_output(raw_input, host);
    }

    let parsed = normalize_github_resource(raw_input, allowed_hosts)?;
    let proxy_link = format!(
        "{}/{}{}{}{}",
        origin,
        parsed.hostname(),
        parsed.pathname(),
        parsed.search(),
        parsed.hash()
    );

    let text = match format {
        LinkFormat::Direct => proxy_link.clone(),
        LinkFormat::GitClone => format!("git clone {}", proxy_link),
        LinkFormat::Wget => format!("wget \"{}\"", proxy_link),
        LinkFormat::Curl => format!("curl -O \"{}\"", proxy_link),
        LinkFormat::Docker => unreachable!(),
    };

    Ok(GeneratedOutput {
        text,
        is_url: format == LinkFormat::Direct,
    })
}

pub(super) fn build_docker_output(raw_input: &str, host: &str) -> Result<GeneratedOutput, String> {
    let image = raw_input.trim();
    if image.is_empty() {
        return Err("Docker 模式请输入镜像名，例如 library/nginx:latest".to_string());
    }
    if image.contains(char::is_whitespace)
        || image.starts_with("http://")
        || image.starts_with("https://")
        || image.contains("github.com")
    {
        return Err("Docker 模式只接受镜像名，例如 library/nginx:latest".to_string());
    }

    Ok(GeneratedOutput {
        text: format!("docker pull {}/{}", host, image.trim_matches('/')),
        is_url: false,
    })
}
