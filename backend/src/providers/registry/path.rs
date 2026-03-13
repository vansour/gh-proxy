#[derive(Debug, PartialEq)]
pub enum V2Endpoint {
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    BlobUploadInit { name: String },
    BlobUploadComplete { name: String, uuid: String },
    Unknown,
}

pub fn parse_v2_path(rest: &str) -> V2Endpoint {
    let parts: Vec<&str> = rest.split('/').filter(|part| !part.is_empty()).collect();
    if let Some(i) = parts.iter().position(|&p| p == "manifests")
        && i + 1 < parts.len()
    {
        let name = parts[..i].join("/");
        let reference = parts[i + 1].to_string();
        return V2Endpoint::Manifest { name, reference };
    }
    if let Some(i) = parts.iter().position(|&p| p == "blobs") {
        if i + 2 < parts.len() && parts[i + 1] == "uploads" {
            let name = parts[..i].join("/");
            let uuid = parts[i + 2].to_string();
            return V2Endpoint::BlobUploadComplete { name, uuid };
        }
        if i + 1 < parts.len() && parts[i + 1] == "uploads" {
            let name = parts[..i].join("/");
            return V2Endpoint::BlobUploadInit { name };
        }
        if i + 1 < parts.len() {
            let name = parts[..i].join("/");
            let digest = parts[i + 1].to_string();
            return V2Endpoint::Blob { name, digest };
        }
    }
    V2Endpoint::Unknown
}

#[cfg(test)]
mod tests {
    use super::{V2Endpoint, parse_v2_path};

    #[test]
    fn parse_v2_path_handles_manifest_and_blob_routes() {
        assert_eq!(
            parse_v2_path("library/nginx/manifests/latest"),
            V2Endpoint::Manifest {
                name: "library/nginx".to_string(),
                reference: "latest".to_string(),
            }
        );
        assert_eq!(
            parse_v2_path("library/nginx/blobs/sha256:abc"),
            V2Endpoint::Blob {
                name: "library/nginx".to_string(),
                digest: "sha256:abc".to_string(),
            }
        );
    }

    #[test]
    fn parse_v2_path_handles_upload_routes() {
        assert_eq!(
            parse_v2_path("library/nginx/blobs/uploads"),
            V2Endpoint::BlobUploadInit {
                name: "library/nginx".to_string(),
            }
        );
        assert_eq!(
            parse_v2_path("library/nginx/blobs/uploads/uuid-1"),
            V2Endpoint::BlobUploadComplete {
                name: "library/nginx".to_string(),
                uuid: "uuid-1".to_string(),
            }
        );
    }
}
