mod client_identity;
mod ingress;
mod public_url;
#[cfg(test)]
mod tests;

pub use client_identity::{
    detect_client_country, detect_client_country_from_headers, detect_client_ip,
    detect_client_ip_from_headers, trust_client_identity_headers,
};
pub use ingress::{ingress_host_allowed, ops_endpoint_access_allowed, origin_auth_allowed};
pub use public_url::{derive_public_base_url, detect_client_protocol, normalize_public_base_url};
