//! Docker Registry V2 proxy implementation using hyper client.

mod client;
mod handlers;
mod path;

pub use client::DockerProxy;
pub use handlers::{
    debug_blob_info, handle_v2_check, healthz, v2_get, v2_head, v2_patch, v2_post, v2_put,
};
pub use path::{V2Endpoint, parse_v2_path};
