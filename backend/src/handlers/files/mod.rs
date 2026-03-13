mod assets;
mod cache;
mod paths;
mod responses;

pub use assets::{index, serve_favicon, serve_static_asset};

#[cfg(test)]
mod tests;
