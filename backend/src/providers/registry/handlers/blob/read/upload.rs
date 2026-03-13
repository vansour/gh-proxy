use crate::state::AppState;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub(in crate::providers::registry::handlers) async fn initiate_blob_upload(
    _state: State<AppState>,
    Path(_name): Path<String>,
) -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        "Read-only registry proxy: push is not supported",
    )
        .into_response()
}
