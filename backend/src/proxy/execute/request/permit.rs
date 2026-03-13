use std::time::Instant;

use crate::errors::{ProxyError, ProxyResult};
use crate::infra;
use crate::middleware::RequestPermitGuard;
use crate::state::AppState;

pub(in crate::proxy::execute) async fn acquire_request_permit(
    state: &AppState,
    start: Instant,
) -> ProxyResult<RequestPermitGuard> {
    let permit = state
        .download_semaphore
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| ProxyError::TooManyConcurrentRequests)?;
    infra::metrics::HTTP_ACTIVE_REQUESTS.inc();
    Ok(RequestPermitGuard::new(permit, start))
}
