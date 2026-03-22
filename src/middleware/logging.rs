use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

/// Request/response tracing middleware.
pub async fn logging_middleware(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let start = Instant::now();

    tracing::debug!(
        method = %method,
        path = %uri.path(),
        "incoming request"
    );

    let response = next.run(req).await;
    let elapsed = start.elapsed();

    tracing::debug!(
        method = %method,
        path = %uri.path(),
        status = %response.status(),
        duration_ms = %elapsed.as_millis(),
        "request completed"
    );

    response
}
