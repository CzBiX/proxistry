use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    /// Upstream registry returned an error
    #[error("upstream error ({status}): {message}")]
    Upstream { status: StatusCode, message: String },

    /// Registry blocked by whitelist
    #[error("registry blocked: {0}")]
    RegistryBlocked(String),

    /// Client sent an invalid request (bad format, etc.)
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Catch-all for internal / unexpected errors.
    /// Wraps an `anyhow::Error` so the full context chain is preserved.
    #[error(transparent)]
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, error_message) = match &self {
            AppError::Upstream { status, message } => (*status, "UPSTREAM_ERROR", message.clone()),
            AppError::RegistryBlocked(name) => (
                StatusCode::FORBIDDEN,
                "DENIED",
                format!("registry not allowed: {}", name),
            ),
            AppError::BadRequest(err) => {
                (StatusCode::BAD_REQUEST, "INVALID_REQUEST", err.to_string())
            }
            AppError::Internal(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                // Log the full chain but only expose a generic message to
                // the client.  The detailed chain is emitted via tracing below.
                format!("{:#}", err),
            ),
        };

        tracing::error!(%status, error = %error_message, "request error");

        let body = serde_json::json!({
            "errors": [{
                "code": code,
                "message": error_message,
            }]
        });

        (status, axum::Json(body)).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> AppError {
        match err.downcast::<AppError>() {
            Ok(err) => err,
            Err(err) => AppError::Internal(err),
        }
    }
}

impl From<reqwest::Error> for AppError {
    fn from(err: reqwest::Error) -> Self {
        if let Some(status) = err.status() {
            AppError::Upstream {
                status: StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::BAD_GATEWAY),
                message: err.to_string(),
            }
        } else {
            AppError::Internal(err.into())
        }
    }
}
