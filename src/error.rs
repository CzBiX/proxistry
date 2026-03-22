use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use std::fmt;

#[derive(Debug)]
pub enum AppError {
    /// Upstream registry returned an error
    Upstream { status: StatusCode, message: String },
    /// Authentication failure
    Auth(String),
    /// Registry blocked by whitelist
    RegistryBlocked(String),
    /// Cache I/O error
    Cache(String),
    /// Configuration error
    Config(String),
    /// Internal error
    Internal(String),
    /// Client sent an invalid request (bad format, etc.)
    BadRequest(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Upstream { status, message } => {
                write!(f, "upstream error ({}): {}", status, message)
            }
            AppError::Auth(msg) => write!(f, "auth error: {}", msg),
            AppError::RegistryBlocked(name) => write!(f, "registry blocked: {}", name),
            AppError::Cache(msg) => write!(f, "cache error: {}", msg),
            AppError::Config(msg) => write!(f, "config error: {}", msg),
            AppError::Internal(msg) => write!(f, "internal error: {}", msg),
            AppError::BadRequest(msg) => write!(f, "bad request: {}", msg),
        }
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match &self {
            AppError::Upstream { status, message } => (*status, message.clone()),
            AppError::Auth(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::RegistryBlocked(name) => (
                StatusCode::FORBIDDEN,
                format!("registry not allowed: {}", name),
            ),
            AppError::Cache(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("cache error: {}", msg),
            ),
            AppError::Config(msg) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("config error: {}", msg),
            ),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
        };

        tracing::error!(%status, error = %error_message, "request error");

        let body = serde_json::json!({
            "errors": [{
                "code": match &self {
                    AppError::Upstream { .. } => "UPSTREAM_ERROR",
                    AppError::Auth(_) => "UNAUTHORIZED",
                    AppError::RegistryBlocked(_) => "DENIED",
                    AppError::Cache(_) => "CACHE_ERROR",
                    AppError::Config(_) => "CONFIG_ERROR",
                    AppError::Internal(_) => "INTERNAL_ERROR",
                    AppError::BadRequest(_) => "INVALID_REQUEST",
                },
                "message": error_message,
            }]
        });

        (status, axum::Json(body)).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err.to_string())
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Cache(err.to_string())
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
            AppError::Internal(err.to_string())
        }
    }
}

pub type AppResult<T> = Result<T, AppError>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::response::IntoResponse;

    #[test]
    fn test_display_upstream() {
        let err = AppError::Upstream {
            status: StatusCode::NOT_FOUND,
            message: "not found".into(),
        };
        assert_eq!(
            format!("{}", err),
            "upstream error (404 Not Found): not found"
        );
    }

    #[test]
    fn test_display_auth() {
        let err = AppError::Auth("invalid token".into());
        assert_eq!(format!("{}", err), "auth error: invalid token");
    }

    #[test]
    fn test_display_registry_blocked() {
        let err = AppError::RegistryBlocked("evil.io".into());
        assert_eq!(format!("{}", err), "registry blocked: evil.io");
    }

    #[test]
    fn test_display_cache() {
        let err = AppError::Cache("disk full".into());
        assert_eq!(format!("{}", err), "cache error: disk full");
    }

    #[test]
    fn test_display_config() {
        let err = AppError::Config("missing field".into());
        assert_eq!(format!("{}", err), "config error: missing field");
    }

    #[test]
    fn test_display_internal() {
        let err = AppError::Internal("panic".into());
        assert_eq!(format!("{}", err), "internal error: panic");
    }

    #[test]
    fn test_into_response_upstream_preserves_status() {
        let err = AppError::Upstream {
            status: StatusCode::NOT_FOUND,
            message: "manifest unknown".into(),
        };
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_into_response_auth_returns_401() {
        let err = AppError::Auth("unauthorized".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_into_response_registry_blocked_returns_403() {
        let err = AppError::RegistryBlocked("blocked.io".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_into_response_cache_returns_500() {
        let err = AppError::Cache("io error".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_into_response_config_returns_500() {
        let err = AppError::Config("bad config".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_into_response_internal_returns_500() {
        let err = AppError::Internal("something broke".into());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn test_from_anyhow_error() {
        let anyhow_err = anyhow::anyhow!("something went wrong");
        let app_err: AppError = anyhow_err.into();
        assert!(matches!(app_err, AppError::Internal(msg) if msg.contains("something went wrong")));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let app_err: AppError = io_err.into();
        assert!(matches!(app_err, AppError::Cache(msg) if msg.contains("file not found")));
    }
}
