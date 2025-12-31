use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Application error types with structured responses
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Missing configuration: {0}")]
    MissingConfig(String),

    #[error("Key access error: {0}")]
    KeyAccessError(String),

    #[error("Invalid token header: {0}")]
    InvalidTokenHeader(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("Token expired")]
    ExpiredSignature,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid audience")]
    InvalidAudience,

    #[error("Invalid issuer")]
    InvalidIssuer,

    #[error("Token is not yet valid (nbf claim)")]
    ImmatureSignature,

    #[error("Token is malformed or invalid")]
    InvalidToken,

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl AppError {
    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::UnsupportedAlgorithm(_) => StatusCode::BAD_REQUEST,
            Self::MissingConfig(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::KeyAccessError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::InvalidTokenHeader(_) => StatusCode::BAD_REQUEST,
            Self::SigningError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ExpiredSignature => StatusCode::UNAUTHORIZED,
            Self::InvalidSignature => StatusCode::UNAUTHORIZED,
            Self::InvalidAudience => StatusCode::BAD_REQUEST,
            Self::InvalidIssuer => StatusCode::BAD_REQUEST,
            Self::ImmatureSignature => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::BAD_REQUEST,
            Self::VerificationError(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error type string for API responses
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::UnsupportedAlgorithm(_) => "UnsupportedAlgorithm",
            Self::MissingConfig(_) => "MissingConfig",
            Self::KeyAccessError(_) => "KeyAccessError",
            Self::InvalidTokenHeader(_) => "InvalidTokenHeader",
            Self::SigningError(_) => "SignError",
            Self::ExpiredSignature => "ExpiredSignature",
            Self::InvalidSignature => "InvalidSignature",
            Self::InvalidAudience => "InvalidAudience",
            Self::InvalidIssuer => "InvalidIssuer",
            Self::ImmatureSignature => "ImmatureSignature",
            Self::InvalidToken => "InvalidToken",
            Self::VerificationError(_) => "VerificationError",
            Self::Unauthorized(_) => "Unauthorized",
            Self::RateLimitExceeded => "RateLimitExceeded",
            Self::Internal(_) => "InternalError",
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let body = Json(json!({
            "error_type": self.error_type(),
            "error_msg": self.to_string(),
        }));
        (status, body).into_response()
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match err.kind() {
            ErrorKind::ExpiredSignature => Self::ExpiredSignature,
            ErrorKind::InvalidSignature => Self::InvalidSignature,
            ErrorKind::InvalidAudience => Self::InvalidAudience,
            ErrorKind::InvalidIssuer => Self::InvalidIssuer,
            ErrorKind::ImmatureSignature => Self::ImmatureSignature,
            ErrorKind::InvalidToken => Self::InvalidToken,
            _ => Self::VerificationError(err.to_string()),
        }
    }
}

/// Result type alias for application errors
pub type AppResult<T> = Result<T, AppError>;
