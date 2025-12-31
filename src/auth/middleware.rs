use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

/// API key authentication middleware
/// 
/// If `api_key` is Some, requires X-API-Key header to match.
/// If `api_key` is None, authentication is disabled (all requests pass).
pub async fn api_key_auth(
    api_key: Option<String>,
    request: Request,
    next: Next,
) -> Response {
    // If no API key is configured, skip authentication
    let Some(expected_key) = api_key else {
        return next.run(request).await;
    };

    // Extract X-API-Key header
    let provided_key = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok());

    match provided_key {
        Some(key) if key == expected_key => {
            // Key matches, proceed
            next.run(request).await
        }
        Some(_) => {
            // Key provided but doesn't match
            unauthorized_response("Invalid API key")
        }
        None => {
            // No key provided
            unauthorized_response("Missing X-API-Key header")
        }
    }
}

fn unauthorized_response(message: &str) -> Response {
    let body = Json(json!({
        "error_type": "Unauthorized",
        "error_msg": message,
    }));
    (StatusCode::UNAUTHORIZED, body).into_response()
}

/// Check if a path should skip authentication
pub fn should_skip_auth(path: &str) -> bool {
    matches!(
        path,
        "/health" | "/ready" | "/.well-known/jwks.json"
    )
}
