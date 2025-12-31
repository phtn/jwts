use axum::{extract::State, Json};

use crate::models::{HealthResponse, ReadyResponse};
use crate::AppState;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// GET /health - Liveness probe
/// Always returns 200 OK if the service is running
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: VERSION,
    })
}

/// GET /ready - Readiness probe
/// Returns service readiness status and key availability
pub async fn ready(State(state): State<AppState>) -> Json<ReadyResponse> {
    Json(ReadyResponse {
        status: "ready",
        signing_available: state.key_store.has_signing_capability(),
        verification_available: state.key_store.has_verification_capability(),
    })
}
