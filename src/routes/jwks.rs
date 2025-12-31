use axum::{extract::State, Json};

use crate::keys::Jwks;
use crate::AppState;

/// GET /.well-known/jwks.json - Return JSON Web Key Set
pub async fn get_jwks(State(state): State<AppState>) -> Json<Jwks> {
    Json(state.jwks.clone())
}
