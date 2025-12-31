use axum::{extract::State, Json};
use jsonwebtoken::{encode, Algorithm, Header};
use tracing::error;

use crate::error::{AppError, AppResult};
use crate::models::{SignRequest, SignResponse};
use crate::AppState;

/// POST /sign - Create a signed JWT
pub async fn sign_jwt(
    State(state): State<AppState>,
    Json(payload): Json<SignRequest>,
) -> AppResult<Json<SignResponse>> {
    // Extract header fields before consuming payload
    let kid = payload.kid.clone();
    let alg_str = payload.alg.clone();
    
    let alg_enum: Algorithm = alg_str
        .parse()
        .map_err(|_| AppError::UnsupportedAlgorithm(alg_str.clone()))?;

    let claims = payload.into_claims();
    
    let mut header = Header::default();
    if let Some(kid) = kid {
        header.kid = Some(kid);
    }

    header.alg = alg_enum;

    let token = match alg_enum {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let key = state.key_store.hmac_encoding_key()?;
            encode(&header, &claims, &key)
                .map_err(|e| {
                    error!("HMAC signing error: {}", e);
                    AppError::SigningError(e.to_string())
                })?
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let key = state.key_store.rsa_encoding_key()?;
            encode(&header, &claims, &key)
                .map_err(|e| {
                    error!("RSA signing error: {}", e);
                    AppError::SigningError(e.to_string())
                })?
        }
        Algorithm::ES256 => {
            let key = state.key_store.ec_encoding_key()?;
            encode(&header, &claims, &key)
                .map_err(|e| {
                    error!("ES256 signing error: {}", e);
                    AppError::SigningError(e.to_string())
                })?
        }
        Algorithm::ES384 => {
            let key = state.key_store.ec384_encoding_key()?;
            encode(&header, &claims, &key)
                .map_err(|e| {
                    error!("ES384 signing error: {}", e);
                    AppError::SigningError(e.to_string())
                })?
        }
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
            let key = state.key_store.pss_encoding_key()?;
            encode(&header, &claims, &key)
                .map_err(|e| {
                    error!("PSS signing error: {}", e);
                    AppError::SigningError(e.to_string())
                })?
        }
        _ => {
            return Err(AppError::UnsupportedAlgorithm(format!("{:?}", alg_enum)));
        }
    };

    Ok(Json(SignResponse { token }))
}
