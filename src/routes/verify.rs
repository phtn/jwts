use axum::{extract::State, Json};
use jsonwebtoken::{decode, Algorithm, Validation};
use tracing::error;

use crate::error::{AppError, AppResult};
use crate::models::{Claims, VerifyRequest, VerifyResponse};
use crate::AppState;

/// POST /verify - Verify a JWT and return claims
pub async fn verify_jwt(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> AppResult<Json<VerifyResponse>> {
    // Decode header to get algorithm
    let header = jsonwebtoken::decode_header(&payload.token)
        .map_err(|e| AppError::InvalidTokenHeader(e.to_string()))?;

    let alg = header.alg;
    let mut validation = Validation::new(alg);

    // Set audience validation if configured
    if let Some(ref aud) = state.config.audience {
        validation.set_audience(&[aud]);
    }

    let claims = match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            let key = state.key_store.hmac_decoding_key()?;
            decode::<Claims>(&payload.token, &key, &validation)
                .map_err(|e| {
                    error!("HMAC verification error: {:?}", e);
                    AppError::from(e)
                })?
                .claims
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let key = state.key_store.rsa_decoding_key()?;
            decode::<Claims>(&payload.token, &key, &validation)
                .map_err(|e| {
                    error!("RSA verification error: {:?}", e);
                    AppError::from(e)
                })?
                .claims
        }
        Algorithm::ES256 => {
            let key = state.key_store.ec_decoding_key()?;
            decode::<Claims>(&payload.token, &key, &validation)
                .map_err(|e| {
                    error!("ES256 verification error: {:?}", e);
                    AppError::from(e)
                })?
                .claims
        }
        Algorithm::ES384 => {
            let key = state.key_store.ec384_decoding_key()?;
            decode::<Claims>(&payload.token, &key, &validation)
                .map_err(|e| {
                    error!("ES384 verification error: {:?}", e);
                    AppError::from(e)
                })?
                .claims
        }
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
            let key = state.key_store.pss_decoding_key()?;
            decode::<Claims>(&payload.token, &key, &validation)
                .map_err(|e| {
                    error!("PSS verification error: {:?}", e);
                    AppError::from(e)
                })?
                .claims
        }
        _ => {
            return Err(AppError::UnsupportedAlgorithm(format!("{:?}", alg)));
        }
    };

    Ok(Json(VerifyResponse { claims }))
}
