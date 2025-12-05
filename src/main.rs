use axum::response::Response;
use axum::{Json, Router, http::StatusCode, response::IntoResponse, routing::get, routing::post};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tracing::{error, info};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    aud: String,
    custom: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignRequest {
    sub: String,
    exp: usize,
    iat: usize,
    iss: String,
    aud: String,
    custom: Option<String>,
    kid: Option<String>,
    alg: String,
}

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    token: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    error_type: &'static str,
    error_msg: String,
}

impl ApiError {
    fn new(status: StatusCode, error_type: &'static str, error_msg: impl Into<String>) -> Self {
        Self {
            status,
            error_type,
            error_msg: error_msg.into(),
        }
    }
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error_type": self.error_type,
            "error_msg": self.error_msg,
        }));
        (self.status, body).into_response()
    }
}

// Helper to load key from file specified in env var
fn load_key(env_var: &str) -> Result<Vec<u8>, ApiError> {
    match env::var(env_var) {
        Ok(path) => match fs::read(&path) {
            Ok(key) => Ok(key),
            Err(e) => {
                error!("Failed to read key file at {}: {}", path, e);
                Err(ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KeyAccessError",
                    format!("Could not read key file specified in {}: {}", env_var, e),
                ))
            }
        },
        Err(_) => {
            error!("Environment variable {} is not set", env_var);
            Err(ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "MissingConfig",
                format!("Environment variable {} is not set", env_var),
            ))
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    // We allow starting without JWT_SECRET if not using HS algorithms,
    // but we should check it when needed.
    // However, existing logic passes it to handlers.
    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "".to_string());

    if secret.is_empty() {
        info!("JWT_SECRET not set. HMAC signing/verification will fail if attempted.");
    }

    let app = Router::new()
        .route(
            "/sign",
            post({
                let secret = secret.clone();
                move |payload| sign_jwt(payload, secret.clone())
            }),
        )
        .route(
            "/verify",
            post({
                let secret = secret.clone();
                move |payload| verify_jwt(payload, secret.clone())
            }),
        )
        .route("/getenvs", get(envs));

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("𝚓𝚠𝚝𝚜 0.1.32 listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

async fn sign_jwt(Json(payload): Json<SignRequest>, secret: String) -> impl IntoResponse {
    let claims = Claims {
        sub: payload.sub,
        exp: payload.exp,
        iat: payload.iat,
        iss: payload.iss,
        aud: payload.aud,
        custom: payload.custom,
    };
    let mut header = Header::default();
    if let Some(kid) = payload.kid {
        header.kid = Some(kid);
    }

    let alg_enum = match payload.alg.parse::<Algorithm>() {
        Ok(a) => a,
        Err(_) => {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "UnsupportedAlgorithm",
                format!("Algorithm '{}' is not supported", payload.alg),
            )
            .into_response();
        }
    };

    header.alg = alg_enum;

    let result = match alg_enum {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret.is_empty() {
                return ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "MissingConfig",
                    "JWT_SECRET is not configured for HMAC signing",
                )
                .into_response();
            }
            encode(
                &header,
                &claims,
                &EncodingKey::from_secret(secret.as_bytes()),
            )
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let key_data = match load_key("JWT_PRIVATE_KEY") {
                Ok(k) => k,
                Err(e) => return e.into_response(),
            };
            match EncodingKey::from_rsa_pem(&key_data) {
                Ok(k) => encode(&header, &claims, &k),
                Err(e) => Err(jsonwebtoken::errors::Error::from(e)), // Convert to jsonwebtoken Error to match arm types
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let key_data = match load_key("JWT_EC_PRIVATE_KEY") {
                Ok(k) => k,
                Err(e) => return e.into_response(),
            };
            match EncodingKey::from_ec_pem(&key_data) {
                Ok(k) => encode(&header, &claims, &k),
                Err(e) => Err(jsonwebtoken::errors::Error::from(e)),
            }
        }
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
            let key_data = match load_key("JWT_PSS_PRIVATE_KEY") {
                Ok(k) => k,
                Err(e) => return e.into_response(),
            };
            match EncodingKey::from_rsa_pem(&key_data) {
                Ok(k) => encode(&header, &claims, &k),
                Err(e) => Err(jsonwebtoken::errors::Error::from(e)),
            }
        }
        _ => {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "UnsupportedAlgorithm",
                format!("Algorithm '{:?}' is not supported", alg_enum),
            )
            .into_response();
        }
    };

    match result {
        Ok(token) => Json(json!({"token": token})).into_response(),
        Err(e) => {
            error!("Signing error: {}", e);
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "SignError",
                format!("Failed to sign token: {}", e),
            )
            .into_response()
        }
    }
}

async fn verify_jwt(Json(payload): Json<VerifyRequest>, secret: String) -> impl IntoResponse {
    let header = match jsonwebtoken::decode_header(&payload.token) {
        Ok(h) => h,
        Err(e) => {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "InvalidTokenHeader",
                format!("Could not decode header: {}", e),
            )
            .into_response();
        }
    };
    let alg = header.alg;
    let mut validation = Validation::new(alg);
    if let Ok(aud) = env::var("AUDIENCE") {
        validation.set_audience(&[aud]);
    }

    // Attempt to decode
    let result = match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            if secret.is_empty() {
                return ApiError::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "MissingConfig",
                    "JWT_SECRET is not configured for HMAC verification",
                )
                .into_response();
            }
            decode::<Claims>(
                &payload.token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &validation,
            )
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let key_data = match load_key("JWT_PUBLIC_KEY") {
                Ok(k) => k,
                Err(e) => return e.into_response(),
            };
            match DecodingKey::from_rsa_pem(&key_data) {
                Ok(k) => decode::<Claims>(&payload.token, &k, &validation),
                Err(e) => Err(jsonwebtoken::errors::Error::from(e)),
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let key_data = match load_key("JWT_EC_PUBLIC_KEY") {
                Ok(k) => k,
                Err(e) => return e.into_response(),
            };
            match DecodingKey::from_ec_pem(&key_data) {
                Ok(k) => decode::<Claims>(&payload.token, &k, &validation),
                Err(e) => Err(jsonwebtoken::errors::Error::from(e)),
            }
        }
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
            let key_data = match load_key("JWT_PSS_PUBLIC_KEY") {
                Ok(k) => k,
                Err(e) => return e.into_response(),
            };
            match DecodingKey::from_rsa_pem(&key_data) {
                Ok(k) => decode::<Claims>(&payload.token, &k, &validation),
                Err(e) => Err(jsonwebtoken::errors::Error::from(e)),
            }
        }
        _ => {
            return ApiError::new(
                StatusCode::BAD_REQUEST,
                "UnsupportedAlgorithm",
                format!("Algorithm '{:?}' is not supported", alg),
            )
            .into_response();
        }
    };

    match result {
        Ok(data) => Json(json!({"claims": data.claims})).into_response(),
        Err(err) => {
            error!("JWT verification error: {:?}", err);
            let kind = err.kind();
            let (status, error_type, error_msg) = match kind {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => (
                    StatusCode::UNAUTHORIZED,
                    "ExpiredSignature",
                    "Token has expired".to_string(),
                ),
                jsonwebtoken::errors::ErrorKind::InvalidSignature => (
                    StatusCode::UNAUTHORIZED,
                    "InvalidSignature",
                    "Invalid signature".to_string(),
                ),
                jsonwebtoken::errors::ErrorKind::InvalidAudience => (
                    StatusCode::BAD_REQUEST,
                    "InvalidAudience",
                    "Invalid audience".to_string(),
                ),
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => (
                    StatusCode::BAD_REQUEST,
                    "InvalidIssuer",
                    "Invalid issuer".to_string(),
                ),
                jsonwebtoken::errors::ErrorKind::ImmatureSignature => (
                    StatusCode::BAD_REQUEST,
                    "ImmatureSignature",
                    "Token is not yet valid (nbf claim)".to_string(),
                ),
                jsonwebtoken::errors::ErrorKind::InvalidToken => (
                    StatusCode::BAD_REQUEST,
                    "InvalidToken",
                    "Token is malformed or invalid".to_string(),
                ),
                _ => (
                    StatusCode::BAD_REQUEST,
                    "VerificationError",
                    err.to_string(),
                ),
            };
            ApiError::new(status, error_type, error_msg).into_response()
        }
    }
}

async fn envs() -> impl IntoResponse {
    let vars = [
        "JWT_SECRET",
        "JWT_PRIVATE_KEY",
        "JWT_PUBLIC_KEY",
        "JWT_PSS_PRIVATE_KEY",
        "JWT_PSS_PUBLIC_KEY",
        "JWT_EC_PRIVATE_KEY",
        "JWT_EC_PUBLIC_KEY",
        "BASE_URL",
        "AUDIENCE",
    ];

    let mut result = serde_json::Map::new();

    for var in vars {
        let val = env::var(var).ok();
        let exists = val.is_some();
        let mut details = serde_json::Map::new();
        details.insert("set".to_string(), json!(exists));

        if let Some(v) = val {
            // mask secret
            if var == "JWT_SECRET" {
                details.insert("value".to_string(), json!("***"));
            } else if var.contains("KEY") && !var.contains("PUBLIC") {
                // Private key paths are shown, but maybe we want to check if file exists
                details.insert("path".to_string(), json!(v));
                details.insert("file_exists".to_string(), json!(Path::new(&v).exists()));
            } else {
                details.insert("value".to_string(), json!(v));
                if var.contains("KEY") || var.contains("CERT") {
                    details.insert("file_exists".to_string(), json!(Path::new(&v).exists()));
                }
            }
        }
        result.insert(var.to_string(), json!(details));
    }

    Json(result)
}
