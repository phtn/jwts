use axum::{routing::post, Router, Json, response::IntoResponse, http::StatusCode, routing::get};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey, Algorithm};
use std::net::SocketAddr;
use tracing::info;
use std::env;
use std::fs;
use std::path::Path;
use axum::response::Response;
use serde_json::json;

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
        Self { status, error_type, error_msg: error_msg.into() }
    }
    fn into_response(self) -> Response {
        let body = Json(json!({
            "error_type": self.error_type,
            "error_msg": self.error_msg,
        }));
        (self.status, body).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()>  {
    dotenvy::dotenv().ok();
    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");

    let app = Router::new()
        .route("/sign", post({
            let secret = secret.clone();
            move |payload| sign_jwt(payload, secret.clone())
        }))
        .route("/verify", post({
            let secret = secret.clone();
            move |payload| verify_jwt(payload, secret.clone())
        }))
        .route("/test_env", get(test_env));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Hyper JWT is on at :3000");

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
    header.alg = payload.alg.parse().unwrap_or(Algorithm::HS256);

    let result = match payload.alg.as_str() {
        "HS256" => encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes())),
        "HS384" => encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes())),
        "HS512" => encode(&header, &claims, &EncodingKey::from_secret(secret.as_bytes())),
        "RS256" | "RS384" | "RS512" => {
            let private_key_path = std::env::var("JWT_PRIVATE_KEY").ok();
            let private_key = match private_key_path {
                Some(path) => fs::read(path).ok(),
                None => None,
            };
            if let Some(key) = private_key {
                match EncodingKey::from_rsa_pem(&key) {
                    Ok(encoding_key) => encode(&header, &claims, &encoding_key),
                    Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "InvalidKeyFormat", e.to_string()).into_response(),
                }
            } else {
                return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "MissingKey", "Missing or unreadable RSA private key").into_response();
            }
        }
        "ES256" | "ES384" => {
            let ec_private_key_path = std::env::var("JWT_EC_PRIVATE_KEY").ok();
            let ec_private_key = match ec_private_key_path {
                Some(path) => fs::read(path).ok(),
                None => None,
            };
            if let Some(key) = ec_private_key {
                match EncodingKey::from_ec_pem(&key) {
                    Ok(encoding_key) => match encode(&header, &claims, &encoding_key) {
                        Ok(token) => return Json(json!({ "token": token })).into_response(),
                        Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "SignError", e.to_string()).into_response(),
                    },
                    Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "InvalidKeyFormat", e.to_string()).into_response(),
                }
            } else {
                return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "MissingKey", "Missing or unreadable EC private key").into_response();
            }
        }
        "PS256" | "PS384" | "PS512" => {
            let pss_private_key_path = std::env::var("JWT_PSS_PRIVATE_KEY").ok();
            let pss_private_key = match pss_private_key_path {
                Some(path) => fs::read(path).ok(),
                None => None,
            };
            if let Some(key) = pss_private_key {
                match EncodingKey::from_rsa_pem(&key) {
                    Ok(encoding_key) => encode(&header, &claims, &encoding_key),
                    Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "InvalidKeyFormat", e.to_string()).into_response(),
                }
            } else {
                return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "MissingKey", "Missing or unreadable PSS private key").into_response();
            }
        }
        _ => return ApiError::new(StatusCode::BAD_REQUEST, "UnsupportedAlgorithm", "Unsupported algorithm").into_response(),
    };
    match result {
        Ok(token) => Json(json!({"token": token})).into_response(),
        Err(e) => ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "SignError", e.to_string()).into_response(),
    }
}

async fn verify_jwt(Json(payload): Json<VerifyRequest>, secret: String) -> impl IntoResponse {
    let header = match jsonwebtoken::decode_header(&payload.token) {
        Ok(h) => h,
        Err(e) => return ApiError::new(StatusCode::BAD_REQUEST, "InvalidTokenHeader", e.to_string()).into_response(),
    };
    let alg = header.alg;
    let mut validation = Validation::new(alg);
    validation.set_audience(&["my-audience"]);
    let result = match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            decode::<Claims>(
                &payload.token,
                &DecodingKey::from_secret(secret.as_bytes()),
                &validation,
            )
        }
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
            let public_key_path = std::env::var("JWT_PUBLIC_KEY").ok();
            let public_key = match public_key_path {
                Some(path) => fs::read(path).ok(),
                None => None,
            };
            if let Some(key) = public_key {
                match DecodingKey::from_rsa_pem(&key) {
                    Ok(decoding_key) => decode::<Claims>(&payload.token, &decoding_key, &validation),
                    Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "InvalidKeyFormat", e.to_string()).into_response(),
                }
            } else {
                return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "MissingKey", "Missing or unreadable RSA public key").into_response();
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            let ec_public_key_path = std::env::var("JWT_EC_PUBLIC_KEY").ok();
            let ec_public_key = match ec_public_key_path {
                Some(path) => fs::read(path).ok(),
                None => None,
            };
            if let Some(key) = ec_public_key {
                match DecodingKey::from_ec_pem(&key) {
                    Ok(decoding_key) => decode::<Claims>(&payload.token, &decoding_key, &validation),
                    Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "InvalidKeyFormat", e.to_string()).into_response(),
                }
            } else {
                return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "MissingKey", "Missing or unreadable EC public key").into_response();
            }
        }
        Algorithm::PS256 | Algorithm::PS384 | Algorithm::PS512 => {
            let pss_public_key_path = std::env::var("JWT_PSS_PUBLIC_KEY").ok();
            let pss_public_key = match pss_public_key_path {
                Some(path) => fs::read(path).ok(),
                None => None,
            };
            if let Some(key) = pss_public_key {
                match DecodingKey::from_rsa_pem(&key) {
                    Ok(decoding_key) => decode::<Claims>(&payload.token, &decoding_key, &validation),
                    Err(e) => return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "InvalidKeyFormat", e.to_string()).into_response(),
                }
            } else {
                return ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, "MissingKey", "Missing or unreadable PSS public key").into_response();
            }
        }
        _ => return ApiError::new(StatusCode::BAD_REQUEST, "UnsupportedAlgorithm", "Unsupported algorithm").into_response(),
    };
    match result {
        Ok(data) => Json(json!({"claims": data.claims})).into_response(),
        Err(err) => {
            println!("JWT verification error: {:?}", err);
            let error_type = match err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => "ExpiredSignature",
                jsonwebtoken::errors::ErrorKind::InvalidSignature => "InvalidSignature",
                jsonwebtoken::errors::ErrorKind::InvalidAudience => "InvalidAudience",
                _ => "InvalidToken",
            };
            let error_msg = match err.kind() {
                jsonwebtoken::errors::ErrorKind::InvalidSignature => "Invalid signature".to_string(),
                jsonwebtoken::errors::ErrorKind::InvalidAudience => "Invalid audience".to_string(),
                _ => err.to_string(),
            };
            let status = match err.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => StatusCode::UNAUTHORIZED,
                jsonwebtoken::errors::ErrorKind::InvalidSignature => StatusCode::UNAUTHORIZED,
                jsonwebtoken::errors::ErrorKind::InvalidAudience => StatusCode::BAD_REQUEST,
                _ => StatusCode::BAD_REQUEST,
            };
            ApiError::new(status, error_type, error_msg).into_response()
        }
    }
}

async fn test_env() -> impl IntoResponse {
    let jwt_secret = env::var("JWT_SECRET").ok();
    let jwt_private_key = env::var("JWT_PRIVATE_KEY").ok();
    let jwt_public_key = env::var("JWT_PUBLIC_KEY").ok();
    let jwt_pss_private_key = env::var("JWT_PSS_PRIVATE_KEY").ok();
    let jwt_pss_public_key = env::var("JWT_PSS_PUBLIC_KEY").ok();
    let jwt_ec_private_key = env::var("JWT_EC_PRIVATE_KEY").ok();
    let jwt_ec_public_key = env::var("JWT_EC_PUBLIC_KEY").ok();

    let jwt_private_key_exists = jwt_private_key.as_ref().map(|p| Path::new(p).exists());
    let jwt_public_key_exists = jwt_public_key.as_ref().map(|p| Path::new(p).exists());
    let jwt_pss_private_key_exists = jwt_pss_private_key.as_ref().map(|p| Path::new(p).exists());
    let jwt_pss_public_key_exists = jwt_pss_public_key.as_ref().map(|p| Path::new(p).exists());
    let jwt_ec_private_key_exists = jwt_ec_private_key.as_ref().map(|p| Path::new(p).exists());
    let jwt_ec_public_key_exists = jwt_ec_public_key.as_ref().map(|p| Path::new(p).exists());

    println!("JWT_SECRET: {:?}", jwt_secret);
    println!("JWT_PRIVATE_KEY: {:?} exists: {:?}", jwt_private_key, jwt_private_key_exists);
    println!("JWT_PUBLIC_KEY: {:?} exists: {:?}", jwt_public_key, jwt_public_key_exists);
    println!("JWT_PSS_PRIVATE_KEY: {:?} exists: {:?}", jwt_pss_private_key, jwt_pss_private_key_exists);
    println!("JWT_PSS_PUBLIC_KEY: {:?} exists: {:?}", jwt_pss_public_key, jwt_pss_public_key_exists);
    println!("JWT_EC_PRIVATE_KEY: {:?} exists: {:?}", jwt_ec_private_key, jwt_ec_private_key_exists);
    println!("JWT_EC_PUBLIC_KEY: {:?} exists: {:?}", jwt_ec_public_key, jwt_ec_public_key_exists);

    Json(serde_json::json!({
        "JWT_SECRET": jwt_secret,
        "JWT_PRIVATE_KEY": jwt_private_key,
        "JWT_PRIVATE_KEY_EXISTS": jwt_private_key_exists,
        "JWT_PUBLIC_KEY": jwt_public_key,
        "JWT_PUBLIC_KEY_EXISTS": jwt_public_key_exists,
        "JWT_PSS_PRIVATE_KEY": jwt_pss_private_key,
        "JWT_PSS_PRIVATE_KEY_EXISTS": jwt_pss_private_key_exists,
        "JWT_PSS_PUBLIC_KEY": jwt_pss_public_key,
        "JWT_PSS_PUBLIC_KEY_EXISTS": jwt_pss_public_key_exists,
        "JWT_EC_PRIVATE_KEY": jwt_ec_private_key,
        "JWT_EC_PRIVATE_KEY_EXISTS": jwt_ec_private_key_exists,
        "JWT_EC_PUBLIC_KEY": jwt_ec_public_key,
        "JWT_EC_PUBLIC_KEY_EXISTS": jwt_ec_public_key_exists,
    }))
}
