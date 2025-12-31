use serde::{Deserialize, Serialize};

/// JWT Claims structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (who the token refers to)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: usize,
    /// Issued at time (Unix timestamp)
    pub iat: usize,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Not before time (Unix timestamp) - optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<usize>,
    /// JWT ID - optional unique identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Custom claims - now accepts any JSON value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<serde_json::Value>,
}

/// Request body for signing a JWT
#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// Subject (who the token refers to)
    pub sub: String,
    /// Expiration time (Unix timestamp)
    pub exp: usize,
    /// Issued at time (Unix timestamp)
    pub iat: usize,
    /// Issuer
    pub iss: String,
    /// Audience
    pub aud: String,
    /// Not before time (Unix timestamp) - optional
    pub nbf: Option<usize>,
    /// JWT ID - optional unique identifier
    pub jti: Option<String>,
    /// Custom claims - accepts any JSON value
    pub custom: Option<serde_json::Value>,
    /// Key ID (optional header)
    pub kid: Option<String>,
    /// Algorithm to use for signing
    pub alg: String,
}

impl SignRequest {
    /// Convert request into Claims
    pub fn into_claims(self) -> Claims {
        Claims {
            sub: self.sub,
            exp: self.exp,
            iat: self.iat,
            iss: self.iss,
            aud: self.aud,
            nbf: self.nbf,
            jti: self.jti,
            custom: self.custom,
        }
    }
}

/// Request body for verifying a JWT
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// The JWT token to verify
    pub token: String,
}

/// Response for successful token signing
#[derive(Debug, Serialize)]
pub struct SignResponse {
    /// The signed JWT token
    pub token: String,
}

/// Response for successful token verification
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    /// The decoded claims from the token
    pub claims: Claims,
}

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service status
    pub status: &'static str,
    /// Service version
    pub version: &'static str,
}

/// Readiness check response
#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    /// Service status
    pub status: &'static str,
    /// Whether signing is available
    pub signing_available: bool,
    /// Whether verification is available
    pub verification_available: bool,
}
