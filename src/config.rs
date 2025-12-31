use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;

use tracing::info;

/// Application configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct Config {
    /// Server host address
    pub host: String,
    /// Server port
    pub port: u16,
    /// API key for authentication (optional - if not set, auth is disabled)
    pub api_key: Option<String>,
    /// HMAC secret for HS256/384/512
    pub jwt_secret: Option<String>,
    /// Path to RSA private key for RS256/384/512
    pub rsa_private_key_path: Option<PathBuf>,
    /// Path to RSA public key for RS256/384/512
    pub rsa_public_key_path: Option<PathBuf>,
    /// Path to EC private key for ES256 (P-256 curve)
    pub ec_private_key_path: Option<PathBuf>,
    /// Path to EC public key for ES256 (P-256 curve)
    pub ec_public_key_path: Option<PathBuf>,
    /// Path to EC private key for ES384 (P-384 curve)
    pub ec384_private_key_path: Option<PathBuf>,
    /// Path to EC public key for ES384 (P-384 curve)
    pub ec384_public_key_path: Option<PathBuf>,
    /// Path to PSS private key for PS256/384/512
    pub pss_private_key_path: Option<PathBuf>,
    /// Path to PSS public key for PS256/384/512
    pub pss_public_key_path: Option<PathBuf>,
    /// Expected audience for token verification
    pub audience: Option<String>,
    /// Rate limit: requests per second
    pub rate_limit_per_second: u64,
    /// Rate limit: burst size
    pub rate_limit_burst: u32,
}

impl Config {
    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(5000);

        let api_key = env::var("API_KEY").ok().filter(|s| !s.is_empty());
        let jwt_secret = env::var("JWT_SECRET").ok().filter(|s| !s.is_empty());

        let rsa_private_key_path = env::var("JWT_PRIVATE_KEY").ok().map(PathBuf::from);
        let rsa_public_key_path = env::var("JWT_PUBLIC_KEY").ok().map(PathBuf::from);

        let ec_private_key_path = env::var("JWT_EC_PRIVATE_KEY").ok().map(PathBuf::from);
        let ec_public_key_path = env::var("JWT_EC_PUBLIC_KEY").ok().map(PathBuf::from);

        let ec384_private_key_path = env::var("JWT_EC384_PRIVATE_KEY").ok().map(PathBuf::from);
        let ec384_public_key_path = env::var("JWT_EC384_PUBLIC_KEY").ok().map(PathBuf::from);

        let pss_private_key_path = env::var("JWT_PSS_PRIVATE_KEY").ok().map(PathBuf::from);
        let pss_public_key_path = env::var("JWT_PSS_PUBLIC_KEY").ok().map(PathBuf::from);

        let audience = env::var("AUDIENCE").ok().filter(|s| !s.is_empty());

        let rate_limit_per_second = env::var("RATE_LIMIT_PER_SECOND")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(100);

        let rate_limit_burst = env::var("RATE_LIMIT_BURST")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50);

        Self {
            host,
            port,
            api_key,
            jwt_secret,
            rsa_private_key_path,
            rsa_public_key_path,
            ec_private_key_path,
            ec_public_key_path,
            ec384_private_key_path,
            ec384_public_key_path,
            pss_private_key_path,
            pss_public_key_path,
            audience,
            rate_limit_per_second,
            rate_limit_burst,
        }
    }

    /// Get the socket address for binding
    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("Invalid HOST:PORT configuration")
    }

    /// Log configuration summary (masking secrets)
    pub fn log_summary(&self) {
        info!("Configuration loaded:");
        info!("  Host: {}:{}", self.host, self.port);
        info!(
            "  API Key: {}",
            if self.api_key.is_some() {
                "configured"
            } else {
                "disabled"
            }
        );
        info!(
            "  JWT Secret (HMAC): {}",
            if self.jwt_secret.is_some() {
                "configured"
            } else {
                "not set"
            }
        );
        info!(
            "  RSA Keys: private={}, public={}",
            self.rsa_private_key_path
                .as_ref()
                .map(|_| "configured")
                .unwrap_or("not set"),
            self.rsa_public_key_path
                .as_ref()
                .map(|_| "configured")
                .unwrap_or("not set")
        );
        info!(
            "  EC Keys (P-256): private={}, public={}",
            self.ec_private_key_path
                .as_ref()
                .map(|_| "configured")
                .unwrap_or("not set"),
            self.ec_public_key_path
                .as_ref()
                .map(|_| "configured")
                .unwrap_or("not set")
        );
        info!(
            "  EC Keys (P-384): private={}, public={}",
            self.ec384_private_key_path
                .as_ref()
                .map(|_| "configured")
                .unwrap_or("not set"),
            self.ec384_public_key_path
                .as_ref()
                .map(|_| "configured")
                .unwrap_or("not set")
        );
        info!(
            "  PSS Keys: private={}, public={}",
            self.pss_private_key_path
                .as_ref()
                .map(|_| "configured")
                .unwrap_or("not set"),
            self.pss_public_key_path
                .as_ref()
                .map(|_| "configured")
                .unwrap_or("not set")
        );
        info!(
            "  Audience: {}",
            self.audience.as_deref().unwrap_or("not set")
        );
        info!(
            "  Rate Limit: {}/s (burst: {})",
            self.rate_limit_per_second, self.rate_limit_burst
        );
    }

    /// Check if any signing keys are configured
    pub fn has_signing_capability(&self) -> bool {
        self.jwt_secret.is_some()
            || self.rsa_private_key_path.is_some()
            || self.ec_private_key_path.is_some()
            || self.ec384_private_key_path.is_some()
            || self.pss_private_key_path.is_some()
    }

    /// Check if any verification keys are configured
    pub fn has_verification_capability(&self) -> bool {
        self.jwt_secret.is_some()
            || self.rsa_public_key_path.is_some()
            || self.ec_public_key_path.is_some()
            || self.ec384_public_key_path.is_some()
            || self.pss_public_key_path.is_some()
    }
}
