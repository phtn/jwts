use std::fs;
use std::sync::Arc;

use jsonwebtoken::{DecodingKey, EncodingKey};
use tracing::{info, warn};

use crate::config::Config;
use crate::error::{AppError, AppResult};

/// Cached key material for JWT operations
#[derive(Clone)]
pub struct KeyStore {
    /// HMAC secret for HS algorithms
    pub hmac_secret: Option<String>,
    /// RSA private key for RS algorithms (signing)
    pub rsa_encoding_key: Option<Arc<EncodingKey>>,
    /// RSA public key for RS algorithms (verification)
    pub rsa_decoding_key: Option<Arc<DecodingKey>>,
    /// RSA public key raw bytes for JWKS
    pub rsa_public_key_pem: Option<Vec<u8>>,
    /// EC private key for ES256 (P-256 curve, signing)
    pub ec_encoding_key: Option<Arc<EncodingKey>>,
    /// EC public key for ES256 (P-256 curve, verification)
    pub ec_decoding_key: Option<Arc<DecodingKey>>,
    /// EC public key raw bytes for JWKS (P-256)
    pub ec_public_key_pem: Option<Vec<u8>>,
    /// EC private key for ES384 (P-384 curve, signing)
    pub ec384_encoding_key: Option<Arc<EncodingKey>>,
    /// EC public key for ES384 (P-384 curve, verification)
    pub ec384_decoding_key: Option<Arc<DecodingKey>>,
    /// EC public key raw bytes for JWKS (P-384)
    pub ec384_public_key_pem: Option<Vec<u8>>,
    /// PSS private key for PS algorithms (signing)
    pub pss_encoding_key: Option<Arc<EncodingKey>>,
    /// PSS public key for PS algorithms (verification)
    pub pss_decoding_key: Option<Arc<DecodingKey>>,
    /// PSS public key raw bytes for JWKS
    pub pss_public_key_pem: Option<Vec<u8>>,
}

impl KeyStore {
    /// Load all keys from configuration
    pub fn from_config(config: &Config) -> AppResult<Self> {
        let mut store = Self {
            hmac_secret: config.jwt_secret.clone(),
            rsa_encoding_key: None,
            rsa_decoding_key: None,
            rsa_public_key_pem: None,
            ec_encoding_key: None,
            ec_decoding_key: None,
            ec_public_key_pem: None,
            ec384_encoding_key: None,
            ec384_decoding_key: None,
            ec384_public_key_pem: None,
            pss_encoding_key: None,
            pss_decoding_key: None,
            pss_public_key_pem: None,
        };

        // Load RSA keys
        if let Some(path) = &config.rsa_private_key_path {
            match fs::read(path) {
                Ok(key_data) => {
                    match EncodingKey::from_rsa_pem(&key_data) {
                        Ok(key) => {
                            store.rsa_encoding_key = Some(Arc::new(key));
                            info!("Loaded RSA private key from {:?}", path);
                        }
                        Err(e) => {
                            warn!("Failed to parse RSA private key: {}", e);
                            return Err(AppError::KeyAccessError(format!(
                                "Invalid RSA private key at {:?}: {}",
                                path, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read RSA private key file {:?}: {}", path, e);
                    return Err(AppError::KeyAccessError(format!(
                        "Could not read RSA private key at {:?}: {}",
                        path, e
                    )));
                }
            }
        }

        if let Some(path) = &config.rsa_public_key_path {
            match fs::read(path) {
                Ok(key_data) => {
                    match DecodingKey::from_rsa_pem(&key_data) {
                        Ok(key) => {
                            store.rsa_decoding_key = Some(Arc::new(key));
                            store.rsa_public_key_pem = Some(key_data);
                            info!("Loaded RSA public key from {:?}", path);
                        }
                        Err(e) => {
                            warn!("Failed to parse RSA public key: {}", e);
                            return Err(AppError::KeyAccessError(format!(
                                "Invalid RSA public key at {:?}: {}",
                                path, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read RSA public key file {:?}: {}", path, e);
                    return Err(AppError::KeyAccessError(format!(
                        "Could not read RSA public key at {:?}: {}",
                        path, e
                    )));
                }
            }
        }

        // Load EC keys
        if let Some(path) = &config.ec_private_key_path {
            match fs::read(path) {
                Ok(key_data) => {
                    match EncodingKey::from_ec_pem(&key_data) {
                        Ok(key) => {
                            store.ec_encoding_key = Some(Arc::new(key));
                            info!("Loaded EC private key from {:?}", path);
                        }
                        Err(e) => {
                            warn!("Failed to parse EC private key: {}", e);
                            return Err(AppError::KeyAccessError(format!(
                                "Invalid EC private key at {:?}: {}",
                                path, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read EC private key file {:?}: {}", path, e);
                    return Err(AppError::KeyAccessError(format!(
                        "Could not read EC private key at {:?}: {}",
                        path, e
                    )));
                }
            }
        }

        if let Some(path) = &config.ec_public_key_path {
            match fs::read(path) {
                Ok(key_data) => {
                    match DecodingKey::from_ec_pem(&key_data) {
                        Ok(key) => {
                            store.ec_decoding_key = Some(Arc::new(key));
                            store.ec_public_key_pem = Some(key_data);
                            info!("Loaded EC public key from {:?}", path);
                        }
                        Err(e) => {
                            warn!("Failed to parse EC public key: {}", e);
                            return Err(AppError::KeyAccessError(format!(
                                "Invalid EC public key at {:?}: {}",
                                path, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read EC public key file {:?}: {}", path, e);
                    return Err(AppError::KeyAccessError(format!(
                        "Could not read EC public key at {:?}: {}",
                        path, e
                    )));
                }
            }
        }

        // Load EC384 keys (P-384 curve)
        if let Some(path) = &config.ec384_private_key_path {
            match fs::read(path) {
                Ok(key_data) => {
                    match EncodingKey::from_ec_pem(&key_data) {
                        Ok(key) => {
                            store.ec384_encoding_key = Some(Arc::new(key));
                            info!("Loaded EC384 private key from {:?}", path);
                        }
                        Err(e) => {
                            warn!("Failed to parse EC384 private key: {}", e);
                            return Err(AppError::KeyAccessError(format!(
                                "Invalid EC384 private key at {:?}: {}",
                                path, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read EC384 private key file {:?}: {}", path, e);
                    return Err(AppError::KeyAccessError(format!(
                        "Could not read EC384 private key at {:?}: {}",
                        path, e
                    )));
                }
            }
        }

        if let Some(path) = &config.ec384_public_key_path {
            match fs::read(path) {
                Ok(key_data) => {
                    match DecodingKey::from_ec_pem(&key_data) {
                        Ok(key) => {
                            store.ec384_decoding_key = Some(Arc::new(key));
                            store.ec384_public_key_pem = Some(key_data);
                            info!("Loaded EC384 public key from {:?}", path);
                        }
                        Err(e) => {
                            warn!("Failed to parse EC384 public key: {}", e);
                            return Err(AppError::KeyAccessError(format!(
                                "Invalid EC384 public key at {:?}: {}",
                                path, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read EC384 public key file {:?}: {}", path, e);
                    return Err(AppError::KeyAccessError(format!(
                        "Could not read EC384 public key at {:?}: {}",
                        path, e
                    )));
                }
            }
        }

        // Load PSS keys
        if let Some(path) = &config.pss_private_key_path {
            match fs::read(path) {
                Ok(key_data) => {
                    match EncodingKey::from_rsa_pem(&key_data) {
                        Ok(key) => {
                            store.pss_encoding_key = Some(Arc::new(key));
                            info!("Loaded PSS private key from {:?}", path);
                        }
                        Err(e) => {
                            warn!("Failed to parse PSS private key: {}", e);
                            return Err(AppError::KeyAccessError(format!(
                                "Invalid PSS private key at {:?}: {}",
                                path, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read PSS private key file {:?}: {}", path, e);
                    return Err(AppError::KeyAccessError(format!(
                        "Could not read PSS private key at {:?}: {}",
                        path, e
                    )));
                }
            }
        }

        if let Some(path) = &config.pss_public_key_path {
            match fs::read(path) {
                Ok(key_data) => {
                    match DecodingKey::from_rsa_pem(&key_data) {
                        Ok(key) => {
                            store.pss_decoding_key = Some(Arc::new(key));
                            store.pss_public_key_pem = Some(key_data);
                            info!("Loaded PSS public key from {:?}", path);
                        }
                        Err(e) => {
                            warn!("Failed to parse PSS public key: {}", e);
                            return Err(AppError::KeyAccessError(format!(
                                "Invalid PSS public key at {:?}: {}",
                                path, e
                            )));
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read PSS public key file {:?}: {}", path, e);
                    return Err(AppError::KeyAccessError(format!(
                        "Could not read PSS public key at {:?}: {}",
                        path, e
                    )));
                }
            }
        }

        Ok(store)
    }

    /// Check if signing is available
    pub fn has_signing_capability(&self) -> bool {
        self.hmac_secret.is_some()
            || self.rsa_encoding_key.is_some()
            || self.ec_encoding_key.is_some()
            || self.ec384_encoding_key.is_some()
            || self.pss_encoding_key.is_some()
    }

    /// Check if verification is available
    pub fn has_verification_capability(&self) -> bool {
        self.hmac_secret.is_some()
            || self.rsa_decoding_key.is_some()
            || self.ec_decoding_key.is_some()
            || self.ec384_decoding_key.is_some()
            || self.pss_decoding_key.is_some()
    }

    /// Get HMAC encoding key
    pub fn hmac_encoding_key(&self) -> AppResult<EncodingKey> {
        self.hmac_secret
            .as_ref()
            .map(|s| EncodingKey::from_secret(s.as_bytes()))
            .ok_or_else(|| AppError::MissingConfig("JWT_SECRET is not configured for HMAC signing".into()))
    }

    /// Get HMAC decoding key
    pub fn hmac_decoding_key(&self) -> AppResult<DecodingKey> {
        self.hmac_secret
            .as_ref()
            .map(|s| DecodingKey::from_secret(s.as_bytes()))
            .ok_or_else(|| AppError::MissingConfig("JWT_SECRET is not configured for HMAC verification".into()))
    }

    /// Get RSA encoding key
    pub fn rsa_encoding_key(&self) -> AppResult<Arc<EncodingKey>> {
        self.rsa_encoding_key
            .clone()
            .ok_or_else(|| AppError::MissingConfig("JWT_PRIVATE_KEY is not configured for RSA signing".into()))
    }

    /// Get RSA decoding key
    pub fn rsa_decoding_key(&self) -> AppResult<Arc<DecodingKey>> {
        self.rsa_decoding_key
            .clone()
            .ok_or_else(|| AppError::MissingConfig("JWT_PUBLIC_KEY is not configured for RSA verification".into()))
    }

    /// Get EC encoding key
    pub fn ec_encoding_key(&self) -> AppResult<Arc<EncodingKey>> {
        self.ec_encoding_key
            .clone()
            .ok_or_else(|| AppError::MissingConfig("JWT_EC_PRIVATE_KEY is not configured for EC signing".into()))
    }

    /// Get EC decoding key
    pub fn ec_decoding_key(&self) -> AppResult<Arc<DecodingKey>> {
        self.ec_decoding_key
            .clone()
            .ok_or_else(|| AppError::MissingConfig("JWT_EC_PUBLIC_KEY is not configured for EC verification".into()))
    }

    /// Get EC384 encoding key (P-384 curve)
    pub fn ec384_encoding_key(&self) -> AppResult<Arc<EncodingKey>> {
        self.ec384_encoding_key
            .clone()
            .ok_or_else(|| AppError::MissingConfig("JWT_EC384_PRIVATE_KEY is not configured for ES384 signing".into()))
    }

    /// Get EC384 decoding key (P-384 curve)
    pub fn ec384_decoding_key(&self) -> AppResult<Arc<DecodingKey>> {
        self.ec384_decoding_key
            .clone()
            .ok_or_else(|| AppError::MissingConfig("JWT_EC384_PUBLIC_KEY is not configured for ES384 verification".into()))
    }

    /// Get PSS encoding key
    pub fn pss_encoding_key(&self) -> AppResult<Arc<EncodingKey>> {
        self.pss_encoding_key
            .clone()
            .ok_or_else(|| AppError::MissingConfig("JWT_PSS_PRIVATE_KEY is not configured for PSS signing".into()))
    }

    /// Get PSS decoding key
    pub fn pss_decoding_key(&self) -> AppResult<Arc<DecodingKey>> {
        self.pss_decoding_key
            .clone()
            .ok_or_else(|| AppError::MissingConfig("JWT_PSS_PUBLIC_KEY is not configured for PSS verification".into()))
    }
}
