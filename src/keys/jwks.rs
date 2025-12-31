use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use elliptic_curve::pkcs8::DecodePublicKey;
use elliptic_curve::sec1::ToEncodedPoint;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::Serialize;

use crate::keys::KeyStore;

/// JSON Web Key Set
#[derive(Debug, Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key
#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    /// Key type
    pub kty: String,
    /// Public key use
    #[serde(rename = "use")]
    pub use_: String,
    /// Algorithm
    pub alg: String,
    /// Key ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// RSA modulus (base64url encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    /// RSA exponent (base64url encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    /// EC curve name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    /// EC x coordinate (base64url encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    /// EC y coordinate (base64url encoded)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

impl Jwks {
    /// Build JWKS from key store
    pub fn from_key_store(store: &KeyStore) -> Self {
        let mut keys = Vec::new();

        // Add RSA public key
        if let Some(pem_data) = &store.rsa_public_key_pem {
            if let Some(jwk) = rsa_pem_to_jwk(pem_data, "RS256", Some("rsa-key-1")) {
                keys.push(jwk);
            }
        }

        // Add PSS public key (uses RSA format)
        if let Some(pem_data) = &store.pss_public_key_pem {
            if let Some(jwk) = rsa_pem_to_jwk(pem_data, "PS256", Some("pss-key-1")) {
                keys.push(jwk);
            }
        }

        // Add EC public key (P-256)
        if let Some(pem_data) = &store.ec_public_key_pem {
            if let Some(jwk) = ec_pem_to_jwk(pem_data, Some("ec-key-1")) {
                keys.push(jwk);
            }
        }

        // Add EC384 public key (P-384)
        if let Some(pem_data) = &store.ec384_public_key_pem {
            if let Some(jwk) = ec_pem_to_jwk(pem_data, Some("ec-key-2")) {
                keys.push(jwk);
            }
        }

        Self { keys }
    }

    /// Check if JWKS has any keys
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Convert RSA PEM public key to JWK
fn rsa_pem_to_jwk(pem_data: &[u8], alg: &str, kid: Option<&str>) -> Option<Jwk> {
    let pem_str = std::str::from_utf8(pem_data).ok()?;
    
    // Try PKCS#1 format first, then PKCS#8/SPKI
    let public_key = if pem_str.contains("BEGIN RSA PUBLIC KEY") {
        RsaPublicKey::from_pkcs1_pem(pem_str).ok()?
    } else {
        // For SPKI format, we need to use a different parser
        use rsa::pkcs8::DecodePublicKey;
        RsaPublicKey::from_public_key_pem(pem_str).ok()?
    };

    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();

    Some(Jwk {
        kty: "RSA".to_string(),
        use_: "sig".to_string(),
        alg: alg.to_string(),
        kid: kid.map(String::from),
        n: Some(URL_SAFE_NO_PAD.encode(&n)),
        e: Some(URL_SAFE_NO_PAD.encode(&e)),
        crv: None,
        x: None,
        y: None,
    })
}

/// Convert EC PEM public key to JWK
fn ec_pem_to_jwk(pem_data: &[u8], kid: Option<&str>) -> Option<Jwk> {
    let pem_str = std::str::from_utf8(pem_data).ok()?;
    
    // Try P-256 first
    if let Ok(key) = p256::PublicKey::from_public_key_pem(pem_str) {
        let point = key.to_encoded_point(false);
        let x = point.x()?;
        let y = point.y()?;
        
        return Some(Jwk {
            kty: "EC".to_string(),
            use_: "sig".to_string(),
            alg: "ES256".to_string(),
            kid: kid.map(String::from),
            n: None,
            e: None,
            crv: Some("P-256".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(x)),
            y: Some(URL_SAFE_NO_PAD.encode(y)),
        });
    }

    // Try P-384
    if let Ok(key) = p384::PublicKey::from_public_key_pem(pem_str) {
        let point = key.to_encoded_point(false);
        let x = point.x()?;
        let y = point.y()?;
        
        return Some(Jwk {
            kty: "EC".to_string(),
            use_: "sig".to_string(),
            alg: "ES384".to_string(),
            kid: kid.map(String::from),
            n: None,
            e: None,
            crv: Some("P-384".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode(x)),
            y: Some(URL_SAFE_NO_PAD.encode(y)),
        });
    }

    None
}
