use reqwest::Client;
use serde_json::json;
use std::env;

fn url(endpoint: &str) -> String {
    let base = env::var("BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:5000".to_string());
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        endpoint.trim_start_matches('/')
    )
}

// =============================================================================
// Health & Readiness Tests
// =============================================================================

#[tokio::test]
async fn test_health_endpoint() {
    let client = Client::new();
    let resp = client.get(url("/health")).send().await.unwrap();
    
    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn test_ready_endpoint() {
    let client = Client::new();
    let resp = client.get(url("/ready")).send().await.unwrap();
    
    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["status"], "ready");
    assert!(json["signing_available"].is_boolean());
    assert!(json["verification_available"].is_boolean());
}

// =============================================================================
// JWKS Endpoint Tests
// =============================================================================

#[tokio::test]
async fn test_jwks_endpoint() {
    let client = Client::new();
    let resp = client
        .get(url("/.well-known/jwks.json"))
        .send()
        .await
        .unwrap();
    
    assert!(resp.status().is_success());
    let json: serde_json::Value = resp.json().await.unwrap();
    assert!(json["keys"].is_array());
}

// =============================================================================
// HMAC (HS256/384/512) Tests
// =============================================================================

#[tokio::test]
async fn test_sign_and_verify_hs256_success() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": {"role": "admin"},
            "kid": "hmac-key-1",
            "alg": "HS256"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
    // Verify custom claims are preserved as JSON
    assert_eq!(verify_json["claims"]["custom"]["role"], "admin");
}

#[tokio::test]
async fn test_sign_and_verify_hs512_success() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "hmac-key-1",
            "alg": "HS512"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

// =============================================================================
// RSA (RS256/384/512) Tests
// =============================================================================

#[tokio::test]
async fn test_sign_and_verify_rs256_success() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "rsa-key-1",
            "alg": "RS256"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

// =============================================================================
// ECDSA (ES256/384) Tests
// =============================================================================

#[tokio::test]
async fn test_sign_and_verify_es256_success() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "ec-key-1",
            "alg": "ES256"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

#[tokio::test]
async fn test_sign_and_verify_es384_success() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "ec-key-2",
            "alg": "ES384"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

// =============================================================================
// RSASSA-PSS (PS256/384/512) Tests
// =============================================================================

#[tokio::test]
async fn test_sign_and_verify_ps256_success() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "pss-key-1",
            "alg": "PS256"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

// =============================================================================
// Enhanced Claims Tests
// =============================================================================

#[tokio::test]
async fn test_sign_with_nbf_and_jti_claims() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "nbf": 1710000000,
            "jti": "unique-token-id-123",
            "iss": "my-issuer",
            "aud": "provider",
            "custom": {"permissions": ["read", "write"]},
            "alg": "HS256"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
    assert_eq!(verify_json["claims"]["nbf"], 1710000000);
    assert_eq!(verify_json["claims"]["jti"], "unique-token-id-123");
    assert_eq!(verify_json["claims"]["custom"]["permissions"][0], "read");
}

// =============================================================================
// Error Case Tests
// =============================================================================

#[tokio::test]
async fn test_sign_with_unsupported_alg() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "hmac-key-1",
            "alg": "FOO256"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), 400);
    let err_json: serde_json::Value = sign_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "UnsupportedAlgorithm");
}

#[tokio::test]
async fn test_verify_with_invalid_token() {
    let client = Client::new();
    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": "not.a.jwt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 400);
    let err_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "InvalidTokenHeader");
}

#[tokio::test]
async fn test_verify_with_expired_token() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1000, // expired
            "iat": 1000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "hmac-key-1",
            "alg": "HS256"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 401);
    let err_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "ExpiredSignature");
}

#[tokio::test]
async fn test_verify_with_wrong_audience() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "not-provider",
            "custom": "test",
            "kid": "hmac-key-1",
            "alg": "HS256"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    // Note: This test only fails if AUDIENCE env var is set on the server
    // If not set, verification passes regardless of audience
    let status = verify_resp.status();
    if status == 400 {
        let err_json: serde_json::Value = verify_resp.json().await.unwrap();
        assert_eq!(err_json["error_type"], "InvalidAudience");
    } else {
        assert!(status.is_success());
    }
}

#[tokio::test]
async fn test_verify_with_tampered_token() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "hmac-key-1",
            "alg": "HS256"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let mut token = sign_json["token"].as_str().unwrap().to_string();
    
    // Tamper with the token (change last char)
    let last = token.pop().unwrap();
    let tampered = format!("{}{}", token, if last == 'a' { 'b' } else { 'a' });

    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": tampered }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 401);
    let err_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "InvalidSignature");
}

#[tokio::test]
async fn test_verify_with_empty_token_string() {
    let client = Client::new();
    let verify_resp = client
        .post(url("/verify"))
        .json(&json!({ "token": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 400);
    let err_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "InvalidTokenHeader");
}

#[tokio::test]
async fn test_sign_with_missing_required_field() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            // missing sub
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "hmac-key-1",
            "alg": "HS256"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), 422);
}

#[tokio::test]
async fn test_sign_with_invalid_exp_type() {
    let client = Client::new();
    let sign_resp = client
        .post(url("/sign"))
        .json(&json!({
            "sub": "user123",
            "exp": "notanumber",
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "provider",
            "custom": "test",
            "kid": "hmac-key-1",
            "alg": "HS256"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), 422);
}
