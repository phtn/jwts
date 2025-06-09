use reqwest::Client;
use serde_json::json;

#[tokio::test]
async fn test_sign_and_verify_hs256_success() {
    let client = Client::new();
    let sign_resp = client
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

#[tokio::test]
async fn test_sign_with_unsupported_alg() {
    let client = Client::new();
    let sign_resp = client
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({ "token": "not.a.jwt" }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 400);
    let err_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "InvalidTokenHeader");
}

#[tokio::test]
async fn test_sign_and_verify_rs256_success() {
    let client = Client::new();
    let sign_resp = client
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

#[tokio::test]
async fn test_sign_and_verify_es256_success() {
    let client = Client::new();
    let sign_resp = client
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

#[tokio::test]
async fn test_verify_with_expired_token() {
    let client = Client::new();
    let sign_resp = client
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1000, // expired
            "iat": 1000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/verify")
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
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "not-my-audience",
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
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 400);
    let err_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "InvalidAudience");
    assert!(
        err_json["error_msg"]
            .as_str()
            .unwrap()
            .contains("Invalid audience")
    );
}

#[tokio::test]
async fn test_verify_with_tampered_token() {
    let client = Client::new();
    let sign_resp = client
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({ "token": tampered }))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 401);
    let err_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "InvalidSignature");
    assert_eq!(err_json["error_msg"], "Invalid signature");
}

#[tokio::test]
async fn test_sign_and_verify_ps256_success() {
    let client = Client::new();
    let sign_resp = client
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/verify")
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
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
            "custom": "test",
            "kid": "ec-key-1",
            "alg": "ES384"
        }))
        .send()
        .await
        .unwrap();
    assert!(sign_resp.status().is_success());
    let sign_json: serde_json::Value = sign_resp.json().await.unwrap();
    let token = sign_json["token"].as_str().unwrap();

    let verify_resp = client
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

#[tokio::test]
async fn test_sign_and_verify_hs512_success() {
    let client = Client::new();
    let sign_resp = client
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert!(verify_resp.status().is_success());
    let verify_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(verify_json["claims"]["sub"], "user123");
}

#[tokio::test]
async fn test_verify_with_missing_token_field() {
    let client = Client::new();
    let verify_resp = client
        .post("http://127.0.0.1:3000/verify")
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(verify_resp.status(), 422);
    let err_json: serde_json::Value = verify_resp.json().await.unwrap();
    assert_eq!(err_json["error_type"], "InvalidTokenHeader");
}

#[tokio::test]
async fn test_verify_with_empty_token_string() {
    let client = Client::new();
    let verify_resp = client
        .post("http://127.0.0.1:3000/verify")
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
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            // missing sub
            "exp": 1999999999,
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
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
        .post("http://127.0.0.1:3000/sign")
        .json(&json!({
            "sub": "user123",
            "exp": "notanumber",
            "iat": 1710000000,
            "iss": "my-issuer",
            "aud": "my-audience",
            "custom": "test",
            "kid": "hmac-key-1",
            "alg": "HS256"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(sign_resp.status(), 422);
}
