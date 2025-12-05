# JWTs – Multi-Algorithm JWT Signing & Verification Service

A high-performance, Rust-based microservice for signing and verifying JSON Web Tokens (JWTs). It supports HMAC, RSA, ECDSA, and RSASSA-PSS algorithms.

Designed for ease of deployment, it supports configuration via environment variables and includes comprehensive helper scripts.

---

## Features

- **Algorithms**:
  - **HMAC**: HS256, HS384, HS512
  - **RSA**: RS256, RS384, RS512
  - **ECDSA**: ES256, ES384
  - **RSASSA-PSS**: PS256, PS384, PS512
- **API**: Simple RESTful JSON API.
- **Configuration**: 12-factor app compliant (config via environment variables).
- **Observability**: Structured logging with `tracing`.
- **Robust Error Handling**: Clear, typed error messages for easier debugging.

---

## Quick Start

### 1. Prerequisites

- Rust (latest stable)
- OpenSSL (for generating keys)

### 2. Build and Run

```sh
# Build release binary
cargo build --release

# Run locally
cargo run
```

### 3. Configuration

The service is configured entirely via environment variables. You only need to set variables for the algorithms you intend to use.

| Variable | Description | Required For |
|----------|-------------|--------------|
| `JWT_SECRET` | Shared secret string | HS256, HS384, HS512 |
| `JWT_PRIVATE_KEY` | Path to RSA private key (PEM) | RS256, RS384, RS512 (Signing) |
| `JWT_PUBLIC_KEY` | Path to RSA public key (PEM) | RS256, RS384, RS512 (Verification) |
| `JWT_EC_PRIVATE_KEY` | Path to ECDSA private key (PEM) | ES256, ES384 (Signing) |
| `JWT_EC_PUBLIC_KEY` | Path to ECDSA public key (PEM) | ES256, ES384 (Verification) |
| `JWT_PSS_PRIVATE_KEY` | Path to PSS private key (PEM) | PS256, PS384, PS512 (Signing) |
| `JWT_PSS_PUBLIC_KEY` | Path to PSS public key (PEM) | PS256, PS384, PS512 (Verification) |
| `AUDIENCE` | Expected `aud` claim | Optional verification check |

**Example `.env` file:**
```env
JWT_SECRET=super_secret_key
JWT_PRIVATE_KEY=./pem/rsa_private.pem
JWT_PUBLIC_KEY=./pem/rsa_public.pem
```

---

## API Reference

The server listens on `127.0.0.1:4000` by default.

### `POST /sign`

Creates a signed JWT.

**Request Body:**

```json
{
  "sub": "user_123",           // Subject (required)
  "exp": 1735689600,           // Expiration timestamp (required)
  "iat": 1704067200,           // Issued at timestamp (required)
  "iss": "my-app",             // Issuer (required)
  "aud": "my-api",             // Audience (required)
  "custom": "{\"role\":\"admin\"}", // Optional custom data string
  "alg": "RS256",              // Algorithm (required)
  "kid": "key-1"               // Key ID (optional header)
}
```

**Success Response (200 OK):**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### `POST /verify`

Verifies a JWT signature and claims.

**Request Body:**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Success Response (200 OK):**

```json
{
  "claims": {
    "sub": "user_123",
    "exp": 1735689600,
    "iat": 1704067200,
    "iss": "my-app",
    "aud": "my-api",
    "custom": "{\"role\":\"admin\"}"
  }
}
```

### `GET /test_env`

Debug endpoint to check loaded configuration. Returns status of environment variables and key file accessibility.

---

## Error Handling

The API returns structured JSON errors with HTTP status codes.

**Error Format:**
```json
{
  "error_type": "ErrorTypeString",
  "error_msg": "Human readable description"
}
```

**Common Errors:**

| Status | Error Type | Description |
|--------|------------|-------------|
| 400 | `UnsupportedAlgorithm` | The requested `alg` is not supported. |
| 400 | `InvalidTokenHeader` | The token format is invalid. |
| 400 | `InvalidAudience` | The `aud` claim does not match the configured `AUDIENCE`. |
| 401 | `ExpiredSignature` | The token has expired (`exp` claim). |
| 401 | `InvalidSignature` | Signature verification failed. |
| 500 | `MissingConfig` | Required environment variable is not set. |
| 500 | `KeyAccessError` | Could not read the key file from disk. |
| 500 | `SignError` | Internal error during signing. |

---

## Key Generation Guide

Generate keys using OpenSSL. Ensure the service has read permissions for these files.

### RSA (RS256/384/512)
```sh
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

### ECDSA (ES256/384)
```sh
openssl ecparam -name prime256v1 -genkey -noout -out ec256-private.pem
openssl ec -in ec256-private.pem -pubout -out ec256-public.pem
```

### RSASSA-PSS (PS256/384/512)
```sh
openssl genpkey -algorithm RSA -out pss-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in pss-private.pem -pubout -out pss-public.pem
```

---

## Development & Testing

### Running Tests
The integration tests require a running server.

1. **Start the server** (ensure env vars are set):
   ```sh
   export JWT_SECRET=test
   cargo run
   ```

2. **Run tests**:
   ```sh
   export BASE_URL=http://127.0.0.1:5000
   cargo test
   ```

### Helper Scripts
Check the `scripts/` directory for handy `curl` wrappers:
- `./scripts/sign_hs256.sh`
- `./scripts/verify_rs256.sh`
- `./scripts/check-env.sh`

---

## License
MIT
