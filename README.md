# JWTS – Multi-Algorithm JWT Signing & Verification Service

A high-performance, production-ready Rust microservice for signing and verifying JSON Web Tokens (JWTs). Supports HMAC, RSA, ECDSA, and RSASSA-PSS algorithms with comprehensive security features.

---

## What's New in v0.2.0

- **JWKS Endpoint** - Automatic public key distribution via `/.well-known/jwks.json`
- **API Key Authentication** - Optional `X-API-Key` header protection for signing/verification endpoints
- **Rate Limiting** - Configurable request throttling to prevent abuse
- **Enhanced Claims** - Support for `nbf` (not before), `jti` (JWT ID), and JSON object custom claims
- **Health & Readiness** - Kubernetes-ready `/health` and `/ready` endpoints
- **Key Caching** - Keys loaded once at startup for optimal performance
- **Graceful Shutdown** - Clean SIGTERM/SIGINT handling for container deployments
- **Docker Support** - Multi-stage Dockerfile and docker-compose included
- **Modular Architecture** - Refactored codebase for maintainability

---

## Features

- **Multi-Algorithm Support**:
  - **HMAC**: HS256, HS384, HS512
  - **RSA**: RS256, RS384, RS512
  - **ECDSA**: ES256, ES384
  - **RSASSA-PSS**: PS256, PS384, PS512
- **Security**:
  - API key authentication (optional)
  - Rate limiting with configurable limits
  - Key caching for optimal performance
- **Standards Compliant**:
  - JWKS endpoint (`/.well-known/jwks.json`) for public key distribution
  - Support for standard JWT claims (`sub`, `exp`, `iat`, `iss`, `aud`, `nbf`, `jti`)
  - Custom claims as JSON objects
- **Production Ready**:
  - Health (`/health`) and readiness (`/ready`) endpoints
  - Graceful shutdown handling
  - Structured logging with `tracing`
  - Docker support with multi-stage builds
  - 12-factor app compliant configuration

---

## Quick Start

### Prerequisites

- Rust 1.75+ (latest stable recommended)
- OpenSSL (for generating keys)

### Build and Run

```sh
# Build release binary
cargo build --release

# Set minimum required config and run
export JWT_SECRET=your-super-secret-key-at-least-32-chars
cargo run
```

### Docker

```sh
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t jwts .
docker run -p 5000:5000 -e JWT_SECRET=your-secret jwts
```

---

## Usage Examples

### Basic Sign & Verify (HMAC)

**Sign a token:**

```sh
curl -X POST http://127.0.0.1:5001/sign \
  -H "Content-Type: application/json" \
  -d '{
    "sub": "user_123",
    "exp": 1999999999,
    "iat": 1704067200,
    "iss": "my-app",
    "aud": "my-api",
    "alg": "HS256"
  }'
```

Response:
```json
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

**Verify a token:**

```sh
curl -X POST http://127.0.0.1:5001/verify \
  -H "Content-Type: application/json" \
  -d '{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }'
```

Response:
```json
{
  "claims": {
    "sub": "user_123",
    "exp": 1999999999,
    "iat": 1704067200,
    "iss": "my-app",
    "aud": "my-api"
  }
}
```

### With Custom Claims (JSON Objects)

```sh
curl -X POST http://127.0.0.1:5001/sign \
  -H "Content-Type: application/json" \
  -d '{
    "sub": "user_123",
    "exp": 1999999999,
    "iat": 1704067200,
    "iss": "my-app",
    "aud": "my-api",
    "custom": {
      "role": "admin",
      "permissions": ["read", "write", "delete"],
      "tenant_id": "acme-corp"
    },
    "alg": "HS256"
  }'
```

### With NBF and JTI Claims

```sh
curl -X POST http://127.0.0.1:5001/sign \
  -H "Content-Type: application/json" \
  -d '{
    "sub": "user_123",
    "exp": 1999999999,
    "iat": 1704067200,
    "nbf": 1704067200,
    "jti": "550e8400-e29b-41d4-a716-446655440000",
    "iss": "my-app",
    "aud": "my-api",
    "alg": "HS256"
  }'
```

### With API Key Authentication

When `API_KEY` environment variable is set:

```sh
curl -X POST http://127.0.0.1:5001/sign \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "sub": "user_123",
    "exp": 1999999999,
    "iat": 1704067200,
    "iss": "my-app",
    "aud": "my-api",
    "alg": "HS256"
  }'
```

### RSA Signing (RS256)

```sh
# First, set up RSA keys
export JWT_PRIVATE_KEY=./keys/rsa_private.pem
export JWT_PUBLIC_KEY=./keys/rsa_public.pem

curl -X POST http://127.0.0.1:5001/sign \
  -H "Content-Type: application/json" \
  -d '{
    "sub": "user_123",
    "exp": 1999999999,
    "iat": 1704067200,
    "iss": "my-app",
    "aud": "my-api",
    "kid": "rsa-key-2024",
    "alg": "RS256"
  }'
```

### ECDSA Signing (ES256)

```sh
# First, set up EC keys
export JWT_EC_PRIVATE_KEY=./keys/ec_private.pem
export JWT_EC_PUBLIC_KEY=./keys/ec_public.pem

curl -X POST http://127.0.0.1:5001/sign \
  -H "Content-Type: application/json" \
  -d '{
    "sub": "user_123",
    "exp": 1999999999,
    "iat": 1704067200,
    "iss": "my-app",
    "aud": "my-api",
    "kid": "ec-key-2024",
    "alg": "ES256"
  }'
```

### Health & Readiness Checks

```sh
# Liveness probe (Kubernetes)
curl http://127.0.0.1:5001/health
# {"status":"ok","version":"0.2.0"}

# Readiness probe (Kubernetes)
curl http://127.0.0.1:5001/ready
# {"status":"ready","signing_available":true,"verification_available":true}
```

### JWKS Endpoint

Fetch public keys for external verification:

```sh
curl http://127.0.0.1:5001/.well-known/jwks.json
```

Response:
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "rsa-key-1",
      "n": "0vx7agoebGcQSuuP...",
      "e": "AQAB"
    },
    {
      "kty": "EC",
      "use": "sig",
      "alg": "ES256",
      "kid": "ec-key-1",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9...",
      "y": "x_FEzRu9m36HLN_tue..."
    }
  ]
}
```

---

## Configuration

The service is configured entirely via environment variables.

### Core Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Bind address | `0.0.0.0` |
| `PORT` | Listen port | `5000` |
| `RUST_LOG` | Log level | `jwts=info,tower_http=info` |
| `API_KEY` | API key for authentication (optional) | disabled |

### Rate Limiting

| Variable | Description | Default |
|----------|-------------|---------|
| `RATE_LIMIT_PER_SECOND` | Max requests per second | `100` |
| `RATE_LIMIT_BURST` | Burst size | `50` |

### Signing Keys

You only need to configure keys for the algorithms you intend to use.

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

### Example `.env` file

```env
# Server
HOST=0.0.0.0
PORT=5000
RUST_LOG=jwts=info,tower_http=info

# Security
API_KEY=sk_live_abc123xyz
RATE_LIMIT_PER_SECOND=100
RATE_LIMIT_BURST=50

# HMAC (symmetric)
JWT_SECRET=super_secret_key_at_least_32_characters_long

# RSA (asymmetric)
JWT_PRIVATE_KEY=./keys/rsa_private.pem
JWT_PUBLIC_KEY=./keys/rsa_public.pem

# ECDSA (asymmetric)
JWT_EC_PRIVATE_KEY=./keys/ec_private.pem
JWT_EC_PUBLIC_KEY=./keys/ec_public.pem

# Validation
AUDIENCE=my-api
```

---

## API Reference

### Authentication

If `API_KEY` is set, all requests to `/sign` and `/verify` must include:

```
X-API-Key: your-api-key
```

Health, readiness, and JWKS endpoints **do not** require authentication.

---

### `POST /sign`

Creates a signed JWT.

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `sub` | string | Yes | Subject (who the token refers to) |
| `exp` | integer | Yes | Expiration timestamp (Unix) |
| `iat` | integer | Yes | Issued at timestamp (Unix) |
| `iss` | string | Yes | Issuer |
| `aud` | string | Yes | Audience |
| `nbf` | integer | No | Not before timestamp (Unix) |
| `jti` | string | No | JWT ID (unique identifier for token revocation) |
| `custom` | any | No | Custom claims (string, object, or array) |
| `alg` | string | Yes | Algorithm: `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `PS256`, `PS384`, `PS512` |
| `kid` | string | No | Key ID (included in JWT header) |

**Response (200 OK):**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### `POST /verify`

Verifies a JWT signature and claims.

**Request Body:**

```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200 OK):**

```json
{
  "claims": {
    "sub": "user_123",
    "exp": 1735689600,
    "iat": 1704067200,
    "iss": "my-app",
    "aud": "my-api",
    "nbf": 1704067200,
    "jti": "unique-token-id",
    "custom": {"role": "admin"}
  }
}
```

---

### `GET /.well-known/jwks.json`

Returns the JSON Web Key Set containing public keys for external token verification.

Use this endpoint to:
- Configure external services to verify tokens issued by JWTS
- Implement key rotation by updating keys and letting clients fetch the new JWKS
- Support OAuth 2.0 / OpenID Connect flows

**Response (200 OK):**

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "rsa-key-1",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

---

### `GET /health`

Liveness probe - always returns 200 if the service is running.

```json
{
  "status": "ok",
  "version": "0.2.0"
}
```

---

### `GET /ready`

Readiness probe - returns service readiness and key availability.

```json
{
  "status": "ready",
  "signing_available": true,
  "verification_available": true
}
```

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
| 400 | `UnsupportedAlgorithm` | The requested `alg` is not supported |
| 400 | `InvalidTokenHeader` | The token format is invalid |
| 400 | `InvalidAudience` | The `aud` claim does not match configured `AUDIENCE` |
| 400 | `InvalidIssuer` | The issuer validation failed |
| 400 | `ImmatureSignature` | Token is not yet valid (`nbf` claim) |
| 401 | `ExpiredSignature` | The token has expired (`exp` claim) |
| 401 | `InvalidSignature` | Signature verification failed |
| 401 | `Unauthorized` | Missing or invalid API key |
| 429 | `RateLimitExceeded` | Too many requests |
| 500 | `MissingConfig` | Required environment variable is not set |
| 500 | `KeyAccessError` | Could not read the key file from disk |
| 500 | `SignError` | Internal error during signing |

---

## Integration Examples

### Nginx Reverse Proxy

```nginx
upstream jwts {
    server 127.0.0.1:5000;
}

server {
    listen 443 ssl;
    server_name jwt.example.com;

    location / {
        proxy_pass http://jwts;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: jwts
spec:
  replicas: 3
  selector:
    matchLabels:
      app: jwts
  template:
    metadata:
      labels:
        app: jwts
    spec:
      containers:
      - name: jwts
        image: jwts:0.2.0
        ports:
        - containerPort: 5000
        env:
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: jwts-secrets
              key: jwt-secret
        - name: API_KEY
          valueFrom:
            secretKeyRef:
              name: jwts-secrets
              key: api-key
        livenessProbe:
          httpGet:
            path: /health
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 5000
          initialDelaySeconds: 5
          periodSeconds: 10
```

### Verifying Tokens in Your Application

Using the JWKS endpoint with a Node.js application:

```javascript
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const client = jwksClient({
  jwksUri: 'http://127.0.0.1:5001/.well-known/jwks.json'
});

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

// Verify a token
jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
  if (err) {
    console.error('Token verification failed:', err);
  } else {
    console.log('Decoded token:', decoded);
  }
});
```

---

## Key Generation Guide

Generate keys using OpenSSL. Ensure the service has read permissions for these files.

### RSA (RS256/384/512)

```sh
# Generate 2048-bit RSA key pair
openssl genpkey -algorithm RSA -out rsa_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in rsa_private.pem -pubout -out rsa_public.pem
```

### ECDSA (ES256)

```sh
# Generate P-256 EC key pair
openssl ecparam -name prime256v1 -genkey -noout -out ec256_private.pem
openssl ec -in ec256_private.pem -pubout -out ec256_public.pem
```

### ECDSA (ES384)

```sh
# Generate P-384 EC key pair
openssl ecparam -name secp384r1 -genkey -noout -out ec384_private.pem
openssl ec -in ec384_private.pem -pubout -out ec384_public.pem
```

### RSASSA-PSS (PS256/384/512)

```sh
# Generate 2048-bit RSA key pair (same as RS256)
openssl genpkey -algorithm RSA -out pss_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in pss_private.pem -pubout -out pss_public.pem
```

---

## Development & Testing

### Running Tests

The integration tests require a running server.

1. **Start the server** (with all keys configured):

   ```sh
   export JWT_SECRET=test
   export JWT_PRIVATE_KEY=./pem/rsa_private.pem
   export JWT_PUBLIC_KEY=./pem/rsa_public.pem
   export AUDIENCE=provider
   cargo run
   ```

2. **Run tests** (in another terminal):

   ```sh
   export BASE_URL=http://127.0.0.1:5000
   cargo test
   ```

### Using Make

```sh
make c    # cargo check
make r    # cargo run
make w    # cargo watch -x run
make t    # cargo test --test api
make b    # build and run release
```

---

## Deployment

### Systemd

```sh
sudo cp jwts.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable jwts
sudo systemctl start jwts
```

### Docker

```sh
# Production
docker-compose up -d jwts

# Development with hot reload
docker-compose --profile dev up jwts-dev
```

---

## License

MIT
