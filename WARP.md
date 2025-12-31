# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Development Commands

### Building and Running
```bash
# Development
cargo run                        # Run with default config (requires JWT_SECRET env var)
cargo watch -x run              # Hot reload during development
make r                          # Alias for cargo run
make w                          # Alias for cargo watch

# Production build
cargo build --release
make b                          # Build release and run

# Type checking
cargo check
make c                          # Alias for cargo check
```

### Testing
Tests require a **running server** with configured keys. Run in two separate terminals:

**Terminal 1 - Start server:**
```bash
export JWT_SECRET=test
export JWT_PRIVATE_KEY=./pem/rsa_private.pem
export JWT_PUBLIC_KEY=./pem/rsa_public.pem
export AUDIENCE=provider
cargo run
```

**Terminal 2 - Run tests:**
```bash
export BASE_URL=http://127.0.0.1:5000
cargo test --test api
make t                          # Alias for cargo test --test api
```

### Docker
```bash
docker-compose up -d            # Production mode
docker-compose --profile dev up # Development with hot reload
```

### Deployment
```bash
./deploy.sh                     # Deploy to remote server (configure HOST, ROOT in script)
```

## Architecture

### Module Structure
```
src/
├── main.rs          # Server setup, middleware stack, graceful shutdown
├── config.rs        # Environment-based configuration (12-factor)
├── error.rs         # Centralized error types with HTTP status mapping
├── models.rs        # Request/response models
├── auth/            # API key authentication
│   ├── mod.rs
│   └── middleware.rs
├── keys/            # Cryptographic key management
│   ├── mod.rs
│   ├── loader.rs    # Key loading and caching
│   └── jwks.rs      # JWKS endpoint generation
└── routes/          # HTTP handlers
    ├── mod.rs
    ├── sign.rs      # POST /sign
    ├── verify.rs    # POST /verify
    ├── jwks.rs      # GET /.well-known/jwks.json
    └── health.rs    # GET /health, /ready
```

### Application State
The `AppState` struct is shared across all handlers via Axum's state management:
- `config: Arc<Config>` - Environment configuration
- `key_store: KeyStore` - Preloaded cryptographic keys (loaded once at startup)
- `jwks: Jwks` - Public key set for JWKS endpoint

Keys are loaded **once at startup** and cached in memory for performance. No disk I/O occurs during request handling.

### Middleware Stack (Applied in Order)
1. **TraceLayer** - HTTP request/response logging via `tracing`
2. **CorsLayer** - Permissive CORS (allows all origins)
3. **GovernorLayer** - IP-based rate limiting
4. **API Key Auth** - Optional authentication (skipped for `/health`, `/ready`, `/.well-known/jwks.json`)

### Error Handling Pattern
All routes return `Result<Json<T>, AppError>`. The `AppError` type:
- Implements `IntoResponse` for automatic HTTP responses
- Maps error variants to appropriate HTTP status codes (400, 401, 429, 500)
- Returns structured JSON: `{"error_type": "...", "error_msg": "..."}`

### Algorithm Support
- **HMAC**: HS256, HS384, HS512 (symmetric, uses `JWT_SECRET`)
- **RSA**: RS256, RS384, RS512 (asymmetric, uses `JWT_PRIVATE_KEY`/`JWT_PUBLIC_KEY`)
- **ECDSA**: ES256 (P-256), ES384 (P-384) (asymmetric, uses `JWT_EC_PRIVATE_KEY`/`JWT_EC_PUBLIC_KEY`)
- **RSA-PSS**: PS256, PS384, PS512 (asymmetric, uses `JWT_PSS_PRIVATE_KEY`/`JWT_PSS_PUBLIC_KEY`)

Algorithm is specified per-request in the `alg` field, not at service level.

## Configuration

All configuration is via **environment variables** (12-factor app pattern). No config files.

### Required (Minimum)
- `JWT_SECRET` - For HMAC algorithms (HS256/384/512)

### Optional
- `HOST` (default: `0.0.0.0`)
- `PORT` (default: `5000`)
- `API_KEY` - Enable authentication on `/sign` and `/verify`
- `AUDIENCE` - Validate `aud` claim during verification
- `RATE_LIMIT_PER_SECOND` (default: `100`)
- `RATE_LIMIT_BURST` (default: `50`)
- `RUST_LOG` (default: `jwts=info,tower_http=info`)

Key paths (only needed for asymmetric algorithms):
- `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY` (RSA)
- `JWT_EC_PRIVATE_KEY`, `JWT_EC_PUBLIC_KEY` (ECDSA)
- `JWT_PSS_PRIVATE_KEY`, `JWT_PSS_PUBLIC_KEY` (RSA-PSS)

Use `.env` file for local development (loaded via `dotenvy`).

## Key Development Patterns

### Adding a New Route
1. Create handler in `src/routes/your_route.rs`
2. Export from `src/routes/mod.rs`
3. Register in `main.rs` router with `.route("/path", method(handler))`
4. Add to public routes section if it should skip auth

### Adding Support for a New Algorithm
1. Update `KeyStore` in `src/keys/loader.rs` to load required keys
2. Add algorithm variant to sign/verify logic in route handlers
3. Update `Jwks` generation in `src/keys/jwks.rs` if public key is exposed
4. Add corresponding environment variable to `Config` in `src/config.rs`

### Adding a New Error Type
1. Add variant to `AppError` enum in `src/error.rs`
2. Implement status code mapping in `status_code()` method
3. Implement error type string in `error_type()` method

### Working with Claims
Custom claims support any JSON value (string, object, array). They are stored as `serde_json::Value` and preserved during sign/verify operations.

## Important Notes

- **Tests are integration tests** that hit a live server - not unit tests
- **Graceful shutdown** handles SIGTERM and SIGINT for clean container stops
- **Rate limiting** uses IP-based tracking with periodic cleanup (every 60s)
- **Keys are never reloaded** - restart service to update keys
- **No key rotation** - implement externally if needed
- **JWKS endpoint** auto-generates from loaded public keys (RSA, EC, PSS)
