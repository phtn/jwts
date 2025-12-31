mod auth;
mod config;
mod error;
mod keys;
mod models;
mod routes;

use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use tower::ServiceBuilder;
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::GlobalKeyExtractor, GovernorLayer,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

use crate::auth::middleware::should_skip_auth;
use crate::config::Config;
use crate::keys::{Jwks, KeyStore};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub key_store: KeyStore,
    pub jwks: Jwks,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file if present
    dotenvy::dotenv().ok();

    // Initialize tracing with env filter
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "jwts=info,tower_http=info".into()),
        )
        .init();

    // Load configuration
    let config = Config::from_env();
    config.log_summary();

    // Load keys
    let key_store = KeyStore::from_config(&config)?;
    info!(
        "Key store initialized: signing={}, verification={}",
        key_store.has_signing_capability(),
        key_store.has_verification_capability()
    );

    // Build JWKS
    let jwks = Jwks::from_key_store(&key_store);
    if !jwks.is_empty() {
        info!("JWKS endpoint will serve {} key(s)", jwks.keys.len());
    }

    // Build application state
    let state = AppState {
        config: Arc::new(config.clone()),
        key_store,
        jwks,
    };

    // Build rate limiter
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(config.rate_limit_per_second)
        .burst_size(config.rate_limit_burst)
        .key_extractor(GlobalKeyExtractor)
        // .key_extractor(PeerIpKeyExtractor)
        .finish()
        .expect("Failed to build rate limiter config");

    let governor_limiter = governor_conf.limiter().clone();
    let governor_layer = GovernorLayer {
        config: Arc::new(governor_conf),
    };

    // API key for auth middleware
    let api_key = config.api_key.clone();

    // Build router
    let app = Router::new()
        // Public routes (no auth required)
        .route("/health", get(routes::health::health))
        .route("/ready", get(routes::health::ready))
        .route("/.well-known/jwks.json", get(routes::jwks::get_jwks))
        // Protected routes
        .route("/sign", post(routes::sign::sign_jwt))
        .route("/verify", post(routes::verify::verify_jwt))
        .with_state(state)
        // Apply middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
                .layer(governor_layer)
                .layer(middleware::from_fn(move |req: Request, next: Next| {
                    let api_key = api_key.clone();
                    async move { auth_middleware(api_key, req, next).await }
                })),
        );

    // Get bind address
    let addr = config.socket_addr();

    // Setup graceful shutdown
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("jwts {} listening on {}", env!("CARGO_PKG_VERSION"), addr);

    // Start background task to periodically clear rate limiter state
    let limiter = governor_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            limiter.retain_recent();
        }
    });

    // Run server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Server shutdown complete");
    Ok(())
}

/// Authentication middleware that skips certain paths
async fn auth_middleware(api_key: Option<String>, req: Request, next: Next) -> Response {
    // Skip auth for public endpoints
    if should_skip_auth(req.uri().path()) {
        return next.run(req).await;
    }

    // Apply API key auth
    auth::api_key_auth(api_key, req, next).await
}

/// Graceful shutdown signal handler
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
        _ = terminate => {
            info!("Received SIGTERM, initiating graceful shutdown");
        }
    }
}
