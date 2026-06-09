//! viralefy_api — Rust dispatcher.
//!
//! Ponto único de entrada da Viralefy. Por trás de Caddy + Coraza WAF.
//! Responsabilidades em alto nível:
//!
//! 1. Sanitização de input (XSS strip, regex denylist, body size).
//! 2. Validação JWT offline (RS256 + JWKS cache) e hot-set de revogação.
//! 3. Rate limit per-IP + per-token.
//! 4. Reverse proxy seletivo pros 4 upstreams Go: core, auth, payments, sender.
//! 5. Request ID + trace propagation (W3C `traceparent`).
//!
//! Não-objetivos: business logic, mint de token, persistência.
//!
//! Scaffold inicial (PHASE-9 §4.4). Health endpoint funcional;
//! middlewares completos entram em commits subsequentes.

mod config;
mod error;
mod observability;
mod proxy;
mod routes;
mod security;

use std::sync::Arc;

use axum::{routing::get, Router};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
    pub http_client: reqwest::Client,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    observability::init_tracing();

    let cfg = config::Config::load()?;
    info!(
        bind_addr = %cfg.bind_addr,
        core_url = %cfg.core_url,
        auth_url = %cfg.auth_url,
        "viralefy-api starting (scaffold)"
    );

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .pool_idle_timeout(std::time::Duration::from_secs(90))
        .user_agent("viralefy-api/0.1")
        .build()?;

    let state = AppState {
        config: Arc::new(cfg.clone()),
        http_client,
    };

    let app = Router::new()
        .route("/_health", get(routes::health))
        .route("/_ready", get(routes::ready))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = TcpListener::bind(&cfg.bind_addr).await?;
    info!(addr = %cfg.bind_addr, "viralefy-api listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("shutdown signal received");
}
