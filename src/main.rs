//! viralefy_api — Rust dispatcher.
//!
//! Ponto único de entrada da Viralefy. Por trás de Caddy + Coraza WAF.
//! Responsabilidades:
//!
//! 1. Sanitização de input (path traversal denylist, body size).
//! 2. Rate limit per-IP via tower_governor.
//! 3. Reverse proxy seletivo pros 4 upstreams Go: core, auth, payments, sender.
//! 4. Request ID + trace propagation.

mod config;
mod error;
mod observability;
mod proxy;
mod routes;
mod security;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    routing::{any, get},
    Router,
};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
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
        payments_url = %cfg.payments_url,
        sender_url = %cfg.sender_url,
        max_body_bytes = cfg.max_body_bytes,
        "viralefy-api dispatcher starting"
    );

    let http_client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .pool_idle_timeout(Duration::from_secs(90))
        .user_agent("viralefy-api/0.1")
        .build()?;

    let state = AppState {
        config: Arc::new(cfg.clone()),
        http_client,
    };

    // Rate limiter: 30 req/s burst + replenish 1/s. Per-IP (PeerIp default).
    // Em prod com Caddy na frente, este IP é do Caddy → trocar pra SmartIpKey
    // após a layer de X-Forwarded-For ser configurada.
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(30)
            .finish()
            .expect("governor config invalid"),
    );

    // Router: rotas operacionais diretas, tudo o mais cai no proxy.
    let request_id_layer = ServiceBuilder::new()
        .layer(SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(PropagateRequestIdLayer::new(axum::http::HeaderName::from_static(
            "x-request-id",
        )));

    let app = Router::new()
        .route("/_health", get(routes::health))
        .route("/_ready", get(routes::ready))
        .fallback(any(proxy::proxy_handler))
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(request_id_layer)
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::new(Duration::from_secs(60)))
                .layer(GovernorLayer {
                    config: governor_conf,
                }),
        );

    let addr: SocketAddr = cfg.bind_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(addr = %addr, "viralefy-api listening");

    // `into_make_service_with_connect_info` injeta `ConnectInfo<SocketAddr>`
    // em cada request — necessário pro tower_governor extrair IP do peer
    // (PeerIpKeyExtractor) sem cair em "Unable To Extract Key!".
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
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
