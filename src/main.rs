//! viralefy_api — Rust dispatcher.
//!
//! Ponto único de entrada da Viralefy. Por trás de Caddy + Coraza WAF.
//!
//! Pipeline de request:
//!   1. Path safety check (`enforce_path_safety` middleware)
//!   2. Rate limit per-IP (`tower_governor`)
//!   3. Request-id propagation (W3C traceparent-friendly)
//!   4. JWT verify offline (rota-by-rota: `require_auth` / `optional_auth`)
//!   5. Reverse proxy pros 4 upstreams (`proxy::forward`)
//!
//! Estado compartilhado em `AppState`:
//!   - `http_client`: reqwest pool
//!   - `jwks_cache`: chave pública RS256 (TTL 60s)
//!   - `revocation_set`: hot-set sqlx + LISTEN/NOTIFY

mod auth;
mod config;
mod error;
mod metrics;
mod middleware;
mod observability;
mod proxy;
mod routes;
mod security;

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{
    middleware as axum_middleware,
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
use tracing::{info, warn};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<config::Config>,
    pub http_client: reqwest::Client,
    pub jwks_cache: Option<auth::JWKSCache>,
    pub revocation_set: Option<auth::RevocationSet>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    observability::init_tracing();

    // Inicializa o recorder Prometheus ANTES de qualquer outra coisa que
    // possa emitir métricas. Se falhar, log + segue sem métricas — não vale
    // crashar o dispatcher inteiro por causa do scrape.
    let metrics_handle = match metrics::init() {
        Ok(h) => Some(h),
        Err(e) => {
            warn!(error = %e, "metrics recorder init failed; /metrics ficará 404");
            None
        }
    };

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

    // JWKS cache — falha silenciosa em scaffold; rotas que precisam de auth
    // viram 401 com mensagem clara em vez de crash do binário.
    let jwks_cache = if cfg.auth_url.is_empty() {
        warn!("VAPI_AUTH_URL vazio — auth offline desabilitado");
        None
    } else {
        Some(auth::JWKSCache::new(
            &cfg.auth_url,
            http_client.clone(),
            cfg.jwks_cache_ttl_secs,
        ))
    };

    // Hot-set de revogação — opt-in (precisa DATABASE_URL).
    let revocation_set = if cfg.database_url.is_empty() {
        warn!("DATABASE_URL vazio — hot-set de revogação desabilitado");
        None
    } else {
        match auth::RevocationSet::new(&cfg.database_url, cfg.revoked_jtis_poll_secs).await {
            Ok(set) => Some(set),
            Err(e) => {
                warn!(error = %e, "revocation_set init failed — continuando sem hot-set");
                None
            }
        }
    };

    let state = AppState {
        config: Arc::new(cfg.clone()),
        http_client,
        jwks_cache,
        revocation_set,
    };

    // Rate limiter.
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1)
            .burst_size(30)
            .finish()
            .expect("governor config invalid"),
    );

    let request_id_layer = ServiceBuilder::new()
        .layer(SetRequestIdLayer::new(
            axum::http::HeaderName::from_static("x-request-id"),
            MakeRequestUuid,
        ))
        .layer(PropagateRequestIdLayer::new(axum::http::HeaderName::from_static(
            "x-request-id",
        )));

    // Router final. enforce_path_safety + enforce_hot_set como middlewares
    // GLOBAIS. Path safety roda primeiro (bloqueia URLs malformadas antes
    // de qualquer auth). Hot-set checa revogação de Bearer (skippa pra rotas
    // públicas sem token). Defense in depth: core também deve checar
    // revoked_jtis em ValidateToken (TODO em viralefy_core).
    //
    // `/metrics` é registrado ANTES do `fallback` pra ser servido pelo próprio
    // dispatcher — caso contrário cai no proxy_handler e o Prometheus acaba
    // raspando as métricas do core (era o bug do SLO dispatcher_overhead_p95).
    // O handle é capturado num closure pra não conflitar com o `with_state`
    // do AppState do resto do router.
    let metrics_route = match metrics_handle.clone() {
        Some(handle) => get(move || {
            let handle = handle.clone();
            async move {
                (
                    axum::http::StatusCode::OK,
                    [(
                        axum::http::header::CONTENT_TYPE,
                        "text/plain; version=0.0.4",
                    )],
                    handle.render(),
                )
            }
        }),
        // Se métricas falharem na init, devolve 503 — o scrape do Prometheus
        // marca o target como down ao invés de "magicamente funcionar via proxy".
        None => get(|| async {
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "metrics recorder unavailable",
            )
        }),
    };

    let app = Router::new()
        .route("/_health", get(routes::health))
        .route("/_ready", get(routes::ready))
        // /health: alias unificado (PHASE-10 — 2026-06-11). Antes da PHASE-10
        // `/health` caía no fallback e era proxied pro core (que TEM /health),
        // o que mascarava o dispatcher como verde mesmo quando o dispatcher
        // estava com problema. Registrar o alias localmente garante que o
        // probe valida o dispatcher em si.
        .route("/health", get(routes::health))
        .route("/metrics", metrics_route)
        .fallback(any(proxy::proxy_handler))
        .with_state(state.clone())
        .layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::enforce_hot_set,
        ))
        .layer(axum_middleware::from_fn(middleware::enforce_path_safety))
        // Camada de métricas roda DEPOIS do path-safety e do hot-set pra que
        // requests rejeitados sejam contados com o status correto (400/401)
        // e o timing inclua todo o pipeline observável pelo cliente.
        .layer(axum_middleware::from_fn(metrics::track))
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

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
