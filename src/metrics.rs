//! Prometheus metrics endpoint pro dispatcher.
//!
//! Por que existe: antes deste módulo, o job_name `viralefy-dispatcher` no
//! Prometheus apontava pra `127.0.0.1:8090/metrics`, mas o dispatcher Rust
//! não expunha esse path — então caía no fallback do `proxy_handler` e era
//! servido pelo `viralefy-core` (Go) em `127.0.0.1:8084/metrics`. Resultado:
//! todas as séries com `service="viralefy-dispatcher"` eram, na verdade, as
//! métricas do core, e o SLO `dispatcher_overhead_p95` media a latência do
//! core (49–61 ms) e nunca a do dispatcher (≈1 ms p95 medido em loopback).
//!
//! Comportamento:
//! - `init()` cria um recorder Prometheus e devolve um handle que serializa o
//!   estado atual via `render()`. Buckets compatíveis com os do core
//!   (`http_request_duration_seconds`) pra dashboards funcionarem com um
//!   filtro `service=...` apenas.
//! - `track` é um middleware axum que mede a duração de cada request,
//!   normaliza o path (route, não URL completo, pra cardinalidade baixa) e
//!   incrementa contadores + histograma.
//! - `/metrics` é registrado ANTES do `fallback(proxy_handler)` no router,
//!   garantindo que o scrape do Prometheus seja respondido localmente.

use std::time::Instant;

use axum::{
    body::Body,
    extract::{MatchedPath, Request},
    middleware::Next,
    response::Response,
};
pub use metrics_exporter_prometheus::PrometheusHandle;
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};

/// Mesmos buckets que o `viralefy-core` Go usa pra
/// `http_request_duration_seconds` — assim os dashboards/SLOs herdados
/// funcionam só trocando o filtro `service`.
const HTTP_DURATION_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Buckets finos no piso pra capturar o overhead do dispatcher, que em
/// loopback fica sub-milissegundo na maior parte das vezes.
const OVERHEAD_BUCKETS: &[f64] = &[
    0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
];

/// Inicializa o recorder global de métricas. Idempotente em relação ao
/// próprio processo: chamado uma vez no `main`.
pub fn init() -> anyhow::Result<PrometheusHandle> {
    let handle = PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Full("http_request_duration_seconds".to_string()),
            HTTP_DURATION_BUCKETS,
        )?
        .set_buckets_for_metric(
            Matcher::Full("dispatcher_overhead_seconds".to_string()),
            OVERHEAD_BUCKETS,
        )?
        .set_buckets_for_metric(
            Matcher::Full("dispatcher_upstream_seconds".to_string()),
            HTTP_DURATION_BUCKETS,
        )?
        .install_recorder()?;
    Ok(handle)
}

/// Middleware que mede latência por request. Normaliza `path` pro template
/// da rota (`MatchedPath`) — pra rotas que caem no `fallback` (todo o proxy
/// reverso) o axum não fornece `MatchedPath`, então usamos o primeiro
/// segmento do path como agregador (`/v1/plans` vira `/v1/*` etc.) pra
/// manter cardinalidade baixa.
pub async fn track(req: Request<Body>, next: Next) -> Response {
    let started = Instant::now();
    let method = req.method().as_str().to_owned();
    let path_label = route_label(&req);

    let resp = next.run(req).await;

    let status = resp.status().as_u16().to_string();
    let elapsed = started.elapsed().as_secs_f64();

    metrics::histogram!(
        "http_request_duration_seconds",
        "service" => "viralefy-dispatcher",
        "method" => method.clone(),
        "path" => path_label.clone(),
        "status" => status.clone(),
    )
    .record(elapsed);

    metrics::counter!(
        "http_requests_total",
        "service" => "viralefy-dispatcher",
        "method" => method,
        "path" => path_label,
        "status" => status,
    )
    .increment(1);

    resp
}

fn route_label(req: &Request<Body>) -> String {
    if let Some(matched) = req.extensions().get::<MatchedPath>() {
        return matched.as_str().to_owned();
    }
    // Fallback: agrega por primeiro segmento pra evitar explosão de cardinalidade
    // (`/v1/plans/123` → `/v1/*`, `/v2/anything` → `/v2/*`, `/` → `/`).
    let path = req.uri().path();
    if path == "/" {
        return "/".to_owned();
    }
    let mut segments = path.trim_start_matches('/').split('/');
    match segments.next() {
        Some(first) if !first.is_empty() => {
            if segments.next().is_some() {
                format!("/{}/*", first)
            } else {
                format!("/{}", first)
            }
        }
        _ => "/other".to_owned(),
    }
}
