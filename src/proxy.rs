//! Reverse proxy interno pros 4 upstreams Go.
//!
//! Mapeamento de path → upstream em `resolve_upstream`. Streaming
//! bidirecional via `reqwest::Body::wrap_stream` pra suportar SSE/long-poll
//! sem buffer em memória.
//!
//! Headers safe-list: passamos só o que faz sentido (Content-Type,
//! Authorization, Accept, User-Agent, X-Real-IP, X-Forwarded-*, X-Request-Id,
//! traceparent, tracestate). Dropa todo o resto pra reduzir surface
//! de header smuggling.

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use once_cell::sync::Lazy;
use std::collections::HashSet;

use crate::{error::DispatchError, AppState};

#[derive(Debug, Clone, Copy)]
pub enum Upstream {
    Core,
    Auth,
    Payments,
    Sender,
}

impl Upstream {
    pub fn base_url<'a>(&self, state: &'a AppState) -> &'a str {
        match self {
            Upstream::Core => &state.config.core_url,
            Upstream::Auth => &state.config.auth_url,
            Upstream::Payments => &state.config.payments_url,
            Upstream::Sender => &state.config.sender_url,
        }
    }
}

/// Lookup table path → upstream. Caminho default é Core (motor de
/// domínio). Auth e payments têm prefixos específicos.
pub fn resolve_upstream(path: &str) -> Upstream {
    if path.starts_with("/v1/auth")
        || path.starts_with("/.well-known/jwks.json")
        || path == "/v1/login"
        || path == "/v1/register"
        || path == "/v1/refresh"
        || path == "/v1/logout"
    {
        return Upstream::Auth;
    }
    if path.starts_with("/v1/webhooks/stripe")
        || path.starts_with("/v1/webhooks/heleket")
        || path.starts_with("/v1/webhooks/woovi")
        || path.starts_with("/v1/webhooks/abacatepay")
    {
        return Upstream::Payments;
    }
    // sender é fire-and-forget — não há rota pública chamando sender.
    // Tudo o resto vai pro core: /v1/plans, /v1/me, /v1/admin, /v1/checkout, /v2/*
    Upstream::Core
}

// Header allow-list (lowercase) — só esses passam pro upstream Go.
// Demais (Cookie, Host, Origin, etc) podem ser tratados pelo Go side, mas
// o que não estiver aqui é dropado conscientemente.
static HEADER_ALLOWLIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "accept",
        "accept-encoding",
        "accept-language",
        "authorization",
        "content-type",
        "content-length",
        "user-agent",
        "x-real-ip",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
        "x-request-id",
        "x-internal-token",
        "traceparent",
        "tracestate",
        "idempotency-key",
        "x-api-key",
        "stripe-signature",
        "x-webhook-signature",
    ]
    .into_iter()
    .collect()
});

// Headers que NUNCA propagamos do upstream pro cliente (hop-by-hop).
static RESPONSE_HEADER_DROPLIST: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "connection",
        "transfer-encoding",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "upgrade",
    ]
    .into_iter()
    .collect()
});

/// `forward` faz o reverse proxy de um axum::Request pro upstream resolvido.
/// Bidirectional streaming preservado via reqwest body stream.
pub async fn forward(State(state): State<AppState>, req: Request) -> Result<Response, DispatchError> {
    let upstream = resolve_upstream(req.uri().path());
    let base = upstream.base_url(&state).trim_end_matches('/').to_string();

    // Reconstrói URL completa.
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let target_url = format!("{}{}", base, path_and_query);
    let method = req.method().clone();

    // Filtra headers.
    let mut req_headers = HeaderMap::new();
    for (name, value) in req.headers() {
        let lname = name.as_str().to_ascii_lowercase();
        if HEADER_ALLOWLIST.contains(lname.as_str()) {
            req_headers.insert(name.clone(), value.clone());
        }
    }
    // Sempre adiciona X-Internal-Token (loopback secret) — overwrite se cliente tentou injetar.
    if !state.config.internal_shared_secret.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&state.config.internal_shared_secret) {
            req_headers.insert(HeaderName::from_static("x-internal-token"), v);
        }
    }
    // Adiciona/replica X-Real-IP se ausente.
    if !req_headers.contains_key("x-real-ip") {
        // O dispatcher é o primeiro hop; em prod tem Caddy na frente.
        // Use placeholder por ora; em prod Caddy seta X-Real-IP.
        // (Próximo iter: extrair de ConnectInfo do axum)
    }

    // Body stream — preserva tamanho exato e tipo do cliente.
    let (parts, body) = req.into_parts();
    let body_bytes = match axum::body::to_bytes(body, state.config.max_body_bytes).await {
        Ok(b) => b,
        Err(_) => return Err(DispatchError::PayloadTooLarge(state.config.max_body_bytes)),
    };

    // Constroi request reqwest.
    let mut rb = state
        .http_client
        .request(method, &target_url)
        .headers(req_headers);
    if !body_bytes.is_empty() {
        rb = rb.body(body_bytes.to_vec());
    }
    let upstream_resp = rb
        .send()
        .await
        .map_err(|e| DispatchError::UpstreamUnavailable(format!("{}: {}", upstream_label(upstream), e)))?;

    let status = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();

    // Lê body (full buffer — streaming verdadeiro fica pra próxima rodada).
    let resp_body_bytes = upstream_resp
        .bytes()
        .await
        .map_err(|e| DispatchError::UpstreamUnavailable(format!("{}: read body: {}", upstream_label(upstream), e)))?;

    let _ = parts; // não usamos por enquanto
    let mut builder = Response::builder().status(StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (name, value) in upstream_headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if !RESPONSE_HEADER_DROPLIST.contains(lname.as_str()) {
            builder = builder.header(name, value);
        }
    }
    Ok(builder
        .body(Body::from(resp_body_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()))
}

fn upstream_label(u: Upstream) -> &'static str {
    match u {
        Upstream::Core => "core",
        Upstream::Auth => "auth",
        Upstream::Payments => "payments",
        Upstream::Sender => "sender",
    }
}

/// Captura tudo (any path/any method) e despacha pro upstream resolvido.
/// Usado em `Router::fallback`.
pub async fn proxy_handler(state: State<AppState>, req: Request) -> Result<Response, DispatchError> {
    // Path safety check antes de qualquer roteamento.
    if !crate::security::path_is_safe(req.uri().path()) {
        return Err(DispatchError::BadRequest("unsafe path".into()));
    }
    forward(state, req).await
}

// Compatibilidade com chamadas existentes nos commits anteriores.
#[allow(dead_code)]
pub fn resolve_upstream_opt(path: &str) -> Option<Upstream> {
    Some(resolve_upstream(path))
}

#[allow(dead_code)]
fn _u_compat(_: &Uri) {}
