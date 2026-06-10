//! Middlewares axum específicos do dispatcher.
//!
//! - `require_auth` — extrai Bearer token, valida via JWKS+hot-set, injeta
//!   Claims em request extension. Rotas que NÃO precisam de auth não usam.
//! - `enforce_path_safety` — bloqueia paths com pattern proibido antes de
//!   qualquer roteamento (defense in depth com Coraza).

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::{
    auth::{AuthError, Claims, JWKSCache, RevocationSet},
    security,
    AppState,
};

/// `enforce_path_safety` — primeiro middleware. Aplicado SEMPRE.
pub async fn enforce_path_safety(req: Request<Body>, next: Next) -> Response {
    if !security::path_is_safe(req.uri().path()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": {"code": "BAD_REQUEST", "message": "unsafe path"}
            })),
        )
            .into_response();
    }
    next.run(req).await
}

/// `optional_auth` — valida JWT se presente; passthrough se ausente.
/// Usado em rotas que aceitam request anônima (ex.: checkout pode ser
/// guest OR logged-in).
pub async fn optional_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if let Some(token) = extract_bearer(&req) {
        if let Some(jwks) = &state.jwks_cache {
            match jwks.verify(token).await {
                Ok(claims) => {
                    if claim_is_revoked(&claims, &state).await {
                        // Não rejeita — apenas não popula extension.
                        // Caller que exige auth verá ausência.
                    } else {
                        req.extensions_mut().insert(claims);
                    }
                }
                Err(_) => { /* anon */ }
            }
        }
    }
    next.run(req).await
}

/// `require_auth` — exige JWT válido. 401 caso contrário.
pub async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let jwks = match &state.jwks_cache {
        Some(j) => j.clone(),
        None => return unauthorized("auth not configured"),
    };
    let token = match extract_bearer(&req) {
        Some(t) => t,
        None => return unauthorized("missing bearer token"),
    };
    let claims = match jwks.verify(token).await {
        Ok(c) => c,
        Err(AuthError::Expired) => return unauthorized("token expired"),
        Err(AuthError::Revoked) => return unauthorized("token revoked"),
        Err(AuthError::Malformed) => return unauthorized("token malformed"),
        Err(AuthError::InvalidSignature) => return unauthorized("invalid signature"),
        Err(_) => return unauthorized("auth error"),
    };
    if claim_is_revoked(&claims, &state).await {
        return unauthorized("token revoked");
    }
    req.extensions_mut().insert(claims);
    next.run(req).await
}

fn extract_bearer(req: &Request<Body>) -> Option<&str> {
    req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

async fn claim_is_revoked(claims: &Claims, state: &AppState) -> bool {
    if claims.jti.is_empty() {
        return false;
    }
    if let Some(rev) = &state.revocation_set {
        return rev.is_revoked(&claims.jti).await;
    }
    false
}

fn unauthorized(msg: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": {"code": "UNAUTHORIZED", "message": msg}
        })),
    )
        .into_response()
}

// Wrappers acessíveis pros handlers que precisam consultar JWKS/RevocSet
// (rotas internas tipo /_revoked/check, /_jwks/refresh — não públicas).
#[allow(dead_code)]
pub fn jwks_cache(state: &AppState) -> Option<&JWKSCache> {
    state.jwks_cache.as_ref()
}

#[allow(dead_code)]
pub fn revocation_set(state: &AppState) -> Option<&RevocationSet> {
    state.revocation_set.as_ref()
}
