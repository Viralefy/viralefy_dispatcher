//! Erros canônicos do dispatcher. Convertem-se em HTTP via IntoResponse.
//!
//! Política:
//! - 400 BAD_REQUEST: body malformado, header inválido.
//! - 401 UNAUTHORIZED: token ausente/expirado/revogado.
//! - 403 FORBIDDEN: token válido mas sem permissão (passthrough do upstream).
//! - 404 NOT_FOUND: rota desconhecida.
//! - 413 PAYLOAD_TOO_LARGE: body excedeu VAPI_MAX_BODY_BYTES.
//! - 429 TOO_MANY_REQUESTS: rate limit.
//! - 502 BAD_GATEWAY: upstream Go fora ou retornou erro de comunicação.
//! - 503 SERVICE_UNAVAILABLE: dispatcher em shutdown / maintenance.
//! - 500 INTERNAL: bug do dispatcher.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DispatchError {
    #[error("body too large: {0} bytes")]
    PayloadTooLarge(usize),

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("rate limit exceeded")]
    RateLimited,

    #[error("upstream unavailable: {0}")]
    UpstreamUnavailable(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for DispatchError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            DispatchError::PayloadTooLarge(_) => (StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE"),
            DispatchError::BadRequest(_) => (StatusCode::BAD_REQUEST, "BAD_REQUEST"),
            DispatchError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "UNAUTHORIZED"),
            DispatchError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
            DispatchError::UpstreamUnavailable(_) => (StatusCode::BAD_GATEWAY, "BAD_GATEWAY"),
            DispatchError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL_ERROR"),
        };

        let body = Json(json!({
            "error": {
                "code": code,
                "message": self.to_string(),
            }
        }));

        (status, body).into_response()
    }
}
