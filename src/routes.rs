//! Handlers diretos do dispatcher (health, ready, etc).
//!
//! Tudo que NÃO é proxy pros upstreams Go. Mantido propositalmente curto:
//! qualquer business logic vai pro `viralefy_core`. Estes endpoints só
//! servem pra ops (load balancer health check, k8s readiness gate).

use axum::Json;
use serde_json::{json, Value};

pub async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "viralefy-api",
        "stage": "scaffold",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

pub async fn ready() -> Json<Value> {
    // Próximo commit: confirma conexão DB (hot-set), JWKS cache hidratado,
    // 4 upstreams alcançáveis.
    Json(json!({
        "ready": true,
        "checks": {
            "db": "skipped (scaffold)",
            "jwks": "skipped (scaffold)",
            "upstream_core": "skipped (scaffold)",
            "upstream_auth": "skipped (scaffold)",
            "upstream_payments": "skipped (scaffold)",
            "upstream_sender": "skipped (scaffold)",
        }
    }))
}
