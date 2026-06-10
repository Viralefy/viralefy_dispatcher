//! Carrega configuração via env. Prefixo `VAPI_` pra evitar colisão.
//!
//! Algumas envs são compartilhadas com o resto do stack: `DATABASE_URL`
//! (pra hot-set), `INTERNAL_SHARED_SECRET` (pra X-Internal-Token nos
//! upstreams), `JWT_PRIVATE_KEY_PATH` opcional pra cache local de JWKS.

use anyhow::{Context, Result};
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub core_url: String,
    pub auth_url: String,
    pub payments_url: String,
    pub sender_url: String,
    pub database_url: String,
    pub internal_shared_secret: String,
    pub jwks_cache_ttl_secs: u64,
    pub revoked_jtis_poll_secs: u64,
    pub max_body_bytes: usize,
    pub log_level: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        Ok(Self {
            bind_addr: getenv("VAPI_BIND_ADDR", "127.0.0.1:8090"),
            core_url: getenv("VAPI_CORE_URL", "http://127.0.0.1:8084"),
            auth_url: getenv("VAPI_AUTH_URL", "http://127.0.0.1:8083"),
            payments_url: getenv("VAPI_PAYMENTS_URL", "http://127.0.0.1:8081"),
            sender_url: getenv("VAPI_SENDER_URL", "http://127.0.0.1:8082"),
            database_url: env::var("DATABASE_URL").unwrap_or_default(),
            internal_shared_secret: env::var("INTERNAL_SHARED_SECRET").unwrap_or_default(),
            jwks_cache_ttl_secs: env_u64("VAPI_JWKS_CACHE_TTL_SECS", 60)?,
            // 30s reconcile fallback. LISTEN/NOTIFY entrega revogações em
            // tempo real; o polling existe apenas pra reconciliar caso a
            // conexão LISTEN tenha caído. Antes era 5s, o que gerava
            // queries inúteis e log noise — sem ganho real de latência de
            // propagação de revogação.
            revoked_jtis_poll_secs: env_u64("VAPI_REVOKED_POLL_SECS", 30)?,
            max_body_bytes: env_u64("VAPI_MAX_BODY_BYTES", 1_048_576)? as usize, // 1 MB default
            log_level: getenv("VAPI_LOG_LEVEL", "info"),
        })
    }
}

fn getenv(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn env_u64(key: &str, default: u64) -> Result<u64> {
    match env::var(key) {
        Ok(v) => v.parse().with_context(|| format!("invalid {}: {}", key, v)),
        Err(_) => Ok(default),
    }
}
