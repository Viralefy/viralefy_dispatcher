//! Reverse proxy interno pros upstreams Go.
//!
//! Convenção de roteamento (a expandir em commits seguintes):
//!
//! ```text
//!   /v1/auth/*           → viralefy_auth
//!   /v1/me/*             → viralefy_core
//!   /v1/admin/*          → viralefy_core
//!   /v1/checkout         → viralefy_core
//!   /v1/plans*           → viralefy_core
//!   /v1/categories       → viralefy_core
//!   /v1/currencies       → viralefy_core
//!   /v1/webhooks/stripe  → viralefy_payments
//!   /v1/webhooks/heleket → viralefy_payments
//!   /v1/webhooks/woovi   → viralefy_payments
//!   /v1/webhooks/abacatepay → viralefy_payments
//!   /v1/webhooks/resend  → viralefy_core (email events)
//!   /v2/plans            → viralefy_core (B2B API key)
//!   /v2/orders/*         → viralefy_core
//!   /.well-known/jwks    → viralefy_auth
//! ```
//!
//! Scaffold: placeholder. Próximo commit traz o `forward_request` real
//! com reqwest, propagation de headers safe-list, e timeout per-route.

#![allow(dead_code)]

use crate::AppState;

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

/// Lookup table que mapeia path → upstream. Implementação real virá em
/// commit seguinte; por enquanto retorna None pra qualquer path
/// (dispatcher só responde /_health e /_ready).
pub fn resolve_upstream(_path: &str) -> Option<Upstream> {
    None
}
