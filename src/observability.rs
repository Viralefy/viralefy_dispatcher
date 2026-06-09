//! Tracing JSON estruturado pra Loki + OTLP futuro.

use tracing_subscriber::{
    fmt, prelude::*, EnvFilter,
};

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info,viralefy_api=info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().json().with_target(true).with_level(true))
        .init();
}
