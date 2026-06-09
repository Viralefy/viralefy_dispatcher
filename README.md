# viralefy_api (Rust dispatcher)

Borda de segurança do Viralefy. Único serviço exposto ao mundo (atrás do Caddy + Coraza WAF). Filtra, sanitiza, valida tokens, aplica rate-limit e despacha pros serviços de domínio (`viralefy_core`, `viralefy_auth`, `viralefy_payments`, `viralefy_sender`).

Sucessor direto do antigo `viralefy_api` (Go monolítico). O nome `viralefy_api` foi liberado: o monolito virou `viralefy_core`, este aqui é o novo `viralefy_api` reescrito em Rust.

Status: **scaffold inicial (2026-06-09)**. Tracing/health no ar, handlers reais entram nos próximos commits da PHASE-9 §4.4 (Rust dispatcher).

## Por que Rust?

- **Memory safety** sem GC. Borda atacada constantemente — toda vulnerabilidade de memória aqui é catastrófica.
- **Performance previsível** (sem GC pauses) em hot path de validação/sanitização.
- **Footprint baixo** (~10MB RSS) — múltiplas instâncias por VPS quando cluster vier.
- **Type safety forte** — erros de roteamento e parsing detectados em compile.

Decisão registrada em [`PHASE-9-ARCHITECTURE.md`](https://github.com/Viralefy/viralefy_archive/blob/main/PHASE-9-ARCHITECTURE.md) §3.

## Responsabilidades

1. **Input sanitization** (defense-in-depth com Coraza/CRS no Caddy):
   - HTML/JS strip em campos de texto livre (ammonia + DOMPurify-equivalente)
   - Allow-list de tipos de body (JSON only em endpoints estruturados)
   - Tamanho máximo por endpoint
   - Path traversal em params (regex denylist)
2. **JWT verify offline**: valida access tokens RS256 contra JWKS público de `viralefy_auth` (cache 60s).
3. **Hot-set de revogação**: lê tabela `revoked_jtis` do Postgres a cada 5s (LISTEN/NOTIFY se disponível).
4. **Rate limiting** per-IP + per-token + per-endpoint via `tower_governor`.
5. **Reverse proxy** pros serviços internos via DNS interno (loopback ou Tailscale).
6. **Request ID + trace propagation** (W3C `traceparent`) injetado em todo request.
7. **Anti-bot básico**: User-Agent check, Cloudflare Turnstile (já existe), pseudo-WAF de business rules específicas.

## NÃO responsabilidades

- Business logic (vai no `viralefy_core`)
- Mint de tokens (vai no `viralefy_auth`)
- Persistência além de read-only hot-set (vai nos donos)
- Templating/HTML (frontend renderiza)

## Stack

| Componente | Crate |
|---|---|
| Web framework | `axum` 0.7 |
| Runtime async | `tokio` 1.x |
| Middleware | `tower-http` 0.6 |
| Rate limit | `tower_governor` 0.5 |
| HTTP client (proxy) | `reqwest` 0.12 + rustls |
| JWT verify | `jsonwebtoken` 9 |
| Sanitization | `ammonia` 4 + `regex` 1 |
| Postgres read-only | `sqlx` 0.8 + rustls |
| Logging | `tracing` + `tracing-subscriber` JSON |

## Build

```bash
cargo build --release
# binary em target/release/viralefy-api
```

Otimização agressiva já em `Cargo.toml`:
- `opt-level = 3`
- `lto = "thin"`
- `codegen-units = 1`
- `strip = true`

Binary alvo: ~5-8 MB stripped.

## Rodar local

```bash
export VAPI_BIND_ADDR=127.0.0.1:8080
export VAPI_CORE_URL=http://127.0.0.1:8084
export VAPI_AUTH_URL=http://127.0.0.1:8083
export VAPI_PAYMENTS_URL=http://127.0.0.1:8081
export VAPI_SENDER_URL=http://127.0.0.1:8082
export INTERNAL_SHARED_SECRET=$(openssl rand -hex 32)
export DATABASE_URL=postgres://...

cargo run --release
```

Health:
```bash
curl http://127.0.0.1:8080/_health
```

## Tests

```bash
cargo test
cargo clippy -- -D warnings
cargo fmt --check
```

## Status checklist

- [x] Scaffold inicial: Cargo.toml, src/main.rs com health endpoint
- [ ] Tracing JSON estruturado + request_id middleware
- [ ] Reverse proxy pros 4 upstreams (core, auth, payments, sender)
- [ ] JWT verify middleware + JWKS cache
- [ ] Hot-set de revogação via sqlx (poll 5s)
- [ ] Rate limit per-IP via tower_governor
- [ ] Input sanitization layer (ammonia + regex)
- [ ] Health/ready/metrics endpoints
- [ ] systemd unit hardened + viralefy-update integration
- [ ] Smoke tests E2E + benchmark de paridade com core legacy

## Plano de cutover

Detalhado em [`PHASE-9-ARCHITECTURE.md`](https://github.com/Viralefy/viralefy_archive/blob/main/PHASE-9-ARCHITECTURE.md) §4.4. Resumo:

1. Build em CI, deploy paralelo no port `:8090` (não muda tráfego).
2. Smoke E2E em staging com shadow traffic.
3. Migrar 1% (canary) → 10% → 50% → 100% via Caddy upstream weight.
4. Manter Go `viralefy_api` legado por 14 dias como fallback.
5. Cleanup.
