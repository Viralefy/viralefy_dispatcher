//! Auth offline pro dispatcher.
//!
//! 3 responsabilidades:
//!
//! 1. **JWKS cache** — busca chave pública do `viralefy_auth` em
//!    `${VAPI_AUTH_URL}/.well-known/jwks.json` (TTL 60s). Decode RS256 local
//!    sem round-trip pra auth a cada request.
//!
//! 2. **Hot-set de revogação** — bootstrap completo do `revoked_jtis` via
//!    sqlx no startup, depois `LISTEN/NOTIFY` no canal `revoked_jtis_inserted`
//!    pra updates em tempo real. Fallback polling 5s caso LISTEN caia.
//!
//! 3. **Verify claims** — `verify_access(token)` retorna `Claims` válido OU
//!    `AuthError` (expired/revoked/malformed/sig).
//!
//! Rotas que exigem JWT vão por um middleware axum (`require_auth`) que
//! consome esse módulo. Rotas públicas (catalogo, webhooks, login) ficam
//! abertas — dispatcher só valida quando claim é necessária.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sqlx::postgres::PgListener;
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Claims canônicas (subset do que o auth emite).
#[derive(Debug, Clone, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub typ: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub email: String,
    pub exp: i64,
    #[serde(default)]
    pub iat: i64,
    #[serde(default)]
    pub jti: String,
}

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("token missing")]
    Missing,
    #[error("token malformed")]
    Malformed,
    #[error("token expired")]
    Expired,
    #[error("token revoked")]
    Revoked,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("upstream JWKS unreachable: {0}")]
    JWKSUnreachable(String),
}

/// JWKSCache mantém a chave pública em memória + TTL de refresh.
#[derive(Clone)]
pub struct JWKSCache {
    inner: Arc<RwLock<Inner>>,
    auth_url: String,
    http: reqwest::Client,
    ttl: Duration,
}

struct Inner {
    jwks: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

impl JWKSCache {
    pub fn new(auth_url: &str, http: reqwest::Client, ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Inner { jwks: None, fetched_at: None })),
            auth_url: auth_url.trim_end_matches('/').to_string(),
            http,
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Devolve o JwkSet, refresh se TTL estourou.
    pub async fn get(&self) -> Result<JwkSet, AuthError> {
        {
            let g = self.inner.read().await;
            if let (Some(j), Some(at)) = (&g.jwks, g.fetched_at) {
                if at.elapsed() < self.ttl {
                    return Ok(j.clone());
                }
            }
        }
        // Refresh.
        let url = format!("{}/.well-known/jwks.json", self.auth_url);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| AuthError::JWKSUnreachable(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(AuthError::JWKSUnreachable(format!("HTTP {}", resp.status())));
        }
        let jwks: JwkSet = resp
            .json()
            .await
            .map_err(|e| AuthError::JWKSUnreachable(format!("decode: {}", e)))?;
        let mut g = self.inner.write().await;
        g.jwks = Some(jwks.clone());
        g.fetched_at = Some(Instant::now());
        Ok(jwks)
    }

    /// Verifica token RS256 com cache atual. Retorna claims tipadas se OK.
    pub async fn verify(&self, token: &str) -> Result<Claims, AuthError> {
        let header = decode_header(token).map_err(|_| AuthError::Malformed)?;
        let kid = header.kid.ok_or(AuthError::Malformed)?;

        let jwks = self.get().await?;
        let jwk = jwks
            .keys
            .iter()
            .find(|k| {
                k.common.key_id.as_deref() == Some(&kid)
            })
            .ok_or(AuthError::InvalidSignature)?;

        let key = DecodingKey::from_jwk(jwk).map_err(|_| AuthError::InvalidSignature)?;
        let mut val = Validation::new(Algorithm::RS256);
        val.validate_exp = true;
        val.leeway = 60; // 60s tolerância pra clock skew

        match decode::<Claims>(token, &key, &val) {
            Ok(data) => Ok(data.claims),
            Err(e) => {
                use jsonwebtoken::errors::ErrorKind as E;
                match e.kind() {
                    E::ExpiredSignature => Err(AuthError::Expired),
                    E::InvalidSignature => Err(AuthError::InvalidSignature),
                    _ => Err(AuthError::Malformed),
                }
            }
        }
    }
}

/// RevocationSet — hot-set in-memory dos JTIs revogados, sincronizado
/// com Postgres via bootstrap + LISTEN/NOTIFY + fallback polling.
///
/// Implementação `ArcSwap<HashSet<String>>`: leitor pega um snapshot Arc
/// (load atômico, sem syscall, sem espera) e consulta. Writer (polling
/// reconcile e NOTIFY) constrói um novo `HashSet` e troca o ponteiro em
/// um único `store`. Isso elimina a contenção de `RwLock` que aparecia em
/// rajadas a cada `revoked_jtis_poll_secs` segundos (o write-lock do
/// `bootstrap()` bloqueava todos os leitores enquanto persistia).
#[derive(Clone)]
pub struct RevocationSet {
    inner: Arc<ArcSwap<HashSet<String>>>,
    db_pool: sqlx::PgPool,
}

impl RevocationSet {
    /// Cria uma instância e roda bootstrap inicial. Spawna 2 tasks:
    /// LISTEN/NOTIFY pra real-time + polling pra fallback.
    pub async fn new(database_url: &str, poll_secs: u64) -> anyhow::Result<Self> {
        let pool = sqlx::PgPool::connect(database_url).await?;
        let set = Self {
            inner: Arc::new(ArcSwap::from_pointee(HashSet::new())),
            db_pool: pool.clone(),
        };

        // Bootstrap: snapshot atual.
        set.bootstrap().await?;

        // Task 1: LISTEN/NOTIFY real-time.
        let listen_pool = pool.clone();
        let listen_inner = set.inner.clone();
        tokio::spawn(async move {
            loop {
                if let Err(e) = listen_loop(&listen_pool, listen_inner.clone()).await {
                    warn!(error = %e, "LISTEN loop terminated; restart in 5s");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        });

        // Task 2: polling fallback. Caso LISTEN tenha falhado entre bootstrap
        // e reconexão. Reconcilia a cada poll_secs.
        let poll_set = set.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(poll_secs));
            interval.tick().await; // skip first
            loop {
                interval.tick().await;
                if let Err(e) = poll_set.bootstrap().await {
                    warn!(error = %e, "revoked_jtis poll failed");
                }
            }
        });

        Ok(set)
    }

    /// True se jti está no hot-set. Leitor zero-lock — apenas um
    /// `ArcSwap::load` (uma operação atômica, sem syscall).
    pub fn is_revoked(&self, jti: &str) -> bool {
        if jti.is_empty() {
            return false;
        }
        self.inner.load().contains(jti)
    }

    /// Recarrega o set inteiro do DB (active rows). Idempotente.
    /// Constrói o `HashSet` novo fora do caminho de leitores e faz `store`
    /// atômico — nunca bloqueia handlers de request.
    async fn bootstrap(&self) -> anyhow::Result<()> {
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT jti FROM revoked_jtis WHERE expires_at > NOW()",
        )
        .fetch_all(&self.db_pool)
        .await?;
        let n = rows.len();
        let mut new_set = HashSet::with_capacity(n);
        for (jti,) in rows {
            new_set.insert(jti);
        }
        self.inner.store(Arc::new(new_set));
        // Polling de reconciliação acontece a cada N segundos com hot-set
        // tipicamente vazio — log em debug pra não inundar journalctl. NOTIFY
        // continua sendo logado em info pra rastreabilidade de revogação.
        tracing::debug!(count = n, "revoked_jtis bootstrap done");
        Ok(())
    }
}

async fn listen_loop(
    pool: &sqlx::PgPool,
    set: Arc<ArcSwap<HashSet<String>>>,
) -> anyhow::Result<()> {
    let mut listener = PgListener::connect_with(pool).await?;
    listener.listen("revoked_jtis_inserted").await?;
    info!("LISTEN revoked_jtis_inserted active");
    loop {
        let notif = listener.recv().await?;
        let jti = notif.payload().to_string();
        if jti.is_empty() {
            continue;
        }
        // Copy-on-write: clona o set atual, insere, swap. Custo proporcional
        // ao tamanho do hot-set mas só roda na revogação (raro), não no
        // caminho de request.
        let current = set.load_full();
        let mut next = (*current).clone();
        next.insert(jti.clone());
        set.store(Arc::new(next));
        info!(jti = %jti, "jti added to hot-set via NOTIFY");
    }
}
