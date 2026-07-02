//! Vela hub: HTTP server over signed frontier manifests, canonical
//! event logs, and materialized frontier projections.
//!
//! Doctrine: the signed manifest is the publish receipt. The live read
//! source is the verified event/projection tables. Snapshot blobs remain
//! derived export artifacts, and clients still verify signatures and
//! hashes locally.
//!
//! Writes are accepted from anyone who can produce a valid signature
//! over their own manifest — the signature is the bind, not access
//! control. The hub verifies the signature against the manifest's
//! declared `owner_pubkey` and stores the canonical bytes verbatim.
//!
//! Endpoints:
//!   GET  /entries                   - live frontiers, manifest-compatible JSON
//!   GET  /entries/{vfr_id}          - single live frontier entry
//!   GET  /entries/{vfr_id}/events   - cursor-paginated event log
//!   GET  /entries/{vfr_id}/snapshot - derived materialized snapshot
//!   (publication is `git push`: POST /entries retired — the ingest loop
//!   re-derives the index from registered git remotes; the one write left
//!   is POST /entries/{vfr}/git-remote, the owner-signed registration)
//!   GET  /healthz                   - liveness
//!   GET  /                          - banner + endpoint list

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode, header::ACCEPT},
    response::{
        Html, IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;
use tokio::sync::RwLock;

// v0.55: db + storage modules are exposed via the lib (src/lib.rs) so
// sibling binaries such as `vela-hub-backfill-event-first` can reuse them.
// Same modules, just imported through the crate root instead of
// declared inline.
use db::{HubDb, ensure_postgres_event_first_schema, ensure_sqlite_schema};
use tower_http::cors::CorsLayer;
mod html;
use html::*;

use vela_hub::db;
use vela_hub::storage::Storage;
use vela_protocol::canonical;
use vela_protocol::project::Project;
use vela_protocol::sign as vsign;

const HUB_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_PUBLISH_BODY_BYTES: usize = 128 * 1024 * 1024;
const REGISTRY_SCHEMA: &str = "vela.registry.v0.1";

const DEFAULT_PUBLIC_URL: &str = "https://hub.constellate.science";
const DEFAULT_REPO_URL: &str = "https://github.com/constellate-science/vela";
const DEFAULT_SITE_URL: &str = "https://app.constellate.science";

/// Cache key: (vfr_id, signed_publish_at). A fresh publish gets a new
/// timestamp, so the key changes and the next read re-fetches.
type FrontierCache = Arc<RwLock<HashMap<(String, String), Arc<Project>>>>;

/// URL strings the hub renders into HTML. Sourced at startup from env
/// vars (`VELA_HUB_PUBLIC_URL`, `VELA_REPO_URL`, `VELA_SITE_URL`) with
/// hardcoded defaults that match the v0.7 deploy. Changing the deploy
/// target is one secret-set away.
#[derive(Clone)]
struct PublicUrls {
    hub: String,
    repo: String,
    site: String,
}

impl PublicUrls {
    fn from_env() -> Self {
        let strip = |s: String| s.trim_end_matches('/').to_string();
        Self {
            hub: strip(
                env::var("VELA_HUB_PUBLIC_URL").unwrap_or_else(|_| DEFAULT_PUBLIC_URL.into()),
            ),
            repo: strip(env::var("VELA_REPO_URL").unwrap_or_else(|_| DEFAULT_REPO_URL.into())),
            site: strip(env::var("VELA_SITE_URL").unwrap_or_else(|_| DEFAULT_SITE_URL.into())),
        }
    }
    fn hub_host(&self) -> &str {
        self.hub
            .trim_start_matches("https://")
            .trim_start_matches("http://")
    }
}

#[derive(Clone)]
struct AppState {
    /// v0.21: backend-agnostic DB handle. Postgres for production
    /// (vela-hub.fly.dev / vela-hub-2.fly.dev), SQLite for self-hosted
    /// laptop runs. Variant chosen at startup from URL prefix.
    db: HubDb,
    /// Frontier cache for the entry detail page. Keyed by
    /// `(vfr_id, signed_publish_at)` so a fresh publish forces a
    /// re-fetch automatically. Bounded loosely; in v0.7 we expect
    /// fewer than a dozen frontiers ever.
    frontier_cache: FrontierCache,
    /// v0.49: stale-on-read cache for DB reads. When the Postgres
    /// backend hiccups (Neon cold-start, network blip, restart), the
    /// hub serves the last-known-good response with an `X-Vela-Stale`
    /// header instead of 5xx-ing. The TTL is short (60 s) so a
    /// long-lived outage still surfaces; but a single failed query
    /// no longer takes down the registry.
    db_cache: DbCache,
    /// v0.49.1: hit/miss/stale counters for the DB cache. Surfaced at
    /// `/healthz` so an operator can monitor degradation.
    db_cache_metrics: Arc<DbCacheMetrics>,
    /// v0.49.3: optional Ed25519 signing key for the
    /// `/.well-known/vela` discovery manifest. When present, the
    /// manifest's `manifest_canonical` bytes are signed and a
    /// `signature` block is attached so a client can detect
    /// MITM at the hub edge. Loaded once at startup from the file at
    /// `VELA_HUB_SIGNING_KEY_PATH`; absent ⇒ unsigned mode (dev).
    signing_key: Option<Arc<ed25519_dalek::SigningKey>>,
    /// Public-facing URLs the rendered HTML quotes back to readers.
    /// Configurable via env so the same binary serves any deployment.
    urls: PublicUrls,
    /// v0.55.1: substrate object-storage client. Bulk content (multi-MB
    /// Project bundles) is PUT here on publish and can be served via 302
    /// redirects to a CDN URL as an export path. Live reads come from
    /// event/projection tables.
    storage: Option<Storage>,
    /// v0.727: the hosted MCP service, hot-swapped by the per-machine
    /// refresher (`mcp_host`). `None` until the first refresh lands.
    mcp: vela_hub::mcp_host::SharedMcp,
    /// Kicks the MCP refresher ahead of its interval (webhook lane).
    mcp_kick: Arc<tokio::sync::Notify>,
    /// v0.727: shared secret for `POST /webhook/github` (HMAC-SHA256 over
    /// the raw body, GitHub's `X-Hub-Signature-256`). Absent ⇒ the
    /// webhook lane answers 503 and the interval sweeps remain the only
    /// refresh path.
    webhook_secret: Option<Arc<String>>,
}

/// v0.49: tiny stale-on-read cache for DB query results. Keyed by a
/// short string (route + arg). Each entry stores the JSON value, the
/// time it was fetched, and serves stale on any query failure within
/// `DB_CACHE_STALE_WINDOW`.
type DbCache = Arc<RwLock<HashMap<String, DbCacheEntry>>>;

#[derive(Clone)]
struct DbCacheEntry {
    value: Value,
    fetched_at: std::time::Instant,
}

const DB_CACHE_FRESH_TTL: std::time::Duration = std::time::Duration::from_secs(60);
const DB_CACHE_STALE_WINDOW: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// v0.49.1: counters for the DB-cache fast/slow paths so an operator
/// can see at a glance whether the registry is healthy or limping.
/// `hits` are fresh-window cache hits (served without touching the
/// DB). `misses` are misses that fell through to the DB and the DB
/// answered. `stale_hits` are misses where the DB errored *and* we
/// served the last-known-good payload with `X-Vela-Stale: 1`.
///
/// The crucial signal for production: a sustained rise in `stale_hits`
/// means Postgres is failing repeatedly and the registry is degrading.
/// The cache is buying time, not papering over a healthy backend.
///
/// v0.49.2: per-bucket histogram of stale-age in seconds so an
/// operator can distinguish "we served stale 30 s ago" from "we've
/// been serving 28-min-stale data" — both increment `stale_hits`,
/// but only the second is reason to page someone.
#[derive(Default)]
struct DbCacheMetrics {
    hits: std::sync::atomic::AtomicU64,
    misses: std::sync::atomic::AtomicU64,
    stale_hits: std::sync::atomic::AtomicU64,
    db_errors: std::sync::atomic::AtomicU64,
    /// Histogram buckets for stale-age in seconds. Indexes correspond
    /// to STALE_AGE_BUCKETS upper bounds (final bucket is "+Inf").
    stale_age_buckets: [std::sync::atomic::AtomicU64; STALE_AGE_BUCKETS.len() + 1],
}

/// Stale-age histogram bucket upper bounds, in seconds. Chosen to
/// straddle the fresh window (60 s), short outage (5 min), and the
/// stale window itself (30 min).
const STALE_AGE_BUCKETS: [u64; 6] = [60, 120, 300, 600, 1200, 1800];

impl DbCacheMetrics {
    fn record_hit(&self) {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn record_miss(&self) {
        self.misses
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn record_stale_hit(&self, age_secs: u64) {
        self.stale_hits
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let bucket_idx = STALE_AGE_BUCKETS
            .iter()
            .position(|&b| age_secs <= b)
            .unwrap_or(STALE_AGE_BUCKETS.len());
        self.stale_age_buckets[bucket_idx].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn record_db_error(&self) {
        self.db_errors
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    fn snapshot(&self) -> Value {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let stale_hits = self.stale_hits.load(std::sync::atomic::Ordering::Relaxed);
        let db_errors = self.db_errors.load(std::sync::atomic::Ordering::Relaxed);
        let total_serves = hits + misses + stale_hits;
        let stale_hit_rate = if total_serves == 0 {
            0.0
        } else {
            stale_hits as f64 / total_serves as f64
        };

        // Histogram snapshot: cumulative buckets in Prometheus style
        // (each bucket counts every observation ≤ its upper bound).
        let raw: Vec<u64> = self
            .stale_age_buckets
            .iter()
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            .collect();
        let mut cumulative = 0u64;
        let mut buckets_obj = serde_json::Map::new();
        for (i, &bound) in STALE_AGE_BUCKETS.iter().enumerate() {
            cumulative += raw[i];
            buckets_obj.insert(format!("le_{bound}s"), json!(cumulative));
        }
        cumulative += raw[STALE_AGE_BUCKETS.len()];
        buckets_obj.insert("le_inf".to_string(), json!(cumulative));

        json!({
            "hits": hits,
            "misses": misses,
            "stale_hits": stale_hits,
            "db_errors": db_errors,
            "total_serves": total_serves,
            "stale_hit_rate": stale_hit_rate,
            "stale_age_seconds": buckets_obj,
        })
    }

    /// Render the cache metrics as Prometheus 0.0.4 text format. The
    /// shape `vela_hub_db_cache_*` is namespaced so a multi-hub
    /// scrape can pull this hub alongside others without collision.
    fn render_prometheus(&self) -> String {
        let hits = self.hits.load(std::sync::atomic::Ordering::Relaxed);
        let misses = self.misses.load(std::sync::atomic::Ordering::Relaxed);
        let stale_hits = self.stale_hits.load(std::sync::atomic::Ordering::Relaxed);
        let db_errors = self.db_errors.load(std::sync::atomic::Ordering::Relaxed);
        let total_serves = hits + misses + stale_hits;
        let stale_hit_rate = if total_serves == 0 {
            0.0
        } else {
            stale_hits as f64 / total_serves as f64
        };
        let mut out = String::new();
        out.push_str("# HELP vela_hub_db_cache_hits_total Cache fresh-window hits served without touching the DB.\n");
        out.push_str("# TYPE vela_hub_db_cache_hits_total counter\n");
        out.push_str(&format!("vela_hub_db_cache_hits_total {hits}\n"));
        out.push_str("# HELP vela_hub_db_cache_misses_total Cache misses that fell through to the DB and the DB answered.\n");
        out.push_str("# TYPE vela_hub_db_cache_misses_total counter\n");
        out.push_str(&format!("vela_hub_db_cache_misses_total {misses}\n"));
        out.push_str("# HELP vela_hub_db_cache_stale_hits_total Cache misses served stale because the DB errored within the stale window.\n");
        out.push_str("# TYPE vela_hub_db_cache_stale_hits_total counter\n");
        out.push_str(&format!(
            "vela_hub_db_cache_stale_hits_total {stale_hits}\n"
        ));
        out.push_str("# HELP vela_hub_db_errors_total Distinct DB query errors observed by the cache layer.\n");
        out.push_str("# TYPE vela_hub_db_errors_total counter\n");
        out.push_str(&format!("vela_hub_db_errors_total {db_errors}\n"));
        out.push_str("# HELP vela_hub_db_cache_stale_hit_rate Stale hits as a fraction of total cache serves.\n");
        out.push_str("# TYPE vela_hub_db_cache_stale_hit_rate gauge\n");
        out.push_str(&format!(
            "vela_hub_db_cache_stale_hit_rate {stale_hit_rate}\n"
        ));

        // Stale-age histogram, cumulative buckets per Prometheus convention.
        out.push_str("# HELP vela_hub_db_cache_stale_age_seconds Stale-age distribution (seconds since last good fetch) for stale serves.\n");
        out.push_str("# TYPE vela_hub_db_cache_stale_age_seconds histogram\n");
        let raw: Vec<u64> = self
            .stale_age_buckets
            .iter()
            .map(|c| c.load(std::sync::atomic::Ordering::Relaxed))
            .collect();
        let mut cumulative = 0u64;
        for (i, &bound) in STALE_AGE_BUCKETS.iter().enumerate() {
            cumulative += raw[i];
            out.push_str(&format!(
                "vela_hub_db_cache_stale_age_seconds_bucket{{le=\"{bound}\"}} {cumulative}\n"
            ));
        }
        cumulative += raw[STALE_AGE_BUCKETS.len()];
        out.push_str(&format!(
            "vela_hub_db_cache_stale_age_seconds_bucket{{le=\"+Inf\"}} {cumulative}\n"
        ));
        out.push_str(&format!(
            "vela_hub_db_cache_stale_age_seconds_count {cumulative}\n"
        ));
        out
    }
}

async fn db_cache_read(cache: &DbCache, key: &str) -> Option<DbCacheEntry> {
    cache.read().await.get(key).cloned()
}

async fn db_cache_write(cache: &DbCache, key: &str, value: Value) {
    cache.write().await.insert(
        key.to_string(),
        DbCacheEntry {
            value,
            fetched_at: std::time::Instant::now(),
        },
    );
}

// Local RegistryEntry struct removed in v0.21 — db.rs now uses
// vela_protocol::registry::RegistryEntry directly so the publish handler
// and the DB layer agree on the type.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("vela_hub=info,tower_http=info")
            }),
        )
        .init();

    // Load credentials. We read VELA_HUB_DATABASE_URL from env, with
    // ~/.vela/hub.env as a convenience fallback so the dev path "just works"
    // without exporting variables in every shell.
    let _ = dotenvy::from_path(
        std::path::PathBuf::from(env::var("HOME").unwrap_or_default())
            .join(".vela")
            .join("hub.env"),
    );
    let database_url = env::var("VELA_HUB_DATABASE_URL")
        .or_else(|_| env::var("DATABASE_URL"))
        .map_err(|_| "set VELA_HUB_DATABASE_URL (e.g. via ~/.vela/hub.env)")?;

    // v0.21: pick backend by URL prefix.
    //   postgres://… or postgresql://… → production Postgres path
    //   sqlite://…  or sqlite:./…      → self-hosted SQLite path
    //                                     (auto-creates schema if missing)
    let db = if database_url.starts_with("sqlite:") {
        let opts = SqliteConnectOptions::from_str(&database_url)?.create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect_with(opts)
            .await?;
        ensure_sqlite_schema(&pool)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        tracing::info!(url = %database_url, "vela-hub using SQLite backend (self-hosted)");
        HubDb::Sqlite(pool)
    } else {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(&database_url)
            .await?;
        // v0.230: opportunistic schema migration. If the connected role
        // has DDL privileges, apply the event-first schema (idempotent
        // — every CREATE is IF NOT EXISTS). If it lacks DDL perms
        // (production Neon hub uses a least-privilege role; schema is
        // applied separately by a privileged migration job), log a
        // warning and continue. The schema_present() check below still
        // enforces that the core tables exist.
        if let Err(e) = ensure_postgres_event_first_schema(&pool).await {
            tracing::warn!(error = %e, "skipping auto-migration; ensure DDL has been applied via privileged role");
        }
        let h = HubDb::Postgres(pool);
        // Sanity-check schema presence so we fail fast on a misconfigured DB.
        let table_exists = h
            .schema_present()
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        if !table_exists {
            return Err(
                "registry_entries table not found; run the schema migration before starting the hub"
                    .into(),
            );
        }
        tracing::info!("vela-hub using Postgres backend");
        h
    };

    let urls = PublicUrls::from_env();

    // v0.49.3: optional signing key for /.well-known/vela. Loaded
    // once at startup. Absent ⇒ unsigned mode (dev). Present ⇒ the
    // discovery manifest's canonical bytes are signed and a
    // signature block is attached so a client can detect
    // MITM at the hub edge.
    // Inline hex key (`VELA_HUB_SIGNING_KEY`) takes precedence over a file
    // path (`VELA_HUB_SIGNING_KEY_PATH`). The inline form is what a hosted
    // deploy uses: Fly/K8s secrets are environment variables, not files, so
    // there is no path to point at. Absent both ⇒ unsigned mode (dev).
    let signing_key = match env::var("VELA_HUB_SIGNING_KEY") {
        Ok(hex) if !hex.trim().is_empty() => match vsign::signing_key_from_hex(&hex) {
            Ok(k) => {
                tracing::info!(
                    "vela-hub /.well-known/vela signing key loaded from VELA_HUB_SIGNING_KEY ({}…)",
                    &vsign::pubkey_hex(&k)[..16]
                );
                Some(Arc::new(k))
            }
            Err(e) => {
                tracing::warn!(
                    "VELA_HUB_SIGNING_KEY set but failed to parse: {e}; \
                     /.well-known/vela will run in unsigned mode"
                );
                None
            }
        },
        _ => match env::var("VELA_HUB_SIGNING_KEY_PATH") {
            Ok(path) if !path.is_empty() => {
                match vsign::load_signing_key_from_path(std::path::Path::new(&path)) {
                    Ok(k) => {
                        tracing::info!(
                            "vela-hub /.well-known/vela signing key loaded from path ({}…)",
                            &vsign::pubkey_hex(&k)[..16]
                        );
                        Some(Arc::new(k))
                    }
                    Err(e) => {
                        tracing::warn!(
                            "VELA_HUB_SIGNING_KEY_PATH set but key failed to load: {e}; \
                             /.well-known/vela will run in unsigned mode"
                        );
                        None
                    }
                }
            }
            _ => {
                tracing::info!(
                    "no VELA_HUB_SIGNING_KEY[_PATH] set; /.well-known/vela in unsigned mode"
                );
                None
            }
        },
    };

    // v0.55.1: object-storage backend for substrate bytes. Set up
    // automatically when AWS_* + BUCKET_NAME env vars are present
    // (`flyctl storage create` injects these). Absent in local SQLite
    // dev: publishes still work, but CDN export redirects are disabled.
    let storage = vela_hub::storage::from_env().await;
    if storage.is_some() {
        tracing::info!("substrate storage configured (S3-compatible, content-addressed)");
    } else {
        tracing::info!("no S3-compatible storage configured; snapshot export redirects disabled");
    }

    let state = AppState {
        db,
        frontier_cache: Arc::new(RwLock::new(HashMap::new())),
        db_cache: Arc::new(RwLock::new(HashMap::new())),
        db_cache_metrics: Arc::new(DbCacheMetrics::default()),
        signing_key,
        urls,
        storage,
        mcp: Arc::new(tokio::sync::RwLock::new(None)),
        mcp_kick: Arc::new(tokio::sync::Notify::new()),
        webhook_secret: env::var("VELA_HUB_WEBHOOK_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .map(Arc::new),
    };
    if state.webhook_secret.is_none() {
        tracing::info!(
            "no VELA_HUB_WEBHOOK_SECRET set; /webhook/github disabled (interval sweeps only)"
        );
    }

    // Producer-index backfill: re-extract signer_pubkey for finding
    // objects from stored snapshots (covers publishes that predate the
    // event-actor extraction). Idempotent; non-fatal.
    {
        let db = state.db.clone();
        tokio::spawn(async move {
            match db.backfill_signer_pubkeys().await {
                Ok(n) if n > 0 => tracing::info!(updated = n, "producer-index backfill complete"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "producer-index backfill failed"),
            }
        });
    }

    // Boot-time backfill: archive any signed manifest that predates the
    // durable-receipt path. Idempotent (content-addressed keys; rows are
    // selected by manifest_blob_url IS NULL) and non-fatal — the hub
    // serves regardless; the next boot retries what failed.
    if let Some(storage) = state.storage.clone() {
        let db = state.db.clone();
        tokio::spawn(async move {
            match db.entries_missing_manifest_blob().await {
                Ok(rows) => {
                    let total = rows.len();
                    let mut archived = 0usize;
                    for (vfr_id, signature, raw_json) in rows {
                        let (Ok(bytes), Ok(mhash)) = (
                            vela_protocol::canonical::to_canonical_bytes(&raw_json),
                            vela_protocol::canonical::sha256_canonical(&raw_json),
                        ) else {
                            continue;
                        };
                        let key = format!("manifest/{mhash}");
                        match storage.put(&key, bytes, "application/json").await {
                            Ok(url) => {
                                match db.set_manifest_blob_url(&vfr_id, &signature, &url).await {
                                    Ok(()) => archived += 1,
                                    Err(e) => {
                                        // The original silent swallow here hid a
                                        // missing column-level UPDATE grant for
                                        // 89 rows. Receipts must fail loudly.
                                        tracing::warn!(%vfr_id, error = %e, "manifest archived but url not recorded");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(%vfr_id, error = %e, "manifest backfill put failed");
                            }
                        }
                    }
                    if total > 0 {
                        tracing::info!(archived, total, "manifest receipt backfill complete");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "manifest backfill query failed"),
            }
        });
    }

    // Git ingestion (ADR 0001 / HUB.md): re-derive the index from registered
    // frontier git repos on an interval. The repo is the authority; this
    // loop only refreshes the projection.
    vela_hub::git_ingest::spawn(
        state.db.clone(),
        vela_hub::git_ingest::GitIngestConfig::from_env(),
    );

    // The hosted MCP lane (v0.727): per-machine checkout refresher +
    // in-process serve dispatcher behind /mcp. Read-only by construction.
    vela_hub::mcp_host::spawn(
        state.db.clone(),
        vela_hub::git_ingest::GitIngestConfig::from_env(),
        state.mcp.clone(),
        state.mcp_kick.clone(),
    );

    let port: u16 = env::var("VELA_HUB_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3849);
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();

    let app = Router::new()
        .route("/", get(root))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_prometheus))
        .route("/.well-known/vela", get(well_known_vela))
        .route("/entries", get(list_entries))
        .route("/entries/{vfr_id}", get(get_entry))
        .route(
            "/entries/{vfr_id}/git-remote",
            get(get_git_remote).post(register_git_remote),
        )
        .route("/entries/{vfr_id}/snapshot", get(get_entry_snapshot))
        .route(
            "/entries/{vfr_id}/sidon-frontier-map",
            get(get_sidon_frontier_map),
        )
        .route(
            "/entries/{vfr_id}/sidon-observation",
            get(get_sidon_observation),
        )
        .route("/entries/{vfr_id}/summary", get(get_entry_summary))
        .route("/entries/{vfr_id}/manifest", get(get_entry_manifest))
        .route("/entries/{vfr_id}/status", get(get_entry_status))
        .route("/entries/{vfr_id}/maintainers", get(list_maintainers))
        .route("/producers/{pubkey}", get(get_producer))
        // Content-addressed artifact-blob tier (witnesses, proof packets,
        // `local_blob` datasets). GET 302-redirects to the immutable CDN
        // object. The hub is a read-only index: witness bytes are committed
        // to Git LFS in the git-native frontier repos, not ingested here.
        .route("/blobs/{hash}", get(get_blob))
        .route("/search", get(search_endpoint))
        .route("/entries/{vfr_id}/objects/{otype}", get(get_entry_objects))
        .route(
            "/entries/{vfr_id}/objects/{otype}/{object_id}",
            get(get_entry_object),
        )
        .route("/entries/{vfr_id}/log/sth", get(get_log_sth))
        .route("/entries/{vfr_id}/log/proof/{event_id}", get(get_log_proof))
        .route(
            "/entries/{vfr_id}/log/consistency",
            get(get_log_consistency),
        )
        .route("/entries/{vfr_id}/events", get(get_entry_events))
        // Read-only Evidence Diff: a pending proposal's before/after effect
        // on its target claim plus downstream impact. Pure projection over
        // the materialized state. Truth-bearing writes (propose / accept /
        // append) are no longer served here: the hub is a read-only index,
        // and acceptance is a signed review event landed via a git-native
        // frontier PR, not an HTTP endpoint.
        .route(
            "/entries/{vfr_id}/proposals/{proposal_id}/evidence-diff",
            get(get_proposal_evidence_diff),
        )
        .route(
            "/entries/{vfr_id}/events/stream",
            get(get_entry_events_stream),
        )
        .route("/frontier/{vfr_id}/inbox", get(get_entry_events_stream))
        .route("/entries/{vfr_id}/depends-on", get(get_depends_on))
        .route("/diff-packs/{pack_id}", get(get_diff_pack))
        .route("/entries/{vfr_id}/packs/{pack_id}", get(get_pack_review))
        .route("/entries/{vfr_id}/reproduce", get(get_reproduce))
        .route("/entries/{vfr_id}/findings/{vf_id}", get(get_finding))
        .route(
            "/entries/{vfr_id}/findings/{vf_id}/context",
            get(get_finding_context),
        )
        .route(
            "/entries/{vfr_id}/findings/{vf_id}/gate-status",
            get(get_finding_gate_status),
        )
        .route(
            "/entries/{vfr_id}/gate-status",
            get(get_frontier_gate_status),
        )
        .route("/entries/{vfr_id}/proof", get(get_proof_packet))
        .route(
            "/entries/{vfr_id}/proof/download",
            get(get_proof_packet_download),
        )
        .route("/static/tokens.css", get(static_tokens_css))
        .route("/static/workbench.css", get(static_workbench_css))
        .route("/static/site.css", get(static_site_css))
        .route("/static/favicon.svg", get(static_favicon_svg))
        .route("/static/vela-logo-mark.svg", get(static_logo_mark_svg))
        .route(
            "/static/vela-logo-wordmark.svg",
            get(static_logo_wordmark_svg),
        )
        .route("/static/rete.svg", get(static_rete_svg))
        .route(
            "/static/fonts/inter-latin-400-normal.woff2",
            get(|| async { woff2_response(FONT_INTER_400) }),
        )
        .route(
            "/static/fonts/inter-latin-600-normal.woff2",
            get(|| async { woff2_response(FONT_INTER_600) }),
        )
        .route(
            "/static/fonts/source-serif-4-latin-400-normal.woff2",
            get(|| async { woff2_response(FONT_SS4_400) }),
        )
        .route(
            "/static/fonts/source-serif-4-latin-400-italic.woff2",
            get(|| async { woff2_response(FONT_SS4_400_ITALIC) }),
        )
        .route(
            "/static/fonts/jetbrains-mono-latin-400-normal.woff2",
            get(|| async { woff2_response(FONT_JBM_400) }),
        )
        // v0.727: the hosted MCP endpoint (streamable HTTP, stateless
        // JSON, read-only profile) and the GitHub webhook that kicks
        // ingest + MCP refresh ahead of the interval sweeps.
        .route("/mcp", post(post_mcp).get(get_mcp))
        .route("/webhook/github", post(post_webhook_github))
        .layer(DefaultBodyLimit::max(MAX_PUBLISH_BODY_BYTES))
        .layer(CorsLayer::permissive())
        .with_state(state);

    tracing::info!("vela-hub {HUB_VERSION} listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// POST /mcp — the hosted MCP endpoint: streamable HTTP with stateless
/// JSON responses, read-only profile, over this machine's frontier
/// checkouts. 503 until the first refresh lands.
async fn post_mcp(State(state): State<AppState>, body: String) -> Response {
    let guard = state.mcp.read().await;
    let Some(service) = guard.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "jsonrpc": "2.0", "id": null,
                "error": {"code": -32000, "message": "MCP projection not built yet; retry shortly (or no frontier is registered)"}
            })),
        )
            .into_response();
    };
    let (status, response) = service.handle_http(&body).await;
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    match response {
        Some(value) => (status, Json(value)).into_response(),
        None => status.into_response(),
    }
}

/// GET /mcp — no server-initiated SSE stream is offered.
async fn get_mcp() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(serde_json::json!({
            "error": {"kind": "INVALID_ARG", "message": "stateless MCP endpoint: POST a JSON-RPC message; no server-initiated stream is offered"}
        })),
    )
}

/// Verify GitHub's `X-Hub-Signature-256` header (`sha256=<hex>`) over the
/// raw request body. Constant-time comparison via the Mac verifier.
fn github_signature_ok(secret: &str, body: &[u8], header: &str) -> bool {
    use hmac::{Hmac, Mac};
    let Some(hex_sig) = header.strip_prefix("sha256=") else {
        return false;
    };
    let Ok(sig) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<sha2::Sha256>::new_from_slice(secret.as_bytes()) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

/// POST /webhook/github — push events kick the MCP refresher and a DB
/// ingest sweep ahead of the interval, so `git push` reflects in seconds.
/// The webhook is a LATENCY lane only: authenticity of state still comes
/// from strict replay of the signed event log, never from this header.
async fn post_webhook_github(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(secret) = state.webhook_secret.clone() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(error_body(
                "UNAVAILABLE",
                "webhook lane not configured (set VELA_HUB_WEBHOOK_SECRET)",
            )),
        );
    };
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !github_signature_ok(&secret, &body, signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(error_body(
                "PERMISSION_DENIED",
                "invalid or missing X-Hub-Signature-256",
            )),
        );
    }
    let event = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("push")
        .to_string();
    if event == "ping" {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "pong": true})),
        );
    }
    state.mcp_kick.notify_one();
    let db = state.db.clone();
    tokio::spawn(async move {
        match vela_hub::git_ingest::run_once(
            &db,
            &vela_hub::git_ingest::GitIngestConfig::from_env(),
        )
        .await
        {
            Ok(n) if n > 0 => tracing::info!(promoted = n, "webhook-triggered ingest complete"),
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "webhook-triggered ingest failed"),
        }
    });
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"accepted": true, "event": event})),
    )
}

/// usually omit the header or send `*/*`. We render HTML only when the
/// client explicitly asks for it.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.contains("text/html"))
}

/// The one JSON error body shape, shared with `vela serve`'s HTTP surface
/// and the MCP envelope's kind vocabulary:
/// `{"error": {"kind": "...", "message": "..."}}`.
fn error_body(kind: &str, message: impl Into<String>) -> Value {
    json!({"error": {"kind": kind, "message": message.into()}})
}

#[derive(Debug, Deserialize)]
struct EventQuery {
    /// The last-seen `vev_…` event id; events strictly after it are
    /// returned. Omit to start from the genesis event.
    cursor: Option<String>,
    limit: Option<usize>,
    kind: Option<String>,
    target: Option<String>,
}

/// Strict query parsing for the event endpoints: an unknown parameter is
/// a 400, not a silent no-op. A client still sending the retired
/// `?since=` gets told, instead of silently receiving page one.
fn parse_event_query(
    params: &HashMap<String, String>,
    allowed: &[&str],
) -> Result<EventQuery, Box<Response>> {
    if let Some(unknown) = params.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(error_body(
                "INVALID_ARG",
                format!(
                    "unknown query parameter `{unknown}` (allowed: {})",
                    allowed.join(", ")
                ),
            )),
        )
            .into_response()
            .into());
    }
    let limit = match params.get("limit") {
        Some(v) => match v.parse::<usize>() {
            Ok(n) => Some(n),
            Err(_) => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(error_body(
                        "INVALID_ARG",
                        format!("limit `{v}` is not a number"),
                    )),
                )
                    .into_response()
                    .into());
            }
        },
        None => None,
    };
    Ok(EventQuery {
        cursor: params.get("cursor").cloned(),
        limit,
        kind: params.get("kind").cloned(),
        target: params.get("target").cloned(),
    })
}

#[derive(Debug, Deserialize)]
struct SnapshotQuery {
    redirect: Option<String>,
}

fn root_json() -> Value {
    json!({
        "service": "vela-hub",
        "version": HUB_VERSION,
        "doctrine": "Signed manifests are publish receipts. Live reads come from verified frontier events and materialized projections; clients verify signatures and hashes locally.",
        "endpoints": [
            "GET  /              - this banner",
            "GET  /healthz       - liveness + db-cache metrics",
            "GET  /readyz        - readiness (MCP projection built)",
            "GET  /entries       - live frontiers, manifest-compatible JSON",
            "GET  /entries/{vfr_id} - single entry",
            "GET  /entries/{vfr_id}/events - cursor-paginated canonical event log",
            "GET  /entries/{vfr_id}/events/stream - server-sent event inbox",
            "GET  /entries/{vfr_id}/proof - browse the proof packet (HTML or JSON)",
            "GET  /entries/{vfr_id}/proof/download - proof packet as .tar.gz",
            "POST /entries       - publish a signed manifest (open, signature-gated)",
        ],
        "api": {
            "counterfactual": {
                "method": "POST",
                "path": "/api/counterfactual/{vfr_id}",
                "request_body": {
                    "intervene_on": "vf_<id>  // finding to set the confidence of",
                    "set_to":       "0.0..1.0 // confidence value to imagine",
                    "target":       "vf_<id>  // finding to read counterfactual confidence of"
                },
                "response_verdicts": [
                    "Resolved             — twin-network propagated; returns factual, counterfactual, delta, paths_used[]",
                    "MechanismUnspecified — every connecting path has at least one edge without a Mechanism",
                    "NoCausalPath         — no directed path; counterfactual = factual",
                    "UnknownNode          — intervened or target finding not in this frontier",
                    "InvalidIntervention  — set_to outside [0, 1]"
                ],
                "schema": "https://vela.science/schema/counterfactual/v0.45.1",
                "kernel": "vela_edge::counterfactual::answer_counterfactual"
            }
        }
    })
}

async fn root(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if wants_html(&headers) {
        Html(render_root_html(&state.urls)).into_response()
    } else {
        Json(root_json()).into_response()
    }
}

/// v0.49.2: Prometheus 0.0.4 text format metrics endpoint. Exposes
/// the same DbCacheMetrics counters and stale-age histogram an
/// operator would otherwise have to scrape out of `/healthz` JSON.
async fn metrics_prometheus(State(state): State<AppState>) -> impl axum::response::IntoResponse {
    let body = state.db_cache_metrics.render_prometheus();
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

/// v0.49.2: schema discoverability endpoint. Returns the canonical
/// list of versioned protocol schemas this hub knows about. Lets a
/// client bootstrap without scraping HTML or guessing URLs.
async fn well_known_vela(State(state): State<AppState>) -> Json<Value> {
    let signed_at = chrono::Utc::now().to_rfc3339();
    let manifest = json!({
        "name": "vela-hub",
        "version": HUB_VERSION,
        "protocol_version": "0.48",
        "site": state.urls.site.clone(),
        "signed_at": signed_at,
        "endpoints": {
            "registry": format!("{}/entries", state.urls.hub),
            "publish":  format!("{}/entries", state.urls.hub),
            "events": format!("{}/entries/{{vfr_id}}/events", state.urls.hub),
            "events_stream": format!("{}/entries/{{vfr_id}}/events/stream", state.urls.hub),
            "frontier_inbox": format!("{}/frontier/{{vfr_id}}/inbox", state.urls.hub),
            "snapshot": format!("{}/entries/{{vfr_id}}/snapshot", state.urls.hub),
            "counterfactual": format!("{}/api/counterfactual/{{vfr_id}}", state.urls.hub),
            "metrics":  format!("{}/metrics", state.urls.hub),
            "healthz":  format!("{}/healthz", state.urls.hub),
        },
        "agent_sla": {
            "mode": "best_effort",
            "max_events_per_request": 500,
            "max_bytes_per_event": 1048576,
            "retry_after_seconds": 15,
            "writes": "POST /entries accepts signed manifests with inline substrate; direct event append is not enabled on this hub yet"
        },
        "schemas": {
            "registry":               "https://vela.science/schema/registry/v1",
            "finding-bundle":         "https://vela.science/schema/finding-bundle/v0.10.0",
            "frontier-packet":        "https://vela.science/schema/frontier-packet/v1",
            "event":                  "https://vela.science/schema/event/v1",
            "counterfactual-query":   "https://vela.science/schema/counterfactual/v0.45.1",
            "agent-run":              "https://vela.science/schema/agent-run/v0.22",
            "key-revoke":             "https://vela.science/schema/event/key-revoke/v0.49",
            "cross-impl-reducer-fixture": "https://vela.science/schema/cross-impl-reducer-fixture/v1",
            "canonical-json":         "https://vela.science/schema/canonical-json/v1",
        },
        "canonical_json_v1": {
            "summary": "RFC-8785-shaped canonical JSON used as the preimage for every Vela signature.",
            "rules": [
                "object keys sorted lexicographically by UTF-8 byte order, recursively",
                "no insignificant whitespace between tokens",
                "strings are UTF-8 with JSON-standard escaping",
                "numbers in shortest round-trip form; NaN and Infinity rejected",
                "no trailing commas; arrays preserve source order"
            ],
            "reference_impl": "vela_protocol::canonical::to_canonical_bytes (Rust)"
        },
        "second_implementations": {
            "packet_verifier": "https://vela.science/vela_verify.py",
            "reducer":         "https://vela.science/vela_reducer.py",
            "reducer_typescript": "https://vela.science/vela_reducer.ts"
        },
    });

    // v0.49.3.1: detached Ed25519 signature over the manifest's
    // canonical-JSON bytes. To verify (TS / Python / any language with
    // an Ed25519 lib):
    //   1. Take envelope.manifest as a JSON object.
    //   2. Re-canonicalize per the `canonical_json_v1` rules above
    //      (sorted keys, no whitespace, UTF-8) → raw bytes.
    //   3. Verify(signature.pubkey, canonical_bytes, signature.value)
    //      using **pure Ed25519** (RFC 8032 §5.1.7 EdDSA).
    //
    // Pure Ed25519 hashes the message internally with SHA-512 as part
    // of the EdDSA signing equation — DO NOT pre-hash the canonical
    // bytes before verifying. (`ed25519_dalek::SigningKey::sign(bytes)`
    // is pure Ed25519, not Ed25519ph.)
    //
    // Mode is "unsigned" when VELA_HUB_SIGNING_KEY_PATH is unset.
    match (&state.signing_key, canonical::to_canonical_bytes(&manifest)) {
        (Some(key), Ok(bytes)) => {
            let sig = vsign::sign_bytes(key, &bytes);
            Json(json!({
                "manifest": manifest,
                "signature": {
                    "alg": "Ed25519",
                    "alg_variant": "pure",
                    "pubkey": vsign::pubkey_hex(key),
                    "value": hex::encode(sig),
                    "canonical_format": "vela.canonical-json/v1",
                    "canonical_format_spec": "https://vela.science/schema/canonical-json/v1",
                    "signed_at": signed_at,
                    "verifier_steps": [
                        "1. take envelope.manifest as JSON",
                        "2. re-canonicalize per canonical_json_v1 → raw bytes",
                        "3. Ed25519 verify (RFC 8032 §5.1.7, pure not ph) over canonical bytes — do NOT pre-hash"
                    ],
                },
                "mode": "signed",
            }))
        }
        _ => Json(json!({
            "manifest": manifest,
            "signature": null,
            "mode": "unsigned",
            "note": "set VELA_HUB_SIGNING_KEY_PATH on the hub to enable detached pure-Ed25519 signatures over this discovery manifest",
        })),
    }
}

/// Readiness, as distinct from liveness: a machine is READY only once
/// its hosted-MCP projection is built (or there is genuinely nothing to
/// build). Wired as a fly http check so a rolling deploy keeps the old
/// machine serving `/mcp` until the new one has finished its first
/// projection build — a deploy never blanks the public endpoint.
async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    if state.mcp.read().await.is_some() {
        return (
            StatusCode::OK,
            Json(json!({"ready": true, "mcp": "projection built", "version": HUB_VERSION})),
        );
    }
    match state.db.list_live_entries().await {
        Ok(entries) if entries.is_empty() => (
            StatusCode::OK,
            Json(json!({"ready": true, "mcp": "no frontiers registered", "version": HUB_VERSION})),
        ),
        Ok(entries) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ready": false,
                "mcp": format!("projection building ({} frontiers)", entries.len()),
                "version": HUB_VERSION,
            })),
        ),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ready": false,
                "error": {"kind": "UNAVAILABLE", "message": e},
                "version": HUB_VERSION,
            })),
        ),
    }
}

async fn healthz(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let cache = state.db_cache_metrics.snapshot();
    match state.db.health().await {
        Ok(()) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "db": "reachable",
                "version": HUB_VERSION,
                "cache": cache,
            })),
        ),
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "db": "unreachable",
                "error": {"kind": "UNAVAILABLE", "message": e},
                "version": HUB_VERSION,
                "cache": cache,
            })),
        ),
    }
}

async fn list_entries(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let cache_key = "list_entries";
    let cached = db_cache_read(&state.db_cache, cache_key).await;
    let now = std::time::Instant::now();

    // Fresh cache window — serve straight from memory, skip DB.
    if let Some(entry) = cached.as_ref()
        && now.duration_since(entry.fetched_at) < DB_CACHE_FRESH_TTL
    {
        state.db_cache_metrics.record_hit();
        return cached_list_response(&state.urls, &entry.value, &headers, false);
    }

    match state.db.list_live_entries().await {
        Ok(values) => {
            state.db_cache_metrics.record_miss();
            let payload = json!({"schema": REGISTRY_SCHEMA, "entries": values});
            db_cache_write(&state.db_cache, cache_key, payload.clone()).await;
            if wants_html(&headers) {
                Html(render_entries_html(&state.urls, &values)).into_response()
            } else {
                (StatusCode::OK, Json(payload)).into_response()
            }
        }
        Err(e) => {
            state.db_cache_metrics.record_db_error();
            // v0.49: stale-on-read fallback. Serve the last good
            // payload (with X-Vela-Stale) instead of 5xx-ing on a
            // single DB hiccup. Inside the stale window only.
            if let Some(entry) = cached {
                let age = now.duration_since(entry.fetched_at);
                if age < DB_CACHE_STALE_WINDOW {
                    state.db_cache_metrics.record_stale_hit(age.as_secs());
                    tracing::warn!(
                        "list_entries: db error '{e}', serving stale ({}s old)",
                        age.as_secs()
                    );
                    return cached_list_response(&state.urls, &entry.value, &headers, true);
                }
            }
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response()
        }
    }
}

fn cached_list_response(
    urls: &PublicUrls,
    payload: &Value,
    headers: &HeaderMap,
    stale: bool,
) -> Response {
    let entries = payload
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    let mut resp = if wants_html(headers) {
        Html(render_entries_html(urls, &entries)).into_response()
    } else {
        (StatusCode::OK, Json(payload.clone())).into_response()
    };
    if stale {
        resp.headers_mut().insert(
            axum::http::header::HeaderName::from_static("x-vela-stale"),
            axum::http::HeaderValue::from_static("1"),
        );
    }
    resp
}

/// Read a promoted frontier from event/projection tables and cache the
/// reconstructed `Project` by `(vfr_id, signed_publish_at)`.
///
/// This is intentionally strict after the event-first cutover: if a
/// frontier has not been promoted to `frontiers`, live routes surface an
/// unavailable state instead of fetching an old `network_locator` or a
/// blob export as an alternate source of truth.
async fn load_substrate(
    state: &AppState,
    vfr_id: &str,
    signed_publish_at: &str,
) -> Option<Arc<Project>> {
    let cache_key = (vfr_id.to_string(), signed_publish_at.to_string());
    if let Some(hit) = state.frontier_cache.read().await.get(&cache_key).cloned() {
        return Some(hit);
    }

    match state.db.get_materialized_project(vfr_id).await {
        Ok(Some(project)) => {
            let arc = Arc::new(project);
            state
                .frontier_cache
                .write()
                .await
                .insert(cache_key, arc.clone());
            return Some(arc);
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!(%vfr_id, error = %e, "event-first materialized project read failed");
        }
    }
    None
}

/// The live Sidon open-frontier over HTTP: the next bound to beat at each n,
/// compiled from the frontier's accepted record so a producer reads what to
/// attempt without cloning. Keyless (a planning view, not accepted state) and
/// additive. Sidon-specific; a non-Sidon frontier returns 422.
async fn get_sidon_frontier_map(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
) -> Response {
    use std::collections::BTreeSet;
    use vela_protocol::sidon_profile::{
        build_frontier_map, live_presentation, next_bound_obligations,
    };
    let project = match state.db.get_materialized_project(&vfr_id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body(
                    "NOT_FOUND",
                    format!("frontier not found: {vfr_id}"),
                )),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", e)),
            )
                .into_response();
        }
    };
    let pres = match live_presentation(&project) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(error_body(
                    "INVALID_ARG",
                    format!("not a live Sidon frontier ({vfr_id}): {e}"),
                )),
            )
                .into_response();
        }
    };
    let disabled = BTreeSet::new();
    let map =
        next_bound_obligations(&pres).and_then(|obls| build_frontier_map(&pres, &obls, &disabled));
    match map {
        Ok(m) => (StatusCode::OK, Json(m)).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", e)),
        )
            .into_response(),
    }
}

/// The live authoritative Sidon bounds over HTTP: the best lower bound at each n,
/// compiled from the frontier's accepted record, with the presentation root so a
/// consumer can independently replay it. The read half of the loop, paired with
/// sidon-frontier-map. Keyless and replayable; the SIGNED ObservationPacket is the
/// producer's own read (`vela sidon export`). Sidon-specific; non-Sidon → 422.
async fn get_sidon_observation(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
) -> Response {
    use std::collections::BTreeSet;
    use vela_protocol::sidon_profile::{best_bounds, live_presentation};
    let project = match state.db.get_materialized_project(&vfr_id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body(
                    "NOT_FOUND",
                    format!("frontier not found: {vfr_id}"),
                )),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", e)),
            )
                .into_response();
        }
    };
    let pres = match live_presentation(&project) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(error_body(
                    "INVALID_ARG",
                    format!("not a live Sidon frontier ({vfr_id}): {e}"),
                )),
            )
                .into_response();
        }
    };
    let disabled = BTreeSet::new();
    let bounds = match best_bounds(&pres, &disabled) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", e)),
            )
                .into_response();
        }
    };
    let root = pres.presentation_root().unwrap_or_default();
    (
        StatusCode::OK,
        Json(json!({
            "schema": "vela.sidon-bounds.v1",
            "vfr_id": vfr_id,
            "presentation_root": root,
            "bounds": bounds,
            "replay": "vela sidon export --frontier <dir> reproduces this as a signed observation",
        })),
    )
        .into_response()
}

async fn get_entry(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let row = state.db.get_live_entry(&vfr_id).await;
    match row {
        Ok(Some(value)) => {
            if wants_html(&headers) {
                let signed_at = value
                    .get("signed_publish_at")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let frontier = load_substrate(&state, &vfr_id, signed_at).await;
                let git_remote = state
                    .db
                    .get_git_remote(&vfr_id)
                    .await
                    .ok()
                    .flatten()
                    .and_then(|v| {
                        v.get("git_remote")
                            .and_then(|r| r.as_str())
                            .map(str::to_string)
                    });
                Html(render_entry_html(
                    &state.urls,
                    &vfr_id,
                    &value,
                    frontier.as_deref(),
                    git_remote.as_deref(),
                ))
                .into_response()
            } else {
                (StatusCode::OK, Json(value)).into_response()
            }
        }
        Ok(None) => {
            if let Ok(Some(audit)) = state.db.latest_audit_status(&vfr_id).await
                && audit.status == "failed"
            {
                if wants_html(&headers) {
                    return (
                        StatusCode::FAILED_DEPENDENCY,
                        Html(render_entry_unavailable_html(
                            &state.urls,
                            &vfr_id,
                            audit
                                .error
                                .as_deref()
                                .unwrap_or("frontier failed verification"),
                        )),
                    )
                        .into_response();
                }
                return (
                    StatusCode::FAILED_DEPENDENCY,
                    Json(json!({
                        "ok": false,
                        "status": "unavailable",
                        "vfr_id": vfr_id,
                        "error": {"kind": "UNAVAILABLE", "message": audit.error.unwrap_or_else(|| "frontier failed verification".to_string())},
                        "authority_mode": audit.authority_mode,
                    })),
                )
                    .into_response();
            }
            if wants_html(&headers) {
                (
                    StatusCode::NOT_FOUND,
                    Html(render_not_found_html(&state.urls, &vfr_id)),
                )
                    .into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("query: {e}"))),
        )
            .into_response(),
    }
}

/// GET /entries/{vfr_id}/proposals/{proposal_id}/evidence-diff —
/// the read-only Evidence Diff for a pending proposal: its before/after
/// effect on the target claim plus the downstream claims whose status
/// flips. A pure projection over the materialized state (never writes,
/// never accepts); the strict accept gate still runs at accept time and
/// is the only thing that mutates state. The Engine verdict is rendered
/// absent here because `evidence_ci::run_project` needs a frontier path
/// (policy docs, artifact files) the Postgres-materialized project lacks.
async fn get_proposal_evidence_diff(
    State(state): State<AppState>,
    Path((vfr_id, proposal_id)): Path<(String, String)>,
) -> Response {
    let project = match state.db.get_materialized_project(&vfr_id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body(
                    "NOT_FOUND",
                    format!("{vfr_id} not found on this hub"),
                )),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("project query: {e}"))),
            )
                .into_response();
        }
    };
    match vela_protocol::evidence_diff::claim_state_delta(
        &project,
        &proposal_id,
        "reviewer:evidence-diff-preview",
    ) {
        Ok(delta) => Json(delta).into_response(),
        Err(e) => (StatusCode::NOT_FOUND, Json(error_body("NOT_FOUND", e))).into_response(),
    }
}

/// Lightweight per-frontier counts for list/dashboard views. Computed by cheap
/// projection-table aggregates (never the multi-MB snapshot), so the catalogue
/// can render real numbers without downloading whole frontiers. JSON only.
async fn get_entry_summary(State(state): State<AppState>, Path(vfr_id): Path<String>) -> Response {
    match state.db.frontier_summary(&vfr_id).await {
        Ok(Some(value)) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "public, max-age=60")],
            Json(value),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("summary: {e}"))),
        )
            .into_response(),
    }
}

/// Frontier manifest (L1): the small "list, then fetch only what you open"
/// primitive — counts + log head + an index of object ids by type, WITHOUT the
/// bulk raw_json. A client reads this, then pulls individual objects on demand
/// (sparse / partial clone) rather than the whole multi-MB snapshot.
/// Lifecycle status for a frontier: 'live' or 'deprecated', with the
/// signed deprecation receipt when present. Deprecated entries vanish
/// from /entries and /search, but stay auditable here — correction is
/// first-class, never silent deletion.
async fn get_entry_status(State(state): State<AppState>, Path(vfr_id): Path<String>) -> Response {
    let deprecation = match state.db.get_deprecation(&vfr_id).await {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };
    let known = match state.db.frontier_owner_pubkey(&vfr_id).await {
        Ok(k) => k.is_some(),
        Err(_) => false,
    };
    if !known && deprecation.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
        )
            .into_response();
    }
    Json(json!({
        "vfr_id": vfr_id,
        "status": if deprecation.is_some() { "deprecated" } else { "live" },
        "deprecation": deprecation,
    }))
    .into_response()
}

/// The git-remote registration + ingest cursor for a frontier (read side of
/// the git-ingestion lane; docs/HUB.md).
async fn get_git_remote(State(state): State<AppState>, Path(vfr_id): Path<String>) -> Response {
    match state.db.get_git_remote(&vfr_id).await {
        Ok(Some(rec)) => Json(json!({"vfr_id": vfr_id, "git": rec})).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(error_body(
                "NOT_FOUND",
                format!("{vfr_id} has no registered git remote"),
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("query: {e}"))),
        )
            .into_response(),
    }
}

/// Register a frontier's git remote — the ONE owner-signed act in the
/// git-ingestion lane. The body is a `GitRemoteRegistration`
/// (vela.frontier-git-remote.v0.1): the signature must verify AND the signer
/// must be the frontier's effective owner (original publisher or rotation
/// successor). After this, the ingestor re-derives the index from the repo
/// itself; no further signed publishes are needed.
async fn register_git_remote(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
    Json(body): Json<Value>,
) -> Response {
    use vela_protocol::registry::{GitRemoteRegistration, verify_git_remote};
    let rec: GitRemoteRegistration = match serde_json::from_value(body.clone()) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(error_body(
                    "INVALID_ARG",
                    format!("registration parse: {e}"),
                )),
            )
                .into_response();
        }
    };
    if rec.vfr_id != vfr_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body(
                "INVALID_ARG",
                "registration vfr_id does not match the path",
            )),
        )
            .into_response();
    }
    match verify_git_remote(&rec) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(error_body(
                    "PERMISSION_DENIED",
                    "registration signature does not verify",
                )),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(error_body("INVALID_ARG", format!("registration: {e}"))),
            )
                .into_response();
        }
    }
    // Owner check: the signer must be the effective owner of an EXISTING
    // entry. (A brand-new vfr_id may bootstrap by registering its remote —
    // the signature is then the ownership claim, matching the "anyone can
    // publish their own vfr_id" doctrine.)
    match state.db.effective_owner_pubkey(&vfr_id).await {
        Ok(Some(owner)) if owner != rec.signer_pubkey_hex => {
            return (
                StatusCode::FORBIDDEN,
                Json(error_body(
                    "PERMISSION_DENIED",
                    "signer is not the frontier's effective owner",
                )),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("owner lookup: {e}"))),
            )
                .into_response();
        }
    }
    if let Err(e) = state
        .db
        .set_git_remote(
            &vfr_id,
            &rec.git_remote,
            &rec.git_ref,
            &rec.git_subdir,
            &rec.signer_pubkey_hex,
            &rec.registered_at,
            &body,
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("store: {e}"))),
        )
            .into_response();
    }
    Json(json!({
        "ok": true,
        "vfr_id": vfr_id,
        "git_remote": rec.git_remote,
        "git_ref": rec.git_ref,
        "note": "registered; the ingestor re-derives the index from the repo on its next sweep",
    }))
    .into_response()
}

/// The effective maintainer set + the action log scaffold.
async fn list_maintainers(State(state): State<AppState>, Path(vfr_id): Path<String>) -> Response {
    match state.db.effective_maintainers(&vfr_id).await {
        Ok(keys) => Json(json!({
            "vfr_id": vfr_id,
            "maintainer_pubkeys": keys,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("query: {e}"))),
        )
            .into_response(),
    }
}

/// True iff `s` is a lowercase 64-char hex sha256 digest.
fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The object-storage key for an artifact blob, namespaced away from the
/// bare-`{hash}` snapshot keys and the `scratch/` tier.
fn blob_key(hash: &str) -> String {
    format!("blobs/{hash}")
}

/// Content-addressed artifact-blob fetch (`GET /blobs/{hash}`).
///
/// Serves the bytes a frontier's `Artifact` objects commit to by
/// `content_hash` — witnesses, proof packets, `local_blob` datasets. Like
/// the snapshot path, the hub stays OUT of the bytes path: a 302 to the
/// immutable public CDN object. Reads are self-verifying — the client
/// recomputes sha256 and checks it against the `content_hash` committed in
/// the signed snapshot, so a wrong or poisoned blob is caught on receipt,
/// never trusted. This is the read half of what makes a cold `vela clone`
/// able to reconstruct the working tree and re-run `vela reproduce`.
async fn get_blob(State(state): State<AppState>, Path(hash): Path<String>) -> Response {
    let hash = hash.trim().to_ascii_lowercase();
    if !is_sha256_hex(&hash) {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body(
                "INVALID_ARG",
                "blob id must be a 64-char sha256 hex string",
            )),
        )
            .into_response();
    }
    let Some(storage) = &state.storage else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(error_body(
                "UNAVAILABLE",
                "hub has no object storage configured",
            )),
        )
            .into_response();
    };
    let key = blob_key(&hash);
    // 302 to the immutable CDN object. Content-addressed bytes never change,
    // so cache hard. The client follows the redirect and verifies the hash.
    let redirect = || {
        let url = storage.public_url_for(&key);
        let mut resp = (
            StatusCode::FOUND,
            [(axum::http::header::LOCATION, url.as_str())],
            Json(json!({"ok": true, "hash": hash, "blob_url": url})),
        )
            .into_response();
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("public, max-age=31536000, immutable"),
        );
        if let Ok(etag) = axum::http::HeaderValue::from_str(&format!("\"{hash}\"")) {
            resp.headers_mut().insert(axum::http::header::ETAG, etag);
        }
        resp
    };
    match storage.exists(&key).await {
        Ok(true) => redirect(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(error_body("NOT_FOUND", format!("blob {hash} not found"))),
        )
            .into_response(),
        // A HEAD that errors (not a clean 404) must NOT block a blob that may
        // well be present: the CDN is authoritative and the client verifies
        // the hash, so redirect optimistically rather than 500. A truly-absent
        // blob then surfaces as a CDN 404 on the followed request.
        Err(_) => redirect(),
    }
}

/// The producer view: cross-frontier objects signed by one key — the
/// fundable CV, queryable in one call.
async fn get_producer(
    State(state): State<AppState>,
    Path(pubkey): Path<String>,
    headers: HeaderMap,
) -> Response {
    match state.db.producer_objects(&pubkey, 500).await {
        Ok(rows) => {
            let mut by_frontier: std::collections::BTreeMap<String, Vec<Value>> =
                std::collections::BTreeMap::new();
            for (vfr, otype, oid, raw) in rows {
                by_frontier.entry(vfr).or_default().push(json!({
                    "type": otype,
                    "id": oid,
                    "summary": raw.get("claim").or_else(|| raw.get("assertion").and_then(|a| a.get("text"))).cloned().unwrap_or(Value::Null),
                }));
            }
            if wants_html(&headers) {
                return Html(render_producer_html(&state.urls, &pubkey, &by_frontier))
                    .into_response();
            }
            Json(json!({
                "pubkey": pubkey,
                "frontiers": by_frontier,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("query: {e}"))),
        )
            .into_response(),
    }
}

async fn get_entry_manifest(State(state): State<AppState>, Path(vfr_id): Path<String>) -> Response {
    let entry = match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(e)) => e,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };
    let counts = match state.db.frontier_summary(&vfr_id).await {
        Ok(Some(s)) => s,
        _ => json!({}),
    };
    let objects = match state.db.frontier_object_index(&vfr_id).await {
        Ok(o) => o,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("index: {e}"))),
            )
                .into_response();
        }
    };
    let manifest = json!({
        "vfr_id": vfr_id,
        "name": entry.get("name").cloned().unwrap_or(Value::Null),
        "log_head": entry.get("latest_event_log_hash").cloned().unwrap_or(Value::Null),
        "snapshot_hash": entry.get("latest_snapshot_hash").cloned().unwrap_or(Value::Null),
        "counts": counts,
        "objects": objects,
    });
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "public, max-age=60")],
        Json(manifest),
    )
        .into_response()
}

/// Cross-frontier object text search (the public /search page's backend). One
/// hub query over frontier_objects instead of downloading every frontier's
/// snapshot. Params: `q` (text), `type` (finding|source|evidence_atom|…,
/// default finding), `limit` (default 24, max 200).
async fn search_endpoint(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let q = params
        .get("q")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    let object_type = params
        .get("type")
        .cloned()
        .unwrap_or_else(|| "finding".to_string());
    let limit: i64 = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(24)
        .clamp(1, 200);
    let html = wants_html(&headers);
    if q.is_empty() {
        if html {
            return Html(render_search_html(&state.urls, "", &object_type, &[])).into_response();
        }
        return (
            StatusCode::OK,
            Json(json!({"results": [], "q": q, "type": object_type})),
        )
            .into_response();
    }
    match state.db.search_objects(&q, &object_type, limit).await {
        Ok(results) => {
            if html {
                return Html(render_search_html(&state.urls, &q, &object_type, &results))
                    .into_response();
            }
            (
                StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, "public, max-age=60")],
                Json(json!({"results": results, "q": q, "type": object_type})),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("search: {e}"))),
        )
            .into_response(),
    }
}

/// The cross-frontier search page: a form plus result rows. Findings link
/// to their finding page; anything else lands on the frontier entry.
fn render_search_html(urls: &PublicUrls, q: &str, object_type: &str, results: &[Value]) -> String {
    let q_safe = escape_html(q);
    let type_options: String = ["finding", "source", "evidence_atom", "proposal"]
        .iter()
        .map(|t| {
            let sel = if *t == object_type { " selected" } else { "" };
            format!(r#"<option value="{t}"{sel}>{t}</option>"#)
        })
        .collect();
    let form = format!(
        r#"<form method="get" action="/search" class="tm-paper" style="padding:14px 16px;display:flex;gap:10px;align-items:center;">
  <input type="search" name="q" value="{q_safe}" placeholder="search live frontier state…" style="flex:1;font-family:var(--font-mono);font-size:13px;padding:8px 10px;background:transparent;border:1px solid var(--line);border-radius:6px;color:var(--ink-0);" autofocus>
  <select name="type" style="font-family:var(--font-mono);font-size:12px;padding:8px;background:transparent;border:1px solid var(--line);border-radius:6px;color:var(--ink-1);">{type_options}</select>
  <button type="submit" class="wb-chip" style="cursor:pointer;">search</button>
</form>"#
    );
    let rows: String = results
        .iter()
        .filter_map(|r| {
            let vfr = r.get("vfr_id").and_then(Value::as_str)?;
            let obj = r.get("object")?;
            let id = obj.get("id").and_then(Value::as_str).unwrap_or("");
            let text = obj
                .pointer("/assertion/text")
                .and_then(Value::as_str)
                .or_else(|| obj.get("claim").and_then(Value::as_str))
                .or_else(|| obj.get("reason").and_then(Value::as_str))
                .or_else(|| obj.get("title").and_then(Value::as_str))
                .unwrap_or("");
            let text: String = escape_html(&text.chars().take(160).collect::<String>());
            let href = if object_type == "finding" && !id.is_empty() {
                format!("/entries/{vfr}/findings/{id}")
            } else {
                format!("/entries/{vfr}")
            };
            Some(format!(
                r#"<li><span class="link-rel">{vfr_short}</span> <span><a href="{href}"><code>{id}</code></a> · {text}</span></li>"#,
                vfr_short = escape_html(&vfr.chars().take(12).collect::<String>()),
                id = escape_html(id),
            ))
        })
        .collect();
    let body = if q.is_empty() {
        String::new()
    } else if rows.is_empty() {
        r#"<p class="empty">No live object matches. The search is exact-substring over replayed state — try a shorter fragment.</p>"#.to_string()
    } else {
        format!(r#"<ul class="link-list">{rows}</ul>"#)
    };
    let count_note = if q.is_empty() {
        "search every live frontier".to_string()
    } else {
        format!("{} result(s) for “{q_safe}”", results.len())
    };
    shell(
        urls,
        "Vela Hub · Search",
        "entries",
        "Search",
        "Cross-frontier search",
        &count_note,
        "",
        &format!(
            "{form}
{body}"
        ),
        "exact-substring over verified, replayed state — never an index of claims nobody signed",
    )
}

/// One page of a frontier's objects of a given type — lets detail surfaces
/// (sources, proposals, …) render without pulling the whole snapshot. Params:
/// limit (default 100, max 500), offset (default 0). Returns {objects, total}.
async fn get_entry_objects(
    State(state): State<AppState>,
    Path((vfr_id, otype)): Path<(String, String)>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let limit: i64 = params
        .get("limit")
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
        .clamp(1, 500);
    let offset: i64 = params
        .get("offset")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
        .max(0);
    match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    }
    match state
        .db
        .frontier_objects_page(&vfr_id, &otype, limit, offset)
        .await
    {
        Ok((objects, total)) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "public, max-age=60")],
            Json(json!({
                "vfr_id": vfr_id, "type": otype,
                "limit": limit, "offset": offset, "total": total,
                "objects": objects,
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("objects: {e}"))),
        )
            .into_response(),
    }
}

/// A single frontier object by (type, object_id) — a primary-key point lookup.
async fn get_entry_object(
    State(state): State<AppState>,
    Path((vfr_id, otype, object_id)): Path<(String, String, String)>,
) -> Response {
    match state.db.frontier_object(&vfr_id, &otype, &object_id).await {
        Ok(Some(obj)) => (
            StatusCode::OK,
            [(axum::http::header::CACHE_CONTROL, "public, max-age=60")],
            Json(obj),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(error_body(
                "NOT_FOUND",
                format!("{object_id} not found in {vfr_id}"),
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("object: {e}"))),
        )
            .into_response(),
    }
}

/// Load a frontier's event log as Merkle leaves — each leaf is an event's
/// content-address preimage (the vev_ preimage), ordered by seq.
async fn log_leaves(state: &AppState, vfr_id: &str) -> Result<Vec<Vec<u8>>, String> {
    let values = state.db.all_event_values(vfr_id).await?;
    let mut leaves = Vec::with_capacity(values.len());
    for v in &values {
        let ev: vela_protocol::events::StateEvent =
            serde_json::from_value(v.clone()).map_err(|e| format!("event parse: {e}"))?;
        leaves.push(vela_protocol::events::event_content_preimage_bytes(&ev));
    }
    Ok(leaves)
}

/// Signed Tree Head (P2 transparency log): a signed RFC 6962 Merkle commitment to
/// the frontier's whole event log. Lets anyone verify the hub cannot silently
/// rewrite history (against a non-equivocating hub; witness co-signing adds
/// split-view resistance). Signed with the hub key (same key as
/// /.well-known/vela); verifiers MUST pin the pubkey out-of-band, not trust the
/// pubkey in the signature block.
async fn get_log_sth(State(state): State<AppState>, Path(vfr_id): Path<String>) -> Response {
    match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    }
    let leaves = match log_leaves(&state, &vfr_id).await {
        Ok(l) => l,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", e)),
            )
                .into_response();
        }
    };
    let root = vela_protocol::merkle::merkle_root(&leaves);
    let tree_size = leaves.len() as u64;
    let timestamp = chrono::Utc::now().to_rfc3339();
    let log_id = match &state.signing_key {
        Some(key) => format!("vela-log:{}:{}", vfr_id, vsign::pubkey_hex(key)),
        None => format!("vela-log:{vfr_id}:unsigned"),
    };
    let sth = json!({
        "schema": "vela.sth.v1",
        "log_id": log_id,
        "vfr_id": vfr_id,
        "tree_size": tree_size,
        "root_hash": vela_protocol::merkle::to_commitment(&root),
        "timestamp": timestamp,
    });
    match (&state.signing_key, canonical::to_canonical_bytes(&sth)) {
        (Some(key), Ok(bytes)) => {
            let sig = vsign::sign_bytes(key, &bytes);
            (
                StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, "public, max-age=30")],
                Json(json!({
                    "sth": sth,
                    "signature": {
                        "alg": "Ed25519",
                        "alg_variant": "pure",
                        "pubkey": vsign::pubkey_hex(key),
                        "value": hex::encode(sig),
                        "canonical_format": "vela.canonical-json/v1",
                        "verifier_steps": [
                            "1. pin the hub pubkey out-of-band (/.well-known/vela); do NOT trust this block's pubkey",
                            "2. re-canonicalize `sth` to bytes; Ed25519 (pure, not ph) verify the signature over them",
                            "3. recompute leaves = event content-address preimages ordered by seq; merkle_root must equal sth.root_hash"
                        ]
                    },
                    "mode": "signed",
                })),
            )
                .into_response()
        }
        _ => (
            StatusCode::OK,
            Json(json!({"sth": sth, "signature": null, "mode": "unsigned"})),
        )
            .into_response(),
    }
}

/// Inclusion proof that `event_id` is in the frontier's log (RFC 6962 audit
/// path), checkable against the STH root.
async fn get_log_proof(
    State(state): State<AppState>,
    Path((vfr_id, event_id)): Path<(String, String)>,
) -> Response {
    let values = match state.db.all_event_values(&vfr_id).await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("events: {e}"))),
            )
                .into_response();
        }
    };
    let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(values.len());
    let mut found: Option<usize> = None;
    for (i, v) in values.iter().enumerate() {
        match serde_json::from_value::<vela_protocol::events::StateEvent>(v.clone()) {
            Ok(ev) => {
                if ev.id == event_id {
                    found = Some(i);
                }
                leaves.push(vela_protocol::events::event_content_preimage_bytes(&ev));
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(error_body("INTERNAL", format!("event parse: {e}"))),
                )
                    .into_response();
            }
        }
    }
    let m = match found {
        Some(i) => i,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body(
                    "NOT_FOUND",
                    format!("event {event_id} not in {vfr_id}"),
                )),
            )
                .into_response();
        }
    };
    let proof = match vela_protocol::merkle::inclusion_proof(&leaves, m) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", "proof generation failed")),
            )
                .into_response();
        }
    };
    let root = vela_protocol::merkle::merkle_root(&leaves);
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "public, max-age=30")],
        Json(json!({
            "vfr_id": vfr_id,
            "event_id": event_id,
            "leaf_index": m,
            "tree_size": leaves.len(),
            "root_hash": vela_protocol::merkle::to_commitment(&root),
            "audit_path": proof.iter().map(hex::encode).collect::<Vec<_>>(),
        })),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
struct ConsistencyQuery {
    /// Old (first) tree size — the size of the STH you already trust.
    first: usize,
    /// New (second) tree size; defaults to the current log length.
    second: Option<usize>,
}

/// RFC 6962 §2.1.2 consistency proof: that the size-`first` tree is an
/// append-only prefix of the size-`second` tree (defaults to the current
/// length). Lets a verifier holding an older signed STH confirm the log only
/// grew — never forked or rewrote history — before trusting a newer STH.
async fn get_log_consistency(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
    Query(q): Query<ConsistencyQuery>,
) -> Response {
    let leaves = match log_leaves(&state, &vfr_id).await {
        Ok(l) => l,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", e)),
            )
                .into_response();
        }
    };
    let total = leaves.len();
    let m = q.first;
    let n = q.second.unwrap_or(total);
    if m == 0 || m > n || n > total {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body(
                "INVALID_ARG",
                format!("require 1 <= first <= second <= tree_size; got first={m}, second={n}, tree_size={total}"),
            )),
        )
            .into_response();
    }
    let proof = match vela_protocol::merkle::consistency_proof(&leaves[..n], m) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body(
                    "INTERNAL",
                    "consistency proof generation failed",
                )),
            )
                .into_response();
        }
    };
    let first_root = vela_protocol::merkle::merkle_root(&leaves[..m]);
    let second_root = vela_protocol::merkle::merkle_root(&leaves[..n]);
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, "public, max-age=30")],
        Json(json!({
            "schema": "vela.consistency-proof.v1",
            "vfr_id": vfr_id,
            "first_size": m,
            "second_size": n,
            "first_root": vela_protocol::merkle::to_commitment(&first_root),
            "second_root": vela_protocol::merkle::to_commitment(&second_root),
            "consistency_proof": proof.iter().map(hex::encode).collect::<Vec<_>>(),
            "verifier_steps": [
                "1. first_root must equal the root of the older STH you already trust (size=first_size)",
                "2. second_root must equal the root of the newer STH (size=second_size)",
                "3. verify_consistency(first_size, second_size, first_root, second_root, proof) — confirms append-only"
            ],
        })),
    )
        .into_response()
}

/// v0.201: hub lookup handle for a Scientific Diff Pack (`vsd_*`).
///
/// Returns the signed pack JSON if the pack has been registered with
/// this hub via a `diff_pack.released` event. The pack body itself
/// is small (id + frontier_id + summary + member ids + signature);
/// reviewers fetch the full member proposals from the originating
/// frontier's snapshot blob, addressed by its latest_snapshot_hash.
///
/// 404 when the pack id isn't on this hub — that's substrate-honest:
/// a hub can witness packs but is not required to mirror every
/// peer hub's set.
async fn get_diff_pack(State(state): State<AppState>, Path(pack_id): Path<String>) -> Response {
    if !pack_id.starts_with("vsd_") {
        return (
            StatusCode::BAD_REQUEST,
            Json(error_body("INVALID_ARG", "pack_id must start with `vsd_`")),
        )
            .into_response();
    }
    match state.db.get_diff_pack(&pack_id).await {
        Ok(Some(value)) => (StatusCode::OK, Json(value)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(error_body(
                "NOT_FOUND",
                format!(
                    "{pack_id} not found on this hub (a pack lands here when a `diff_pack.released` event has been applied on a frontier this hub mirrors)"
                ),
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("query: {e}"))),
        )
            .into_response(),
    }
}

/// v0.15: hub-level reverse lookup. Returns the registry entries
/// (latest-publish-wins per vfr_id) whose frontier declares a
/// cross-frontier dependency on `{vfr_id}`. Surfaces "who in the world
/// is referencing my frontier" — closes the bidirectional gap in the
/// cross-frontier composition story.
///
/// Implementation is O(N) over current live entries: dependency lists
/// are materialized from promoted frontier state and cached by
/// `(vfr_id, signed_publish_at)`. Failed or unpromoted registry rows do
/// not participate.
async fn get_depends_on(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let _ = &headers; // reserved for future HTML rendering
    let rows = match state.db.list_live_entries().await {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };

    let mut dependents: Vec<serde_json::Value> = Vec::new();
    for entry in &rows {
        let entry_vfr = entry.get("vfr_id").and_then(|v| v.as_str()).unwrap_or("");
        if entry_vfr == vfr_id {
            continue; // a frontier doesn't depend on itself
        }
        let signed_at = entry
            .get("signed_publish_at")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let Some(project) = load_substrate(&state, entry_vfr, signed_at).await else {
            // Projection unavailable means the frontier is not live for
            // composition. Skip it; direct entry routes surface the
            // unavailable state.
            continue;
        };
        if project
            .project
            .dependencies
            .iter()
            .any(|d| d.vfr_id.as_deref() == Some(vfr_id.as_str()))
        {
            dependents.push(entry.clone());
        }
    }

    (
        StatusCode::OK,
        Json(json!({
            "schema": "vela.depends-on.v0.1",
            "target_vfr_id": vfr_id,
            "dependents": dependents,
            "count": dependents.len(),
        })),
    )
        .into_response()
}

/// Single-finding detail page. Fetches the cached frontier (same one
/// the entry detail page uses), looks up the finding by id, renders
/// claim + conditions + evidence + history in workbench finding-pattern.
/// JSON path returns the finding bundle as-is.
async fn get_finding(
    State(state): State<AppState>,
    Path((vfr_id, vf_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    // Find the entry to get the locator.
    let entry = state.db.get_live_entry(&vfr_id).await;
    let entry = match entry {
        Ok(Some(v)) => v,
        Ok(None) => {
            if wants_html(&headers) {
                return (
                    StatusCode::NOT_FOUND,
                    Html(render_not_found_html(&state.urls, &vfr_id)),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };

    let signed_at = entry
        .get("signed_publish_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let frontier = load_substrate(&state, &vfr_id, signed_at).await;

    let Some(project) = frontier else {
        if wants_html(&headers) {
            return Html(render_finding_unavailable_html(
                &state.urls,
                &vfr_id,
                &vf_id,
            ))
            .into_response();
        }
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(error_body(
                "UNAVAILABLE",
                "frontier projection unavailable; pull via the CLI to inspect",
            )),
        )
            .into_response();
    };

    let Some(bundle) = project.findings.iter().find(|b| b.id == vf_id) else {
        if wants_html(&headers) {
            return (
                StatusCode::NOT_FOUND,
                Html(render_finding_not_found_html(&state.urls, &vfr_id, &vf_id)),
            )
                .into_response();
        }
        return (
            StatusCode::NOT_FOUND,
            Json(error_body("NOT_FOUND", format!("{vf_id} not in {vfr_id}"))),
        )
            .into_response();
    };

    if wants_html(&headers) {
        // Citation anchors: the snapshot hash from the registry row and
        // the ingest cursor from the git-remote registration, when one
        // exists. Both are content addresses — the citation pins to
        // them, not to this page.
        let snapshot_hash = entry
            .get("latest_snapshot_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let ingest_commit = match state.db.get_git_remote(&vfr_id).await {
            Ok(Some(rec)) => rec
                .get("last_ingested_commit")
                .and_then(|v| v.as_str())
                .map(String::from),
            _ => None,
        };
        Html(render_finding_html(
            &state.urls,
            &vfr_id,
            &project,
            bundle,
            &snapshot_hash,
            ingest_commit.as_deref(),
        ))
        .into_response()
    } else {
        match serde_json::to_value(bundle) {
            Ok(v) => (StatusCode::OK, Json(v)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("serialize: {e}"))),
            )
                .into_response(),
        }
    }
}

/// Pack review page: one released Scientific Diff Pack (`vsd_*`) on one
/// frontier, read end-to-end — release metadata, the human verdict when
/// present, and the member proposals with their Evidence Diff links.
/// HTML for browsers; `Accept: application/json` returns the replayed
/// `ReleasedDiffPackRecord` as-is (same dual-mode contract as the
/// finding page). The record is pure replay state from the canonical
/// event log — this page renders it, it never adjudicates it.
async fn get_pack_review(
    State(state): State<AppState>,
    Path((vfr_id, pack_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let entry = match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            if wants_html(&headers) {
                return (
                    StatusCode::NOT_FOUND,
                    Html(render_not_found_html(&state.urls, &vfr_id)),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };

    let signed_at = entry
        .get("signed_publish_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(project) = load_substrate(&state, &vfr_id, signed_at).await else {
        if wants_html(&headers) {
            return Html(render_pack_unavailable_html(&state.urls, &vfr_id, &pack_id))
                .into_response();
        }
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(error_body(
                "UNAVAILABLE",
                "frontier projection unavailable; pull via the CLI to inspect",
            )),
        )
            .into_response();
    };

    let Some(rec) = project
        .released_diff_packs
        .iter()
        .find(|r| r.pack_id == pack_id)
    else {
        if wants_html(&headers) {
            return (
                StatusCode::NOT_FOUND,
                Html(render_pack_not_found_html(&state.urls, &vfr_id, &pack_id)),
            )
                .into_response();
        }
        return (
            StatusCode::NOT_FOUND,
            Json(error_body(
                "NOT_FOUND",
                format!("{pack_id} not released on {vfr_id}"),
            )),
        )
            .into_response();
    };

    if wants_html(&headers) {
        Html(render_pack_html(&state.urls, &vfr_id, &project, rec)).into_response()
    } else {
        match serde_json::to_value(rec) {
            Ok(v) => (StatusCode::OK, Json(v)).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("serialize: {e}"))),
            )
                .into_response(),
        }
    }
}

/// The "verify this yourself" page: the exact copy-paste sequence that
/// re-derives this frontier's state locally — clone the registered
/// repo, replay the event log under `vela check --strict`, re-check
/// every witness with the frozen verifiers under `vela reproduce`.
/// The hub is an index; nothing on this page requires trusting it.
async fn get_reproduce(State(state): State<AppState>, Path(vfr_id): Path<String>) -> Response {
    let remote = match state.db.get_git_remote(&vfr_id).await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };

    let Some(rec) = remote else {
        // No registered remote. Say so honestly — but only 404 when the
        // frontier itself is unknown to this hub.
        return match state.db.get_live_entry(&vfr_id).await {
            Ok(Some(_)) => {
                Html(render_reproduce_no_remote_html(&state.urls, &vfr_id)).into_response()
            }
            Ok(None) => (
                StatusCode::NOT_FOUND,
                Html(render_not_found_html(&state.urls, &vfr_id)),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response(),
        };
    };

    // `get_git_remote` does not carry the subdir; the ingest-targets
    // table does. One extra tiny-table read, main.rs-local.
    let git_subdir = match state.db.git_ingest_targets().await {
        Ok(rows) => rows
            .into_iter()
            .find(|r| r.0 == vfr_id)
            .map(|r| r.3)
            .unwrap_or_default(),
        Err(_) => String::new(),
    };

    Html(render_reproduce_html(
        &state.urls,
        &vfr_id,
        &rec,
        &git_subdir,
    ))
    .into_response()
}

/// `GET /entries/{vfr_id}/findings/{vf_id}/context`
///
/// Returns a *project-shaped slice* scoped to one finding: the target finding
/// plus the source findings that link into it (so the web's incoming-link scan
/// resolves), with evidence atoms / events / proposals / verifier attachments /
/// statement attestations filtered to the target, and the small shared metadata
/// (sources, actors, frontier meta, proof_state) carried whole. The finding page
/// consumes this in hub mode instead of pulling the whole multi-MB snapshot per
/// request (the erdos snapshot is ~15 MB; a finding page needs a few KB of it).
/// The shape is a strict subset of the snapshot `Project`, so the same web-side
/// normalizer applies unchanged. Filtering is done on the serialized JSON using
/// the exact field names the web consumes, so this never couples to the Rust
/// struct layout.
async fn get_finding_context(
    State(state): State<AppState>,
    Path((vfr_id, vf_id)): Path<(String, String)>,
) -> Response {
    let entry = match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };
    let signed_at = entry
        .get("signed_publish_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(project) = load_substrate(&state, &vfr_id, signed_at).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(error_body(
                "UNAVAILABLE",
                "frontier projection unavailable; pull via the CLI to inspect",
            )),
        )
            .into_response();
    };

    let full = match serde_json::to_value(&*project) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("serialize: {e}"))),
            )
                .into_response();
        }
    };
    let obj = full.as_object().cloned().unwrap_or_default();
    let arr = |k: &str| -> Vec<serde_json::Value> {
        obj.get(k)
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
    };

    let findings = arr("findings");
    let Some(target) = findings
        .iter()
        .find(|f| f.get("id").and_then(|v| v.as_str()) == Some(vf_id.as_str()))
        .cloned()
    else {
        return (
            StatusCode::NOT_FOUND,
            Json(error_body("NOT_FOUND", format!("{vf_id} not in {vfr_id}"))),
        )
            .into_response();
    };

    // Target first, then the source findings whose links point at it, so the
    // web's `bundle.findings.flatMap(... link.target === id)` incoming-link scan
    // resolves against the slice without shipping every finding.
    let mut sliced_findings = vec![target];
    for f in &findings {
        if f.get("id").and_then(|v| v.as_str()) == Some(vf_id.as_str()) {
            continue;
        }
        let links_in = f
            .get("links")
            .and_then(|v| v.as_array())
            .map(|ls| {
                ls.iter()
                    .any(|l| l.get("target").and_then(|v| v.as_str()) == Some(vf_id.as_str()))
            })
            .unwrap_or(false);
        if links_in {
            sliced_findings.push(f.clone());
        }
    }

    let by_finding_id = |k: &str| -> Vec<serde_json::Value> {
        arr(k)
            .into_iter()
            .filter(|a| a.get("finding_id").and_then(|v| v.as_str()) == Some(vf_id.as_str()))
            .collect()
    };
    let by_target_id = |k: &str| -> Vec<serde_json::Value> {
        arr(k)
            .into_iter()
            .filter(|a| {
                a.get("target")
                    .and_then(|t| t.get("id"))
                    .and_then(|v| v.as_str())
                    == Some(vf_id.as_str())
            })
            .collect()
    };
    let by_target_str = |k: &str| -> Vec<serde_json::Value> {
        arr(k)
            .into_iter()
            .filter(|a| a.get("target").and_then(|v| v.as_str()) == Some(vf_id.as_str()))
            .collect()
    };

    let mut slice = serde_json::Map::new();
    // Envelope fields the web normalizer reads (frontier meta + proof state).
    for k in [
        "vela_version",
        "schema",
        "frontier_id",
        "frontier",
        "stats",
        "proof_state",
    ] {
        if let Some(v) = obj.get(k) {
            slice.insert(k.to_string(), v.clone());
        }
    }
    slice.insert("findings".into(), serde_json::Value::Array(sliced_findings));
    slice.insert(
        "evidence_atoms".into(),
        serde_json::Value::Array(by_finding_id("evidence_atoms")),
    );
    slice.insert(
        "events".into(),
        serde_json::Value::Array(by_target_id("events")),
    );
    slice.insert(
        "proposals".into(),
        serde_json::Value::Array(by_target_id("proposals")),
    );
    slice.insert(
        "verifier_attachments".into(),
        serde_json::Value::Array(by_target_str("verifier_attachments")),
    );
    slice.insert(
        "statement_attestations".into(),
        serde_json::Value::Array(by_target_str("statement_attestations")),
    );
    // Small shared metadata, carried whole (bibliography + actor key map).
    slice.insert("sources".into(), serde_json::Value::Array(arr("sources")));
    slice.insert("actors".into(), serde_json::Value::Array(arr("actors")));

    (StatusCode::OK, Json(serde_json::Value::Object(slice))).into_response()
}

/// `GET /entries/{vfr_id}/findings/{vf_id}/gate-status`
///
/// Returns the **derived** trust-gate status for one finding — never stored,
/// always recomputed from the finding's current claim and its verifier
/// attachments (doctrine: status is a read-time projection). The UI uses this
/// to render verification as a material state without re-deriving the gate.
///
/// The response separates two things the campaign deliberately keeps apart:
///   - `machine_sealed` — the gate says `verified` (G1–G4: ≥2 independent,
///     matched, adversarially-probed attachments). This is the gold seam.
///   - `reviewer_accepted` — a human review verdict of `accepted`. A finding
///     can be reviewer-accepted yet NOT machine-sealed. `reviewer-accepted ≠
///     machine-sealed`; the UI must not conflate them.
/// `distinct_verifier_actors` / `distinct_methods` expose the independence
/// truth directly (independence is by distinct method/solver, not by count of
/// attachments), so the UI can be honest about thin evidence.
async fn get_finding_gate_status(
    State(state): State<AppState>,
    Path((vfr_id, vf_id)): Path<(String, String)>,
) -> Response {
    let entry = match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };

    let signed_at = entry
        .get("signed_publish_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(project) = load_substrate(&state, &vfr_id, signed_at).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(error_body(
                "UNAVAILABLE",
                "frontier projection unavailable; pull via the CLI to inspect",
            )),
        )
            .into_response();
    };

    match finding_gate_status_body(
        &project.findings,
        &project.verifier_attachments,
        &vfr_id,
        &vf_id,
    ) {
        Some(body) => (StatusCode::OK, Json(body)).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(error_body("NOT_FOUND", format!("{vf_id} not in {vfr_id}"))),
        )
            .into_response(),
    }
}

/// `GET /entries/{vfr_id}/gate-status`
///
/// The frontier-wide projection: one gate-status row per finding, so a list
/// view renders the whole frontier's seal state in a single request instead
/// of N. Same derivation as the per-finding endpoint (status never stored).
async fn get_frontier_gate_status(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
) -> Response {
    let entry = match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };
    let signed_at = entry
        .get("signed_publish_at")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let Some(project) = load_substrate(&state, &vfr_id, signed_at).await else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(error_body(
                "UNAVAILABLE",
                "frontier projection unavailable; pull via the CLI to inspect",
            )),
        )
            .into_response();
    };

    // Group attachments by target ONCE (O(attachments)), so each finding's
    // derivation is an O(1) lookup. The earlier per-finding re-scan was
    // O(findings × attachments) + O(findings²) on the bundle lookup — quadratic
    // on large frontiers (e.g. 5.5k findings).
    use std::collections::HashMap;
    type Att = vela_protocol::verifier_attachment::VerifierAttachment;
    let mut by_target: HashMap<&str, Vec<Att>> = HashMap::new();
    for a in &project.verifier_attachments {
        by_target
            .entry(a.target.as_str())
            .or_default()
            .push(a.clone());
    }
    let empty: Vec<Att> = Vec::new();
    let rows: Vec<Value> = project
        .findings
        .iter()
        .map(|b| gate_status_value(b, by_target.get(b.id.as_str()).unwrap_or(&empty), &vfr_id))
        .collect();
    let sealed = rows
        .iter()
        .filter(|r| r["machine_sealed"] == json!(true))
        .count();
    let body = json!({
        "schema": "vela.gate-status-page.v0.1",
        "vfr_id": vfr_id,
        "count": rows.len(),
        "machine_sealed_count": sealed,
        "findings": rows,
    });
    (StatusCode::OK, Json(body)).into_response()
}

/// Pure projection: the gate-status response body for one finding, or `None`
/// if the finding is absent. Takes just the slices it reads so the
/// seal-vs-review distinction is unit-testable without a server, DB, or a
/// fully-constructed `Project`.
fn finding_gate_status_body(
    findings: &[vela_protocol::bundle::FindingBundle],
    attachments_all: &[vela_protocol::verifier_attachment::VerifierAttachment],
    vfr_id: &str,
    vf_id: &str,
) -> Option<Value> {
    let bundle = findings.iter().find(|b| b.id == vf_id)?;
    // Single finding: filtering the attachments once is O(attachments). The
    // frontier-wide path must NOT call this in a loop (that is O(findings ×
    // attachments)); it groups attachments by target once and uses
    // `gate_status_value` directly.
    let attachments: Vec<_> = attachments_all
        .iter()
        .filter(|a| a.target == vf_id)
        .cloned()
        .collect();
    Some(gate_status_value(bundle, &attachments, vfr_id))
}

/// Core projection: the gate-status body for one finding given its bundle and
/// the attachments ALREADY filtered to it. No lookups or scans here, so the
/// caller controls the cost — the frontier-wide endpoint resolves attachments
/// once via a by-target map and calls this O(1) per finding.
fn gate_status_value(
    bundle: &vela_protocol::bundle::FindingBundle,
    attachments: &[vela_protocol::verifier_attachment::VerifierAttachment],
    vfr_id: &str,
) -> Value {
    use std::collections::BTreeSet;
    use vela_protocol::bundle::ReviewState;
    use vela_protocol::verifier_attachment::{GateStatus, claim_digest, derive_gate_status};

    let digest = claim_digest(&bundle.assertion.text);
    let outcome = derive_gate_status(&digest, attachments);

    let distinct_actors: BTreeSet<&str> = attachments
        .iter()
        .map(|a| a.verifier_actor.as_str())
        .collect();
    let distinct_methods: BTreeSet<&str> = attachments
        .iter()
        .map(|a| a.verifier_method.as_str())
        .collect();
    let reviewer_accepted = matches!(bundle.flags.review_state, Some(ReviewState::Accepted));
    let machine_sealed = outcome.status == GateStatus::Verified;

    json!({
        "schema": "vela.gate-status.v0.1",
        "vfr_id": vfr_id,
        "vf_id": bundle.id,
        "claim_digest": digest,
        // Machine seal (the gold seam): derived, fail-closed.
        "gate_status": outcome.status,
        "machine_sealed": machine_sealed,
        "reasons": outcome.reasons,
        // Human review verdict — distinct from the machine seal.
        "reviewer_accepted": reviewer_accepted,
        "review_state": bundle.flags.review_state,
        // Independence truth, exposed so the UI cannot overstate thin evidence.
        "attachment_count": attachments.len(),
        "distinct_verifier_actors": distinct_actors.len(),
        "distinct_methods": distinct_methods.len(),
        // Stone seam: superseded by a newer content-addressed finding.
        "superseded": bundle.flags.superseded,
    })
}

// ─── Proof packet ─────────────────────────────────────────────────────
//
// `vela frontier export --packet` produces a directory of canonical
// proof artifacts (manifest.json + packet.lock.json + proof-trace.json
// + findings/full.json + sources/source-registry.json + ...). The hub
// surfaces that directory inline so a skeptic can see the seam: signer
// hashes, included-files sha256 table, replay status, schema version.
//
// Resolution: env VELA_PROOF_PACKET_DIR points at either
//   (a) a single packet directory containing manifest.json (single-
//       packet demo deploy — handler ignores vfr_id and serves it for
//       every entry), or
//   (b) a directory of packet directories named by vfr_id (multi-
//       packet deploy, future).
// If the env is unset OR the path doesn't resolve, the route renders
// an honest "no packet has been generated for this entry yet" page
// with the CLI invocation that would generate one.

fn resolve_packet_dir(vfr_id: &str) -> Option<std::path::PathBuf> {
    let base = std::env::var("VELA_PROOF_PACKET_DIR").ok()?;
    let base_path = std::path::PathBuf::from(&base);
    if !base_path.is_dir() {
        return None;
    }
    // Multi-packet deploy: prefer ${base}/${vfr_id}.
    let by_id = base_path.join(vfr_id);
    if by_id.join("manifest.json").is_file() {
        return Some(by_id);
    }
    // Single-packet deploy: serve ${base} itself if it has a manifest.
    if base_path.join("manifest.json").is_file() {
        return Some(base_path);
    }
    None
}

fn read_packet_json(dir: &std::path::Path, name: &str) -> Option<Value> {
    let raw = std::fs::read_to_string(dir.join(name)).ok()?;
    serde_json::from_str(&raw).ok()
}

async fn get_proof_packet(State(state): State<AppState>, Path(vfr_id): Path<String>) -> Response {
    let dir = match resolve_packet_dir(&vfr_id) {
        Some(d) => d,
        None => {
            return Html(render_no_packet_html(&state.urls, &vfr_id)).into_response();
        }
    };
    let manifest = match read_packet_json(&dir, "manifest.json") {
        Some(v) => v,
        None => return Html(render_no_packet_html(&state.urls, &vfr_id)).into_response(),
    };
    let proof_trace = read_packet_json(&dir, "proof-trace.json");
    let lock = read_packet_json(&dir, "packet.lock.json");
    Html(render_proof_packet_html(
        &state.urls,
        &vfr_id,
        &dir,
        &manifest,
        proof_trace.as_ref(),
        lock.as_ref(),
    ))
    .into_response()
}

async fn get_proof_packet_download(
    State(_state): State<AppState>,
    Path(vfr_id): Path<String>,
) -> Response {
    let dir = match resolve_packet_dir(&vfr_id) {
        Some(d) => d,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(error_body(
                    "NOT_FOUND",
                    "no proof packet available for this entry",
                )),
            )
                .into_response();
        }
    };
    // Build the tar.gz in memory. Packets are a few MB; this is fine.
    let mut buf: Vec<u8> = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut buf, flate2::Compression::default());
        let mut tar = tar::Builder::new(enc);
        let label = format!("{vfr_id}-proof-packet");
        if let Err(e) = tar.append_dir_all(&label, &dir) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("tar: {e}"))),
            )
                .into_response();
        }
        if let Err(e) = tar.into_inner().and_then(|enc| enc.finish()) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("gz: {e}"))),
            )
                .into_response();
        }
    }
    let filename = format!("{vfr_id}-proof-packet.tar.gz");
    (
        StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/gzip".to_string(),
            ),
            (
                axum::http::header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        buf,
    )
        .into_response()
}

/// Return the materialized frontier state for `vfr_id`.
///
/// The event/projection tables are the source of truth after the
/// event-first cutover. Callers that explicitly pass `?redirect=cdn`
/// can still receive a 302 to an immutable snapshot export when one is
/// available, but old `network_locator` URLs are never fetched on the
/// live read path.
async fn get_entry_snapshot(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
    Query(params): Query<SnapshotQuery>,
) -> Response {
    let row = match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            if let Ok(Some(audit)) = state.db.latest_audit_status(&vfr_id).await
                && audit.status == "failed"
            {
                return (
                    StatusCode::FAILED_DEPENDENCY,
                    Json(json!({
                        "ok": false,
                        "status": "unavailable",
                        "vfr_id": vfr_id,
                        "error": {"kind": "UNAVAILABLE", "message": audit.error.unwrap_or_else(|| "frontier failed verification".to_string())},
                        "authority_mode": audit.authority_mode,
                    })),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    };

    let snap_hash = row
        .get("latest_snapshot_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if snap_hash.is_empty() {
        return (
            StatusCode::FAILED_DEPENDENCY,
            Json(error_body(
                "UNAVAILABLE",
                format!("registry entry for {vfr_id} is missing latest_snapshot_hash"),
            )),
        )
            .into_response();
    }

    // Optional export optimization: callers that explicitly ask for
    // the CDN path can still get the immutable object-storage redirect.
    if params.redirect.as_deref() == Some("cdn")
        && let Ok(Some(meta)) = state.db.get_snapshot_meta(snap_hash).await
        && !meta.blob_url.is_empty()
    {
        let mut resp = (
            StatusCode::FOUND,
            [(axum::http::header::LOCATION, meta.blob_url.as_str())],
            Json(json!({
                "snapshot_hash": snap_hash,
                "blob_url": meta.blob_url,
                "size_bytes": meta.size_bytes,
                "schema_version": meta.schema_version,
                "content_type": meta.content_type,
            })),
        )
            .into_response();
        resp.headers_mut().insert(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static(
                "public, max-age=300, stale-while-revalidate=3600",
            ),
        );
        if let Ok(etag) = axum::http::HeaderValue::from_str(&format!("\"{snap_hash}\"")) {
            resp.headers_mut().insert(axum::http::header::ETAG, etag);
        }
        return resp;
    }

    match state.db.get_materialized_project(&vfr_id).await {
        Ok(Some(project)) => {
            let value = serde_json::to_value(&project).unwrap_or(Value::Null);
            let mut resp = (StatusCode::OK, Json(value)).into_response();
            resp.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static(
                    "public, max-age=60, stale-while-revalidate=300",
                ),
            );
            if let Ok(etag) = axum::http::HeaderValue::from_str(&format!("\"{snap_hash}\"")) {
                resp.headers_mut().insert(axum::http::header::ETAG, etag);
            }
            return resp;
        }
        Ok(None) => {}
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body(
                    "INTERNAL",
                    format!("event-first snapshot read: {e}"),
                )),
            )
                .into_response();
        }
    }

    (
        StatusCode::FAILED_DEPENDENCY,
        Json(json!({
            "ok": false,
            "status": "unavailable",
            "vfr_id": vfr_id,
            "snapshot_hash": snap_hash,
            "error": {"kind": "UNAVAILABLE", "message": "frontier projection unavailable"},
        })),
    )
        .into_response()
}

async fn get_entry_events(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
    Query(raw): Query<HashMap<String, String>>,
) -> Response {
    let params = match parse_event_query(&raw, &["cursor", "limit", "kind", "target"]) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Ok(Some(audit)) = state.db.latest_audit_status(&vfr_id).await
                && audit.status == "failed"
            {
                return (
                    StatusCode::FAILED_DEPENDENCY,
                    Json(json!({
                        "ok": false,
                        "status": "unavailable",
                        "vfr_id": vfr_id,
                        "error": {"kind": "UNAVAILABLE", "message": audit.error.unwrap_or_else(|| "frontier failed verification".to_string())},
                        "authority_mode": audit.authority_mode,
                    })),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    }

    let limit = params.limit.unwrap_or(100);
    match state
        .db
        .event_page(
            &vfr_id,
            params.cursor.as_deref(),
            limit,
            params.kind.as_deref(),
            params.target.as_deref(),
        )
        .await
    {
        Ok(page) => (
            StatusCode::OK,
            Json(json!({
                "schema": "vela.events-page.v0.1",
                "vfr_id": vfr_id,
                "events": page.events,
                "count": page.events.len(),
                "next_cursor": page.next_cursor,
                "log_total": page.log_total,
            })),
        )
            .into_response(),
        Err(e) if e.starts_with("cursor_not_found:") => (
            StatusCode::BAD_REQUEST,
            Json(error_body(
                "INVALID_ARG",
                e.trim_start_matches("cursor_not_found: "),
            )),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(error_body("INTERNAL", format!("events query: {e}"))),
        )
            .into_response(),
    }
}

// ─── Public-write boundary (v0.128) ───────────────────────────────────
//
// Two endpoints close the gap publish_entry leaves open. POST
// /proposals mirrors publish_entry: open submission, the
// signature is the bind. POST /proposals/.../accept is the
// access-controlled reviewer write — the signer MUST resolve to a
// registered, non-revoked actor on the frontier carrying reviewer
// authority. Both carry the signature in headers (so the body stays the
// canonical preimage bytes), both are rate-limited and body-size-capped,
// and the accept runs the strict Engine gate with force HARD-WIRED off.

async fn get_entry_events_stream(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
    Query(raw): Query<HashMap<String, String>>,
) -> Response {
    let params = match parse_event_query(&raw, &["cursor", "kind", "target"]) {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    match state.db.get_live_entry(&vfr_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            if let Ok(Some(audit)) = state.db.latest_audit_status(&vfr_id).await
                && audit.status == "failed"
            {
                return (
                    StatusCode::FAILED_DEPENDENCY,
                    Json(json!({
                        "ok": false,
                        "status": "unavailable",
                        "vfr_id": vfr_id,
                        "error": {"kind": "UNAVAILABLE", "message": audit.error.unwrap_or_else(|| "frontier failed verification".to_string())},
                        "authority_mode": audit.authority_mode,
                    })),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(error_body("NOT_FOUND", format!("{vfr_id} not found"))),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(error_body("INTERNAL", format!("query: {e}"))),
            )
                .into_response();
        }
    }

    let stream_state = state.clone();
    let stream_vfr = vfr_id.clone();
    let kind = params.kind.clone();
    let target = params.target.clone();
    let mut cursor = params.cursor.clone();
    let stream = async_stream::stream! {
        loop {
            match stream_state
                .db
                .event_page(
                    &stream_vfr,
                    cursor.as_deref(),
                    100,
                    kind.as_deref(),
                    target.as_deref(),
                )
                .await
            {
                Ok(page) if !page.events.is_empty() => {
                    for raw in page.events {
                        let id = raw
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("event")
                            .to_string();
                        cursor = Some(id.clone());
                        yield Ok::<Event, std::convert::Infallible>(
                            Event::default()
                                .event("event")
                                .id(id)
                                .data(raw.to_string())
                        );
                    }
                }
                Ok(_) => {
                    let heartbeat = json!({
                        "vfr_id": stream_vfr,
                        "cursor": cursor,
                        "status": "idle",
                    });
                    yield Ok::<Event, std::convert::Infallible>(
                        Event::default()
                            .event("heartbeat")
                            .data(heartbeat.to_string())
                    );
                    tokio::time::sleep(Duration::from_secs(15)).await;
                }
                Err(e) => {
                    let payload = json!({
                        "vfr_id": stream_vfr,
                        "error": {"kind": "INTERNAL", "message": e},
                    });
                    yield Ok::<Event, std::convert::Infallible>(
                        Event::default()
                            .event("error")
                            .data(payload.to_string())
                    );
                    break;
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ── HTML rendering ───────────────────────────────────────────────────
//
// The hub renders against the canonical Vela design system. The same
// `tokens.css` and `workbench.css` files that drive `web/index.html`
// are baked into the binary via `include_str!` and served at
// `/static/...` so the marketing site and the hub share one source of
// truth. Hub-specific page styles are kept in a small inline block.

// Self-hosted latin subsets (OFL; web/fonts/LICENSE.md) — no third-party
// font CDN. The faces match the frontier kit and the production app.
#[cfg(test)]
mod gate_status_tests {
    use super::finding_gate_status_body;
    use vela_protocol::bundle::FindingBundle;

    // A complete-but-minimal finding, reviewer-accepted (flags.review_state),
    // carrying ZERO verifier attachments. This is the exact shape the Lane C
    // design hinges on: a human said "accepted" but no machine seal exists.
    const REVIEWER_ACCEPTED_FINDING: &str = r#"{
        "id": "vf_test0000000001",
        "version": 1,
        "assertion": {
            "text": "a Sidon set of size 33 in {0,1}^8",
            "type": "mechanism",
            "entities": [],
            "relation": null,
            "direction": null
        },
        "evidence": {
            "type": "computational",
            "model_system": "search",
            "species": null,
            "method": "exhaustive enumeration",
            "sample_size": null,
            "effect_size": null,
            "p_value": null,
            "replicated": false,
            "replication_count": null,
            "evidence_spans": []
        },
        "conditions": {
            "text": "n/a",
            "species_verified": [],
            "species_unverified": [],
            "in_vitro": false,
            "in_vivo": false,
            "human_data": false,
            "clinical_trial": false
        },
        "confidence": {
            "kind": "frontier_epistemic",
            "score": 0.7,
            "method": "llm_initial",
            "basis": "test",
            "extraction_confidence": 0.9
        },
        "provenance": {
            "source_type": "computation",
            "title": "test"
        },
        "flags": {
            "review_state": "accepted"
        },
        "created": "2026-06-07T00:00:00Z"
    }"#;

    #[test]
    fn reviewer_accepted_is_not_machine_sealed() {
        let f: FindingBundle =
            serde_json::from_str(REVIEWER_ACCEPTED_FINDING).expect("deserialize test finding");
        let findings = vec![f];
        let body = finding_gate_status_body(&findings, &[], "vfr_test", "vf_test0000000001")
            .expect("finding present");

        // The keystone distinction: reviewer-accepted, but NO machine seal.
        assert_eq!(body["reviewer_accepted"], serde_json::json!(true));
        assert_eq!(body["machine_sealed"], serde_json::json!(false));
        assert_eq!(body["gate_status"], serde_json::json!("needs_verification"));
        // Zero attachments -> no independence to overstate.
        assert_eq!(body["attachment_count"], serde_json::json!(0));
        assert_eq!(body["distinct_verifier_actors"], serde_json::json!(0));
        assert_eq!(body["distinct_methods"], serde_json::json!(0));
        assert_eq!(body["superseded"], serde_json::json!(false));
        assert_eq!(body["schema"], serde_json::json!("vela.gate-status.v0.1"));
    }

    #[test]
    fn absent_finding_yields_none() {
        let f: FindingBundle =
            serde_json::from_str(REVIEWER_ACCEPTED_FINDING).expect("deserialize test finding");
        let findings = vec![f];
        assert!(
            finding_gate_status_body(&findings, &[], "vfr_test", "vf_does_not_exist").is_none(),
            "absent finding must return None (404), not a body"
        );
    }
}

#[cfg(test)]
mod webhook_signature_tests {
    use super::github_signature_ok;

    #[test]
    fn valid_signature_verifies_and_wrong_ones_do_not() {
        // hmac-sha256("secret", "payload") — precomputable with any HMAC
        // implementation; pinned here so the header format is exercised
        // end-to-end (sha256= prefix + lowercase hex).
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(b"payload");
        let good = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

        assert!(github_signature_ok("secret", b"payload", &good));
        assert!(!github_signature_ok("secret", b"tampered", &good));
        assert!(!github_signature_ok("wrong-secret", b"payload", &good));
        assert!(!github_signature_ok(
            "secret",
            b"payload",
            "sha256=deadbeef"
        ));
        assert!(!github_signature_ok("secret", b"payload", "no-prefix"));
        assert!(!github_signature_ok("secret", b"payload", ""));
    }
}
