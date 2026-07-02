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
            "error": "stateless MCP endpoint: POST a JSON-RPC message; no server-initiated stream is offered"
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
            Json(serde_json::json!({
                "error": "webhook lane not configured (set VELA_HUB_WEBHOOK_SECRET)"
            })),
        );
    };
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !github_signature_ok(&secret, &body, signature) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid or missing X-Hub-Signature-256"})),
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

#[derive(Debug, Deserialize)]
struct EventQuery {
    since: Option<String>,
    limit: Option<usize>,
    kind: Option<String>,
    target: Option<String>,
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
                "error": e,
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
                Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({ "error": "frontier not found", "vfr_id": vfr_id })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response();
        }
    };
    let pres = match live_presentation(&project) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": format!("not a live Sidon frontier: {e}"),
                    "vfr_id": vfr_id,
                })),
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
            Json(json!({ "error": e })),
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
                Json(json!({ "error": "frontier not found", "vfr_id": vfr_id })),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": e })),
            )
                .into_response();
        }
    };
    let pres = match live_presentation(&project) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(json!({
                    "error": format!("not a live Sidon frontier: {e}"),
                    "vfr_id": vfr_id,
                })),
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
                Json(json!({ "error": e })),
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
                        "error": audit.error.unwrap_or_else(|| "frontier failed verification".to_string()),
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
                    Json(json!({"error": format!("{vfr_id} not found")})),
                )
                    .into_response()
            }
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({"ok": false, "error": format!("{vfr_id} not found on this hub")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": format!("project query: {e}")})),
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
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": e})),
        )
            .into_response(),
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
            Json(json!({"error": format!("{vfr_id} not found")})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("summary: {e}")})),
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
                Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({"error": format!("{vfr_id} not found")})),
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
            Json(json!({"error": format!("{vfr_id} has no registered git remote")})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({"error": format!("registration parse: {e}")})),
            )
                .into_response();
        }
    };
    if rec.vfr_id != vfr_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "registration vfr_id does not match the path"})),
        )
            .into_response();
    }
    match verify_git_remote(&rec) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "registration signature does not verify"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": format!("registration: {e}")})),
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
                Json(json!({"error": "signer is not the frontier's effective owner"})),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("owner lookup: {e}")})),
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
            Json(json!({"error": format!("store: {e}")})),
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
            Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({"ok": false, "error": "blob id must be a 64-char sha256 hex string"})),
        )
            .into_response();
    }
    let Some(storage) = &state.storage else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ok": false, "error": "hub has no object storage configured"})),
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
            Json(json!({"ok": false, "error": format!("blob {hash} not found")})),
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
            Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({"error": format!("index: {e}")})),
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
            Json(json!({"error": format!("search: {e}")})),
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
        "04 · Search",
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
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({"error": format!("objects: {e}")})),
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
            Json(json!({"error": format!("{object_id} not found in {vfr_id}")})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("object: {e}")})),
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
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
            )
                .into_response();
        }
    }
    let leaves = match log_leaves(&state, &vfr_id).await {
        Ok(l) => l,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
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
                Json(json!({"error": format!("events: {e}")})),
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
                    Json(json!({"error": format!("event parse: {e}")})),
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
                Json(json!({"error": format!("event {event_id} not in {vfr_id}")})),
            )
                .into_response();
        }
    };
    let proof = match vela_protocol::merkle::inclusion_proof(&leaves, m) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "proof generation failed"})),
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
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response();
        }
    };
    let total = leaves.len();
    let m = q.first;
    let n = q.second.unwrap_or(total);
    if m == 0 || m > n || n > total {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": format!("require 1 <= first <= second <= tree_size; got first={m}, second={n}, tree_size={total}"),
            })),
        )
            .into_response();
    }
    let proof = match vela_protocol::merkle::consistency_proof(&leaves[..n], m) {
        Some(p) => p,
        None => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "consistency proof generation failed"})),
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
            Json(json!({"error": "pack_id must start with `vsd_`"})),
        )
            .into_response();
    }
    match state.db.get_diff_pack(&pack_id).await {
        Ok(Some(value)) => (StatusCode::OK, Json(value)).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": format!("{pack_id} not found on this hub"),
                "hub_note": "v0.201: A pack lands here when a `diff_pack.released` event has been applied on a frontier this hub mirrors.",
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({"error": "frontier projection unavailable; pull via the CLI to inspect"})),
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
            Json(json!({"error": format!("{vf_id} not in {vfr_id}")})),
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
                Json(json!({"error": format!("serialize: {e}")})),
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
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({"error": "frontier projection unavailable; pull via the CLI to inspect"})),
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
            Json(json!({"error": format!("{pack_id} not released on {vfr_id}")})),
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
                Json(json!({"error": format!("serialize: {e}")})),
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
                Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({"error": format!("query: {e}")})),
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
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({"error": "frontier projection unavailable; pull via the CLI to inspect"})),
        )
            .into_response();
    };

    let full = match serde_json::to_value(&*project) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("serialize: {e}")})),
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
            Json(json!({"error": format!("{vf_id} not in {vfr_id}")})),
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
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({"error": "frontier projection unavailable; pull via the CLI to inspect"})),
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
            Json(json!({"error": format!("{vf_id} not in {vfr_id}")})),
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
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({"error": "frontier projection unavailable; pull via the CLI to inspect"})),
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
                Json(json!({"error": "no proof packet available for this entry"})),
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
                Json(json!({"error": format!("tar: {e}")})),
            )
                .into_response();
        }
        if let Err(e) = tar.into_inner().and_then(|enc| enc.finish()) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("gz: {e}")})),
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
                        "error": audit.error.unwrap_or_else(|| "frontier failed verification".to_string()),
                        "authority_mode": audit.authority_mode,
                    })),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
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
            Json(json!({
                "error": "registry entry missing latest_snapshot_hash",
                "vfr_id": vfr_id,
            })),
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
                Json(json!({"error": format!("event-first snapshot read: {e}")})),
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
            "error": "frontier projection unavailable",
        })),
    )
        .into_response()
}

async fn get_entry_events(
    State(state): State<AppState>,
    Path(vfr_id): Path<String>,
    Query(params): Query<EventQuery>,
) -> Response {
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
                        "error": audit.error.unwrap_or_else(|| "frontier failed verification".to_string()),
                        "authority_mode": audit.authority_mode,
                    })),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
            )
                .into_response();
        }
    }

    let limit = params.limit.unwrap_or(100);
    match state
        .db
        .event_page(
            &vfr_id,
            params.since.as_deref(),
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
            Json(json!({"error": e.trim_start_matches("cursor_not_found: ")})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": format!("events query: {e}")})),
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
    Query(params): Query<EventQuery>,
) -> Response {
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
                        "error": audit.error.unwrap_or_else(|| "frontier failed verification".to_string()),
                        "authority_mode": audit.authority_mode,
                    })),
                )
                    .into_response();
            }
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("{vfr_id} not found")})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": format!("query: {e}")})),
            )
                .into_response();
        }
    }

    let stream_state = state.clone();
    let stream_vfr = vfr_id.clone();
    let kind = params.kind.clone();
    let target = params.target.clone();
    let mut cursor = params.since.clone();
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
                        "error": e,
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
const FONT_LINK: &str = r#"<link rel="preload" href="/static/fonts/inter-latin-400-normal.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="/static/fonts/source-serif-4-latin-400-normal.woff2" as="font" type="font/woff2" crossorigin>"#;

const FONT_INTER_400: &[u8] = include_bytes!("../../../web/fonts/inter-latin-400-normal.woff2");
const FONT_INTER_600: &[u8] = include_bytes!("../../../web/fonts/inter-latin-600-normal.woff2");
const FONT_SS4_400: &[u8] = include_bytes!("../../../web/fonts/source-serif-4-latin-400-normal.woff2");
const FONT_SS4_400_ITALIC: &[u8] = include_bytes!("../../../web/fonts/source-serif-4-latin-400-italic.woff2");
const FONT_JBM_400: &[u8] = include_bytes!("../../../web/fonts/jetbrains-mono-latin-400-normal.woff2");

// Embedded design-system files. Compiled into the binary so the runtime
// has no external file dependency; touching any of these forces a rebuild.
const TOKENS_CSS: &str = include_str!("../../../web/styles/tokens.css");
const WORKBENCH_CSS: &str = include_str!("../../../web/styles/workbench.css");
const SITE_CSS: &str = include_str!("../../../web/styles/site.css");
const FAVICON_SVG: &str = include_str!("../../../assets/brand/favicon.svg");
const LOGO_MARK_SVG: &str = include_str!("../../../assets/brand/vela-logo-mark.svg");
const LOGO_WORDMARK_SVG: &str = include_str!("../../../assets/brand/vela-logo-wordmark.svg");
const RETE_SVG: &str = include_str!("../../../assets/brand/rete.svg");

// Hub-specific page styles. The frame and tokens come from the shared
// stylesheets above; this block adds the entries table, the manifest
// detail layout, the terminal-paper code block, and the endpoint list.
//
// Visual register: Borrowed Light. Inter Tight as the dominant face;
// EB Garamond reserved for true prose (evidence quotes, annotations);
// JetBrains Mono for IDs / kickers. Cream paper, gold accent, hairlines.
const HUB_STYLES: &str = r#"
/* Entries table — frontier registry */
.fr-table { width: 100%; border-collapse: collapse; margin-top: 8px; }
.fr-table thead th {
  font-family: var(--font-mono); font-size: 10px; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.18em;
  color: color-mix(in oklab, var(--ink-3) 92%, transparent);
  text-align: left; padding: 14px 12px; border-bottom: 1px solid var(--rule-2);
}
.fr-table thead th.num { text-align: right; }
.fr-table tbody tr {
  border-bottom: 1px solid var(--rule-1);
  transition: background var(--dur-1) var(--ease);
}
.fr-table tbody tr:hover { background: var(--paper-1); cursor: pointer; }
.fr-table tbody td { padding: 16px 12px; vertical-align: top; font-size: 14px; }
.fr-table td.idx {
  font-family: var(--font-mono); font-size: 11px; color: var(--ink-3);
  white-space: nowrap; width: 200px;
}
.fr-table td.idx a { color: var(--ink-2); border: 0; }
.fr-table td.idx a:hover { color: var(--gold); }
.fr-table td.name {
  font-family: var(--font-sans); font-weight: 500; font-size: 15px;
  letter-spacing: -0.012em; color: var(--ink-0);
  line-height: 1.4; max-width: 360px;
}
.fr-table td.owner { font-family: var(--font-mono); font-size: 11px; color: var(--ink-2); white-space: nowrap; }
.fr-table td.state { width: 110px; }
.fr-table td.upd {
  width: 160px; color: var(--ink-3);
  font-family: var(--font-mono); font-size: 11px; text-align: right;
  letter-spacing: 0.04em;
}

/* Single-entry detail — finding page two-column layout */
.fd { display: grid; grid-template-columns: minmax(0, 1fr) 320px; gap: 56px; padding-top: 8px; }
@media (max-width: 1080px) { .fd { grid-template-columns: 1fr; gap: 32px; } }
.fd-claim {
  font-family: var(--font-sans); font-weight: 600;
  font-size: clamp(1.5rem, 3.2vw, 2rem);
  line-height: 1.08; letter-spacing: -0.022em;
  color: var(--ink-0); margin: 0 0 18px;
  text-wrap: balance;
}
.fd-note {
  font-family: var(--font-body); font-style: italic; font-size: 1.02rem;
  color: color-mix(in oklab, var(--ink-2) 92%, transparent);
  line-height: 1.55; max-width: 58ch;
  padding-left: 1.1rem;
  border-left: 1px solid color-mix(in oklab, var(--gold) 56%, transparent);
  margin: 0 0 32px;
  text-wrap: pretty;
}

.fd-conditions { border-top: 1px solid var(--rule-2); margin: 0; padding: 0; }
.fd-cond {
  display: grid; grid-template-columns: 180px 1fr;
  padding: 12px 0; border-bottom: 1px solid var(--rule-1); align-items: baseline;
  margin: 0;
}
.fd-cond dt {
  font-family: var(--font-mono); font-size: 10px;
  color: color-mix(in oklab, var(--ink-3) 88%, transparent);
  letter-spacing: 0.18em; text-transform: uppercase; margin: 0;
  font-weight: 500;
}
.fd-cond dd {
  font-family: var(--font-mono); font-size: 13px; color: var(--ink-1);
  word-break: break-all; margin: 0;
  letter-spacing: -0.005em;
}
.fd-cond dd.serif {
  font-family: var(--font-sans); font-weight: 400; font-size: 14px;
  letter-spacing: -0.005em; word-break: normal; color: var(--ink-1);
}
.fd-cond dd a {
  border-bottom: 1px solid color-mix(in oklab, var(--gold) 38%, transparent);
}
.fd-cond dd a:hover {
  color: var(--gold);
  border-bottom-color: var(--gold);
}

.fd-margin { padding-top: 4px; }
.fd-dial {
  border-top: 1px solid color-mix(in oklab, var(--gold) 32%, transparent);
  border-bottom: 1px solid var(--rule-2);
  padding: 14px 0 16px;
  margin-bottom: 22px;
  position: relative;
  background: transparent;
}
.fd-dial__k {
  position: relative; font-family: var(--font-mono); font-size: 10px;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: color-mix(in oklab, var(--gold) 72%, var(--ink-3));
  margin-bottom: 8px; font-weight: 500;
}
.fd-dial__v {
  position: relative; font-family: var(--font-sans); font-weight: 500;
  font-size: 1.15rem; letter-spacing: -0.015em; color: var(--ink-0);
}
.fd-dial__v.mono {
  font-family: var(--font-mono); font-weight: 400; font-size: 14px;
  word-break: break-all; letter-spacing: -0.005em;
}

/* Terminal-paper code block */
.tm-paper {
  background: var(--paper-1); border: 1px solid var(--rule-2);
  border-radius: var(--radius-sm); font-family: var(--font-mono);
  font-size: 13px; line-height: 1.65; color: var(--ink-1);
  overflow: hidden; margin: 16px 0 24px;
}
.tm-paper__bar {
  display: flex; align-items: center; gap: 12px;
  padding: 8px 14px; border-bottom: 1px solid var(--rule-2);
  font-family: var(--font-mono); font-size: 10px;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: color-mix(in oklab, var(--gold) 60%, var(--ink-3));
  background: transparent;
}
.tm-paper__body { padding: 14px 18px 16px; white-space: pre; overflow-x: auto; }
.tm-ps { color: color-mix(in oklab, var(--gold) 60%, var(--ink-3)); }
.tm-cmd { color: var(--ink-0); }
.tm-flag { color: var(--ink-2); }

/* Endpoint list */
.hub-endpoints { list-style: none; padding: 0; margin: 0; }
.hub-endpoints li {
  display: flex; align-items: baseline; gap: 24px;
  padding: 12px 0; border-bottom: 1px solid var(--rule-1);
}
.hub-endpoints li:last-child { border-bottom: 0; }
.hub-endpoints li .verb {
  font-family: var(--font-mono); font-size: 12px;
  color: var(--ink-2); flex: 0 0 auto; white-space: nowrap;
  letter-spacing: 0.04em;
}
.hub-endpoints li .verb .v {
  color: color-mix(in oklab, var(--gold) 64%, var(--ink-3));
  letter-spacing: 0.06em; margin-right: 8px;
  text-transform: uppercase;
}
.hub-endpoints li .desc {
  color: var(--ink-2); font-family: var(--font-sans); font-size: 14px;
  line-height: 1.5; min-width: 0;
  letter-spacing: -0.005em;
}
.hub-endpoints li .desc a {
  border-bottom: 1px solid color-mix(in oklab, var(--gold) 38%, transparent);
}
.hub-endpoints li .desc a:hover {
  color: var(--gold);
  border-bottom-color: var(--gold);
}

/* Inline code */
code, .mono-inline {
  font-family: var(--font-mono); font-size: 0.88em;
  color: var(--ink-1); background: var(--paper-1);
  padding: 1px 5px; border: 1px solid var(--rule-2); border-radius: var(--radius-xs);
}

/* Lead paragraph */
.t-lead {
  font-family: var(--font-sans); font-weight: 400;
  font-size: 1.1rem; line-height: 1.5;
  letter-spacing: -0.012em;
  color: color-mix(in oklab, var(--ink-1) 92%, var(--ink-2));
  max-width: 60ch; margin: 0 0 24px;
  text-wrap: pretty;
}

/* Empty state — atmospheric, italic Garamond is appropriate here */
.empty {
  font-family: var(--font-body); font-style: italic;
  color: var(--ink-3); padding: 40px 0; text-align: center;
  font-size: 1.05rem;
}

/* Raw json block */
.raw-json {
  font-family: var(--font-mono); font-size: 12px;
  background: var(--paper-1); border: 1px solid var(--rule-2);
  padding: 14px 18px; overflow-x: auto;
  white-space: pre; color: var(--ink-1);
  border-radius: var(--radius-sm);
  margin: 12px 0 0;
}

/* Section heads */
.wb-section { margin: 32px 0 16px; }
.wb-section__head {
  display: flex; align-items: baseline; gap: 14px;
  padding-bottom: 10px;
  border-bottom: 1px solid color-mix(in oklab, var(--gold) 28%, transparent);
  margin-bottom: 14px;
}
.wb-section__num {
  font-family: var(--font-mono); font-size: 10px; letter-spacing: 0.22em;
  color: color-mix(in oklab, var(--gold) 64%, var(--ink-3));
  font-weight: 500;
}
.wb-section__t {
  font-family: var(--font-sans); font-weight: 600; font-size: 1rem;
  color: var(--ink-0); letter-spacing: -0.018em;
}
.wb-section__aside {
  margin-left: auto; font-family: var(--font-mono); font-size: 10px;
  letter-spacing: 0.18em; text-transform: uppercase; color: var(--ink-3);
}

/* Finding page — provenance, annotations, links */
.fd-prov-meta {
  margin-top: 6px;
  font-family: var(--font-sans); font-weight: 400; font-size: 13px;
  color: var(--ink-3); letter-spacing: -0.005em;
}
.fd-dial__gauge {
  margin-top: 10px;
  height: 3px;
  background: var(--rule-1);
  position: relative;
}
.fd-dial__gauge i {
  position: absolute; top: 0; left: 0; height: 100%;
  background: var(--gold);
}

.ann-list, .link-list {
  list-style: none;
  padding: 0;
  margin: 0;
  border-top: 1px solid var(--rule-2);
}
.ann-list li, .link-list li {
  padding: 12px 0;
  border-bottom: 1px solid var(--rule-1);
  display: grid;
  grid-template-columns: 140px 1fr;
  gap: 18px;
  align-items: baseline;
}
.ann-author, .link-rel {
  font-family: var(--font-mono);
  font-size: 10px;
  color: color-mix(in oklab, var(--ink-3) 92%, transparent);
  letter-spacing: 0.18em;
  text-transform: uppercase;
  font-weight: 500;
}
/* Annotation text — keep serif EB Garamond. These are quoted reviewer
   prose and serif reads as "this is a quote from a person." */
.ann-text {
  font-family: var(--font-body);
  font-size: 1rem;
  color: color-mix(in oklab, var(--ink-1) 92%, var(--ink-2));
  line-height: 1.55;
  text-wrap: pretty;
}
.link-list li a {
  font-family: var(--font-sans); font-weight: 500;
  font-size: 14px;
  color: var(--ink-1);
  border-bottom: 1px solid color-mix(in oklab, var(--gold) 38%, transparent);
  letter-spacing: -0.008em;
}
.link-list li a:hover {
  color: var(--gold);
  border-bottom-color: var(--gold);
}
.link-list li code {
  font-family: var(--font-mono);
  font-size: 12px;
  background: var(--paper-1);
  padding: 1px 5px;
  border: 1px solid var(--rule-2);
  border-radius: var(--radius-xs);
}
.link-list li .cross-vfr {
  font-family: var(--font-sans); font-weight: 400;
  font-size: 12px;
  color: var(--ink-3);
  letter-spacing: -0.005em;
}
.link-list li a:hover .cross-vfr { color: var(--gold); }
.link-list li .cross-vfr-bad {
  font-family: var(--font-mono);
  font-size: 10px;
  color: var(--cinnabar);
  letter-spacing: 0.12em;
  text-transform: uppercase;
  margin-left: 6px;
}

/* Findings toolbar — search + state chips above the table */
.vf-toolbar {
  display: flex; gap: 18px; align-items: center;
  flex-wrap: wrap;
  padding: 12px 0 6px;
  border-bottom: 1px solid var(--rule-1);
  margin-bottom: 4px;
}
.vf-search {
  display: flex; align-items: center; gap: 8px;
  flex: 1 1 320px; min-width: 240px;
  padding: 6px 4px;
  border-bottom: 1px solid var(--rule-2);
  color: var(--ink-3);
  transition: border-bottom-color var(--dur-1) var(--ease);
}
.vf-search:focus-within { border-bottom-color: var(--gold); color: var(--ink-2); }
.vf-search input {
  flex: 1; border: 0; outline: 0; background: transparent;
  font-family: var(--font-sans); font-weight: 400; font-size: 14px;
  color: var(--ink-0); letter-spacing: -0.005em;
}
.vf-search input::placeholder { color: var(--ink-4); }
.vf-search__count {
  font-family: var(--font-mono); font-size: 11px;
  color: var(--ink-3); font-variant-numeric: tabular-nums;
  letter-spacing: 0.04em;
}
.vf-chips { display: flex; gap: 6px; flex-wrap: wrap; }
.vf-chip {
  font-family: var(--font-mono); font-size: 10px;
  letter-spacing: 0.14em; text-transform: uppercase;
  color: var(--ink-3);
  border: 1px solid var(--rule-2);
  background: transparent;
  padding: 4px 9px; border-radius: var(--radius-sm);
  cursor: pointer;
  transition: border-color var(--dur-1) var(--ease), color var(--dur-1) var(--ease);
}
.vf-chip:hover {
  color: var(--ink-1);
  border-color: color-mix(in oklab, var(--gold) 56%, transparent);
}
.vf-chip--on {
  color: var(--ink-0);
  border-color: color-mix(in oklab, var(--gold) 64%, transparent);
  background: var(--paper-1);
}
.vf-chip span {
  margin-left: 6px; color: var(--ink-3);
  font-variant-numeric: tabular-nums;
}
.vf-chip--on span { color: var(--ink-2); }
.vf-empty {
  font-family: var(--font-body); font-style: italic;
  color: var(--ink-3); padding: 28px 0; text-align: center;
}

/* Findings table */
.vf-table { width: 100%; border-collapse: collapse; margin-top: 8px; }
.vf-table thead th {
  font-family: var(--font-mono); font-size: 10px; font-weight: 500;
  text-transform: uppercase; letter-spacing: 0.18em;
  color: color-mix(in oklab, var(--ink-3) 92%, transparent);
  text-align: left; padding: 12px 10px; border-bottom: 1px solid var(--rule-2);
}
.vf-table thead th.num { text-align: right; }
.vf-table tbody tr {
  border-bottom: 1px solid var(--rule-1);
  cursor: pointer;
  transition: background var(--dur-1) var(--ease);
}
.vf-table tbody tr:hover { background: var(--paper-1); }
.vf-table tbody td a { color: inherit; border: 0; }
.vf-table tbody td a:hover { color: var(--gold); }
.vf-table tbody td {
  padding: 14px 10px; vertical-align: top; font-size: 14px;
}
.vf-table td.vf-id {
  font-family: var(--font-mono); font-size: 11px; color: var(--ink-3);
  white-space: nowrap; width: 130px; letter-spacing: 0.02em;
}
.vf-table td.vf-cls {
  font-family: var(--font-mono); font-size: 10px;
  text-transform: uppercase; letter-spacing: 0.14em;
  color: color-mix(in oklab, var(--gold) 60%, var(--ink-3));
  white-space: nowrap; width: 110px;
}
.vf-table td.vf-claim {
  font-family: var(--font-sans); font-weight: 500; font-size: 14px;
  letter-spacing: -0.012em; color: var(--ink-0);
  line-height: 1.45;
}
.vf-table td.vf-state { width: 130px; white-space: nowrap; }
.vf-table td.vf-conf {
  width: 92px; text-align: right;
  display: flex; align-items: center; justify-content: flex-end; gap: 8px;
  padding-top: 16px;
}
.vf-bar {
  display: inline-block; width: 36px; height: 3px;
  background: var(--rule-1); position: relative;
}
.vf-bar i {
  position: absolute; top: 0; left: 0; height: 100%;
  background: color-mix(in oklab, var(--gold) 72%, var(--ink-2));
}
.vf-num {
  font-family: var(--font-mono); font-size: 12px;
  color: var(--ink-2); font-variant-numeric: tabular-nums;
  letter-spacing: 0.02em;
}

/* Constellation — findings as a star chart, sits above the table.
   Deterministic radial layout: each finding is a node colored by state
   and sized by confidence; links between findings render as faint gold
   arcs through the centre. Hover reads the claim; click opens the
   finding detail page. */
.vc-figure {
  margin: 0 0 28px;
  padding: 0;
  position: relative;
  background: var(--paper-1);
  border: 1px solid var(--rule-2);
  border-radius: var(--radius-md);
  overflow: hidden;
}
.vc {
  display: block;
  width: 100%;
  height: auto;
  max-height: 420px;
  background:
    radial-gradient(circle at 50% 50%,
      var(--star-glow) 0%,
      transparent 38%),
    var(--paper-1);
}
.vc-ring {
  fill: none;
  stroke: color-mix(in oklab, var(--gold) 22%, transparent);
  stroke-width: 0.6;
  stroke-dasharray: 1 5;
}
.vc-center {
  fill: var(--gold);
  filter: drop-shadow(0 0 6px var(--gold-glow));
}
.vc-edges {
  fill: none;
  stroke: color-mix(in oklab, var(--gold) 28%, transparent);
  stroke-width: 0.6;
  pointer-events: none;
}
.vc-edge {
  transition: stroke 200ms var(--ease), stroke-width 200ms var(--ease), opacity 200ms var(--ease);
}
.vc-edge--cross {
  stroke: color-mix(in oklab, var(--winter) 64%, transparent);
  stroke-width: 0.85;
  stroke-linecap: round;
}
.vc-node {
  cursor: pointer;
  outline: none;
  transition: opacity 200ms var(--ease);
}
.vc-glow {
  fill: var(--gold);
  opacity: 0;
  transition: opacity 200ms var(--ease);
  pointer-events: none;
}
.vc-node:hover .vc-glow,
.vc-node:focus .vc-glow {
  opacity: 0.32;
}
.vc-dot {
  transition: r 200ms var(--ease), stroke 200ms var(--ease), stroke-width 200ms var(--ease);
  stroke: color-mix(in oklab, var(--ink-1) 18%, transparent);
  stroke-width: 0.5;
}
.vc-node:hover .vc-dot,
.vc-node:focus .vc-dot {
  stroke: var(--ink-1);
  stroke-width: 1;
}
.vc-node--live .vc-dot {
  filter: drop-shadow(0 0 4px var(--gold-glow));
}
.vc-node--live .vc-glow {
  opacity: 0.18;
}

/* ─── Focus mode ─── click a node, fade everything but it and its
   incident edges + connected nodes. Click again or click background or
   press Esc to clear. */
.vc--focused .vc-node           { opacity: 0.22; }
.vc--focused .vc-node--focus    { opacity: 1; }
.vc--focused .vc-node--related  { opacity: 1; }
.vc--focused .vc-edge           { opacity: 0.16; }
.vc--focused .vc-edge--focus    { opacity: 1; stroke: var(--gold); stroke-width: 1.4; }
.vc--focused .vc-ring           { opacity: 0.4; }
.vc--focused .vc-center         { opacity: 0.5; }
.vc-node--focus .vc-glow        { opacity: 0.42; }
.vc-node--focus .vc-dot {
  stroke: var(--ink-0);
  stroke-width: 1.4;
}

.vc-tooltip {
  margin: 0;
  padding: 12px 18px 14px;
  border-top: 1px solid var(--rule-2);
  font-family: var(--font-sans);
  font-weight: 500;
  font-size: 14px;
  letter-spacing: -0.012em;
  line-height: 1.4;
  color: var(--ink-1);
  text-wrap: pretty;
  min-height: 1.4em;
  background: var(--paper-1);
  opacity: 1;
  transition: opacity 200ms var(--ease);
}
.vc-tooltip:empty::before {
  content: 'Hover a node to read the claim · click to focus · esc to clear.';
  color: var(--ink-3);
  font-weight: 400;
  font-style: italic;
}
.vc-tooltip__meta {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 400;
  letter-spacing: 0.04em;
  color: color-mix(in oklab, var(--ink-3) 92%, transparent);
}
.vc-tooltip__open {
  margin-left: 8px;
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.04em;
  color: var(--gold);
  border-bottom: 1px solid color-mix(in oklab, var(--gold) 56%, transparent);
}
.vc-tooltip__open:hover {
  border-bottom-color: var(--gold);
}
.vc-legend {
  margin: 0;
  padding: 8px 18px 12px;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.14em;
  text-transform: uppercase;
  color: color-mix(in oklab, var(--ink-3) 92%, transparent);
  display: flex;
  flex-wrap: wrap;
  gap: 4px 10px;
  align-items: center;
  border-top: 1px solid var(--rule-1);
  background: transparent;
}
.vc-legend > span {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
.vc-legend__dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  margin-right: 2px;
}
.vc-legend .vc-sep {
  color: var(--ink-4);
}

@media (max-width: 720px) {
  .vc { max-height: 280px; }
  .vc-tooltip { font-size: 13px; padding: 10px 14px 12px; }
  .vc-legend { padding: 8px 14px 12px; font-size: 9px; gap: 3px 8px; }
}

/* ─── Proof packet page ─── manifest + trace + lock + included-files
   table. The seam the skeptic wants to see. */
.pp-subhead {
  margin: 22px 0 10px;
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 500;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: color-mix(in oklab, var(--gold) 64%, var(--ink-3));
}
.pp-checked {
  list-style: none;
  margin: 0 0 16px;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 4px 14px;
}
.pp-checked li code {
  display: inline-block;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--ink-1);
  background: transparent;
  border: 0;
  padding: 0;
  letter-spacing: 0.005em;
}
.pp-caveats {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.pp-caveats li {
  font-family: var(--font-body);
  font-size: 14px;
  line-height: 1.5;
  color: color-mix(in oklab, var(--ink-2) 92%, transparent);
  text-wrap: pretty;
}
.pp-table {
  width: 100%;
  border-collapse: collapse;
  margin-top: 4px;
}
.pp-table thead th {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 500;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: color-mix(in oklab, var(--ink-3) 92%, transparent);
  text-align: left;
  padding: 10px 10px;
  border-bottom: 1px solid var(--rule-2);
}
.pp-table thead th.num { text-align: right; }
.pp-table tbody tr {
  border-bottom: 1px solid var(--rule-1);
  transition: background var(--dur-1) var(--ease);
}
.pp-table tbody tr:hover { background: var(--paper-1); }
.pp-table td { padding: 8px 10px; vertical-align: baseline; }
.pp-path {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--ink-1);
  letter-spacing: -0.005em;
}
.pp-path code {
  font-family: inherit; font-size: inherit; color: inherit;
  background: transparent; border: 0; padding: 0;
}
.pp-bytes {
  width: 90px;
  text-align: right;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--ink-3);
  font-variant-numeric: tabular-nums;
}
.pp-sha {
  width: 180px;
  font-family: var(--font-mono);
  font-size: 11px;
  color: color-mix(in oklab, var(--ink-2) 92%, transparent);
  letter-spacing: 0.02em;
  cursor: help;
}
.pp-sha code {
  font-family: inherit; font-size: inherit; color: inherit;
  background: transparent; border: 0; padding: 0;
}
.pp-row--canonical .pp-path,
.pp-row--canonical .pp-path code {
  color: color-mix(in oklab, var(--gold) 60%, var(--ink-0));
  font-weight: 500;
}
.pp-row--canonical .pp-sha {
  color: color-mix(in oklab, var(--gold) 36%, var(--ink-2));
}

/* ============================================================
   Chrome — the frontier-kit register. The old .wb grid died in the
   Workbench.astro migration; this is its replacement: sticky header,
   one 1180px container, hero head, quiet footer.
   ============================================================ */

@font-face { font-family: "Inter"; font-style: normal; font-weight: 400; font-display: swap;
  src: url("/static/fonts/inter-latin-400-normal.woff2") format("woff2"); }
@font-face { font-family: "Inter"; font-style: normal; font-weight: 600; font-display: swap;
  src: url("/static/fonts/inter-latin-600-normal.woff2") format("woff2"); }
@font-face { font-family: "Source Serif 4"; font-style: normal; font-weight: 400; font-display: swap;
  src: url("/static/fonts/source-serif-4-latin-400-normal.woff2") format("woff2"); }
@font-face { font-family: "Source Serif 4"; font-style: italic; font-weight: 400; font-display: swap;
  src: url("/static/fonts/source-serif-4-latin-400-italic.woff2") format("woff2"); }
@font-face { font-family: "JetBrains Mono"; font-style: normal; font-weight: 400; font-display: swap;
  src: url("/static/fonts/jetbrains-mono-latin-400-normal.woff2") format("woff2"); }

body {
  margin: 0;
  background: var(--paper-0);
  color: var(--ink-1);
  font-family: var(--font-sans);
  font-size: var(--text-body);
  line-height: var(--leading-body);
  -webkit-font-smoothing: antialiased;
}

.hub-header {
  position: sticky; top: 0; z-index: 20;
  background: var(--paper-0);
  border-bottom: 1px solid var(--rule-1);
}
.hub-header__inner {
  max-width: var(--measure-page); margin: 0 auto;
  padding: 0 clamp(20px, 4vw, 48px);
  height: 60px; display: flex; align-items: center; gap: 24px;
}
.hub-mark {
  display: inline-flex; align-items: center; gap: 8px;
  font-family: var(--font-display); font-size: 17px;
  color: var(--ink-0); text-decoration: none; white-space: nowrap; border: 0;
}
.hub-mark span { color: var(--ink-3); }
.hub-nav { display: flex; gap: 4px; align-items: center; font-size: var(--text-small); }
.hub-nav a {
  color: var(--ink-3); text-decoration: none; border: 0;
  padding: 0.35rem 0.8rem; border-radius: 999px; line-height: 1;
}
.hub-nav a:hover { color: var(--ink-1); background: var(--paper-2); }
.hub-nav a[aria-current="page"] {
  color: var(--ink-0); background: var(--paper-2);
  box-shadow: inset 0 -1.5px 0 var(--gold);
}
.hub-header__right { margin-left: auto; display: inline-flex; align-items: center; gap: 12px; }
.hub-ver {
  font-family: var(--font-mono); font-size: 10.5px;
  letter-spacing: 0.18em; text-transform: uppercase; color: var(--ink-4);
}

.hub-page {
  max-width: var(--measure-page); margin: 0 auto;
  padding: 40px clamp(20px, 4vw, 48px) 120px;
}

.wb-head { max-width: 52rem; margin: 0 0 40px; }
.wb-head__row { display: flex; gap: 40px; align-items: flex-start; justify-content: space-between; }
.wb-head__eyebrow {
  font-family: var(--font-mono); font-weight: 500; font-size: 10.5px;
  letter-spacing: 0.18em; text-transform: uppercase;
  color: var(--gold-ink); margin: 0 0 8px;
}
.wb-head__eyebrow a { color: inherit; border: 0; }
.wb-head__title {
  font-family: var(--font-display); font-weight: 400;
  font-size: clamp(26px, 3.4vw, 34px); line-height: 1.08;
  color: var(--ink-0); margin: 0 0 8px; text-wrap: balance;
}
.wb-head__sub {
  font-size: var(--text-lede); line-height: 1.5; color: var(--ink-2);
  max-width: 60ch; margin: 0; text-wrap: pretty;
}
.wb-head__aside { flex-shrink: 0; }

.wb-main { min-width: 0; }

.wb-foot {
  margin-top: 72px; padding-top: 16px;
  border-top: 1px solid var(--rule-2);
  color: var(--ink-3); font-size: 13px; line-height: 1.7;
  display: flex; justify-content: space-between; gap: 24px; flex-wrap: wrap;
}
.wb-foot__left { display: flex; gap: 16px; flex-wrap: wrap; }
.wb-foot a { color: var(--ink-3); }

/* Quiet the numbered section labels; the heading carries the meaning. */
.wb-section__num { display: none; }

@media (max-width: 720px) {
  .hub-header__inner { height: auto; min-height: 52px; flex-wrap: wrap; padding-top: 8px; padding-bottom: 8px; row-gap: 4px; }
  .hub-header__right { display: none; }
  .hub-page { padding-top: 24px; padding-bottom: 72px; }
  .wb-head__row { flex-direction: column; gap: 16px; }
  .vf-table td.vf-cls, .vf-table thead th:nth-child(2) { display: none; }
  .pp-table thead th, .pp-table td { padding: 6px 6px; }
  .pp-sha { width: 110px; }
  .pp-bytes { width: 60px; }
}
"#;

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Build the workbench frame around a page body. `active` controls which
/// rim link is marked with the alidade; `eyebrow` is the small mono label
/// above the title. URLs in the rim and foot come from `urls` so the
/// same render code works for any deploy.
#[allow(clippy::too_many_arguments)]
fn shell(
    urls: &PublicUrls,
    title: &str,
    active: &str,
    eyebrow_html: &str,
    title_html: &str,
    sub_html: &str,
    aside_html: &str,
    main_html: &str,
    foot_left_html: &str,
) -> String {
    let nav_link = |id: &str, href: &str, label: &str| -> String {
        let current = if id == active {
            r#" aria-current="page""#
        } else {
            ""
        };
        format!(r#"<a{current} href="{href}">{label}</a>"#)
    };
    let header = format!(
        r#"<header class="hub-header"><div class="hub-header__inner">
  <a class="hub-mark" href="/" aria-label="Vela Hub">
    <img src="/static/vela-logo-mark.svg" width="20" height="20" alt="">Vela<span> Hub</span>
  </a>
  <nav class="hub-nav" aria-label="Hub">
    {l1}
    {l2}
  </nav>
  <span class="hub-header__right">
    <span class="wb-chip wb-chip--live"><span class="wb-chip__dot"></span>live</span>
    <span class="hub-ver">v{HUB_VERSION}</span>
  </span>
</div></header>"#,
        l1 = nav_link("hub", "/", "Hub"),
        l2 = nav_link("entries", "/entries", "Entries"),
    );
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<link rel="icon" type="image/svg+xml" href="/static/favicon.svg">
{FONT_LINK}
<link rel="stylesheet" href="/static/tokens.css">
<link rel="stylesheet" href="/static/workbench.css">
<style>{HUB_STYLES}</style>
</head>
<body>
{header}
<div class="hub-page">
<header class="wb-head">
  <div class="wb-head__row">
    <div>
      <div class="wb-head__eyebrow">{eyebrow_html}</div>
      <h1 class="wb-head__title">{title_html}</h1>
      <p class="wb-head__sub">{sub_html}</p>
    </div>
    <div class="wb-head__aside">{aside_html}</div>
  </div>
</header>
<main class="wb-main">
{main_html}
</main>
<footer class="wb-foot">
  <div class="wb-foot__left">
    <span>live · {hub_host}</span>
    <span>{foot_left_html}</span>
  </div>
  <div>Vela · <a href="{repo_url}">{repo_short}</a></div>
</footer>
</div>
</body>
</html>
"#,
        title = escape_html(title),
        hub_host = escape_html(urls.hub_host()),
        repo_url = escape_html(&urls.repo),
        repo_short = escape_html(
            urls.repo
                .trim_start_matches("https://")
                .trim_start_matches("http://")
        ),
    )
}

// ── Static asset handlers ────────────────────────────────────────────
//
// The hub embeds the design-system stylesheets and brand SVGs at build
// time and serves them at /static/<name>. This keeps the binary
// self-contained (no Docker volume juggling) and ensures the marketing
// site (web/index.html) and the hub render against the same source
// files. Cache headers are conservative — the deploy is small enough
// that a redeploy is the cache-bust path.

fn css_response(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=300"),
        ],
        body,
    )
        .into_response()
}

fn woff2_response(body: &'static [u8]) -> Response {
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "font/woff2"),
            (
                axum::http::header::CACHE_CONTROL,
                "public, max-age=31536000, immutable",
            ),
        ],
        body,
    )
        .into_response()
}

fn svg_response(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "image/svg+xml"),
            (axum::http::header::CACHE_CONTROL, "public, max-age=300"),
        ],
        body,
    )
        .into_response()
}

async fn static_tokens_css() -> Response {
    css_response(TOKENS_CSS)
}
async fn static_workbench_css() -> Response {
    css_response(WORKBENCH_CSS)
}
async fn static_site_css() -> Response {
    css_response(SITE_CSS)
}
async fn static_favicon_svg() -> Response {
    svg_response(FAVICON_SVG)
}
async fn static_logo_mark_svg() -> Response {
    svg_response(LOGO_MARK_SVG)
}
async fn static_logo_wordmark_svg() -> Response {
    svg_response(LOGO_WORDMARK_SVG)
}
async fn static_rete_svg() -> Response {
    svg_response(RETE_SVG)
}

fn render_root_html(urls: &PublicUrls) -> String {
    let hub_url = escape_html(&urls.hub);
    let site_host = escape_html(
        urls.site
            .trim_start_matches("https://")
            .trim_start_matches("http://"),
    );
    let main = format!(
        r#"<p class="t-lead">A signed-manifest registry for scientific frontiers. Anyone with an Ed25519 key can publish their own <code>vfr_id</code>; clients verify locally. The hub stores canonical bytes verbatim.</p>

<section class="wb-section">
  <div class="wb-section__head">
    <span class="wb-section__num">§1</span>
    <span class="wb-section__t">Endpoints</span>
    <span class="wb-section__aside">read · open · signature-gated</span>
  </div>
  <ul class="hub-endpoints">
    <li><span class="verb"><span class="v">GET</span>/</span><span class="desc">this banner</span></li>
    <li><span class="verb"><span class="v">GET</span>/healthz</span><span class="desc"><a href="/healthz">liveness</a></span></li>
    <li><span class="verb"><span class="v">GET</span>/entries</span><span class="desc"><a href="/entries">full registry, latest-publish-wins per <code>vfr_id</code></a></span></li>
    <li><span class="verb"><span class="v">GET</span>/entries/&#123;vfr_id&#125;</span><span class="desc">single entry</span></li>
    <li><span class="verb"><span class="v">POST</span>/entries/&#123;vfr_id&#125;/git-remote</span><span class="desc">the one write: owner-signed git-remote registration</span></li>
    <li><span class="verb"><span class="v">POST</span>/mcp</span><span class="desc">hosted MCP (streamable HTTP, read-only tools over every live frontier)</span></li>
    <li><span class="verb"><span class="v">POST</span>/webhook/github</span><span class="desc">push events refresh the index ahead of the sweep</span></li>
  </ul>
</section>

<section class="wb-section">
  <div class="wb-section__head">
    <span class="wb-section__num">§2</span>
    <span class="wb-section__t">Publish</span>
    <span class="wb-section__aside">the signature is the bind</span>
  </div>
  <div class="tm-paper">
    <div class="tm-paper__bar"><span>git push · vela hub register-git</span></div>
    <div class="tm-paper__body"><span class="tm-ps">$</span> <span class="tm-cmd">vela hub register-git</span> vfr_&hellip; \
  <span class="tm-flag">--remote</span> https://github.com/you/your-frontier.git \
  <span class="tm-flag">--to</span> {hub_url}
<span class="tm-ps">$</span> <span class="tm-cmd">git push</span>   <span class="tm-flag"># publication; the hub re-derives on ingest</span></div>
  </div>
</section>

<section class="wb-section">
  <div class="wb-section__head">
    <span class="wb-section__num">§3</span>
    <span class="wb-section__t">Pull and verify</span>
    <span class="wb-section__aside">byte-identical reconstruction</span>
  </div>
  <div class="tm-paper">
    <div class="tm-paper__bar"><span>git clone · vela check</span></div>
    <div class="tm-paper__body"><span class="tm-ps">$</span> <span class="tm-cmd">git clone</span> &lt;frontier-repo-url&gt;
<span class="tm-ps">$</span> <span class="tm-cmd">vela check</span> &lt;dir&gt; <span class="tm-flag">--strict</span></div>
  </div>
</section>"#,
    );
    shell(
        urls,
        "Vela Hub",
        "hub",
        "00 · Hub",
        "Vela Hub",
        "Signed registry manifests over HTTP. Open publishing, signature-gated; clients verify locally.",
        &format!(
            r#"<span>v{HUB_VERSION}</span><span>·</span><a class="wb-chip wb-chip--live"><span class="wb-chip__dot"></span>live</a>"#
        ),
        &main,
        &site_host,
    )
}

/// A producer's public ledger: everything this pubkey signed, grouped by
/// frontier. The page IS the reputation object — signed work, nothing else.
fn render_producer_html(
    urls: &PublicUrls,
    pubkey: &str,
    by_frontier: &std::collections::BTreeMap<String, Vec<Value>>,
) -> String {
    let pubkey_safe = escape_html(pubkey);
    let total: usize = by_frontier.values().map(Vec::len).sum();
    let sections: String = by_frontier
        .iter()
        .map(|(vfr, objs)| {
            let vfr_safe = escape_html(vfr);
            let items: String = objs
                .iter()
                .take(50)
                .map(|o| {
                    let otype = o.get("type").and_then(Value::as_str).unwrap_or("");
                    let oid = o.get("id").and_then(Value::as_str).unwrap_or("");
                    let summary = o
                        .get("summary")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .chars()
                        .take(120)
                        .collect::<String>();
                    let href = if otype == "finding" {
                        format!("/entries/{vfr_safe}/findings/{oid}")
                    } else {
                        format!("/entries/{vfr_safe}")
                    };
                    format!(
                        r#"<li><span class="link-rel">{otype}</span> <span><a href="{href}"><code>{oid}</code></a> · {summary}</span></li>"#,
                        otype = escape_html(otype),
                        oid = escape_html(oid),
                        summary = escape_html(&summary),
                    )
                })
                .collect();
            format!(
                r#"<section class="wb-section">
  <div class="wb-section__head">
    <span class="wb-section__t"><a href="/entries/{vfr_safe}">{vfr_safe}</a> · {n}</span>
  </div>
  <ul class="link-list">{items}</ul>
</section>"#,
                n = objs.len(),
            )
        })
        .collect();
    let main = if by_frontier.is_empty() {
        r#"<p class="empty">No signed objects from this key are live on the index.</p>"#.to_string()
    } else {
        sections
    };
    shell(
        urls,
        "Vela Hub · Producer",
        "entries",
        "05 · Producer",
        "Signed work",
        &format!("{total} object(s) across {} frontier(s)", by_frontier.len()),
        &format!(
            r#"<div class="fd-dial"><div class="fd-dial__k">pubkey</div><div class="fd-dial__v mono" style="word-break:break-all;">{pubkey_safe}</div></div>"#
        ),
        &main,
        "a producer's record is the signed objects that replay — not a profile anyone wrote",
    )
}

fn render_entries_html(urls: &PublicUrls, entries: &[Value]) -> String {
    // Name-first rows: the frontier's QUESTION is the identity a reader
    // scans for; the vfr_ id is the machine handle underneath. Each row
    // carries its doors (verify walkthrough, live search).
    let row = |entry: &Value| -> String {
        let s = |key: &str| -> String {
            entry
                .get(key)
                .and_then(|v| v.as_str())
                .map(escape_html)
                .unwrap_or_else(|| String::from("—"))
        };
        let vfr = s("vfr_id");
        let name = s("name");
        let owner = s("owner_actor_id");
        let signed_at = s("signed_publish_at");
        format!(
            r#"<tr onclick="location.href='/entries/{vfr}'">
  <td class="name"><a href="/entries/{vfr}" style="font-family:var(--font-serif,serif);font-size:15px;">{name}</a><br><code style="font-size:11px;color:var(--ink-3);">{vfr}</code></td>
  <td class="owner">{owner}</td>
  <td class="state"><span class="wb-chip wb-chip--live"><span class="wb-chip__dot"></span>live</span></td>
  <td class="doors"><a href="/entries/{vfr}/reproduce">verify</a></td>
  <td class="upd">{signed_at}</td>
</tr>"#
        )
    };
    let body_rows: String = entries.iter().map(row).collect();
    let count = entries.len();
    let main = if entries.is_empty() {
        r#"<p class="empty">The index is empty. Bind a frontier repo once with <code>vela hub register-git</code>; after that, <code>git push</code> is publication.</p>"#.to_string()
    } else {
        format!(
            r#"<table class="fr-table">
  <thead>
    <tr>
      <th>frontier</th>
      <th>owner</th>
      <th>state</th>
      <th>doors</th>
      <th class="num">signed</th>
    </tr>
  </thead>
  <tbody>{body_rows}</tbody>
</table>
<p class="fd-note" style="margin-top:14px;">Every row is re-derived from its git repo by strict replay — <a href="/search">search across all of them</a>, or connect an agent to <code>/mcp</code>.</p>"#
        )
    };
    shell(
        urls,
        "Vela Hub · Entries",
        "entries",
        &format!("01 · Entries · <span style=\"color:var(--ink-2);\">{count} signed</span>"),
        "Registry",
        "Latest-publish-wins per <code>vfr_id</code>. Click through for the manifest, the pull recipe, and the raw signed bytes.",
        &format!(
            r#"<span>{count} {plural}</span><span>·</span><a href="/entries">JSON</a>"#,
            plural = if count == 1 { "entry" } else { "entries" }
        ),
        &main,
        &format!("registry · v{HUB_VERSION}"),
    )
}

fn render_entry_html(
    urls: &PublicUrls,
    vfr_id: &str,
    entry: &Value,
    frontier: Option<&Project>,
    git_remote: Option<&str>,
) -> String {
    let s = |key: &str| -> String {
        entry
            .get(key)
            .and_then(|v| v.as_str())
            .map(escape_html)
            .unwrap_or_else(|| String::from("—"))
    };
    let name = s("name");
    let owner = s("owner_actor_id");
    let pubkey = s("owner_pubkey");
    let snapshot = s("latest_snapshot_hash");
    let event_log = s("latest_event_log_hash");
    let locator_raw = entry
        .get("network_locator")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let locator_safe = escape_html(locator_raw);
    let signed_at = s("signed_publish_at");
    let signature = s("signature");
    let schema = s("schema");
    let raw_json = serde_json::to_string_pretty(entry).unwrap_or_default();
    let vfr_safe = escape_html(vfr_id);

    // Note line varies by whether the frontier loaded.
    let note = if let Some(p) = frontier {
        let pending = p
            .proposals
            .iter()
            .filter(|pr| pr.status == "pending_review" && pr.applied_event_id.is_none())
            .count();
        let pending_note = if pending > 0 {
            format!(
                " · {pending} proposal{} pending review",
                if pending == 1 { "" } else { "s" }
            )
        } else {
            String::new()
        };
        format!(
            r#"{count} signed finding{plural} · {events} canonical event{events_plural}{pending_note}. Signed by <span class="t-mono">{owner}</span> at <span class="t-mono">{signed_at}</span>."#,
            count = p.findings.len(),
            plural = if p.findings.len() == 1 { "" } else { "s" },
            events = p.events.len(),
            events_plural = if p.events.len() == 1 { "" } else { "s" },
        )
    } else {
        format!(
            r#"Signed by <span class="t-mono">{owner}</span> at <span class="t-mono">{signed_at}</span>. The frontier file is fetched from the network locator on demand; verification happens on the client."#,
        )
    };

    let constellation = render_findings_constellation(vfr_id, frontier);
    let findings_section = render_findings_section(vfr_id, frontier);

    // Open changesets: undecided packs are the reviewer's units of work;
    // orphaning their pages behind an unlinked URL hides the queue.
    let packs_section = frontier
        .map(|p| {
            let mut undecided: Vec<_> = p
                .released_diff_packs
                .iter()
                .filter(|r| vela_edge::frontier_next::pack_awaits_decision(r, p))
                .collect();
            undecided.sort_by(|a, b| a.summary.cmp(&b.summary));
            if undecided.is_empty() {
                return String::new();
            }
            let items: String = undecided
                .iter()
                .map(|r| {
                    format!(
                        r#"<li><span class="link-rel">pending</span> <span><a href="/entries/{vfr_safe}/packs/{pid}"><code>{pid}</code></a> · {members} member{plural} · {summary}</span></li>"#,
                        pid = escape_html(&r.pack_id),
                        members = r.member_proposals.len(),
                        plural = if r.member_proposals.len() == 1 { "" } else { "s" },
                        summary = escape_html(&r.summary.chars().take(80).collect::<String>()),
                    )
                })
                .collect();
            format!(
                r#"
    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§P</span>
        <span class="wb-section__t">Open changesets · {n}</span>
        <span class="wb-section__aside">one key-custody decision each</span>
      </div>
      <ul class="link-list">{items}</ul>
    </section>"#,
                n = undecided.len(),
            )
        })
        .unwrap_or_default();

    let remote_display = git_remote
        .map(escape_html)
        .unwrap_or_else(|| "&lt;this frontier's registered repo&gt;".to_string());
    let main = format!(
        r#"<div class="fd">
  <article>
    <p class="fd-claim">{name}</p>
    <p class="fd-note">{note}</p>

    {constellation}
    {findings_section}
    {packs_section}

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§{pull_num}</span>
        <span class="wb-section__t">Pull and verify</span>
        <span class="wb-section__aside">byte-identical reconstruction</span>
      </div>
      <div class="tm-paper">
        <div class="tm-paper__bar"><span>git clone · {vfr_safe}</span></div>
        <div class="tm-paper__body"><span class="tm-ps">$</span> <span class="tm-cmd">git clone</span> {remote_display}
<span class="tm-ps">$</span> <span class="tm-cmd">vela check</span> &lt;dir&gt; <span class="tm-flag">--strict</span></div>
      </div>
      <p class="fd-note">Full walkthrough (clone → strict check → frozen-verifier reproduce, with the last-ingest commit): <a href="/entries/{vfr_safe}/reproduce">/entries/{vfr_safe}/reproduce</a></p>
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§{manifest_num}</span>
        <span class="wb-section__t">Manifest</span>
        <span class="wb-section__aside">vela.registry-entry.v0.1</span>
      </div>
      <dl class="fd-conditions">
        <div class="fd-cond"><dt>vfr_id</dt><dd>{vfr_safe}</dd></div>
        <div class="fd-cond"><dt>schema</dt><dd>{schema}</dd></div>
        <div class="fd-cond"><dt>name</dt><dd class="serif">{name}</dd></div>
        <div class="fd-cond"><dt>owner_actor_id</dt><dd>{owner}</dd></div>
        <div class="fd-cond"><dt>network_locator</dt><dd><a href="{locator_safe}" rel="noopener">{locator_safe}</a></dd></div>
        <div class="fd-cond"><dt>signed_publish_at</dt><dd>{signed_at}</dd></div>
      </dl>
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§{hashes_num}</span>
        <span class="wb-section__t">Hashes</span>
        <span class="wb-section__aside">SHA-256 hex · canonical-JSON</span>
      </div>
      <dl class="fd-conditions">
        <div class="fd-cond"><dt>snapshot_hash</dt><dd>{snapshot}</dd></div>
        <div class="fd-cond"><dt>event_log_hash</dt><dd>{event_log}</dd></div>
      </dl>
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§{sig_num}</span>
        <span class="wb-section__t">Signature</span>
        <span class="wb-section__aside">Ed25519 over canonical preimage</span>
      </div>
      <dl class="fd-conditions">
        <div class="fd-cond"><dt>owner_pubkey</dt><dd>{pubkey}</dd></div>
        <div class="fd-cond"><dt>signature</dt><dd>{signature}</dd></div>
      </dl>
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§{raw_num}</span>
        <span class="wb-section__t">Raw manifest</span>
        <span class="wb-section__aside">canonical bytes the publisher signed</span>
      </div>
      <pre class="raw-json">{raw}</pre>
    </section>
  </article>

  <aside class="fd-margin">
    <div class="fd-dial">
      <div class="fd-dial__k">state</div>
      <div class="fd-dial__v" style="color:var(--signal);">Latest</div>
      <div class="fd-dial__k" style="margin-top:16px;">vfr_id</div>
      <div class="fd-dial__v mono">{vfr_safe}</div>
      <div class="fd-dial__k" style="margin-top:16px;">signed</div>
      <div class="fd-dial__v mono">{signed_at}</div>
    </div>

    {margin_extras}

    <div class="fd-dial">
      <div class="fd-dial__k">JSON</div>
      <div style="font-family:var(--font-mono);font-size:12px;line-height:1.6;color:var(--ink-1);margin-top:6px;">
        <a href="/entries/{vfr_safe}" style="border-bottom:1px solid var(--rule-3);">/entries/{vfr_safe}</a>
        <div style="color:var(--ink-3);margin-top:4px;">with <code>Accept: application/json</code></div>
      </div>
    </div>
  </aside>
</div>"#,
        raw = escape_html(&raw_json),
        // Section numbering: if findings rendered, they take §1; otherwise we
        // skip that slot.
        pull_num = if frontier.is_some() { "2" } else { "1" },
        manifest_num = if frontier.is_some() { "3" } else { "2" },
        hashes_num = if frontier.is_some() { "4" } else { "3" },
        sig_num = if frontier.is_some() { "5" } else { "4" },
        raw_num = if frontier.is_some() { "6" } else { "5" },
        margin_extras = render_margin_extras(frontier),
    );

    shell(
        urls,
        &format!("Vela Hub · {vfr_id}"),
        "entries",
        &format!("02 · Entry · <span style=\"color:var(--ink-2);\">{vfr_safe}</span>"),
        &name,
        "One signed manifest, read end-to-end. Pull the frontier from the network locator; verify hashes locally.",
        &format!(
            r#"<a href="/entries">← Entries</a><span>·</span><a href="/entries/{vfr_safe}">JSON</a><span>·</span><a href="/entries/{vfr_safe}/proof">Proof packet →</a>"#
        ),
        &main,
        &format!("{vfr_safe} · latest"),
    )
}

/// Map a finding's flags + review verdict to the chip variants the
/// design system carries: replicated, supported, contested, gap,
/// retracted. Order of precedence matches the substrate's own
/// derivation: explicit retraction > gap > review verdict > replication
/// status > default supported. Replication status reads the core
/// `evidence.replicated` finding field.
fn is_replicated(b: &vela_protocol::bundle::FindingBundle) -> bool {
    b.evidence.replicated
}

fn finding_state(b: &vela_protocol::bundle::FindingBundle) -> (&'static str, &'static str) {
    use vela_protocol::bundle::ReviewState;
    if b.flags.retracted {
        return ("retracted", "lost");
    }
    if b.flags.gap || b.flags.negative_space {
        return ("gap", "stale");
    }
    if let Some(state) = &b.flags.review_state {
        match state {
            ReviewState::Contested => return ("contested", "warn"),
            ReviewState::NeedsRevision => return ("contested", "warn"),
            ReviewState::Rejected => return ("retracted", "lost"),
            ReviewState::Accepted => {
                if is_replicated(b) {
                    return ("replicated", "ok");
                }
                return ("supported", "ok");
            }
        }
    }
    if b.flags.contested {
        return ("contested", "warn");
    }
    if is_replicated(b) {
        return ("replicated", "ok");
    }
    ("supported", "ok")
}

/// Render the findings as a constellation — a deterministic radial layout
/// where each finding is a star colored by state and sized by confidence,
/// and the cross-finding `links` become faint gold dependency arcs through
/// the centre. Sits above the findings table as a navigable visual proof
/// that the substrate is a graph, not a list.
///
/// Layout: stable order = order in p.findings; a single ring at evenly
/// distributed angles. Hover a node to read the claim; click to navigate
/// to its detail page.
fn render_findings_constellation(vfr_id: &str, frontier: Option<&Project>) -> String {
    let Some(p) = frontier else {
        return String::new();
    };
    if p.findings.is_empty() {
        return String::new();
    }

    let n = p.findings.len();
    let view_w: i32 = 720;
    let view_h: i32 = 380;
    let cx = view_w as f64 / 2.0;
    let cy = view_h as f64 / 2.0;
    let ring_r = (cx.min(cy) - 60.0).max(80.0);

    // Stable position per finding id. Angle starts at top (-π/2) and runs
    // clockwise so the first finding is "12 o'clock".
    let pos: std::collections::HashMap<&str, (f64, f64)> = p
        .findings
        .iter()
        .enumerate()
        .map(|(i, b)| {
            let angle = (i as f64 / n as f64) * std::f64::consts::TAU - std::f64::consts::FRAC_PI_2;
            let x = cx + ring_r * angle.cos();
            let y = cy + ring_r * angle.sin();
            (b.id.as_str(), (x, y))
        })
        .collect();

    // Per-finding link counts so the focused tooltip can show
    // "N dependencies · M dependents". We count edges incident to each
    // node; cross-frontier links count too.
    let mut deps_out: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    let mut deps_in: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for b in &p.findings {
        let from = b.id.as_str();
        for link in &b.links {
            *deps_out.entry(from).or_default() += 1;
            // Only count inbound for resolvable targets.
            if pos.contains_key(link.target.as_str()) {
                *deps_in.entry(link.target.as_str()).or_default() += 1;
            }
        }
    }

    // Edges first so nodes render on top. Same-frontier links render as
    // quadratic-Bezier arcs through the centre (gold). Cross-frontier
    // links — those whose target id doesn't resolve to a local
    // finding — render as short outward strokes from the source node
    // toward the rim, in --winter (cool, distinct from --gold) so the
    // viewer sees external dependencies without a fetch chain.
    let mut edges = String::new();
    for b in &p.findings {
        let Some(&(x1, y1)) = pos.get(b.id.as_str()) else {
            continue;
        };
        let from = escape_html(&b.id);
        for link in &b.links {
            if let Some(&(x2, y2)) = pos.get(link.target.as_str()) {
                let mx = (x1 + x2) / 2.0;
                let my = (y1 + y2) / 2.0;
                let pull = 0.45;
                let qx = cx + (mx - cx) * pull;
                let qy = cy + (my - cy) * pull;
                let to = escape_html(&link.target);
                edges.push_str(&format!(
                    r##"<path class="vc-edge" data-from="{from}" data-to="{to}" d="M {x1:.1} {y1:.1} Q {qx:.1} {qy:.1} {x2:.1} {y2:.1}"/>"##
                ));
            } else {
                // Cross-frontier link — draw a short outward stroke from
                // the source node toward the rim. Length tapers with the
                // source's confidence (so a high-confidence external
                // dependency reaches further). The length is bounded so
                // it stays inside the figure.
                let dx = x1 - cx;
                let dy = y1 - cy;
                let mag = (dx * dx + dy * dy).sqrt().max(1e-6);
                let conf = b.confidence.score.clamp(0.0, 1.0);
                let outward = 18.0 + conf * 22.0;
                let xt = x1 + (dx / mag) * outward;
                let yt = y1 + (dy / mag) * outward;
                edges.push_str(&format!(
                    r##"<path class="vc-edge vc-edge--cross" data-from="{from}" data-to="cross" d="M {x1:.1} {y1:.1} L {xt:.1} {yt:.1}"/>"##
                ));
            }
        }
    }

    // Nodes.
    let mut nodes = String::new();
    for b in &p.findings {
        let (x, y) = pos[b.id.as_str()];
        let (label, state_class) = finding_state(b);
        let r = 4.0 + b.confidence.score.clamp(0.0, 1.0) * 5.0;
        let live_class = if label == "replicated" {
            " vc-node--live"
        } else {
            ""
        };
        let vf = escape_html(&b.id);
        let claim = escape_html(&b.assertion.text);
        let n_out = deps_out.get(b.id.as_str()).copied().unwrap_or(0);
        let n_in = deps_in.get(b.id.as_str()).copied().unwrap_or(0);
        let href = format!("/entries/{vfr}/findings/{vf}", vfr = escape_html(vfr_id));
        nodes.push_str(&format!(
            r#"<a class="vc-node{live_class}" href="{href}" data-vf="{vf}" data-state="{label}" data-claim="{claim}" data-deps-out="{n_out}" data-deps-in="{n_in}">
              <circle class="vc-glow" cx="{x:.1}" cy="{y:.1}" r="{rg:.1}"/>
              <circle class="vc-dot" cx="{x:.1}" cy="{y:.1}" r="{r:.1}" style="fill:var(--state-{state_class});"/>
            </a>"#,
            rg = r * 2.6,
        ));
    }

    format!(
        r#"<figure class="vc-figure" data-vc-figure>
          <svg class="vc" viewBox="0 0 {w} {h}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Finding constellation — {n} findings as a star chart">
            <circle class="vc-ring" cx="{cx}" cy="{cy}" r="{rr}"/>
            <circle class="vc-center" cx="{cx}" cy="{cy}" r="2.5"/>
            <g class="vc-edges">{edges}</g>
            <g class="vc-nodes">{nodes}</g>
          </svg>
          <p class="vc-tooltip" data-vc-tooltip aria-hidden="true"></p>
          <p class="vc-legend">
            <span><span class="vc-legend__dot" style="background:var(--state-ok);"></span>replicated · supported</span>
            <span class="vc-sep">·</span>
            <span><span class="vc-legend__dot" style="background:var(--state-warn);"></span>contested</span>
            <span class="vc-sep">·</span>
            <span><span class="vc-legend__dot" style="background:var(--state-stale);"></span>gap · inferred</span>
            <span class="vc-sep">·</span>
            <span><span class="vc-legend__dot" style="background:var(--state-lost);"></span>retracted</span>
            <span class="vc-sep">·</span>
            <span><span class="vc-legend__dot" style="background:var(--winter);"></span>cross-frontier</span>
            <span class="vc-sep">·</span>
            <span>radius = confidence · click to focus · esc to clear</span>
          </p>
          <script>
          (function(){{
            var fig    = document.querySelector('[data-vc-figure]');
            var nodes  = document.querySelectorAll('.vc-node');
            var edges  = document.querySelectorAll('.vc-edge');
            var tip    = document.querySelector('[data-vc-tooltip]');
            if (!fig || !tip) return;
            var focused = null;
            var openHref = null;

            function clearTip() {{
              tip.innerHTML = '';
            }}
            function showTipFromNode(n) {{
              var claim = n.getAttribute('data-claim') || '';
              var nOut = parseInt(n.getAttribute('data-deps-out') || '0', 10);
              var nIn  = parseInt(n.getAttribute('data-deps-in')  || '0', 10);
              var href = n.getAttribute('href');
              var meta = nOut + ' dep' + (nOut === 1 ? '' : 's') + ' · ' + nIn + ' dependent' + (nIn === 1 ? '' : 's');
              if (focused) {{
                tip.innerHTML = claim + ' <span class="vc-tooltip__meta">· ' + meta + '</span> <a class="vc-tooltip__open" href="' + href + '">→ open</a>';
              }} else {{
                tip.innerHTML = claim + ' <span class="vc-tooltip__meta">· ' + meta + '</span>';
              }}
            }}

            function relatedSet(vf) {{
              var related = {{}};
              edges.forEach(function(e){{
                var from = e.getAttribute('data-from');
                var to   = e.getAttribute('data-to');
                if (from === vf) {{
                  related[to] = true;
                  e.classList.add('vc-edge--focus');
                }} else if (to === vf) {{
                  related[from] = true;
                  e.classList.add('vc-edge--focus');
                }} else {{
                  e.classList.remove('vc-edge--focus');
                }}
              }});
              return related;
            }}

            function applyFocus(node) {{
              var vf = node.getAttribute('data-vf');
              focused = vf;
              openHref = node.getAttribute('href');
              fig.classList.add('vc--focused');
              var related = relatedSet(vf);
              nodes.forEach(function(n){{
                var nv = n.getAttribute('data-vf');
                n.classList.remove('vc-node--focus','vc-node--related');
                if (nv === vf) n.classList.add('vc-node--focus');
                else if (related[nv]) n.classList.add('vc-node--related');
              }});
              showTipFromNode(node);
            }}

            function clearFocus() {{
              focused = null;
              openHref = null;
              fig.classList.remove('vc--focused');
              nodes.forEach(function(n){{ n.classList.remove('vc-node--focus','vc-node--related'); }});
              edges.forEach(function(e){{ e.classList.remove('vc-edge--focus'); }});
              clearTip();
            }}

            nodes.forEach(function(n){{
              n.addEventListener('mouseenter', function(){{ if (!focused) showTipFromNode(n); }});
              n.addEventListener('mouseleave', function(){{ if (!focused) clearTip(); }});
              n.addEventListener('focus',      function(){{ if (!focused) showTipFromNode(n); }});
              n.addEventListener('blur',       function(){{ if (!focused) clearTip(); }});
              n.addEventListener('click',      function(e){{
                var vf = n.getAttribute('data-vf');
                if (focused === vf) {{
                  // Second click on same node → navigate.
                  return;
                }}
                e.preventDefault();
                applyFocus(n);
              }});
              n.addEventListener('keydown', function(e){{
                if (e.key === 'Enter' && focused === n.getAttribute('data-vf')) {{
                  // Enter on a focused node → navigate.
                  return;
                }}
              }});
            }});

            // Click anywhere outside the SVG to clear focus.
            document.addEventListener('click', function(e){{
              if (!focused) return;
              if (!fig.contains(e.target)) clearFocus();
            }});
            // Escape clears focus.
            document.addEventListener('keydown', function(e){{
              if (e.key === 'Escape' && focused) {{ clearFocus(); }}
            }});
          }})();
          </script>
        </figure>"#,
        w = view_w,
        h = view_h,
        rr = ring_r,
    )
}

fn render_findings_section(vfr_id: &str, frontier: Option<&Project>) -> String {
    let Some(p) = frontier else {
        return String::from(
            r#"<section class="wb-section">
              <div class="wb-section__head">
                <span class="wb-section__num">§1</span>
                <span class="wb-section__t">Findings</span>
                <span class="wb-section__aside">frontier unavailable · pull to inspect</span>
              </div>
              <p class="empty">This manifest has not been promoted into live frontier state. The manifest remains verifiable below; pull the frontier with the CLI to inspect findings.</p>
            </section>"#,
        );
    };
    if p.findings.is_empty() {
        return String::from(
            r#"<section class="wb-section">
              <div class="wb-section__head">
                <span class="wb-section__num">§1</span>
                <span class="wb-section__t">Findings</span>
                <span class="wb-section__aside">empty frontier</span>
              </div>
              <p class="empty">This frontier has no findings yet.</p>
            </section>"#,
        );
    }

    // Counts for the section aside.
    let by_state: std::collections::BTreeMap<&str, usize> =
        p.findings
            .iter()
            .fold(std::collections::BTreeMap::new(), |mut acc, b| {
                *acc.entry(finding_state(b).0).or_default() += 1;
                acc
            });
    let counts = by_state
        .iter()
        .map(|(label, n)| format!("{n} {label}"))
        .collect::<Vec<_>>()
        .join(" · ");

    let mut rows = String::new();
    for b in &p.findings {
        let (label, state_class) = finding_state(b);
        let live_class = if label == "replicated" {
            " wb-chip--live"
        } else {
            ""
        };
        let pct = (b.confidence.score.clamp(0.0, 1.0) * 100.0).round() as u32;
        let assertion_type = b
            .assertion
            .assertion_type
            .split_whitespace()
            .next()
            .unwrap_or(&b.assertion.assertion_type);
        let vf_safe = escape_html(&b.id);
        let vfr_safe = escape_html(vfr_id);
        let href = format!("/entries/{vfr_safe}/findings/{vf_safe}");
        rows.push_str(&format!(
            r#"<tr onclick="location.href='{href}'">
              <td class="vf-id"><a href="{href}">{vf_safe}</a></td>
              <td class="vf-cls">{cls}</td>
              <td class="vf-claim"><a href="{href}">{claim}</a></td>
              <td class="vf-state"><span class="wb-chip{live_class}" style="--chip:var(--state-{state_class});"><span class="wb-chip__dot"></span>{label}</span></td>
              <td class="vf-conf"><span class="vf-bar"><i style="width:{pct}%;"></i></span><span class="vf-num">{score:.2}</span></td>
            </tr>"#,
            cls = escape_html(assertion_type),
            claim = escape_html(&b.assertion.text),
            score = b.confidence.score,
        ));
    }

    // State-filter chip row. data-state matches finding_state()'s label set.
    let mut chip_html =
        String::from(r#"<button class="vf-chip vf-chip--on" data-state="all">all</button>"#);
    for (label, n) in by_state.iter() {
        chip_html.push_str(&format!(
            r#"<button class="vf-chip" data-state="{label}">{label} <span>{n}</span></button>"#
        ));
    }

    format!(
        r#"<section class="wb-section">
          <div class="wb-section__head">
            <span class="wb-section__num">§1</span>
            <span class="wb-section__t">Findings · {count}</span>
            <span class="wb-section__aside">{counts}</span>
          </div>
          <div class="vf-toolbar">
            <label class="vf-search">
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" aria-hidden="true"><circle cx="7" cy="7" r="5" stroke-width="1"/><line x1="11" y1="11" x2="15" y2="15" stroke-width="1"/></svg>
              <input type="search" placeholder="filter by claim, class, vf_id…" data-vf-search>
              <span class="vf-search__count" data-vf-count>{count} / {count}</span>
            </label>
            <div class="vf-chips" data-vf-chips>{chip_html}</div>
          </div>
          <table class="vf-table" data-vf-table>
            <thead>
              <tr>
                <th>vf_id</th>
                <th>class</th>
                <th>claim</th>
                <th>state</th>
                <th class="num">conf</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
          <p class="vf-empty" data-vf-empty hidden>No findings match the current filter.</p>
          <script>
          (function() {{
            var search = document.querySelector('[data-vf-search]');
            var chips  = document.querySelectorAll('[data-vf-chips] button');
            var rows   = document.querySelectorAll('[data-vf-table] tbody tr');
            var empty  = document.querySelector('[data-vf-empty]');
            var countEl = document.querySelector('[data-vf-count]');
            var total = rows.length;
            var activeState = 'all';
            var query = '';

            function rowMatches(r) {{
              if (activeState !== 'all') {{
                var st = r.querySelector('.vf-state .wb-chip');
                if (!st || !st.textContent.toLowerCase().includes(activeState)) return false;
              }}
              if (!query) return true;
              return (r.textContent || '').toLowerCase().includes(query);
            }}
            function apply() {{
              var shown = 0;
              rows.forEach(function(r) {{
                if (rowMatches(r)) {{ r.hidden = false; shown++; }} else {{ r.hidden = true; }}
              }});
              if (countEl) countEl.textContent = shown + ' / ' + total;
              if (empty)   empty.hidden = shown !== 0;
            }}
            if (search) search.addEventListener('input', function(e) {{
              query = (e.target.value || '').toLowerCase();
              apply();
            }});
            chips.forEach(function(c) {{
              c.addEventListener('click', function() {{
                activeState = c.getAttribute('data-state');
                chips.forEach(function(b) {{ b.classList.remove('vf-chip--on'); }});
                c.classList.add('vf-chip--on');
                apply();
              }});
            }});
          }})();
          </script>
        </section>"#,
        count = p.findings.len(),
    )
}

/// Extra margin-column dials when the frontier has loaded.
fn render_margin_extras(frontier: Option<&Project>) -> String {
    let Some(p) = frontier else {
        return String::new();
    };
    let actor_count = p.actors.len();
    let event_count = p.events.len();
    let proposal_count = p.proposals.len();
    format!(
        r#"<div class="fd-dial">
          <div class="fd-dial__k">findings</div>
          <div class="fd-dial__v" style="font-family:var(--font-mono);font-variant-numeric:tabular-nums;">{n}</div>
          <div class="fd-dial__k" style="margin-top:14px;">actors</div>
          <div class="fd-dial__v mono">{actors}</div>
          <div class="fd-dial__k" style="margin-top:14px;">events</div>
          <div class="fd-dial__v mono">{events}</div>
          <div class="fd-dial__k" style="margin-top:14px;">proposals</div>
          <div class="fd-dial__v mono">{proposals}</div>
        </div>"#,
        n = p.findings.len(),
        actors = actor_count,
        events = event_count,
        proposals = proposal_count,
    )
}

/// Single-finding detail. Workbench finding-pattern: serif claim,
/// italic note, conditions table, evidence atoms with stance, history
/// ledger in the margin. Reuses the cached frontier so navigation
/// from /entries/{vfr_id} adds zero round trips.
fn render_finding_html(
    urls: &PublicUrls,
    vfr_id: &str,
    project: &Project,
    bundle: &vela_protocol::bundle::FindingBundle,
    snapshot_hash: &str,
    ingest_commit: Option<&str>,
) -> String {
    use vela_protocol::bundle::FindingBundle;

    let vfr_safe = escape_html(vfr_id);
    let vf_safe = escape_html(&bundle.id);
    let claim_html = escape_html(&bundle.assertion.text);
    let assertion_type = escape_html(&bundle.assertion.assertion_type);
    let (state_label, state_class) = finding_state(bundle);

    // Conditions row — surface only the fields that have content,
    // and present the structured ones as small chips alongside the
    // free-text description.
    let cond = &bundle.conditions;
    let mut cond_rows: Vec<String> = Vec::new();
    if !cond.text.is_empty() {
        cond_rows.push(format!(
            r#"<div class="fd-cond"><dt>scope</dt><dd class="serif">{}</dd></div>"#,
            escape_html(&cond.text),
        ));
    }
    if let Some(d) = &cond.duration {
        cond_rows.push(format!(
            r#"<div class="fd-cond"><dt>duration</dt><dd>{}</dd></div>"#,
            escape_html(d),
        ));
    }
    let conditions_dl = if cond_rows.is_empty() {
        String::from(r#"<p class="empty">No structured conditions declared.</p>"#)
    } else {
        format!(r#"<dl class="fd-conditions">{}</dl>"#, cond_rows.join(""),)
    };

    // Evidence row.
    let ev = &bundle.evidence;
    let mut ev_rows: Vec<String> = Vec::new();
    if !ev.evidence_type.is_empty() {
        ev_rows.push(format!(
            r#"<div class="fd-cond"><dt>type</dt><dd>{}</dd></div>"#,
            escape_html(&ev.evidence_type),
        ));
    }
    if !ev.method.is_empty() {
        ev_rows.push(format!(
            r#"<div class="fd-cond"><dt>method</dt><dd>{}</dd></div>"#,
            escape_html(&ev.method),
        ));
    }
    if !ev.model_system.is_empty() {
        ev_rows.push(format!(
            r#"<div class="fd-cond"><dt>model system</dt><dd>{}</dd></div>"#,
            escape_html(&ev.model_system),
        ));
    }
    let replicated_label = if ev.replicated {
        format!(
            "yes{}",
            ev.replication_count
                .map_or(String::new(), |n| format!(" · {n}×"))
        )
    } else {
        "no".to_string()
    };
    ev_rows.push(format!(
        r#"<div class="fd-cond"><dt>replicated</dt><dd>{}</dd></div>"#,
        escape_html(&replicated_label),
    ));
    let evidence_dl = format!(r#"<dl class="fd-conditions">{}</dl>"#, ev_rows.join(""));

    // Provenance — link to source paper.
    let prov = &bundle.provenance;
    let prov_link = if let Some(doi) = &prov.doi {
        format!(
            r#"<a href="https://doi.org/{}" rel="noopener">{}</a>"#,
            escape_html(doi),
            escape_html(&prov.title),
        )
    } else {
        escape_html(&prov.title)
    };
    let mut prov_meta = Vec::new();
    if !prov.authors.is_empty() {
        let n = prov.authors.len();
        let first = prov.authors.first().map(|a| a.name.as_str()).unwrap_or("");
        prov_meta.push(if n > 1 {
            format!("{first} et al.")
        } else {
            first.to_string()
        });
    }
    if let Some(y) = prov.year {
        prov_meta.push(y.to_string());
    }
    let prov_meta_html = if prov_meta.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="fd-prov-meta">{}</div>"#,
            escape_html(&prov_meta.join(" · ")),
        )
    };

    // Annotations (notes from reviewers).
    let mut annotations_html = String::new();
    if !bundle.annotations.is_empty() {
        let mut items = Vec::new();
        for a in &bundle.annotations {
            items.push(format!(
                r#"<li><span class="ann-author">{author}</span><span class="ann-text">{text}</span></li>"#,
                author = escape_html(&a.author),
                text = escape_html(&a.text),
            ));
        }
        annotations_html = format!(
            r#"<section class="wb-section">
              <div class="wb-section__head">
                <span class="wb-section__num">§3</span>
                <span class="wb-section__t">Annotations · {n}</span>
                <span class="wb-section__aside">notes from reviewers</span>
              </div>
              <ul class="ann-list">{items}</ul>
            </section>"#,
            n = bundle.annotations.len(),
            items = items.join(""),
        );
    }

    // Links — outgoing references. v0.8 splits these:
    //   · Local (vf_…)            → in-frontier click-through
    //   · Cross (vf_…@vfr_…)      → cross-frontier click-through when
    //                               the target's vfr_id is a declared
    //                               dep of this frontier; raw id otherwise.
    let mut links_html = String::new();
    if !bundle.links.is_empty() {
        let id_index: std::collections::HashMap<&str, &FindingBundle> = project
            .findings
            .iter()
            .map(|f| (f.id.as_str(), f))
            .collect();
        let mut items = Vec::new();
        for link in &bundle.links {
            use vela_protocol::bundle::LinkRef;
            let target_label = match LinkRef::parse(&link.target) {
                Ok(LinkRef::Local { vf_id }) => {
                    if let Some(target) = id_index.get(vf_id.as_str()) {
                        let claim = if target.assertion.text.len() > 60 {
                            format!("{}…", &target.assertion.text[..60])
                        } else {
                            target.assertion.text.clone()
                        };
                        format!(
                            r#"<a href="/entries/{vfr}/findings/{vf}">{claim}</a>"#,
                            vfr = vfr_safe,
                            vf = escape_html(&target.id),
                            claim = escape_html(&claim),
                        )
                    } else {
                        // Local target whose vf_id isn't in this frontier
                        // — usually a dangling reference. Render as code.
                        format!("<code>{}</code>", escape_html(&link.target))
                    }
                }
                Ok(LinkRef::Cross { vf_id, vfr_id }) => {
                    let dep = project.dep_for_vfr(&vfr_id);
                    let dep_name = dep
                        .map(|d| d.name.clone())
                        .unwrap_or_else(|| vfr_id.clone());
                    if dep.is_some() {
                        // Declared cross-frontier dep — link out to the
                        // hub's entry page for that frontier and finding.
                        format!(
                            r#"<a href="/entries/{vfr_id_e}/findings/{vf_id_e}">{vf_id_e}<span class="cross-vfr"> @ {dep_name_e}</span></a>"#,
                            vfr_id_e = escape_html(&vfr_id),
                            vf_id_e = escape_html(&vf_id),
                            dep_name_e = escape_html(&dep_name),
                        )
                    } else {
                        // Cross-frontier syntax but no declared dep —
                        // strict validation would have flagged this; on
                        // the hub we just render the raw id with a hint.
                        format!(
                            r#"<code>{}</code> <span class="cross-vfr-bad">(undeclared dep)</span>"#,
                            escape_html(&link.target),
                        )
                    }
                }
                Err(_) => {
                    // Malformed target. Surface raw bytes for debugging.
                    format!("<code>{}</code>", escape_html(&link.target))
                }
            };
            items.push(format!(
                r#"<li><span class="link-rel">{rel}</span> {target}</li>"#,
                rel = escape_html(&link.link_type),
                target = target_label,
            ));
        }
        links_html = format!(
            r#"<section class="wb-section">
              <div class="wb-section__head">
                <span class="wb-section__num">§4</span>
                <span class="wb-section__t">Links · {n}</span>
                <span class="wb-section__aside">references in this frontier</span>
              </div>
              <ul class="link-list">{items}</ul>
            </section>"#,
            n = bundle.links.len(),
            items = items.join(""),
        );
    }

    let live_class = if state_label == "replicated" {
        " wb-chip--live"
    } else {
        ""
    };
    let conf_pct = (bundle.confidence.score.clamp(0.0, 1.0) * 100.0).round() as u32;

    // ── Cite this state ─────────────────────────────────────────────
    // A citation points at content addresses (snapshot hash, ingest
    // commit), not at this page. Both blocks are plain text inside a
    // pre so they copy-paste whole.
    let finding_url = format!(
        "{hub}/entries/{vfr_id}/findings/{vf}",
        hub = urls.hub,
        vf = bundle.id
    );
    let frontier_name = project.project.name.as_str();
    let snapshot_txt = if snapshot_hash.is_empty() {
        "unavailable".to_string()
    } else {
        format!("sha256:{snapshot_hash}")
    };
    let ingest_txt = ingest_commit
        .map(|c| format!(", ingest commit {c}"))
        .unwrap_or_default();
    let cite_year = bundle.created.get(..4).unwrap_or("");
    let cite_plain = format!(
        "{frontier_name}. Finding {vf} (frontier {vfr_id}). Vela frontier state, snapshot {snapshot_txt}{ingest_txt}. {finding_url}",
        vf = bundle.id,
    );
    let cite_bibtex = format!(
        "@misc{{{vf},\n  title        = {{{claim}}},\n  howpublished = {{Vela frontier state: {frontier_name} ({vfr_id}), finding {vf} v{version}}},\n  year         = {{{cite_year}}},\n  url          = {{{finding_url}}},\n  note         = {{snapshot {snapshot_txt}{ingest_txt}}}\n}}",
        vf = bundle.id,
        claim = bundle.assertion.text,
        version = bundle.version,
    );
    let cite_html = format!(
        r#"<section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§5</span>
        <span class="wb-section__t">Cite this state</span>
        <span class="wb-section__aside">hash-pinned · content addresses, not a moving page</span>
      </div>
      <div class="tm-paper">
        <div class="tm-paper__bar"><span>plain text</span></div>
        <div class="tm-paper__body">{plain}</div>
      </div>
      <div class="tm-paper">
        <div class="tm-paper__bar"><span>bibtex</span></div>
        <div class="tm-paper__body">{bibtex}</div>
      </div>
    </section>"#,
        plain = escape_html(&cite_plain),
        bibtex = escape_html(&cite_bibtex),
    );

    let main = format!(
        r#"<div class="fd">
  <article>
    <p class="fd-claim">{claim_html}</p>
    <p class="fd-note">{prov_link}{prov_meta_html}</p>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§1</span>
        <span class="wb-section__t">Conditions</span>
        <span class="wb-section__aside">declared on creation · immutable</span>
      </div>
      {conditions_dl}
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§2</span>
        <span class="wb-section__t">Evidence</span>
        <span class="wb-section__aside">{assertion_type}</span>
      </div>
      {evidence_dl}
    </section>

    {annotations_html}
    {links_html}
    {cite_html}
  </article>

  <aside class="fd-margin">
    <div class="fd-dial">
      <div class="fd-dial__k">state</div>
      <div class="fd-dial__v"><span class="wb-chip{live_class}" style="--chip:var(--state-{state_class});"><span class="wb-chip__dot"></span>{state_label}</span></div>
      <div class="fd-dial__k" style="margin-top:16px;">confidence</div>
      <div class="fd-dial__v" style="font-family:var(--font-mono);font-variant-numeric:tabular-nums;">{score:.2}</div>
      <div class="fd-dial__gauge"><i style="width:{conf_pct}%"></i></div>
    </div>

    <div class="fd-dial">
      <div class="fd-dial__k">vf_id</div>
      <div class="fd-dial__v mono">{vf_safe}</div>
      <div class="fd-dial__k" style="margin-top:14px;">version</div>
      <div class="fd-dial__v mono">{version}</div>
      <div class="fd-dial__k" style="margin-top:14px;">created</div>
      <div class="fd-dial__v mono">{created}</div>
    </div>

    <div class="fd-dial">
      <div class="fd-dial__k">JSON</div>
      <div style="font-family:var(--font-mono);font-size:12px;line-height:1.6;color:var(--ink-1);margin-top:6px;">
        <a href="/entries/{vfr_safe}/findings/{vf_safe}" style="border-bottom:1px solid var(--rule-3);">/entries/{vfr_safe}/findings/{vf_safe}</a>
        <div style="color:var(--ink-3);margin-top:4px;">with <code>Accept: application/json</code></div>
      </div>
    </div>
  </aside>
</div>"#,
        score = bundle.confidence.score,
        version = bundle.version,
        created = escape_html(&bundle.created),
    );

    shell(
        urls,
        &format!("Vela Hub · {}", &bundle.id),
        "entries",
        &format!("03 · Finding · <span style=\"color:var(--ink-2);\">{vf_safe}</span>"),
        "Finding",
        &claim_html,
        &format!(
            r#"<a href="/entries/{vfr_safe}">← {vfr_safe}</a><span>·</span><a href="/entries/{vfr_safe}/findings/{vf_safe}">JSON</a><span>·</span><a href="/entries/{vfr_safe}/proof">Proof packet →</a>"#
        ),
        &main,
        &format!("{vf_safe} @ {vfr_safe}"),
    )
}

fn render_finding_unavailable_html(urls: &PublicUrls, vfr_id: &str, vf_id: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let vf_safe = escape_html(vf_id);
    let main = format!(
        r#"<p class="t-lead">The frontier state for <code>{vfr_safe}</code> is not currently available in the hub projections, so we cannot show finding <code>{vf_safe}</code>. The manifest is still verifiable; pull the frontier with the CLI to inspect.</p>
<p class="t-lead"><a href="/entries/{vfr_safe}" style="border-bottom:1px solid var(--rule-3);">← back to entry</a></p>"#
    );
    shell(
        urls,
        "Vela Hub · finding unavailable",
        "entries",
        "503 · Frontier unavailable",
        "Frontier unavailable",
        "The manifest is verifiable from the hub; live reads require promoted frontier state.",
        "",
        &main,
        &vfr_safe,
    )
}

fn render_finding_not_found_html(urls: &PublicUrls, vfr_id: &str, vf_id: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let vf_safe = escape_html(vf_id);
    let main = format!(
        r#"<p class="t-lead">No finding <code>{vf_safe}</code> in <code>{vfr_safe}</code>. The id may belong to a different frontier or an earlier publish.</p>
<p class="t-lead"><a href="/entries/{vfr_safe}" style="border-bottom:1px solid var(--rule-3);">← back to entry</a></p>"#
    );
    shell(
        urls,
        "Vela Hub · finding not found",
        "entries",
        "404 · Finding not found",
        "Not found",
        "Findings are content-addressed; their ids change with content.",
        "",
        &main,
        &vfr_safe,
    )
}

/// Pack review page body. Renders one `ReleasedDiffPackRecord` — the
/// release metadata, the verdict state (pending until a
/// `diff_pack.reviewed` event lands), and the member proposals with
/// their Evidence Diff links. The verdict reason lives on the review
/// event itself, so it is resolved from the canonical event log.
fn render_pack_html(
    urls: &PublicUrls,
    vfr_id: &str,
    project: &Project,
    rec: &vela_protocol::released_diff_pack::ReleasedDiffPackRecord,
) -> String {
    use vela_protocol::released_diff_pack::ReleasedVerdict;

    let vfr_safe = escape_html(vfr_id);
    let pack_safe = escape_html(&rec.pack_id);
    let summary = escape_html(&rec.summary);
    let aggregate_kind = escape_html(&rec.aggregate_kind);
    let released_at = escape_html(&rec.released_at);
    let released_event = escape_html(&rec.released_event_id);
    let frontier_name = escape_html(&project.project.name);

    // ── Verdict state ───────────────────────────────────────────────
    let (verdict_label, verdict_class) = match rec.verdict {
        None => ("pending", "stale"),
        Some(ReleasedVerdict::Accept) => ("accepted", "ok"),
        Some(ReleasedVerdict::Reject) => ("rejected", "lost"),
        Some(ReleasedVerdict::Revise) => ("revise", "warn"),
    };
    let verdict_chip = format!(
        r#"<span class="wb-chip" style="--chip:var(--state-{verdict_class});"><span class="wb-chip__dot"></span>{verdict_label}</span>"#
    );
    // The reason is recorded on the `diff_pack.reviewed` event, not on
    // the replayed record — resolve it from the log when present.
    let verdict_reason = rec
        .verdict_event_id
        .as_deref()
        .and_then(|id| project.events.iter().find(|e| e.id == id))
        .map(|e| e.reason.as_str())
        .filter(|r| !r.is_empty());

    let mut verdict_rows: Vec<String> = vec![format!(
        r#"<div class="fd-cond"><dt>state</dt><dd>{verdict_chip}</dd></div>"#
    )];
    if let Some(reviewer) = &rec.reviewer_actor {
        verdict_rows.push(format!(
            r#"<div class="fd-cond"><dt>reviewer</dt><dd>{}</dd></div>"#,
            escape_html(reviewer),
        ));
    }
    if let Some(vev) = &rec.verdict_event_id {
        verdict_rows.push(format!(
            r#"<div class="fd-cond"><dt>verdict_event_id</dt><dd>{}</dd></div>"#,
            escape_html(vev),
        ));
    }
    if let Some(reason) = verdict_reason {
        verdict_rows.push(format!(
            r#"<div class="fd-cond"><dt>reason</dt><dd class="serif">{}</dd></div>"#,
            escape_html(reason),
        ));
    }
    let verdict_html = if rec.verdict.is_none() {
        format!(
            r#"<dl class="fd-conditions">{rows}</dl>
      <p class="fd-prov-meta">No <code>diff_pack.reviewed</code> event has landed. Acceptance is a key-custody human decision; the hub only mirrors it.</p>"#,
            rows = verdict_rows.join(""),
        )
    } else {
        format!(
            r#"<dl class="fd-conditions">{rows}</dl>"#,
            rows = verdict_rows.join(""),
        )
    };

    // ── Members ─────────────────────────────────────────────────────
    // Each member id links to the read-only Evidence Diff projection;
    // kind/target are resolved from the frontier's proposal store when
    // the proposal is present in this projection.
    let member_li = |member_id: &str, lane: &str| -> String {
        let member_safe = escape_html(member_id);
        let meta = project
            .proposals
            .iter()
            .find(|p| p.id == member_id)
            .map(|p| {
                format!(
                    r#"<span class="cross-vfr"> {kind} → {ttype} {tid}</span>"#,
                    kind = escape_html(&p.kind),
                    ttype = escape_html(&p.target.r#type),
                    tid = escape_html(&p.target.id),
                )
            })
            .unwrap_or_else(|| {
                r#"<span class="cross-vfr"> (proposal not in this projection)</span>"#.to_string()
            });
        format!(
            r#"<li><span class="link-rel">{lane}</span> <span><code>{member_safe}</code>{meta} · <a href="/entries/{vfr_safe}/proposals/{member_safe}/evidence-diff">evidence diff (JSON)</a></span></li>"#
        )
    };
    let n_members = rec.applied_members.len() + rec.sdk_only_members.len();
    // A PENDING pack is exactly what a reviewer opens this page for, and
    // the release event carries its proposed members — render them, each
    // with its evidence-diff link, instead of "Members · 0".
    let n_display = if n_members == 0 && rec.verdict.is_none() {
        rec.member_proposals.len()
    } else {
        n_members
    };
    let members_html = if n_members == 0 {
        if rec.verdict.is_none() && !rec.member_proposals.is_empty() {
            let items: String = rec
                .member_proposals
                .iter()
                .map(|m| member_li(m, "proposed"))
                .collect();
            format!(
                r#"<ul class="link-list">{items}</ul><p class="empty">Proposed members from the signed release event; attribution finalizes with the verdict (<code>diff_pack.reviewed</code>).</p>"#
            )
        } else if rec.verdict.is_none() {
            format!(
                r#"<p class="empty">Member attribution lands with the verdict (<code>diff_pack.reviewed</code>). Until then, the signed pack body at <a href="/diff-packs/{pack_safe}">/diff-packs/{pack_safe}</a> lists the member proposal ids.</p>"#
            )
        } else {
            r#"<p class="empty">The verdict applied no members.</p>"#.to_string()
        }
    } else {
        let items: String = rec
            .applied_members
            .iter()
            .map(|m| member_li(m, "applied"))
            .chain(
                rec.sdk_only_members
                    .iter()
                    .map(|m| member_li(m, "sdk-only")),
            )
            .collect();
        format!(r#"<ul class="link-list">{items}</ul>"#)
    };

    let main = format!(
        r#"<div class="fd">
  <article>
    <p class="fd-claim">{summary}</p>
    <p class="fd-note">A released Scientific Diff Pack on <a href="/entries/{vfr_safe}">{frontier_name}</a>. Pure replay state from the canonical event log — the hub renders it, never adjudicates it.</p>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§1</span>
        <span class="wb-section__t">Release</span>
        <span class="wb-section__aside">diff_pack.released · replayed</span>
      </div>
      <dl class="fd-conditions">
        <div class="fd-cond"><dt>pack_id</dt><dd>{pack_safe}</dd></div>
        <div class="fd-cond"><dt>frontier</dt><dd><a href="/entries/{vfr_safe}">{vfr_safe}</a></dd></div>
        <div class="fd-cond"><dt>aggregate_kind</dt><dd>{aggregate_kind}</dd></div>
        <div class="fd-cond"><dt>released_at</dt><dd>{released_at}</dd></div>
        <div class="fd-cond"><dt>released_event_id</dt><dd>{released_event}</dd></div>
      </dl>
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§2</span>
        <span class="wb-section__t">Verdict</span>
        <span class="wb-section__aside">diff_pack.reviewed · key-custody</span>
      </div>
      {verdict_html}
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§3</span>
        <span class="wb-section__t">Members · {n_display}</span>
        <span class="wb-section__aside">proposed · applied · sdk-only</span>
      </div>
      {members_html}
    </section>
  </article>

  <aside class="fd-margin">
    <div class="fd-dial">
      <div class="fd-dial__k">verdict</div>
      <div class="fd-dial__v">{verdict_chip}</div>
      <div class="fd-dial__k" style="margin-top:16px;">released</div>
      <div class="fd-dial__v mono">{released_at}</div>
      <div class="fd-dial__k" style="margin-top:16px;">members</div>
      <div class="fd-dial__v mono">{n_display}</div>
    </div>

    <div class="fd-dial">
      <div class="fd-dial__k">pack_id</div>
      <div class="fd-dial__v mono">{pack_safe}</div>
      <div class="fd-dial__k" style="margin-top:14px;">released_event_id</div>
      <div class="fd-dial__v mono">{released_event}</div>
    </div>

    <div class="fd-dial">
      <div class="fd-dial__k">JSON</div>
      <div style="font-family:var(--font-mono);font-size:12px;line-height:1.6;color:var(--ink-1);margin-top:6px;">
        <a href="/entries/{vfr_safe}/packs/{pack_safe}" style="border-bottom:1px solid var(--rule-3);">/entries/{vfr_safe}/packs/{pack_safe}</a>
        <div style="color:var(--ink-3);margin-top:4px;">with <code>Accept: application/json</code></div>
        <a href="/diff-packs/{pack_safe}" style="border-bottom:1px solid var(--rule-3);margin-top:8px;display:inline-block;">/diff-packs/{pack_safe}</a>
        <div style="color:var(--ink-3);margin-top:4px;">signed pack body</div>
      </div>
    </div>
  </aside>
</div>"#,
    );

    shell(
        urls,
        &format!("Vela Hub · {}", rec.pack_id),
        "entries",
        &format!("03 · Pack · <span style=\"color:var(--ink-2);\">{pack_safe}</span>"),
        "Diff pack review",
        &summary,
        &format!(
            r#"<a href="/entries/{vfr_safe}">← {vfr_safe}</a><span>·</span><a href="/entries/{vfr_safe}/packs/{pack_safe}">JSON</a><span>·</span><a href="/diff-packs/{pack_safe}">Pack body</a>"#
        ),
        &main,
        &format!("{pack_safe} @ {vfr_safe}"),
    )
}

fn render_pack_unavailable_html(urls: &PublicUrls, vfr_id: &str, pack_id: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let pack_safe = escape_html(pack_id);
    let main = format!(
        r#"<p class="t-lead">The frontier state for <code>{vfr_safe}</code> is not currently available in the hub projections, so we cannot show pack <code>{pack_safe}</code>. The manifest is still verifiable; pull the frontier with the CLI to inspect.</p>
<p class="t-lead"><a href="/entries/{vfr_safe}" style="border-bottom:1px solid var(--rule-3);">← back to entry</a></p>"#
    );
    shell(
        urls,
        "Vela Hub · pack unavailable",
        "entries",
        "503 · Frontier unavailable",
        "Frontier unavailable",
        "The manifest is verifiable from the hub; live reads require promoted frontier state.",
        "",
        &main,
        &vfr_safe,
    )
}

fn render_pack_not_found_html(urls: &PublicUrls, vfr_id: &str, pack_id: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let pack_safe = escape_html(pack_id);
    let main = format!(
        r#"<p class="t-lead">No released pack <code>{pack_safe}</code> on <code>{vfr_safe}</code>. A pack appears here once a <code>diff_pack.released</code> event has been applied on this frontier's canonical log.</p>
<p class="t-lead"><a href="/entries/{vfr_safe}" style="border-bottom:1px solid var(--rule-3);">← back to entry</a></p>"#
    );
    shell(
        urls,
        "Vela Hub · pack not found",
        "entries",
        "404 · Pack not found",
        "Not found",
        "Packs are content-addressed; their ids change with content.",
        "",
        &main,
        &vfr_safe,
    )
}

/// Directory name a `git clone` of `remote` produces: the last path
/// segment with any `.git` suffix removed. Handles both HTTPS and
/// scp-style SSH remotes.
fn repo_dir_from_remote(remote: &str) -> String {
    let dir = remote
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .rsplit(['/', ':'])
        .next()
        .unwrap_or("");
    if dir.is_empty() {
        "<repo>".to_string()
    } else {
        dir.to_string()
    }
}

/// The "verify this yourself" page body: clone, replay, reproduce.
fn render_reproduce_html(urls: &PublicUrls, vfr_id: &str, rec: &Value, git_subdir: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let s = |key: &str| -> String {
        rec.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    let git_remote = s("git_remote");
    let git_ref = s("git_ref");
    let last_commit = s("last_ingested_commit");
    let last_at = s("last_ingested_at");
    let ingest_error = s("ingest_error");

    let repo_dir = repo_dir_from_remote(&git_remote);
    let cd_path = if git_subdir.is_empty() || git_subdir == "." {
        repo_dir
    } else {
        format!("{repo_dir}/{git_subdir}")
    };

    let remote_safe = escape_html(&git_remote);
    let cd_safe = escape_html(&cd_path);
    let remote_dd = if git_remote.starts_with("http") {
        format!(r#"<a href="{remote_safe}" rel="noopener">{remote_safe}</a>"#)
    } else {
        remote_safe.clone()
    };

    let mut cursor_rows: Vec<String> = vec![
        format!(r#"<div class="fd-cond"><dt>git_remote</dt><dd>{remote_dd}</dd></div>"#),
        format!(
            r#"<div class="fd-cond"><dt>git_ref</dt><dd>{}</dd></div>"#,
            escape_html(&git_ref),
        ),
    ];
    if !git_subdir.is_empty() && git_subdir != "." {
        cursor_rows.push(format!(
            r#"<div class="fd-cond"><dt>git_subdir</dt><dd>{}</dd></div>"#,
            escape_html(git_subdir),
        ));
    }
    cursor_rows.push(format!(
        r#"<div class="fd-cond"><dt>last_ingested_commit</dt><dd>{}</dd></div>"#,
        if last_commit.is_empty() {
            "— (not yet ingested)".to_string()
        } else {
            escape_html(&last_commit)
        },
    ));
    cursor_rows.push(format!(
        r#"<div class="fd-cond"><dt>last_ingested_at</dt><dd>{}</dd></div>"#,
        if last_at.is_empty() {
            "—".to_string()
        } else {
            escape_html(&last_at)
        },
    ));
    if !ingest_error.is_empty() {
        cursor_rows.push(format!(
            r#"<div class="fd-cond"><dt>ingest_error</dt><dd>{}</dd></div>"#,
            escape_html(&ingest_error),
        ));
    }
    let cursor_dl = format!(r#"<dl class="fd-conditions">{}</dl>"#, cursor_rows.join(""));

    let short_commit = if last_commit.is_empty() {
        "—".to_string()
    } else {
        escape_html(&last_commit[..last_commit.len().min(12)])
    };

    let main = format!(
        r#"<div class="fd">
  <article>
    <p class="fd-claim">Verify this yourself</p>
    <p class="fd-note">The hub is an index, not an authority. This sequence clones the frontier's registered repository, replays the signed event log, and re-runs the frozen verifiers over every witness — re-deriving everything the hub shows, locally, with no hub dependency.</p>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§1</span>
        <span class="wb-section__t">Run it</span>
        <span class="wb-section__aside">clone · replay · reproduce</span>
      </div>
      <div class="tm-paper">
        <div class="tm-paper__bar"><span>git clone · vela check · vela reproduce</span></div>
        <div class="tm-paper__body"><span class="tm-ps">$</span> <span class="tm-cmd">git clone</span> {remote_safe} &amp;&amp; <span class="tm-cmd">cd</span> {cd_safe}
<span class="tm-ps">$</span> <span class="tm-cmd">vela check</span> . <span class="tm-flag">--strict</span>     <span class="tm-flag"># replay + signatures + parity</span>
<span class="tm-ps">$</span> <span class="tm-cmd">vela reproduce</span> .          <span class="tm-flag"># frozen verifiers re-check every witness</span></div>
      </div>
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§2</span>
        <span class="wb-section__t">Ingest cursor</span>
        <span class="wb-section__aside">what this hub's index was derived from</span>
      </div>
      {cursor_dl}
    </section>
  </article>

  <aside class="fd-margin">
    <div class="fd-dial">
      <div class="fd-dial__k">last ingested commit</div>
      <div class="fd-dial__v mono">{short_commit}</div>
      <div class="fd-dial__k" style="margin-top:16px;">ingested at</div>
      <div class="fd-dial__v mono">{last_at_dial}</div>
    </div>

    <div class="fd-dial">
      <div class="fd-dial__k">JSON</div>
      <div style="font-family:var(--font-mono);font-size:12px;line-height:1.6;color:var(--ink-1);margin-top:6px;">
        <a href="/entries/{vfr_safe}/git-remote" style="border-bottom:1px solid var(--rule-3);">/entries/{vfr_safe}/git-remote</a>
        <div style="color:var(--ink-3);margin-top:4px;">registration + cursor</div>
      </div>
    </div>
  </aside>
</div>"#,
        last_at_dial = if last_at.is_empty() {
            "—".to_string()
        } else {
            escape_html(&last_at)
        },
    );

    shell(
        urls,
        &format!("Vela Hub · reproduce · {vfr_id}"),
        "entries",
        &format!("05 · Reproduce · <span style=\"color:var(--ink-2);\">{vfr_safe}</span>"),
        "Reproduce",
        "Two commands re-derive this frontier's state from its source repository. Nothing here requires trusting the hub.",
        &format!(
            r#"<a href="/entries/{vfr_safe}">← Entry</a><span>·</span><a href="/entries/{vfr_safe}/proof">Proof packet →</a>"#
        ),
        &main,
        &format!("{vfr_safe} · reproduce"),
    )
}

fn render_reproduce_no_remote_html(urls: &PublicUrls, vfr_id: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let main = format!(
        r#"<p class="t-lead">No git remote is registered for <code>{vfr_safe}</code>, so there is no clone-and-replay recipe to hand you. That is the honest answer: the hub only knows a source repository when the frontier's owner registers one with <code>vela hub register-git</code>.</p>
<p class="t-lead">The signed manifest and its hashes remain verifiable on the entry page.</p>
<p class="t-lead"><a href="/entries/{vfr_safe}" style="border-bottom:1px solid var(--rule-3);">← back to entry</a></p>"#
    );
    shell(
        urls,
        "Vela Hub · reproduce",
        "entries",
        &format!("05 · Reproduce · <span style=\"color:var(--ink-2);\">{vfr_safe}</span>"),
        "No registered repository",
        "Reproduction needs a source repository; this frontier has not registered one.",
        &format!(r#"<a href="/entries/{vfr_safe}">← Entry</a>"#),
        &main,
        &vfr_safe,
    )
}

fn render_no_packet_html(urls: &PublicUrls, vfr_id: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let main = format!(
        r#"<p class="t-lead">No proof packet has been generated for <code>{vfr_safe}</code> yet, or this hub instance was not started with <code>VELA_PROOF_PACKET_DIR</code> pointing at a packet directory.</p>
<p class="t-lead">Generate one locally with the CLI:</p>
<div class="tm-paper">
  <div class="tm-paper__bar"><span>vela frontier export · {vfr_safe}</span></div>
  <div class="tm-paper__body"><span class="tm-ps">$</span> <span class="tm-cmd">vela frontier export</span> <span class="tm-flag">--packet</span> &lt;path/to/frontier.json&gt; <span class="tm-flag">--out</span> ./packet</div>
</div>
<p class="t-lead">Then point this hub at the packet directory and reload:</p>
<div class="tm-paper">
  <div class="tm-paper__bar"><span>vela-hub serve</span></div>
  <div class="tm-paper__body"><span class="tm-ps">$</span> <span class="tm-cmd">VELA_PROOF_PACKET_DIR=./packet</span> vela-hub</div>
</div>
<p class="t-lead"><a href="/entries/{vfr_safe}" style="border-bottom:1px solid var(--rule-3);">← back to entry</a></p>"#
    );
    shell(
        urls,
        "Vela Hub · no proof packet",
        "entries",
        &format!("04 · Proof · <span style=\"color:var(--ink-2);\">{vfr_safe}</span>"),
        "No proof packet",
        "The hub has no packet for this entry. Generate one with the CLI and serve it via VELA_PROOF_PACKET_DIR.",
        &format!(r#"<a href="/entries/{vfr_safe}">← Entry</a>"#),
        &main,
        &vfr_safe,
    )
}

/// Render the proof packet inline: manifest summary, proof-trace
/// summary, lock summary, included-files table with sha256 hashes.
/// The skeptic-facing seam.
fn render_proof_packet_html(
    urls: &PublicUrls,
    vfr_id: &str,
    dir: &std::path::Path,
    manifest: &Value,
    proof_trace: Option<&Value>,
    lock: Option<&Value>,
) -> String {
    let vfr_safe = escape_html(vfr_id);
    let dir_safe = escape_html(&dir.display().to_string());

    // ─── Manifest summary ──────────────────────────────────────────
    let generated_at = manifest
        .get("generated_at")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let packet_format = manifest
        .get("packet_format")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let packet_version = manifest
        .get("packet_version")
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let source = manifest.get("source");
    let vela_version = source
        .and_then(|s| s.get("vela_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let compiler = source
        .and_then(|s| s.get("compiler"))
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let project_name = source
        .and_then(|s| s.get("project_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let description = source
        .and_then(|s| s.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("—");
    let schema = source
        .and_then(|s| s.get("schema"))
        .and_then(|v| v.as_str())
        .unwrap_or("—");

    let stats = manifest.get("stats");
    let stat = |k: &str| -> i64 {
        stats
            .and_then(|s| s.get(k))
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
    };
    let stats_html = format!(
        r#"<dl class="fd-conditions">
  <div class="fd-cond"><dt>findings</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>contested</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>gaps</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>contradiction edges</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>evidence atoms</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>condition records</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>sources</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>proposals</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>review events</dt><dd>{}</dd></div>
</dl>"#,
        stat("findings"),
        stat("contested"),
        stat("gaps"),
        stat("contradiction_edges"),
        stat("evidence_atoms"),
        stat("condition_records"),
        stat("sources"),
        stat("proposals"),
        stat("review_events"),
    );

    // ─── Proof-trace summary ───────────────────────────────────────
    let trace_html = if let Some(t) = proof_trace {
        let s = |k: &str| -> &str { t.get(k).and_then(|v| v.as_str()).unwrap_or("—") };
        let checked: Vec<String> = t
            .get("checked_artifacts")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(escape_html))
                    .collect()
            })
            .unwrap_or_default();
        let checked_list = if checked.is_empty() {
            String::from(r#"<p class="empty">no checked_artifacts in trace</p>"#)
        } else {
            format!(
                r#"<ul class="pp-checked">{}</ul>"#,
                checked
                    .iter()
                    .map(|c| format!(r#"<li><code>{c}</code></li>"#))
                    .collect::<String>()
            )
        };
        let caveats: Vec<String> = t
            .get("caveats")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(escape_html))
                    .collect()
            })
            .unwrap_or_default();
        let caveats_html = if caveats.is_empty() {
            String::new()
        } else {
            format!(
                r#"<dl class="fd-conditions"><div class="fd-cond"><dt>caveats</dt><dd class="serif"><ul class="pp-caveats">{}</ul></dd></div></dl>"#,
                caveats
                    .iter()
                    .map(|c| format!(r#"<li>{c}</li>"#))
                    .collect::<String>()
            )
        };
        format!(
            r#"<dl class="fd-conditions">
  <div class="fd-cond"><dt>trace_version</dt><dd>{tv}</dd></div>
  <div class="fd-cond"><dt>schema_version</dt><dd>{sv}</dd></div>
  <div class="fd-cond"><dt>source_hash</dt><dd>{sh}</dd></div>
  <div class="fd-cond"><dt>snapshot_hash</dt><dd>{snh}</dd></div>
  <div class="fd-cond"><dt>event_log_hash</dt><dd>{eh}</dd></div>
  <div class="fd-cond"><dt>proposal_state_hash</dt><dd>{ph}</dd></div>
  <div class="fd-cond"><dt>replay_status</dt><dd>{rs}</dd></div>
  <div class="fd-cond"><dt>status</dt><dd>{st}</dd></div>
</dl>
<h4 class="pp-subhead">Checked artifacts ({n})</h4>
{checked_list}
{caveats_html}"#,
            tv = escape_html(s("trace_version")),
            sv = escape_html(s("schema_version")),
            sh = escape_html(s("source_hash")),
            snh = escape_html(s("snapshot_hash")),
            eh = escape_html(s("event_log_hash")),
            ph = escape_html(s("proposal_state_hash")),
            rs = escape_html(s("replay_status")),
            st = escape_html(s("status")),
            n = checked.len(),
        )
    } else {
        String::from(r#"<p class="empty">No proof-trace.json in this packet.</p>"#)
    };

    // ─── Lock summary ──────────────────────────────────────────────
    let lock_html = if let Some(l) = lock {
        let lock_format = l.get("lock_format").and_then(|v| v.as_str()).unwrap_or("—");
        let lock_generated = l
            .get("generated_at")
            .and_then(|v| v.as_str())
            .unwrap_or("—");
        let n_files = l
            .get("files")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        format!(
            r#"<dl class="fd-conditions">
  <div class="fd-cond"><dt>lock_format</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>generated_at</dt><dd>{}</dd></div>
  <div class="fd-cond"><dt>locked file count</dt><dd>{}</dd></div>
</dl>"#,
            escape_html(lock_format),
            escape_html(lock_generated),
            n_files,
        )
    } else {
        String::from(r#"<p class="empty">No packet.lock.json in this packet.</p>"#)
    };

    // ─── Included files table ──────────────────────────────────────
    // Mark canonical proof-bearing files (the set listed by
    // proof-trace.json's checked_artifacts) in gold.
    let canonical: std::collections::HashSet<String> = proof_trace
        .and_then(|t| t.get("checked_artifacts"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let empty: Vec<Value> = Vec::new();
    let included = manifest
        .get("included_files")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    let mut total_bytes: u64 = 0;
    let mut rows = String::new();
    for f in included {
        let path = f.get("path").and_then(|v| v.as_str()).unwrap_or("—");
        let bytes = f.get("bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let sha = f.get("sha256").and_then(|v| v.as_str()).unwrap_or("—");
        total_bytes += bytes;
        let cls = if canonical.contains(path) {
            "pp-row pp-row--canonical"
        } else {
            "pp-row"
        };
        rows.push_str(&format!(
            r#"<tr class="{cls}"><td class="pp-path"><code>{}</code></td><td class="pp-bytes">{}</td><td class="pp-sha"><code title="{}">{}</code></td></tr>"#,
            escape_html(path),
            bytes,
            escape_html(sha),
            escape_html(&sha[..sha.len().min(16)]),
        ));
    }

    // ─── Page assembly ─────────────────────────────────────────────
    let main = format!(
        r#"<div class="fd">
  <article>
    <p class="fd-claim">Proof packet for {project}</p>
    <p class="fd-note">{description}</p>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§1</span>
        <span class="wb-section__t">Manifest</span>
        <span class="wb-section__aside">{packet_format} · {packet_version}</span>
      </div>
      <dl class="fd-conditions">
        <div class="fd-cond"><dt>generated_at</dt><dd>{generated_at}</dd></div>
        <div class="fd-cond"><dt>vela_version</dt><dd>{vela_version}</dd></div>
        <div class="fd-cond"><dt>compiler</dt><dd>{compiler}</dd></div>
        <div class="fd-cond"><dt>schema</dt><dd>{schema}</dd></div>
      </dl>
      <h4 class="pp-subhead">Stats</h4>
      {stats_html}
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§2</span>
        <span class="wb-section__t">Proof trace</span>
        <span class="wb-section__aside">canonical-JSON SHA-256 chain</span>
      </div>
      {trace_html}
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§3</span>
        <span class="wb-section__t">Lock</span>
        <span class="wb-section__aside">packet integrity</span>
      </div>
      {lock_html}
    </section>

    <section class="wb-section">
      <div class="wb-section__head">
        <span class="wb-section__num">§4</span>
        <span class="wb-section__t">Included files · {n_files}</span>
        <span class="wb-section__aside">canonical files in gold · sha256 truncated to 16</span>
      </div>
      <table class="pp-table">
        <thead><tr><th>path</th><th class="num">bytes</th><th>sha256</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </section>
  </article>

  <aside class="fd-margin">
    <div class="fd-dial">
      <div class="fd-dial__k">findings</div>
      <div class="fd-dial__v" style="font-family:var(--font-mono);font-variant-numeric:tabular-nums;">{n_findings}</div>
      <div class="fd-dial__k" style="margin-top:14px;">total bytes</div>
      <div class="fd-dial__v mono">{total_kb} KB</div>
      <div class="fd-dial__k" style="margin-top:14px;">files</div>
      <div class="fd-dial__v mono">{n_files}</div>
      <div class="fd-dial__k" style="margin-top:14px;">generated</div>
      <div class="fd-dial__v mono">{generated_at}</div>
    </div>

    <div class="fd-dial">
      <div class="fd-dial__k">download</div>
      <p style="margin:8px 0 0;font-family:var(--font-sans);font-size:13px;line-height:1.5;color:var(--ink-2);">
        <a href="/entries/{vfr_safe}/proof/download" style="border-bottom:1px solid color-mix(in oklab, var(--gold) 56%, transparent);">↓ {vfr_safe}-proof-packet.tar.gz</a>
      </p>
      <p style="margin:10px 0 0;font-family:var(--font-mono);font-size:11px;color:var(--ink-3);">
        verify locally with <code>shasum -a 256</code>
      </p>
    </div>

    <div class="fd-dial">
      <div class="fd-dial__k">source</div>
      <p style="margin:6px 0 0;font-family:var(--font-mono);font-size:11px;color:var(--ink-3);word-break:break-all;">{dir_safe}</p>
      <p style="margin:10px 0 0;font-family:var(--font-mono);font-size:11px;color:var(--ink-3);">
        <a href="/entries/{vfr_safe}" style="border-bottom:1px solid var(--rule-3);">← /entries/{vfr_safe}</a>
      </p>
    </div>
  </aside>
</div>"#,
        n_findings = stat("findings"),
        n_files = included.len(),
        total_kb = total_bytes / 1024,
        project = escape_html(project_name),
        description = escape_html(description),
        generated_at = escape_html(generated_at),
        vela_version = escape_html(vela_version),
        compiler = escape_html(compiler),
        schema = escape_html(schema),
        packet_format = escape_html(packet_format),
        packet_version = escape_html(packet_version),
    );

    shell(
        urls,
        &format!("Vela Hub · proof · {vfr_id}"),
        "entries",
        &format!("04 · Proof · <span style=\"color:var(--ink-2);\">{vfr_safe}</span>"),
        "Proof packet",
        "Manifest, signed-trace chain, integrity lock, and the file-by-file SHA-256 table the skeptic actually wants to see.",
        &format!(
            r#"<a href="/entries/{vfr_safe}">← Entry</a><span>·</span><a href="/entries/{vfr_safe}/proof/download">Download (.tar.gz)</a>"#
        ),
        &main,
        &format!("{vfr_safe} · proof packet"),
    )
}

fn render_not_found_html(urls: &PublicUrls, vfr_id: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let main = format!(
        r#"<p class="t-lead">No entry for <code>{vfr_safe}</code> in this hub. The id may belong to a different registry, or the publisher may not have pushed yet.</p>
<p class="t-lead"><a href="/entries" style="border-bottom:1px solid var(--rule-3);">← back to entries</a></p>"#
    );
    shell(
        urls,
        "Vela Hub · not found",
        "entries",
        "404 · Not found",
        "Not found",
        "Anyone can publish a signed manifest at this id. Until then, there is nothing here.",
        "",
        &main,
        &vfr_safe,
    )
}

fn render_entry_unavailable_html(urls: &PublicUrls, vfr_id: &str, reason: &str) -> String {
    let vfr_safe = escape_html(vfr_id);
    let reason_safe = escape_html(reason);
    let main = format!(
        r#"<p class="t-lead">The latest publish for <code>{vfr_safe}</code> is present in the registry, but it was not promoted to live frontier state.</p>
<div class="fd-cond"><dt>status</dt><dd>unavailable</dd></div>
<div class="fd-cond"><dt>reason</dt><dd>{reason_safe}</dd></div>
<p class="t-lead"><a href="/entries" style="border-bottom:1px solid var(--rule-3);">← back to entries</a></p>"#
    );
    shell(
        urls,
        "Vela Hub · unavailable",
        "entries",
        "424 · Unavailable",
        "Frontier unavailable",
        "The signed registry row remains auditable. It is not served as live state.",
        "",
        &main,
        &vfr_safe,
    )
}

#[cfg(test)]
mod reproduce_page_tests {
    use super::repo_dir_from_remote;

    #[test]
    fn https_remote_with_git_suffix() {
        assert_eq!(
            repo_dir_from_remote("https://github.com/constellate-science/erdos-frontier.git"),
            "erdos-frontier"
        );
    }

    #[test]
    fn https_remote_without_suffix_and_trailing_slash() {
        assert_eq!(
            repo_dir_from_remote("https://github.com/constellate-science/vela/"),
            "vela"
        );
    }

    #[test]
    fn scp_style_ssh_remote() {
        assert_eq!(
            repo_dir_from_remote("git@github.com:constellate-science/vela.git"),
            "vela"
        );
    }

    #[test]
    fn empty_remote_falls_back_to_placeholder() {
        assert_eq!(repo_dir_from_remote(""), "<repo>");
    }
}

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
