//! Event-first hub backfill.
//!
//! Selects the latest registry row per `vfr_id`, fetches the substrate
//! from `frontier_snapshots.blob_url` when available and otherwise from
//! `network_locator`, verifies the signed manifest plus snapshot and
//! event-log hashes, then promotes verified frontiers into the event
//! and projection tables.
//!
//! Usage:
//!   VELA_HUB_DATABASE_URL="postgres://..." \
//!     cargo run -p vela-hub --bin vela-hub-backfill-event-first -- --dry-run
//!
//! Run against a Neon branch first. Rows that fail verification are
//! recorded in `frontier_publish_audit` on real runs and are not
//! promoted as live frontiers.

use std::env;
use std::time::Duration;

use serde_json::Value;
use sqlx::{Row, postgres::PgPoolOptions};
use vela_hub::db::{HubDb, SnapshotMeta, ensure_postgres_event_first_schema};
use vela_protocol::events::{event_log_hash, snapshot_hash};
use vela_protocol::project::Project;
use vela_protocol::registry::{RegistryEntry, verify_entry};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let _ = dotenvy::dotenv();

    let dry_run = env::args().any(|a| a == "--dry-run");
    let db_url = env::var("VELA_HUB_DATABASE_URL").map_err(|_| "VELA_HUB_DATABASE_URL not set")?;
    if !db_url.starts_with("postgres://") && !db_url.starts_with("postgresql://") {
        return Err("event-first backfill targets Postgres only".into());
    }

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .acquire_timeout(Duration::from_secs(15))
        .connect(&db_url)
        .await?;
    ensure_postgres_event_first_schema(&pool).await?;
    let db = HubDb::Postgres(pool.clone());
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(90))
        .user_agent("vela-hub-backfill-event-first/0.55")
        .build()?;

    let rows = sqlx::query(
        r#"
        SELECT DISTINCT ON (vfr_id) raw_json
        FROM registry_entries
        ORDER BY vfr_id, signed_publish_at DESC, id DESC
        "#,
    )
    .fetch_all(&pool)
    .await?;

    let mut stats = Stats {
        total_latest: rows.len(),
        ..Stats::default()
    };

    for row in rows {
        let raw: Value = row.try_get("raw_json")?;
        let entry: RegistryEntry = match serde_json::from_value(raw.clone()) {
            Ok(entry) => entry,
            Err(e) => {
                stats.fail_schema += 1;
                tracing::warn!(error = %e, "latest registry row is not a registry entry");
                continue;
            }
        };

        let record_failure = |db: HubDb, entry: RegistryEntry, error: String| async move {
            if let Err(e) = db
                .record_publish_audit_failed(&entry, &error, "manifest_snapshot")
                .await
            {
                tracing::warn!(
                    vfr_id = %entry.vfr_id,
                    audit_error = %e,
                    "failed to record event-first audit failure"
                );
            }
        };

        let verified_signature = match verify_entry(&entry) {
            Ok(true) => true,
            Ok(false) => false,
            Err(e) => {
                let msg = format!("registry signature verification errored: {e}");
                stats.fail_signature += 1;
                tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
                if !dry_run {
                    record_failure(db.clone(), entry.clone(), msg).await;
                }
                continue;
            }
        };
        if !verified_signature {
            let msg = "registry signature does not verify".to_string();
            stats.fail_signature += 1;
            tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
            if !dry_run {
                record_failure(db.clone(), entry.clone(), msg).await;
            }
            continue;
        }

        let snapshot_meta = match db.get_snapshot_meta(&entry.latest_snapshot_hash).await {
            Ok(meta) => meta,
            Err(e) => {
                let msg = format!("snapshot metadata lookup failed: {e}");
                stats.fail_db += 1;
                tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
                if !dry_run {
                    record_failure(db.clone(), entry.clone(), msg).await;
                }
                continue;
            }
        };

        let fetch_url = snapshot_meta
            .as_ref()
            .map(|m| m.blob_url.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(entry.network_locator.as_str())
            .to_string();
        if !fetch_url.starts_with("http://") && !fetch_url.starts_with("https://") {
            let msg = format!("no http substrate locator for latest row: {fetch_url}");
            stats.fail_fetch += 1;
            tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
            if !dry_run {
                record_failure(db.clone(), entry.clone(), msg).await;
            }
            continue;
        }

        let bytes = match fetch_bytes(&http, &fetch_url).await {
            Ok(bytes) => bytes,
            Err(e) => {
                stats.fail_fetch += 1;
                tracing::warn!(vfr_id = %entry.vfr_id, locator = %fetch_url, error = %e);
                if !dry_run {
                    record_failure(db.clone(), entry.clone(), e).await;
                }
                continue;
            }
        };
        let project: Project = match serde_json::from_slice(&bytes) {
            Ok(project) => project,
            Err(e) => {
                let msg = format!("substrate schema parse failed: {e}");
                stats.fail_schema += 1;
                tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
                if !dry_run {
                    record_failure(db.clone(), entry.clone(), msg).await;
                }
                continue;
            }
        };

        let computed_snapshot = snapshot_hash(&project);
        if computed_snapshot != entry.latest_snapshot_hash {
            let msg = format!(
                "snapshot_hash mismatch: manifest declares {}, substrate hashes to {}",
                entry.latest_snapshot_hash, computed_snapshot
            );
            stats.fail_hash += 1;
            tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
            if !dry_run {
                record_failure(db.clone(), entry.clone(), msg).await;
            }
            continue;
        }
        let computed_event_log = event_log_hash(&project.events);
        if computed_event_log != entry.latest_event_log_hash {
            let msg = format!(
                "event_log_hash mismatch: manifest declares {}, substrate events hash to {}",
                entry.latest_event_log_hash, computed_event_log
            );
            stats.fail_hash += 1;
            tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
            if !dry_run {
                record_failure(db.clone(), entry.clone(), msg).await;
            }
            continue;
        }

        if dry_run {
            stats.verified_dry_run += 1;
            tracing::info!(
                vfr_id = %entry.vfr_id,
                findings = project.findings.len(),
                events = project.events.len(),
                sources = project.sources.len(),
                evidence_atoms = project.evidence_atoms.len(),
                condition_records = project.condition_records.len(),
                "[dry-run] verified latest frontier"
            );
            continue;
        }

        let meta = normalized_meta(snapshot_meta, &bytes, &project);
        let report = match db
            .promote_frontier_snapshot(&entry, &project, meta.as_ref(), "manifest_snapshot")
            .await
        {
            Ok(report) => report,
            Err(e) => {
                stats.fail_db += 1;
                tracing::warn!(vfr_id = %entry.vfr_id, error = %e, "promotion failed");
                record_failure(db.clone(), entry.clone(), e).await;
                continue;
            }
        };
        let db_hash = match db.event_log_hash_from_db(&entry.vfr_id).await {
            Ok(hash) => hash,
            Err(e) => {
                stats.fail_db += 1;
                let msg = format!("event-log hash readback failed: {e}");
                tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
                record_failure(db.clone(), entry.clone(), msg).await;
                continue;
            }
        };
        if db_hash != entry.latest_event_log_hash {
            stats.fail_hash += 1;
            let msg = format!(
                "event-log hash readback mismatch: manifest declares {}, DB hashes to {}",
                entry.latest_event_log_hash, db_hash
            );
            tracing::warn!(vfr_id = %entry.vfr_id, error = %msg);
            record_failure(db.clone(), entry.clone(), msg).await;
            continue;
        }

        stats.promoted += 1;
        tracing::info!(
            vfr_id = %report.vfr_id,
            findings = report.findings_count,
            events = report.events_count,
            sources = report.sources_count,
            evidence_atoms = report.evidence_atoms_count,
            condition_records = report.condition_records_count,
            objects = report.objects_count,
            "promoted latest frontier"
        );
    }

    println!();
    println!("event-first backfill summary");
    println!("latest rows scanned      : {}", stats.total_latest);
    println!("verified dry-run         : {}", stats.verified_dry_run);
    println!("promoted                 : {}", stats.promoted);
    println!("fail: signature          : {}", stats.fail_signature);
    println!("fail: fetch              : {}", stats.fail_fetch);
    println!("fail: schema             : {}", stats.fail_schema);
    println!("fail: hash               : {}", stats.fail_hash);
    println!("fail: db                 : {}", stats.fail_db);

    Ok(())
}

async fn fetch_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("GET {url}: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GET {url}: HTTP {status}"));
    }
    resp.bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|e| format!("read {url}: {e}"))
}

fn normalized_meta(
    snapshot_meta: Option<SnapshotMeta>,
    bytes: &[u8],
    project: &Project,
) -> Option<SnapshotMeta> {
    snapshot_meta.or_else(|| {
        let value = serde_json::to_value(project).ok()?;
        let schema_version = value
            .get("schema")
            .and_then(Value::as_str)
            .or_else(|| value.get("vela_version").and_then(Value::as_str))
            .unwrap_or("unknown")
            .to_string();
        let size_bytes = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
        Some(SnapshotMeta {
            blob_url: String::new(),
            content_type: "application/json".to_string(),
            schema_version,
            size_bytes,
        })
    })
}

#[derive(Default)]
struct Stats {
    total_latest: usize,
    verified_dry_run: usize,
    promoted: usize,
    fail_signature: usize,
    fail_fetch: usize,
    fail_schema: usize,
    fail_hash: usize,
    fail_db: usize,
}
