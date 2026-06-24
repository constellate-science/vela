//! v0.21: backend abstraction so the hub can run on Postgres (production)
//! or SQLite (self-hosted, no external dependencies). The enum stays
//! small — five methods cover everything the route handlers need. Each
//! backend handles its own placeholder syntax (`$1` vs `?`) and raw_json
//! storage (`JSONB` vs `TEXT`).
//!
//! Doctrine: the SQL surface stays minimal. If the enum grows past ~10
//! methods, the right move is to re-think whether the hub should be a
//! sqlx-direct service or move to an ORM.

use serde_json::{Value, json};
use sqlx::{PgPool, Row, SqlitePool};
use vela_protocol::bundle::FindingBundle;
use vela_protocol::events::{StateEvent, event_log_hash, snapshot_hash};
use vela_protocol::project::Project;
use vela_protocol::registry::RegistryEntry;

const LATEST_PER_VFR_SQL: &str = r#"
SELECT raw_json FROM registry_entries r
WHERE r.signed_publish_at = (
    SELECT MAX(signed_publish_at) FROM registry_entries
    WHERE vfr_id = r.vfr_id
)
ORDER BY r.signed_publish_at DESC
"#;

/// Backend-agnostic hub database handle. Variant is picked at startup
/// based on the `VELA_HUB_DATABASE_URL` prefix.
#[derive(Clone)]
pub enum HubDb {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

#[derive(Debug, Clone)]
pub struct EventFirstPromotionReport {
    pub vfr_id: String,
    pub registry_entry_id: Option<i64>,
    pub findings_count: i64,
    pub events_count: i64,
    pub sources_count: i64,
    pub evidence_atoms_count: i64,
    pub condition_records_count: i64,
    pub objects_count: i64,
    pub authority_mode: String,
}

/// Outcome of an incremental [`Db::append_to_frontier`]. Counts reflect what
/// the append actually wrote; `skipped_*` are records already present (the
/// idempotent no-ops). The new hashes are the frontier's post-append tail.
#[derive(Debug, Clone)]
pub struct AppendToFrontierOutcome {
    pub vfr_id: String,
    pub appended_findings: i64,
    pub appended_events: i64,
    pub skipped_duplicate_findings: i64,
    pub skipped_duplicate_events: i64,
    pub findings_count: i64,
    pub events_count: i64,
    pub new_event_log_hash: String,
    pub new_snapshot_hash: String,
}

#[derive(Debug, Clone)]
pub struct EventPage {
    pub events: Vec<Value>,
    pub next_cursor: Option<String>,
    pub log_total: i64,
}

#[derive(Debug, Clone)]
pub struct PublishAuditStatus {
    pub status: String,
    pub error: Option<String>,
    pub authority_mode: Option<String>,
}

struct FrontierObjectRow {
    object_type: String,
    object_id: String,
    seq: i64,
    target_id: Option<String>,
    raw_json: Value,
    /// Producer index: the key that signed/authored the object, when
    /// derivable (finding provenance actor pubkey, attempt signer, …).
    signer_pubkey: Option<String>,
}

impl HubDb {
    /// Local/SQLite mode: the database file IS the durable local store,
    /// so inline substrate is acceptable without object storage (the
    /// snapshot lands in materialized_snapshot_json). Production
    /// Postgres still requires the blob tier.
    pub fn is_sqlite(&self) -> bool {
        matches!(self, Self::Sqlite(_))
    }

    pub async fn health(&self) -> Result<(), String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(p)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Self::Sqlite(p) => sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(p)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string()),
        }
    }

    pub async fn schema_present(&self) -> Result<bool, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'registry_entries')",
            )
            .fetch_one(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='registry_entries'",
            )
            .fetch_one(p)
            .await
            .map(|n| n > 0)
            .map_err(|e| e.to_string()),
        }
    }

    pub async fn list_latest_entries(&self) -> Result<Vec<Value>, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, Value>(LATEST_PER_VFR_SQL)
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string()),
            Self::Sqlite(p) => {
                let rows: Vec<String> = sqlx::query_scalar(LATEST_PER_VFR_SQL)
                    .fetch_all(p)
                    .await
                    .map_err(|e| e.to_string())?;
                rows.into_iter()
                    .map(|s| serde_json::from_str::<Value>(&s).map_err(|e| e.to_string()))
                    .collect()
            }
        }
    }

    pub async fn get_entry(&self, vfr_id: &str) -> Result<Option<Value>, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, Value>(
                r#"
                SELECT raw_json FROM registry_entries
                WHERE vfr_id = $1
                ORDER BY signed_publish_at DESC
                LIMIT 1
                "#,
            )
            .bind(vfr_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => {
                let row: Option<String> = sqlx::query_scalar(
                    r#"
                    SELECT raw_json FROM registry_entries
                    WHERE vfr_id = ?
                    ORDER BY signed_publish_at DESC
                    LIMIT 1
                    "#,
                )
                .bind(vfr_id)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                match row {
                    Some(s) => serde_json::from_str::<Value>(&s)
                        .map(Some)
                        .map_err(|e| e.to_string()),
                    None => Ok(None),
                }
            }
        }
    }

    /// Event-first live registry listing. Hard-cutover reads should use
    /// this path: only verified, promoted frontiers appear. The returned
    /// JSON is still the signed manifest shape (`registry_entries.raw_json`)
    /// so old CLI clients keep working.
    pub async fn list_live_entries(&self) -> Result<Vec<Value>, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, Value>(
                r#"
                SELECT r.raw_json
                FROM frontiers f
                JOIN registry_entries r ON r.id = f.registry_entry_id
                WHERE f.status = 'live'
                ORDER BY f.signed_publish_at DESC
                "#,
            )
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => {
                let rows: Vec<String> = sqlx::query_scalar(
                    r#"
                    SELECT r.raw_json
                    FROM frontiers f
                    JOIN registry_entries r ON r.id = f.registry_entry_id
                    WHERE f.status = 'live'
                    ORDER BY f.signed_publish_at DESC
                    "#,
                )
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                rows.into_iter()
                    .map(|s| serde_json::from_str::<Value>(&s).map_err(|e| e.to_string()))
                    .collect()
            }
        }
    }

    pub async fn get_live_entry(&self, vfr_id: &str) -> Result<Option<Value>, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, Value>(
                r#"
                SELECT r.raw_json
                FROM frontiers f
                JOIN registry_entries r ON r.id = f.registry_entry_id
                WHERE f.vfr_id = $1 AND f.status = 'live'
                LIMIT 1
                "#,
            )
            .bind(vfr_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => {
                let row: Option<String> = sqlx::query_scalar(
                    r#"
                    SELECT r.raw_json
                    FROM frontiers f
                    JOIN registry_entries r ON r.id = f.registry_entry_id
                    WHERE f.vfr_id = ? AND f.status = 'live'
                    LIMIT 1
                    "#,
                )
                .bind(vfr_id)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                match row {
                    Some(s) => serde_json::from_str::<Value>(&s)
                        .map(Some)
                        .map_err(|e| e.to_string()),
                    None => Ok(None),
                }
            }
        }
    }

    /// Lightweight per-frontier counts for list/dashboard views, computed by
    /// cheap aggregates over the projection tables — never by reading the full
    /// (multi-MB) snapshot. object_type counts come from `frontier_objects`
    /// (indexed on `(vfr_id, object_type)`); events from `frontier_events`;
    /// contested/human_reviewed/avg_confidence from finding `review_state` flags
    /// and confidence scores. Returns None when the frontier is not live.
    pub async fn frontier_summary(&self, vfr_id: &str) -> Result<Option<Value>, String> {
        if self.get_live_entry(vfr_id).await?.is_none() {
            return Ok(None);
        }
        type FlagAgg = (i64, i64, Option<f64>);
        let (obj_counts, events, flags): (Vec<(String, i64)>, i64, FlagAgg) = match self {
            Self::Postgres(p) => {
                let rows: Vec<(String, i64)> = sqlx::query_as(
                    "SELECT object_type, COUNT(*)::bigint FROM frontier_objects \
                     WHERE vfr_id = $1 GROUP BY object_type",
                )
                .bind(vfr_id)
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                let events: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*)::bigint FROM frontier_events WHERE vfr_id = $1",
                )
                .bind(vfr_id)
                .fetch_one(p)
                .await
                .map_err(|e| e.to_string())?;
                let flags: FlagAgg = sqlx::query_as(
                    "SELECT \
                       COUNT(CASE WHEN raw_json #>> '{flags,review_state}' = 'contested' THEN 1 END)::bigint, \
                       COUNT(CASE WHEN raw_json #>> '{flags,review_state}' = 'accepted'  THEN 1 END)::bigint, \
                       AVG((raw_json #>> '{confidence,score}')::double precision) \
                     FROM frontier_objects WHERE vfr_id = $1 AND object_type = 'finding'",
                )
                .bind(vfr_id)
                .fetch_one(p)
                .await
                .map_err(|e| e.to_string())?;
                (rows, events, flags)
            }
            Self::Sqlite(p) => {
                let rows: Vec<(String, i64)> = sqlx::query_as(
                    "SELECT object_type, COUNT(*) FROM frontier_objects \
                     WHERE vfr_id = ? GROUP BY object_type",
                )
                .bind(vfr_id)
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                let events: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM frontier_events WHERE vfr_id = ?")
                        .bind(vfr_id)
                        .fetch_one(p)
                        .await
                        .map_err(|e| e.to_string())?;
                let flags: FlagAgg = sqlx::query_as(
                    "SELECT \
                       COUNT(CASE WHEN json_extract(raw_json,'$.flags.review_state') = 'contested' THEN 1 END), \
                       COUNT(CASE WHEN json_extract(raw_json,'$.flags.review_state') = 'accepted'  THEN 1 END), \
                       AVG(json_extract(raw_json,'$.confidence.score')) \
                     FROM frontier_objects WHERE vfr_id = ? AND object_type = 'finding'",
                )
                .bind(vfr_id)
                .fetch_one(p)
                .await
                .map_err(|e| e.to_string())?;
                (rows, events, flags)
            }
        };
        let map: std::collections::BTreeMap<String, i64> = obj_counts.into_iter().collect();
        let g = |k: &str| map.get(k).copied().unwrap_or(0);
        let (contested, human_reviewed, avg_confidence) = flags;
        Ok(Some(json!({
            "vfr_id": vfr_id,
            "findings": g("finding"),
            "sources": g("source"),
            "evidence_atoms": g("evidence_atom"),
            "links": g("link"),
            "proposals": g("proposal"),
            "events": events,
            "contested": contested,
            "human_reviewed": human_reviewed,
            "avg_confidence": avg_confidence.unwrap_or(0.0),
        })))
    }

    /// Lightweight object index for the frontier manifest: `(type, id, target_id,
    /// seq)` for every object, WITHOUT the bulk raw_json. Lets a client list a
    /// frontier and then fetch only the objects it opens (sparse / partial clone),
    /// instead of pulling the whole multi-MB snapshot.
    pub async fn frontier_object_index(&self, vfr_id: &str) -> Result<Vec<Value>, String> {
        type Row = (String, String, Option<String>, i64);
        let rows: Vec<Row> = match self {
            Self::Postgres(p) => sqlx::query_as(
                "SELECT object_type, object_id, target_id, seq FROM frontier_objects \
                 WHERE vfr_id = $1 ORDER BY object_type, seq",
            )
            .bind(vfr_id)
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_as(
                "SELECT object_type, object_id, target_id, seq FROM frontier_objects \
                 WHERE vfr_id = ? ORDER BY object_type, seq",
            )
            .bind(vfr_id)
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string())?,
        };
        Ok(rows
            .into_iter()
            .map(|(t, id, tgt, seq)| json!({"type": t, "id": id, "target_id": tgt, "seq": seq}))
            .collect())
    }

    /// Cross-frontier object text search for the public site's /search page —
    /// one query over `frontier_objects` instead of downloading every frontier's
    /// multi-MB snapshot and scanning client-side. Matches `q` anywhere in the
    /// object's raw_json (id, assertion text, doi, …), restricted to one
    /// `object_type`, across live frontiers only. Returns `{vfr_id, object}`.
    pub async fn search_objects(
        &self,
        q: &str,
        object_type: &str,
        limit: i64,
    ) -> Result<Vec<Value>, String> {
        let pattern = format!(
            "%{}%",
            q.replace('\\', "\\\\")
                .replace('%', "\\%")
                .replace('_', "\\_")
        );
        type Row = (String, String);
        let rows: Vec<Row> = match self {
            Self::Postgres(p) => sqlx::query_as(
                "SELECT f.vfr_id, o.raw_json::text \
                 FROM frontier_objects o \
                 JOIN frontiers f ON f.vfr_id = o.vfr_id AND f.status = 'live' \
                 WHERE o.object_type = $1 AND o.raw_json::text ILIKE $2 ESCAPE '\\' \
                 ORDER BY o.vfr_id, o.seq LIMIT $3",
            )
            .bind(object_type)
            .bind(&pattern)
            .bind(limit)
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_as(
                "SELECT f.vfr_id, o.raw_json \
                 FROM frontier_objects o \
                 JOIN frontiers f ON f.vfr_id = o.vfr_id AND f.status = 'live' \
                 WHERE o.object_type = ? AND o.raw_json LIKE ? ESCAPE '\\' \
                 ORDER BY o.vfr_id, o.seq LIMIT ?",
            )
            .bind(object_type)
            .bind(&pattern)
            .bind(limit)
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string())?,
        };
        Ok(rows
            .into_iter()
            .filter_map(|(vfr, raw)| {
                serde_json::from_str::<Value>(&raw)
                    .ok()
                    .map(|obj| json!({"vfr_id": vfr, "object": obj}))
            })
            .collect())
    }

    /// One page of a frontier's objects of a given type (raw_json), ordered by
    /// seq, with the total count — so the site renders a detail surface (sources,
    /// proposals, …) without pulling the whole multi-MB snapshot. Returns
    /// `(objects, total)`.
    pub async fn frontier_objects_page(
        &self,
        vfr_id: &str,
        object_type: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<Value>, i64), String> {
        let (rows, total): (Vec<String>, i64) = match self {
            Self::Postgres(p) => {
                let rows: Vec<String> = sqlx::query_scalar(
                    "SELECT raw_json::text FROM frontier_objects \
                     WHERE vfr_id = $1 AND object_type = $2 ORDER BY seq LIMIT $3 OFFSET $4",
                )
                .bind(vfr_id)
                .bind(object_type)
                .bind(limit)
                .bind(offset)
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                let total: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*)::bigint FROM frontier_objects WHERE vfr_id = $1 AND object_type = $2",
                )
                .bind(vfr_id).bind(object_type).fetch_one(p).await.map_err(|e| e.to_string())?;
                (rows, total)
            }
            Self::Sqlite(p) => {
                let rows: Vec<String> = sqlx::query_scalar(
                    "SELECT raw_json FROM frontier_objects \
                     WHERE vfr_id = ? AND object_type = ? ORDER BY seq LIMIT ? OFFSET ?",
                )
                .bind(vfr_id)
                .bind(object_type)
                .bind(limit)
                .bind(offset)
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                let total: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM frontier_objects WHERE vfr_id = ? AND object_type = ?",
                )
                .bind(vfr_id)
                .bind(object_type)
                .fetch_one(p)
                .await
                .map_err(|e| e.to_string())?;
                (rows, total)
            }
        };
        let objects = rows
            .into_iter()
            .filter_map(|s| serde_json::from_str::<Value>(&s).ok())
            .collect();
        Ok((objects, total))
    }

    /// A single frontier object by `(type, object_id)` — a primary-key point
    /// lookup. Returns the raw_json, or None if absent.
    pub async fn frontier_object(
        &self,
        vfr_id: &str,
        object_type: &str,
        object_id: &str,
    ) -> Result<Option<Value>, String> {
        let row: Option<String> = match self {
            Self::Postgres(p) => sqlx::query_scalar(
                "SELECT raw_json::text FROM frontier_objects \
                 WHERE vfr_id = $1 AND object_type = $2 AND object_id = $3 LIMIT 1",
            )
            .bind(vfr_id)
            .bind(object_type)
            .bind(object_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_scalar(
                "SELECT raw_json FROM frontier_objects \
                 WHERE vfr_id = ? AND object_type = ? AND object_id = ? LIMIT 1",
            )
            .bind(vfr_id)
            .bind(object_type)
            .bind(object_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
        };
        match row {
            Some(s) => serde_json::from_str::<Value>(&s)
                .map(Some)
                .map_err(|e| e.to_string()),
            None => Ok(None),
        }
    }

    /// All of a frontier's events as raw_json Values, ordered by seq — the input
    /// to the Merkle transparency log (P2). Unbounded: transparency needs the
    /// whole log, not a page.
    pub async fn all_event_values(&self, vfr_id: &str) -> Result<Vec<Value>, String> {
        match self {
            Self::Postgres(p) => sqlx::query(
                "SELECT raw_json FROM frontier_events WHERE vfr_id = $1 ORDER BY seq ASC",
            )
            .bind(vfr_id)
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|row| {
                row.try_get::<Value, _>("raw_json")
                    .map_err(|e| e.to_string())
            })
            .collect(),
            Self::Sqlite(p) => {
                let rows: Vec<String> = sqlx::query_scalar(
                    "SELECT raw_json FROM frontier_events WHERE vfr_id = ? ORDER BY seq ASC",
                )
                .bind(vfr_id)
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                rows.into_iter()
                    .map(|s| serde_json::from_str::<Value>(&s).map_err(|e| e.to_string()))
                    .collect()
            }
        }
    }

    /// v0.201: look up a Scientific Diff Pack by its `vsd_*` id.
    /// Returns the raw signed pack JSON if the pack has been
    /// registered with this hub via a `diff_pack.released` federation
    /// event, otherwise None.
    pub async fn get_diff_pack(&self, pack_id: &str) -> Result<Option<Value>, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, Value>(
                r#"
                SELECT raw_json
                FROM registry_diff_packs
                WHERE pack_id = $1
                ORDER BY inserted_at DESC
                LIMIT 1
                "#,
            )
            .bind(pack_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => {
                let row: Option<String> = sqlx::query_scalar(
                    r#"
                    SELECT raw_json
                    FROM registry_diff_packs
                    WHERE pack_id = ?
                    ORDER BY inserted_at DESC
                    LIMIT 1
                    "#,
                )
                .bind(pack_id)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                match row {
                    Some(s) => serde_json::from_str::<Value>(&s)
                        .map(Some)
                        .map_err(|e| e.to_string()),
                    None => Ok(None),
                }
            }
        }
    }

    /// v0.209: register a signed Scientific Diff Pack with this hub.
    /// Idempotent on (pack_id, signature) via the unique index. Returns
    /// `true` when a new row landed, `false` when the same signed pack
    /// was already present.
    pub async fn insert_diff_pack(
        &self,
        pack: &vela_protocol::scientific_diff::ScientificDiffPack,
        raw_json: &Value,
    ) -> Result<bool, String> {
        let signature = pack.signature.clone().unwrap_or_default();
        let signer_pubkey_hex = pack.signer_pubkey_hex.clone().unwrap_or_default();
        if signature.is_empty() || signer_pubkey_hex.is_empty() {
            return Err("publish_diff_pack requires a signed pack".to_string());
        }
        let member_ids_json = serde_json::to_string(&pack.proposals)
            .map_err(|e| format!("serialize members: {e}"))?;
        match self {
            Self::Postgres(p) => {
                let inserted = sqlx::query_scalar::<_, String>(
                    r#"
                    INSERT INTO registry_diff_packs (
                      pack_id, frontier_id, aggregate_kind, summary,
                      created_at, agent_run, parent_pack, applied_event_id,
                      member_ids, signature, signer_pubkey_hex, raw_json
                    )
                    VALUES (
                      $1, $2, $3, $4, $5::timestamptz,
                      $6, $7, $8,
                      $9::jsonb, $10, $11, $12::jsonb
                    )
                    ON CONFLICT (pack_id, signature) DO NOTHING
                    RETURNING pack_id
                    "#,
                )
                .bind(&pack.pack_id)
                .bind(&pack.frontier_id)
                .bind(&pack.aggregate_kind)
                .bind(&pack.summary)
                .bind(&pack.created_at)
                .bind(pack.agent_run.as_deref())
                .bind(pack.parent_pack.as_deref())
                .bind(pack.applied_event_id.as_deref())
                .bind(&member_ids_json)
                .bind(&signature)
                .bind(&signer_pubkey_hex)
                .bind(raw_json)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(inserted.is_some())
            }
            Self::Sqlite(p) => {
                let raw_json_str = serde_json::to_string(raw_json)
                    .map_err(|e| format!("serialize raw_json: {e}"))?;
                let result = sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO registry_diff_packs (
                      pack_id, frontier_id, aggregate_kind, summary,
                      created_at, agent_run, parent_pack, applied_event_id,
                      member_ids_json, signature, signer_pubkey_hex, raw_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&pack.pack_id)
                .bind(&pack.frontier_id)
                .bind(&pack.aggregate_kind)
                .bind(&pack.summary)
                .bind(&pack.created_at)
                .bind(pack.agent_run.as_deref())
                .bind(pack.parent_pack.as_deref())
                .bind(pack.applied_event_id.as_deref())
                .bind(&member_ids_json)
                .bind(&signature)
                .bind(&signer_pubkey_hex)
                .bind(&raw_json_str)
                .execute(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    /// v0.201: count of registered `vsd_*` packs.
    pub async fn count_diff_packs(&self) -> Result<i64, String> {
        match self {
            Self::Postgres(p) => {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM registry_diff_packs")
                    .fetch_one(p)
                    .await
                    .map_err(|e| e.to_string())
            }
            Self::Sqlite(p) => {
                sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM registry_diff_packs")
                    .fetch_one(p)
                    .await
                    .map_err(|e| e.to_string())
            }
        }
    }

    pub async fn latest_audit_status(
        &self,
        vfr_id: &str,
    ) -> Result<Option<PublishAuditStatus>, String> {
        match self {
            Self::Postgres(p) => {
                let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
                    r#"
                    SELECT status, error, authority_mode
                    FROM frontier_publish_audit
                    WHERE vfr_id = $1
                    ORDER BY verified_at DESC, id DESC
                    LIMIT 1
                    "#,
                )
                .bind(vfr_id)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(
                    row.map(|(status, error, authority_mode)| PublishAuditStatus {
                        status,
                        error,
                        authority_mode,
                    }),
                )
            }
            Self::Sqlite(p) => {
                let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
                    r#"
                    SELECT status, error, authority_mode
                    FROM frontier_publish_audit
                    WHERE vfr_id = ?
                    ORDER BY verified_at DESC, id DESC
                    LIMIT 1
                    "#,
                )
                .bind(vfr_id)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(
                    row.map(|(status, error, authority_mode)| PublishAuditStatus {
                        status,
                        error,
                        authority_mode,
                    }),
                )
            }
        }
    }

    /// Returns true on fresh insert, false on duplicate.
    /// The EFFECTIVE owner pubkey: the latest owner rotation's successor,
    /// or the original publisher's key if no rotation exists. Every owner
    /// check (re-publish continuity, deprecation, further rotation) must
    /// use this, never the raw frontiers.owner_pubkey.
    pub async fn effective_owner_pubkey(&self, vfr_id: &str) -> Result<Option<String>, String> {
        let rotated: Option<(String,)> = match self {
            Self::Postgres(p) => sqlx::query_as(
                "SELECT new_owner_pubkey FROM frontier_owner_rotations WHERE vfr_id = $1 ORDER BY id DESC LIMIT 1",
            )
            .bind(vfr_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_as(
                "SELECT new_owner_pubkey FROM frontier_owner_rotations WHERE vfr_id = ?1 ORDER BY id DESC LIMIT 1",
            )
            .bind(vfr_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
        };
        if let Some((k,)) = rotated {
            return Ok(Some(k));
        }
        self.frontier_owner_pubkey(vfr_id).await
    }

    /// Append an owner rotation (the signature was verified by the caller
    /// against the CURRENT effective owner).
    pub async fn record_owner_rotation(
        &self,
        vfr_id: &str,
        new_owner_pubkey: &str,
        rotated_at: &str,
        raw_json: &Value,
    ) -> Result<(), String> {
        match self {
            Self::Postgres(p) => sqlx::query(
                "INSERT INTO frontier_owner_rotations (vfr_id, new_owner_pubkey, rotated_at, raw_json) VALUES ($1, $2, $3, $4)",
            )
            .bind(vfr_id)
            .bind(new_owner_pubkey)
            .bind(rotated_at)
            .bind(raw_json)
            .execute(p)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => {
                let raw = serde_json::to_string(raw_json).map_err(|e| e.to_string())?;
                sqlx::query(
                    "INSERT INTO frontier_owner_rotations (vfr_id, new_owner_pubkey, rotated_at, raw_json) VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(vfr_id)
                .bind(new_owner_pubkey)
                .bind(rotated_at)
                .bind(raw)
                .execute(p)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
            }
        }
    }

    /// Append a maintainer add/remove (signature verified by the caller
    /// against the effective owner or a current maintainer).
    pub async fn record_maintainer_action(
        &self,
        vfr_id: &str,
        pubkey: &str,
        action: &str,
        authorized_by: &str,
        authorized_at: &str,
        raw_json: &Value,
    ) -> Result<(), String> {
        match self {
            Self::Postgres(p) => sqlx::query(
                "INSERT INTO frontier_maintainers (vfr_id, pubkey, action, authorized_by_pubkey, authorized_at, raw_json) VALUES ($1,$2,$3,$4,$5,$6)",
            )
            .bind(vfr_id).bind(pubkey).bind(action).bind(authorized_by).bind(authorized_at).bind(raw_json)
            .execute(p).await.map(|_| ()).map_err(|e| e.to_string()),
            Self::Sqlite(p) => {
                let raw = serde_json::to_string(raw_json).map_err(|e| e.to_string())?;
                sqlx::query(
                    "INSERT INTO frontier_maintainers (vfr_id, pubkey, action, authorized_by_pubkey, authorized_at, raw_json) VALUES (?1,?2,?3,?4,?5,?6)",
                )
                .bind(vfr_id).bind(pubkey).bind(action).bind(authorized_by).bind(authorized_at).bind(raw)
                .execute(p).await.map(|_| ()).map_err(|e| e.to_string())
            }
        }
    }

    /// The effective maintainer set: latest action per pubkey, filtered
    /// to 'add'.
    pub async fn effective_maintainers(&self, vfr_id: &str) -> Result<Vec<String>, String> {
        let rows: Vec<(String, String)> = match self {
            Self::Postgres(p) => sqlx::query_as(
                "SELECT DISTINCT ON (pubkey) pubkey, action FROM frontier_maintainers WHERE vfr_id = $1 ORDER BY pubkey, id DESC",
            )
            .bind(vfr_id).fetch_all(p).await.map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_as(
                "SELECT pubkey, action FROM frontier_maintainers fm WHERE vfr_id = ?1 AND id = (SELECT MAX(id) FROM frontier_maintainers fm2 WHERE fm2.vfr_id = fm.vfr_id AND fm2.pubkey = fm.pubkey)",
            )
            .bind(vfr_id).fetch_all(p).await.map_err(|e| e.to_string())?,
        };
        Ok(rows
            .into_iter()
            .filter(|(_, a)| a == "add")
            .map(|(k, _)| k)
            .collect())
    }

    /// Every key with accept authority on this frontier: the effective
    /// owner plus the effective maintainer set.
    pub async fn effective_accept_keys(&self, vfr_id: &str) -> Result<Vec<String>, String> {
        let mut keys = self.effective_maintainers(vfr_id).await?;
        if let Some(owner) = self.effective_owner_pubkey(vfr_id).await?
            && !keys.iter().any(|k| k.eq_ignore_ascii_case(&owner))
        {
            keys.push(owner);
        }
        Ok(keys)
    }

    /// Cross-frontier producer view: verified-frontier objects signed by
    /// one key (the fundable CV / 48-hour due-diligence query).
    pub async fn producer_objects(
        &self,
        pubkey: &str,
        limit: i64,
    ) -> Result<Vec<(String, String, String, Value)>, String> {
        match self {
            Self::Postgres(p) => {
                let rows: Vec<(String, String, String, Value)> = sqlx::query_as(
                    "SELECT vfr_id, object_type, object_id, raw_json FROM frontier_objects WHERE signer_pubkey = $1 ORDER BY vfr_id, object_type, object_id LIMIT $2",
                )
                .bind(pubkey).bind(limit).fetch_all(p).await.map_err(|e| e.to_string())?;
                Ok(rows)
            }
            Self::Sqlite(p) => {
                let rows: Vec<(String, String, String, String)> = sqlx::query_as(
                    "SELECT vfr_id, object_type, object_id, raw_json FROM frontier_objects WHERE signer_pubkey = ?1 ORDER BY vfr_id, object_type, object_id LIMIT ?2",
                )
                .bind(pubkey).bind(limit).fetch_all(p).await.map_err(|e| e.to_string())?;
                rows.into_iter()
                    .map(|(v, t, i, r)| {
                        serde_json::from_str(&r)
                            .map(|j| (v, t, i, j))
                            .map_err(|e| e.to_string())
                    })
                    .collect()
            }
        }
    }

    /// Boot-time producer-index backfill: for live frontiers whose
    /// finding objects lack signer_pubkey, re-run extraction from the
    /// stored materialized snapshot. Idempotent.
    pub async fn backfill_signer_pubkeys(&self) -> Result<usize, String> {
        // The DB's materialized_snapshot_json is a stripped projection
        // (no actors array), so signer resolution MUST come from the
        // full content-addressed snapshot blob in object storage —
        // which is the signed substrate and always carries actors.
        let vfrs: Vec<(String, Option<String>)> = match self {
            Self::Postgres(p) => sqlx::query_as(
                "SELECT vfr_id, snapshot_blob_url FROM frontiers WHERE status = 'live' AND snapshot_blob_url IS NOT NULL",
            )
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_as(
                "SELECT vfr_id, snapshot_blob_url FROM frontiers WHERE status = 'live' AND snapshot_blob_url IS NOT NULL",
            )
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string())?,
        };
        let client = reqwest::Client::new();
        let mut updated = 0usize;
        for (vfr, blob_url) in vfrs {
            let Some(url) = blob_url else { continue };
            let Ok(resp) = client.get(&url).send().await else {
                continue;
            };
            let Ok(text) = resp.text().await else {
                continue;
            };
            let Ok(snapshot) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            for row in collect_frontier_objects(&snapshot) {
                let Some(pk) = row.signer_pubkey else {
                    continue;
                };
                let affected: u64 = match self {
                    Self::Postgres(p) => sqlx::query(
                        "UPDATE frontier_objects SET signer_pubkey = $1 WHERE vfr_id = $2 AND object_type = $3 AND object_id = $4 AND signer_pubkey IS NULL",
                    )
                    .bind(&pk).bind(&vfr).bind(&row.object_type).bind(&row.object_id)
                    .execute(p).await.map(|r| r.rows_affected()).unwrap_or(0),
                    Self::Sqlite(p) => sqlx::query(
                        "UPDATE frontier_objects SET signer_pubkey = ?1 WHERE vfr_id = ?2 AND object_type = ?3 AND object_id = ?4 AND signer_pubkey IS NULL",
                    )
                    .bind(&pk).bind(&vfr).bind(&row.object_type).bind(&row.object_id)
                    .execute(p).await.map(|r| r.rows_affected()).unwrap_or(0),
                };
                updated += affected as usize;
            }
        }
        Ok(updated)
    }

    /// Append-only frontier deprecation (earliest-wins; a second
    /// deprecation of the same vfr_id is a no-op). Also flips
    /// `frontiers.status` to 'deprecated', which every live read
    /// (`list_live_entries`, `get_live_entry`, search) already filters on.
    pub async fn record_deprecation(
        &self,
        vfr_id: &str,
        deprecated_at: &str,
        reason: &str,
        raw_json: &Value,
    ) -> Result<bool, String> {
        match self {
            Self::Postgres(p) => {
                let inserted = sqlx::query_scalar::<_, String>(
                    r#"
                    INSERT INTO frontier_deprecations (vfr_id, deprecated_at, reason, raw_json)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (vfr_id) DO NOTHING
                    RETURNING vfr_id
                    "#,
                )
                .bind(vfr_id)
                .bind(deprecated_at)
                .bind(reason)
                .bind(raw_json)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?
                .is_some();
                sqlx::query("UPDATE frontiers SET status = 'deprecated' WHERE vfr_id = $1")
                    .bind(vfr_id)
                    .execute(p)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(inserted)
            }
            Self::Sqlite(p) => {
                let raw = serde_json::to_string(raw_json).map_err(|e| e.to_string())?;
                let res = sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO frontier_deprecations (vfr_id, deprecated_at, reason, raw_json)
                    VALUES (?1, ?2, ?3, ?4)
                    "#,
                )
                .bind(vfr_id)
                .bind(deprecated_at)
                .bind(reason)
                .bind(raw)
                .execute(p)
                .await
                .map_err(|e| e.to_string())?;
                sqlx::query("UPDATE frontiers SET status = 'deprecated' WHERE vfr_id = ?1")
                    .bind(vfr_id)
                    .execute(p)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(res.rows_affected() > 0)
            }
        }
    }

    /// The deprecation record for a frontier, if any (the audit receipt).
    pub async fn get_deprecation(&self, vfr_id: &str) -> Result<Option<Value>, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, Value>(
                "SELECT raw_json FROM frontier_deprecations WHERE vfr_id = $1",
            )
            .bind(vfr_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => {
                let row: Option<String> = sqlx::query_scalar(
                    "SELECT raw_json FROM frontier_deprecations WHERE vfr_id = ?1",
                )
                .bind(vfr_id)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                row.map(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
                    .transpose()
            }
        }
    }

    /// Record the object-storage URL of the archived signed manifest for
    /// every entry row of this (vfr_id, signature) publish.
    pub async fn set_manifest_blob_url(
        &self,
        vfr_id: &str,
        signature: &str,
        url: &str,
    ) -> Result<(), String> {
        match self {
            Self::Postgres(p) => sqlx::query(
                "UPDATE registry_entries SET manifest_blob_url = $1 WHERE vfr_id = $2 AND signature = $3",
            )
            .bind(url)
            .bind(vfr_id)
            .bind(signature)
            .execute(p)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => sqlx::query(
                "UPDATE registry_entries SET manifest_blob_url = ?1 WHERE vfr_id = ?2 AND signature = ?3",
            )
            .bind(url)
            .bind(vfr_id)
            .bind(signature)
            .execute(p)
            .await
            .map(|_| ())
            .map_err(|e| e.to_string()),
        }
    }

    /// Entries whose signed manifest has not yet been archived to object
    /// storage. Drives the idempotent boot-time backfill.
    pub async fn entries_missing_manifest_blob(
        &self,
    ) -> Result<Vec<(String, String, Value)>, String> {
        match self {
            Self::Postgres(p) => {
                let rows: Vec<(String, String, Value)> = sqlx::query_as(
                    "SELECT vfr_id, signature, raw_json FROM registry_entries WHERE manifest_blob_url IS NULL",
                )
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(rows)
            }
            Self::Sqlite(p) => {
                let rows: Vec<(String, String, String)> = sqlx::query_as(
                    "SELECT vfr_id, signature, raw_json FROM registry_entries WHERE manifest_blob_url IS NULL",
                )
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                rows.into_iter()
                    .map(|(v, s, r)| {
                        serde_json::from_str(&r)
                            .map(|j| (v, s, j))
                            .map_err(|e| e.to_string())
                    })
                    .collect()
            }
        }
    }

    pub async fn insert_entry(
        &self,
        entry: &RegistryEntry,
        raw_json: &Value,
    ) -> Result<bool, String> {
        match self {
            Self::Postgres(p) => {
                let inserted = sqlx::query_scalar::<_, String>(
                    r#"
                    INSERT INTO registry_entries (
                      vfr_id, schema, name, owner_actor_id, owner_pubkey,
                      latest_snapshot_hash, latest_event_log_hash, network_locator,
                      signed_publish_at, signature, raw_json
                    )
                    VALUES (
                      $1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10, $11
                    )
                    ON CONFLICT (vfr_id, signature) DO NOTHING
                    RETURNING vfr_id
                    "#,
                )
                .bind(&entry.vfr_id)
                .bind(&entry.schema)
                .bind(&entry.name)
                .bind(&entry.owner_actor_id)
                .bind(&entry.owner_pubkey)
                .bind(&entry.latest_snapshot_hash)
                .bind(&entry.latest_event_log_hash)
                .bind(&entry.network_locator)
                .bind(&entry.signed_publish_at)
                .bind(&entry.signature)
                .bind(raw_json)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(inserted.is_some())
            }
            Self::Sqlite(p) => {
                let raw_json_str = serde_json::to_string(raw_json)
                    .map_err(|e| format!("serialize raw_json: {e}"))?;
                let result = sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO registry_entries (
                      vfr_id, schema, name, owner_actor_id, owner_pubkey,
                      latest_snapshot_hash, latest_event_log_hash, network_locator,
                      signed_publish_at, signature, raw_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&entry.vfr_id)
                .bind(&entry.schema)
                .bind(&entry.name)
                .bind(&entry.owner_actor_id)
                .bind(&entry.owner_pubkey)
                .bind(&entry.latest_snapshot_hash)
                .bind(&entry.latest_event_log_hash)
                .bind(&entry.network_locator)
                .bind(&entry.signed_publish_at)
                .bind(&entry.signature)
                .bind(&raw_json_str)
                .execute(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    async fn registry_entry_id(&self, entry: &RegistryEntry) -> Result<Option<i64>, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, i64>(
                "SELECT id FROM registry_entries WHERE vfr_id = $1 AND signature = $2 LIMIT 1",
            )
            .bind(&entry.vfr_id)
            .bind(&entry.signature)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => sqlx::query_scalar::<_, i64>(
                "SELECT id FROM registry_entries WHERE vfr_id = ? AND signature = ? LIMIT 1",
            )
            .bind(&entry.vfr_id)
            .bind(&entry.signature)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string()),
        }
    }

    /// Promote a verified substrate into the event-first tables. This is
    /// the hard-cutover write path for both backfill and future publishes:
    /// registry manifest remains the signature receipt, while events and
    /// materialized projections become the hub's read source.
    /// The `owner_pubkey` of an already-promoted frontier, or None if this
    /// vfr_id has never been promoted. Used to enforce owner continuity on
    /// re-publish (an attacker cannot produce a valid signature for the
    /// original owner's key, so they cannot pass the continuity check).
    pub async fn frontier_owner_pubkey(&self, vfr_id: &str) -> Result<Option<String>, String> {
        let row: Option<(String,)> = match self {
            Self::Postgres(p) => {
                sqlx::query_as("SELECT owner_pubkey FROM frontiers WHERE vfr_id = $1")
                    .bind(vfr_id)
                    .fetch_optional(p)
                    .await
                    .map_err(|e| e.to_string())?
            }
            Self::Sqlite(p) => {
                sqlx::query_as("SELECT owner_pubkey FROM frontiers WHERE vfr_id = ?1")
                    .bind(vfr_id)
                    .fetch_optional(p)
                    .await
                    .map_err(|e| e.to_string())?
            }
        };
        Ok(row.map(|(pk,)| pk))
    }

    /// Record every revoked actor in `project` into the authoritative,
    /// append-only `frontier_revocations` log. Keyed by pubkey (lowercased
    /// crypto identity); `ON CONFLICT DO NOTHING` makes it earliest-wins, so a
    /// later snapshot that drops the revocation cannot un-revoke a key here.
    /// Called on every promote. Returns the count of newly-recorded revocations.
    pub async fn record_revocations(
        &self,
        vfr_id: &str,
        project: &Project,
    ) -> Result<usize, String> {
        let mut recorded = 0usize;
        for actor in &project.actors {
            let Some(revoked_at) = actor.revoked_at.as_deref() else {
                continue;
            };
            let pubkey = actor.public_key.to_lowercase();
            let reason = actor.revoked_reason.as_deref();
            let affected = match self {
                Self::Postgres(p) => sqlx::query(
                    "INSERT INTO frontier_revocations \
                       (vfr_id, pubkey, actor_id, revoked_at, revoked_reason) \
                     VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT (vfr_id, pubkey) DO NOTHING",
                )
                .bind(vfr_id)
                .bind(&pubkey)
                .bind(&actor.id)
                .bind(revoked_at)
                .bind(reason)
                .execute(p)
                .await
                .map_err(|e| e.to_string())?
                .rows_affected(),
                Self::Sqlite(p) => sqlx::query(
                    "INSERT OR IGNORE INTO frontier_revocations \
                       (vfr_id, pubkey, actor_id, revoked_at, revoked_reason) \
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(vfr_id)
                .bind(&pubkey)
                .bind(&actor.id)
                .bind(revoked_at)
                .bind(reason)
                .execute(p)
                .await
                .map_err(|e| e.to_string())?
                .rows_affected(),
            };
            recorded += affected as usize;
        }
        Ok(recorded)
    }

    /// Whether `pubkey` is in the authoritative revocation log for this
    /// frontier. Returns `(revoked_at, reason)` if so. The accept/append paths
    /// consult this in ADDITION to the snapshot's `ActorRecord::is_revoked_at`,
    /// so a revoked key stays revoked even if a later snapshot drops it.
    pub async fn is_pubkey_revoked(
        &self,
        vfr_id: &str,
        pubkey: &str,
    ) -> Result<Option<(String, String)>, String> {
        let pk = pubkey.to_lowercase();
        let row: Option<(String, Option<String>)> = match self {
            Self::Postgres(p) => sqlx::query_as(
                "SELECT revoked_at, revoked_reason FROM frontier_revocations \
                 WHERE vfr_id = $1 AND pubkey = $2",
            )
            .bind(vfr_id)
            .bind(&pk)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_as(
                "SELECT revoked_at, revoked_reason FROM frontier_revocations \
                 WHERE vfr_id = ?1 AND pubkey = ?2",
            )
            .bind(vfr_id)
            .bind(&pk)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
        };
        Ok(row.map(|(at, reason)| (at, reason.unwrap_or_default())))
    }

    pub async fn promote_frontier_snapshot(
        &self,
        entry: &RegistryEntry,
        project: &Project,
        snapshot_meta: Option<&SnapshotMeta>,
        authority_mode: &str,
    ) -> Result<EventFirstPromotionReport, String> {
        let computed_snapshot = snapshot_hash(project);
        if computed_snapshot != entry.latest_snapshot_hash {
            return Err(format!(
                "snapshot_hash mismatch: manifest declares {}, substrate hashes to {}",
                entry.latest_snapshot_hash, computed_snapshot
            ));
        }
        let computed_event_log = event_log_hash(&project.events);
        if computed_event_log != entry.latest_event_log_hash {
            return Err(format!(
                "event_log_hash mismatch: manifest declares {}, substrate events hash to {}",
                entry.latest_event_log_hash, computed_event_log
            ));
        }

        // Owner-continuity guard. A frontier that already exists may only be
        // re-published under its ORIGINAL owner key. The manifest's
        // `owner_pubkey` is self-declared and `verify_entry` only checks the
        // signature against that self-declared key — so a valid signature is
        // NOT access control on an existing frontier. Without this check anyone
        // could overwrite any published frontier (and rewrite its actor /
        // revocation list) with their own self-signed manifest.
        if let Some(existing_owner) = self.effective_owner_pubkey(&entry.vfr_id).await?
            && existing_owner != entry.owner_pubkey
        {
            return Err(format!(
                "owner continuity: vfr {} already belongs to a different owner key; a \
                     re-publish must be signed by the current effective owner (original \
                     publisher, or the successor named by the latest signed owner rotation)",
                entry.vfr_id
            ));
        }

        // Monotonic anti-replay guard. A re-publish must not carry an OLDER
        // `signed_publish_at` than the live row. Without this, a captured old
        // owner-signed manifest could be replayed to roll the frontier back to
        // a prior state (e.g. undoing a revocation or a correction). A re-send
        // at the SAME timestamp is allowed (idempotent retry — the upsert is a
        // no-op for identical content, and the owner-continuity guard above
        // already requires the owner key); only a strictly-older timestamp is a
        // rollback. The comparison is done in SQL so the DB applies the right
        // ordering — Postgres on `timestamptz`, SQLite on the RFC3339 `Z` text
        // (which sorts chronologically).
        let rolled_back: Option<(String,)> = match self {
            Self::Postgres(p) => sqlx::query_as(
                "SELECT vfr_id FROM frontiers WHERE vfr_id = $1 AND signed_publish_at > $2::timestamptz",
            )
            .bind(&entry.vfr_id)
            .bind(&entry.signed_publish_at)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_as(
                "SELECT vfr_id FROM frontiers WHERE vfr_id = ?1 AND signed_publish_at > ?2",
            )
            .bind(&entry.vfr_id)
            .bind(&entry.signed_publish_at)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
        };
        if rolled_back.is_some() {
            return Err(format!(
                "monotonic publish: vfr {} already has a newer live publish than {}; a \
                 re-publish must not roll signed_publish_at backwards (anti-replay / \
                 rollback guard)",
                entry.vfr_id, entry.signed_publish_at
            ));
        }

        let registry_entry_id = self.registry_entry_id(entry).await?;
        let snapshot_value =
            serde_json::to_value(project).map_err(|e| format!("serialize project: {e}"))?;
        let snapshot_json =
            serde_json::to_string(&snapshot_value).map_err(|e| format!("project json: {e}"))?;
        let snapshot_skeleton = frontier_skeleton(&snapshot_value);
        let snapshot_skeleton_json =
            serde_json::to_string(&snapshot_skeleton).map_err(|e| format!("project json: {e}"))?;
        let schema_version = snapshot_value
            .get("schema")
            .and_then(Value::as_str)
            .or_else(|| snapshot_value.get("vela_version").and_then(Value::as_str))
            .unwrap_or("unknown");
        let blob_url = snapshot_meta.map(|m| m.blob_url.as_str()).unwrap_or("");
        let size_bytes = snapshot_meta
            .map(|m| i64::from(m.size_bytes))
            .unwrap_or(snapshot_json.len() as i64);
        let findings_count = project.findings.len() as i64;
        let events_count = project.events.len() as i64;
        let sources_count = project.sources.len() as i64;
        let evidence_atoms_count = project.evidence_atoms.len() as i64;
        let condition_records_count = project.condition_records.len() as i64;
        let objects = collect_frontier_objects(&snapshot_value);
        let objects_count = objects.len() as i64;

        match self {
            Self::Postgres(p) => {
                let mut tx = p.begin().await.map_err(|e| e.to_string())?;
                sqlx::query("DELETE FROM frontier_events WHERE vfr_id = $1")
                    .bind(&entry.vfr_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query("DELETE FROM frontier_objects WHERE vfr_id = $1")
                    .bind(&entry.vfr_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query(
                    r#"
                    INSERT INTO frontiers (
                      vfr_id, registry_entry_id, name, owner_actor_id, owner_pubkey,
                      latest_snapshot_hash, latest_event_log_hash, schema_version,
                      signed_publish_at, snapshot_blob_url, snapshot_size_bytes,
                      findings_count, events_count, sources_count, evidence_atoms_count,
                      condition_records_count, materialized_snapshot_json, authority_mode, status
                    )
                    VALUES (
                      $1, $2, $3, $4, $5,
                      $6, $7, $8,
                      $9::timestamptz, $10, $11,
                      $12, $13, $14, $15,
                      $16, $17::jsonb, $18, 'live'
                    )
                    ON CONFLICT (vfr_id) DO UPDATE SET
                      registry_entry_id = EXCLUDED.registry_entry_id,
                      name = EXCLUDED.name,
                      owner_actor_id = EXCLUDED.owner_actor_id,
                      owner_pubkey = EXCLUDED.owner_pubkey,
                      latest_snapshot_hash = EXCLUDED.latest_snapshot_hash,
                      latest_event_log_hash = EXCLUDED.latest_event_log_hash,
                      schema_version = EXCLUDED.schema_version,
                      signed_publish_at = EXCLUDED.signed_publish_at,
                      snapshot_blob_url = EXCLUDED.snapshot_blob_url,
                      snapshot_size_bytes = EXCLUDED.snapshot_size_bytes,
                      findings_count = EXCLUDED.findings_count,
                      events_count = EXCLUDED.events_count,
                      sources_count = EXCLUDED.sources_count,
                      evidence_atoms_count = EXCLUDED.evidence_atoms_count,
                      condition_records_count = EXCLUDED.condition_records_count,
                      materialized_snapshot_json = EXCLUDED.materialized_snapshot_json,
                      authority_mode = EXCLUDED.authority_mode,
                      status = 'live',
                      updated_at = now()
                    "#,
                )
                .bind(&entry.vfr_id)
                .bind(registry_entry_id)
                .bind(&entry.name)
                .bind(&entry.owner_actor_id)
                .bind(&entry.owner_pubkey)
                .bind(&entry.latest_snapshot_hash)
                .bind(&entry.latest_event_log_hash)
                .bind(schema_version)
                .bind(&entry.signed_publish_at)
                .bind(blob_url)
                .bind(size_bytes)
                .bind(findings_count)
                .bind(events_count)
                .bind(sources_count)
                .bind(evidence_atoms_count)
                .bind(condition_records_count)
                .bind(&snapshot_skeleton_json)
                .bind(authority_mode)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;

                let mut event_rows = Vec::with_capacity(project.events.len());
                for (idx, event) in project.events.iter().enumerate() {
                    let raw = serde_json::to_value(event)
                        .map_err(|e| format!("serialize event {}: {e}", event.id))?;
                    event_rows.push(json!({
                        "seq": idx as i64,
                        "event_id": event.id,
                        "kind": event.kind,
                        "target_type": event.target.r#type,
                        "target_id": event.target.id,
                        "actor_id": event.actor.id,
                        "event_timestamp": event.timestamp,
                        "raw_json": raw,
                    }));
                }
                for chunk in event_rows.chunks(4_000) {
                    let batch = Value::Array(chunk.to_vec());
                    sqlx::query(
                        r#"
                        INSERT INTO frontier_events (
                          vfr_id, seq, event_id, kind, target_type, target_id,
                          actor_id, event_timestamp, raw_json
                        )
                        SELECT
                          $1,
                          (item->>'seq')::bigint,
                          item->>'event_id',
                          item->>'kind',
                          item->>'target_type',
                          item->>'target_id',
                          item->>'actor_id',
                          (item->>'event_timestamp')::timestamptz,
                          item->'raw_json'
                        FROM jsonb_array_elements($2::jsonb) AS item
                        "#,
                    )
                    .bind(&entry.vfr_id)
                    .bind(&batch)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }

                for chunk in objects.chunks(1_000) {
                    let batch = Value::Array(
                        chunk
                            .iter()
                            .map(|object| {
                                json!({
                                    "object_type": object.object_type,
                                    "object_id": object.object_id,
                                    "seq": object.seq,
                                    "target_id": object.target_id,
                                    "raw_json": object.raw_json,
                                    "signer_pubkey": object.signer_pubkey,
                                })
                            })
                            .collect(),
                    );
                    sqlx::query(
                        r#"
                        INSERT INTO frontier_objects (
                          vfr_id, object_type, object_id, seq, target_id, raw_json, signer_pubkey
                        )
                        SELECT
                          $1,
                          item->>'object_type',
                          item->>'object_id',
                          (item->>'seq')::bigint,
                          item->>'target_id',
                          item->'raw_json',
                          item->>'signer_pubkey'
                        FROM jsonb_array_elements($2::jsonb) AS item
                        "#,
                    )
                    .bind(&entry.vfr_id)
                    .bind(&batch)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }

                sqlx::query(
                    r#"
                    INSERT INTO frontier_publish_audit (
                      vfr_id, registry_entry_id, latest_snapshot_hash, signed_publish_at,
                      status, error, authority_mode, findings_count, events_count,
                      sources_count, evidence_atoms_count, condition_records_count
                    )
                    VALUES ($1, $2, $3, $4::timestamptz, 'verified', NULL, $5, $6, $7, $8, $9, $10)
                    "#,
                )
                .bind(&entry.vfr_id)
                .bind(registry_entry_id)
                .bind(&entry.latest_snapshot_hash)
                .bind(&entry.signed_publish_at)
                .bind(authority_mode)
                .bind(findings_count)
                .bind(events_count)
                .bind(sources_count)
                .bind(evidence_atoms_count)
                .bind(condition_records_count)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                tx.commit().await.map_err(|e| e.to_string())?;
            }
            Self::Sqlite(p) => {
                let mut tx = p.begin().await.map_err(|e| e.to_string())?;
                sqlx::query("DELETE FROM frontier_events WHERE vfr_id = ?")
                    .bind(&entry.vfr_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query("DELETE FROM frontier_objects WHERE vfr_id = ?")
                    .bind(&entry.vfr_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query(
                    r#"
                    INSERT INTO frontiers (
                      vfr_id, registry_entry_id, name, owner_actor_id, owner_pubkey,
                      latest_snapshot_hash, latest_event_log_hash, schema_version,
                      signed_publish_at, snapshot_blob_url, snapshot_size_bytes,
                      findings_count, events_count, sources_count, evidence_atoms_count,
                      condition_records_count, materialized_snapshot_json, authority_mode, status
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'live')
                    ON CONFLICT(vfr_id) DO UPDATE SET
                      registry_entry_id = excluded.registry_entry_id,
                      name = excluded.name,
                      owner_actor_id = excluded.owner_actor_id,
                      owner_pubkey = excluded.owner_pubkey,
                      latest_snapshot_hash = excluded.latest_snapshot_hash,
                      latest_event_log_hash = excluded.latest_event_log_hash,
                      schema_version = excluded.schema_version,
                      signed_publish_at = excluded.signed_publish_at,
                      snapshot_blob_url = excluded.snapshot_blob_url,
                      snapshot_size_bytes = excluded.snapshot_size_bytes,
                      findings_count = excluded.findings_count,
                      events_count = excluded.events_count,
                      sources_count = excluded.sources_count,
                      evidence_atoms_count = excluded.evidence_atoms_count,
                      condition_records_count = excluded.condition_records_count,
                      materialized_snapshot_json = excluded.materialized_snapshot_json,
                      authority_mode = excluded.authority_mode,
                      status = 'live',
                      updated_at = datetime('now')
                    "#,
                )
                .bind(&entry.vfr_id)
                .bind(registry_entry_id)
                .bind(&entry.name)
                .bind(&entry.owner_actor_id)
                .bind(&entry.owner_pubkey)
                .bind(&entry.latest_snapshot_hash)
                .bind(&entry.latest_event_log_hash)
                .bind(schema_version)
                .bind(&entry.signed_publish_at)
                .bind(blob_url)
                .bind(size_bytes)
                .bind(findings_count)
                .bind(events_count)
                .bind(sources_count)
                .bind(evidence_atoms_count)
                .bind(condition_records_count)
                .bind(&snapshot_skeleton_json)
                .bind(authority_mode)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;

                for (idx, event) in project.events.iter().enumerate() {
                    let raw = serde_json::to_string(event)
                        .map_err(|e| format!("serialize event {}: {e}", event.id))?;
                    sqlx::query(
                        r#"
                        INSERT INTO frontier_events (
                          vfr_id, seq, event_id, kind, target_type, target_id,
                          actor_id, event_timestamp, raw_json
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        "#,
                    )
                    .bind(&entry.vfr_id)
                    .bind(idx as i64)
                    .bind(&event.id)
                    .bind(event.kind.as_str())
                    .bind(&event.target.r#type)
                    .bind(&event.target.id)
                    .bind(&event.actor.id)
                    .bind(&event.timestamp)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }

                for object in &objects {
                    let raw = serde_json::to_string(&object.raw_json)
                        .map_err(|e| format!("serialize object {}: {e}", object.object_id))?;
                    sqlx::query(
                        r#"
                        INSERT INTO frontier_objects (
                          vfr_id, object_type, object_id, seq, target_id, raw_json, signer_pubkey
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        "#,
                    )
                    .bind(&entry.vfr_id)
                    .bind(&object.object_type)
                    .bind(&object.object_id)
                    .bind(object.seq)
                    .bind(&object.target_id)
                    .bind(&raw)
                    .bind(&object.signer_pubkey)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }

                sqlx::query(
                    r#"
                    INSERT INTO frontier_publish_audit (
                      vfr_id, registry_entry_id, latest_snapshot_hash, signed_publish_at,
                      status, error, authority_mode, findings_count, events_count,
                      sources_count, evidence_atoms_count, condition_records_count
                    )
                    VALUES (?, ?, ?, ?, 'verified', NULL, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(&entry.vfr_id)
                .bind(registry_entry_id)
                .bind(&entry.latest_snapshot_hash)
                .bind(&entry.signed_publish_at)
                .bind(authority_mode)
                .bind(findings_count)
                .bind(events_count)
                .bind(sources_count)
                .bind(evidence_atoms_count)
                .bind(condition_records_count)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                tx.commit().await.map_err(|e| e.to_string())?;
            }
        }

        // Record any revoked actors into the authoritative append-only log.
        // Append-only + earliest-wins: a key revoked in any promoted snapshot
        // stays revoked even if a later snapshot drops the revocation.
        self.record_revocations(&entry.vfr_id, project).await?;

        Ok(EventFirstPromotionReport {
            vfr_id: entry.vfr_id.clone(),
            registry_entry_id,
            findings_count,
            events_count,
            sources_count,
            evidence_atoms_count,
            condition_records_count,
            objects_count,
            authority_mode: authority_mode.to_string(),
        })
    }

    /// Incrementally append a batch of already-decided records (new findings
    /// and their canonical events) to a live frontier, writing ONLY the new
    /// rows. The owner-authenticated, DB-level analogue of
    /// `incremental_ingest::append_batch` (which is the local `.vela/` path):
    /// no DELETE + re-INSERT of the whole event/object set — new events go in
    /// at `seq > max(seq)`, new objects upsert, and the `frontiers` row's
    /// counts + hashes + skeleton update in place. O(batch), not O(frontier).
    ///
    /// Guards:
    /// - **Owner continuity** — `owner_pubkey` must match the frontier's
    ///   recorded owner. This is an OWNER/maintainer deposit path: it records
    ///   decisions the owner has already made and deliberately does NOT run the
    ///   Evidence-CI accept gate. A reviewer *accept* of a truth-bearing claim
    ///   still goes through the gated accept path; this is for the spine /
    ///   watcher case (the owner asserting genesis findings).
    /// - **Optimistic concurrency** — `parent_event_log_hash` must equal the
    ///   frontier's current event-log hash, else the append is rejected with a
    ///   `conflict:`-prefixed error and the caller refetches. No frontier lock.
    /// - **Idempotency** — records whose id is already present are skipped, so
    ///   a retried deposit is a no-op.
    pub async fn append_to_frontier(
        &self,
        vfr_id: &str,
        owner_pubkey: &str,
        new_findings: &[FindingBundle],
        new_events: &[StateEvent],
        parent_event_log_hash: &str,
    ) -> Result<AppendToFrontierOutcome, String> {
        let Some(mut project) = self.get_materialized_project(vfr_id).await? else {
            return Err(format!("frontier {vfr_id} not found or not live"));
        };

        // Owner continuity is the only authority on an existing frontier; a
        // valid self-signature is NOT access control (see promote's guard).
        let accept_keys = self.effective_accept_keys(vfr_id).await?;
        match self.effective_owner_pubkey(vfr_id).await? {
            Some(_)
                if accept_keys
                    .iter()
                    .any(|k| k.eq_ignore_ascii_case(owner_pubkey)) => {}
            Some(_) => {
                return Err(format!(
                    "accept authority: append to {vfr_id} must be authorized by the \
                     frontier's owner key or an effective maintainer key"
                ));
            }
            None => return Err(format!("frontier {vfr_id} has no recorded owner")),
        }

        // Optimistic concurrency on the event-log tail — no whole-frontier lock.
        let current_hash = event_log_hash(&project.events);
        if current_hash != parent_event_log_hash {
            return Err(format!(
                "conflict: parent_event_log_hash is stale (current {current_hash}); \
                 refetch and retry"
            ));
        }

        // Dedup the batch against what's already present (idempotent re-apply).
        let existing_findings: std::collections::HashSet<&str> =
            project.findings.iter().map(|f| f.id.as_str()).collect();
        let existing_events: std::collections::HashSet<&str> =
            project.events.iter().map(|e| e.id.as_str()).collect();

        let mut to_add_findings: Vec<FindingBundle> = Vec::new();
        let mut skipped_findings = 0i64;
        for f in new_findings {
            if existing_findings.contains(f.id.as_str())
                || to_add_findings.iter().any(|x| x.id == f.id)
            {
                skipped_findings += 1;
            } else {
                to_add_findings.push(f.clone());
            }
        }
        let mut to_add_events: Vec<StateEvent> = Vec::new();
        let mut skipped_events = 0i64;
        for e in new_events {
            if existing_events.contains(e.id.as_str()) || to_add_events.iter().any(|x| x.id == e.id)
            {
                skipped_events += 1;
            } else {
                to_add_events.push(e.clone());
            }
        }

        // The appended events get seq continuing from the current tail.
        let base_seq = project.events.len() as i64;

        // Build the post-append project so hashes + counts + skeleton are
        // coherent. recompute_stats keeps the snapshot hash canonical.
        project.findings.extend(to_add_findings.iter().cloned());
        project.events.extend(to_add_events.iter().cloned());
        // CANONICAL EVENT ORDER: the CLI loader reads `.vela/events/{id}.json`
        // and sorts by filename, i.e. by content-hash id. An append, left
        // alone, would land new events at the tail (append order) and store a
        // tail-order event_log_hash + skeleton that a cold `vela clone`
        // (which reloads id-sorted) would NOT match — breaking clone/pull on
        // appended frontiers. Sort by id here so the stored hash + the served
        // snapshot are in the SAME canonical order the loader reconstructs.
        // (For a full promote the publisher already id-sorts, so this is a
        // no-op there; seq stays append-order in frontier_events, which only
        // affects the order-independent /events listing.)
        project.events.sort_by(|a, b| a.id.cmp(&b.id));
        vela_protocol::project::recompute_stats(&mut project);

        let new_event_log_hash = event_log_hash(&project.events);
        let new_snapshot_hash = snapshot_hash(&project);
        let snapshot_value =
            serde_json::to_value(&project).map_err(|e| format!("serialize project: {e}"))?;
        let skeleton_json = serde_json::to_string(&frontier_skeleton(&snapshot_value))
            .map_err(|e| format!("skeleton json: {e}"))?;

        // Object rows for ONLY the new findings — keeps the write O(batch),
        // derived exactly as promote derives them (same `collect_frontier_objects`).
        let new_findings_value =
            serde_json::to_value(&to_add_findings).map_err(|e| format!("findings json: {e}"))?;
        let new_objects = collect_frontier_objects(&json!({
            "findings": new_findings_value,
            "sources": [], "evidence_atoms": [], "condition_records": [],
            "actors": [], "artifacts": [], "proposals": [],
        }));

        let findings_count = project.findings.len() as i64;
        let events_count = project.events.len() as i64;
        let sources_count = project.sources.len() as i64;
        let evidence_atoms_count = project.evidence_atoms.len() as i64;
        let condition_records_count = project.condition_records.len() as i64;

        match self {
            Self::Postgres(p) => {
                let mut tx = p.begin().await.map_err(|e| e.to_string())?;
                for (j, event) in to_add_events.iter().enumerate() {
                    let raw = serde_json::to_string(event)
                        .map_err(|e| format!("serialize event {}: {e}", event.id))?;
                    sqlx::query(
                        r#"
                        INSERT INTO frontier_events (
                          vfr_id, seq, event_id, kind, target_type, target_id,
                          actor_id, event_timestamp, raw_json
                        )
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9::jsonb)
                        ON CONFLICT (vfr_id, event_id) DO NOTHING
                        "#,
                    )
                    .bind(vfr_id)
                    .bind(base_seq + j as i64)
                    .bind(&event.id)
                    .bind(event.kind.as_str())
                    .bind(&event.target.r#type)
                    .bind(&event.target.id)
                    .bind(&event.actor.id)
                    .bind(&event.timestamp)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }
                for object in &new_objects {
                    let raw = serde_json::to_string(&object.raw_json)
                        .map_err(|e| format!("serialize object {}: {e}", object.object_id))?;
                    sqlx::query(
                        r#"
                        INSERT INTO frontier_objects (
                          vfr_id, object_type, object_id, seq, target_id, raw_json
                        )
                        VALUES ($1, $2, $3, $4, $5, $6::jsonb)
                        ON CONFLICT (vfr_id, object_type, object_id) DO NOTHING
                        "#,
                    )
                    .bind(vfr_id)
                    .bind(&object.object_type)
                    .bind(&object.object_id)
                    .bind(object.seq)
                    .bind(&object.target_id)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }
                sqlx::query(
                    r#"
                    UPDATE frontiers SET
                      latest_snapshot_hash = $2,
                      latest_event_log_hash = $3,
                      findings_count = $4,
                      events_count = $5,
                      sources_count = $6,
                      evidence_atoms_count = $7,
                      condition_records_count = $8,
                      materialized_snapshot_json = $9::jsonb,
                      updated_at = now()
                    WHERE vfr_id = $1 AND status = 'live'
                    "#,
                )
                .bind(vfr_id)
                .bind(&new_snapshot_hash)
                .bind(&new_event_log_hash)
                .bind(findings_count)
                .bind(events_count)
                .bind(sources_count)
                .bind(evidence_atoms_count)
                .bind(condition_records_count)
                .bind(&skeleton_json)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                tx.commit().await.map_err(|e| e.to_string())?;
            }
            Self::Sqlite(p) => {
                let mut tx = p.begin().await.map_err(|e| e.to_string())?;
                for (j, event) in to_add_events.iter().enumerate() {
                    let raw = serde_json::to_string(event)
                        .map_err(|e| format!("serialize event {}: {e}", event.id))?;
                    sqlx::query(
                        r#"
                        INSERT INTO frontier_events (
                          vfr_id, seq, event_id, kind, target_type, target_id,
                          actor_id, event_timestamp, raw_json
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT (vfr_id, event_id) DO NOTHING
                        "#,
                    )
                    .bind(vfr_id)
                    .bind(base_seq + j as i64)
                    .bind(&event.id)
                    .bind(event.kind.as_str())
                    .bind(&event.target.r#type)
                    .bind(&event.target.id)
                    .bind(&event.actor.id)
                    .bind(&event.timestamp)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }
                for object in &new_objects {
                    let raw = serde_json::to_string(&object.raw_json)
                        .map_err(|e| format!("serialize object {}: {e}", object.object_id))?;
                    sqlx::query(
                        r#"
                        INSERT INTO frontier_objects (
                          vfr_id, object_type, object_id, seq, target_id, raw_json
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT (vfr_id, object_type, object_id) DO NOTHING
                        "#,
                    )
                    .bind(vfr_id)
                    .bind(&object.object_type)
                    .bind(&object.object_id)
                    .bind(object.seq)
                    .bind(&object.target_id)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }
                sqlx::query(
                    r#"
                    UPDATE frontiers SET
                      latest_snapshot_hash = ?2,
                      latest_event_log_hash = ?3,
                      findings_count = ?4,
                      events_count = ?5,
                      sources_count = ?6,
                      evidence_atoms_count = ?7,
                      condition_records_count = ?8,
                      materialized_snapshot_json = ?9,
                      updated_at = datetime('now')
                    WHERE vfr_id = ?1 AND status = 'live'
                    "#,
                )
                .bind(vfr_id)
                .bind(&new_snapshot_hash)
                .bind(&new_event_log_hash)
                .bind(findings_count)
                .bind(events_count)
                .bind(sources_count)
                .bind(evidence_atoms_count)
                .bind(condition_records_count)
                .bind(&skeleton_json)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                tx.commit().await.map_err(|e| e.to_string())?;
            }
        }

        Ok(AppendToFrontierOutcome {
            vfr_id: vfr_id.to_string(),
            appended_findings: to_add_findings.len() as i64,
            appended_events: to_add_events.len() as i64,
            skipped_duplicate_findings: skipped_findings,
            skipped_duplicate_events: skipped_events,
            findings_count,
            events_count,
            new_event_log_hash,
            new_snapshot_hash,
        })
    }

    pub async fn record_publish_audit_failed(
        &self,
        entry: &RegistryEntry,
        error: &str,
        authority_mode: &str,
    ) -> Result<(), String> {
        let registry_entry_id = self.registry_entry_id(entry).await?;
        match self {
            Self::Postgres(p) => {
                let mut tx = p.begin().await.map_err(|e| e.to_string())?;
                sqlx::query(
                    r#"
                    INSERT INTO frontier_publish_audit (
                      vfr_id, registry_entry_id, latest_snapshot_hash, signed_publish_at,
                      status, error, authority_mode
                    )
                    VALUES ($1, $2, $3, $4::timestamptz, 'failed', $5, $6)
                    "#,
                )
                .bind(&entry.vfr_id)
                .bind(registry_entry_id)
                .bind(&entry.latest_snapshot_hash)
                .bind(&entry.signed_publish_at)
                .bind(error)
                .bind(authority_mode)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                sqlx::query(
                    "UPDATE frontiers SET status = 'unavailable', updated_at = now() WHERE vfr_id = $1",
                )
                .bind(&entry.vfr_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                tx.commit().await.map_err(|e| e.to_string())
            }
            Self::Sqlite(p) => {
                let mut tx = p.begin().await.map_err(|e| e.to_string())?;
                sqlx::query(
                    r#"
                    INSERT INTO frontier_publish_audit (
                      vfr_id, registry_entry_id, latest_snapshot_hash, signed_publish_at,
                      status, error, authority_mode
                    )
                    VALUES (?, ?, ?, ?, 'failed', ?, ?)
                    "#,
                )
                .bind(&entry.vfr_id)
                .bind(registry_entry_id)
                .bind(&entry.latest_snapshot_hash)
                .bind(&entry.signed_publish_at)
                .bind(error)
                .bind(authority_mode)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                sqlx::query(
                    "UPDATE frontiers SET status = 'unavailable', updated_at = datetime('now') WHERE vfr_id = ?",
                )
                .bind(&entry.vfr_id)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;
                tx.commit().await.map_err(|e| e.to_string())
            }
        }
    }

    pub async fn get_materialized_project(&self, vfr_id: &str) -> Result<Option<Project>, String> {
        match self {
            Self::Postgres(p) => {
                let mut value: Option<Value> = sqlx::query_scalar(
                    "SELECT materialized_snapshot_json FROM frontiers WHERE vfr_id = $1 AND status = 'live'",
                )
                .bind(vfr_id)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                if let Some(snapshot) = value.as_mut() {
                    let rows = sqlx::query(
                        r#"
                        SELECT object_type, seq, raw_json
                        FROM frontier_objects
                        WHERE vfr_id = $1
                        ORDER BY object_type, seq
                        "#,
                    )
                    .bind(vfr_id)
                    .fetch_all(p)
                    .await
                    .map_err(|e| e.to_string())?;
                    let objects = rows
                        .into_iter()
                        .map(|row| {
                            Ok((
                                row.try_get::<String, _>("object_type")?,
                                row.try_get::<i64, _>("seq")?,
                                row.try_get::<Value, _>("raw_json")?,
                            ))
                        })
                        .collect::<Result<Vec<_>, sqlx::Error>>()
                        .map_err(|e| e.to_string())?;
                    merge_projected_objects(snapshot, objects);
                }
                value
                    .map(serde_json::from_value::<Project>)
                    .transpose()
                    .map_err(|e| e.to_string())
            }
            Self::Sqlite(p) => {
                let value: Option<String> = sqlx::query_scalar(
                    "SELECT materialized_snapshot_json FROM frontiers WHERE vfr_id = ? AND status = 'live'",
                )
                .bind(vfr_id)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                let Some(raw) = value else {
                    return Ok(None);
                };
                let mut snapshot =
                    serde_json::from_str::<Value>(&raw).map_err(|e| e.to_string())?;
                let rows: Vec<(String, i64, String)> = sqlx::query_as(
                    r#"
                    SELECT object_type, seq, raw_json
                    FROM frontier_objects
                    WHERE vfr_id = ?
                    ORDER BY object_type, seq
                    "#,
                )
                .bind(vfr_id)
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                let objects = rows
                    .into_iter()
                    .map(|(object_type, seq, raw)| {
                        serde_json::from_str::<Value>(&raw)
                            .map(|value| (object_type, seq, value))
                            .map_err(|e| e.to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                merge_projected_objects(&mut snapshot, objects);
                serde_json::from_value::<Project>(snapshot)
                    .map(Some)
                    .map_err(|e| e.to_string())
            }
        }
    }

    pub async fn event_log_hash_from_db(&self, vfr_id: &str) -> Result<String, String> {
        let values = self
            .event_values_after(vfr_id, None, None, None, i64::MAX)
            .await?;
        let mut events: Vec<StateEvent> = values
            .into_iter()
            .map(serde_json::from_value)
            .collect::<Result<_, _>>()
            .map_err(|e| format!("parse event log: {e}"))?;
        // Hash in the loader's canonical id-sorted order (rows come back in
        // seq/append order), so this recompute equals the stored hash and what
        // a cold clone reconstructs. See append_to_frontier.
        events.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(event_log_hash(&events))
    }

    pub async fn event_page(
        &self,
        vfr_id: &str,
        since: Option<&str>,
        limit: usize,
        kind: Option<&str>,
        target: Option<&str>,
    ) -> Result<EventPage, String> {
        let cursor_seq = match since {
            Some(cursor) => Some(self.event_seq(vfr_id, cursor).await?.ok_or_else(|| {
                format!("cursor_not_found: cursor '{cursor}' not found in event log")
            })?),
            None => None,
        };
        let take = limit.clamp(1, 500) as i64;
        let rows = self
            .event_values_after(vfr_id, cursor_seq, kind, target, take + 1)
            .await?;
        let log_total = self.event_log_total(vfr_id).await?;
        let has_more = rows.len() as i64 > take;
        let events: Vec<Value> = rows.into_iter().take(take as usize).collect();
        let next_cursor = if has_more {
            events
                .last()
                .and_then(|v| v.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        };
        Ok(EventPage {
            events,
            next_cursor,
            log_total,
        })
    }

    async fn event_seq(&self, vfr_id: &str, event_id: &str) -> Result<Option<i64>, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, i64>(
                "SELECT seq FROM frontier_events WHERE vfr_id = $1 AND event_id = $2",
            )
            .bind(vfr_id)
            .bind(event_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => sqlx::query_scalar::<_, i64>(
                "SELECT seq FROM frontier_events WHERE vfr_id = ? AND event_id = ?",
            )
            .bind(vfr_id)
            .bind(event_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string()),
        }
    }

    async fn event_log_total(&self, vfr_id: &str) -> Result<i64, String> {
        match self {
            Self::Postgres(p) => sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM frontier_events WHERE vfr_id = $1",
            )
            .bind(vfr_id)
            .fetch_one(p)
            .await
            .map_err(|e| e.to_string()),
            Self::Sqlite(p) => sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM frontier_events WHERE vfr_id = ?",
            )
            .bind(vfr_id)
            .fetch_one(p)
            .await
            .map_err(|e| e.to_string()),
        }
    }

    async fn event_values_after(
        &self,
        vfr_id: &str,
        cursor_seq: Option<i64>,
        kind: Option<&str>,
        target: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Value>, String> {
        let start_seq = cursor_seq.unwrap_or(-1);
        match self {
            Self::Postgres(p) => sqlx::query(
                r#"
                SELECT raw_json
                FROM frontier_events
                WHERE vfr_id = $1
                  AND seq > $2
                  AND ($3::text IS NULL OR kind = $3)
                  AND ($4::text IS NULL OR target_id = $4)
                ORDER BY seq ASC
                LIMIT $5
                "#,
            )
            .bind(vfr_id)
            .bind(start_seq)
            .bind(kind)
            .bind(target)
            .bind(limit)
            .fetch_all(p)
            .await
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|row| {
                row.try_get::<Value, _>("raw_json")
                    .map_err(|e| e.to_string())
            })
            .collect(),
            Self::Sqlite(p) => {
                let rows: Vec<String> = sqlx::query_scalar(
                    r#"
                    SELECT raw_json
                    FROM frontier_events
                    WHERE vfr_id = ?
                      AND seq > ?
                      AND (? IS NULL OR kind = ?)
                      AND (? IS NULL OR target_id = ?)
                    ORDER BY seq ASC
                    LIMIT ?
                    "#,
                )
                .bind(vfr_id)
                .bind(start_seq)
                .bind(kind)
                .bind(kind)
                .bind(target)
                .bind(target)
                .bind(limit)
                .fetch_all(p)
                .await
                .map_err(|e| e.to_string())?;
                rows.into_iter()
                    .map(|s| serde_json::from_str::<Value>(&s).map_err(|e| e.to_string()))
                    .collect()
            }
        }
    }

    /// Record metadata for a content-addressed snapshot whose bytes
    /// already live in object storage at `blob_url`. Idempotent on
    /// `snapshot_hash` — re-publishing identical content is a no-op
    /// (PK conflict). Returns true on fresh insert.
    ///
    /// v0.55.1: substrate bytes do NOT live in this row. They live at
    /// `blob_url` in Tigris/R2. This row is just the metadata index
    /// the hub uses to route GETs and verify content addressing.
    pub async fn insert_snapshot(
        &self,
        snapshot_hash: &str,
        schema_version: &str,
        size_bytes: i32,
        blob_url: &str,
        content_type: &str,
    ) -> Result<bool, String> {
        match self {
            Self::Postgres(p) => {
                let inserted = sqlx::query_scalar::<_, String>(
                    r#"
                    INSERT INTO frontier_snapshots (
                      snapshot_hash, schema_version, size_bytes, blob_url, content_type
                    )
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT (snapshot_hash) DO NOTHING
                    RETURNING snapshot_hash
                    "#,
                )
                .bind(snapshot_hash)
                .bind(schema_version)
                .bind(size_bytes)
                .bind(blob_url)
                .bind(content_type)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(inserted.is_some())
            }
            Self::Sqlite(p) => {
                let result = sqlx::query(
                    r#"
                    INSERT OR IGNORE INTO frontier_snapshots (
                      snapshot_hash, schema_version, size_bytes, blob_url, content_type
                    )
                    VALUES (?, ?, ?, ?, ?)
                    "#,
                )
                .bind(snapshot_hash)
                .bind(schema_version)
                .bind(size_bytes)
                .bind(blob_url)
                .bind(content_type)
                .execute(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    /// Look up the storage URL for a content-addressed snapshot export.
    /// The hub uses this only when callers request
    /// `GET /entries/:vfr/snapshot?redirect=cdn`; live reads come from
    /// event/projection tables.
    pub async fn get_snapshot_meta(
        &self,
        snapshot_hash: &str,
    ) -> Result<Option<SnapshotMeta>, String> {
        match self {
            Self::Postgres(p) => {
                let row: Option<(String, String, String, i32)> = sqlx::query_as(
                    "SELECT blob_url, content_type, schema_version, size_bytes
                     FROM frontier_snapshots WHERE snapshot_hash = $1",
                )
                .bind(snapshot_hash)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(row.map(
                    |(blob_url, content_type, schema_version, size_bytes)| SnapshotMeta {
                        blob_url,
                        content_type,
                        schema_version,
                        size_bytes,
                    },
                ))
            }
            Self::Sqlite(p) => {
                let row: Option<(String, String, String, i64)> = sqlx::query_as(
                    "SELECT blob_url, content_type, schema_version, size_bytes
                     FROM frontier_snapshots WHERE snapshot_hash = ?",
                )
                .bind(snapshot_hash)
                .fetch_optional(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(row.map(
                    |(blob_url, content_type, schema_version, size_bytes)| SnapshotMeta {
                        blob_url,
                        content_type,
                        schema_version,
                        size_bytes: size_bytes as i32,
                    },
                ))
            }
        }
    }

    /// v0.128: enqueue a verified, signature-bound `StateProposal` as a
    /// pending projected object on the frontier. The proposal lands as a
    /// `frontier_objects` row (`object_type = 'proposal'`, `object_id =
    /// proposal.id`) so `get_materialized_project` merges it into
    /// `project.proposals` via `merge_projected_objects` exactly as it
    /// merges every other projected object.
    ///
    /// Idempotency: the `vpr_` content address is the natural key. The
    /// upsert is `ON CONFLICT (vfr_id, object_type, object_id) DO NOTHING`,
    /// so an agent re-POSTing the same signed proposal is a no-op and the
    /// returned `bool` reports `true` for a duplicate.
    ///
    /// The status is forced to `pending_review` at the boundary; this
    /// method stores the proposal verbatim and does not apply it.
    pub async fn append_pending_proposal(
        &self,
        vfr_id: &str,
        proposal: &vela_protocol::proposals::StateProposal,
    ) -> Result<bool, String> {
        let raw_value = serde_json::to_value(proposal)
            .map_err(|e| format!("serialize proposal {}: {e}", proposal.id))?;
        let target_id = proposal.target.id.clone();
        match self {
            Self::Postgres(p) => {
                // seq is appended after the current max for this object_type
                // so the projection preserves submission order.
                let next_seq: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(seq), -1) + 1 FROM frontier_objects \
                     WHERE vfr_id = $1 AND object_type = 'proposal'",
                )
                .bind(vfr_id)
                .fetch_one(p)
                .await
                .map_err(|e| e.to_string())?;
                let inserted = sqlx::query(
                    r#"INSERT INTO frontier_objects (
                          vfr_id, object_type, object_id, seq, target_id, raw_json
                       )
                       VALUES ($1, 'proposal', $2, $3, $4, $5)
                       ON CONFLICT (vfr_id, object_type, object_id) DO NOTHING"#,
                )
                .bind(vfr_id)
                .bind(&proposal.id)
                .bind(next_seq)
                .bind(&target_id)
                .bind(&raw_value)
                .execute(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(inserted.rows_affected() == 0)
            }
            Self::Sqlite(p) => {
                let next_seq: i64 = sqlx::query_scalar(
                    "SELECT COALESCE(MAX(seq), -1) + 1 FROM frontier_objects \
                     WHERE vfr_id = ? AND object_type = 'proposal'",
                )
                .bind(vfr_id)
                .fetch_one(p)
                .await
                .map_err(|e| e.to_string())?;
                let raw_string = serde_json::to_string(&raw_value)
                    .map_err(|e| format!("serialize proposal {}: {e}", proposal.id))?;
                let inserted = sqlx::query(
                    r#"INSERT OR IGNORE INTO frontier_objects (
                          vfr_id, object_type, object_id, seq, target_id, raw_json
                       )
                       VALUES (?, 'proposal', ?, ?, ?, ?)"#,
                )
                .bind(vfr_id)
                .bind(&proposal.id)
                .bind(next_seq)
                .bind(&target_id)
                .bind(&raw_string)
                .execute(p)
                .await
                .map_err(|e| e.to_string())?;
                Ok(inserted.rows_affected() == 0)
            }
        }
    }

    /// v0.128: persist the result of an accepted proposal in ONE
    /// transaction. The caller has already run `accept_in_frontier_engine`
    /// (strict, no-force) over the materialized `project`, which flipped
    /// the proposal to `applied` (setting `reviewed_by` / `reviewed_at` /
    /// `decision_reason` / `applied_event_id`) and appended the canonical
    /// apply `event` to `project.events`. This method rewrites the
    /// frontier projection to that accepted state:
    ///
    ///   (a) the proposal object rows are refreshed (the accepted
    ///       proposal now carries status=applied),
    ///   (b) the emitted canonical `event` is appended to `frontier_events`
    ///       under the `UNIQUE (vfr_id, event_id)` guard — a re-accept of
    ///       the same proposal yields the same event id, the insert is a
    ///       no-op, and the method reports `Duplicate`,
    ///   (c) the `frontiers.materialized_snapshot_json` skeleton + counts
    ///       are refreshed.
    ///
    /// All three happen inside a single DB transaction, so a failed
    /// persist leaves zero canonical state change. The whole projection
    /// for `vfr_id` is rebuilt from `project` (delete + reinsert
    /// events/objects), matching the `promote_frontier_snapshot` write
    /// shape; the frontier row's identity columns (owner, hashes,
    /// signed_publish_at) are preserved by only updating the projection
    /// columns.
    pub async fn persist_accept(
        &self,
        vfr_id: &str,
        project: &Project,
        event_id: &str,
    ) -> Result<AppendOutcome, String> {
        // Replay idempotency: if the emitted apply event is already on the
        // log, the accept has already been persisted. Report Duplicate and
        // do not rewrite anything.
        let already: Option<i64> = match self {
            Self::Postgres(p) => sqlx::query_scalar(
                "SELECT seq FROM frontier_events WHERE vfr_id = $1 AND event_id = $2",
            )
            .bind(vfr_id)
            .bind(event_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
            Self::Sqlite(p) => sqlx::query_scalar(
                "SELECT seq FROM frontier_events WHERE vfr_id = ? AND event_id = ?",
            )
            .bind(vfr_id)
            .bind(event_id)
            .fetch_optional(p)
            .await
            .map_err(|e| e.to_string())?,
        };
        if let Some(seq) = already {
            return Ok(AppendOutcome::Duplicate { seq });
        }

        let snapshot_value =
            serde_json::to_value(project).map_err(|e| format!("serialize project: {e}"))?;
        let snapshot_skeleton = frontier_skeleton(&snapshot_value);
        let snapshot_skeleton_json =
            serde_json::to_string(&snapshot_skeleton).map_err(|e| format!("project json: {e}"))?;
        let objects = collect_frontier_objects(&snapshot_value);
        let findings_count = project.findings.len() as i64;
        let events_count = project.events.len() as i64;
        let sources_count = project.sources.len() as i64;
        let evidence_atoms_count = project.evidence_atoms.len() as i64;
        let condition_records_count = project.condition_records.len() as i64;
        let applied_seq = events_count - 1;

        match self {
            Self::Postgres(p) => {
                let mut tx = p.begin().await.map_err(|e| e.to_string())?;
                sqlx::query("DELETE FROM frontier_events WHERE vfr_id = $1")
                    .bind(vfr_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query("DELETE FROM frontier_objects WHERE vfr_id = $1")
                    .bind(vfr_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query(
                    r#"UPDATE frontiers SET
                         findings_count = $2,
                         events_count = $3,
                         sources_count = $4,
                         evidence_atoms_count = $5,
                         condition_records_count = $6,
                         materialized_snapshot_json = $7::jsonb,
                         updated_at = now()
                       WHERE vfr_id = $1"#,
                )
                .bind(vfr_id)
                .bind(findings_count)
                .bind(events_count)
                .bind(sources_count)
                .bind(evidence_atoms_count)
                .bind(condition_records_count)
                .bind(&snapshot_skeleton_json)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;

                for (idx, event) in project.events.iter().enumerate() {
                    let raw = serde_json::to_value(event)
                        .map_err(|e| format!("serialize event {}: {e}", event.id))?;
                    sqlx::query(
                        r#"INSERT INTO frontier_events (
                              vfr_id, seq, event_id, kind, target_type, target_id,
                              actor_id, event_timestamp, raw_json
                           )
                           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, $9)"#,
                    )
                    .bind(vfr_id)
                    .bind(idx as i64)
                    .bind(&event.id)
                    .bind(event.kind.as_str())
                    .bind(&event.target.r#type)
                    .bind(&event.target.id)
                    .bind(&event.actor.id)
                    .bind(&event.timestamp)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }

                for object in &objects {
                    sqlx::query(
                        r#"INSERT INTO frontier_objects (
                              vfr_id, object_type, object_id, seq, target_id, raw_json
                           )
                           VALUES ($1, $2, $3, $4, $5, $6)"#,
                    )
                    .bind(vfr_id)
                    .bind(&object.object_type)
                    .bind(&object.object_id)
                    .bind(object.seq)
                    .bind(&object.target_id)
                    .bind(&object.raw_json)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }

                tx.commit().await.map_err(|e| e.to_string())?;
                Ok(AppendOutcome::Inserted { seq: applied_seq })
            }
            Self::Sqlite(p) => {
                let mut tx = p.begin().await.map_err(|e| e.to_string())?;
                sqlx::query("DELETE FROM frontier_events WHERE vfr_id = ?")
                    .bind(vfr_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query("DELETE FROM frontier_objects WHERE vfr_id = ?")
                    .bind(vfr_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                sqlx::query(
                    r#"UPDATE frontiers SET
                         findings_count = ?2,
                         events_count = ?3,
                         sources_count = ?4,
                         evidence_atoms_count = ?5,
                         condition_records_count = ?6,
                         materialized_snapshot_json = ?7,
                         updated_at = datetime('now')
                       WHERE vfr_id = ?1"#,
                )
                .bind(vfr_id)
                .bind(findings_count)
                .bind(events_count)
                .bind(sources_count)
                .bind(evidence_atoms_count)
                .bind(condition_records_count)
                .bind(&snapshot_skeleton_json)
                .execute(&mut *tx)
                .await
                .map_err(|e| e.to_string())?;

                for (idx, event) in project.events.iter().enumerate() {
                    let raw = serde_json::to_string(event)
                        .map_err(|e| format!("serialize event {}: {e}", event.id))?;
                    sqlx::query(
                        r#"INSERT INTO frontier_events (
                              vfr_id, seq, event_id, kind, target_type, target_id,
                              actor_id, event_timestamp, raw_json
                           )
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"#,
                    )
                    .bind(vfr_id)
                    .bind(idx as i64)
                    .bind(&event.id)
                    .bind(event.kind.as_str())
                    .bind(&event.target.r#type)
                    .bind(&event.target.id)
                    .bind(&event.actor.id)
                    .bind(&event.timestamp)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }

                for object in &objects {
                    let raw = serde_json::to_string(&object.raw_json)
                        .map_err(|e| format!("serialize object {}: {e}", object.object_id))?;
                    sqlx::query(
                        r#"INSERT INTO frontier_objects (
                              vfr_id, object_type, object_id, seq, target_id, raw_json
                           )
                           VALUES (?, ?, ?, ?, ?, ?)"#,
                    )
                    .bind(vfr_id)
                    .bind(&object.object_type)
                    .bind(&object.object_id)
                    .bind(object.seq)
                    .bind(&object.target_id)
                    .bind(&raw)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| e.to_string())?;
                }

                tx.commit().await.map_err(|e| e.to_string())?;
                Ok(AppendOutcome::Inserted { seq: applied_seq })
            }
        }
    }
}

/// Outcome of an idempotent append (e.g. `persist_accept`). `Duplicate`
/// covers the idempotent retry path (same signed object arriving twice)
/// and is surfaced as 200 OK to the caller. `Inserted` is the fresh-write
/// path and is surfaced as 202 Accepted.
#[derive(Debug, Clone)]
pub enum AppendOutcome {
    Inserted { seq: i64 },
    Duplicate { seq: i64 },
}

/// The metadata the hub holds about a snapshot. The bytes themselves
/// live at `blob_url` (typically a Tigris/R2 public URL).
#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    pub blob_url: String,
    pub content_type: String,
    pub schema_version: String,
    pub size_bytes: i32,
}

pub const POSTGRES_EVENT_FIRST_SCHEMA: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS frontiers (
        vfr_id TEXT PRIMARY KEY,
        registry_entry_id BIGINT REFERENCES registry_entries(id),
        name TEXT NOT NULL,
        owner_actor_id TEXT NOT NULL,
        owner_pubkey TEXT NOT NULL,
        latest_snapshot_hash TEXT NOT NULL,
        latest_event_log_hash TEXT NOT NULL,
        schema_version TEXT NOT NULL,
        signed_publish_at TIMESTAMPTZ NOT NULL,
        snapshot_blob_url TEXT NOT NULL DEFAULT '',
        snapshot_size_bytes BIGINT NOT NULL DEFAULT 0,
        findings_count BIGINT NOT NULL DEFAULT 0,
        events_count BIGINT NOT NULL DEFAULT 0,
        sources_count BIGINT NOT NULL DEFAULT 0,
        evidence_atoms_count BIGINT NOT NULL DEFAULT 0,
        condition_records_count BIGINT NOT NULL DEFAULT 0,
        materialized_snapshot_json JSONB NOT NULL,
        authority_mode TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'live',
        inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_frontiers_signed_publish_at ON frontiers (signed_publish_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_frontiers_status ON frontiers (status)",
    r#"CREATE TABLE IF NOT EXISTS frontier_events (
        vfr_id TEXT NOT NULL REFERENCES frontiers(vfr_id) ON DELETE CASCADE,
        seq BIGINT NOT NULL,
        event_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        target_type TEXT NOT NULL,
        target_id TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        event_timestamp TIMESTAMPTZ NOT NULL,
        raw_json JSONB NOT NULL,
        inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (vfr_id, seq),
        UNIQUE (vfr_id, event_id)
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_frontier_events_cursor ON frontier_events (vfr_id, seq)",
    "CREATE INDEX IF NOT EXISTS idx_frontier_events_kind ON frontier_events (vfr_id, kind, seq)",
    "CREATE INDEX IF NOT EXISTS idx_frontier_events_target ON frontier_events (vfr_id, target_id, seq)",
    r#"CREATE TABLE IF NOT EXISTS frontier_objects (
        vfr_id TEXT NOT NULL REFERENCES frontiers(vfr_id) ON DELETE CASCADE,
        object_type TEXT NOT NULL,
        object_id TEXT NOT NULL,
        seq BIGINT NOT NULL DEFAULT 0,
        target_id TEXT,
        raw_json JSONB NOT NULL,
        inserted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (vfr_id, object_type, object_id)
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_frontier_objects_type ON frontier_objects (vfr_id, object_type)",
    "CREATE INDEX IF NOT EXISTS idx_frontier_objects_target ON frontier_objects (vfr_id, target_id)",
    r#"CREATE TABLE IF NOT EXISTS frontier_publish_audit (
        id BIGSERIAL PRIMARY KEY,
        vfr_id TEXT NOT NULL,
        registry_entry_id BIGINT REFERENCES registry_entries(id),
        latest_snapshot_hash TEXT NOT NULL,
        signed_publish_at TIMESTAMPTZ NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        authority_mode TEXT,
        findings_count BIGINT NOT NULL DEFAULT 0,
        events_count BIGINT NOT NULL DEFAULT 0,
        sources_count BIGINT NOT NULL DEFAULT 0,
        evidence_atoms_count BIGINT NOT NULL DEFAULT 0,
        condition_records_count BIGINT NOT NULL DEFAULT 0,
        verified_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_frontier_publish_audit_vfr ON frontier_publish_audit (vfr_id, verified_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_frontier_publish_audit_status ON frontier_publish_audit (status)",
    // Authoritative, append-only revocation log. Keyed by the cryptographic
    // identity (pubkey), recorded on promote when a snapshot's actor carries a
    // revoked_at. ON CONFLICT DO NOTHING makes it earliest-wins / never-undone:
    // once a key is revoked it stays revoked here, so a later snapshot that
    // drops the revocation (silent un-revoke) cannot restore its authority —
    // the accept/append paths consult this log, not just the mutable snapshot.
    r#"CREATE TABLE IF NOT EXISTS frontier_revocations (
        vfr_id TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        actor_id TEXT NOT NULL,
        revoked_at TEXT NOT NULL,
        revoked_reason TEXT,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        PRIMARY KEY (vfr_id, pubkey)
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_frontier_revocations_vfr ON frontier_revocations (vfr_id)",
    // Frontier lifecycle: append-only, earliest-wins deprecation log.
    // Once deprecated a frontier never returns to 'live' (a successor is
    // a new vfr_id). Mirrors the revocation pattern above. The signed
    // DeprecationRecord rides in raw_json as the audit receipt.
    r#"CREATE TABLE IF NOT EXISTS frontier_deprecations (
        vfr_id TEXT NOT NULL PRIMARY KEY,
        deprecated_at TEXT NOT NULL,
        reason TEXT,
        raw_json JSONB NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )"#,
    // Durable publish receipts: the signed manifest archived to object
    // storage, content-addressed by sha256(canonical manifest bytes).
    // Postgres becomes a queryable cache; the trust chain (manifest +
    // snapshot blobs) is reconstructible from storage alone.
    "ALTER TABLE registry_entries ADD COLUMN IF NOT EXISTS manifest_blob_url TEXT",
    // Owner rotation: the CURRENT owner key authorizes a successor.
    // Append-only chain; the effective owner is the latest rotation's
    // successor (or the original publisher if none). The signed record
    // rides in raw_json as the audit receipt.
    r#"CREATE TABLE IF NOT EXISTS frontier_owner_rotations (
        id BIGSERIAL PRIMARY KEY,
        vfr_id TEXT NOT NULL,
        new_owner_pubkey TEXT NOT NULL,
        rotated_at TEXT NOT NULL,
        raw_json JSONB NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_owner_rotations_vfr ON frontier_owner_rotations (vfr_id, id DESC)",
    // Maintainer sets: append-only add/remove actions; the effective set
    // is the latest action per pubkey. Accept authority = owner key OR
    // any effective maintainer (the Linux pull model).
    r#"CREATE TABLE IF NOT EXISTS frontier_maintainers (
        id BIGSERIAL PRIMARY KEY,
        vfr_id TEXT NOT NULL,
        pubkey TEXT NOT NULL,
        action TEXT NOT NULL,
        authorized_by_pubkey TEXT NOT NULL,
        authorized_at TEXT NOT NULL,
        raw_json JSONB NOT NULL,
        recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_frontier_maintainers_vfr ON frontier_maintainers (vfr_id, pubkey, id DESC)",
    // Producer index: signer extracted at promote for cross-frontier
    // per-key queries.
    "ALTER TABLE frontier_objects ADD COLUMN IF NOT EXISTS signer_pubkey TEXT",
    // v0.201: federation handle for `vsd_*` Scientific Diff Packs.
    // Mirror of registry_entries but for the v0.193 primitive.
    r#"CREATE TABLE IF NOT EXISTS registry_diff_packs (
        id BIGSERIAL PRIMARY KEY,
        pack_id TEXT NOT NULL,
        frontier_id TEXT NOT NULL,
        aggregate_kind TEXT NOT NULL,
        summary TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        agent_run TEXT,
        parent_pack TEXT,
        applied_event_id TEXT,
        member_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        signature TEXT NOT NULL,
        signer_pubkey_hex TEXT NOT NULL,
        raw_json JSONB NOT NULL,
        inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_registry_diff_packs_pack_id ON registry_diff_packs (pack_id)",
    "CREATE INDEX IF NOT EXISTS idx_registry_diff_packs_frontier_id ON registry_diff_packs (frontier_id)",
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_registry_diff_packs_pack_sig ON registry_diff_packs (pack_id, signature)",
    // Snapshot blob routing index: content-addressed pointer (snapshot_hash ->
    // Tigris blob_url) the `?redirect=cdn` path reads via get_snapshot_meta.
    // The live hub has this table from schema history, but it was missing from
    // this Postgres schema string — so a FRESH Postgres hub would fail
    // `insert_snapshot` on the first publish. `IF NOT EXISTS` makes adding it a
    // no-op on the existing table and correct for a new hub. (The SQLite schema
    // already creates it.)
    r#"CREATE TABLE IF NOT EXISTS frontier_snapshots (
        snapshot_hash TEXT PRIMARY KEY,
        schema_version TEXT NOT NULL,
        size_bytes BIGINT NOT NULL,
        blob_url TEXT NOT NULL,
        content_type TEXT NOT NULL DEFAULT 'application/json',
        inserted_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )"#,
    "CREATE INDEX IF NOT EXISTS idx_snapshots_inserted_at ON frontier_snapshots (inserted_at DESC)",
];

pub async fn ensure_postgres_event_first_schema(pool: &PgPool) -> Result<(), String> {
    for stmt in POSTGRES_EVENT_FIRST_SCHEMA {
        sqlx::query(stmt)
            .execute(pool)
            .await
            .map_err(|e| format!("postgres event-first schema migration: {e}"))?;
    }
    Ok(())
}

/// SQLite hub schema. Auto-applied at startup; safe to call repeatedly
/// (`IF NOT EXISTS` everywhere). The shape mirrors the Postgres schema
/// in `docs/HUB.md`: BIGSERIAL → INTEGER PRIMARY KEY AUTOINCREMENT,
/// TIMESTAMPTZ → TEXT (RFC3339), JSONB → TEXT.
pub async fn ensure_sqlite_schema(pool: &SqlitePool) -> Result<(), String> {
    for stmt in [
        r#"CREATE TABLE IF NOT EXISTS registry_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vfr_id TEXT NOT NULL,
            schema TEXT NOT NULL,
            name TEXT NOT NULL,
            owner_actor_id TEXT NOT NULL,
            owner_pubkey TEXT NOT NULL,
            latest_snapshot_hash TEXT NOT NULL,
            latest_event_log_hash TEXT NOT NULL,
            network_locator TEXT NOT NULL,
            signed_publish_at TEXT NOT NULL,
            signature TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            manifest_blob_url TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_entries_vfr_id ON registry_entries (vfr_id)",
        "CREATE INDEX IF NOT EXISTS idx_entries_signed_publish_at ON registry_entries (signed_publish_at DESC)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_entries_vfr_signature ON registry_entries (vfr_id, signature)",
        // v0.201: registry_diff_packs is the federation handle for
        // `vsd_*` Scientific Diff Packs. A pack lands here when the
        // corresponding `diff_pack.released` event has been applied
        // on a frontier and its member proposals have been accepted.
        // The pack itself stays small (id + frontier_id + summary +
        // member ids + signature); reviewers fetch the full body
        // and the resolved member proposals from the originating
        // frontier's snapshot blob, addressed by latest_snapshot_hash.
        r#"CREATE TABLE IF NOT EXISTS registry_diff_packs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pack_id TEXT NOT NULL,
            frontier_id TEXT NOT NULL,
            aggregate_kind TEXT NOT NULL,
            summary TEXT NOT NULL,
            created_at TEXT NOT NULL,
            agent_run TEXT,
            parent_pack TEXT,
            applied_event_id TEXT,
            member_ids_json TEXT NOT NULL DEFAULT '[]',
            signature TEXT NOT NULL,
            signer_pubkey_hex TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            inserted_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_diff_packs_pack_id ON registry_diff_packs (pack_id)",
        "CREATE INDEX IF NOT EXISTS idx_diff_packs_frontier_id ON registry_diff_packs (frontier_id)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_diff_packs_pack_signature ON registry_diff_packs (pack_id, signature)",
        // v0.55.1: snapshots are metadata-only. Bulk substrate lives in
        // object storage (Tigris/R2), addressed by `snapshot_hash`. This
        // table is the routing index — `blob_url` is where the bytes
        // actually live, served by the CDN. The hub never holds bulk
        // substrate in process memory.
        //
        // For local SQLite hubs (single-publisher self-host), `blob_url`
        // can be a `file://` path to a local content-addressed store.
        r#"CREATE TABLE IF NOT EXISTS frontier_snapshots (
            snapshot_hash TEXT PRIMARY KEY,
            schema_version TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            blob_url TEXT NOT NULL,
            content_type TEXT NOT NULL DEFAULT 'application/json',
            inserted_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_snapshots_inserted_at ON frontier_snapshots (inserted_at DESC)",
        r#"CREATE TABLE IF NOT EXISTS frontiers (
            vfr_id TEXT PRIMARY KEY,
            registry_entry_id INTEGER,
            name TEXT NOT NULL,
            owner_actor_id TEXT NOT NULL,
            owner_pubkey TEXT NOT NULL,
            latest_snapshot_hash TEXT NOT NULL,
            latest_event_log_hash TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            signed_publish_at TEXT NOT NULL,
            snapshot_blob_url TEXT NOT NULL DEFAULT '',
            snapshot_size_bytes INTEGER NOT NULL DEFAULT 0,
            findings_count INTEGER NOT NULL DEFAULT 0,
            events_count INTEGER NOT NULL DEFAULT 0,
            sources_count INTEGER NOT NULL DEFAULT 0,
            evidence_atoms_count INTEGER NOT NULL DEFAULT 0,
            condition_records_count INTEGER NOT NULL DEFAULT 0,
            materialized_snapshot_json TEXT NOT NULL,
            authority_mode TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'live',
            inserted_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_frontiers_signed_publish_at ON frontiers (signed_publish_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_frontiers_status ON frontiers (status)",
        r#"CREATE TABLE IF NOT EXISTS frontier_events (
            vfr_id TEXT NOT NULL,
            seq INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            event_timestamp TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            inserted_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (vfr_id, seq),
            UNIQUE (vfr_id, event_id)
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_frontier_events_cursor ON frontier_events (vfr_id, seq)",
        "CREATE INDEX IF NOT EXISTS idx_frontier_events_kind ON frontier_events (vfr_id, kind, seq)",
        "CREATE INDEX IF NOT EXISTS idx_frontier_events_target ON frontier_events (vfr_id, target_id, seq)",
        r#"CREATE TABLE IF NOT EXISTS frontier_objects (
            vfr_id TEXT NOT NULL,
            object_type TEXT NOT NULL,
            object_id TEXT NOT NULL,
            seq INTEGER NOT NULL DEFAULT 0,
            target_id TEXT,
            raw_json TEXT NOT NULL,
            signer_pubkey TEXT,
            inserted_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (vfr_id, object_type, object_id)
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_frontier_objects_type ON frontier_objects (vfr_id, object_type)",
        "CREATE INDEX IF NOT EXISTS idx_frontier_objects_target ON frontier_objects (vfr_id, target_id)",
        r#"CREATE TABLE IF NOT EXISTS frontier_publish_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vfr_id TEXT NOT NULL,
            registry_entry_id INTEGER,
            latest_snapshot_hash TEXT NOT NULL,
            signed_publish_at TEXT NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            authority_mode TEXT,
            findings_count INTEGER NOT NULL DEFAULT 0,
            events_count INTEGER NOT NULL DEFAULT 0,
            sources_count INTEGER NOT NULL DEFAULT 0,
            evidence_atoms_count INTEGER NOT NULL DEFAULT 0,
            condition_records_count INTEGER NOT NULL DEFAULT 0,
            verified_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_frontier_publish_audit_vfr ON frontier_publish_audit (vfr_id, verified_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_frontier_publish_audit_status ON frontier_publish_audit (status)",
        // Authoritative append-only revocation log (see the Postgres schema for
        // the rationale): earliest-wins, never un-revoked, consulted by accept.
        r#"CREATE TABLE IF NOT EXISTS frontier_revocations (
            vfr_id TEXT NOT NULL,
            pubkey TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            revoked_at TEXT NOT NULL,
            revoked_reason TEXT,
            recorded_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (vfr_id, pubkey)
        )"#,
        r#"CREATE TABLE IF NOT EXISTS frontier_deprecations (
            vfr_id TEXT NOT NULL PRIMARY KEY,
            deprecated_at TEXT NOT NULL,
            reason TEXT,
            raw_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
        r#"CREATE TABLE IF NOT EXISTS frontier_owner_rotations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vfr_id TEXT NOT NULL,
            new_owner_pubkey TEXT NOT NULL,
            rotated_at TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
        r#"CREATE TABLE IF NOT EXISTS frontier_maintainers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vfr_id TEXT NOT NULL,
            pubkey TEXT NOT NULL,
            action TEXT NOT NULL,
            authorized_by_pubkey TEXT NOT NULL,
            authorized_at TEXT NOT NULL,
            raw_json TEXT NOT NULL,
            recorded_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
        "CREATE INDEX IF NOT EXISTS idx_frontier_revocations_vfr ON frontier_revocations (vfr_id)",
    ] {
        sqlx::query(stmt)
            .execute(pool)
            .await
            .map_err(|e| format!("sqlite schema migration: {e}"))?;
    }
    Ok(())
}

/// The array keys whose contents live in the `frontier_objects` projection,
/// not the stored skeleton. `frontier_skeleton` empties them and
/// `merge_projected_objects` rebuilds them on read.
const PROJECTED_ARRAY_KEYS: [&str; 10] = [
    "findings",
    "sources",
    "evidence_atoms",
    "condition_records",
    "actors",
    "artifacts",
    "proposals",
    // The trust arrays: projected so the record pages can fetch them granularly
    // instead of pulling the whole snapshot to render the verification web.
    "verifier_attachments",
    "statement_attestations",
    "statement_registrations",
];

fn frontier_skeleton(snapshot: &Value) -> Value {
    let mut skeleton = snapshot.clone();
    if let Value::Object(map) = &mut skeleton {
        for array_key in PROJECTED_ARRAY_KEYS {
            map.insert(array_key.to_string(), Value::Array(Vec::new()));
        }
    }
    skeleton
}

fn projection_array_key(object_type: &str) -> Option<&'static str> {
    match object_type {
        "finding" => Some("findings"),
        "source" => Some("sources"),
        "evidence_atom" => Some("evidence_atoms"),
        "condition_record" => Some("condition_records"),
        "actor" => Some("actors"),
        "artifact" => Some("artifacts"),
        "proposal" => Some("proposals"),
        "verifier_attachment" => Some("verifier_attachments"),
        "statement_attestation" => Some("statement_attestations"),
        "statement_registration" => Some("statement_registrations"),
        _ => None,
    }
}

fn merge_projected_objects(snapshot: &mut Value, objects: Vec<(String, i64, Value)>) {
    let Some(map) = snapshot.as_object_mut() else {
        return;
    };
    // Only rebuild a type's array when the projection actually has rows for it.
    // A frontier promoted before a type was projected has no such rows, so its
    // skeleton-held array is left intact — which makes adding a newly-projected
    // type a single safe deploy with no re-projection ordering dependency.
    let mut present: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    for (object_type, _seq, _) in &objects {
        if let Some(key) = projection_array_key(object_type) {
            present.insert(key);
        }
    }
    for array_key in &present {
        map.insert((*array_key).to_string(), Value::Array(Vec::new()));
    }
    for (object_type, _seq, raw_json) in objects {
        let Some(array_key) = projection_array_key(&object_type) else {
            continue;
        };
        if let Some(Value::Array(values)) = map.get_mut(array_key) {
            values.push(raw_json);
        }
    }
}

fn collect_frontier_objects(snapshot: &Value) -> Vec<FrontierObjectRow> {
    let mut out = Vec::new();
    collect_array_objects(snapshot, "findings", "finding", &mut out);
    collect_array_objects(snapshot, "sources", "source", &mut out);
    collect_array_objects(snapshot, "evidence_atoms", "evidence_atom", &mut out);
    collect_array_objects(snapshot, "condition_records", "condition_record", &mut out);
    collect_array_objects(snapshot, "actors", "actor", &mut out);
    collect_array_objects(snapshot, "artifacts", "artifact", &mut out);
    collect_array_objects(snapshot, "proposals", "proposal", &mut out);
    // The trust arrays the record pages render (verification web, attestation
    // cards). Projecting them lets a page fetch GET /objects/{type} instead of
    // the whole snapshot. See PROJECTED_ARRAY_KEYS / merge_projected_objects.
    collect_array_objects(
        snapshot,
        "verifier_attachments",
        "verifier_attachment",
        &mut out,
    );
    collect_array_objects(
        snapshot,
        "statement_attestations",
        "statement_attestation",
        &mut out,
    );
    collect_array_objects(
        snapshot,
        "statement_registrations",
        "statement_registration",
        &mut out,
    );

    if let Some(findings) = snapshot.get("findings").and_then(Value::as_array) {
        for finding in findings {
            let source_id = finding
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            if let Some(links) = finding.get("links").and_then(Value::as_array) {
                for (idx, link) in links.iter().enumerate() {
                    let target_id = link
                        .get("target")
                        .and_then(Value::as_str)
                        .map(str::to_string);
                    out.push(FrontierObjectRow {
                        object_type: "link".to_string(),
                        object_id: format!("{source_id}:link:{idx}"),
                        seq: idx as i64,
                        target_id,
                        raw_json: json!({
                            "source": source_id,
                            "link": link,
                        }),
                        signer_pubkey: None,
                    });
                }
            }
        }
    }
    // Producer index: derive the signing/authoring key. Attempts,
    // transfers, and endorsements carry signer_pubkey_hex directly.
    // Findings carry no pubkey — signatures live on EVENTS, keyed by
    // actor id, with pubkeys in the snapshot's actor table — so resolve
    // finding -> asserting/accepting event actor -> registered pubkey.
    let actor_pubkeys: std::collections::HashMap<String, String> = snapshot
        .get("actors")
        .and_then(Value::as_array)
        .map(|actors| {
            actors
                .iter()
                .filter_map(|a| {
                    Some((
                        a.get("id")?.as_str()?.to_string(),
                        a.get("public_key")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    let finding_actor: std::collections::HashMap<String, String> = snapshot
        .get("events")
        .and_then(Value::as_array)
        .map(|events| {
            events
                .iter()
                .filter(|e| {
                    matches!(
                        e.get("kind").and_then(Value::as_str),
                        Some("finding.asserted") | Some("finding.reviewed")
                    )
                })
                .filter_map(|e| {
                    Some((
                        e.get("target")?.get("id")?.as_str()?.to_string(),
                        e.get("actor")?.get("id")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    for row in &mut out {
        row.signer_pubkey = match row.object_type.as_str() {
            "attempt" | "transfer" | "endorsement" => row
                .raw_json
                .get("signer_pubkey_hex")
                .and_then(Value::as_str)
                .map(str::to_string),
            "finding" => finding_actor
                .get(&row.object_id)
                .and_then(|actor| actor_pubkeys.get(actor))
                .cloned(),
            _ => None,
        };
    }
    out
}
fn collect_array_objects(
    snapshot: &Value,
    array_key: &str,
    object_type: &str,
    out: &mut Vec<FrontierObjectRow>,
) {
    if let Some(items) = snapshot.get(array_key).and_then(Value::as_array) {
        for (idx, item) in items.iter().enumerate() {
            let object_id = item
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("{object_type}:{idx}"));
            let target_id = item
                .get("target")
                .and_then(|v| v.get("id"))
                .and_then(Value::as_str)
                .map(str::to_string);
            out.push(FrontierObjectRow {
                object_type: object_type.to_string(),
                object_id,
                seq: idx as i64,
                target_id,
                raw_json: item.clone(),
                signer_pubkey: None,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;
    use tempfile::NamedTempFile;
    use vela_protocol::repo;

    async fn sqlite_db() -> HubDb {
        let file = NamedTempFile::new().expect("temp sqlite");
        let url = format!("sqlite://{}", file.path().display());
        let opts = SqliteConnectOptions::from_str(&url)
            .expect("sqlite opts")
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .expect("sqlite connect");
        ensure_sqlite_schema(&pool).await.expect("schema");
        // Keep the temp file alive for the duration of this process by
        // intentionally leaking it inside the test helper.
        std::mem::forget(file);
        HubDb::Sqlite(pool)
    }

    // The bbb-extension fixture is campaign data (Alzheimer's BBB) that lives in
    // the internal monorepo, not the standalone OSS checkout. Returns None when
    // absent so the tests below skip cleanly there and still run in-monorepo.
    fn fixture_project() -> Option<Project> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../frontiers/bbb-extension.json");
        if !path.exists() {
            return None;
        }
        let mut project = repo::load_from_path(&path).expect("load fixture frontier");
        if project.events.len() == 1 {
            let mut second = project.events[0].clone();
            second.id = "vev_test_second_event".to_string();
            second.timestamp = "2026-05-05T00:00:01Z".to_string();
            project.events.push(second);
        }
        Some(project)
    }

    fn entry_for(project: &Project) -> RegistryEntry {
        RegistryEntry {
            schema: vela_protocol::registry::ENTRY_SCHEMA.to_string(),
            vfr_id: project.frontier_id(),
            name: project.project.name.clone(),
            owner_actor_id: "reviewer:test".to_string(),
            owner_pubkey: "00".repeat(32),
            latest_snapshot_hash: snapshot_hash(project),
            latest_event_log_hash: event_log_hash(&project.events),
            network_locator: "https://example.com/frontier.json".to_string(),
            license: None,
            extras_manifest_hash: None,
            signed_publish_at: "2026-05-05T00:00:00Z".to_string(),
            signature: "sig_fixture".to_string(),
        }
    }

    #[test]
    fn trust_arrays_round_trip_through_projection() {
        // A snapshot carrying the trust arrays: after promote (the skeleton
        // holds none of the projected types) and read (merge the projected
        // rows back), the reconstruction must equal the original on those
        // arrays — the property the record pages now depend on for granular
        // /objects fetches.
        let snapshot = json!({
            "frontier_id": "vfr_demo",
            "findings": [{"id": "vf_1"}],
            "verifier_attachments": [
                {"id": "vva_1", "target": {"id": "vf_1"}, "outcome": "pass"},
                {"id": "vva_2", "target": {"id": "vf_1"}, "outcome": "pass"}
            ],
            "statement_attestations": [{"id": "vsa_1", "target": "vf_1", "verdict": "faithful"}],
            "statement_registrations": [{"statement_hash": "sha256:abc", "informal_ref": "erdos:1"}]
        });

        let objects = collect_frontier_objects(&snapshot);
        for t in [
            "verifier_attachment",
            "statement_attestation",
            "statement_registration",
        ] {
            assert!(
                objects.iter().any(|o| o.object_type == t),
                "expected projected object_type {t}"
            );
        }

        let mut reconstructed = frontier_skeleton(&snapshot);
        let rows: Vec<(String, i64, Value)> = objects
            .iter()
            .map(|o| (o.object_type.clone(), o.seq, o.raw_json.clone()))
            .collect();
        merge_projected_objects(&mut reconstructed, rows);

        assert_eq!(
            reconstructed["verifier_attachments"],
            snapshot["verifier_attachments"]
        );
        assert_eq!(
            reconstructed["statement_attestations"],
            snapshot["statement_attestations"]
        );
        assert_eq!(
            reconstructed["statement_registrations"],
            snapshot["statement_registrations"]
        );
        assert_eq!(reconstructed["findings"], snapshot["findings"]);
    }

    #[test]
    fn merge_keeps_skeleton_arrays_when_a_type_has_no_projected_rows() {
        // Deploy safety: a frontier promoted before the trust arrays were
        // projected holds them in its stored skeleton and has no projected
        // rows for them. The conditional merge must leave them intact rather
        // than blanking them — otherwise the live trust web would vanish the
        // instant this change deploys, before any re-publish.
        let mut stored_skeleton = json!({
            "findings": [],
            "verifier_attachments": [{"id": "vva_old", "outcome": "pass"}],
            "statement_attestations": [{"id": "vsa_old", "verdict": "faithful"}]
        });
        let rows = vec![("finding".to_string(), 0i64, json!({"id": "vf_1"}))];
        merge_projected_objects(&mut stored_skeleton, rows);

        assert_eq!(stored_skeleton["findings"], json!([{"id": "vf_1"}]));
        assert_eq!(
            stored_skeleton["verifier_attachments"],
            json!([{"id": "vva_old", "outcome": "pass"}])
        );
        assert_eq!(
            stored_skeleton["statement_attestations"],
            json!([{"id": "vsa_old", "verdict": "faithful"}])
        );
    }

    #[tokio::test]
    async fn append_to_frontier_writes_only_new_rows_and_guards() {
        let db = sqlite_db().await;
        let Some(project) = fixture_project() else {
            eprintln!("skip: bbb-extension.json fixture absent (internal-only)");
            return;
        };
        let entry = entry_for(&project);
        let raw = serde_json::to_value(&entry).expect("entry json");
        db.insert_entry(&entry, &raw).await.expect("insert entry");
        db.promote_frontier_snapshot(&entry, &project, None, "manifest_snapshot")
            .await
            .expect("promote");

        let parent = entry.latest_event_log_hash.clone();
        let findings_before = project.findings.len() as i64;
        let events_before = project.events.len() as i64;

        // A new finding (clone with a fresh id) + its asserting event.
        let mut new_finding = project.findings[0].clone();
        new_finding.id = "vf_append_test_001".to_string();
        let mut new_event = project.events[0].clone();
        new_event.id = "vev_append_test_001".to_string();
        new_event.target.r#type = "finding".to_string();
        new_event.target.id = new_finding.id.clone();

        let outcome = db
            .append_to_frontier(
                &entry.vfr_id,
                &entry.owner_pubkey,
                std::slice::from_ref(&new_finding),
                std::slice::from_ref(&new_event),
                &parent,
            )
            .await
            .expect("append");
        assert_eq!(outcome.appended_findings, 1);
        assert_eq!(outcome.appended_events, 1);
        assert_eq!(outcome.findings_count, findings_before + 1);
        assert_eq!(outcome.events_count, events_before + 1);

        // The stored event-log hash is the new tail.
        assert_eq!(
            db.event_log_hash_from_db(&entry.vfr_id)
                .await
                .expect("hash"),
            outcome.new_event_log_hash
        );

        // The materialized project now contains the appended finding + event.
        let mat = db
            .get_materialized_project(&entry.vfr_id)
            .await
            .expect("read")
            .expect("project");
        assert!(mat.findings.iter().any(|f| f.id == "vf_append_test_001"));
        assert_eq!(
            mat.events
                .iter()
                .filter(|e| e.id == "vev_append_test_001")
                .count(),
            1
        );

        // Idempotent re-apply (against the NEW parent hash): nothing written.
        let again = db
            .append_to_frontier(
                &entry.vfr_id,
                &entry.owner_pubkey,
                std::slice::from_ref(&new_finding),
                std::slice::from_ref(&new_event),
                &outcome.new_event_log_hash,
            )
            .await
            .expect("idempotent append");
        assert_eq!(again.appended_findings, 0);
        assert_eq!(again.skipped_duplicate_findings, 1);
        assert_eq!(again.skipped_duplicate_events, 1);

        // Stale parent hash -> optimistic-concurrency conflict.
        let stale = db
            .append_to_frontier(&entry.vfr_id, &entry.owner_pubkey, &[], &[], &parent)
            .await;
        assert!(
            stale.as_ref().is_err_and(|e| e.contains("conflict")),
            "stale parent should conflict, got {stale:?}"
        );

        // Wrong owner key -> owner-continuity rejection.
        let bad_owner = db
            .append_to_frontier(
                &entry.vfr_id,
                &"ff".repeat(32),
                &[],
                &[],
                &outcome.new_event_log_hash,
            )
            .await;
        assert!(
            bad_owner
                .as_ref()
                .is_err_and(|e| e.contains("owner continuity")),
            "wrong owner should be rejected, got {bad_owner:?}"
        );
    }

    #[tokio::test]
    async fn revocation_is_authoritative_and_append_only() {
        let db = sqlite_db().await;
        let Some(mut project) = fixture_project() else {
            eprintln!("skip: bbb-extension.json fixture absent (internal-only)");
            return;
        };
        let pubkey = "ab".repeat(32);
        project.actors.push(vela_protocol::sign::ActorRecord {
            id: "reviewer:compromised".to_string(),
            public_key: pubkey.clone(),
            algorithm: "ed25519".to_string(),
            created_at: "2026-05-01T00:00:00Z".to_string(),
            tier: None,
            orcid: None,
            access_clearance: None,
            revoked_at: Some("2026-05-10T00:00:00Z".to_string()),
            revoked_reason: Some("key compromised".to_string()),
        });
        let entry = entry_for(&project);
        let raw = serde_json::to_value(&entry).expect("entry json");
        db.insert_entry(&entry, &raw).await.expect("insert entry");
        db.promote_frontier_snapshot(&entry, &project, None, "manifest_snapshot")
            .await
            .expect("promote");

        // Recorded in the authoritative log.
        let rev = db
            .is_pubkey_revoked(&entry.vfr_id, &pubkey)
            .await
            .expect("query");
        assert!(rev.is_some(), "revocation must be recorded");
        assert_eq!(rev.unwrap().1, "key compromised");

        // A later snapshot that DROPS the revocation (silent un-revoke) must not
        // restore the key's authority — record_revocations is what the next
        // promote runs, and the append-only log keeps the original revocation.
        if let Some(actor) = project.actors.iter_mut().find(|a| a.public_key == pubkey) {
            actor.revoked_at = None;
            actor.revoked_reason = None;
        }
        let newly = db
            .record_revocations(&entry.vfr_id, &project)
            .await
            .expect("re-record");
        assert_eq!(newly, 0, "the un-revoked snapshot records nothing new");
        assert!(
            db.is_pubkey_revoked(&entry.vfr_id, &pubkey)
                .await
                .expect("query")
                .is_some(),
            "the key must STILL be revoked authoritatively after the un-revoke attempt"
        );

        // Case-insensitive on pubkey hex.
        assert!(
            db.is_pubkey_revoked(&entry.vfr_id, &pubkey.to_uppercase())
                .await
                .expect("query")
                .is_some(),
            "revocation lookup must be case-insensitive"
        );
    }

    #[tokio::test]
    async fn promote_rejects_signed_publish_at_replay() {
        let db = sqlite_db().await;
        let Some(project) = fixture_project() else {
            eprintln!("skip: bbb-extension.json fixture absent (internal-only)");
            return;
        };
        let mut entry = entry_for(&project);
        entry.signed_publish_at = "2026-05-05T12:00:00Z".to_string();
        let raw = serde_json::to_value(&entry).expect("entry json");
        db.insert_entry(&entry, &raw).await.expect("insert entry");
        db.promote_frontier_snapshot(&entry, &project, None, "manifest_snapshot")
            .await
            .expect("first promote");

        // Replay an OLDER owner-signed manifest -> rejected (rollback guard).
        let mut older = entry.clone();
        older.signed_publish_at = "2026-05-05T00:00:00Z".to_string();
        let err = db
            .promote_frontier_snapshot(&older, &project, None, "manifest_snapshot")
            .await
            .expect_err("replay should be rejected");
        assert!(err.contains("monotonic publish"), "{err}");

        // Same timestamp is allowed — an idempotent retry, not a rollback.
        db.promote_frontier_snapshot(&entry, &project, None, "manifest_snapshot")
            .await
            .expect("same-timestamp re-publish (idempotent) should be allowed");

        // A strictly newer publish is accepted.
        let mut newer = entry.clone();
        newer.signed_publish_at = "2026-05-06T00:00:00Z".to_string();
        let raw_newer = serde_json::to_value(&newer).expect("entry json");
        db.insert_entry(&newer, &raw_newer)
            .await
            .expect("insert newer");
        db.promote_frontier_snapshot(&newer, &project, None, "manifest_snapshot")
            .await
            .expect("strictly newer promote should succeed");
    }

    #[tokio::test]
    async fn event_first_promotion_preserves_event_log_order_and_hash() {
        let db = sqlite_db().await;
        let Some(project) = fixture_project() else {
            eprintln!("skip: bbb-extension.json fixture absent (internal-only)");
            return;
        };
        let entry = entry_for(&project);
        let raw = serde_json::to_value(&entry).expect("entry json");
        db.insert_entry(&entry, &raw).await.expect("insert entry");

        let report = db
            .promote_frontier_snapshot(&entry, &project, None, "manifest_snapshot")
            .await
            .expect("promote");

        assert_eq!(report.vfr_id, entry.vfr_id);
        assert_eq!(report.events_count, project.events.len() as i64);
        assert_eq!(report.findings_count, project.findings.len() as i64);
        assert_eq!(
            db.event_log_hash_from_db(&entry.vfr_id)
                .await
                .expect("event hash"),
            entry.latest_event_log_hash
        );
        let materialized = db
            .get_materialized_project(&entry.vfr_id)
            .await
            .expect("materialized read")
            .expect("materialized project");
        assert_eq!(snapshot_hash(&materialized), entry.latest_snapshot_hash);

        let page = db
            .event_page(&entry.vfr_id, None, 1, None, None)
            .await
            .expect("first page");
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.log_total, project.events.len() as i64);
        assert_eq!(
            page.events[0].get("id").and_then(Value::as_str),
            Some(project.events[0].id.as_str())
        );
        assert_eq!(page.next_cursor, Some(project.events[0].id.clone()));

        let tail = db
            .event_page(&entry.vfr_id, page.next_cursor.as_deref(), 500, None, None)
            .await
            .expect("tail page");
        assert_eq!(tail.next_cursor, None);
    }

    #[tokio::test]
    async fn event_first_pagination_rejects_unknown_cursor() {
        let db = sqlite_db().await;
        let Some(project) = fixture_project() else {
            eprintln!("skip: bbb-extension.json fixture absent (internal-only)");
            return;
        };
        let entry = entry_for(&project);
        let raw = serde_json::to_value(&entry).expect("entry json");
        db.insert_entry(&entry, &raw).await.expect("insert entry");
        db.promote_frontier_snapshot(&entry, &project, None, "manifest_snapshot")
            .await
            .expect("promote");

        let err = db
            .event_page(&entry.vfr_id, Some("vev_missing"), 10, None, None)
            .await
            .expect_err("unknown cursor should fail");
        assert!(err.contains("cursor_not_found"), "{err}");
    }

    #[tokio::test]
    async fn event_first_promotion_rejects_snapshot_hash_mismatch() {
        let db = sqlite_db().await;
        let Some(project) = fixture_project() else {
            eprintln!("skip: bbb-extension.json fixture absent (internal-only)");
            return;
        };
        let mut entry = entry_for(&project);
        entry.latest_snapshot_hash = "bad".to_string();

        let err = db
            .promote_frontier_snapshot(&entry, &project, None, "manifest_snapshot")
            .await
            .expect_err("bad hash should fail");
        assert!(err.contains("snapshot_hash mismatch"), "{err}");
    }

    #[tokio::test]
    async fn failed_latest_audit_demotes_prior_live_frontier() {
        let db = sqlite_db().await;
        let Some(project) = fixture_project() else {
            eprintln!("skip: bbb-extension.json fixture absent (internal-only)");
            return;
        };
        let entry = entry_for(&project);
        let raw = serde_json::to_value(&entry).expect("entry json");
        db.insert_entry(&entry, &raw).await.expect("insert entry");
        db.promote_frontier_snapshot(&entry, &project, None, "manifest_snapshot")
            .await
            .expect("promote");
        assert!(db.get_live_entry(&entry.vfr_id).await.unwrap().is_some());

        let mut failed_entry = entry.clone();
        failed_entry.signed_publish_at = "2026-05-05T00:01:00Z".to_string();
        failed_entry.signature = "sig_failed_latest".to_string();
        let raw = serde_json::to_value(&failed_entry).expect("failed entry json");
        db.insert_entry(&failed_entry, &raw)
            .await
            .expect("insert failed latest");
        db.record_publish_audit_failed(&failed_entry, "fetch failed", "manifest_snapshot")
            .await
            .expect("record failed audit");

        assert!(db.get_live_entry(&entry.vfr_id).await.unwrap().is_none());
        let audit = db
            .latest_audit_status(&entry.vfr_id)
            .await
            .expect("audit lookup")
            .expect("audit row");
        assert_eq!(audit.status, "failed");
    }
}
