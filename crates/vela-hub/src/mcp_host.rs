//! The hosted MCP lane: `hub.constellate.science/mcp`.
//!
//! The hub embeds the `vela serve` dispatcher in-process (`McpService`
//! from vela-cli) and points it at local checkouts of every registered
//! frontier remote. A refresher loop keeps the checkouts and the merged
//! in-memory projection current — on an interval, and immediately when
//! the GitHub webhook kicks it.
//!
//! Custody note: the service is READ-ONLY profile with the hosted
//! exclusions (the filesystem-path `vela_*` runtime family). There is no
//! configuration in which this endpoint mutates state; the hub stays an
//! index, and decisions stay key-custody human acts in the repos.
//!
//! Every machine runs its own refresher (unlike the DB ingest sweep,
//! which elects a leader): the checkouts and the merged projection are
//! per-machine state, so each machine must maintain its own.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Notify, RwLock};
use vela_cli::McpService;

use crate::db::HubDb;
use crate::git_ingest::{self, GitIngestConfig};

/// The hot-swappable service handle shared with the HTTP layer. `None`
/// until the first successful refresh (the route answers 503 meanwhile).
pub type SharedMcp = Arc<RwLock<Option<McpService>>>;

/// Refresh cadence. Reuses the ingest interval unless overridden; the
/// webhook makes the interval mostly irrelevant (it kicks immediately).
fn refresh_interval_secs() -> u64 {
    std::env::var("VELA_HUB_MCP_REFRESH_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300)
        .max(30)
}

/// Spawn the per-machine refresher. `kick` is notified by the webhook
/// handler to refresh ahead of the interval.
pub fn spawn(db: HubDb, cfg: GitIngestConfig, shared: SharedMcp, kick: Arc<Notify>) {
    tokio::spawn(async move {
        // The set of (vfr, HEAD) the current service was built from;
        // an unchanged set means the rebuild can be skipped.
        let mut built_from: HashMap<String, String> = HashMap::new();
        loop {
            match refresh(&db, &cfg, &shared, &mut built_from).await {
                Ok(Some(n)) => tracing::info!(frontiers = n, "mcp-host: projection rebuilt"),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "mcp-host: refresh failed"),
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(refresh_interval_secs())) => {}
                _ = kick.notified() => {
                    tracing::info!("mcp-host: webhook kick, refreshing ahead of interval");
                }
            }
        }
    });
}

/// Fetch every registered remote into this machine's MCP checkout dir and
/// rebuild the merged service when any HEAD moved. `Ok(Some(n))` = rebuilt
/// over n frontiers, `Ok(None)` = nothing changed.
async fn refresh(
    db: &HubDb,
    cfg: &GitIngestConfig,
    shared: &SharedMcp,
    built_from: &mut HashMap<String, String>,
) -> Result<Option<usize>, String> {
    let targets = db.git_ingest_targets().await?;
    if targets.is_empty() {
        return Ok(None);
    }
    // A sibling of the ingest scratch dir, NOT the same tree: the ingest
    // sweep and this refresher run concurrently and git locks per repo.
    let root = cfg.scratch_dir.join("_mcp");
    let mut entries: Vec<(String, PathBuf)> = Vec::new();
    let mut heads: HashMap<String, String> = HashMap::new();
    for (vfr_id, remote, git_ref, subdir, _last, _owner) in targets {
        let dir = root.join(&vfr_id);
        if let Err(e) = git_ingest::fetch_repo(&remote, &git_ref, &dir).await {
            tracing::warn!(%vfr_id, error = %e, "mcp-host: fetch failed; serving last checkout if any");
        }
        if let Ok(head) = git_ingest::rev_parse_head(&dir).await {
            heads.insert(vfr_id.clone(), head);
        }
        let frontier_dir = if subdir.is_empty() {
            dir.clone()
        } else {
            let sub = dir.join(&subdir);
            // Same rule as the ingest lane: a subdir escaping the clone is
            // a malicious registration, not a layout.
            if !sub.starts_with(&dir) {
                continue;
            }
            sub
        };
        if frontier_dir.exists() {
            entries.push((vfr_id, frontier_dir));
        }
    }
    if entries.is_empty() {
        return Err("no registered frontier has a usable checkout yet".to_string());
    }
    if heads == *built_from && shared.read().await.is_some() {
        return Ok(None);
    }

    // The load replays every frontier (sync, CPU-bound) — off the runtime.
    let count = entries.len();
    let exclude = McpService::hosted_exclusions();
    let loaded = tokio::task::spawn_blocking(move || {
        McpService::from_named_paths(&entries, "read-only", &exclude)
    })
    .await
    .map_err(|e| format!("mcp load task: {e}"))?;
    match loaded {
        Ok((service, warnings)) => {
            for w in warnings {
                tracing::warn!("mcp-host: skipped {w}");
            }
            *shared.write().await = Some(service);
            *built_from = heads;
            Ok(Some(count))
        }
        Err(e) => Err(e),
    }
}
