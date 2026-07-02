//! Git ingestion: the hub as an index over git-replayed state (ADR 0001,
//! docs/HUB.md). For each frontier whose owner registered a git remote, the
//! ingestor fetches the repo, replays the committed `.vela/events` log with
//! the protocol library, holds it to the one canonical strict bar
//! (`vela_edge::verify::verify_frontier_strict`), and promotes the result
//! through the same gate the legacy publish path used
//! (`HubDb::promote_frontier_snapshot`).
//!
//! Authority model, stated plainly: an ingested entry carries NO owner-signed
//! manifest. Its authority is the repo's individually signed events, verified
//! on replay — the hub derives the index; it never owns the truth. The one
//! owner-signed act is the registration binding a vfr_id to a git remote
//! (`GitRemoteRegistration`, verified at POST time against the effective
//! owner key).
//!
//! Anti-replay: `signed_publish_at` for an ingested entry is the tip commit's
//! committer timestamp, so the existing monotonic guard in
//! `promote_frontier_snapshot` rejects a force-push that rewinds history.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::db::HubDb;
use vela_protocol::events::{event_log_hash, snapshot_hash};
use vela_protocol::registry::RegistryEntry;

/// Authority mode recorded on frontiers whose index rows derive from a git
/// remote rather than an owner-signed manifest.
pub const AUTHORITY_GIT_INGESTED: &str = "git_ingested";

pub struct GitIngestConfig {
    /// Seconds between ingest sweeps. 0 disables the loop.
    pub interval_secs: u64,
    /// Scratch directory for clones (persisted between ticks so ingests
    /// after the first are incremental fetches).
    pub scratch_dir: PathBuf,
}

impl GitIngestConfig {
    pub fn from_env() -> Self {
        let interval_secs = std::env::var("VELA_HUB_GIT_INGEST_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300);
        let scratch_dir = std::env::var("VELA_HUB_GIT_INGEST_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("vela-hub-git-ingest"));
        Self {
            interval_secs,
            scratch_dir,
        }
    }
}

/// Spawn the recurring ingest loop (no-op when interval is 0).
pub fn spawn(db: HubDb, cfg: GitIngestConfig) {
    if cfg.interval_secs == 0 {
        eprintln!("git-ingest: disabled (VELA_HUB_GIT_INGEST_INTERVAL_SECS=0)");
        return;
    }
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(cfg.interval_secs));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            if let Err(err) = run_once(&db, &cfg).await {
                eprintln!("git-ingest: sweep error: {err}");
            }
        }
    });
}

/// One sweep over every registered target. Errors on one target are recorded
/// on its row and do not stop the sweep.
pub async fn run_once(db: &HubDb, cfg: &GitIngestConfig) -> Result<usize, String> {
    // One sweeper at a time: with more than one hub machine on the same
    // database, concurrent sweeps duplicate fetch work and race the
    // receipt insert. A session advisory lock elects a leader per sweep;
    // the loser skips this tick (the state converges next tick).
    let _guard = match db.try_ingest_lock().await? {
        Some(g) => Some(g),
        None => {
            return Ok(0);
        }
    };
    let targets = db.git_ingest_targets().await?;
    let mut ingested = 0;
    for (vfr_id, remote, git_ref, subdir, last_commit, owner_pubkey) in targets {
        match ingest_one(
            db,
            cfg,
            &vfr_id,
            &remote,
            &git_ref,
            &subdir,
            last_commit.as_deref(),
            &owner_pubkey,
        )
        .await
        {
            Ok(Some(commit)) => {
                db.record_git_ingest(&vfr_id, Some(&commit), None).await?;
                eprintln!("git-ingest: {vfr_id} promoted at {commit}");
                ingested += 1;
            }
            Ok(None) => {
                // up to date — touch the timestamp, keep the cursor
                db.record_git_ingest(&vfr_id, None, None).await?;
            }
            Err(err) => {
                eprintln!("git-ingest: {vfr_id}: {err}");
                db.record_git_ingest(&vfr_id, None, Some(&err)).await?;
            }
        }
    }
    Ok(ingested)
}

/// Ingest a single frontier. Returns Ok(Some(commit)) on promotion,
/// Ok(None) when already at the tip.
#[allow(clippy::too_many_arguments)]
async fn ingest_one(
    db: &HubDb,
    cfg: &GitIngestConfig,
    vfr_id: &str,
    remote: &str,
    git_ref: &str,
    subdir: &str,
    last_commit: Option<&str>,
    owner_pubkey: &str,
) -> Result<Option<String>, String> {
    let dir = cfg.scratch_dir.join(vfr_id);
    fetch_repo(remote, git_ref, &dir).await?;
    let commit = rev_parse_head(&dir).await?;
    if Some(commit.as_str()) == last_commit {
        return Ok(None);
    }
    let commit_time = commit_timestamp(&dir).await?;

    // A multi-frontier monorepo (vela-frontiers) registers each frontier at
    // a signed subdirectory; a plain frontier repo replays from its root.
    let frontier_dir = if subdir.is_empty() {
        dir.clone()
    } else {
        let sub = dir.join(subdir);
        // The clone is fetched fresh above; a subdir escaping it is a
        // malicious registration, not a layout.
        if !sub.starts_with(&dir) || !sub.exists() {
            return Err(format!(
                "registered subdir '{subdir}' not found in the repo"
            ));
        }
        sub
    };

    // Replay + verify off the async runtime (the protocol code is sync).
    // The strict bar is defined ONCE, in `vela_edge::verify` — the same
    // bundle any indexer must hold a frontier to.
    let dir_cloned = frontier_dir.clone();
    let (project, fid) =
        tokio::task::spawn_blocking(move || vela_edge::verify::verify_frontier_strict(&dir_cloned))
            .await
            .map_err(|e| format!("verify task: {e}"))??;

    // The repo must BE the registered frontier: a remote that replays to a
    // different frontier_id is a mis-registration (or a swap attack), not an
    // update.
    if fid != vfr_id {
        return Err(format!(
            "frontier_id mismatch: the repo replays to {fid}, registration is for {vfr_id}"
        ));
    }

    // Synthetic index entry. No manifest signature — authority_mode marks the
    // lane, and the promoted state was verified event-by-event above. The
    // owner fields carry the REGISTRATION's owner so the existing
    // owner-continuity guard keeps holding across re-publishes.
    let entry = RegistryEntry {
        schema: "vela.registry-entry.v0.1".to_string(),
        vfr_id: vfr_id.to_string(),
        name: project.project.name.clone(),
        owner_actor_id: project
            .actors
            .iter()
            .find(|a| a.public_key == owner_pubkey)
            .map(|a| a.id.clone())
            .unwrap_or_else(|| "owner:unregistered-in-frontier".to_string()),
        owner_pubkey: owner_pubkey.to_string(),
        latest_snapshot_hash: snapshot_hash(&project),
        latest_event_log_hash: event_log_hash(&project.events),
        network_locator: format!("git+{remote}"),
        signed_publish_at: commit_time,
        signature: String::new(),
        license: None,
        extras_manifest_hash: None,
    };
    // Insert the receipt row FIRST: the promotion links
    // frontiers.registry_entry_id to it, and every read path JOINs on that
    // link (an unlinked frontiers row is invisible to /entries). A
    // duplicate is IDEMPOTENT here (synthetic ingest entries share the
    // empty-signature key; a second machine or a re-run inserts the same
    // row) — tolerate it and continue to the hash-guarded promotion.
    let raw = serde_json::to_value(&entry).map_err(|e| e.to_string())?;
    if let Err(e) = db.insert_entry(&entry, &raw).await
        && !e.contains("duplicate")
        && !e.contains("UNIQUE constraint")
    {
        return Err(e);
    }
    db.promote_frontier_snapshot(&entry, &project, None, AUTHORITY_GIT_INGESTED)
        .await?;
    Ok(Some(commit))
}

// ── git plumbing (process git: the borrow-logistics choice — git is the
//    transport everywhere else in the doctrine, so the ingestor speaks the
//    same tool rather than reimplementing it) ─────────────────────────────

async fn git(args: &[&str], cwd: Option<&Path>) -> Result<String, String> {
    let mut cmd = tokio::process::Command::new("git");
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    let out = cmd
        .args(args)
        .output()
        .await
        .map_err(|e| format!("git {:?}: {e}", args.first().unwrap_or(&"")))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn fetch_repo(remote: &str, git_ref: &str, dir: &Path) -> Result<(), String> {
    if dir.join(".git").exists() {
        // A re-registration may have re-pointed the remote: the scratch
        // clone must always fetch the CURRENTLY registered URL, never a
        // stale origin.
        git(&["remote", "set-url", "origin", remote], Some(dir)).await?;
        git(&["fetch", "--depth", "1", "origin", git_ref], Some(dir)).await?;
        git(&["reset", "--hard", "FETCH_HEAD"], Some(dir)).await?;
        git(&["clean", "-fdq"], Some(dir)).await?;
    } else {
        if let Some(parent) = dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("scratch dir: {e}"))?;
        }
        git(
            &[
                "clone",
                "--depth",
                "1",
                "--branch",
                git_ref,
                remote,
                &dir.to_string_lossy(),
            ],
            None,
        )
        .await?;
    }
    Ok(())
}

async fn rev_parse_head(dir: &Path) -> Result<String, String> {
    git(&["rev-parse", "HEAD"], Some(dir)).await
}

/// Committer timestamp of the tip, RFC3339 — the ingested entry's
/// `signed_publish_at` surrogate (monotone for fast-forward history, so the
/// promote guard rejects rewinds).
async fn commit_timestamp(dir: &Path) -> Result<String, String> {
    git(&["show", "-s", "--format=%cI", "HEAD"], Some(dir)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn copy_tree(src: &Path, dst: &Path) {
        std::fs::create_dir_all(dst).unwrap();
        for entry in std::fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let to = dst.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &to);
            } else {
                std::fs::copy(entry.path(), to).unwrap();
            }
        }
    }

    fn fixture_copy() -> tempfile::TempDir {
        // The in-repo example frontier is a real signed substrate — the same
        // fixture class the live hub ingests.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/erdos-formalization");
        let tmp = tempfile::TempDir::new().unwrap();
        copy_tree(&src, tmp.path());
        tmp
    }

    #[test]
    fn verify_passes_on_clean_frontier() {
        let tmp = fixture_copy();
        let (project, _fid) = vela_edge::verify::verify_frontier_strict(tmp.path())
            .expect("clean frontier must verify");
        assert!(!project.events.is_empty());
    }

    #[test]
    fn verify_refuses_tampered_signed_event() {
        // Live red-test regression (2026-07-01): flipping a verdict inside a
        // SIGNED statement.attested event slipped past replay+signals alone;
        // the validation pass (content-address re-derivation) must refuse it.
        let tmp = fixture_copy();
        let events_dir = tmp.path().join(".vela/events");
        let mut tampered = false;
        for entry in std::fs::read_dir(&events_dir).unwrap() {
            let path = entry.unwrap().path();
            let text = std::fs::read_to_string(&path).unwrap();
            let mut v: serde_json::Value = serde_json::from_str(&text).unwrap();
            if v.get("kind").and_then(|k| k.as_str()) == Some("statement.attested")
                && v.get("signature").is_some_and(|s| !s.is_null())
            {
                let att = v
                    .pointer_mut("/payload/attestation/verdict")
                    .expect("attestation verdict");
                *att = serde_json::Value::String("faithful".into());
                std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
                tampered = true;
                break;
            }
        }
        assert!(
            tampered,
            "fixture must contain a signed statement.attested event"
        );
        let err = vela_edge::verify::verify_frontier_strict(tmp.path())
            .expect_err("tampered event must refuse");
        assert!(
            err.contains("validation failed") || err.contains("re-derive"),
            "expected an integrity refusal, got: {err}"
        );
    }
}
