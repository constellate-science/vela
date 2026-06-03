//! v0.221: backfill `diff_pack.released` events for packs that exist
//! on disk under `.vela/diff_packs/<vsd_id>.json` but have no
//! matching event in `.vela/events/`.
//!
//! Why this exists: v0.213 introduced `Project.released_diff_packs`
//! as the canonical replay-state mirror of `.vela/diff_packs/`.
//! The v0.213 reducer arm `apply_diff_pack_released` populates
//! that field — but only when a `diff_pack.released` event lands
//! on the log. Pre-v0.221 scaffolding scripts wrote packs to disk
//! without ever emitting the release event, so `released_diff_packs`
//! stayed empty on the exemplary frontier even though four packs
//! exist on disk.
//!
//! v0.221 closes the loop: this module scans the diff_pack
//! directory, identifies packs without a corresponding release
//! event, and emits one for each. Idempotent — re-running is a
//! no-op once every pack has a release event.
//!
//! Substrate-honest framing: the release event's `released_at`
//! timestamp is the pack's `created_at` (since the pack body
//! pins it canonically). The event id is content-addressed over
//! the canonical preimage so backfilling twice produces the same
//! event id, which is what makes idempotency cheap to assert.

use serde_json::json;
use std::path::Path;

use crate::canonical;
use crate::events::{StateActor, StateEvent, StateTarget};
use crate::repo;
use crate::scientific_diff::ScientificDiffPack;

#[derive(Debug, Clone)]
pub struct BackfillReport {
    pub pack_id: String,
    pub event_id: String,
    /// True if the event was newly written by this call. False if a
    /// matching event already existed on the frontier.
    pub created: bool,
}

/// Walk `.vela/diff_packs/` on the given frontier. For each pack
/// without a matching `diff_pack.released` event, emit one. Returns
/// one BackfillReport per pack (whether or not it was newly written).
pub fn backfill_all(repo_path: &Path) -> Result<Vec<BackfillReport>, String> {
    let diff_packs_dir = repo_path.join(".vela").join("diff_packs");
    let mut reports = Vec::new();
    let Ok(entries) = std::fs::read_dir(&diff_packs_dir) else {
        return Ok(reports);
    };
    let mut paths: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();
    paths.sort();

    // Pre-load existing release events into a set keyed by pack_id so
    // we don't re-emit. The events directory is small in practice;
    // walk-once is fine.
    let existing = load_existing_release_target_ids(repo_path);

    for path in paths {
        let body =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let pack: ScientificDiffPack =
            serde_json::from_str(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;
        if existing.contains(&pack.pack_id) {
            // Already has a release event. Compute the canonical event
            // id from the pack so the report includes it (useful for
            // operators verifying the link without re-walking events).
            let event = build_release_event(&pack);
            reports.push(BackfillReport {
                pack_id: pack.pack_id.clone(),
                event_id: event.id,
                created: false,
            });
            continue;
        }
        let event = build_release_event(&pack);
        append_event_to_frontier(repo_path, &event)?;
        reports.push(BackfillReport {
            pack_id: pack.pack_id.clone(),
            event_id: event.id,
            created: true,
        });
    }
    Ok(reports)
}

/// Build a `diff_pack.released` event for the given pack. The event
/// id is content-addressed over the canonical preimage, so this is
/// deterministic — calling twice on the same pack produces the same
/// event id, which is the foundation of backfill idempotency.
pub fn build_release_event(pack: &ScientificDiffPack) -> StateEvent {
    let mut event = StateEvent {
        schema: "vela.event.v0.1".to_string(),
        id: String::new(),
        kind: "diff_pack.released".to_string(),
        target: StateTarget {
            r#type: "diff_pack".to_string(),
            id: pack.pack_id.clone(),
        },
        actor: StateActor {
            // The producing agent (when present) signed the pack; we
            // use the signer's pubkey-derived actor here if the pack
            // carries an agent_run link, else fall back to a generic
            // "releaser:backfill" identity. Pre-v0.221 packs typically
            // have an agent_run link.
            id: pack
                .agent_run
                .clone()
                .unwrap_or_else(|| "releaser:backfill".to_string()),
            r#type: "system".to_string(),
        },
        timestamp: pack.created_at.clone(),
        reason: format!("Backfilled release for pre-v0.221 pack {}", pack.pack_id),
        before_hash: "sha256:none".to_string(),
        after_hash: "sha256:none".to_string(),
        payload: json!({
            "pack_id": pack.pack_id,
            "frontier_id": pack.frontier_id,
            "summary": pack.summary,
            "aggregate_kind": pack.aggregate_kind,
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    event.id = compute_event_id_via_canonical(&event);
    event
}

fn compute_event_id_via_canonical(event: &StateEvent) -> String {
    use sha2::{Digest, Sha256};
    let content = json!({
        "schema": event.schema,
        "kind": event.kind,
        "target": event.target,
        "actor": event.actor,
        "timestamp": event.timestamp,
        "reason": event.reason,
        "before_hash": event.before_hash,
        "after_hash": event.after_hash,
        "payload": event.payload,
        "caveats": event.caveats,
    });
    let bytes = canonical::to_canonical_bytes(&content).unwrap_or_default();
    format!("vev_{}", &hex::encode(Sha256::digest(bytes))[..16])
}

fn load_existing_release_target_ids(repo_path: &Path) -> std::collections::HashSet<String> {
    let events_dir = repo_path.join(".vela").join("events");
    let mut out = std::collections::HashSet::new();
    let Ok(entries) = std::fs::read_dir(&events_dir) else {
        return out;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(body) = std::fs::read_to_string(&p) else {
            continue;
        };
        let Ok(v): Result<serde_json::Value, _> = serde_json::from_str(&body) else {
            continue;
        };
        if v.get("kind").and_then(|k| k.as_str()) != Some("diff_pack.released") {
            continue;
        }
        if let Some(tid) = v
            .get("target")
            .and_then(|t| t.get("id"))
            .and_then(|i| i.as_str())
        {
            out.insert(tid.to_string());
        }
    }
    out
}

fn append_event_to_frontier(repo_path: &Path, event: &StateEvent) -> Result<(), String> {
    let mut project = repo::load_from_path(repo_path).map_err(|e| format!("load: {e}"))?;
    project.events.push(event.clone());
    // Apply the event through the reducer so `Project.released_diff_packs`
    // gets populated in-line. Without this step, the event would land on
    // the log but the canonical state field would stay stale until the
    // next full replay. Closes the v0.213 reducer arm.
    crate::reducer::apply_event(&mut project, event)
        .map_err(|e| format!("apply diff_pack.released: {e}"))?;
    let events_dir = repo_path.join(".vela").join("events");
    std::fs::create_dir_all(&events_dir).map_err(|e| format!("create events dir: {e}"))?;
    let path = events_dir.join(format!("{}.json", event.id));
    let body = serde_json::to_string_pretty(event).map_err(|e| format!("serialize event: {e}"))?;
    std::fs::write(&path, format!("{body}\n"))
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    repo::save_to_path(repo_path, &project).map_err(|e| format!("save: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scientific_diff::PackDraft;
    use ed25519_dalek::SigningKey;
    use tempfile::tempdir;

    fn fixture_repo() -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        let vela = tmp.path().join(".vela");
        std::fs::create_dir_all(vela.join("diff_packs")).unwrap();
        std::fs::create_dir_all(vela.join("events")).unwrap();
        std::fs::create_dir_all(vela.join("proposals")).unwrap();
        std::fs::create_dir_all(vela.join("findings")).unwrap();
        // Minimal frontier.json so repo::load_from_path succeeds.
        let frontier_json = tmp.path().join("frontier.json");
        std::fs::write(
            &frontier_json,
            r#"{"frontier_id":"vfr_test","frontier":{"id":"vfr_test","name":"test"}}"#,
        )
        .unwrap();
        tmp
    }

    fn make_pack(frontier_id: &str, summary: &str) -> ScientificDiffPack {
        let draft = PackDraft {
            frontier_id: frontier_id.to_string(),
            created_at: "2026-05-12T00:00:00Z".to_string(),
            summary: summary.to_string(),
            proposals: vec![format!("vpr_{}", "a".repeat(16))],
            aggregate_kind: "evidence.refresh".to_string(),
            agent_run: None,
            parent_pack: None,
        };
        let mut pack = ScientificDiffPack::build(draft).unwrap();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        pack.sign(&key);
        pack
    }

    #[test]
    fn empty_diff_packs_dir_is_noop() {
        let tmp = fixture_repo();
        let reports = backfill_all(tmp.path()).unwrap();
        assert!(reports.is_empty());
    }

    #[test]
    fn backfills_pack_without_release_event() {
        let tmp = fixture_repo();
        let pack = make_pack("vfr_test", "test pack");
        let pack_path = tmp
            .path()
            .join(".vela")
            .join("diff_packs")
            .join(format!("{}.json", pack.pack_id));
        std::fs::write(&pack_path, serde_json::to_string_pretty(&pack).unwrap()).unwrap();

        let reports = backfill_all(tmp.path()).unwrap();
        assert_eq!(reports.len(), 1);
        assert!(reports[0].created);
        assert_eq!(reports[0].pack_id, pack.pack_id);
        // Event file landed under .vela/events/.
        let event_path = tmp
            .path()
            .join(".vela")
            .join("events")
            .join(format!("{}.json", reports[0].event_id));
        assert!(event_path.exists(), "event file should exist");
    }

    #[test]
    fn second_run_is_idempotent() {
        let tmp = fixture_repo();
        let pack = make_pack("vfr_test", "idempotent");
        let pack_path = tmp
            .path()
            .join(".vela")
            .join("diff_packs")
            .join(format!("{}.json", pack.pack_id));
        std::fs::write(&pack_path, serde_json::to_string_pretty(&pack).unwrap()).unwrap();

        let r1 = backfill_all(tmp.path()).unwrap();
        let r2 = backfill_all(tmp.path()).unwrap();
        assert_eq!(r1.len(), 1);
        assert_eq!(r2.len(), 1);
        assert!(r1[0].created);
        assert!(!r2[0].created, "second run should not re-create");
        assert_eq!(r1[0].event_id, r2[0].event_id, "deterministic event id");
    }
}
