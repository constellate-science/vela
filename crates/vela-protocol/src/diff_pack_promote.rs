//! v0.205: promotion path from `.vela/pending_verdicts/` to canonical
//! `diff_pack.reviewed` events.
//!
//! v0.203 introduced pending verdicts as a workbench-side artifact
//! awaiting the v0.205 reducer arm. This module walks the pending-
//! verdict directory and, for each verdict, emits a canonical
//! `diff_pack.reviewed` event onto the frontier's event log.
//!
//! Atomicity guarantee (Theorem 26): for verdict=accept, either every
//! canonical member proposal is applied via the existing
//! `proposals::accept_at_path` path AND the diff_pack.reviewed event
//! is appended, OR no state change occurs and the pending verdict
//! stays on disk for re-promotion. SDK-only stubs (members without a
//! matching canonical StateProposal) are documented in the event
//! payload but do not block the verdict — they ride a future
//! promotion path.
//!
//! Substrate-honest framing: this is a CLI-time operation, not a
//! reducer-time operation. The reducer's `diff_pack.reviewed` arm is
//! metadata-only (records the verdict in the event log); the actual
//! member-by-member acceptance happens through the same path
//! `vela workbench` already drives. The promoter is the layer that
//! batches these for a Diff Pack reviewer.

use serde_json::json;
use std::path::Path;

use crate::canonical;
use crate::diff_pack_review::{self, DiffPackVerdict, PendingVerdict};
use crate::events::{self, StateActor, StateEvent, StateTarget};
use crate::project::Project;
use crate::proposals;
use crate::repo;
use crate::scientific_diff::ScientificDiffPack;
use crate::{frontier_policy, reviewer_identity};

#[derive(Debug, Clone)]
pub struct PromotionReport {
    pub verdict_id: String,
    pub pack_id: String,
    pub verdict: DiffPackVerdict,
    pub event_id: String,
    /// Members that were applied through proposals.rs.
    pub applied_members: Vec<String>,
    /// Members that matched no canonical StateProposal on the frontier
    /// (SDK-only stubs). The verdict still records them in its
    /// payload but the substrate does not mutate state for them.
    pub sdk_only_members: Vec<String>,
}

/// Promote every pending verdict on disk to a canonical event. Returns
/// the list of reports, one per promoted verdict. Stops at the first
/// failure and leaves the failing verdict on disk.
pub fn promote_all(repo_path: &Path) -> Result<Vec<PromotionReport>, String> {
    let pending = diff_pack_review::list_at_path(repo_path);
    let mut reports = Vec::new();
    for pv in pending {
        let r = promote_one(repo_path, &pv)?;
        reports.push(r);
    }
    Ok(reports)
}

/// Promote a single pending verdict. Atomicity: for verdict=accept,
/// either every canonical member is applied AND the event lands, OR
/// no state change occurs and the pending verdict stays. Errors leave
/// the frontier in its pre-promotion state.
pub fn promote_one(repo_path: &Path, verdict: &PendingVerdict) -> Result<PromotionReport, String> {
    let pack = load_pack(repo_path, &verdict.pack_id)?;
    let review_summary = pack.review_summary(repo_path);
    let policy_summary = frontier_policy::load_policy_summary(repo_path).ok();
    let enforce_attestations =
        frontier_policy::attestation_enforcement_enabled(policy_summary.as_ref());
    let missing_required_roles = reviewer_identity::missing_roles_for_target(
        repo_path,
        &pack.pack_id,
        &review_summary.required_reviewers,
    )
    .unwrap_or_else(|_| review_summary.required_reviewers.clone());
    let has_policy_override = frontier_policy::override_reason_is_explicit(&verdict.reason);
    if enforce_attestations && !missing_required_roles.is_empty() && !has_policy_override {
        return Err(format!(
            "required role attestations missing for {}: {}. Record attestations with `vela attest`, or include `policy_override:` in the local reviewer reason.",
            pack.pack_id,
            missing_required_roles.join(", ")
        ));
    }

    // Snapshot frontier state for rollback. We load fresh, mutate
    // through proposals::, then on failure restore the snapshot to
    // disk. The full project shape is large but the safest rollback
    // is to round-trip through repo::save_to_path with the snapshot.
    let snapshot: Project =
        repo::load_from_path(repo_path).map_err(|e| format!("snapshot load: {e}"))?;

    let (applied, sdk_only) = match verdict.verdict {
        DiffPackVerdict::Accept => {
            apply_members(repo_path, &pack, &verdict.reviewer_actor, &verdict.reason).inspect_err(
                |_| {
                    // Rollback on partial failure.
                    let _ = repo::save_to_path(repo_path, &snapshot);
                },
            )?
        }
        // Reject / revise: no member mutations. We still emit the
        // canonical event so the verdict is on the log.
        DiffPackVerdict::Reject | DiffPackVerdict::Revise => {
            let applied: Vec<String> = Vec::new();
            let sdk_only: Vec<String> = pack.proposals.clone();
            (applied, sdk_only)
        }
    };

    // Emit the canonical `diff_pack.reviewed` event.
    let event = build_verdict_event(
        repo_path,
        &pack,
        verdict,
        &applied,
        &sdk_only,
        &missing_required_roles,
        has_policy_override,
    );
    append_event_to_frontier(repo_path, &event).inspect_err(|_| {
        // Rollback to snapshot if the event write fails after member
        // mutations succeeded.
        let _ = repo::save_to_path(repo_path, &snapshot);
    })?;

    // The verdict is canonical now; remove the pending-verdict file.
    let pv_path = diff_pack_review::pending_verdicts_dir(repo_path)
        .join(format!("{}.json", verdict.verdict_id));
    let _ = std::fs::remove_file(&pv_path);

    Ok(PromotionReport {
        verdict_id: verdict.verdict_id.clone(),
        pack_id: pack.pack_id.clone(),
        verdict: verdict.verdict,
        event_id: event.id,
        applied_members: applied,
        sdk_only_members: sdk_only,
    })
}

fn load_pack(repo_path: &Path, pack_id: &str) -> Result<ScientificDiffPack, String> {
    let path = repo_path
        .join(".vela")
        .join("diff_packs")
        .join(format!("{pack_id}.json"));
    let body =
        std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let pack: ScientificDiffPack =
        serde_json::from_str(&body).map_err(|e| format!("parse pack: {e}"))?;
    pack.verify()?;
    Ok(pack)
}

/// Apply every canonical member proposal. Returns (applied, sdk_only).
/// SDK-only members are returned but not applied; they belong to the
/// SDK-stub directory `.vela/agent_proposals/` and have no canonical
/// StateProposal on the frontier.
fn apply_members(
    repo_path: &Path,
    pack: &ScientificDiffPack,
    reviewer: &str,
    reason: &str,
) -> Result<(Vec<String>, Vec<String>), String> {
    // We need to know which member ids correspond to canonical
    // proposals on the frontier (vs SDK-only stubs). Load the
    // frontier fresh and walk its proposals list.
    let project = repo::load_from_path(repo_path).map_err(|e| format!("load frontier: {e}"))?;
    let mut applied = Vec::new();
    let mut sdk_only = Vec::new();
    for vpr in &pack.proposals {
        let canonical_match = project.proposals.iter().any(|p| &p.id == vpr);
        if !canonical_match {
            sdk_only.push(vpr.clone());
            continue;
        }
        proposals::accept_at_path(repo_path, vpr, reviewer, reason)
            .map_err(|e| format!("accept member {vpr}: {e}"))?;
        applied.push(vpr.clone());
    }
    Ok((applied, sdk_only))
}

fn build_verdict_event(
    repo_path: &Path,
    pack: &ScientificDiffPack,
    verdict: &PendingVerdict,
    applied: &[String],
    sdk_only: &[String],
    missing_required_roles: &[String],
    policy_override: bool,
) -> StateEvent {
    let review_summary = pack.review_summary(repo_path);
    let proof_freshness_impact = match verdict.verdict {
        DiffPackVerdict::Accept if !applied.is_empty() || !sdk_only.is_empty() => {
            "stale_if_accepted"
        }
        _ => "metadata_only",
    };
    let mut event = StateEvent {
        schema: "vela.event.v0.1".to_string(),
        id: String::new(),
        kind: "diff_pack.reviewed".to_string(),
        target: StateTarget {
            r#type: "diff_pack".to_string(),
            id: pack.pack_id.clone(),
        },
        actor: StateActor {
            id: verdict.reviewer_actor.clone(),
            r#type: events::actor_kind(&verdict.reviewer_actor).to_string(),
        },
        timestamp: verdict.at.clone(),
        reason: verdict.reason.clone(),
        before_hash: "sha256:none".to_string(),
        after_hash: "sha256:none".to_string(),
        payload: json!({
            "pack_id": pack.pack_id,
            "verdict": verdict.verdict.canonical(),
            "reviewer": verdict.reviewer_actor,
            "reviewer_actor": verdict.reviewer_actor,
            "reason": verdict.reason,
            "affected_objects": review_summary.affected_findings,
            "applied_members": applied,
            "sdk_only_members": sdk_only,
            "evidence_ci_summary": review_summary.evidence_ci_summary,
            "missing_required_roles": missing_required_roles,
            "policy_override": policy_override,
            "policy_override_reason": if policy_override { serde_json::Value::String(verdict.reason.clone()) } else { serde_json::Value::Null },
            "operation_counts": {
                "total_members": pack.proposals.len(),
                "applied_members": applied.len(),
                "sdk_only_members": sdk_only.len(),
            },
            "proof_freshness_impact": proof_freshness_impact,
            "pending_verdict_id": verdict.verdict_id,
            "review_session_scope": review_summary.review_session_scope,
            "review_session_id": serde_json::Value::Null,
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

fn append_event_to_frontier(repo_path: &Path, event: &StateEvent) -> Result<(), String> {
    let mut project = repo::load_from_path(repo_path).map_err(|e| format!("load: {e}"))?;
    project.events.push(event.clone());
    // Also write the event file under .vela/events/<vev_id>.json so
    // the split-repo layout sees it (mirrors the existing canonical
    // event-write path in proposals.rs).
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
    use tempfile::tempdir;

    fn fixture_repo() -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        // Minimal .vela/ scaffolding so repo::load_from_path succeeds.
        // We seed via the same path the quickstart uses.
        let vela = tmp.path().join(".vela");
        std::fs::create_dir_all(vela.join("diff_packs")).unwrap();
        std::fs::create_dir_all(vela.join("events")).unwrap();
        std::fs::create_dir_all(vela.join("proposals")).unwrap();
        std::fs::create_dir_all(vela.join("pending_verdicts")).unwrap();
        // Empty frontier.json — repo::load_from_path needs the canonical
        // file at the repo root.
        std::fs::write(
            tmp.path().join("frontier.json"),
            r#"{"frontier_id":"vfr_test","project":{"name":"t","description":"","compiled_at":"2026-05-12T00:00:00Z","compiler":"test","papers_processed":0,"errors":0,"dependencies":[]}}"#,
        )
        .unwrap();
        tmp
    }

    #[test]
    fn pack_id_validation_holds() {
        // We don't need a full frontier — this just exercises the
        // load_pack guard path.
        let tmp = fixture_repo();
        let res = load_pack(tmp.path(), "vsd_nonexistent");
        assert!(res.is_err());
    }

    #[test]
    fn build_verdict_event_payload_has_expected_keys() {
        let pack = ScientificDiffPack {
            schema: "vela.scientific_diff.v0.1".to_string(),
            pack_id: "vsd_aaaaaaaaaaaaaaaa".to_string(),
            frontier_id: "vfr_test".to_string(),
            created_at: "2026-05-12T00:00:00Z".to_string(),
            summary: "test".to_string(),
            proposals: vec!["vpr_one".to_string(), "vpr_two".to_string()],
            aggregate_kind: "test".to_string(),
            agent_run: None,
            parent_pack: None,
            applied_event_id: None,
            signature: None,
            signer_pubkey_hex: None,
        };
        let pv = PendingVerdict::build(
            "vsd_aaaaaaaaaaaaaaaa",
            DiffPackVerdict::Reject,
            "reviewer:t",
            "no",
            "2026-05-12T01:00:00Z",
        )
        .unwrap();
        let tmp = fixture_repo();
        let ev = build_verdict_event(tmp.path(), &pack, &pv, &[], &pack.proposals, &[], false);
        assert_eq!(ev.kind, "diff_pack.reviewed");
        assert!(ev.id.starts_with("vev_"));
        assert_eq!(ev.target.id, "vsd_aaaaaaaaaaaaaaaa");
        let payload = ev.payload.as_object().unwrap();
        assert_eq!(payload["verdict"], "reject");
        assert_eq!(payload["reviewer"], "reviewer:t");
        assert_eq!(payload["reason"], "no");
        assert_eq!(payload["pending_verdict_id"], pv.verdict_id);
        assert_eq!(payload["operation_counts"]["total_members"], 2);
        assert_eq!(payload["operation_counts"]["applied_members"], 0);
        assert_eq!(payload["operation_counts"]["sdk_only_members"], 2);
        assert_eq!(payload["proof_freshness_impact"], "metadata_only");
    }
}
