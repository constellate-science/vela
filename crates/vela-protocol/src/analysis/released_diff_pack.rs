//! v0.213: ReleasedDiffPackRecord — first-class replay state for the
//! v0.201 `diff_pack.released` and v0.205 `diff_pack.reviewed` event
//! arms.
//!
//! Prior cycles left these arms metadata-only (the reducer returned
//! `Ok(())` and nothing on the Project struct changed). That kept the
//! initial implementations small but left a gap: a consumer walking
//! the canonical event log alone cannot answer "what packs have been
//! released on this frontier?" — they had to read sibling
//! `.vela/diff_packs/` directories independently. Three consumers
//! (workbench, site-next, search) each duplicated that walk.
//!
//! v0.213 makes the arms mutate `Project.released_diff_packs` so the
//! event log is self-sufficient for replay. Theorem 29 pins the
//! algebra: replay of N `diff_pack.released` events produces an
//! array of length N with no duplicates by pack_id; subsequent
//! `diff_pack.reviewed` events update verdict + verdict_event_id
//! in place without changing length.

use serde::{Deserialize, Serialize};

/// A released diff pack's verdict is the same three-valued enum as a
/// pending review verdict ([`crate::diff_pack_review::DiffPackVerdict`]) —
/// identical variants, identical `snake_case` wire form, identical
/// `canonical()` / `from_str_ci()`. It was previously duplicated here as
/// a separate `ReleasedVerdict`; this alias collapses the two to one
/// definition without changing the on-disk replay format.
pub type ReleasedVerdict = crate::diff_pack_review::DiffPackVerdict;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleasedDiffPackRecord {
    /// `vsd_<16hex>` content-addressed pack id.
    pub pack_id: String,
    /// `vfr_<16hex>` frontier the pack targets.
    pub frontier_id: String,
    pub summary: String,
    pub aggregate_kind: String,
    /// RFC 3339 timestamp the pack was released onto this log.
    pub released_at: String,
    /// `vev_*` id of the `diff_pack.released` event.
    pub released_event_id: String,
    /// Set once a `diff_pack.reviewed` event lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<ReleasedVerdict>,
    /// `vev_*` id of the `diff_pack.reviewed` event when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_event_id: Option<String>,
    /// Reviewer actor on the verdict event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_actor: Option<String>,
    /// Members the verdict applied (canonical proposals) and members
    /// it did not (SDK-only stubs). Empty until `diff_pack.reviewed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_members: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sdk_only_members: Vec<String>,
    /// The member proposals BUNDLED at release time (`vela pack`): the
    /// pending set a reviewer judges as one unit. Distinct from
    /// `applied_members`, which is what a verdict actually applied.
    /// Optional + skip-empty: pre-pack records serialize byte-identically.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub member_proposals: Vec<String>,
}

impl ReleasedDiffPackRecord {
    /// Build a fresh record from a `diff_pack.released` event payload.
    pub fn from_released_event(
        pack_id: String,
        frontier_id: String,
        summary: String,
        aggregate_kind: String,
        released_at: String,
        released_event_id: String,
        member_proposals: Vec<String>,
    ) -> Self {
        Self {
            pack_id,
            frontier_id,
            summary,
            aggregate_kind,
            released_at,
            released_event_id,
            verdict: None,
            verdict_event_id: None,
            reviewer_actor: None,
            applied_members: Vec::new(),
            sdk_only_members: Vec::new(),
            member_proposals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_from_str_lenient() {
        assert_eq!(
            ReleasedVerdict::from_str_ci("Accepted"),
            Some(ReleasedVerdict::Accept)
        );
        assert_eq!(
            ReleasedVerdict::from_str_ci("needs_revision"),
            Some(ReleasedVerdict::Revise)
        );
        assert_eq!(ReleasedVerdict::from_str_ci("yes"), None);
    }

    #[test]
    fn record_serializes_with_optional_verdict() {
        let r = ReleasedDiffPackRecord::from_released_event(
            "vsd_test".to_string(),
            "vfr_test".to_string(),
            "summary".to_string(),
            "kind".to_string(),
            "2026-05-13T00:00:00Z".to_string(),
            "vev_test".to_string(),
            Vec::new(),
        );
        let s = serde_json::to_string(&r).unwrap();
        // No verdict set yet — should not serialize verdict / verdict_event_id.
        assert!(!s.contains("verdict"), "verdict elided when None: {s}");

        let back: ReleasedDiffPackRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back.pack_id, "vsd_test");
        assert!(back.verdict.is_none());
    }
}

/// Report from `release_pack`: the changeset now exists on the log.
#[derive(Debug, serde::Serialize)]
pub struct PackReleaseReport {
    pub pack_id: String,
    pub event_id: String,
    pub members: Vec<String>,
}

/// `vela pack` — bundle PENDING proposals into a `vsd_` changeset: one
/// `diff_pack.released` event carrying the member ids, so a reviewer can
/// judge the whole set as a unit (`vela accept . --pack vsd_…`). Grouping
/// is an activity act, not a decision: any actor may pack; only a human
/// key may later accept.
pub fn release_pack_at_path(
    path: &std::path::Path,
    summary: &str,
    aggregate_kind: &str,
    member_ids: &[String],
    actor_id: &str,
) -> Result<PackReleaseReport, String> {
    use sha2::{Digest, Sha256};
    if summary.trim().is_empty() {
        return Err("a pack needs a --summary (the reviewer reads it first)".to_string());
    }
    if member_ids.is_empty() {
        return Err("a pack needs at least one member proposal (vpr_…)".to_string());
    }
    let mut frontier = crate::repo::load_from_path(path)?;
    let frontier_id = frontier.frontier_id();
    let mut members: Vec<String> = member_ids.to_vec();
    members.sort();
    members.dedup();
    for id in &members {
        let Some(p) = frontier.proposals.iter().find(|p| &p.id == id) else {
            return Err(format!("pack member {id} not found"));
        };
        if p.status != "pending_review" {
            return Err(format!(
                "pack member {id} is {}, not pending_review — a pack bundles \
                 undecided work",
                p.status
            ));
        }
        if frontier
            .released_diff_packs
            .iter()
            .any(|r| r.verdict.is_none() && r.member_proposals.contains(id))
        {
            return Err(format!("pack member {id} is already in an undecided pack"));
        }
    }
    let preimage = crate::canonical::to_canonical_bytes(&serde_json::json!({
        "frontier_id": frontier_id,
        "summary": summary,
        "members": members,
    }))?;
    let pack_id = format!("vsd_{}", &hex::encode(Sha256::digest(&preimage))[..16]);
    if frontier
        .released_diff_packs
        .iter()
        .any(|r| r.pack_id == pack_id)
    {
        return Err(format!(
            "pack {pack_id} already released (identical content)"
        ));
    }
    let actor_type = if actor_id.starts_with("agent:") || actor_id.starts_with("ci:") {
        "agent"
    } else {
        "human"
    };
    let mut event = crate::events::StateEvent {
        schema: crate::events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "diff_pack.released".into(),
        target: crate::events::StateTarget {
            r#type: "frontier".to_string(),
            id: frontier_id.clone(),
        },
        actor: crate::events::StateActor {
            id: actor_id.to_string(),
            r#type: actor_type.to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: summary.to_string(),
        before_hash: crate::events::NULL_HASH.to_string(),
        after_hash: crate::events::NULL_HASH.to_string(),
        payload: serde_json::json!({
            "pack_id": pack_id,
            "frontier_id": frontier_id,
            "summary": summary,
            "aggregate_kind": aggregate_kind,
            "members": members,
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    event.id = crate::events::compute_event_id(&event);
    let event_id = event.id.clone();
    frontier.events.push(event);
    crate::repo::save_to_path(path, &frontier)?;
    Ok(PackReleaseReport {
        pack_id,
        event_id,
        members,
    })
}

/// `vela accept --pack` — one human decision for the whole changeset:
/// engine-accept every member (the SAME custody + Engine gates as any
/// accept), then land the atomic `diff_pack.reviewed` verdict.
pub fn accept_pack_at_path(
    path: &std::path::Path,
    pack_id: &str,
    reviewer: &str,
    reason: &str,
    opts: crate::proposals::AcceptOptions,
    dry_run: bool,
) -> Result<(crate::proposals::BatchAcceptReport, Option<String>), String> {
    let frontier = crate::repo::load_from_path(path)?;
    let Some(rec) = frontier
        .released_diff_packs
        .iter()
        .find(|r| r.pack_id == pack_id)
    else {
        return Err(format!("pack {pack_id} not found"));
    };
    if rec.verdict.is_some() {
        return Err(format!(
            "pack {pack_id} already has a verdict ({:?})",
            rec.verdict
        ));
    }
    let members = rec.member_proposals.clone();
    if members.is_empty() {
        return Err(format!(
            "pack {pack_id} carries no member list (pre-porcelain pack?) — \
             accept its proposals individually"
        ));
    }
    let report =
        crate::proposals::accept_batch_at_path(path, &members, reviewer, reason, opts, dry_run)?;
    if dry_run {
        return Ok((report, None));
    }
    // The atomic verdict event. Applied members = what the batch actually
    // landed; any failures stay visible in the report.
    let mut frontier = crate::repo::load_from_path(path)?;
    let mut event = crate::events::StateEvent {
        schema: crate::events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "diff_pack.reviewed".into(),
        target: crate::events::StateTarget {
            r#type: "frontier".to_string(),
            id: frontier.frontier_id(),
        },
        actor: crate::events::StateActor {
            id: reviewer.to_string(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: reason.to_string(),
        before_hash: crate::events::NULL_HASH.to_string(),
        after_hash: crate::events::NULL_HASH.to_string(),
        payload: serde_json::json!({
            "pack_id": pack_id,
            "verdict": "accepted",
            "reviewer_actor": reviewer,
            "applied_members": report.accepted_proposal_ids,
            "sdk_only_members": [],
        }),
        caveats: Vec::new(),
        signature: None,
        schema_artifact_id: None,
    };
    event.id = crate::events::compute_event_id(&event);
    let event_id = event.id.clone();
    frontier.events.push(event);
    crate::repo::save_to_path(path, &frontier)?;
    Ok((report, Some(event_id)))
}
