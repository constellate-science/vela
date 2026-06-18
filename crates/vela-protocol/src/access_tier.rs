//! v0.51: Access tiers — the dual-use deposition channel.
//!
//! The Constellations essay's hardest paragraph commits the substrate
//! to a governed channel for content where readability is itself part
//! of the harm: gain-of-function trial readouts, model-generated
//! protein designs in dual-use space, certain synthesis routes for
//! controlled compounds. Today most scientific repositories are
//! either fully open or fully closed — not "open by default with a
//! permissioned tier above it."
//!
//! v0.51 ships the structural shape so any future maintainer
//! consortium can plug in a real DURC review pipeline without
//! renegotiating the protocol surface.
//!
//! Three tiers, ordered by sensitivity:
//!
//! - `Public` (default) — open read. The substrate's normal mode.
//! - `Restricted` — read access requires an `ActorRecord` with
//!   `access_clearance >= Restricted`. The IBC review level: dual-use
//!   research that the host institution has declared subject to
//!   incident-response review but not capability-gated.
//! - `Classified` — read access requires an `ActorRecord` with
//!   `access_clearance == Classified`. Aligned with the federal DURC
//!   framework and the capability gates frontier AI labs already
//!   publish under their own safety frameworks (Anthropic's
//!   Responsible Scaling Policy, OpenAI's Preparedness Framework,
//!   Google DeepMind's Frontier Safety Framework). Content above
//!   those internal thresholds is excluded from public deposit
//!   entirely; the substrate's openness default fails closed on
//!   ambiguous cases, with the operational cost borne by depositors.
//!
//! The composition risk — capability uplift from aggregation across
//! the dependency graph rather than any single deposit — is the
//! harder problem and v0.51 does not claim to solve it. Treating it
//! as solved would be the wrong move. v0.51 carries the
//! per-object tier; the composition graph is a follow-up.

use serde::{Deserialize, Serialize};

/// Access tier — the read-side gate on a single kernel object.
///
/// Ordering: `Public < Restricted < Classified`. An actor with
/// clearance `T` can read every object with tier `<= T`. Pre-v0.51
/// actors and objects load with `Public` and behave exactly as
/// before — the tier system is purely additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessTier {
    #[default]
    Public,
    Restricted,
    Classified,
}

impl AccessTier {
    /// Stable canonical string. Used in event payloads, schema
    /// validation, and CLI argument parsing.
    pub fn canonical(&self) -> &'static str {
        match self {
            AccessTier::Public => "public",
            AccessTier::Restricted => "restricted",
            AccessTier::Classified => "classified",
        }
    }

    /// Parse the canonical string. Unknown values are rejected
    /// loudly; a typo'd `"restrictd"` must not silently fall back to
    /// `Public`.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "public" => Ok(AccessTier::Public),
            "restricted" => Ok(AccessTier::Restricted),
            "classified" => Ok(AccessTier::Classified),
            other => Err(format!(
                "unknown access tier '{other}'; valid: public, restricted, classified"
            )),
        }
    }
}

/// Whether an actor with the given clearance is permitted to read an
/// object with the given tier. The check is `tier <= clearance`.
/// Anonymous reads (clearance `None`) are equivalent to clearance
/// `Some(Public)` — they may read public-tier objects only.
pub fn actor_may_read(tier: AccessTier, clearance: Option<AccessTier>) -> bool {
    let effective = clearance.unwrap_or(AccessTier::Public);
    tier <= effective
}

/// Apply the read gate to a `Project`, producing a redacted clone
/// containing only the kernel objects readable under the requesting
/// actor's `clearance`. Used by `serve.rs` MCP/HTTP handlers and any
/// external client that wants to surface "what would actor X see?"
///
/// Doctrine:
/// - Objects above the actor's clearance are removed from the
///   collection entirely. Their existence is not revealed.
/// - The `stats` summary (e.g. `findings: usize`) is left as-is —
///   downstream callers must recompute stats off the redacted
///   collection if they want the redacted counts. The substrate
///   surfaces the unredacted aggregate so the existence of
///   restricted material remains accountable in the abstract; the
///   *content* is what the tier protects.
/// - Events targeting objects the actor cannot see are also dropped.
///   The audit trail for restricted material is itself restricted.
pub fn redact_for_actor(
    project: &crate::project::Project,
    clearance: Option<AccessTier>,
) -> crate::project::Project {
    let findings: Vec<_> = project
        .findings
        .iter()
        .filter(|f| actor_may_read(f.access_tier, clearance))
        .cloned()
        .collect();
    let visible_finding_ids: std::collections::BTreeSet<&str> =
        findings.iter().map(|f| f.id.as_str()).collect();

    let negative_results: Vec<_> = project
        .negative_results
        .iter()
        .filter(|n| actor_may_read(n.access_tier, clearance))
        .cloned()
        .collect();
    let visible_nr_ids: std::collections::BTreeSet<&str> =
        negative_results.iter().map(|n| n.id.as_str()).collect();

    let trajectories: Vec<_> = project
        .trajectories
        .iter()
        .filter(|t| actor_may_read(t.access_tier, clearance))
        .cloned()
        .collect();
    let visible_traj_ids: std::collections::BTreeSet<&str> =
        trajectories.iter().map(|t| t.id.as_str()).collect();

    let artifacts: Vec<_> = project
        .artifacts
        .iter()
        .filter(|a| actor_may_read(a.access_tier, clearance))
        .cloned()
        .collect();
    let visible_artifact_ids: std::collections::BTreeSet<&str> =
        artifacts.iter().map(|a| a.id.as_str()).collect();

    let events: Vec<_> = project
        .events
        .iter()
        .filter(|e| match e.target.r#type.as_str() {
            "finding" => visible_finding_ids.contains(e.target.id.as_str()),
            "negative_result" => visible_nr_ids.contains(e.target.id.as_str()),
            "trajectory" => visible_traj_ids.contains(e.target.id.as_str()),
            "artifact" => visible_artifact_ids.contains(e.target.id.as_str()),
            _ => true, // frontier-level events (frontier.created, etc.) stay visible
        })
        .cloned()
        .collect();

    crate::project::Project {
        findings,
        negative_results,
        trajectories,
        artifacts,
        events,
        // Everything else passes through. Sources, evidence atoms,
        // condition records, signatures, and actors aren't tiered in
        // v0.51 — the tiering is on the load-bearing claim objects.
        // v0.51.x can extend if a downstream auditor needs it.
        ..clone_project_metadata(project)
    }
}

/// Helper that clones the non-tiered fields of a Project for the
/// `redact_for_actor` rebuild. Kept private to this module so the
/// redaction is the only path that splits the Project struct.
fn clone_project_metadata(p: &crate::project::Project) -> crate::project::Project {
    crate::project::Project {
        vela_version: p.vela_version.clone(),
        schema: p.schema.clone(),
        frontier_id: p.frontier_id.clone(),
        project: crate::project::ProjectMeta {
            name: p.project.name.clone(),
            description: p.project.description.clone(),
            compiled_at: p.project.compiled_at.clone(),
            compiler: p.project.compiler.clone(),
            papers_processed: p.project.papers_processed,
            errors: p.project.errors,
            dependencies: p.project.dependencies.clone(),
        },
        stats: serde_json::from_value(serde_json::to_value(&p.stats).unwrap_or_default())
            .unwrap_or_default(),
        findings: Vec::new(),
        sources: p.sources.clone(),
        evidence_atoms: p.evidence_atoms.clone(),
        condition_records: p.condition_records.clone(),
        review_events: p.review_events.clone(),
        confidence_updates: p.confidence_updates.clone(),
        events: Vec::new(),
        proposals: p.proposals.clone(),
        proof_state: p.proof_state.clone(),
        signatures: p.signatures.clone(),
        actors: p.actors.clone(),
        replications: p.replications.clone(),
        datasets: p.datasets.clone(),
        code_artifacts: p.code_artifacts.clone(),
        artifacts: Vec::new(),
        predictions: p.predictions.clone(),
        resolutions: p.resolutions.clone(),
        negative_results: Vec::new(),
        trajectories: Vec::new(),
        released_diff_packs: Vec::new(),
        verdict_conflicts: Vec::new(),
        contradictions: Vec::new(),
        verifier_attachments: Vec::new(),
        attempts: Vec::new(),
        attempt_resolutions: Vec::new(),
        transfers: Vec::new(),
        endorsements: Vec::new(),
        statement_attestations: Vec::new(),
        anchor_links: Vec::new(),
        attempt_claims: Vec::new(),
        statement_registrations: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_is_public_lt_restricted_lt_classified() {
        assert!(AccessTier::Public < AccessTier::Restricted);
        assert!(AccessTier::Restricted < AccessTier::Classified);
    }

    #[test]
    fn anonymous_reader_sees_only_public() {
        assert!(actor_may_read(AccessTier::Public, None));
        assert!(!actor_may_read(AccessTier::Restricted, None));
        assert!(!actor_may_read(AccessTier::Classified, None));
    }

    #[test]
    fn restricted_clearance_excludes_classified() {
        assert!(actor_may_read(
            AccessTier::Public,
            Some(AccessTier::Restricted)
        ));
        assert!(actor_may_read(
            AccessTier::Restricted,
            Some(AccessTier::Restricted)
        ));
        assert!(!actor_may_read(
            AccessTier::Classified,
            Some(AccessTier::Restricted)
        ));
    }

    #[test]
    fn classified_clearance_reads_everything() {
        assert!(actor_may_read(
            AccessTier::Public,
            Some(AccessTier::Classified)
        ));
        assert!(actor_may_read(
            AccessTier::Restricted,
            Some(AccessTier::Classified)
        ));
        assert!(actor_may_read(
            AccessTier::Classified,
            Some(AccessTier::Classified)
        ));
    }

    #[test]
    fn parse_round_trips_canonical() {
        for tier in [
            AccessTier::Public,
            AccessTier::Restricted,
            AccessTier::Classified,
        ] {
            assert_eq!(AccessTier::parse(tier.canonical()).unwrap(), tier);
        }
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(AccessTier::parse("restrictd").is_err());
        assert!(AccessTier::parse("").is_err());
        assert!(AccessTier::parse("CLASSIFIED").is_err());
    }
}
