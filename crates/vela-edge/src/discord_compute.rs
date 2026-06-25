//! Compute discord assignments against live Project state.
//!
//! Bridges the algebraic types in [`crate::discord`] to running
//! substrate state. Implements the computational side of
//! `docs/THEORY.md` Section 4 in read-only form: this module
//! does not mutate any on-disk state, it only computes a derived
//! view from existing findings, evidence atoms, and events.
//!
//! ## Detectors shipped
//!
//! Each detector is a closure that takes a `Project` and a finding
//! id and returns whether the corresponding discord kind fires.
//! All detectors are read-only and pure functions of substrate
//! state.
//!
//! - [`detect_evidence_gap`]: fires when a finding has no verified
//!   evidence spans and no linked evidence atoms.
//! - [`detect_provenance_fragile`]: fires when a finding has fewer
//!   than two supporting derivations (single point of failure
//!   under retraction per Theorem 2).
//! - [`detect_status_divergent`]: fires when the on-disk
//!   `flags.review_state` or `flags.contested` disagrees with the
//!   substrate-derived `BelnapStatus`. Distinguishes data drift
//!   between manual flags and event-log-derived state.
//!
//! ## What this module does NOT do
//!
//! - Detectors do not run upward propagation through a context
//!   category. Theorem 4's monotonicity guarantee applies only
//!   when the context refinement relation exists. v0.85's context
//!   model is flat (each finding is its own leaf). Future cycles
//!   will extend.
//! - Discord results are advisory. They do not block any gate.

use crate::discord::{ContextId, DiscordAssignment, DiscordKind, DiscordSet};
use crate::provenance_compute::status_provenance_for_finding;
use vela_protocol::project::Project;
use vela_protocol::status_provenance::BelnapStatus;

/// Detector: fires when a finding has no verified evidence spans
/// and no linked evidence atoms in the project.
pub fn detect_evidence_gap(project: &Project, finding_id: &str) -> bool {
    let Some(finding) = project.findings.iter().find(|f| f.id == finding_id) else {
        return false;
    };
    let has_spans = !finding.evidence.evidence_spans.is_empty();
    if has_spans {
        return false;
    }
    let has_evidence_atoms = project
        .evidence_atoms
        .iter()
        .any(|ea| ea.finding_id == finding_id);
    !has_evidence_atoms
}

/// Detector: fires when a finding has fewer than two distinct
/// supporting derivation events. Composing Theorem 2 with the
/// status derivation rule, a single supporting event is a
/// retraction-fragile claim: retracting that one event flips
/// status from T to N (or to F if a refute exists).
pub fn detect_provenance_fragile(project: &Project, finding_id: &str) -> bool {
    let sp = status_provenance_for_finding(project, finding_id);
    if sp.support.is_zero() {
        // No supporting derivations at all is `EvidenceGap`'s job.
        return false;
    }
    sp.support.term_count() < 2
}

/// Detector: fires when the on-disk `flags.review_state` /
/// `flags.contested` disagrees with the substrate-derived
/// `BelnapStatus` from the event log. Surfaces drift between
/// manually-set flags and event-log-derived state.
pub fn detect_status_divergent(project: &Project, finding_id: &str) -> bool {
    use vela_protocol::bundle::ReviewState;

    let Some(finding) = project.findings.iter().find(|f| f.id == finding_id) else {
        return false;
    };
    let belnap = status_provenance_for_finding(project, finding_id).derive_status();
    let on_disk_contested = finding.flags.contested;
    let review_state = finding.flags.review_state.as_ref();

    // Substrate says contradiction (Belnap B) but on-disk flags
    // say no contradiction.
    if matches!(belnap, BelnapStatus::Both) && !on_disk_contested {
        return true;
    }

    // On-disk says rejected but substrate says T (the rejected
    // event was not represented in the event-derived view).
    if matches!(review_state, Some(ReviewState::Rejected)) && matches!(belnap, BelnapStatus::True) {
        return true;
    }

    false
}

/// Compute the discord set for a single finding by running the
/// shipped detectors against live Project state.
pub fn compute_discord_for_finding(project: &Project, finding_id: &str) -> DiscordSet {
    let mut set = DiscordSet::empty();
    if detect_evidence_gap(project, finding_id) {
        set.insert(DiscordKind::EvidenceGap);
    }
    if detect_provenance_fragile(project, finding_id) {
        set.insert(DiscordKind::ProvenanceFragile);
    }
    if detect_status_divergent(project, finding_id) {
        set.insert(DiscordKind::StatusDivergent);
    }
    set
}

/// Compute a `DiscordAssignment` over every finding in the
/// project, treating each finding id as a flat context. Future
/// cycles will index by the formal context category (target v0.8).
pub fn compute_discord_assignment(project: &Project) -> DiscordAssignment {
    let mut a = DiscordAssignment::empty();
    for finding in &project.findings {
        let context: ContextId = finding.id.clone();
        let set = compute_discord_for_finding(project, &finding.id);
        if !set.is_empty() {
            a.set(context, set);
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vela_protocol::bundle::{
        Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Evidence,
        FindingBundle, Flags, Provenance,
    };
    use vela_protocol::events::{StateActor, StateEvent, StateTarget};

    fn make_assertion(text: &str) -> Assertion {
        Assertion {
            text: text.to_string(),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        }
    }

    fn make_evidence() -> Evidence {
        Evidence {
            evidence_type: "experimental".into(),
            model_system: "test".into(),
            method: "test".into(),
            replicated: false,
            replication_count: None,
            evidence_spans: vec![],
        }
    }

    fn make_conditions() -> Conditions {
        Conditions {
            text: String::new(),
            duration: None,
        }
    }

    fn make_confidence() -> Confidence {
        Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: 0.5,
            basis: "test".into(),
            method: ConfidenceMethod::LlmInitial,
            extraction_confidence: 0.5,
        }
    }

    fn make_provenance(id_seed: &str) -> Provenance {
        Provenance {
            source_type: "expert_assertion".into(),
            doi: None,
            url: None,
            title: format!("title-{id_seed}"),
            authors: vec![Author {
                name: "test".into(),
                orcid: None,
            }],
            year: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Default::default(),
            review: None,
        }
    }

    /// Build a finding with a given id by constructing it via
    /// FindingBundle::new and then overriding the id field. The
    /// content-addressed id from `new` is replaced so tests can
    /// reference findings by stable names.
    fn empty_finding(id: &str) -> FindingBundle {
        let mut f = FindingBundle::new(
            make_assertion(&format!("test claim {id}")),
            make_evidence(),
            make_conditions(),
            make_confidence(),
            make_provenance(id),
            Flags::default(),
        );
        f.id = id.to_string();
        f
    }

    fn synthetic_event(id: &str, kind: &str, finding_id: &str, status: Option<&str>) -> StateEvent {
        let payload = match status {
            Some(s) => json!({"status": s}),
            None => json!(null),
        };
        StateEvent {
            schema: "vela.event.v0.1".into(),
            id: id.to_string(),
            kind: kind.into(),
            target: StateTarget {
                r#type: "finding".into(),
                id: finding_id.to_string(),
            },
            actor: StateActor {
                id: "reviewer:test".into(),
                r#type: "human".into(),
            },
            timestamp: "2026-05-09T00:00:00Z".into(),
            reason: "test".into(),
            before_hash: String::new(),
            after_hash: String::new(),
            payload,
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        }
    }

    fn build_project(findings: Vec<FindingBundle>, events: Vec<StateEvent>) -> Project {
        let mut p = vela_protocol::project::assemble("test-frontier", vec![], 0, 0, "test");
        p.events.clear();
        p.findings = findings;
        p.events = events;
        p
    }

    #[test]
    fn evidence_gap_fires_when_no_spans_and_no_atoms() {
        let f = empty_finding("vf_x");
        let p = build_project(vec![f], vec![]);
        assert!(detect_evidence_gap(&p, "vf_x"));
    }

    #[test]
    fn evidence_gap_does_not_fire_when_finding_has_spans() {
        let mut f = empty_finding("vf_x");
        f.evidence
            .evidence_spans
            .push(json!({"text": "verbatim quote"}));
        let p = build_project(vec![f], vec![]);
        assert!(!detect_evidence_gap(&p, "vf_x"));
    }

    #[test]
    fn provenance_fragile_fires_when_only_one_supporting_event() {
        let f = empty_finding("vf_x");
        // Single asserted event = single derivation path.
        let events = vec![synthetic_event("vev_001", "finding.asserted", "vf_x", None)];
        let p = build_project(vec![f], events);
        assert!(detect_provenance_fragile(&p, "vf_x"));
    }

    #[test]
    fn provenance_fragile_does_not_fire_when_multiple_supporting_events() {
        let f = empty_finding("vf_x");
        let events = vec![
            synthetic_event("vev_001", "finding.asserted", "vf_x", None),
            synthetic_event("vev_002", "finding.reviewed", "vf_x", Some("accepted")),
        ];
        let p = build_project(vec![f], events);
        assert!(!detect_provenance_fragile(&p, "vf_x"));
    }

    #[test]
    fn provenance_fragile_does_not_fire_when_no_support_at_all() {
        // EvidenceGap territory, not ProvenanceFragile.
        let f = empty_finding("vf_x");
        let p = build_project(vec![f], vec![]);
        assert!(!detect_provenance_fragile(&p, "vf_x"));
    }

    #[test]
    fn status_divergent_fires_when_belnap_b_but_flags_say_uncontested() {
        let mut f = empty_finding("vf_x");
        f.flags.contested = false;
        // Both supporting and refuting events: substrate says B,
        // but on-disk says uncontested. Drift detected.
        let events = vec![
            synthetic_event("vev_001", "finding.asserted", "vf_x", None),
            synthetic_event("vev_002", "finding.reviewed", "vf_x", Some("contested")),
        ];
        let p = build_project(vec![f], events);
        assert!(detect_status_divergent(&p, "vf_x"));
    }

    #[test]
    fn status_divergent_does_not_fire_when_flags_match_substrate() {
        let mut f = empty_finding("vf_x");
        f.flags.contested = true;
        // Both polarities + on-disk contested: aligned.
        let events = vec![
            synthetic_event("vev_001", "finding.asserted", "vf_x", None),
            synthetic_event("vev_002", "finding.reviewed", "vf_x", Some("contested")),
        ];
        let p = build_project(vec![f], events);
        assert!(!detect_status_divergent(&p, "vf_x"));
    }

    #[test]
    fn compute_discord_for_finding_with_only_asserted_event() {
        let f = empty_finding("vf_x");
        let events = vec![synthetic_event("vev_001", "finding.asserted", "vf_x", None)];
        let p = build_project(vec![f], events);
        let set = compute_discord_for_finding(&p, "vf_x");
        // EvidenceGap (no spans, no atoms) and ProvenanceFragile
        // (single supporting event) both fire.
        assert!(set.contains(DiscordKind::EvidenceGap));
        assert!(set.contains(DiscordKind::ProvenanceFragile));
        assert!(!set.contains(DiscordKind::StatusDivergent));
    }

    #[test]
    fn compute_discord_for_finding_with_multiple_events_and_spans() {
        let mut f = empty_finding("vf_x");
        f.evidence.evidence_spans.push(json!({"text": "span"}));
        let events = vec![
            synthetic_event("vev_001", "finding.asserted", "vf_x", None),
            synthetic_event("vev_002", "finding.reviewed", "vf_x", Some("accepted")),
        ];
        let p = build_project(vec![f], events);
        let set = compute_discord_for_finding(&p, "vf_x");
        assert!(set.is_empty());
    }

    #[test]
    fn compute_discord_assignment_collects_per_finding_results() {
        let f1 = empty_finding("vf_a");
        let f2 = {
            let mut f = empty_finding("vf_b");
            f.evidence.evidence_spans.push(json!({"text": "span"}));
            f
        };
        let events = vec![
            synthetic_event("vev_001", "finding.asserted", "vf_a", None),
            synthetic_event("vev_002", "finding.asserted", "vf_b", None),
            synthetic_event("vev_003", "finding.reviewed", "vf_b", Some("accepted")),
        ];
        let p = build_project(vec![f1, f2], events);
        let assignment = compute_discord_assignment(&p);
        // vf_a fires EvidenceGap + ProvenanceFragile.
        // vf_b: has spans (no EvidenceGap) and 2 supporting events
        // (no ProvenanceFragile). Empty discord set.
        let support = assignment.frontier_support();
        assert!(support.contains("vf_a"));
        assert!(!support.contains("vf_b"));
    }
}
