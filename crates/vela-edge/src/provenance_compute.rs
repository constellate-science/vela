//! Compute provenance polynomials and Belnap status from an
//! event log.
//!
//! Bridges the algebraic primitives in
//! [`vela_protocol::provenance_poly`] and [`vela_protocol::status_provenance`] to
//! the running substrate's `StateEvent` log. Implements the
//! computational side of `docs/THEORY.md` Section 7
//! ("status derivation from provenance") in read-only form: this
//! module does not mutate any on-disk state, it only computes a
//! derived view from existing events.
//!
//! ## Mapping
//!
//! For a target claim-context pair (in v0.84 we identify this with
//! a finding id; per-context attribution lands when the formal
//! context category does, target v0.8), each event contributes to
//! either the supporting or refuting polynomial:
//!
//! | Event kind          | Status payload         | Effect                        |
//! |---------------------|------------------------|-------------------------------|
//! | `finding.asserted`  | n/a                    | support += singleton(event_id) |
//! | `finding.reviewed`  | accepted               | support += singleton(event_id) |
//! | `finding.reviewed`  | needs_revision         | support += singleton(event_id) |
//! | `finding.reviewed`  | contested              | refute  += singleton(event_id) |
//! | `finding.reviewed`  | rejected               | refute  += singleton(event_id) |
//! | `finding.rejected`  | n/a                    | refute  += singleton(event_id) |
//! | `finding.retracted` | n/a                    | retract event-id from both     |
//!
//! The retraction case interprets `finding.retracted` as: the
//! finding-level retraction event removes the finding's previous
//! supporting derivations from scope. In the polynomial layer
//! this is the homomorphism `rho` over the prior support set.
//!
//! ## Scope
//!
//! - This module only handles finding-level events. Replication
//!   and prediction events are not yet mapped; that mapping rides
//!   on a richer Carina-payload type system (target v0.85+).
//! - The result is purely a function of the events passed in.
//!   Callers control which events are in scope; this lets the
//!   substrate compute the polynomial under different review
//!   policies without baking policy into the algebra.

use serde_json::Value;

use vela_protocol::provenance_poly::ProvenancePoly;
use vela_protocol::status_provenance::{BelnapStatus, StatusProvenance};

/// A minimal projection of a [`vela_protocol::events::StateEvent`] needed
/// for provenance computation.
///
/// Decoupled from the concrete `StateEvent` type so this module
/// can be used in tests, against synthetic event logs, and across
/// future event-shape changes without rippling.
#[derive(Debug, Clone)]
pub struct ProvenanceEventRef<'a> {
    /// Content-addressed event id (`vev_*`). Becomes a variable in
    /// the polynomial.
    pub id: &'a str,
    /// Event kind string (e.g. `finding.asserted`).
    pub kind: &'a str,
    /// Target finding id (`vf_*`). Filters events to a single
    /// claim-context pair.
    pub finding_id: &'a str,
    /// Event payload, used to read review status fields.
    pub payload: &'a Value,
}

/// Compute the support/refute provenance polynomials for a single
/// finding from a sequence of events targeting that finding.
///
/// The caller is responsible for filtering events to the right
/// finding id; this function does not re-filter. The returned
/// [`StatusProvenance`] yields a [`BelnapStatus`] under
/// `derive_status()` per `docs/THEORY.md` Section 7.
pub fn compute_status_provenance<'a, I>(events: I) -> StatusProvenance
where
    I: IntoIterator<Item = ProvenanceEventRef<'a>>,
{
    let mut sp = StatusProvenance::empty();

    // Track retractions in canonical order so we can apply them
    // after the polynomials have been built. A retraction event
    // removes its target finding's prior derivations from scope by
    // mapping the prior event ids to zero. We model this by
    // collecting the set of pre-retraction event ids as the
    // retraction target.
    let mut prior_event_ids: Vec<String> = Vec::new();
    let mut retract_pending: bool = false;

    for ev in events {
        let kind = ev.kind;
        let event_id = ev.id;

        match kind {
            "finding.asserted" => {
                sp.add_support(&ProvenancePoly::singleton(event_id));
                prior_event_ids.push(event_id.to_string());
            }
            "finding.reviewed" => {
                let status = ev
                    .payload
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match status {
                    "accepted" | "needs_revision" => {
                        sp.add_support(&ProvenancePoly::singleton(event_id));
                    }
                    "contested" | "rejected" => {
                        sp.add_refute(&ProvenancePoly::singleton(event_id));
                    }
                    _ => {
                        // Unknown status string: do nothing rather
                        // than fabricate polarity.
                    }
                }
                prior_event_ids.push(event_id.to_string());
            }
            "finding.rejected" => {
                sp.add_refute(&ProvenancePoly::singleton(event_id));
                prior_event_ids.push(event_id.to_string());
            }
            "finding.retracted" => {
                // Apply at the end so prior events are accounted
                // for first.
                retract_pending = true;
            }
            _ => {
                // Other event kinds (span_repaired, etc.) do not
                // change support polarity in v0.84. They may be
                // wired in later cycles via Carina payload typing.
            }
        }
    }

    if retract_pending {
        let retracted: std::collections::BTreeSet<String> = prior_event_ids.into_iter().collect();
        sp = sp.retract(&retracted);
    }

    sp
}

/// Compute the [`BelnapStatus`] of a finding directly from its
/// event stream. This is the substrate's status rule per
/// `docs/THEORY.md` Section 7, applied to the live event log.
pub fn compute_belnap_status<'a, I>(events: I) -> BelnapStatus
where
    I: IntoIterator<Item = ProvenanceEventRef<'a>>,
{
    compute_status_provenance(events).derive_status()
}

/// Convenience helper: compute the [`StatusProvenance`] for a
/// single finding from the live `StateEvent` log of a `Project`.
///
/// Filters events to those targeting `finding_id` and projects
/// each into a [`ProvenanceEventRef`] before delegating to
/// [`compute_status_provenance`].
///
/// This is the bridge layer the Workbench API uses to surface
/// derived BelnapStatus alongside each finding without changing
/// any on-disk state. The status field on the finding remains
/// authoritative; the Belnap value is a computed view.
pub fn status_provenance_for_finding(
    project: &vela_protocol::project::Project,
    finding_id: &str,
) -> StatusProvenance {
    let refs: Vec<ProvenanceEventRef<'_>> = project
        .events
        .iter()
        .filter(|e| e.target.id == finding_id && e.target.r#type == "finding")
        .map(|e| ProvenanceEventRef {
            id: &e.id,
            kind: e.kind.as_str(),
            finding_id: &e.target.id,
            payload: &e.payload,
        })
        .collect();
    compute_status_provenance(refs)
}

/// Convenience helper: compute the [`BelnapStatus`] of a finding
/// in a `Project` directly. Equivalent to
/// `status_provenance_for_finding(project, id).derive_status()`.
pub fn belnap_status_for_finding(
    project: &vela_protocol::project::Project,
    finding_id: &str,
) -> BelnapStatus {
    status_provenance_for_finding(project, finding_id).derive_status()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ev<'a>(
        id: &'a str,
        kind: &'a str,
        finding_id: &'a str,
        payload: &'a Value,
    ) -> ProvenanceEventRef<'a> {
        ProvenanceEventRef {
            id,
            kind,
            finding_id,
            payload,
        }
    }

    #[test]
    fn empty_event_log_yields_n() {
        let events: Vec<ProvenanceEventRef> = vec![];
        assert_eq!(compute_belnap_status(events), BelnapStatus::None);
    }

    #[test]
    fn finding_asserted_yields_t() {
        let null = json!(null);
        let events = vec![ev("vev_001", "finding.asserted", "vf_x", &null)];
        assert_eq!(compute_belnap_status(events), BelnapStatus::True);
    }

    #[test]
    fn accepted_review_keeps_t() {
        let null = json!(null);
        let accepted = json!({"status": "accepted"});
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.reviewed", "vf_x", &accepted),
        ];
        let sp = compute_status_provenance(events);
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.support.term_count(), 2);
        assert!(sp.refute.is_zero());
    }

    #[test]
    fn contested_review_promotes_to_b() {
        let null = json!(null);
        let contested = json!({"status": "contested"});
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.reviewed", "vf_x", &contested),
        ];
        assert_eq!(compute_belnap_status(events), BelnapStatus::Both);
    }

    #[test]
    fn rejected_review_promotes_to_b() {
        let null = json!(null);
        let rejected = json!({"status": "rejected"});
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.reviewed", "vf_x", &rejected),
        ];
        assert_eq!(compute_belnap_status(events), BelnapStatus::Both);
    }

    #[test]
    fn finding_rejected_event_adds_refute() {
        let null = json!(null);
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.rejected", "vf_x", &null),
        ];
        assert_eq!(compute_belnap_status(events), BelnapStatus::Both);
    }

    #[test]
    fn retraction_drops_all_prior_support_to_n() {
        let null = json!(null);
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.retracted", "vf_x", &null),
        ];
        // After retraction, no support derivations remain.
        // No refutation either, so status falls to N.
        assert_eq!(compute_belnap_status(events), BelnapStatus::None);
    }

    #[test]
    fn retraction_drops_refute_too() {
        // Theorem-2-aware: retraction is a homomorphism over both
        // polynomials. If the only refute came from a now-retracted
        // event, refute also empties.
        let null = json!(null);
        let rejected = json!({"status": "rejected"});
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.reviewed", "vf_x", &rejected),
            ev("vev_003", "finding.retracted", "vf_x", &null),
        ];
        // All three event ids are retracted. Both polynomials empty.
        assert_eq!(compute_belnap_status(events), BelnapStatus::None);
    }

    #[test]
    fn needs_revision_keeps_t_not_b() {
        let null = json!(null);
        let nr = json!({"status": "needs_revision"});
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.reviewed", "vf_x", &nr),
        ];
        // needs_revision is a flag, not a polarity flip.
        assert_eq!(compute_belnap_status(events), BelnapStatus::True);
    }

    #[test]
    fn unknown_review_status_is_ignored() {
        let null = json!(null);
        let weird = json!({"status": "potato"});
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.reviewed", "vf_x", &weird),
        ];
        // The asserted event keeps support; the review with an
        // unknown status string contributes nothing rather than
        // fabricating polarity.
        let sp = compute_status_provenance(events);
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.support.term_count(), 1);
    }

    #[test]
    fn support_polynomial_records_all_supporting_event_ids() {
        let null = json!(null);
        let accepted = json!({"status": "accepted"});
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.reviewed", "vf_x", &accepted),
            ev("vev_003", "finding.reviewed", "vf_x", &accepted),
        ];
        let sp = compute_status_provenance(events);
        assert_eq!(sp.support.term_count(), 3);
        let support_vars = sp.support.support();
        assert!(support_vars.contains("vev_001"));
        assert!(support_vars.contains("vev_002"));
        assert!(support_vars.contains("vev_003"));
    }

    /// Build a synthetic Project with the given events targeting
    /// the given finding id. Used to test the Project-level
    /// helpers that bridge to the live event log.
    fn synthetic_project(
        _finding_id: &str,
        events: Vec<vela_protocol::events::StateEvent>,
    ) -> vela_protocol::project::Project {
        // Use the canonical factory (assemble) with no findings and
        // then override events. The genesis event is preserved
        // because the factory emits one; we filter it out of our
        // tests by targeting unrelated finding ids.
        let mut p = vela_protocol::project::assemble("test-frontier", vec![], 0, 0, "test");
        // Drop the genesis event; tests want a clean event list.
        p.events.clear();
        p.events = events;
        p
    }

    fn synthetic_event(
        id: &str,
        kind: &str,
        finding_id: &str,
        status: Option<&str>,
    ) -> vela_protocol::events::StateEvent {
        use vela_protocol::events::{StateActor, StateEvent, StateTarget};
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

    #[test]
    fn project_level_helper_filters_by_finding_id() {
        // Two events: one targets vf_x, one targets vf_y.
        // The helper should only consider events targeting vf_x.
        let events = vec![
            synthetic_event("vev_001", "finding.asserted", "vf_x", None),
            synthetic_event("vev_002", "finding.asserted", "vf_y", None),
        ];
        let p = synthetic_project("vf_x", events);
        let sp = status_provenance_for_finding(&p, "vf_x");
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        // Only one event contributed — the vf_x one.
        assert_eq!(sp.support.term_count(), 1);
        assert!(sp.support.support().contains("vev_001"));
        assert!(!sp.support.support().contains("vev_002"));
    }

    #[test]
    fn project_level_helper_handles_full_chain() {
        // asserted -> reviewed(contested) on vf_x
        let events = vec![
            synthetic_event("vev_001", "finding.asserted", "vf_x", None),
            synthetic_event("vev_002", "finding.reviewed", "vf_x", Some("contested")),
        ];
        let p = synthetic_project("vf_x", events);
        let belnap = belnap_status_for_finding(&p, "vf_x");
        assert_eq!(belnap, BelnapStatus::Both);
    }

    #[test]
    fn project_level_helper_with_no_events_yields_n() {
        let p = synthetic_project("vf_x", vec![]);
        assert_eq!(belnap_status_for_finding(&p, "vf_x"), BelnapStatus::None);
    }

    #[test]
    fn unrelated_event_kinds_do_not_affect_status() {
        let null = json!(null);
        let events = vec![
            ev("vev_001", "finding.asserted", "vf_x", &null),
            ev("vev_002", "finding.span_repaired", "vf_x", &null),
        ];
        let sp = compute_status_provenance(events);
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.support.term_count(), 1);
    }
}
