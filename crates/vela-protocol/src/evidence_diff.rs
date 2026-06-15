//! Evidence Diff: the before/after lens over a claim's state.
//!
//! Two derived projections, both read-only over the accepted event log —
//! they never write, never store, and mint no new event kinds:
//!
//!   - [`state_cell`] — the Claim-State Cell (frontier_calculus §4.2 /
//!     STATE_PLANE_MEMO §7.1): claim, context, Belnap-style status,
//!     status provenance (support/refute polynomials + graded bilattice),
//!     supersession, dependencies, open obligations, priority. This is the
//!     pure core relocated out of the CLI so the hub can compute the
//!     identical cell.
//!   - [`claim_state_delta`] — applies one pending proposal in-memory
//!     (the same `apply_proposal` the preview uses, never saved) and
//!     reports the target claim's state *before* and *after*, plus the
//!     downstream claims whose status letter flips as a result. This is
//!     the integrating lens behind the Evidence Diff page: "what changed,
//!     what broke, what should be reviewed next."
//!
//! The Engine verdict ("what would CI say if accepted?") is deliberately
//! NOT computed here: `evidence_ci::run_project` needs a frontier path
//! (policy docs, artifact files), which the hub's Postgres-materialized
//! project does not have. The CLI caller, which holds the path, merges in
//! `proposals::preview_engine_verdict`; the hub renders engine as absent
//! (the real strict gate runs at accept time and returns 422 on refusal).

use std::collections::BTreeSet;

use serde_json::{Value, json};

use crate::bundle::{FindingBundle, ReviewState};
use crate::contradiction::ContradictionStatus;
use crate::events::StateEvent;
use crate::project::{Project, StatementRegistration};
use crate::provenance_poly::ProvenancePoly;
use crate::status_provenance::{BelnapStatus, StatusProvenance};
use crate::verifier_attachment::{
    AttachmentOutcome, GateStatus, MethodIntegrity, VerifierAttachment, claim_digest,
    derive_gate_status,
};

/// A passed, claim-matched attachment whose method integrity is not
/// `Compromised` — artifact-level support. Replicates the gate's private
/// `is_passing_match` over public fields (the projection is read-only and
/// must not depend on gate internals).
fn is_passing_match(a: &VerifierAttachment, digest: &str) -> bool {
    a.id.starts_with("vva_")
        && a.outcome == AttachmentOutcome::Passed
        && a.claim_digest == digest
        && a.match_to_claim.matches
        && a.method_integrity != MethodIntegrity::Compromised
}

/// The verifier attachments bound to this finding's CURRENT claim.
/// Cloned (owned) to match `derive_gate_status`'s `&[VerifierAttachment]`.
pub fn matched_attachments(project: &Project, finding: &FindingBundle) -> Vec<VerifierAttachment> {
    project
        .verifier_attachments
        .iter()
        .filter(|a| a.target == finding.id)
        .cloned()
        .collect()
}

/// Adjudicated (human-confirmed/resolved) contradictions naming this
/// finding — a refute signal. Candidates are NOT counted (doctrine:
/// contradictions are never auto-adjudicated).
fn adjudicated_contradiction(project: &Project, id: &str) -> bool {
    project.contradictions.iter().any(|c| {
        (c.finding_a == id || c.finding_b == id)
            && matches!(
                c.status,
                ContradictionStatus::ExpertConfirmed { .. } | ContradictionStatus::Resolved { .. }
            )
    })
}

/// The priority registration for a finding (gap 5). Prefers the exact
/// finding-to-registration edge (`payload.finding_id`, stored on
/// `StatementRegistration.finding_id`); falls back to the original
/// heuristic (statement hash equals the claim digest, or the
/// informal_ref names the finding id) for registrations that predate
/// the edge. Returns the registration plus how it matched.
pub fn find_priority_registration<'a>(
    project: &'a Project,
    id: &str,
    digest: &str,
) -> Option<(&'a StatementRegistration, &'static str)> {
    project
        .statement_registrations
        .iter()
        .find(|r| r.finding_id.as_deref() == Some(id))
        .map(|r| (r, "finding_edge"))
        .or_else(|| {
            project
                .statement_registrations
                .iter()
                .find(|r| r.statement_hash == digest || r.informal_ref.contains(id))
                .map(|r| (r, "heuristic"))
        })
}

/// Gap 2: derive the support/refute provenance polynomials for a
/// finding from its event history — a READ-SIDE projection, computed
/// at projection time and never stored. Zero reducer or state changes.
///
/// Contribution rules over the canonical log (in log order):
///   - `finding.asserted` and accept events (`finding.reviewed` with
///     status accepted/approved) contribute support variables — the
///     event ids themselves.
///   - `finding.superseded` and `finding.retracted` apply the
///     retraction homomorphism `rho_Y` with Y = the support variables
///     accumulated so far, so every supporting derivation path dies
///     (Theorem 2/3: no zombie findings — superseded implies the
///     support polynomial is zero, hence the status cannot be T).
///   - `finding.dependency_invalidated` contributes a refute variable.
pub fn derive_status_provenance(events: &[StateEvent], id: &str) -> StatusProvenance {
    let mut sp = StatusProvenance::empty();
    for e in events.iter().filter(|e| e.target.id == id) {
        match e.kind.as_str() {
            "finding.asserted" => sp.add_support(&ProvenancePoly::singleton(e.id.as_str())),
            "finding.reviewed" => {
                if matches!(
                    e.payload.get("status").and_then(Value::as_str),
                    Some("accepted") | Some("approved")
                ) {
                    sp.add_support(&ProvenancePoly::singleton(e.id.as_str()));
                }
            }
            "finding.dependency_invalidated" => {
                sp.add_refute(&ProvenancePoly::singleton(e.id.as_str()));
            }
            "finding.superseded" | "finding.retracted" => {
                let retracted: BTreeSet<String> = sp.support.support();
                sp = sp.retract(&retracted);
            }
            _ => {}
        }
    }
    sp
}

fn belnap_meaning(status: BelnapStatus) -> &'static str {
    match status {
        BelnapStatus::True => "supported",
        BelnapStatus::False => "refuted",
        BelnapStatus::Both => "both supported and refuted (contested)",
        BelnapStatus::None => "neither supported nor refuted",
    }
}

/// Derive the Claim-State Cell — a projection over the event log, never
/// a stored object. (frontier_calculus §4.2, STATE_PLANE_MEMO §7.1.)
///
/// Relocated verbatim from `vela-cli::cli_claim::derive_state_cell` so
/// both the CLI projection and the hub Evidence-Diff endpoint compute
/// the identical cell from one source of truth.
pub fn state_cell(project: &Project, finding: &FindingBundle) -> Value {
    let id = finding.id.as_str();
    let digest = claim_digest(&finding.assertion.text);
    let atts = matched_attachments(project, finding);
    let gate = derive_gate_status(&digest, &atts);

    // Evidence-polarity signals (Belnap). Support and refute are
    // independent bits over EXISTING objects; status is their join.
    let mut support_signals: Vec<&str> = Vec::new();
    let mut refute_signals: Vec<&str> = Vec::new();

    if matches!(finding.flags.review_state, Some(ReviewState::Accepted)) {
        support_signals.push("review_state=accepted");
    }
    if gate.status == GateStatus::Verified {
        support_signals.push("verifier_gate=verified");
    }
    // A passing, claim-matched attachment is artifact-level support even
    // when the full G1–G4 gate is not yet satisfied (the §7.1 example:
    // "contested flag + passing attachment" → B).
    if atts.iter().any(|a| is_passing_match(a, &digest)) {
        support_signals.push("verifier_attachment=passed");
    }

    if finding.flags.retracted {
        refute_signals.push("retracted");
    }
    match finding.flags.review_state {
        Some(ReviewState::Rejected) => refute_signals.push("review_state=rejected"),
        Some(ReviewState::Contested) => refute_signals.push("review_state=contested"),
        Some(ReviewState::NeedsRevision) => refute_signals.push("review_state=needs_revision"),
        _ => {}
    }
    if finding.flags.contested {
        refute_signals.push("flags.contested");
    }
    if gate.status == GateStatus::Refuted {
        refute_signals.push("verifier_gate=refuted");
    }
    if adjudicated_contradiction(project, id) {
        refute_signals.push("contradiction=adjudicated");
    }

    let has_support = !support_signals.is_empty();
    let has_refute = !refute_signals.is_empty();
    let status = match (has_support, has_refute) {
        (true, true) => "B",
        (true, false) => "T",
        (false, true) => "F",
        (false, false) => "N",
    };
    let status_meaning = match status {
        "T" => "supported",
        "F" => "refuted",
        "B" => "both supported and refuted (contested)",
        _ => "neither supported nor refuted",
    };

    // Supersession: the OLD finding carries flags.superseded; the
    // replacement id (if any) is in the thin finding.superseded event.
    let superseding_id = project
        .events
        .iter()
        .filter(|e| e.kind == "finding.superseded" && e.target.id == id)
        .max_by(|a, b| a.timestamp.cmp(&b.timestamp))
        .and_then(|e| {
            e.payload
                .get("new_finding_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    let supersession = json!({
        "superseded": finding.flags.superseded,
        "superseded_by": superseding_id,
    });

    // Dependencies: this finding's outbound typed links.
    let dependencies: Vec<Value> = finding
        .links
        .iter()
        .map(|l| {
            json!({
                "target": l.target,
                "type": l.link_type,
                "note": l.note,
            })
        })
        .collect();

    // Open obligations: gap-flagged findings linked to this finding in
    // either direction (mirrors the task_packet derivation).
    let open_obligations: Vec<Value> = project
        .findings
        .iter()
        .filter(|f| f.flags.gap && f.id != id)
        .filter(|f| {
            f.links.iter().any(|l| l.target == id) || finding.links.iter().any(|l| l.target == f.id)
        })
        .map(|f| {
            json!({
                "id": f.id,
                "statement": f.assertion.text,
                "review_state": f.flags.review_state.as_ref().map(|s| format!("{s:?}")),
            })
        })
        .collect();

    // Priority registration: the exact finding-to-registration edge
    // when present (gap 5), else the original heuristic (statement
    // hash equals the claim digest, or informal_ref names the id).
    // Rendered `null` (absent) when nothing matches — never invented.
    let priority = find_priority_registration(project, id, &digest).map(|(r, matched_by)| {
        json!({
            "statement_hash": r.statement_hash,
            "informal_ref": r.informal_ref,
            "registered_by": r.registered_by,
            "registered_at": r.registered_at,
            "finding_id": r.finding_id,
            "matched_by": matched_by,
        })
    });

    // Gap 2: the provenance-semiring view of the same status — derived
    // from the event history at read time, never stored. Printed NEXT
    // TO the signal-derived status with an explicit divergence flag:
    // measurement, not silent replacement.
    let sp = derive_status_provenance(&project.events, id);
    let poly_status = sp.derive_status();
    let poly_letter = poly_status.letter().to_string();
    // v2 frontier calculus: the graded bilattice status (kappa of support,
    // kappa of refute), derived from the SAME polynomials at read time. Absent
    // per-source confidence it defaults to 1, so the corner reproduces the
    // Belnap status exactly — the conservative extension, live.
    let graded = sp.derive_graded_status(&std::collections::BTreeMap::new());
    let status_provenance = json!({
        "support_poly": sp.support.to_string(),
        "refute_poly": sp.refute.to_string(),
        "letter": poly_letter,
        "meaning": belnap_meaning(poly_status),
        "divergence": poly_letter != status,
        "graded_status": {
            "support_degree": graded.x.to_f64(),
            "opposition_degree": graded.y.to_f64(),
            "information": graded.information().to_f64(),
            "conflict": graded.conflict().to_f64(),
            "corner": graded.corner().letter().to_string(),
            "note": "v2 bilattice point [0,1]x[0,1] (frontier_calculus); confidence defaults to 1 so the corner equals the Belnap letter (conservative extension). Per-source confidence is the deferred refinement.",
        },
        // Projection provenance (T16): the derived graded flag is auditable, not
        // authoritative. This record names the evaluator, valuation, and source
        // so anyone can recompute the flag from the declared inputs above. It is
        // a proof packet for a projection, never stored state.
        "projection_provenance": {
            "projection_kind": "graded_bilattice_status",
            "evaluator": "kappa = Eval_Viterbi . env (square-free environment quotient of N[X], v3); corner thresholds each coordinate at > 0",
            "valuation": "per-source confidence in [0,1]; absent sources default to 1",
            "source": { "support_poly": sp.support.to_string(), "refute_poly": sp.refute.to_string() },
            "policy": "frontier_calculus v3 (env-quotient kappa; conservative extension is Theorem 20, lean/Vela/FrontierCalculus.lean)",
            "reproduce": "kappa(support_poly) and kappa(refute_poly) under the valuation give (support_degree, opposition_degree); the corner letter is deriveStatus(support_degree > 0, opposition_degree > 0)",
        },
        "note": "read-side projection over the event log (asserted/accept -> support vars, supersession/retraction -> rho_Y, dependency_invalidated -> refute); never stored",
    });

    json!({
        "projection": "claim_state_cell",
        "frontier_id": project.frontier_id(),
        "claim": finding.assertion.text,
        "context": {
            "conditions": finding.conditions.text,
            "species_verified": finding.conditions.species_verified,
            "in_vitro": finding.conditions.in_vitro,
            "in_vivo": finding.conditions.in_vivo,
            "human_data": finding.conditions.human_data,
            "clinical_trial": finding.conditions.clinical_trial,
        },
        "id": id,
        "status": {
            "letter": status,
            "meaning": status_meaning,
            "support_signals": support_signals,
            "refute_signals": refute_signals,
        },
        "status_provenance": status_provenance,
        "supersession": supersession,
        "dependencies": dependencies,
        "open_obligations": open_obligations,
        "priority_registration": priority,
    })
}

/// The headline Belnap letter of a finding's current state cell.
fn status_letter(project: &Project, finding: &FindingBundle) -> String {
    state_cell(project, finding)["status"]["letter"]
        .as_str()
        .unwrap_or("N")
        .to_string()
}

/// Whether `dependent` depends on `target_id` through any outbound link.
fn depends_on(dependent: &FindingBundle, target_id: &str) -> bool {
    dependent.links.iter().any(|l| l.target == target_id)
}

/// Classify a downstream letter transition into a human-readable reason.
fn downstream_reason(before: &str, after: &str) -> &'static str {
    match (before, after) {
        // Lost its only support path (T/B -> F/N with no support left).
        ("T", "F") | ("T", "N") | ("B", "F") => "support_path_lost",
        // Gained a refute signal (a dependency_invalidated cascade), or
        // landed in B (both) — contested either way.
        (_, "B") | ("N", "F") => "now_contested",
        // Gained support without conflict.
        ("N", "T") | ("F", "T") => "strengthened",
        _ => "changed",
    }
}

/// The integrating Evidence-Diff lens: apply one pending proposal
/// in-memory (never saved) and report the target claim's state cell
/// before and after, plus the downstream claims whose status letter
/// flips as a result.
///
/// `reviewer` is the synthetic actor under which the in-memory apply
/// runs (e.g. `reviewer:evidence-diff-preview`); nothing is persisted,
/// so it never confers authority. The Engine verdict is NOT included —
/// see the module docs; callers with a frontier path merge it in.
pub fn claim_state_delta(
    project: &Project,
    proposal_id: &str,
    reviewer: &str,
) -> Result<Value, String> {
    let proposal = project
        .proposals
        .iter()
        .find(|p| p.id == proposal_id)
        .ok_or_else(|| format!("Proposal not found: {proposal_id}"))?
        .clone();
    let target_id = proposal.target.id.clone();

    // before: the target's current cell (null if the proposal introduces
    // a new finding that does not exist yet).
    let before = project
        .findings
        .iter()
        .find(|f| f.id == target_id)
        .map(|f| state_cell(project, f));
    let before_letter = before
        .as_ref()
        .and_then(|c| c["status"]["letter"].as_str())
        .unwrap_or("N")
        .to_string();

    // after: clone, apply the proposal in-memory under the synthetic
    // reviewer, recompute the target cell. Reuses the same
    // `apply_proposal` the diff preview uses, so before/after agree.
    let mut after_state: Project = serde_json::from_value(
        serde_json::to_value(project).map_err(|e| format!("serialize project: {e}"))?,
    )
    .map_err(|e| format!("clone project: {e}"))?;
    crate::proposals::apply_proposal(
        &mut after_state,
        &proposal,
        reviewer,
        "Evidence Diff preview application",
    )?;
    let after = after_state
        .findings
        .iter()
        .find(|f| f.id == target_id)
        .map(|f| state_cell(&after_state, f));
    let after_letter = after
        .as_ref()
        .and_then(|c| c["status"]["letter"].as_str())
        .unwrap_or("N")
        .to_string();

    // downstream: every finding that depends on the target and whose
    // status letter flips between before and after.
    let mut downstream: Vec<Value> = Vec::new();
    for dep in project.findings.iter().filter(|f| depends_on(f, &target_id)) {
        let before_d = status_letter(project, dep);
        let after_d = after_state
            .findings
            .iter()
            .find(|f| f.id == dep.id)
            .map(|f| status_letter(&after_state, f))
            .unwrap_or_else(|| "N".to_string());
        if before_d != after_d {
            downstream.push(json!({
                "id": dep.id,
                "statement": dep.assertion.text,
                "before": before_d,
                "after": after_d,
                "reason": downstream_reason(&before_d, &after_d),
            }));
        }
    }

    Ok(json!({
        "projection": "claim_state_delta",
        "frontier_id": project.frontier_id(),
        "proposal_id": proposal.id,
        "kind": proposal.kind,
        "target": target_id,
        "status_change": {
            "before": before_letter,
            "after": after_letter,
            "changed": before_letter != after_letter,
        },
        "before": before,
        "after": after,
        "downstream": downstream,
        "downstream_count": downstream.len(),
        // Filled by callers that hold a frontier path (the CLI); the hub
        // leaves it absent because the strict gate runs at accept time.
        "engine": { "available": false, "note": "Engine verdict (new_blocking/new_warnings) requires a frontier path; run `vela claim diff` locally, or attempt the accept to see the strict gate verdict." },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{NULL_HASH, StateActor, StateTarget};

    fn ev(idx: usize, kind: &str, target: &str, payload: Value) -> StateEvent {
        StateEvent {
            schema: crate::events::EVENT_SCHEMA.to_string(),
            id: format!("vev_synthetic_{idx:04}"),
            kind: kind.to_string(),
            target: StateTarget {
                r#type: "finding".to_string(),
                id: target.to_string(),
            },
            actor: StateActor {
                id: "reviewer:synthetic".to_string(),
                r#type: "human".to_string(),
            },
            timestamp: format!("2026-06-12T00:00:{:02}Z", idx % 60),
            reason: "synthetic provenance test".to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload,
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        }
    }

    #[test]
    fn asserted_plus_accept_derives_t() {
        let log = vec![
            ev(0, "finding.asserted", "vf_a", json!({})),
            ev(1, "finding.reviewed", "vf_a", json!({"status": "accepted"})),
        ];
        let sp = derive_status_provenance(&log, "vf_a");
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.support.term_count(), 2);
        assert!(sp.refute.is_zero());
    }

    /// Polynomial no-zombie (Theorem 3 at the projection layer):
    /// supersession applies rho_Y over every accumulated support
    /// variable, so the support polynomial is zero and the derived
    /// status cannot remain T.
    #[test]
    fn polynomial_no_zombie_superseded_support_is_zero_not_t() {
        let log = vec![
            ev(0, "finding.asserted", "vf_a", json!({})),
            ev(1, "finding.reviewed", "vf_a", json!({"status": "accepted"})),
            ev(
                2,
                "finding.superseded",
                "vf_a",
                json!({"new_finding_id": "vf_b"}),
            ),
        ];
        let sp = derive_status_provenance(&log, "vf_a");
        assert!(sp.support.is_zero());
        assert_ne!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.derive_status(), BelnapStatus::None);
    }

    #[test]
    fn retraction_also_zeroes_support() {
        let log = vec![
            ev(0, "finding.asserted", "vf_a", json!({})),
            ev(1, "finding.retracted", "vf_a", json!({})),
        ];
        let sp = derive_status_provenance(&log, "vf_a");
        assert!(sp.support.is_zero());
        assert_eq!(sp.derive_status(), BelnapStatus::None);
    }

    #[test]
    fn dependency_invalidated_contributes_refute() {
        let log = vec![
            ev(0, "finding.asserted", "vf_b", json!({})),
            ev(
                1,
                "finding.dependency_invalidated",
                "vf_b",
                json!({"upstream_finding_id": "vf_a", "depth": 1}),
            ),
        ];
        let sp = derive_status_provenance(&log, "vf_b");
        assert_eq!(sp.derive_status(), BelnapStatus::Both);
        let mut log2 = log;
        log2.push(ev(
            2,
            "finding.superseded",
            "vf_b",
            json!({"new_finding_id": "vf_c"}),
        ));
        let sp2 = derive_status_provenance(&log2, "vf_b");
        assert!(sp2.support.is_zero());
        assert_eq!(sp2.derive_status(), BelnapStatus::False);
    }

    #[test]
    fn support_after_supersession_revives_via_new_event_only() {
        let log = vec![
            ev(0, "finding.asserted", "vf_a", json!({})),
            ev(1, "finding.superseded", "vf_a", json!({})),
            ev(2, "finding.reviewed", "vf_a", json!({"status": "accepted"})),
        ];
        let sp = derive_status_provenance(&log, "vf_a");
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.support.term_count(), 1);
    }

    #[test]
    fn non_accept_reviews_contribute_nothing() {
        let log = vec![
            ev(0, "finding.asserted", "vf_a", json!({})),
            ev(
                1,
                "finding.reviewed",
                "vf_a",
                json!({"status": "contested"}),
            ),
        ];
        let sp = derive_status_provenance(&log, "vf_a");
        assert_eq!(sp.support.term_count(), 1);
        assert!(sp.refute.is_zero());
        assert_eq!(sp.derive_status(), BelnapStatus::True);
    }

    #[test]
    fn events_for_other_findings_are_ignored() {
        let log = vec![
            ev(0, "finding.asserted", "vf_a", json!({})),
            ev(1, "finding.asserted", "vf_b", json!({})),
            ev(2, "finding.retracted", "vf_b", json!({})),
        ];
        let sp = derive_status_provenance(&log, "vf_a");
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.support.term_count(), 1);
    }

    #[test]
    fn downstream_reason_classifies_transitions() {
        assert_eq!(downstream_reason("T", "F"), "support_path_lost");
        assert_eq!(downstream_reason("T", "B"), "now_contested");
        assert_eq!(downstream_reason("N", "T"), "strengthened");
        assert_eq!(downstream_reason("T", "T"), "changed");
    }

    /// End-to-end: a retract proposal on a supported claim flips it
    /// T -> F, and the dependent that `depends` on it is reported in
    /// `downstream` as now-contested (the cascade marks it `contested`,
    /// so its accepted support meets a new refute signal -> B).
    #[test]
    fn claim_state_delta_retract_cascades_to_dependents() {
        use crate::bundle::{Link, ReviewState};
        use crate::events::StateTarget;
        use crate::proposals::new_proposal;
        use crate::test_support::{make_finding, make_project};

        let mut target = make_finding("vf_target", 0.9, "result");
        target.flags.review_state = Some(ReviewState::Accepted);

        let mut dep = make_finding("vf_dep", 0.8, "result");
        dep.flags.review_state = Some(ReviewState::Accepted);
        dep.links.push(Link {
            target: "vf_target".into(),
            link_type: "depends".into(),
            note: "dep depends on target".into(),
            inferred_by: "test".into(),
            created_at: String::new(),
            mechanism: None,
        });

        let mut project = make_project("cascade", vec![target, dep]);
        let proposal = new_proposal(
            "finding.retract",
            StateTarget {
                r#type: "finding".into(),
                id: "vf_target".into(),
            },
            "reviewer:test",
            "human",
            "retracting target",
            json!({}),
            vec![],
            vec![],
        );
        let proposal_id = proposal.id.clone();
        project.proposals.push(proposal);

        let delta = claim_state_delta(&project, &proposal_id, "reviewer:test").unwrap();

        // Target: accepted (T) -> retracted. The prior accept signal
        // lingers as support while `retracted` adds a refute signal, so
        // the signal-derived headline lands at B (both). The status
        // PROVENANCE poly, in contrast, zeroes support under rho_Y — both
        // views travel together in the cell, by design.
        assert_eq!(delta["status_change"]["before"], "T");
        assert_eq!(delta["status_change"]["after"], "B");
        assert_eq!(delta["status_change"]["changed"], true);
        assert_eq!(
            delta["after"]["status_provenance"]["letter"], "N",
            "provenance support is zeroed by the retraction homomorphism"
        );

        // The dependent flips and is reported with a reason code:
        // accepted support + the new contested refute = B (both).
        let downstream = delta["downstream"].as_array().unwrap();
        assert_eq!(downstream.len(), 1, "exactly one dependent should flip");
        assert_eq!(downstream[0]["id"], "vf_dep");
        assert_eq!(downstream[0]["before"], "T");
        assert_eq!(downstream[0]["after"], "B");
        assert_eq!(downstream[0]["reason"], "now_contested");
    }
}
