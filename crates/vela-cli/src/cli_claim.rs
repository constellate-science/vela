//! Read-side claim projections: `vela claim {state,trust,pack}`.
//!
//! These are DERIVED projections over the accepted event log — they
//! never write, never store, and mint no new event kinds. Each loads the
//! repo (`repo::load_from_path`) and recomputes a view from objects the
//! reducer already produced:
//!
//!   - `state`  — the Claim-State Cell (frontier_calculus §4.2 /
//!     STATE_PLANE_MEMO §7.1): claim, context, Belnap-style status,
//!     supersession, dependencies, open obligations, priority.
//!   - `trust`  — the Trust Vector (§7 / §7.2) as a projection over
//!     EXISTING objects. Absent fields render `"absent"`, never invented.
//!   - `pack`   — state + trust + the exact reproduce command + the
//!     event ids that touch the claim: a citable claim pack.
//!
//! Dispatched by an intercept in `cli.rs::run_from_args` (mirroring the
//! `proof verify` / atlas-r2 read-only intercepts) so the projections
//! sit ahead of the clap dispatcher and never collide with the existing
//! `vela claim <frontier> <obligation>` lease command.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value, json};
use vela_protocol::bundle::{FindingBundle, ReviewState};
use vela_protocol::contradiction::ContradictionStatus;
use vela_protocol::events::{StateEvent, actor_kind};
use vela_protocol::project::{Project, StatementRegistration};
use vela_protocol::provenance_poly::ProvenancePoly;
use vela_protocol::repo;
use vela_protocol::status_provenance::{BelnapStatus, StatusProvenance};
use vela_protocol::verifier_attachment::{
    AttachmentOutcome, GateStatus, MethodIntegrity, VerifierAttachment, claim_digest,
    derive_gate_status,
};

use crate::cli::{fail, print_json};

/// Entry point from the `cli.rs::run_from_args` intercept. `args` is the
/// full `std::env::args()` vector; `args[2]` is the verb
/// (`state`/`trust`/`pack`), `args[3]` the frontier, `args[4]` the
/// `vf_…` id.
pub(crate) fn run(args: &[String]) {
    let verb = args.get(2).map(String::as_str).unwrap_or("");
    let json = args.iter().any(|a| a == "--json");
    // Positional operands: the first two non-flag tokens after the verb.
    let positionals: Vec<&str> = args
        .iter()
        .skip(3)
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect();
    let frontier = positionals.first().copied().unwrap_or_else(|| {
        fail(&format!(
            "usage: vela claim {verb} <frontier> <vf_id> [--json]"
        ))
    });
    let vf_id = positionals.get(1).copied().unwrap_or_else(|| {
        fail(&format!(
            "usage: vela claim {verb} <frontier> <vf_id> [--json]"
        ))
    });

    let project = repo::load_from_path(Path::new(frontier)).unwrap_or_else(|e| fail(&e));
    let finding = project
        .findings
        .iter()
        .find(|f| f.id == vf_id)
        .unwrap_or_else(|| fail(&format!("finding {vf_id} not found in {frontier}")));

    match verb {
        "state" => {
            let cell = derive_state_cell(&project, finding);
            if json {
                print_json(&cell);
            } else {
                print_state_human(&cell);
            }
        }
        "trust" => {
            let vector = derive_trust_vector(&project, finding);
            if json {
                print_json(&vector);
            } else {
                print_trust_human(&vector);
            }
        }
        "pack" => {
            let pack = derive_pack(&project, finding, frontier);
            // The pack is a citable JSON object; the default render is
            // also JSON so a copy-paste is byte-faithful.
            print_json(&pack);
        }
        other => fail(&format!("unknown claim projection '{other}'")),
    }
}

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
fn matched_attachments(project: &Project, finding: &FindingBundle) -> Vec<VerifierAttachment> {
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
fn find_priority_registration<'a>(
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
fn derive_status_provenance(events: &[StateEvent], id: &str) -> StatusProvenance {
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

/// Latest `finding.reviewed` event targeting this finding, if any —
/// used to attribute the human/agent provenance of the review verdict.
fn latest_review_event<'a>(
    project: &'a Project,
    id: &str,
) -> Option<&'a vela_protocol::events::StateEvent> {
    project
        .events
        .iter()
        .filter(|e| e.kind == "finding.reviewed" && e.target.id == id)
        .max_by(|a, b| a.timestamp.cmp(&b.timestamp))
}

/// Derive the Claim-State Cell — a projection over the event log, never
/// a stored object. (frontier_calculus §4.2, STATE_PLANE_MEMO §7.1.)
fn derive_state_cell(project: &Project, finding: &FindingBundle) -> Value {
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

/// Derive the Trust Vector as a projection over EXISTING objects.
/// Scoped to the seven fields the substrate can answer from accepted
/// state; absent fields render `"absent"`, never invented. (§7 / §7.2.)
fn derive_trust_vector(project: &Project, finding: &FindingBundle) -> Value {
    let id = finding.id.as_str();
    let digest = claim_digest(&finding.assertion.text);
    let atts = matched_attachments(project, finding);
    let gate = derive_gate_status(&digest, &atts);

    // log_integrity: whole-log replay verification (frontier-scoped).
    let replay = vela_protocol::reducer::verify_replay(project);
    let log_integrity = json!({
        "result": if replay.ok { "pass" } else { "fail" },
        "note": replay.note,
    });

    // artifact_replay: the outcome of THIS claim's verifier attachments
    // (witness / proof re-checks). Absent when nothing is attached.
    let artifact_replay = if atts.is_empty() {
        Value::String("absent".into())
    } else {
        let passed = atts
            .iter()
            .filter(|a| a.outcome == AttachmentOutcome::Passed)
            .count();
        let failed = atts.len() - passed;
        json!({
            "attachments": atts.len(),
            "passed": passed,
            "failed": failed,
            "methods": atts
                .iter()
                .map(|a| a.verifier_method.as_str())
                .collect::<Vec<_>>(),
        })
    };

    // verifier_gate: the derived G1–G4 gate status (never stored).
    let verifier_gate = json!({
        "status": format!("{:?}", gate.status),
        "reasons": gate.reasons,
    });

    // statement_faithfulness: a vsa_ verdict targeting this finding.
    let statement_faithfulness = project
        .statement_attestations
        .iter()
        .filter(|a| a.target == id)
        .max_by(|a, b| a.attested_at.cmp(&b.attested_at))
        .map(|a| {
            json!({
                "verdict": format!("{:?}", a.verdict),
                "attested_by": a.attested_by,
                "informal_ref": a.informal_ref,
                "formal_ref": a.formal_ref,
            })
        })
        .unwrap_or_else(|| Value::String("absent".into()));

    // human_review: the typed review verdict + the reviewer's provenance.
    let human_review = match finding.flags.review_state.as_ref() {
        None => Value::String("absent".into()),
        Some(state) => {
            let reviewer = latest_review_event(project, id).map(|e| e.actor.id.clone());
            let actor_class = reviewer.as_deref().map(actor_kind);
            json!({
                "review_state": format!("{state:?}"),
                "reviewer": reviewer,
                "actor_class": actor_class,
            })
        }
    };

    // transfer_status: vtr_ records that touch this finding as source or
    // target premise. The full T1–T5 admission re-derivation needs the
    // resolved source gate + theorem verification + domain tags; here we
    // surface the records themselves (touching it) per the projection's
    // scope, with the producer-declared status marked DISPLAY ONLY.
    let transfers: Vec<Value> = project
        .transfers
        .iter()
        .filter(|t| t.source_claim == id || t.target_claim == id)
        .map(|t| {
            json!({
                "transfer_id": t.transfer_id,
                "role": if t.source_claim == id { "source" } else { "target" },
                "source_claim": t.source_claim,
                "target_claim": t.target_claim,
                "kind": format!("{:?}", t.homomorphism.kind),
                "source_gate_status_claimed": t.source_gate_status_claimed,
                "note": "source_gate_status_claimed is DISPLAY ONLY; admission re-derives via derive_transfer_status",
            })
        })
        .collect();
    let transfer_status = if transfers.is_empty() {
        Value::String("absent".into())
    } else {
        Value::Array(transfers)
    };

    // priority: a registered statement hash (the priority timestamp).
    // Exact finding edge first (gap 5), heuristic fallback.
    let priority = find_priority_registration(project, id, &digest)
        .map(|(r, matched_by)| {
            json!({
                "registered": true,
                "statement_hash": r.statement_hash,
                "registered_at": r.registered_at,
                "finding_id": r.finding_id,
                "matched_by": matched_by,
            })
        })
        .unwrap_or_else(|| Value::String("absent".into()));

    json!({
        "projection": "trust_vector",
        "frontier_id": project.frontier_id(),
        "id": id,
        "claim": finding.assertion.text,
        "trust_vector": {
            "log_integrity": log_integrity,
            "artifact_replay": artifact_replay,
            "verifier_gate": verifier_gate,
            "statement_faithfulness": statement_faithfulness,
            "human_review": human_review,
            "transfer_status": transfer_status,
            "priority": priority,
        },
        "law": "no safe universal projection trust_vector -> verified_bool preserves all safety-relevant distinctions",
    })
}

/// Derive the citable claim pack: state + trust + the exact reproduce
/// command + the event ids that touch the claim.
fn derive_pack(project: &Project, finding: &FindingBundle, frontier: &str) -> Value {
    let id = finding.id.as_str();
    let state = derive_state_cell(project, finding);
    let trust = derive_trust_vector(project, finding);

    // Every canonical event whose target is this finding — the
    // provenance trail a citor can replay.
    let event_ids: Vec<Value> = project
        .events
        .iter()
        .filter(|e| e.target.id == id)
        .map(|e| {
            json!({
                "id": e.id,
                "kind": e.kind,
                "timestamp": e.timestamp,
            })
        })
        .collect();

    json!({
        "projection": "claim_pack",
        "schema": "https://vela.science/schema/claim-pack/v1",
        "frontier_id": project.frontier_id(),
        "id": id,
        "snapshot_hash": vela_protocol::events::snapshot_hash(project),
        "event_log_hash": vela_protocol::events::event_log_hash(&project.events),
        "claim_state": state,
        "trust_vector": trust,
        "reproduce": {
            "command": format!("vela reproduce {frontier}"),
            "gate_command": format!("vela gate {frontier}"),
            "note": "re-verifies stored witnesses from scratch with the frozen exact verifiers",
        },
        "events": event_ids,
    })
}

fn print_state_human(cell: &Value) {
    println!("claim-state cell  {}", cell["id"].as_str().unwrap_or(""));
    println!("  claim:   {}", cell["claim"].as_str().unwrap_or(""));
    println!(
        "  context: {}",
        cell["context"]["conditions"].as_str().unwrap_or("")
    );
    println!(
        "  status:  {} ({})",
        cell["status"]["letter"].as_str().unwrap_or("?"),
        cell["status"]["meaning"].as_str().unwrap_or("")
    );
    if let Some(s) = cell["status"]["support_signals"].as_array()
        && !s.is_empty()
    {
        println!(
            "    support: {}",
            s.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if let Some(r) = cell["status"]["refute_signals"].as_array()
        && !r.is_empty()
    {
        println!(
            "    refute:  {}",
            r.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    let sp = &cell["status_provenance"];
    println!(
        "  status (provenance): {} (support: {}, refute: {}){}",
        sp["letter"].as_str().unwrap_or("?"),
        sp["support_poly"].as_str().unwrap_or("0"),
        sp["refute_poly"].as_str().unwrap_or("0"),
        if sp["divergence"].as_bool().unwrap_or(false) {
            "  [DIVERGES from signal-derived status]"
        } else {
            ""
        }
    );
    println!(
        "  superseded: {}",
        cell["supersession"]["superseded"]
            .as_bool()
            .unwrap_or(false)
    );
    println!(
        "  dependencies: {}",
        cell["dependencies"].as_array().map_or(0, Vec::len)
    );
    println!(
        "  open obligations: {}",
        cell["open_obligations"].as_array().map_or(0, Vec::len)
    );
    let prio = if cell["priority_registration"].is_null() {
        "absent"
    } else {
        "registered"
    };
    println!("  priority: {prio}");
    println!("  (run with --json for the full cell)");
}

fn print_trust_human(vector: &Value) {
    let tv = &vector["trust_vector"];
    println!("trust vector  {}", vector["id"].as_str().unwrap_or(""));
    println!(
        "  log_integrity:         {}",
        tv["log_integrity"]["result"].as_str().unwrap_or("?")
    );
    let ar = &tv["artifact_replay"];
    if ar.is_string() {
        println!("  artifact_replay:       absent");
    } else {
        println!(
            "  artifact_replay:       {} passed / {} failed",
            ar["passed"].as_u64().unwrap_or(0),
            ar["failed"].as_u64().unwrap_or(0)
        );
    }
    println!(
        "  verifier_gate:         {}",
        tv["verifier_gate"]["status"].as_str().unwrap_or("?")
    );
    println!(
        "  statement_faithfulness:{}",
        render_field(&tv["statement_faithfulness"], "verdict")
    );
    println!(
        "  human_review:          {}",
        render_field(&tv["human_review"], "review_state")
    );
    let ts = &tv["transfer_status"];
    if ts.is_string() {
        println!("  transfer_status:       absent");
    } else {
        println!(
            "  transfer_status:       {} record(s)",
            ts.as_array().map_or(0, Vec::len)
        );
    }
    println!(
        "  priority:              {}",
        if tv["priority"].is_string() {
            "absent".to_string()
        } else {
            "registered".to_string()
        }
    );
    println!("  (run with --json for the full vector)");
}

/// Render a trust field that is either the string `"absent"` or an
/// object with a named summary key.
fn render_field(v: &Value, key: &str) -> String {
    if v.is_string() {
        format!(" {}", v.as_str().unwrap_or("absent"))
    } else {
        format!(" {}", v[key].as_str().unwrap_or("present"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::events::{NULL_HASH, StateActor, StateTarget};

    fn ev(idx: usize, kind: &str, target: &str, payload: Value) -> StateEvent {
        StateEvent {
            schema: vela_protocol::events::EVENT_SCHEMA.to_string(),
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
        // Two independent support variables (the two event ids).
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
        // superseded => support poly zero => not T.
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
        // Refute variables survive a later supersession of support:
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
        // rho_Y kills history; only NEW events (new variables) can
        // re-support. Retraction never invents support (Theorem 2).
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
        // Only the assertion supports; the contested review is a
        // signal-plane fact (flags), not a polynomial contribution.
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
}
