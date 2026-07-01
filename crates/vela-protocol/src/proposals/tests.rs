use super::*;
use crate::bundle::{
    Assertion, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Entity, Evidence,
    Extraction, Flags, Provenance,
};
use crate::project;
use tempfile::TempDir;

fn finding(id: &str) -> FindingBundle {
    FindingBundle {
        id: id.to_string(),
        version: 1,
        previous_version: None,
        assertion: Assertion {
            text: format!("Test finding {id}"),
            assertion_type: "mechanism".to_string(),
            entities: vec![Entity {
                name: "LRP1".to_string(),
                entity_type: "protein".to_string(),
                identifiers: serde_json::Map::new(),
                canonical_id: None,
                candidates: Vec::new(),
                aliases: Vec::new(),
                resolution_provenance: None,
                resolution_confidence: 1.0,
                resolution_method: None,
                species_context: None,
                needs_review: false,
            }],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        },
        evidence: Evidence {
            evidence_type: "experimental".to_string(),
            model_system: String::new(),
            method: "manual".to_string(),
            replicated: false,
            replication_count: None,
            evidence_spans: Vec::new(),
        },
        conditions: Conditions {
            text: "mouse".to_string(),
            duration: None,
        },
        confidence: Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: 0.7,
            basis: "test".to_string(),
            method: ConfidenceMethod::ExpertJudgment,
            extraction_confidence: 1.0,
        },
        provenance: Provenance {
            source_type: "published_paper".to_string(),
            doi: None,
            url: None,
            title: "Test".to_string(),
            authors: Vec::new(),
            year: Some(2024),
            license: None,
            publisher: None,
            funders: Vec::new(),
            extraction: Extraction::default(),
            review: None,
        },
        flags: Flags {
            gap: false,
            negative_space: false,
            contested: false,
            retracted: false,
            declining: false,
            gravity_well: false,
            review_state: None,
            superseded: false,
            signature_threshold: None,
            jointly_accepted: false,
        },
        links: Vec::new(),
        annotations: Vec::new(),
        attachments: Vec::new(),
        created: "2026-04-23T00:00:00Z".to_string(),
        updated: None,

        access_tier: crate::access_tier::AccessTier::Public,
    }
}

#[test]
fn pending_review_proposal_does_not_mutate_frontier() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let proposal = new_proposal(
        "finding.review",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        },
        "reviewer:test",
        "human",
        "Mouse-only evidence",
        json!({"status": "contested"}),
        Vec::new(),
        Vec::new(),
    );
    create_or_apply(&path, proposal, false).unwrap();
    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.events.len(), 1); // genesis only (proposal pending)
    assert_eq!(loaded.proposals.len(), 1);
    assert!(!loaded.findings[0].flags.contested);
}

#[test]
fn applied_proposal_emits_event_and_stales_proof() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let mut frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    record_proof_export(
        &mut frontier,
        ProofPacketRecord {
            generated_at: "2026-04-23T00:00:00Z".to_string(),
            snapshot_hash: "a".repeat(64),
            event_log_hash: "b".repeat(64),
            packet_manifest_hash: "c".repeat(64),
        },
    );
    repo::save_to_path(&path, &frontier).unwrap();
    let proposal = new_proposal(
        "finding.review",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        },
        "reviewer:test",
        "human",
        "Mouse-only evidence",
        json!({"status": "contested"}),
        Vec::new(),
        Vec::new(),
    );
    create_or_apply(&path, proposal, true).unwrap();
    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.events.len(), 2); // genesis + applied
    assert!(loaded.findings[0].flags.contested);
    assert_eq!(loaded.proposals[0].status, "applied");
    assert_eq!(loaded.proof_state.latest_packet.status, "stale");
}

// ── v0.339: bounded trusted-reviewer-agent accept policy ──────────

fn full_replication_attestation() -> Value {
    json!({
        "independent_replications": 4,
        "all_replications_passed": true,
        "held_out_prompts": true,
        "second_model_confirmed": true,
        "cpu_verified": true,
        "min_effect_size": 0.62
    })
}

fn agent_proposal(reviewer_actor: &str, kind: &str, payload: Value) -> StateProposal {
    new_proposal(
        kind,
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_claim".to_string(),
        },
        reviewer_actor,
        "agent",
        "from experiment fleet",
        payload,
        Vec::new(),
        Vec::new(),
    )
}

#[test]
fn replication_attestation_passes_only_when_fully_verified() {
    assert!(replication_attestation_passes(
        &json!({"replication_attestation": full_replication_attestation()})
    ));
    // absent entirely
    assert!(!replication_attestation_passes(&json!({})));
    // too few independent replications
    let mut att = full_replication_attestation();
    att["independent_replications"] = json!(2);
    assert!(!replication_attestation_passes(
        &json!({"replication_attestation": att})
    ));
    // a replication failed
    let mut att = full_replication_attestation();
    att["all_replications_passed"] = json!(false);
    assert!(!replication_attestation_passes(
        &json!({"replication_attestation": att})
    ));
    // only confirmed on one model
    let mut att = full_replication_attestation();
    att["second_model_confirmed"] = json!(false);
    assert!(!replication_attestation_passes(
        &json!({"replication_attestation": att})
    ));
    // never CPU-verified (MPS can be silently wrong)
    let mut att = full_replication_attestation();
    att["cpu_verified"] = json!(false);
    assert!(!replication_attestation_passes(
        &json!({"replication_attestation": att})
    ));
    // marginal effect under threshold
    let mut att = full_replication_attestation();
    att["min_effect_size"] = json!(0.10);
    assert!(!replication_attestation_passes(
        &json!({"replication_attestation": att})
    ));
}

#[test]
fn human_reviewer_is_unaffected_by_agent_policy() {
    // The gate is a strict no-op for non-agent reviewers, even for a
    // destructive kind carrying no attestation.
    let p = agent_proposal("reviewer:will-blair", "finding.retract", json!({}));
    assert!(enforce_trusted_agent_accept_policy(&p, "reviewer:will-blair").is_ok());
}

#[test]
fn replicator_accepts_verified_claim_only() {
    let verified = agent_proposal(
        "agent:replicator",
        "finding.add",
        json!({"replication_attestation": full_replication_attestation()}),
    );
    assert!(enforce_trusted_agent_accept_policy(&verified, "agent:replicator").is_ok());

    // same role, no attestation -> denied
    let unverified = agent_proposal("agent:replicator", "finding.add", json!({}));
    assert!(enforce_trusted_agent_accept_policy(&unverified, "agent:replicator").is_err());

    // verified but destructive/lifecycle kind -> denied (needs a human)
    let destructive = agent_proposal(
        "agent:replicator",
        "finding.retract",
        json!({"replication_attestation": full_replication_attestation()}),
    );
    assert!(enforce_trusted_agent_accept_policy(&destructive, "agent:replicator").is_err());
}

#[test]
fn repair_agent_accepts_only_mechanical_kinds() {
    let span = agent_proposal("agent:repair", "finding.span_repair", json!({}));
    assert!(enforce_trusted_agent_accept_policy(&span, "agent:repair").is_ok());
    let locator = agent_proposal("agent:repair", "evidence_atom.locator_repair", json!({}));
    assert!(enforce_trusted_agent_accept_policy(&locator, "agent:repair").is_ok());
    // a claim is not a mechanical repair -> denied
    let claim = agent_proposal(
        "agent:repair",
        "finding.add",
        json!({"replication_attestation": full_replication_attestation()}),
    );
    assert!(enforce_trusted_agent_accept_policy(&claim, "agent:repair").is_err());
}

#[test]
fn untrusted_agent_reviewer_cannot_accept_even_verified_work() {
    let p = agent_proposal(
        "agent:literature-scout",
        "finding.add",
        json!({"replication_attestation": full_replication_attestation()}),
    );
    assert!(enforce_trusted_agent_accept_policy(&p, "agent:literature-scout").is_err());
}

#[test]
fn replicator_can_apply_verified_review_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let proposal = new_proposal(
        "finding.review",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        },
        "agent:replicator",
        "agent",
        "survived adversarial replication on held-out prompts + second model",
        json!({"status": "accepted", "replication_attestation": full_replication_attestation()}),
        Vec::new(),
        Vec::new(),
    );
    // apply = true accepts under the proposal actor (agent:replicator).
    create_or_apply(&path, proposal, true).unwrap();
    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.proposals[0].status, "applied");
    assert_eq!(
        loaded.proposals[0].reviewed_by.as_deref(),
        Some("agent:replicator")
    );
}

#[test]
fn replicator_cannot_apply_unverified_review_end_to_end() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let proposal = new_proposal(
        "finding.review",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        },
        "agent:replicator",
        "agent",
        "no replication evidence",
        json!({"status": "accepted"}),
        Vec::new(),
        Vec::new(),
    );
    let result = create_or_apply(&path, proposal, true);
    assert!(
        result.is_err(),
        "agent:replicator must not auto-apply a claim without a passing attestation"
    );
    // Fail-closed and atomic: the apply errors before the frontier is
    // saved, so nothing is persisted at all.
    let loaded = repo::load_from_path(&path).unwrap();
    assert!(loaded.proposals.is_empty());
    assert!(!loaded.findings[0].flags.contested);
}

#[test]
fn preview_reports_changed_objects_and_event_kind_without_mutation() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let proposal = new_proposal(
        "finding.review",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        },
        "reviewer:test",
        "human",
        "Mouse-only evidence",
        json!({"status": "contested"}),
        Vec::new(),
        Vec::new(),
    );
    let proposal_id = create_or_apply(&path, proposal, false).unwrap().proposal_id;

    let preview = preview_at_path(&path, &proposal_id, "reviewer:test").unwrap();

    assert_eq!(preview.changed_findings, vec!["vf_test"]);
    assert!(preview.changed_artifacts.is_empty());
    assert_eq!(preview.event_kinds, vec!["finding.reviewed"]);
    assert_eq!(
        preview.new_event_ids,
        vec![preview.applied_event_id.clone()]
    );
    assert_eq!(preview.events_delta, 1);
    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.events.len(), 1, "preview must not mutate events");
    assert_eq!(
        loaded.proposals[0].status, "pending_review",
        "preview must not accept the proposal"
    );
}

#[test]
fn pending_note_proposal_does_not_mutate_annotations() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let proposal = new_proposal(
        "finding.note",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        },
        "reviewer:test",
        "human",
        "Track mouse-only evidence",
        json!({"text": "Track mouse-only evidence"}),
        Vec::new(),
        Vec::new(),
    );
    create_or_apply(&path, proposal, false).unwrap();
    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.events.len(), 1); // genesis only
    assert_eq!(loaded.proposals.len(), 1);
    assert!(loaded.findings[0].annotations.is_empty());
    assert_eq!(loaded.proposals[0].kind, "finding.note");
}

#[test]
fn applied_note_emits_noted_event_and_stales_proof() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let mut frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    record_proof_export(
        &mut frontier,
        ProofPacketRecord {
            generated_at: "2026-04-23T00:00:00Z".to_string(),
            snapshot_hash: "a".repeat(64),
            event_log_hash: "b".repeat(64),
            packet_manifest_hash: "c".repeat(64),
        },
    );
    repo::save_to_path(&path, &frontier).unwrap();
    let proposal = new_proposal(
        "finding.note",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        },
        "reviewer:test",
        "human",
        "Track mouse-only evidence",
        json!({"text": "Track mouse-only evidence"}),
        Vec::new(),
        Vec::new(),
    );
    let result = create_or_apply(&path, proposal, true).unwrap();
    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.events.len(), 2); // genesis + finding.noted
    assert_eq!(loaded.events[1].kind, "finding.noted");
    assert_eq!(loaded.findings[0].annotations.len(), 1);
    assert_eq!(loaded.proposals[0].status, "applied");
    assert_eq!(
        loaded.proposals[0].applied_event_id,
        result.applied_event_id
    );
    assert_eq!(loaded.proof_state.latest_packet.status, "stale");
}

#[test]
fn retract_emits_per_dependent_cascade_events() {
    // Phase L: a retraction must emit one canonical
    // `finding.dependency_invalidated` event per affected dependent
    // in BFS depth order. Build a tiny dependency chain:
    //   src  <-supports- dep1  <-depends- dep2
    // and assert that retracting `src` produces three events:
    // [retracted(src), dep_invalidated(dep1, depth=1),
    //  dep_invalidated(dep2, depth=2)] all carrying the source's
    // canonical event ID as `upstream_event_id`.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let mut src = finding("vf_src");
    let mut dep1 = finding("vf_dep1");
    let mut dep2 = finding("vf_dep2");
    src.assertion.text = "src finding".into();
    dep1.assertion.text = "dep1 finding".into();
    dep2.assertion.text = "dep2 finding".into();
    // BFS edges flow from dependent → upstream via `target`.
    dep1.add_link("vf_src", "supports", "");
    dep2.add_link("vf_dep1", "depends", "");
    let frontier = project::assemble("test", vec![src, dep1, dep2], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();

    let proposal = new_proposal(
        "finding.retract",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_src".to_string(),
        },
        "reviewer:test",
        "human",
        "Source paper retracted by publisher",
        json!({}),
        Vec::new(),
        Vec::new(),
    );
    create_or_apply(&path, proposal, true).unwrap();
    let loaded = repo::load_from_path(&path).unwrap();

    // genesis + 1 source retract + 2 cascade events = 4 total.
    assert_eq!(loaded.events.len(), 4, "{:?}", loaded.events);
    let kinds: Vec<&str> = loaded.events.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds[0], "frontier.created");
    assert_eq!(kinds[1], "finding.retracted");
    assert_eq!(kinds[2], "finding.dependency_invalidated");
    assert_eq!(kinds[3], "finding.dependency_invalidated");

    let source_event_id = loaded.events[1].id.clone();
    let dep1_event = &loaded.events[2];
    let dep2_event = &loaded.events[3];
    assert_eq!(dep1_event.target.id, "vf_dep1");
    assert_eq!(dep2_event.target.id, "vf_dep2");
    assert_eq!(
        dep1_event
            .payload
            .get("upstream_event_id")
            .and_then(|v| v.as_str()),
        Some(source_event_id.as_str())
    );
    assert_eq!(
        dep1_event.payload.get("depth").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        dep2_event.payload.get("depth").and_then(|v| v.as_u64()),
        Some(2)
    );
    // Both dependents must end up contested in materialized state.
    let dep1 = loaded.findings.iter().find(|f| f.id == "vf_dep1").unwrap();
    let dep2 = loaded.findings.iter().find(|f| f.id == "vf_dep2").unwrap();
    assert!(dep1.flags.contested);
    assert!(dep2.flags.contested);
    let src = loaded.findings.iter().find(|f| f.id == "vf_src").unwrap();
    assert!(src.flags.retracted);
}

#[test]
fn proposal_id_is_content_addressed_independent_of_created_at() {
    // Phase P (v0.5): identical logical proposals constructed at different
    // times must produce the same `vpr_…`. This is the substrate property
    // that makes agent retries idempotent.
    let target = StateTarget {
        r#type: "finding".to_string(),
        id: "vf_test".to_string(),
    };
    let mut a = new_proposal(
        "finding.review",
        target.clone(),
        "reviewer:test",
        "human",
        "scope narrower than claim",
        json!({"status": "contested"}),
        Vec::new(),
        Vec::new(),
    );
    let mut b = new_proposal(
        "finding.review",
        target,
        "reviewer:test",
        "human",
        "scope narrower than claim",
        json!({"status": "contested"}),
        Vec::new(),
        Vec::new(),
    );
    // Force divergent timestamps; the IDs must still match.
    a.created_at = "2026-04-25T00:00:00Z".to_string();
    b.created_at = "2026-09-12T17:32:00Z".to_string();
    a.id = proposal_id(&a);
    b.id = proposal_id(&b);
    assert_eq!(a.id, b.id, "vpr_… must not depend on created_at");
}

#[test]
fn create_or_apply_is_idempotent_under_repeated_calls() {
    // Phase P: invoking create_or_apply twice with identical content must
    // not duplicate the proposal nor emit two events. The second call
    // returns the same proposal_id and applied_event_id as the first.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();

    let make = || {
        new_proposal(
            "finding.review",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "reviewer:test",
            "human",
            "agent retry test",
            json!({"status": "contested"}),
            Vec::new(),
            Vec::new(),
        )
    };

    let first = create_or_apply(&path, make(), true).unwrap();
    let second = create_or_apply(&path, make(), true).unwrap();

    assert_eq!(first.proposal_id, second.proposal_id);
    assert_eq!(first.applied_event_id, second.applied_event_id);

    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(
        loaded.proposals.len(),
        1,
        "second create_or_apply must not insert a duplicate proposal"
    );
    // genesis + 1 applied review event = 2; not 3.
    assert_eq!(
        loaded.events.len(),
        2,
        "second create_or_apply must not emit a duplicate event"
    );
}

#[test]
fn accepting_applied_proposal_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let proposal = new_proposal(
        "finding.review",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test".to_string(),
        },
        "reviewer:test",
        "human",
        "Mouse-only evidence",
        json!({"status": "contested"}),
        Vec::new(),
        Vec::new(),
    );
    let created = create_or_apply(&path, proposal, true).unwrap();
    let first_event = created.applied_event_id.clone().unwrap();
    let second_event =
        accept_at_path(&path, &created.proposal_id, "reviewer:test", "same").unwrap();
    assert_eq!(first_event, second_event);
}

#[test]
fn verifier_attach_accepts_and_derives_verified() {
    use crate::verifier_attachment::{
        AdversarialProbe, AttachmentDraft, AttachmentOutcome, MatchToClaim, ProbeKind, ProbeResult,
        VerifierAttachment, VerifierMethod, derive_gate_status,
    };
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_test")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let cd = crate::verifier_attachment::claim_digest("Test finding");
    let mk = |method: VerifierMethod, solver: &str, indep: Vec<String>| {
        VerifierAttachment::build(AttachmentDraft {
            target: "vf_test".to_string(),
            claim_digest: cd.clone(),
            verifier_method: method,
            solver_id: solver.to_string(),
            independent_of: indep,
            match_to_claim: MatchToClaim {
                matches: true,
                checker_actor: "opus".to_string(),
            },
            adversarial_probes: vec![AdversarialProbe {
                kind: ProbeKind::CounterexampleSearch,
                result: ProbeResult::Survived,
                note: String::new(),
            }],
            outcome: AttachmentOutcome::Passed,
            verifier_actor: "opus".to_string(),
            note: String::new(),
        })
        .unwrap()
    };
    let a1 = mk(VerifierMethod::ExactArithmeticRecompute, "solver-a", vec![]);
    let a2 = mk(
        VerifierMethod::LiteratureCorroboration,
        "solver-b",
        vec![a1.id.clone()],
    );
    for att in [&a1, &a2] {
        let proposal = new_proposal(
            "verifier.attach",
            StateTarget {
                r#type: "finding".to_string(),
                id: "vf_test".to_string(),
            },
            "reviewer:test",
            "human",
            "attach verifier evidence",
            json!({ "attachment": att }),
            Vec::new(),
            Vec::new(),
        );
        create_or_apply(&path, proposal, true).unwrap();
    }
    let reloaded = repo::load_from_path(&path).unwrap();
    assert_eq!(
        reloaded.verifier_attachments.len(),
        2,
        "both attachments stored in the sidecar collection"
    );
    // Per-finding gate status is DERIVED on read, never stored.
    let outcome = derive_gate_status(&cd, &reloaded.verifier_attachments);
    assert!(
        outcome.is_verified(),
        "two independent matched surviving-probe attachments must derive Verified"
    );
}

// ---- exact-lane proposal-level wrapper (Phase 1A) ----

fn admit_ready_fixture() -> (
    StateProposal,
    crate::bundle::FindingBundle,
    Vec<crate::verifier_attachment::VerifierAttachment>,
) {
    use crate::verifier_attachment::{
        AdversarialProbe, AttachmentDraft, AttachmentOutcome, MatchToClaim, MethodIntegrity,
        ProbeKind, ProbeResult, VerifierAttachment, VerifierMethod,
    };
    // A finding whose id is its real content-address (the drift-pin passes).
    let mut finding = crate::test_support::make_finding("vf_placeholder", 1.0, "measurement");
    finding.id =
        crate::bundle::FindingBundle::content_address(&finding.assertion, &finding.provenance);
    let cd = crate::verifier_attachment::claim_digest(&finding.assertion.text);
    // Build genuinely id-valid attachments: integrity and implementation_id
    // are set through the re-deriving builders (post-build field mutation
    // would leave the stored id no longer content-addressing the body, which
    // the gate's G4 id-integrity check now excludes). Independence is
    // one-directional (a2 names a1); a mutual 2-cycle is unconstructable.
    let mk = |method: VerifierMethod, solver: &str, impl_id: &str, independent_of: Vec<String>| {
        VerifierAttachment::build(AttachmentDraft {
            target: finding.id.clone(),
            claim_digest: cd.clone(),
            verifier_method: method,
            solver_id: solver.to_string(),
            independent_of,
            match_to_claim: MatchToClaim {
                matches: true,
                checker_actor: "checker".to_string(),
            },
            adversarial_probes: vec![AdversarialProbe {
                kind: ProbeKind::FormalismFidelity,
                result: ProbeResult::Survived,
                note: String::new(),
            }],
            outcome: AttachmentOutcome::Passed,
            verifier_actor: "verifier:vela-verify".to_string(),
            note: String::new(),
        })
        .unwrap()
        .with_method_integrity(MethodIntegrity::Sound)
        .unwrap()
        .with_implementation_id(impl_id)
        .unwrap()
    };
    // a1 is built first so its id is final before a2 references it.
    let a1 = mk(
        VerifierMethod::ComputationalSearch,
        "cp-sat",
        "impl-a",
        vec![],
    );
    let a2 = mk(
        VerifierMethod::ExactArithmeticRecompute,
        "pari",
        "impl-b",
        vec![a1.id.clone()],
    );
    let proposal = new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: finding.id.clone(),
        },
        "producer:campaign", // != every verifier_actor
        "agent",
        "campaign finding",
        json!({ "finding": finding.clone() }),
        Vec::new(),
        Vec::new(),
    );
    (proposal, finding, vec![a1, a2])
}

#[test]
fn exact_lane_wrapper_happy_path() {
    let (p, f, atts) = admit_ready_fixture();
    let (admit, reasons) =
        exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
    assert!(admit, "should admit, refused for: {reasons:?}");
}

#[test]
fn exact_lane_wrapper_rejects_wrong_kind() {
    let (mut p, f, atts) = admit_ready_fixture();
    p.kind = "verifier.attach".to_string();
    let (admit, reasons) =
        exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
    assert!(!admit);
    assert!(reasons.iter().any(|r| r.contains("finding.add")));
}

#[test]
fn exact_lane_wrapper_rejects_target_mismatch() {
    let (mut p, f, atts) = admit_ready_fixture();
    p.target.id = "vf_other".to_string();
    let (admit, _r) =
        exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
    assert!(!admit);
}

// ATTACK: the assertion text is edited after the id was minted.
#[test]
fn exact_lane_wrapper_rejects_content_address_drift() {
    let (p, mut f, atts) = admit_ready_fixture();
    f.assertion.text = "a tampered, inflated claim".to_string();
    let (admit, reasons) =
        exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
    assert!(!admit);
    assert!(reasons.iter().any(|r| r.contains("drift")));
}

#[test]
fn exact_lane_wrapper_rejects_retracted_or_superseded() {
    let (p, mut f, atts) = admit_ready_fixture();
    f.flags.retracted = true;
    let (admit, _r) =
        exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
    assert!(!admit);
    let (p2, mut f2, atts2) = admit_ready_fixture();
    f2.flags.superseded = true;
    let (admit2, _r2) =
        exact_lane_auto_admit(&p2, &f2, &atts2, &BTreeSet::new(), &BTreeSet::new(), false);
    assert!(!admit2);
}

#[test]
fn exact_lane_wrapper_rejects_synthetic_signal() {
    let (p, f, atts) = admit_ready_fixture();
    let synthetic = BTreeSet::from([f.id.clone()]);
    let (admit, reasons) =
        exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &synthetic, false);
    assert!(!admit);
    assert!(reasons.iter().any(|r| r.contains("synthetic")));
}

#[test]
fn exact_lane_wrapper_rejects_open_contradiction() {
    let (p, f, atts) = admit_ready_fixture();
    let contradictions = BTreeSet::from([f.id.clone()]);
    let (admit, reasons) =
        exact_lane_auto_admit(&p, &f, &atts, &contradictions, &BTreeSet::new(), false);
    assert!(!admit);
    assert!(reasons.iter().any(|r| r.contains("contradiction")));
}

// ATTACK: the producer is also a corroborator (same actor).
#[test]
fn exact_lane_wrapper_rejects_producer_equals_verifier() {
    let (p, f, mut atts) = admit_ready_fixture();
    atts[0].verifier_actor = "producer:campaign".to_string(); // == proposal.actor.id
    let (admit, reasons) =
        exact_lane_auto_admit(&p, &f, &atts, &BTreeSet::new(), &BTreeSet::new(), false);
    assert!(!admit);
    assert!(reasons.iter().any(|r| r.contains("corroborate itself")));
}

// The attachment predicate still gates: a single attachment fails.
#[test]
fn exact_lane_wrapper_delegates_to_attachment_predicate() {
    let (p, f, atts) = admit_ready_fixture();
    let single = vec![atts[0].clone()];
    let (admit, _r) =
        exact_lane_auto_admit(&p, &f, &single, &BTreeSet::new(), &BTreeSet::new(), false);
    assert!(!admit);
}

// floor_sufficient: the exact-lane FLOOR is the proof, so the lane admits
// on the floor alone (NO attachments) — the >=2-attachment bar is waived.
#[test]
fn exact_lane_wrapper_floor_sufficient_admits_without_attachments() {
    let (p, f, _atts) = admit_ready_fixture();
    let (admit, reasons) =
        exact_lane_auto_admit(&p, &f, &[], &BTreeSet::new(), &BTreeSet::new(), true);
    assert!(
        admit,
        "floor-sufficient should admit with no attachments: {reasons:?}"
    );
}

// ...but floor_sufficient never bypasses the proposal-level guards.
#[test]
fn exact_lane_wrapper_floor_sufficient_still_honors_guards() {
    let (p, mut f, _atts) = admit_ready_fixture();
    f.flags.retracted = true;
    let (admit, _r) = exact_lane_auto_admit(&p, &f, &[], &BTreeSet::new(), &BTreeSet::new(), true);
    assert!(
        !admit,
        "retracted finding refuses even when floor-sufficient"
    );

    let (p2, f2, _) = admit_ready_fixture();
    let synthetic = BTreeSet::from([f2.id.clone()]);
    let (admit2, _r2) = exact_lane_auto_admit(&p2, &f2, &[], &BTreeSet::new(), &synthetic, true);
    assert!(
        !admit2,
        "synthetic source refuses even when floor-sufficient"
    );
}

// ---- derive_trust_tier projection ----

fn policy_admit_event(proposal_id: &str) -> StateEvent {
    StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: "vev_test_admit".to_string(),
        kind: events::EVENT_KIND_POLICY_AUTO_ADMITTED.into(),
        target: StateTarget {
            r#type: "proposal".to_string(),
            id: proposal_id.to_string(),
        },
        actor: StateActor {
            id: "policy:exact-lane".to_string(),
            r#type: "agent".to_string(),
        },
        timestamp: "2026-06-19T00:00:00Z".to_string(),
        reason: "exact-lane auto-admit".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({ "proposal_id": proposal_id }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }
}

#[test]
fn trust_tier_accepted_when_landed() {
    let (_p, f, _a) = admit_ready_fixture();
    let frontier = project::assemble("t", vec![f.clone()], 0, 0, "t");
    assert_eq!(derive_trust_tier(&frontier, &f.id), TrustTier::Accepted);
}

#[test]
fn trust_tier_candidate_when_retracted() {
    let (_p, mut f, _a) = admit_ready_fixture();
    f.flags.retracted = true;
    let frontier = project::assemble("t", vec![f.clone()], 0, 0, "t");
    assert_eq!(derive_trust_tier(&frontier, &f.id), TrustTier::Candidate);
}

#[test]
fn trust_tier_machine_verified_for_pending_auto_admitted() {
    let (p, f, atts) = admit_ready_fixture();
    let mut frontier = project::assemble("t", vec![], 0, 0, "t");
    frontier.verifier_attachments = atts;
    frontier.events.push(policy_admit_event(&p.id));
    frontier.proposals.push(p);
    assert_eq!(
        derive_trust_tier(&frontier, &f.id),
        TrustTier::MachineVerified
    );
}

// A pending finding with passing attachments but no auto-admit marker is
// only schema_checked — never machine_verified.
#[test]
fn trust_tier_schema_checked_without_admit_marker() {
    let (p, f, atts) = admit_ready_fixture();
    let mut frontier = project::assemble("t", vec![], 0, 0, "t");
    frontier.verifier_attachments = atts;
    frontier.proposals.push(p); // pending, NO policy.auto_admitted event
    assert_eq!(
        derive_trust_tier(&frontier, &f.id),
        TrustTier::SchemaChecked
    );
}

#[test]
fn trust_tier_candidate_when_unknown() {
    let frontier = project::assemble("t", vec![], 0, 0, "t");
    assert_eq!(
        derive_trust_tier(&frontier, "vf_nothing"),
        TrustTier::Candidate
    );
}

#[test]
fn emit_policy_auto_admitted_is_idempotent_and_promotes_tier() {
    let (p, f, atts) = admit_ready_fixture();
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let mut frontier = project::assemble("t", vec![], 0, 0, "t");
    frontier.verifier_attachments = atts;
    frontier.proposals.push(p.clone());
    repo::save_to_path(&path, &frontier).unwrap();

    let att_ids: Vec<String> = frontier
        .verifier_attachments
        .iter()
        .map(|a| a.id.clone())
        .collect();
    let digest = crate::verifier_attachment::claim_digest(&f.assertion.text);

    let (id1, new1) = emit_policy_auto_admitted(
        &path,
        &p.id,
        &digest,
        &att_ids,
        "exact-lane.v1",
        "vela-verify@test",
    )
    .unwrap();
    assert!(new1, "first emit creates the event");

    // Idempotent: a second emit writes nothing and returns the same id.
    let (id2, new2) = emit_policy_auto_admitted(
        &path,
        &p.id,
        &digest,
        &att_ids,
        "exact-lane.v1",
        "vela-verify@test",
    )
    .unwrap();
    assert_eq!(id1, id2);
    assert!(!new2, "second emit is a no-op (idempotent)");

    let reloaded = repo::load_from_path(&path).unwrap();
    let count = reloaded
        .events
        .iter()
        .filter(|e| e.kind.as_str() == events::EVENT_KIND_POLICY_AUTO_ADMITTED)
        .count();
    assert_eq!(count, 1, "exactly one admit event after two applies");

    // The pending finding now projects to MachineVerified (live gate Verified).
    assert_eq!(
        derive_trust_tier(&reloaded, &f.id),
        TrustTier::MachineVerified
    );
}

#[test]
fn engine_gate_warns_then_strict_blocks_then_force_applies() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();

    // A sparse finding (no evidence span) introduces a review warning
    // on accept — the deterministic signal the Engine reads.
    let f = finding("vf_engine_gate");
    let proposal = new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: f.id.clone(),
        },
        "reviewer:test",
        "human",
        "add a sparse finding",
        json!({ "finding": f }),
        Vec::new(),
        Vec::new(),
    );
    let created = create_or_apply(&path, proposal, false).unwrap();
    let vpr = created.proposal_id.clone();

    // Prospective verdict: warns (new review warning), would not block.
    let preview = preview_engine_verdict(&path, &vpr).unwrap();
    assert_eq!(preview.status, "warn");
    assert!(!preview.new_warnings.is_empty());

    // Strict + no force: the new warning now gates. Nothing persists.
    let blocked = accept_at_path_engine(
        &path,
        &vpr,
        "reviewer:test",
        "strict",
        AcceptOptions {
            strict: true,
            force: false,
            signing_key: None,
            custody_verified: false,
            provenance: None,
        },
    );
    assert!(blocked.is_err(), "strict accept should be gated");
    let reloaded = repo::load_from_path(&path).unwrap();
    assert_eq!(
        reloaded
            .proposals
            .iter()
            .find(|p| p.id == vpr)
            .unwrap()
            .status,
        "pending_review",
        "a blocked accept must not change canonical state"
    );

    // Strict + force: applies, records the override, verdict is `forced`.
    let outcome = accept_at_path_engine(
        &path,
        &vpr,
        "reviewer:test",
        "strict",
        AcceptOptions {
            strict: true,
            force: true,
            signing_key: None,
            custody_verified: false,
            provenance: None,
        },
    )
    .unwrap();
    assert_eq!(outcome.verdict.status, "forced");
    assert!(outcome.verdict.forced);
    let after = repo::load_from_path(&path).unwrap();
    let applied = after.proposals.iter().find(|p| p.id == vpr).unwrap();
    assert_eq!(applied.status, "applied");
    assert!(
        applied
            .decision_reason
            .as_deref()
            .unwrap_or("")
            .contains("--force"),
        "the override must be recorded in the decision reason"
    );
}

// Build a frontier on disk seeded with `n` pending `finding.add`
// proposals (sparse findings → review warnings on accept, not blocking),
// returning the path and the proposal ids in creation order.
fn frontier_with_pending_adds(n: usize) -> (TempDir, std::path::PathBuf, Vec<String>) {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("batch-test", vec![], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let mut ids = Vec::new();
    for i in 0..n {
        let f = finding(&format!("vf_batch_{i}"));
        let proposal = new_proposal(
            "finding.add",
            StateTarget {
                r#type: "finding".to_string(),
                id: f.id.clone(),
            },
            "reviewer:test",
            "human",
            "batch add",
            json!({ "finding": f }),
            Vec::new(),
            Vec::new(),
        );
        ids.push(create_or_apply(&path, proposal, false).unwrap().proposal_id);
    }
    (tmp, path, ids)
}

#[test]
fn accept_batch_applies_all_in_one_pass() {
    let (_tmp, path, ids) = frontier_with_pending_adds(3);
    let report = accept_batch_at_path(
        &path,
        &ids,
        "reviewer:test",
        "batch accept",
        AcceptOptions::default(),
        false,
    )
    .unwrap();

    // Non-strict: sparse-finding warnings do not block; the batch lands.
    assert!(!report.gated);
    assert_eq!(report.accepted_proposal_ids.len(), 3);
    assert_eq!(report.event_ids.len(), 3);
    assert_eq!(report.failed.len(), 0);

    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.findings.len(), 3, "all three findings materialized");
    assert!(
        loaded.proposals.iter().all(|p| p.status == "applied"),
        "every selected proposal is applied"
    );
}

#[test]
fn accept_batch_dry_run_persists_nothing() {
    let (_tmp, path, ids) = frontier_with_pending_adds(3);
    let report = accept_batch_at_path(
        &path,
        &ids,
        "reviewer:test",
        "preview",
        AcceptOptions::default(),
        true, // dry_run
    )
    .unwrap();
    assert!(report.dry_run);
    assert!(!report.gated);
    assert_eq!(
        report.accepted_proposal_ids.len(),
        3,
        "reports what would apply"
    );

    // Nothing was written: the proposals are still pending, no findings.
    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.findings.len(), 0);
    assert!(
        loaded
            .proposals
            .iter()
            .all(|p| p.status == "pending_review")
    );
}

#[test]
fn accept_batch_strict_gate_blocks_whole_batch() {
    let (_tmp, path, ids) = frontier_with_pending_adds(3);
    // Strict: the new review warnings now gate the aggregate. The batch
    // is refused as a whole and nothing is persisted.
    let report = accept_batch_at_path(
        &path,
        &ids,
        "reviewer:test",
        "strict batch",
        AcceptOptions {
            strict: true,
            force: false,
            signing_key: None,
            custody_verified: false,
            provenance: None,
        },
        false,
    )
    .unwrap();
    assert!(report.gated, "strict batch with new warnings must be gated");
    assert_eq!(report.verdict.status, "blocked");

    let loaded = repo::load_from_path(&path).unwrap();
    assert_eq!(loaded.findings.len(), 0, "a blocked batch persists nothing");
    assert!(
        loaded
            .proposals
            .iter()
            .all(|p| p.status == "pending_review")
    );

    // Strict + force: the same batch now applies in one pass, audited.
    let forced = accept_batch_at_path(
        &path,
        &ids,
        "reviewer:test",
        "strict batch",
        AcceptOptions {
            strict: true,
            force: true,
            signing_key: None,
            custody_verified: false,
            provenance: None,
        },
        false,
    )
    .unwrap();
    assert!(!forced.gated);
    assert_eq!(forced.verdict.status, "forced");
    let after = repo::load_from_path(&path).unwrap();
    assert_eq!(after.findings.len(), 3);
    assert!(after.proposals.iter().all(|p| {
        p.decision_reason
            .as_deref()
            .unwrap_or("")
            .contains("--force")
    }));
}

#[test]
fn math_profile_skips_study_design_checks_for_theoretical_findings() {
    use crate::evidence_ci::{self, EvidenceCiClassification};

    fn warn_ids(report: &evidence_ci::EvidenceCiReport) -> std::collections::BTreeSet<String> {
        report
            .checks
            .iter()
            .filter(|c| c.classification == EvidenceCiClassification::ReviewWarning)
            .map(|c| c.id.clone())
            .collect()
    }
    const STUDY_DESIGN: &[&str] = &[
        "condition.population",
        "condition.comparator_or_baseline",
        "condition.endpoint",
        "trial.registry_reference",
    ];

    // A theoretical claim (Erdős-style open question, no empirical signal)
    // must NOT raise the clinical study-design warnings — they are a
    // category error on a formal claim.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let mut theo = finding("vf_theo");
    theo.assertion.assertion_type = "open_question".to_string();
    theo.evidence.evidence_type = "theoretical".to_string();
    theo.conditions.text = "Erdős problem statement".to_string();
    let frontier = project::assemble("math", vec![theo], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let report = evidence_ci::run_project(&repo::load_from_path(&path).unwrap(), &path);
    let theo_warns = warn_ids(&report);
    for id in STUDY_DESIGN {
        assert!(
            !theo_warns.contains(*id),
            "theoretical finding should not warn on {id}, got {theo_warns:?}"
        );
    }

    // The default empirical finding (mechanism / experimental, in_vivo)
    // still gets the study-design checks — the gate stays meaningful where
    // a study-design dimension actually exists.
    let tmp2 = TempDir::new().unwrap();
    let path2 = tmp2.path().join("frontier.json");
    let emp = finding("vf_emp"); // assertion mechanism, evidence experimental
    let frontier2 = project::assemble("bio", vec![emp], 0, 0, "test");
    repo::save_to_path(&path2, &frontier2).unwrap();
    let report2 = evidence_ci::run_project(&repo::load_from_path(&path2).unwrap(), &path2);
    let emp_warns = warn_ids(&report2);
    assert!(
        emp_warns.contains("condition.comparator_or_baseline")
            || emp_warns.contains("condition.endpoint"),
        "empirical finding should still raise a study-design warning, got {emp_warns:?}"
    );
}

#[test]
fn v0_13_apply_materializes_source_records_inline() {
    // Pre-v0.13: vela check --strict on a CLI-built frontier flagged
    // `missing_source_record` because source_records weren't populated
    // until vela normalize --write — and normalize refuses on event-ful
    // frontiers. v0.13 materializes inline at apply time so source_records
    // grow in lockstep with findings.
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let mut frontier = project::assemble("test", vec![], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    // Add a finding via the standard finding.add proposal flow.
    let f = finding("vf_v013_inline_src");
    let proposal = new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: f.id.clone(),
        },
        "reviewer:test",
        "human",
        "Manual finding for v0.13 source-record materialization test",
        json!({"finding": f}),
        Vec::new(),
        Vec::new(),
    );
    create_or_apply(&path, proposal, true).unwrap();
    let loaded = repo::load_from_path(&path).unwrap();
    // Source records, evidence atoms, and condition records should all
    // be materialized — without any explicit normalize call.
    assert!(
        !loaded.sources.is_empty(),
        "v0.13: source_records should materialize inline at apply time"
    );
    assert!(
        !loaded.evidence_atoms.is_empty(),
        "v0.13: evidence_atoms should materialize inline at apply time"
    );
    assert!(
        !loaded.condition_records.is_empty(),
        "v0.13: condition_records should materialize inline at apply time"
    );
    // Sanity: stats reflect the new source registry.
    assert_eq!(loaded.stats.source_count, loaded.sources.len());
    // Suppress unused-mut warning when frontier isn't reused below.
    let _ = &mut frontier;
}

fn make_supersede_payload(old_id: &str, new_text: &str) -> (FindingBundle, Value) {
    let mut new_finding = finding("vf_supersede_new");
    new_finding.assertion.text = new_text.to_string();
    // Re-derive id from the new assertion text + provenance. For the
    // test we just hand-pick a distinct id; the real CLI uses
    // `build_finding_bundle` which content-addresses correctly.
    new_finding.id = format!(
        "vf_{:0>16}",
        old_id
            .bytes()
            .fold(0u64, |acc, b| acc.wrapping_add(b as u64))
    );
    let payload = json!({"new_finding": new_finding.clone()});
    (new_finding, payload)
}

#[test]
fn v0_14_supersede_creates_new_finding_and_marks_old() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let mut frontier = project::assemble("test", vec![finding("vf_old")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let (new_finding, payload) = make_supersede_payload("vf_old", "Newer claim");
    let proposal = new_proposal(
        "finding.supersede",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_old".to_string(),
        },
        "reviewer:test",
        "human",
        "Newer evidence updates the wording",
        payload,
        Vec::new(),
        Vec::new(),
    );
    let result = create_or_apply(&path, proposal, true).unwrap();
    assert!(result.applied_event_id.is_some());
    let loaded = repo::load_from_path(&path).unwrap();
    // Old finding now flagged superseded.
    let old = loaded.findings.iter().find(|f| f.id == "vf_old").unwrap();
    assert!(
        old.flags.superseded,
        "old finding should be flagged superseded"
    );
    // New finding present, with auto-injected supersedes link back to old.
    let new_f = loaded
        .findings
        .iter()
        .find(|f| f.id == new_finding.id)
        .expect("new finding should be in frontier");
    assert!(
        new_f
            .links
            .iter()
            .any(|l| l.target == "vf_old" && l.link_type == "supersedes"),
        "new finding should have an auto-injected supersedes link to old finding"
    );
    // Event with kind finding.superseded targeting old, payload carries new_finding_id.
    let supersede_event = loaded
        .events
        .iter()
        .find(|e| e.kind == "finding.superseded")
        .expect("a finding.superseded event should be emitted");
    assert_eq!(supersede_event.target.id, "vf_old");
    assert_eq!(
        supersede_event.payload["new_finding_id"].as_str(),
        Some(new_finding.id.as_str())
    );
    // suppress unused warning
    let _ = &mut frontier;
}

#[test]
fn v0_14_supersede_refuses_already_superseded() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let mut old = finding("vf_already_done");
    old.flags.superseded = true;
    let frontier = project::assemble("test", vec![old], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    let (_, payload) = make_supersede_payload("vf_already_done", "Newer wording");
    let proposal = new_proposal(
        "finding.supersede",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_already_done".to_string(),
        },
        "reviewer:test",
        "human",
        "Attempt to double-supersede",
        payload,
        Vec::new(),
        Vec::new(),
    );
    let result = create_or_apply(&path, proposal, true);
    assert!(
        result.is_err(),
        "double-supersede should be refused; got {result:?}"
    );
}

#[test]
fn v0_14_supersede_refuses_same_content_address() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("frontier.json");
    let frontier = project::assemble("test", vec![finding("vf_same")], 0, 0, "test");
    repo::save_to_path(&path, &frontier).unwrap();
    // new_finding.id == target.id should be refused at validate-time.
    let mut new_finding = finding("vf_same");
    new_finding.assertion.text = "Different text but reused id".to_string();
    let proposal = new_proposal(
        "finding.supersede",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_same".to_string(),
        },
        "reviewer:test",
        "human",
        "Same id, should fail",
        json!({"new_finding": new_finding}),
        Vec::new(),
        Vec::new(),
    );
    let result = create_or_apply(&path, proposal, true);
    assert!(
        result.is_err(),
        "supersede with same content address should be refused; got {result:?}"
    );
}

/// v0.22 byte-stability: a proposal with `agent_run = None`
/// must serialize without an `agent_run` field, so existing
/// frontiers (none of which have agent_run today) round-trip
/// byte-identically. The whole substrate guarantee depends on
/// canonical-JSON not silently gaining new keys.
#[test]
fn agent_run_none_skips_serialization() {
    let p = new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test0000000000".to_string(),
        },
        "reviewer:will-blair",
        "human",
        "test",
        json!({}),
        Vec::new(),
        Vec::new(),
    );
    let bytes = canonical::to_canonical_bytes(&p).unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(
        !s.contains("agent_run"),
        "proposal without agent_run leaked the field into canonical JSON: {s}"
    );
}

/// And when `agent_run` *is* set, the same proposal id is
/// produced regardless — `proposal_id`'s preimage explicitly
/// excludes agent_run, so attaching provenance never changes
/// the content address.
#[test]
fn agent_run_does_not_change_proposal_id() {
    let bare = new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test0000000000".to_string(),
        },
        "agent:literature-scout",
        "agent",
        "scout extracted this from paper_014",
        json!({}),
        vec!["src_paper_014".to_string()],
        Vec::new(),
    );
    let id_bare = bare.id.clone();

    let mut with_run = bare.clone();
    with_run.agent_run = Some(AgentRun {
        agent: "literature-scout".to_string(),
        model: "claude-opus-4-7".to_string(),
        run_id: "vrun_abc1234567890def".to_string(),
        started_at: "2026-04-26T01:23:45Z".to_string(),
        finished_at: Some("2026-04-26T01:24:10Z".to_string()),
        context: BTreeMap::from([
            ("input_folder".to_string(), "./papers".to_string()),
            ("pdf_count".to_string(), "12".to_string()),
        ]),
        tool_calls: Vec::new(),
        permissions: None,
    });
    let id_with_run = proposal_id(&with_run);
    assert_eq!(
        id_bare, id_with_run,
        "agent_run leaked into proposal_id preimage"
    );
}

/// v0.49 byte-stability: tool_calls and permissions on AgentRun
/// must skip serialization when empty/None, so existing frontiers
/// (none of which carry these fields today) round-trip byte-
/// identically through canonical JSON. Same invariant as
/// agent_run itself in v0.22.
#[test]
fn agent_run_empty_tool_calls_and_permissions_skip_serialization() {
    let p = new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test0000000000".to_string(),
        },
        "agent:scout",
        "agent",
        "test",
        json!({}),
        Vec::new(),
        Vec::new(),
    );
    let mut with_run = p.clone();
    with_run.agent_run = Some(AgentRun {
        agent: "scout".to_string(),
        model: "claude-opus-4-7".to_string(),
        run_id: "vrun_x".to_string(),
        started_at: "2026-04-26T01:00:00Z".to_string(),
        finished_at: None,
        context: BTreeMap::new(),
        tool_calls: Vec::new(),
        permissions: None,
    });
    let bytes = canonical::to_canonical_bytes(&with_run).unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(
        !s.contains("tool_calls"),
        "empty tool_calls leaked into canonical JSON: {s}"
    );
    assert!(
        !s.contains("permissions"),
        "empty permissions leaked into canonical JSON: {s}"
    );
}

/// v0.49: when populated, tool_calls and permissions DO serialize
/// — this is the round-trip we want for new agent runs that
/// actually carry tool traces.
#[test]
fn agent_run_populated_tool_calls_and_permissions_roundtrip() {
    let mut p = new_proposal(
        "finding.add",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_test0000000000".to_string(),
        },
        "agent:scout",
        "agent",
        "test",
        json!({}),
        Vec::new(),
        Vec::new(),
    );
    p.agent_run = Some(AgentRun {
        agent: "scout".to_string(),
        model: "claude-opus-4-7".to_string(),
        run_id: "vrun_x".to_string(),
        started_at: "2026-04-26T01:00:00Z".to_string(),
        finished_at: None,
        context: BTreeMap::new(),
        tool_calls: vec![
            ToolCallTrace {
                tool: "pubmed_search".to_string(),
                input_sha256: "a".repeat(64),
                output_sha256: Some("b".repeat(64)),
                at: "2026-04-26T01:00:05Z".to_string(),
                duration_ms: Some(842),
                status: "ok".to_string(),
                error_message: String::new(),
            },
            // v0.49: a failed tool call with an explanatory
            // error_message — the field a reviewer needs to audit
            // what went wrong without re-running the agent.
            ToolCallTrace {
                tool: "arxiv_fetch".to_string(),
                input_sha256: "c".repeat(64),
                output_sha256: None,
                at: "2026-04-26T01:00:18Z".to_string(),
                duration_ms: Some(1200),
                status: "error".to_string(),
                error_message: "HTTP 503 from arxiv.org; retry budget exhausted".to_string(),
            },
        ],
        permissions: Some(PermissionState {
            data_access: vec!["pubmed:".to_string(), "frontier:vfr_bd91".to_string()],
            tool_access: vec!["pubmed_search".to_string(), "arxiv_fetch".to_string()],
            note: "read-only access to BBB Flagship".to_string(),
        }),
    });
    let bytes = canonical::to_canonical_bytes(&p).unwrap();
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).expect("canonical bytes round-trip");
    assert_eq!(
        json["agent_run"]["tool_calls"][0]["tool"], "pubmed_search",
        "tool_calls did not survive the round trip: {json}"
    );
    assert_eq!(
        json["agent_run"]["permissions"]["data_access"][0], "pubmed:",
        "permissions did not survive the round trip: {json}"
    );
    // v0.49: a failed tool call with error_message carries the
    // explanation through canonical JSON. A reviewer can audit
    // exactly what failed without rerunning the agent.
    assert_eq!(
        json["agent_run"]["tool_calls"][1]["status"], "error",
        "failed tool call status did not survive: {json}"
    );
    assert_eq!(
        json["agent_run"]["tool_calls"][1]["error_message"],
        "HTTP 503 from arxiv.org; retry budget exhausted",
        "error_message did not survive the round trip: {json}"
    );
    // ...and successful calls still don't leak an empty
    // error_message into canonical bytes.
    let raw = std::str::from_utf8(&bytes).unwrap();
    let okay_call_block_end = raw.find("pubmed_search").unwrap();
    let until_first_call = &raw[..okay_call_block_end + 200];
    assert!(
        !until_first_call.contains("\"error_message\":\"\""),
        "successful tool call leaked an empty error_message: {until_first_call}"
    );
}

// ── v0.128: protocol-side accept authority gate ──────────────────
//
// These exercise `authorize_proposal_accept` — the per-reviewer-key
// predicate the public accept boundary runs *before* the strict
// canonical accept. They prove the gate the open `publish_entry`
// path lacks: a reviewer accept must resolve to a registered,
// non-revoked, reviewer-authority actor whose key signed the exact
// (action, vfr_id, proposal_id, reviewer_id, reason) preimage.

use crate::sign::ActorRecord;
use ed25519_dalek::SigningKey;

fn accept_keypair() -> SigningKey {
    use rand::rngs::OsRng;
    SigningKey::generate(&mut OsRng)
}

fn accept_actor(id: &str, pubkey_hex: &str) -> ActorRecord {
    ActorRecord {
        id: id.to_string(),
        public_key: pubkey_hex.to_string(),
        algorithm: "ed25519".to_string(),
        created_at: "2026-05-01T00:00:00Z".to_string(),
        tier: None,
        orcid: None,
        access_clearance: None,
        revoked_at: None,
        revoked_reason: None,
    }
}

/// A frontier carrying one pending proposal targeting a finding,
/// plus the actors passed in. Returns (project, proposal).
fn frontier_with_proposal(actors: Vec<ActorRecord>) -> (Project, StateProposal) {
    let mut project =
        project::assemble("accept-gate", vec![finding("vf_target0000000")], 0, 0, "t");
    let proposal = new_proposal(
        "finding.review",
        StateTarget {
            r#type: "finding".to_string(),
            id: "vf_target0000000".to_string(),
        },
        "agent:literature-scout",
        "agent",
        "Mouse-only evidence; recommend contested",
        json!({"status": "contested"}),
        Vec::new(),
        Vec::new(),
    );
    project.proposals.push(proposal.clone());
    project.actors = actors;
    (project, proposal)
}

const VFR: &str = "vfr_accept_gate_fixture";
const NOW: &str = "2026-05-29T00:00:00Z";

/// Sign the canonical accept preimage for `reviewer_id` with `key`,
/// binding the head of `project` (ADR 0001 Phase 0d) so it matches what
/// `authorize_proposal_accept` rebuilds from the same pre-accept project.
fn sign_accept(
    key: &SigningKey,
    project: &Project,
    vfr_id: &str,
    proposal_id: &str,
    reviewer_id: &str,
    reason: &str,
) -> String {
    let parent = crate::events::event_log_hash(&project.events);
    let bytes = accept_preimage_bytes(vfr_id, proposal_id, reviewer_id, reason, &parent).unwrap();
    hex::encode(crate::sign::sign_bytes(key, &bytes))
}

#[test]
fn authorize_accept_valid_reviewer_passes() {
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let (project, proposal) =
        frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
    let reason = "Verified; mouse-only scope is accurate";
    let sig = sign_accept(
        &key,
        &project,
        VFR,
        &proposal.id,
        "reviewer:will-blair",
        reason,
    );

    let auth =
        authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW).unwrap();
    assert_eq!(auth.actor.id, "reviewer:will-blair");
}

#[test]
fn authorize_accept_against_stale_head_rejected() {
    // ADR 0001 Phase 0d: an accept signed against head H is rejected once
    // the head moves to H' (a captured accept replayed onto a re-ordered
    // or extended history). The verifier recomputes the parent from its
    // own pre-accept project, so the bound head no longer matches and the
    // signature fails. This is the property that closes the accept-replay
    // hole the ADR identified.
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let (mut project, proposal) =
        frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
    let reason = "Verified";
    // Sign binding the CURRENT head.
    let sig = sign_accept(
        &key,
        &project,
        VFR,
        &proposal.id,
        "reviewer:will-blair",
        reason,
    );
    // Valid against the head it was signed over.
    assert!(
        authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW).is_ok()
    );
    // The head moves: another event lands. The same signature now binds a
    // stale head and must be rejected.
    project.events.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: "vev_headmover00000".to_string(),
        kind: "note.added".into(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: "vf_target0000000".to_string(),
        },
        actor: StateActor {
            id: "reviewer:will-blair".to_string(),
            r#type: "human".to_string(),
        },
        timestamp: "2026-05-28T00:00:00Z".to_string(),
        reason: "moves the head".to_string(),
        before_hash: String::new(),
        after_hash: String::new(),
        payload: serde_json::Value::Null,
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });
    let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
        .unwrap_err();
    assert!(
        err.contains("does not verify"),
        "stale-head accept must be rejected, got: {err}"
    );
}

#[test]
fn authorize_accept_forged_signature_rejected() {
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let (project, proposal) =
        frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
    let reason = "Verified";
    // Garbage signature of the right length but not over the preimage.
    let forged = "00".repeat(64);

    let err = authorize_proposal_accept(&project, VFR, &pubkey, &forged, &proposal, reason, NOW)
        .unwrap_err();
    assert!(err.contains("does not verify"), "unexpected error: {err}");
}

#[test]
fn authorize_accept_signature_over_other_reason_rejected() {
    // A captured signature for reason A cannot be replayed under B —
    // reason is bound into the preimage.
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let (project, proposal) =
        frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
    let sig_for_a = sign_accept(
        &key,
        &project,
        VFR,
        &proposal.id,
        "reviewer:will-blair",
        "reason A",
    );

    let err = authorize_proposal_accept(
        &project, VFR, &pubkey, &sig_for_a, &proposal, "reason B", NOW,
    )
    .unwrap_err();
    assert!(err.contains("does not verify"), "unexpected error: {err}");
}

#[test]
fn authorize_accept_signature_for_other_proposal_rejected() {
    // A signature bound to a different proposal id must not verify
    // against this proposal — proposal_id is in the preimage.
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let (project, proposal) =
        frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
    let reason = "Verified";
    let sig_other = sign_accept(
        &key,
        &project,
        VFR,
        "vpr_some_other_proposal",
        "reviewer:will-blair",
        reason,
    );

    let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig_other, &proposal, reason, NOW)
        .unwrap_err();
    assert!(err.contains("does not verify"), "unexpected error: {err}");
}

#[test]
fn authorize_accept_unregistered_signer_rejected() {
    // The frontier registers reviewer:will-blair, but the signer
    // presents a different (valid) key that is not on the frontier.
    let registered_key = accept_keypair();
    let registered_pubkey = crate::sign::pubkey_hex(&registered_key);
    let (project, proposal) = frontier_with_proposal(vec![accept_actor(
        "reviewer:will-blair",
        &registered_pubkey,
    )]);

    let stranger = accept_keypair();
    let stranger_pubkey = crate::sign::pubkey_hex(&stranger);
    let reason = "Verified";
    // Even a cryptographically valid self-signature does not help:
    // the key resolves to no registered actor.
    let sig = sign_accept(
        &stranger,
        &project,
        VFR,
        &proposal.id,
        "reviewer:will-blair",
        reason,
    );

    let err = authorize_proposal_accept(
        &project,
        VFR,
        &stranger_pubkey,
        &sig,
        &proposal,
        reason,
        NOW,
    )
    .unwrap_err();
    assert!(
        err.contains("not a registered actor"),
        "unexpected error: {err}"
    );
}

#[test]
fn authorize_accept_revoked_key_rejected() {
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let mut actor = accept_actor("reviewer:will-blair", &pubkey);
    actor.revoked_at = Some("2026-05-10T00:00:00Z".to_string());
    actor.revoked_reason = Some("key rotated".to_string());
    let (project, proposal) = frontier_with_proposal(vec![actor]);
    let reason = "Verified";
    let sig = sign_accept(
        &key,
        &project,
        VFR,
        &proposal.id,
        "reviewer:will-blair",
        reason,
    );

    // NOW (2026-05-29) is after revoked_at → rejected even though
    // the signature itself is valid.
    let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
        .unwrap_err();
    assert!(err.contains("revoked"), "unexpected error: {err}");
}

#[test]
fn authorize_accept_non_reviewer_namespace_rejected() {
    // A registered, non-revoked actor in the agent: namespace with a
    // valid signature is still refused: it lacks reviewer authority.
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let (project, proposal) =
        frontier_with_proposal(vec![accept_actor("agent:replicator", &pubkey)]);
    let reason = "Verified";
    let sig = sign_accept(
        &key,
        &project,
        VFR,
        &proposal.id,
        "agent:replicator",
        reason,
    );

    let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
        .unwrap_err();
    assert!(
        err.contains("does not carry reviewer authority"),
        "unexpected error: {err}"
    );
}

#[test]
fn authorize_accept_auto_notes_tier_does_not_grant_authority() {
    // The v0.6 write tier (auto-notes) never confers accept
    // authority: the id is still outside the reviewer: namespace.
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let mut actor = accept_actor("agent:notes-compiler", &pubkey);
    actor.tier = Some("auto-notes".to_string());
    let (project, proposal) = frontier_with_proposal(vec![actor]);
    let reason = "Verified";
    let sig = sign_accept(
        &key,
        &project,
        VFR,
        &proposal.id,
        "agent:notes-compiler",
        reason,
    );

    let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
        .unwrap_err();
    assert!(
        err.contains("does not carry reviewer authority"),
        "unexpected error: {err}"
    );
}

#[test]
fn authorize_accept_placeholder_reviewer_rejected() {
    // A "reviewer:" prefix is necessary but not sufficient — a
    // placeholder reviewer id is refused.
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    // "reviewer" (bare) and "local-*" are placeholders.
    let (project, proposal) = frontier_with_proposal(vec![accept_actor("local-reviewer", &pubkey)]);
    let reason = "Verified";
    let sig = sign_accept(&key, &project, VFR, &proposal.id, "local-reviewer", reason);
    let err = authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, reason, NOW)
        .unwrap_err();
    assert!(
        err.contains("does not carry reviewer authority"),
        "unexpected error: {err}"
    );
}

#[test]
fn authorize_accept_empty_reason_rejected() {
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let (project, proposal) =
        frontier_with_proposal(vec![accept_actor("reviewer:will-blair", &pubkey)]);
    let sig = sign_accept(
        &key,
        &project,
        VFR,
        &proposal.id,
        "reviewer:will-blair",
        "   ",
    );
    let err =
        authorize_proposal_accept(&project, VFR, &pubkey, &sig, &proposal, "   ", NOW).unwrap_err();
    assert!(err.contains("Decision reason"), "unexpected error: {err}");
}

#[test]
fn authorize_accept_resolves_pubkey_case_insensitively() {
    // The registry hex and the wire hex differ only in case; the
    // resolve must match (Ed25519 hex is case-insensitive).
    let key = accept_keypair();
    let pubkey = crate::sign::pubkey_hex(&key);
    let (project, proposal) = frontier_with_proposal(vec![accept_actor(
        "reviewer:will-blair",
        &pubkey.to_uppercase(),
    )]);
    let reason = "Verified";
    let sig = sign_accept(
        &key,
        &project,
        VFR,
        &proposal.id,
        "reviewer:will-blair",
        reason,
    );
    let auth = authorize_proposal_accept(
        &project, VFR, &pubkey, // lowercase on the wire
        &sig, &proposal, reason, NOW,
    )
    .unwrap();
    assert_eq!(auth.actor.id, "reviewer:will-blair");
}

// ── Signed review events + decision parity ────────────────────────

fn review_events_for<'a>(project: &'a Project, proposal_id: &str) -> Vec<&'a StateEvent> {
    project
        .events
        .iter()
        .filter(|e| {
            e.target.r#type == "proposal"
                && e.target.id == proposal_id
                && e.kind.as_str().starts_with("review.")
        })
        .collect()
}

#[test]
fn reject_emits_signed_review_event_and_parity_holds() {
    let key = accept_keypair();
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let (mut project, proposal) =
        frontier_with_proposal(vec![accept_actor("reviewer:will", &pubkey)]);
    reject_proposal_in_frontier_signed(
        &mut project,
        &proposal.id,
        "reviewer:will",
        "automated draft, not adjudicated",
        Some(&key),
        false,
    )
    .unwrap();

    // The decision is now a signed, log-resident event — the thing a
    // reject used to lack entirely.
    let reviews = review_events_for(&project, &proposal.id);
    assert_eq!(reviews.len(), 1, "exactly one review event");
    let ev = reviews[0];
    assert_eq!(ev.kind, events::EVENT_KIND_REVIEW_REJECTED);
    assert_eq!(ev.target.r#type, "proposal");
    assert!(ev.signature.is_some(), "review.rejected must be signed");
    assert!(
        crate::sign::verify_event_signature(ev, &pubkey).unwrap(),
        "signature must verify under the reviewer's registered key"
    );
    // Side-table: chain-transparent.
    assert_eq!(ev.before_hash, NULL_HASH);
    assert_eq!(ev.after_hash, NULL_HASH);
    // Stored status agrees with the log.
    let stored = &project
        .proposals
        .iter()
        .find(|p| p.id == proposal.id)
        .unwrap()
        .status;
    assert_eq!(stored, "rejected");
    assert!(
        verify_proposal_decision_parity(&project).is_empty(),
        "parity must hold after a signed reject"
    );
}

#[test]
fn reject_requires_key_for_keyed_reviewer() {
    let key = accept_keypair();
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let (mut project, proposal) =
        frontier_with_proposal(vec![accept_actor("reviewer:will", &pubkey)]);
    // No key supplied → an agent cannot reject under a keyed identity.
    let err = reject_proposal_in_frontier_signed(
        &mut project,
        &proposal.id,
        "reviewer:will",
        "no key here",
        None,
        false,
    )
    .unwrap_err();
    assert!(
        err.contains("require") && err.contains("key"),
        "expected key-custody error, got: {err}"
    );
    // And nothing was recorded.
    assert!(review_events_for(&project, &proposal.id).is_empty());
}

#[test]
fn reject_keyless_ok_for_unregistered_reviewer() {
    // Bootstrap: a reviewer with no registered key can still reject
    // (a brand-new frontier must be usable before any keys exist).
    let (mut project, proposal) = frontier_with_proposal(vec![]);
    reject_proposal_in_frontier_signed(
        &mut project,
        &proposal.id,
        "reviewer:bootstrap",
        "legacy reject",
        None,
        false,
    )
    .unwrap();
    let reviews = review_events_for(&project, &proposal.id);
    assert_eq!(reviews.len(), 1);
    assert!(reviews[0].signature.is_none(), "keyless reject is unsigned");
    assert!(verify_proposal_decision_parity(&project).is_empty());
}

#[test]
fn reject_refuses_agent_and_ci_actors() {
    // The keyless bootstrap above must never admit an agent: a reject is a
    // truth-bearing review verdict with no agent carve-out (burying a
    // proposal is as much a decision as applying one). Found live: an agent
    // driving the CLI with VELA_ACTOR_ID=agent:... could reject through the
    // unregistered-reviewer bootstrap path.
    let (mut project, proposal) = frontier_with_proposal(vec![]);
    for actor in ["agent:claude", "ci:github-actions"] {
        let err = reject_proposal_in_frontier_signed(
            &mut project,
            &proposal.id,
            actor,
            "probe",
            None,
            false,
        )
        .unwrap_err();
        assert!(
            err.contains("may not reject"),
            "expected the agent refusal for {actor}, got: {err}"
        );
    }
    assert!(review_events_for(&project, &proposal.id).is_empty());
}

#[test]
fn parity_flags_status_with_no_backing_event() {
    // Hand-edit a status to "rejected" with no event behind it — the
    // exact tamper the mutable field used to allow silently.
    let (mut project, proposal) = frontier_with_proposal(vec![]);
    let idx = project
        .proposals
        .iter()
        .position(|p| p.id == proposal.id)
        .unwrap();
    project.proposals[idx].status = "rejected".to_string();
    project.proposals[idx].reviewed_by = Some("reviewer:ghost".to_string());
    let conflicts = verify_proposal_decision_parity(&project);
    assert_eq!(conflicts.len(), 1);
    assert!(conflicts[0].contains("NO decision event"));
}

#[test]
fn accept_decision_is_recognized_by_its_domain_event() {
    // An accept's trace is the domain event it produces; parity must
    // recognize that without requiring a separate review.accepted.
    let (mut project, proposal) = frontier_with_proposal(vec![]);
    let event_id = accept_proposal_in_frontier_signed(
        &mut project,
        &proposal.id,
        "reviewer:test",
        "looks right",
        None,
    )
    .unwrap();
    let stored = project
        .proposals
        .iter()
        .find(|p| p.id == proposal.id)
        .unwrap();
    assert_eq!(stored.status, "applied");
    assert_eq!(stored.applied_event_id.as_deref(), Some(event_id.as_str()));
    assert!(
        verify_proposal_decision_parity(&project).is_empty(),
        "an applied proposal backed by its domain event satisfies parity"
    );
}

#[test]
fn review_event_targeting_missing_proposal_is_flagged() {
    let (mut project, _proposal) = frontier_with_proposal(vec![]);
    let orphan = events::new_review_decision_event(
        "vpr_does_not_exist",
        "finding.add",
        "rejected",
        None,
        "reviewer:x",
        "orphan",
        Some("2026-06-01T00:00:00Z"),
    )
    .unwrap();
    project.events.push(orphan);
    let conflicts = verify_proposal_decision_parity(&project);
    assert!(
        conflicts.iter().any(|c| c.contains("does not exist")),
        "an orphan review event must be flagged: {conflicts:?}"
    );
}
