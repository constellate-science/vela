//! Trust invariants, frozen as fail-closed fixtures.
//!
//! These are the load-bearing security properties of the trust kernel
//! (`docs/TRUST_MODEL_REDESIGN.md` sections 11 and 13), pinned in one place so a
//! later migration phase cannot silently relax them. Each test asserts that a
//! violation is REJECTED, not merely that the happy path works. The remaining
//! section-11 fixtures (DSSE keyid ignored, multi-signature judgment rejected,
//! revoked-key point-in-time) land with the phases that introduce those code
//! paths.

use vela_protocol::events::{
    EVENT_SCHEMA, NULL_HASH, StateActor, StateEvent, StateTarget, event_id,
};
use vela_protocol::provenance::{
    Activity, EvidenceRef, MachineContribution, Provenance, attach_to_payload,
};
use vela_protocol::statement_attestation::{AttestationDraft, FaithfulnessVerdict};
use vela_protocol::verifier_attachment::{
    AdversarialProbe, AttachmentDraft, AttachmentOutcome, GateStatus, MatchToClaim, ProbeKind,
    ProbeResult, VerifierAttachment, VerifierMethod, claim_digest, derive_gate_status,
};

// ── Invariant 1: no AI in a trust path via provenance ──────────────────────

#[test]
fn human_id_is_refused_in_machine_provenance() {
    // A human reviewer id smuggled into machine_contributions would be a typed
    // name standing in for the accountable signature. It must be a hard error.
    let p = Provenance {
        machine_contributions: vec![MachineContribution {
            id: "reviewer:will-blair".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(
        p.validate().is_err(),
        "a human id in machine_contributions must be rejected"
    );

    let e = Provenance {
        evidence_refs: vec![EvidenceRef {
            id: "reviewer:will-blair".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(
        e.validate().is_err(),
        "a human id in evidence_refs must be rejected"
    );
}

#[test]
fn machine_contribution_cannot_claim_authority() {
    // Authority is always the signer path. A machine contribution that asserts
    // any authority other than "none" is rejected.
    let p = Provenance {
        machine_contributions: vec![MachineContribution {
            id: "agent:claude".to_string(),
            authority: "signer".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    };
    assert!(
        p.validate().is_err(),
        "a machine contribution claiming authority must be rejected"
    );
}

// ── Invariant 2: judgment is human-only (a CI key cannot judge) ─────────────

#[test]
fn ci_actor_cannot_sign_a_faithfulness_attestation() {
    // statement faithfulness is human judgment by design. build() must refuse a
    // non-reviewer: actor, so a CI or agent key can never produce a vsa_.
    let key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let draft = AttestationDraft {
        target: "vf_0123456789abcdef".to_string(),
        informal_ref: "erdosproblems.com/214".to_string(),
        formal_ref: "fc/Erdos214.lean@abc".to_string(),
        formal_statement_hash: "a".repeat(64),
        verdict: FaithfulnessVerdict::Faithful,
        note: "looks faithful".to_string(),
        attested_by: "ci:vela-verify".to_string(),
        attested_at: "2026-06-30T00:00:00Z".to_string(),
    };
    assert!(
        vela_protocol::statement_attestation::StatementAttestation::build(draft, &key).is_err(),
        "a ci: actor must not be able to sign a faithfulness attestation"
    );
}

// ── Invariant 3: provenance is additive (omitted is byte-identical) ─────────

#[test]
fn populated_provenance_changes_event_id_omitted_is_identical() {
    let base = || StateEvent {
        schema: EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "review.accepted".into(),
        target: StateTarget {
            r#type: "proposal".to_string(),
            id: "vpr_test".to_string(),
        },
        actor: StateActor {
            id: "reviewer:will-blair".to_string(),
            r#type: "human".to_string(),
        },
        timestamp: "2026-06-30T00:00:00Z".to_string(),
        reason: "accept".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: "sha256:abc".to_string(),
        payload: serde_json::json!({ "proposal_id": "vpr_test", "verdict": "accepted" }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };

    // Omitted provenance: an event identical to a pre-redesign one keeps its id.
    let plain = base();
    let mut still_plain = base();
    attach_to_payload(&mut still_plain.payload, &Provenance::default()).unwrap();
    assert_eq!(
        event_id(&plain),
        event_id(&still_plain),
        "an empty provenance block must not perturb the event id"
    );

    // Populated provenance: enters the id preimage by design.
    let mut with_prov = base();
    attach_to_payload(
        &mut with_prov.payload,
        &Provenance {
            activity: Some(Activity {
                kind: "accepted".to_string(),
                ..Default::default()
            }),
            machine_contributions: vec![MachineContribution {
                id: "agent:claude".to_string(),
                role: "drafted".to_string(),
                authority: "none".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        },
    )
    .unwrap();
    assert_ne!(
        event_id(&plain),
        event_id(&with_prov),
        "a populated provenance block must change the event id (it is signed-over)"
    );
}

// ── Invariant 4: independence binds to a witness id, never the claim digest ──
//
// The thesis leak the design review caught. G1 independence must be satisfiable
// only by naming a sibling vva_ id, never the shared claim_digest, or one
// self-signed attachment could declare independence from the digest it already
// carries and read as verified alone.

fn attach(
    digest: &str,
    method: VerifierMethod,
    solver: &str,
    independent_of: Vec<String>,
) -> VerifierAttachment {
    VerifierAttachment::build(AttachmentDraft {
        target: "vf_0123456789abcdef".to_string(),
        claim_digest: digest.to_string(),
        verifier_method: method,
        solver_id: solver.to_string(),
        independent_of,
        match_to_claim: MatchToClaim {
            matches: true,
            checker_actor: "checker".to_string(),
        },
        adversarial_probes: vec![AdversarialProbe {
            kind: ProbeKind::CounterexampleSearch,
            result: ProbeResult::Survived,
            note: String::new(),
        }],
        outcome: AttachmentOutcome::Passed,
        verifier_actor: "ci:vela-verify".to_string(),
        note: String::new(),
    })
    .unwrap()
}

#[test]
fn independence_via_claim_digest_does_not_verify() {
    let digest = claim_digest("claim X");
    // Two genuinely diverse attachments (distinct method + solver, surviving
    // probe), but each declares independence by naming the CLAIM DIGEST rather
    // than the sibling attachment's vva_ id.
    let a1 = attach(
        &digest,
        VerifierMethod::ComputationalSearch,
        "cp-sat",
        vec![digest.clone()],
    );
    let a2 = attach(
        &digest,
        VerifierMethod::LpDualRecompute,
        "pulp-cbc",
        vec![digest.clone()],
    );
    let outcome = derive_gate_status(&digest, &[a1, a2]);
    assert_eq!(
        outcome.status,
        GateStatus::NeedsVerification,
        "independence declared via the shared claim digest must NOT reach Verified"
    );
    assert!(
        outcome.reasons.iter().any(|r| r.contains("independence")),
        "the failure must be the independence clause, got: {:?}",
        outcome.reasons
    );
}

#[test]
fn independence_via_sibling_witness_id_verifies() {
    // Positive control: the SAME two attachments, but a2 names a1's vva_ id.
    let digest = claim_digest("claim X");
    let a1 = attach(
        &digest,
        VerifierMethod::ComputationalSearch,
        "cp-sat",
        vec![],
    );
    let a2 = attach(
        &digest,
        VerifierMethod::LpDualRecompute,
        "pulp-cbc",
        vec![a1.id.clone()],
    );
    let outcome = derive_gate_status(&digest, &[a1, a2]);
    assert_eq!(
        outcome.status,
        GateStatus::Verified,
        "independence declared via a sibling witness id must reach Verified, got: {:?}",
        outcome.reasons
    );
}
