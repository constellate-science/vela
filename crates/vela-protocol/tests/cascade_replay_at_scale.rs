//! Cascade replay at scale.
//!
//! Doctrine: "two implementations of the reducer must agree on the
//! mutation rules per kind." This test stresses that doctrine inside a
//! single implementation by generating many synthetic frontiers, each
//! with a deep cascade triggered by a single retraction, then verifying
//! that re-replaying the canonical event log from a clean genesis state
//! produces a byte-identical snapshot hash.
//!
//! What this proves:
//! 1. The reducer is deterministic across many independent frontiers.
//! 2. Cascade events propagate via `finding.dependency_invalidated`
//!    are themselves replayable — the post-cascade state isn't a
//!    function of when the propagator ran; it's a function of the
//!    canonical event log.
//! 3. `snapshot_hash` is order-stable and content-stable across replay.
//!
//! Scale (default): 50 frontiers, 20 findings each, with a retraction
//! that fans out to depth 10 via dependency_invalidated cascade events.
//! Total: ~1500 events processed, two passes through the reducer per
//! frontier, every snapshot hash compared.
//!
//! If this test ever fails on a hash mismatch, the reducer is no longer
//! deterministic for the failing kind — that's a hard correctness bug.

use serde_json::{Map, json};

use vela_protocol::bundle::{
    Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Entity, Evidence,
    Extraction, FindingBundle, Flags, Link, Provenance,
};
use vela_protocol::events::{
    self, FindingEventInput, NULL_HASH, StateActor, StateEvent, StateTarget, snapshot_hash,
};
use vela_protocol::reducer::replay_from_genesis;

const FRONTIER_COUNT: usize = 50;
const FINDINGS_PER_FRONTIER: usize = 20;
const CASCADE_DEPTH: usize = 10;

/// Build a synthetic FindingBundle with deterministic content. The id
/// is content-addressed off (assertion text + provenance.title), so
/// a fresh bundle for the same `(frontier_idx, finding_idx)` pair
/// always produces the same id — exactly what we need for re-replay
/// to land on the same snapshot.
fn make_finding(frontier_idx: usize, finding_idx: usize) -> FindingBundle {
    let assertion = Assertion {
        text: format!(
            "Synthetic finding {finding_idx} in frontier {frontier_idx}: protein-X activates pathway-Y."
        ),
        assertion_type: "mechanism".into(),
        entities: vec![Entity {
            name: format!("ProteinX{finding_idx}"),
            entity_type: "protein".into(),
            identifiers: Map::new(),
            canonical_id: None,
            candidates: vec![],
            aliases: vec![],
            resolution_provenance: None,
            resolution_confidence: 1.0,
            resolution_method: None,
            species_context: None,
            needs_review: false,
        }],
        relation: Some("activates".into()),
        direction: Some("positive".into()),
        causal_claim: None,
        causal_evidence_grade: None,
    };

    let evidence = Evidence {
        evidence_type: "experimental".into(),
        model_system: "mouse".into(),
        species: Some("Mus musculus".into()),
        method: "Western blot".into(),
        sample_size: Some("n=30".into()),
        effect_size: None,
        p_value: Some("p<0.05".into()),
        replicated: true,
        replication_count: Some(3),
        evidence_spans: vec![],
    };

    let conditions = Conditions {
        text: "In vitro, mouse microglia".into(),
        species_verified: vec!["Mus musculus".into()],
        species_unverified: vec![],
        in_vitro: true,
        in_vivo: false,
        human_data: false,
        clinical_trial: false,
        concentration_range: None,
        duration: None,
        age_group: None,
        cell_type: Some("microglia".into()),
    };

    let confidence = Confidence {
        kind: ConfidenceKind::FrontierEpistemic,
        score: 0.7,
        basis: "Synthetic test fixture".into(),
        method: ConfidenceMethod::LlmInitial,
        components: None,
        extraction_confidence: 0.9,
    };

    let provenance = Provenance {
        source_type: "published_paper".into(),
        // Doi makes the content-address deterministic per (frontier,
        // finding) pair; same inputs → same finding id, every time.
        doi: Some(format!(
            "10.0000/synthetic.frontier{frontier_idx:04}.finding{finding_idx:04}"
        )),
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Synthetic paper {frontier_idx}-{finding_idx}"),
        authors: vec![Author {
            name: "Synthetic A".into(),
            orcid: None,
        }],
        year: Some(2026),
        journal: Some("Synthetic Journal".into()),
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
        citation_count: Some(0),
    };

    let flags = Flags {
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
    };

    let mut bundle = FindingBundle::new(
        assertion, evidence, conditions, confidence, provenance, flags,
    );

    // Build a chain of dependency links: finding[i] supports
    // finding[i+1] supports finding[i+2] ... so a retraction at the
    // root cascades down the chain. We attach the link from i to
    // (i+1) — which is the dependency the cascade will invalidate.
    if finding_idx + 1 < FINDINGS_PER_FRONTIER {
        let next_id = synthetic_finding_id(frontier_idx, finding_idx + 1);
        bundle.links = vec![Link {
            target: next_id,
            link_type: "supports".into(),
            note: "synthetic dependency".into(),
            inferred_by: "vela-cascade-test/0".into(),
            created_at: "2026-05-02T00:00:00Z".into(),
            mechanism: None,
        }];
    }
    bundle
}

/// Recreate the deterministic id `make_finding(frontier_idx,
/// finding_idx)` will produce, without rebuilding the whole bundle.
/// We only care about the id; FindingBundle::content_address keys on
/// (assertion text + assertion type + doi).
fn synthetic_finding_id(frontier_idx: usize, finding_idx: usize) -> String {
    let assertion = Assertion {
        text: format!(
            "Synthetic finding {finding_idx} in frontier {frontier_idx}: protein-X activates pathway-Y."
        ),
        assertion_type: "mechanism".into(),
        entities: vec![],
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let provenance = Provenance {
        source_type: "published_paper".into(),
        doi: Some(format!(
            "10.0000/synthetic.frontier{frontier_idx:04}.finding{finding_idx:04}"
        )),
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Synthetic paper {frontier_idx}-{finding_idx}"),
        authors: vec![],
        year: None,
        journal: None,
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
        citation_count: None,
    };
    FindingBundle::content_address(&assertion, &provenance)
}

/// Build the sequence of canonical events for one synthetic frontier.
/// The shape: every finding gets reviewed (status accepted), then the
/// root finding gets retracted and the retraction cascades down the
/// dependency chain via `finding.dependency_invalidated` events.
fn build_event_log(frontier_idx: usize, findings: &[FindingBundle]) -> Vec<StateEvent> {
    let mut log = Vec::new();
    let actor_id = format!("reviewer:synthetic-{frontier_idx}");

    // Asserted + reviewed for every finding.
    for f in findings {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "synthetic genesis assertion",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id}),
            caveats: vec![],
            timestamp: None,
        }));
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "auto-review for cascade fixture",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id, "status": "accepted"}),
            caveats: vec![],
            timestamp: None,
        }));
    }

    // Retract the root finding (index 0). This is the source of the
    // cascade chain.
    let root = &findings[0];
    let root_proposal = format!("vpr_{}_{}", frontier_idx, &root.id[3..]);
    let retract_event = events::new_finding_event(FindingEventInput {
        kind: "finding.retracted",
        finding_id: &root.id,
        actor_id: &actor_id,
        actor_type: "human",
        reason: "synthetic retraction triggers cascade",
        before_hash: NULL_HASH,
        after_hash: NULL_HASH,
        payload: json!({
            "proposal_id": root_proposal,
            "affected": CASCADE_DEPTH,
        }),
        caveats: vec![],
        timestamp: None,
    });
    let retract_event_id = retract_event.id.clone();
    let root_id = root.id.clone();
    log.push(retract_event);

    // Cascade chain: each step invalidates the next dependent in the
    // chain, naming the upstream retraction so a replay reproduces the
    // post-cascade state without re-running the propagator.
    for depth in 1..=CASCADE_DEPTH {
        if depth >= findings.len() {
            break;
        }
        let dependent = &findings[depth];
        let dependent_proposal = format!("vpr_{}_{}", frontier_idx, &dependent.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.dependency_invalidated",
            finding_id: &dependent.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "cascade from synthetic root retraction",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({
                "proposal_id": dependent_proposal,
                "upstream_finding_id": root_id,
                "upstream_event_id": retract_event_id,
                "depth": depth as u64,
            }),
            caveats: vec![],
            timestamp: None,
        }));
    }

    log
}

#[test]
fn cascade_replay_is_deterministic_at_50_frontier_scale() {
    let mut total_events = 0usize;
    let mut total_cascades = 0usize;

    for frontier_idx in 0..FRONTIER_COUNT {
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();

        // Sanity: links should resolve to in-frontier ids for at
        // least the first FINDINGS_PER_FRONTIER-1 nodes.
        for (i, f) in findings.iter().enumerate() {
            if i + 1 < FINDINGS_PER_FRONTIER {
                assert_eq!(
                    f.links.len(),
                    1,
                    "frontier {frontier_idx} finding {i}: missing dependency link"
                );
                let link_target = &f.links[0].target;
                let expected = &findings[i + 1].id;
                assert_eq!(
                    link_target, expected,
                    "link target drift at frontier {frontier_idx} finding {i}"
                );
            }
        }

        let event_log = build_event_log(frontier_idx, &findings);
        total_events += event_log.len();

        // Pass 1: reduce events into state.
        let state_a = replay_from_genesis(
            findings.clone(),
            event_log.clone(),
            &format!("Synthetic Frontier {frontier_idx}"),
            "auto-generated cascade fixture",
            "2026-05-02T00:00:00Z",
            "vela-cascade-test/0",
        )
        .expect("pass 1 replay must succeed");

        // Pass 2: reduce again from a fresh genesis copy.
        let state_b = replay_from_genesis(
            findings.clone(),
            event_log.clone(),
            &format!("Synthetic Frontier {frontier_idx}"),
            "auto-generated cascade fixture",
            "2026-05-02T00:00:00Z",
            "vela-cascade-test/0",
        )
        .expect("pass 2 replay must succeed");

        let hash_a = snapshot_hash(&state_a);
        let hash_b = snapshot_hash(&state_b);
        assert_eq!(
            hash_a, hash_b,
            "snapshot hash mismatch at frontier {frontier_idx}: pass1={hash_a} pass2={hash_b}"
        );

        // The dependency_invalidated cascade events should be
        // present in the materialised log; if the reducer silently
        // dropped one, replay would diverge but we'd never know why.
        let cascade_count = state_a
            .events
            .iter()
            .filter(|e| e.kind == "finding.dependency_invalidated")
            .count();
        assert_eq!(
            cascade_count,
            CASCADE_DEPTH.min(FINDINGS_PER_FRONTIER - 1),
            "frontier {frontier_idx}: cascade event count drift"
        );
        total_cascades += cascade_count;

        // Validate every event the log carries against the protocol's
        // payload validator. A malformed cascade payload would slip
        // through the reducer (which doesn't validate) and only fail
        // at the registry boundary.
        for ev in &event_log {
            events::validate_event_payload(ev.kind.as_str(), &ev.payload).unwrap_or_else(|e| {
                panic!(
                    "frontier {frontier_idx}: event {} ({}) failed payload validation: {e}",
                    ev.id, ev.kind
                )
            });
        }
    }

    // Independent sanity numbers — these are what the test logs at
    // pass; if anyone tunes the constants down silently, the count
    // shifts and the failure is loud.
    assert_eq!(
        total_events,
        FRONTIER_COUNT * (FINDINGS_PER_FRONTIER * 2 + 1 + CASCADE_DEPTH)
    );
    assert_eq!(total_cascades, FRONTIER_COUNT * CASCADE_DEPTH);
}

/// Companion test: a single revocation chain (key.revoke events) over
/// the actor identity stays valid through the full validator pipeline.
/// Doesn't apply through the reducer (revocation events target an
/// actor, not a finding) — the assertion is that a deep chain of
/// revocations all pass payload validation.
#[test]
fn revocation_chain_validates_at_depth() {
    use vela_protocol::events::{EVENT_KIND_KEY_REVOKE, RevocationPayload, new_revocation_event};

    let actor_id = "reviewer:synthetic-rotator";
    let mut prev_pubkey = "0".repeat(64);
    let mut chain = Vec::new();

    for step in 0..CASCADE_DEPTH {
        // Synthesise two distinct 64-hex pubkeys per step.
        let revoked = format!("{:064x}", step * 2 + 1);
        let replacement = format!("{:064x}", step * 2 + 2);
        let payload = RevocationPayload {
            revoked_pubkey: revoked.clone(),
            revoked_at: format!("2026-05-{:02}T00:00:00Z", step + 1),
            replacement_pubkey: replacement.clone(),
            reason: format!("scheduled rotation step {step}"),
        };
        let event = new_revocation_event(
            actor_id,
            "human",
            payload,
            "rotation chain test",
            NULL_HASH,
            NULL_HASH,
        );
        // Validate against the v0.49 validator arm.
        events::validate_event_payload(event.kind.as_str(), &event.payload)
            .unwrap_or_else(|e| panic!("step {step} validation failed: {e}"));
        assert_eq!(event.kind, EVENT_KIND_KEY_REVOKE);
        // Each step's revoked key must differ from the previous step's
        // (otherwise the chain would loop), so the test catches a
        // generator that forgets to advance.
        assert_ne!(
            event
                .payload
                .get("revoked_pubkey")
                .and_then(|v| v.as_str())
                .unwrap(),
            prev_pubkey,
            "revoked_pubkey did not advance at step {step}"
        );
        prev_pubkey = revoked;
        chain.push(event);
    }

    assert_eq!(chain.len(), CASCADE_DEPTH);
}

// Use `_` to acknowledge that StateActor / StateTarget are part of
// the public surface this test exercises indirectly through
// new_finding_event. Keeping a reference here so a future API rename
// surfaces a compile error in this file too.
const _: fn(&StateActor, &StateTarget) = |_, _| {};
