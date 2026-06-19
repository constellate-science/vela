//! Cross-implementation reducer fixtures.
//!
//! Doctrine: "two implementations of the reducer must agree on the
//! mutation rules per kind." The cascade test in
//! `cascade_replay_at_scale.rs` already proves Rust agrees with Rust at
//! scale. This test exports the same cascade fixtures to JSON files
//! that a second-implementation reducer (e.g. `clients/python/vela_reducer.py`)
//! can consume and verify byte-equivalently.
//!
//! What gets exported per fixture:
//!   - `genesis_findings`: the initial finding bundles (FindingBundle JSON)
//!   - `event_log`: the canonical event log (StateEvent JSON)
//!   - `expected_states`: the post-replay reducer-effects array, sorted
//!     by finding id, capturing only the fields the reducer mutates
//!     (retracted, contested, review_state, confidence_score, annotation_ids)
//!
//! A second-implementation reducer reads `genesis_findings` + `event_log`,
//! applies its own per-kind mutation rules, builds the same shape from
//! its result, and asserts deep equality with `expected_states`. If two
//! implementations agree on this mutation surface across N fixtures with
//! cascade chains, the doctrine is no longer a single-implementation
//! claim.

use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;

use vela_protocol::access_tier::AccessTier;
use vela_protocol::bundle::{
    Artifact, Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Entity,
    Evidence, Extraction, FindingBundle, Flags, Link, Provenance,
};
use vela_protocol::events::{
    self, FindingEventInput, NULL_HASH, StateActor, StateEvent, StateTarget,
};
use vela_protocol::reducer::replay_from_genesis;

const FIXTURE_FRONTIER_COUNT: usize = 3;
const FINDINGS_PER_FRONTIER: usize = 8;
const CASCADE_DEPTH: usize = 5;

fn fixture_timestamp(frontier_idx: usize, event_idx: usize) -> String {
    format!(
        "2026-05-02T{:02}:{:02}:{:02}Z",
        frontier_idx % 24,
        (event_idx / 60) % 60,
        event_idx % 60
    )
}

fn fixture_object_timestamp(frontier_idx: usize, object_idx: usize) -> String {
    format!(
        "2026-05-02T{:02}:30:{:02}Z",
        frontier_idx % 24,
        object_idx % 60
    )
}

fn pin_artifact(mut artifact: Artifact, frontier_idx: usize, object_idx: usize) -> Artifact {
    artifact.created = fixture_object_timestamp(frontier_idx, object_idx);
    artifact
}

fn replace_event_id_strings(value: &mut Value, id_map: &BTreeMap<String, String>) {
    match value {
        Value::String(s) => {
            if let Some(replacement) = id_map.get(s) {
                *s = replacement.clone();
            }
        }
        Value::Array(items) => {
            for item in items {
                replace_event_id_strings(item, id_map);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                replace_event_id_strings(item, id_map);
            }
        }
        _ => {}
    }
}

fn normalize_event_log(
    frontier_idx: usize,
    event_log: Vec<events::StateEvent>,
) -> Vec<events::StateEvent> {
    let mut id_map = BTreeMap::new();
    let mut normalized = Vec::with_capacity(event_log.len());

    for (event_idx, mut event) in event_log.into_iter().enumerate() {
        let old_id = event.id.clone();
        event.timestamp = fixture_timestamp(frontier_idx, event_idx);
        replace_event_id_strings(&mut event.payload, &id_map);
        event.id = events::compute_event_id(&event);

        if !old_id.is_empty() {
            id_map.insert(old_id, event.id.clone());
        }

        normalized.push(event);
    }

    normalized
}

fn make_finding(frontier_idx: usize, finding_idx: usize) -> FindingBundle {
    let assertion = Assertion {
        text: format!(
            "Cross-impl finding {finding_idx} in frontier {frontier_idx}: protein-X activates pathway-Y."
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
        method: "Western blot".into(),
        replicated: true,
        replication_count: Some(3),
        evidence_spans: vec![],
    };
    let conditions = Conditions {
        text: "In vitro, mouse microglia".into(),
        duration: None,
    };
    let confidence = Confidence {
        kind: ConfidenceKind::FrontierEpistemic,
        score: 0.7,
        basis: "Cross-impl test fixture".into(),
        method: ConfidenceMethod::LlmInitial,
        components: None,
        extraction_confidence: 0.9,
    };
    let provenance = Provenance {
        source_type: "published_paper".into(),
        doi: Some(format!(
            "10.0000/crossimpl.frontier{frontier_idx:04}.finding{finding_idx:04}"
        )),
        url: None,
        title: format!("Cross-impl paper {frontier_idx}-{finding_idx}"),
        authors: vec![Author {
            name: "Cross-Impl A".into(),
            orcid: None,
        }],
        year: Some(2026),
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
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
    bundle.created = fixture_object_timestamp(frontier_idx, finding_idx);
    if finding_idx + 1 < FINDINGS_PER_FRONTIER {
        let next_id = synthetic_id(frontier_idx, finding_idx + 1);
        bundle.links = vec![Link {
            target: next_id,
            link_type: "supports".into(),
            note: "synthetic dependency".into(),
            inferred_by: "vela-cross-impl-fixture/0".into(),
            created_at: "2026-05-02T00:00:00Z".into(),
            mechanism: None,
        }];
    }
    bundle
}

fn synthetic_id(frontier_idx: usize, finding_idx: usize) -> String {
    let assertion = Assertion {
        text: format!(
            "Cross-impl finding {finding_idx} in frontier {frontier_idx}: protein-X activates pathway-Y."
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
            "10.0000/crossimpl.frontier{frontier_idx:04}.finding{finding_idx:04}"
        )),
        url: None,
        title: format!("Cross-impl paper {frontier_idx}-{finding_idx}"),
        authors: vec![],
        year: None,
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
    };
    FindingBundle::content_address(&assertion, &provenance)
}

fn build_event_log(frontier_idx: usize, findings: &[FindingBundle]) -> Vec<events::StateEvent> {
    let mut log = Vec::new();
    let actor_id = format!("reviewer:cross-impl-{frontier_idx}");
    for f in findings {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "cross-impl genesis assertion",
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
            reason: "cross-impl review",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id, "status": "accepted"}),
            caveats: vec![],
            timestamp: None,
        }));
    }
    let root = &findings[0];
    let root_proposal = format!("vpr_{}_{}", frontier_idx, &root.id[3..]);
    let retract = events::new_finding_event(FindingEventInput {
        kind: "finding.retracted",
        finding_id: &root.id,
        actor_id: &actor_id,
        actor_type: "human",
        reason: "cross-impl retraction triggers cascade",
        before_hash: NULL_HASH,
        after_hash: NULL_HASH,
        payload: json!({
            "proposal_id": root_proposal,
            "affected": CASCADE_DEPTH,
        }),
        caveats: vec![],
        timestamp: None,
    });
    let retract_event_id = retract.id.clone();
    let root_id = root.id.clone();
    log.push(retract);

    for depth in 1..=CASCADE_DEPTH {
        if depth >= findings.len() {
            break;
        }
        let dep = &findings[depth];
        let dep_proposal = format!("vpr_{}_{}", frontier_idx, &dep.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.dependency_invalidated",
            finding_id: &dep.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "cross-impl cascade",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({
                "proposal_id": dep_proposal,
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

/// v0.49.3 — Coverage fixture: exercises every dispatch arm in the
/// reducer that the cascade fixtures don't already touch. Each
/// finding gets:
///   - finding.asserted (genesis)
///   - finding.reviewed (rotated through accepted/contested/needs_revision/rejected)
///   - finding.confidence_revised (alternating int and float new_score
///     values to lock the basis-string formatting and the 6-decimal
///     score boundary across implementations)
///
/// This is the fixture the engineer + integrator both flagged as
/// missing. After this, every per-kind branch in
/// reducer.rs::apply_event has at least one cross-impl reproducer.
fn build_review_branches_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let mut log = Vec::new();
    let actor_id = format!("reviewer:review-branches-{frontier_idx}");
    let statuses = ["accepted", "contested", "needs_revision", "rejected"];
    for (i, f) in findings.iter().enumerate() {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "review-branch genesis",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id}),
            caveats: vec![],
            timestamp: None,
        }));
        // Rotate through every status so all four arms in
        // apply_finding_reviewed land at least once.
        let status = statuses[i % statuses.len()];
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "review-branch coverage",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id, "status": status}),
            caveats: vec![],
            timestamp: None,
        }));
        // Alternate integer vs fractional new_score to stress the
        // basis-string formatting (Rust {:.3}, Python :.3f, JS
        // .toFixed(3)) and the digest 6-decimal boundary.
        let (prev, new) = if i % 2 == 0 {
            (0.7, 1.0)
        } else {
            (0.7, 0.42_f64)
        };
        let revise_reason = format!("revise to {new:.3}");
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.confidence_revised",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: &revise_reason,
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({
                "proposal_id": proposal_id,
                "previous_score": prev,
                "new_score": new,
            }),
            caveats: vec![],
            timestamp: None,
        }));
    }
    log
}

/// v0.49.3 — Annotations fixture: exercises both annotation kinds
/// (finding.noted and finding.caveated) plus finding.rejected, the
/// last reducer arms not covered by cascade or review-branches.
fn build_annotations_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let mut log = Vec::new();
    let actor_id = format!("reviewer:annotations-{frontier_idx}");
    for (i, f) in findings.iter().enumerate() {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "annotations-fixture genesis",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id}),
            caveats: vec![],
            timestamp: None,
        }));
        // First half get a noted; second half a caveated. Both go
        // through apply_finding_annotation but are dispatched on
        // distinct kinds, so a future reducer that forgets the
        // caveated → annotation route will fail one half.
        let kind = if i < findings.len() / 2 {
            "finding.noted"
        } else {
            "finding.caveated"
        };
        let annotation_id = format!("ann_{}_{}", frontier_idx, i);
        log.push(events::new_finding_event(FindingEventInput {
            kind,
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "annotation coverage",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({
                "proposal_id": proposal_id,
                "annotation_id": annotation_id,
                "text": format!("note {i} on finding {}", &f.id[..8]),
                // Provenance with a doi satisfies the validator's
                // "at least one of doi/pmid/title" rule.
                "provenance": {
                    "doi": format!("10.0000/annot.{frontier_idx}.{i}"),
                },
            }),
            caveats: vec![],
            timestamp: None,
        }));
    }
    // Reject the last finding — the only event kind that's not
    // exercised by cascade, review-branches, or annotations.
    if let Some(last) = findings.last() {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &last.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.rejected",
            finding_id: &last.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "rejection coverage",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id}),
            caveats: vec![],
            timestamp: None,
        }));
    }
    log
}

/// Coverage fixture: exercises every generic Artifact lifecycle arm.
/// Deposits two content-addressed records, reviews one as accepted,
/// reclassifies it as restricted, and retracts the other.
fn build_artifacts_log(frontier_idx: usize, findings: &[FindingBundle]) -> Vec<events::StateEvent> {
    let mut log = Vec::new();
    let actor_id = format!("reviewer:artifacts-{frontier_idx}");

    for f in findings {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "artifact-fixture genesis",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id}),
            caveats: vec![],
            timestamp: None,
        }));
    }

    let provenance = |title: String| Provenance {
        source_type: "published_paper".into(),
        doi: None,
        url: Some(format!("https://example.org/frontier-{frontier_idx}/trial")),
        title,
        authors: vec![],
        year: Some(2026),
        license: Some("CC0-1.0".into()),
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
    };

    let mut metadata = BTreeMap::new();
    metadata.insert("nct_id".to_string(), json!(format!("NCT{frontier_idx:08}")));
    metadata.insert("overall_status".to_string(), json!("COMPLETED"));

    let trial = pin_artifact(
        Artifact::new(
            "clinical_trial_record",
            format!("Cross-impl trial record {frontier_idx}"),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Some(2048),
            Some("application/json".into()),
            "remote",
            Some(format!(
                "https://clinicaltrials.gov/api/v2/studies/NCT{frontier_idx:08}"
            )),
            Some(format!(
                "https://clinicaltrials.gov/study/NCT{frontier_idx:08}"
            )),
            Some("Public domain".into()),
            vec![findings[0].id.clone()],
            provenance(format!("Cross-impl trial source {frontier_idx}")),
            metadata,
            AccessTier::Public,
        )
        .expect("valid trial artifact"),
        frontier_idx,
        300,
    );
    let trial_id = trial.id.clone();
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "artifact.asserted".into(),
        target: StateTarget {
            r#type: "artifact".to_string(),
            id: trial_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "deposit trial registry artifact for cross-impl fixture".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_artifact_{frontier_idx}_trial"),
            "artifact": trial,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "artifact.reviewed".into(),
        target: StateTarget {
            r#type: "artifact".to_string(),
            id: trial_id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:artifact-second-reader-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "trial registry artifact verified against source locator".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_artifact_{frontier_idx}_trial_review"),
            "status": "accepted",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "tier.set".into(),
        target: StateTarget {
            r#type: "artifact".to_string(),
            id: trial_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "artifact includes review notes under restricted read tier".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_artifact_{frontier_idx}_trial_tier"),
            "object_type": "artifact",
            "object_id": trial_id,
            "new_tier": "restricted",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    let lab_file = pin_artifact(
        Artifact::new(
            "lab_file",
            format!("Cross-impl lab file {frontier_idx}"),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            Some(512),
            Some("text/plain".into()),
            "pointer",
            Some(format!("lab://frontier-{frontier_idx}/notebook-17")),
            None,
            Some("internal lab note".into()),
            vec![],
            provenance(format!("Cross-impl lab source {frontier_idx}")),
            BTreeMap::new(),
            AccessTier::Public,
        )
        .expect("valid lab artifact"),
        frontier_idx,
        301,
    );
    let lab_id = lab_file.id.clone();
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "artifact.asserted".into(),
        target: StateTarget {
            r#type: "artifact".to_string(),
            id: lab_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "deposit lab file pointer for cross-impl fixture".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_artifact_{frontier_idx}_lab"),
            "artifact": lab_file,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "artifact.retracted".into(),
        target: StateTarget {
            r#type: "artifact".to_string(),
            id: lab_id,
        },
        actor: StateActor {
            id: actor_id,
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "lab file pointer was superseded by a verified blob".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_artifact_{frontier_idx}_lab_retract"),
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    log
}

/// v0.51 — Coverage fixture: exercises the `tier.set` reducer arm
/// across both tierable kernel object types (finding, artifact). This
/// builder covers the finding side: it asserts findings, then issues
/// `tier.set` events to reclassify findings[0] at restricted and
/// findings[1] at classified. The artifact side is covered by the
/// artifacts fixture, which carries an artifact-targeted tier.set.
fn build_tier_set_log(frontier_idx: usize, findings: &[FindingBundle]) -> Vec<events::StateEvent> {
    let mut log = Vec::new();
    let actor_id = format!("reviewer:tier-{frontier_idx}");

    for f in findings {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "tier-set fixture genesis",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id}),
            caveats: vec![],
            timestamp: None,
        }));
    }

    // Reclassify findings[0] to restricted and findings[1] to
    // classified, exercising both non-public tiers on the finding arm.
    let reclassifications = [
        (
            "finding",
            findings[0].id.clone(),
            "restricted",
            "Finding reclassified for IBC review.",
        ),
        (
            "finding",
            findings[1].id.clone(),
            "classified",
            "Finding reclassified — readout includes capability-relevant detail above DURC threshold.",
        ),
    ];
    for (i, (object_type, object_id, new_tier, reason)) in reclassifications.iter().enumerate() {
        log.push(StateEvent {
            schema: events::EVENT_SCHEMA.to_string(),
            id: String::new(),
            kind: "tier.set".into(),
            target: StateTarget {
                r#type: object_type.to_string(),
                id: object_id.clone(),
            },
            actor: StateActor {
                id: format!("reviewer:ibc-{frontier_idx}"),
                r#type: "human".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason: reason.to_string(),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({
                "proposal_id": format!("vpr_tier_set_{frontier_idx}_{i}"),
                "object_type": object_type,
                "object_id": object_id,
                "previous_tier": "public",
                "new_tier": new_tier,
            }),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        });
    }

    log
}

/// v0.56: Coverage fixture for the `evidence_atom.locator_repaired`
/// reducer arm. Builds a single hand-crafted event that targets a
/// stable atom id with a mechanically derivable locator. The arm
/// mutates `state.evidence_atoms[i].locator` only and leaves
/// `state.findings` untouched, so the cross-impl post-replay digest
/// (which covers `findings[]` only) treats it as a no-op. The TS or
/// Python reducer is expected to either implement the same arm or
/// silently ignore the event without dropping subsequent finding
/// events.
fn build_locator_repair_log(
    frontier_idx: usize,
    _findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "evidence_atom.locator_repaired".into(),
        target: StateTarget {
            r#type: "evidence_atom".to_string(),
            id: format!("vea_fixture_locator_{frontier_idx}"),
        },
        actor: StateActor {
            id: format!("agent:vela-curation-bot-{frontier_idx}"),
            r#type: "agent".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Mechanical repair from parent source".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_locator_repair_{frontier_idx}"),
            "source_id": format!("vs_fixture_source_{frontier_idx}"),
            "locator": format!("doi:10.1/fixture-locator-{frontier_idx}"),
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// v0.57: Coverage fixture for the `finding.span_repaired` reducer
/// arm. Builds a single hand-crafted event that targets a finding by
/// id with `{section, text}` payload. The arm appends to
/// `state.findings[i].evidence.evidence_spans` and is idempotent
/// under identical re-application.
fn build_span_repair_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let target_finding = &findings[0];
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "finding.span_repaired".into(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: target_finding.id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:span-repair-fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Mechanical evidence-span repair".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_span_repair_{frontier_idx}"),
            "section": "abstract",
            "text": format!("Fixture span body for span-repair coverage {frontier_idx}."),
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// `finding.superseded` builder. The event targets the OLD finding and
/// flips `flags.superseded` (the replacement's body lives in the
/// accepted proposal and enters via loader genesis seeding, never via
/// the reducer — the payload is deliberately thin). `superseded` is not
/// part of the finding-effects digest, so expected_states pins that the
/// digested fields stay untouched and that no reducer ERRORS on the
/// kind; the flag-flip semantics are pinned by the Rust unit tests.
fn build_superseded_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let target = &findings[0];
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "finding.superseded".into(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: target.id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:supersede-fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture supersession for cross-impl coverage".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_fixture_{frontier_idx:08x}"),
            "new_finding_id": format!("vf_fixture_new_{frontier_idx:08x}"),
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// Supersession-propagation builder (fixture 16). A two-finding log
/// where B depends on A, A is superseded, then B is invalidated through
/// the upstream cascade:
///
///   - `finding.asserted` + `finding.reviewed(accepted)` for A and B
///   - `finding.superseded` on A — flips `A.flags.superseded` (outside
///     the finding-effects digest)
///   - `finding.dependency_invalidated` on B citing A as the upstream —
///     sets `B.flags.contested` and appends a deterministic cascade
///     annotation (BOTH inside the digest)
///
/// This encodes REALITY: supersession itself is a LOCAL flag-flip on the
/// old finding. It does NOT auto-propagate to dependents — propagation to
/// B is an explicit, separately-emitted `finding.dependency_invalidated`
/// event, not an automatic homomorphism over A's provenance. The fixture
/// pins both the supersession of A (digest-invisible, no reducer error)
/// and the visible cascade onto B (contested + annotation), so a second
/// implementation must reproduce the propagation byte-for-byte.
fn build_supersession_propagation_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let actor_id = format!("reviewer:supersede-prop-{frontier_idx}");
    let a = &findings[0];
    let b = &findings[1];
    let mut log = Vec::new();

    for f in [a, b] {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "supersession-propagation genesis assertion",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({ "proposal_id": proposal_id }),
            caveats: vec![],
            timestamp: None,
        }));
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "supersession-propagation review",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({ "proposal_id": proposal_id, "status": "accepted" }),
            caveats: vec![],
            timestamp: None,
        }));
    }

    // Supersede A. Thin event: the replacement body enters via loader
    // genesis seeding, never the reducer. `flags.superseded` flips on A.
    let supersede = events::new_finding_event(FindingEventInput {
        kind: "finding.superseded",
        finding_id: &a.id,
        actor_id: &actor_id,
        actor_type: "human",
        reason: "A superseded by a corrected finding",
        before_hash: NULL_HASH,
        after_hash: NULL_HASH,
        payload: json!({
            "proposal_id": format!("vpr_supersede_{frontier_idx:08x}"),
            "new_finding_id": format!("vf_supersede_new_{frontier_idx:08x}"),
        }),
        caveats: vec![],
        timestamp: None,
    });
    let supersede_id = supersede.id.clone();
    log.push(supersede);

    // B depends on A; the upstream supersession invalidates B via an
    // EXPLICIT cascade event (the reducer never emits this itself).
    let dep_proposal = format!("vpr_{}_{}", frontier_idx, &b.id[3..]);
    log.push(events::new_finding_event(FindingEventInput {
        kind: "finding.dependency_invalidated",
        finding_id: &b.id,
        actor_id: &actor_id,
        actor_type: "human",
        reason: "upstream A superseded — invalidate dependent B",
        before_hash: NULL_HASH,
        after_hash: NULL_HASH,
        payload: json!({
            "proposal_id": dep_proposal,
            "upstream_finding_id": a.id,
            "upstream_event_id": supersede_id,
            "depth": 1u64,
        }),
        caveats: vec![],
        timestamp: None,
    }));

    log
}

/// `assertion.reinterpreted_causal` builder. Replays the causal
/// re-grading from `payload.after` ({claim, grade}). Causal fields are
/// not part of the finding-effects digest; coverage proves no reducer
/// errors on the kind.
fn build_reinterpreted_causal_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let target = &findings[1 % findings.len()];
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "assertion.reinterpreted_causal".into(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: target.id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:causal-fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 1),
        reason: "Fixture causal re-grading for cross-impl coverage".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_fixture_causal_{frontier_idx:08x}"),
            "before": {"claim": null, "grade": null},
            "after": {"claim": "correlation", "grade": "observational"},
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// `statement.attested` builder. The attestation is a signed vsa_ record
/// riding in payload.attestation; the Rust reducer re-verifies its
/// signature and upserts it into a side table outside the
/// finding-effects digest. Coverage proves no reducer errors on the
/// kind; the upsert + signature semantics are pinned by the Rust unit
/// tests in statement_attestation.rs and reducer tests.
fn build_statement_attested_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    use vela_protocol::statement_attestation::{
        AttestationDraft, FaithfulnessVerdict, StatementAttestation,
    };
    let key = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let att = StatementAttestation::build(
        AttestationDraft {
            target: findings[0].id.clone(),
            informal_ref: format!("fixture-problem #{frontier_idx}"),
            formal_ref: format!("fixture/Formal{frontier_idx}.lean"),
            formal_statement_hash: "b".repeat(64),
            verdict: FaithfulnessVerdict::Faithful,
            note: "Fixture attestation for cross-impl coverage.".to_string(),
            attested_by: "reviewer:attest-fixture".to_string(),
            attested_at: fixture_timestamp(frontier_idx, 0),
        },
        &key,
    )
    .expect("build fixture attestation");
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "statement.attested".into(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: findings[0].id.clone(),
        },
        actor: StateActor {
            id: "reviewer:attest-fixture".to_string(),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 2),
        reason: "Fixture statement attestation for cross-impl coverage".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({ "attestation": att }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// `anchor.attached` / `anchor.retracted` builder. A signed `val_` anchor
/// link rides in payload.anchor_link; the reducer re-verifies its signature
/// and upserts it, and the retract removes it by id. Coverage proves no
/// reducer errors on either kind; upsert/remove + signature semantics are
/// pinned by anchor.rs and the reducer unit tests.
fn build_anchor_log(frontier_idx: usize, findings: &[FindingBundle]) -> Vec<events::StateEvent> {
    use vela_protocol::anchor::{Anchor, AnchorKind, AnchorLink, AnchorLinkDraft, JoinPolicy};
    let key = ed25519_dalek::SigningKey::from_bytes(&[13u8; 32]);
    let link = AnchorLink::build(
        AnchorLinkDraft {
            target: findings[0].id.clone(),
            anchor: Anchor {
                namespace: "oeis".to_string(),
                id: format!("A{frontier_idx:06}"),
                role: "fixture-bound".to_string(),
                kind: AnchorKind::Sequence,
                join_policy: JoinPolicy::HardIdentity,
                namespace_version: None,
                source_revision: None,
                statement_fingerprint: None,
            },
            attached_by: "reviewer:anchor-fixture".to_string(),
            attached_at: fixture_timestamp(frontier_idx, 0),
        },
        &key,
    )
    .expect("build fixture anchor link");
    let mk = |kind: &str, payload: serde_json::Value, t: usize| StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: kind.into(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: findings[0].id.clone(),
        },
        actor: StateActor {
            id: "reviewer:anchor-fixture".to_string(),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, t),
        reason: format!("Fixture {kind} for cross-impl coverage"),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload,
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };
    vec![
        mk("anchor.attached", json!({ "anchor_link": link }), 2),
        mk("anchor.retracted", json!({ "anchor_link_id": link.id }), 3),
    ]
}

/// `attempt.claimed` + `statement.registered` builders: side-table
/// kinds outside the finding-effects digest; coverage proves no reducer
/// errors. Lease/registration semantics are pinned by Rust unit tests.
fn build_claim_and_register_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let mk = |kind: &str, ts_idx: usize, payload: serde_json::Value| StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: kind.into(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: findings[0].id.clone(),
        },
        actor: StateActor {
            id: "reviewer:lease-fixture".to_string(),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, ts_idx),
        reason: "fixture".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload,
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };
    vec![
        mk(
            "attempt.claimed",
            0,
            json!({"obligation_id": findings[0].id, "lease_ttl_seconds": 3600, "claimant_actor": "agent:fixture"}),
        ),
        mk(
            "statement.registered",
            1,
            json!({"statement_hash": "d".repeat(64), "informal_ref": "fixture #1"}),
        ),
    ]
}

/// Gap 5 (STATE_PLANE_MEMO appendix): `statement.registered` carrying
/// the optional finding-to-registration edge as a payload field
/// (`finding_id`) on the EXISTING kind — no new event kind. The edge
/// lands on `StatementRegistration.finding_id` in the Rust side table,
/// which is outside the cross-impl finding-effects digest, so the
/// expected_* arrays are the untouched genesis findings; a second
/// implementation must not ERROR on the extended payload (the no-op
/// arms in the Python/TypeScript reducers already accept any payload
/// for this kind).
fn build_register_with_finding_edge_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let mk = |ts_idx: usize, target: &str, payload: serde_json::Value| StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "statement.registered".into(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: target.to_string(),
        },
        actor: StateActor {
            id: "reviewer:priority-fixture".to_string(),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, ts_idx),
        reason: "fixture: finding-to-registration edge".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload,
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };
    vec![
        // With the edge: payload.finding_id names a genesis finding.
        mk(
            0,
            &findings[0].id,
            json!({
                "statement_hash": "e".repeat(64),
                "informal_ref": "fixture priority with edge",
                "finding_id": findings[0].id,
            }),
        ),
        // Without the edge: the pre-gap-5 payload shape still applies
        // cleanly alongside the extended one.
        mk(
            1,
            &findings[1].id,
            json!({
                "statement_hash": "f".repeat(64),
                "informal_ref": "fixture priority without edge",
            }),
        ),
    ]
}

/// v0.220: diff_pack.released / diff_pack.reviewed /
/// verdict_conflict.resolved fixture builders. These three reducer
/// arms write to side tables (`released_diff_packs`,
/// `verdict_conflicts`) that are not part of the cross-impl finding-
/// effects digest. The fixtures' job is purely coverage — to prove
/// that the kinds are present in the union of event-builder outputs
/// so `fixture_coverage_includes_every_reducer_arm` stays green.
fn build_diff_pack_released_log(
    frontier_idx: usize,
    _findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let pack_id = format!("vsd_release_fixture_{frontier_idx:04x}");
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: format!("vev_release_fixture_{frontier_idx:04x}"),
        kind: "diff_pack.released".into(),
        target: StateTarget {
            r#type: "diff_pack".to_string(),
            id: pack_id.clone(),
        },
        actor: StateActor {
            id: format!("releaser:fixture-{frontier_idx}"),
            r#type: "system".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture diff_pack.released for cross-impl coverage".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "pack_id": pack_id,
            "frontier_id": format!("vfr_fixture_{frontier_idx:04x}"),
            "summary": "Fixture release for coverage",
            "aggregate_kind": "fixture",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

fn build_diff_pack_reviewed_log(
    frontier_idx: usize,
    _findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let pack_id = format!("vsd_release_fixture_{frontier_idx:04x}");
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: format!("vev_review_fixture_{frontier_idx:04x}"),
        kind: "diff_pack.reviewed".into(),
        target: StateTarget {
            r#type: "diff_pack".to_string(),
            id: pack_id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 1),
        reason: "Fixture diff_pack.reviewed for cross-impl coverage".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "pack_id": pack_id,
            "verdict": "accept",
            "reviewer_actor": format!("reviewer:fixture-{frontier_idx}"),
            "applied_members": [],
            "sdk_only_members": [],
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

fn build_verdict_conflict_resolved_log(
    frontier_idx: usize,
    _findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    use vela_protocol::verdict_conflict::{ConflictDraft, ResolutionMode, VerdictConflict};

    // Build an unsigned but content-addressed VerdictConflict so the
    // event payload satisfies VerdictConflict::verify() (which only
    // checks signature when both sig + pubkey are present).
    let draft = ConflictDraft {
        frontier_id: format!("vfr_fixture_conflict_{frontier_idx:04x}"),
        verdicts: vec![
            format!("vpv_a_{frontier_idx:04x}"),
            format!("vpv_b_{frontier_idx:04x}"),
        ],
        shared_member_ids: vec![format!("vpr_shared_{frontier_idx:04x}")],
        resolution_mode: ResolutionMode::OwnerOverride,
        resolution_actor: format!("reviewer:fixture-{frontier_idx}"),
        resolved_at: fixture_timestamp(frontier_idx, 0),
        winning_verdict_id: Some(format!("vpv_a_{frontier_idx:04x}")),
        rationale: Some("Fixture resolution for cross-impl coverage".to_string()),
    };
    let conflict = VerdictConflict::build(draft).expect("fixture VerdictConflict build");
    let conflict_value = serde_json::to_value(&conflict).expect("fixture conflict serialize");
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: format!("vev_conflict_fixture_{frontier_idx:04x}"),
        kind: "verdict_conflict.resolved".into(),
        target: StateTarget {
            r#type: "verdict_conflict".to_string(),
            id: conflict.conflict_id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture verdict_conflict.resolved for cross-impl coverage".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "conflict": conflict_value,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// contradiction.resolved fixture builder. The reducer arm
/// (`reducer.rs::apply_contradiction_resolved`) upserts a
/// `Contradiction` into `Project.contradictions`, a side table that is
/// not part of the cross-impl finding-effects digest. The payload
/// carries a content-addressed, adjudicated `Contradiction` so the
/// reducer's id-match check passes. No-op on findings.
fn build_contradiction_resolved_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    use vela_protocol::contradiction::Contradiction;

    let a = findings[0].id.clone();
    let b = findings[1].id.clone();
    let frontier_id = format!("vfr_fixture_contradiction_{frontier_idx:04x}");
    let resolved = Contradiction::candidate(&frontier_id, &a, &b, "shared-axis disagreement")
        .resolve(
            &format!("reviewer:fixture-{frontier_idx}"),
            &fixture_timestamp(frontier_idx, 0),
            "finding_a superseded by a corrected measurement",
        );
    let contradiction_id = resolved.contradiction_id.clone();
    let contradiction_value = serde_json::to_value(&resolved).expect("serialize contradiction");
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: format!("vev_contradiction_fixture_{frontier_idx:04x}"),
        kind: "contradiction.resolved".into(),
        target: StateTarget {
            r#type: "contradiction".to_string(),
            id: contradiction_id,
        },
        actor: StateActor {
            id: format!("reviewer:fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture contradiction.resolved for cross-impl coverage".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "contradiction": contradiction_value,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// v0.53: Reducer-effects digest per finding. v0.53 extends the v1
/// digest with `access_tier` so `tier.set` events on findings now
/// participate in the cross-impl byte-equivalence promise.
fn finding_state(f: &FindingBundle) -> Value {
    let review_state = f
        .flags
        .review_state
        .as_ref()
        .map(|s| match s {
            vela_protocol::bundle::ReviewState::Accepted => "accepted",
            vela_protocol::bundle::ReviewState::Contested => "contested",
            vela_protocol::bundle::ReviewState::NeedsRevision => "needs_revision",
            vela_protocol::bundle::ReviewState::Rejected => "rejected",
        })
        .unwrap_or("none");
    let mut annotation_ids: Vec<String> = f.annotations.iter().map(|a| a.id.clone()).collect();
    annotation_ids.sort();
    json!({
        "id": f.id,
        "retracted": f.flags.retracted,
        "contested": f.flags.contested,
        "review_state": review_state,
        // Format to 6 decimal places so f64 precision noise can't
        // cross the cross-implementation boundary.
        "confidence_score": format!("{:.6}", f.confidence.score),
        "annotation_ids": annotation_ids,
        "access_tier": f.access_tier.canonical(),
    })
}

/// Reducer-effects digest per Artifact. Captures the artifact lifecycle
/// fields and access tier. Static provenance and byte commitments remain
/// in the event payload itself.
fn artifact_state(a: &vela_protocol::bundle::Artifact) -> Value {
    let review_state = a
        .review_state
        .as_ref()
        .map(|s| match s {
            vela_protocol::bundle::ReviewState::Accepted => "accepted",
            vela_protocol::bundle::ReviewState::Contested => "contested",
            vela_protocol::bundle::ReviewState::NeedsRevision => "needs_revision",
            vela_protocol::bundle::ReviewState::Rejected => "rejected",
        })
        .unwrap_or("none");
    json!({
        "id": a.id,
        "kind": a.kind,
        "retracted": a.retracted,
        "review_state": review_state,
        "access_tier": a.access_tier.canonical(),
    })
}

/// Helper: replay an event log from a fresh genesis, sort by id,
/// extract the reducer-effects digest, and write the fixture.
fn export_one(
    out_dir: &PathBuf,
    fixture_idx: usize,
    scenario: &str,
    findings: Vec<FindingBundle>,
    event_log: Vec<events::StateEvent>,
) {
    let event_log = normalize_event_log(fixture_idx, event_log);
    let post = replay_from_genesis(
        findings.clone(),
        event_log.clone(),
        &format!("Cross-Impl Frontier {fixture_idx} ({scenario})"),
        "Cross-implementation reducer fixture",
        "2026-05-02T00:00:00Z",
        "vela-cross-impl/0",
    )
    .expect("replay must succeed");

    let mut sorted = post.findings.clone();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    let expected_states: Vec<Value> = sorted.iter().map(finding_state).collect();

    let mut sorted_artifacts = post.artifacts.clone();
    sorted_artifacts.sort_by(|a, b| a.id.cmp(&b.id));
    let expected_artifacts: Vec<Value> = sorted_artifacts.iter().map(artifact_state).collect();

    // Inventory which event kinds appear in this fixture. Lets a
    // reviewer spot-check that the coverage promise is real per
    // fixture, not just "we ship some events."
    let mut kinds_seen: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for ev in &event_log {
        *kinds_seen.entry(ev.kind.to_string()).or_insert(0) += 1;
    }
    let kinds_value: Value = serde_json::to_value(&kinds_seen).unwrap();

    let fixture = json!({
        // bumped from "5" to "6". The entity-resolution event family
        // (finding.entity_resolved, finding.entity_added) was retired
        // from the protocol, so the entity_resolve + entity_added
        // coverage fixtures are gone. The per-finding digest never
        // covered entity fields, so the surviving fixtures' digests are
        // byte-identical across the bump.
        //
        // v0.108: bumped from "4" to "5". The empirical object families
        // (negative_results, trajectories, replications, predictions)
        // were retired from the protocol, so the digest now covers only
        // findings and artifacts. v4 readers that looked for the four
        // removed collections find them absent and treat them as empty.
        //
        // v0.55: the digest covers expected_artifacts, covering
        // artifact.asserted/reviewed/retracted and artifact tier changes.
        //
        // v0.53: added access_tier on each finding so `tier.set` events
        // on findings participate in the cross-impl byte-equivalence
        // promise.
        "fixture_version": "6",
        "schema_url": "https://vela.science/schema/cross-impl-reducer-fixture/v6",
        "doctrine": "every reducer implementation must agree on per-kind mutation rules across findings and artifacts",
        "scenario": scenario,
        "frontier_idx": fixture_idx,
        "stats": {
            "findings": findings.len(),
            "artifacts": post.artifacts.len(),
            "events": event_log.len(),
            "cascade_depth": if scenario == "cascade" {
                CASCADE_DEPTH.min(findings.len() - 1)
            } else {
                0
            },
            "kinds_seen": kinds_value,
        },
        "genesis_findings": findings,
        "event_log": event_log,
        "expected_states": expected_states,
        "expected_artifacts": expected_artifacts,
    });

    let path = out_dir.join(format!("cascade-fixture-{fixture_idx:02}.json"));
    std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).expect("write fixture");
    eprintln!("wrote {}", path.display());
}

#[test]
fn export_cross_impl_reducer_fixtures() {
    let out_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures");
    std::fs::create_dir_all(&out_dir).expect("create fixtures dir");

    // Fixtures 00..02 — cascade scenario (the original 3).
    for frontier_idx in 0..FIXTURE_FRONTIER_COUNT {
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_event_log(frontier_idx, &findings);
        export_one(&out_dir, frontier_idx, "cascade", findings, event_log);
    }

    // Fixture 03 — review-branches + confidence-revised scenario.
    // Exercises every status arm of finding.reviewed plus the
    // confidence-revised path with both integer and fractional
    // new_score values.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_review_branches_log(frontier_idx, &findings);
        export_one(
            &out_dir,
            frontier_idx,
            "review_branches",
            findings,
            event_log,
        );
    }

    // Fixture 04 — annotations + rejected scenario. Exercises both
    // finding.noted and finding.caveated (which share a reducer arm
    // but dispatch on distinct kinds) plus finding.rejected.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 1;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_annotations_log(frontier_idx, &findings);
        export_one(&out_dir, frontier_idx, "annotations", findings, event_log);
    }

    // Fixture slots 05 (negative_results) and 06 (trajectories) were
    // retired with the empirical object families; their frontier_idx
    // offsets (+2, +3) are intentionally skipped so the surviving
    // fixtures keep their established numbers.

    // Fixture 07 — tier.set lifecycle scenario (v0.51). Exercises the
    // dual-use access tier reclassification on the finding arm
    // (restricted + classified); the artifact arm is covered by
    // fixture 08.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 4;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_tier_set_log(frontier_idx, &findings);
        export_one(&out_dir, frontier_idx, "tier_set", findings, event_log);
    }

    // Fixture 08: generic Artifact lifecycle scenario. Exercises
    // artifact.asserted, artifact.reviewed, artifact.retracted, and a
    // tier.set event whose target type is artifact.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 5;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_artifacts_log(frontier_idx, &findings);
        export_one(&out_dir, frontier_idx, "artifacts", findings, event_log);
    }

    // v0.56: the locator-repair arm is exercised by
    // `build_locator_repair_log` in the coverage test below, but is
    // not exported as a standalone replayable fixture because its
    // atom-id references depend on the materialized evidence_atoms
    // produced by `sources::materialize_project`, which derives ids
    // from finding content. A self-consistent locator-repair fixture
    // needs the same materialization path the BBB curation work uses,
    // and that path lives in the integration test suite, not in the
    // genesis-only replay scaffold the cross-impl reducer relies on.

    // v0.105.7: export span-repair, entity-resolve, and entity-added
    // fixtures so the public conformance contract at
    // `conformance/fixtures/` exercises every reducer arm that
    // mutates a finding bundle in the genesis-only replay scaffold.
    // Pre-v0.105.7 the cross-impl coverage test asserted these arms
    // existed in some builder somewhere; v0.105.7 makes them part of
    // the exported fixture set so a second-implementation reducer
    // running `conformance/verify.py` exercises them too. The
    // post-replay finding digest covers `findings[]` only and these
    // arms each mutate a finding (evidence_spans, entity resolution
    // metadata, entities list), so the digest catches drift.

    // Fixture 09 — finding.span_repaired scenario (v0.57).
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 6;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_span_repair_log(frontier_idx, &findings);
        export_one(&out_dir, frontier_idx, "span_repair", findings, event_log);
    }

    // Fixtures 10 and 11 (finding.entity_resolved / finding.entity_added)
    // were retired with the entity-resolution event family. The slots are
    // left vacant; surviving fixtures keep their numbers.

    // Fixture 12 — side-table events. Pins the reducer arms that
    // mutate side tables outside the finding-effects digest
    // (released_diff_packs, verdict_conflicts, contradictions) into the
    // public conformance set, so all three reducers are exercised on
    // `diff_pack.released`, `diff_pack.reviewed`,
    // `verdict_conflict.resolved`, and `contradiction.resolved`.
    // Every one is a no-op on the seven digested collections, so the
    // expected_* arrays are the untouched genesis findings; a reducer
    // that ERRORS on any of these kinds (rather than implementing or
    // no-oping them) fails this fixture.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 9;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let mut event_log = build_diff_pack_released_log(frontier_idx, &findings);
        event_log.extend(build_diff_pack_reviewed_log(frontier_idx, &findings));
        event_log.extend(build_verdict_conflict_resolved_log(frontier_idx, &findings));
        event_log.extend(build_contradiction_resolved_log(frontier_idx, &findings));
        export_one(
            &out_dir,
            frontier_idx,
            "side_table_events",
            findings,
            event_log,
        );
    }

    // Fixture 13 — supersession + causal re-grading (v0.701). Both
    // kinds are no-ops on the finding-effects digest (superseded and
    // causal fields are outside it), so the expected_* arrays are the
    // untouched genesis findings; a reducer that ERRORS on either kind
    // fails this fixture. The replacement finding of a supersession
    // deliberately does NOT appear: the event is thin and the body
    // enters via loader genesis seeding, which is outside the
    // genesis-only replay scaffold.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 10;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let mut event_log = build_superseded_log(frontier_idx, &findings);
        event_log.extend(build_reinterpreted_causal_log(frontier_idx, &findings));
        export_one(
            &out_dir,
            frontier_idx,
            "supersede_and_causal",
            findings,
            event_log,
        );
    }

    // Fixture 14 — statement.attested (v0.702). No-op on the
    // finding-effects digest (attestations live in a side table); a
    // reducer that ERRORS on the kind fails this fixture.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 11;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_statement_attested_log(frontier_idx, &findings);
        export_one(
            &out_dir,
            frontier_idx,
            "statement_attested",
            findings,
            event_log,
        );
    }

    // Fixture 15 — attempt.claimed + statement.registered (v0.703).
    // Side-table kinds; expected_* arrays are untouched genesis findings.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 12;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_claim_and_register_log(frontier_idx, &findings);
        export_one(
            &out_dir,
            frontier_idx,
            "claim_and_register",
            findings,
            event_log,
        );
    }

    // Fixture 16 — supersession + dependency-cascade propagation.
    // Two findings: A (findings[0]) and B (findings[1]), where B carries
    // a `depends_on` link to A. The log supersedes A and then invalidates
    // B through the upstream cascade. Unlike the no-op coverage fixtures,
    // this one moves the finding-effects digest: B becomes contested and
    // gains a deterministic `ann_dep_*` cascade annotation, so a second
    // implementation must reproduce the propagation byte-for-byte.
    // A's supersession is digest-invisible (`flags.superseded` is outside
    // the digest) but the reducer must not error on the kind. The Rust
    // unit tests `supersession_is_local_no_dependent_cascade` and
    // `superseded_finding_never_renders_live` pin the flag-flip and the
    // no-zombie property directly.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 13;
        let mut findings: Vec<FindingBundle> =
            vec![make_finding(frontier_idx, 0), make_finding(frontier_idx, 1)];
        // B (findings[1]) depends on A (findings[0]). Overwrite the
        // synthetic forward "supports" link with an explicit depends_on
        // edge to A. Links are excluded from the content-address, so the
        // ids are unchanged.
        let a_id = findings[0].id.clone();
        findings[0].links = vec![];
        findings[1].links = vec![Link {
            target: a_id,
            link_type: "depends_on".into(),
            note: "B's premise rests on A".into(),
            inferred_by: "vela-cross-impl-fixture/0".into(),
            created_at: "2026-05-02T00:00:00Z".into(),
            mechanism: None,
        }];
        let event_log = build_supersession_propagation_log(frontier_idx, &findings);
        export_one(
            &out_dir,
            frontier_idx,
            "supersession_propagation",
            findings,
            event_log,
        );
    }

    // Fixture 17 — statement.registered with the finding-to-
    // registration edge (STATE_PLANE_MEMO appendix gap 5). The payload
    // gains an OPTIONAL `finding_id` field on the existing kind; the
    // registration side table is outside the finding-effects digest,
    // so the expected_* arrays are the untouched genesis findings and
    // a second implementation must accept (no-op) both the extended
    // and the legacy payload shapes without erroring.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 14;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_register_with_finding_edge_log(frontier_idx, &findings);
        export_one(
            &out_dir,
            frontier_idx,
            "register_with_finding_edge",
            findings,
            event_log,
        );
    }

    // v0.107.4: write fixtures.manifest.json with SHA-256 of every
    // exported fixture. THREAT_MODEL.md A12 names tampered fixtures
    // as a real attack surface; the manifest closes the integrity
    // half (a future cycle adds maintainer-key signing on top).
    // verify.py reads the manifest and refuses to run if any
    // fixture's bytes drift from the recorded digest.
    write_fixtures_manifest(&out_dir);
}

/// v0.107.4: produce a fixtures.manifest.json alongside the
/// exported cascade-fixture-*.json files. Digest is SHA-256 of
/// the file's exact bytes; bytes is the file size on disk.
/// Sorted by path so the manifest is deterministic.
fn write_fixtures_manifest(out_dir: &PathBuf) {
    use sha2::{Digest, Sha256};
    let mut entries: Vec<serde_json::Value> = Vec::new();
    let mut paths: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .expect("read fixtures dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|ext| ext == "json")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("cascade-fixture-"))
        })
        .collect();
    paths.sort();
    for path in &paths {
        let bytes = std::fs::read(path).expect("read fixture bytes");
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("fixture name utf8")
            .to_string();
        entries.push(json!({
            "path": name,
            "sha256": digest,
            "bytes": bytes.len(),
        }));
    }
    let manifest = json!({
        "schema": "vela.conformance-fixtures-manifest.v1",
        "doctrine": "every fixture's SHA-256 is recorded; verify.py refuses to run on a fixture whose bytes drift from the recorded digest. Closes THREAT_MODEL.md A12 (integrity half).",
        "fixtures": entries,
    });
    let manifest_path = out_dir.join("fixtures.manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write manifest");
    eprintln!("wrote {}", manifest_path.display());
}

/// Coverage-completeness assertion: the union of event kinds across
/// all exported fixtures must include every dispatch arm in
/// `apply_event`. v0.49.3 derives the required-kinds list from
/// `vela_protocol::reducer::REDUCER_MUTATION_KINDS` instead of a
/// hand-maintained mirror, so adding a new arm to the reducer
/// automatically extends the fixture coverage requirement (and the
/// `dispatch_handles_every_declared_kind` test in reducer.rs catches
/// the inverse drift).
#[test]
fn fixture_coverage_includes_every_reducer_arm() {
    use vela_protocol::reducer::REDUCER_MUTATION_KINDS;

    let frontier_idx = 0;
    let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
        .map(|i| make_finding(frontier_idx, i))
        .collect();

    let mut all_kinds: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for ev in build_event_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_review_branches_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_annotations_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_tier_set_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_artifacts_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_locator_repair_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_span_repair_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_diff_pack_released_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_diff_pack_reviewed_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_verdict_conflict_resolved_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_contradiction_resolved_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_superseded_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_reinterpreted_causal_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_statement_attested_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_claim_and_register_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }
    for ev in build_anchor_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind.to_string());
    }

    for kind in REDUCER_MUTATION_KINDS {
        assert!(
            all_kinds.contains(*kind),
            "cross-impl fixture coverage missing reducer arm: {kind} \
             (declared in REDUCER_MUTATION_KINDS but not exercised by \
             any fixture builder)"
        );
    }
}

/// Build the (A, B) genesis pair for the supersession-propagation
/// fixture: B (index 1) carries a `depends_on` link to A (index 0).
fn supersession_pair(frontier_idx: usize) -> Vec<FindingBundle> {
    let mut findings = vec![make_finding(frontier_idx, 0), make_finding(frontier_idx, 1)];
    let a_id = findings[0].id.clone();
    findings[0].links = vec![];
    findings[1].links = vec![Link {
        target: a_id,
        link_type: "depends_on".into(),
        note: "B's premise rests on A".into(),
        inferred_by: "vela-cross-impl-fixture/0".into(),
        created_at: "2026-05-02T00:00:00Z".into(),
        mechanism: None,
    }];
    findings
}

/// Reality check on what supersession actually does in the reducer.
/// Supersession is a LOCAL flag-flip on the old finding; it does NOT
/// auto-propagate down the `depends_on` edge. The dependent B only
/// changes because of the EXPLICIT `finding.dependency_invalidated`
/// cascade event — which sets `contested` and appends a deterministic
/// `ann_dep_*` annotation, both visible in the cross-impl digest.
#[test]
fn supersession_is_local_no_dependent_cascade() {
    let frontier_idx = 990;
    let findings = supersession_pair(frontier_idx);
    let a_id = findings[0].id.clone();
    let b_id = findings[1].id.clone();
    let log = normalize_event_log(
        frontier_idx,
        build_supersession_propagation_log(frontier_idx, &findings),
    );
    let post = replay_from_genesis(
        findings.clone(),
        log,
        "supersession-propagation",
        "reality test",
        "2026-05-02T00:00:00Z",
        "vela-cross-impl/0",
    )
    .expect("replay must succeed");

    let a = post.findings.iter().find(|f| f.id == a_id).unwrap();
    let b = post.findings.iter().find(|f| f.id == b_id).unwrap();

    // A: superseded (local), and ONLY superseded — supersession does not
    // contest or retract the old finding itself.
    assert!(a.flags.superseded, "A must carry flags.superseded");
    assert!(!a.flags.contested, "supersession must not contest A");
    assert!(!a.flags.retracted, "supersession must not retract A");

    // B: contested via the explicit cascade, with the deterministic
    // annotation. The `superseded` flag NEVER propagates to B.
    assert!(b.flags.contested, "B must be contested by the cascade");
    assert!(
        !b.flags.superseded,
        "superseded must NOT propagate down the depends_on edge"
    );
    assert!(
        b.annotations
            .iter()
            .any(|ann| ann.id.starts_with("ann_dep_")),
        "B must carry the deterministic cascade annotation"
    );
    // B's dependency on A survives — the link target still points at A.
    assert!(
        b.links
            .iter()
            .any(|l| l.target == a_id && l.link_type == "depends_on"),
        "B's depends_on edge to A is preserved"
    );
}

/// No-zombie property, as it EXISTS in the reducer: once a finding is
/// superseded it never re-renders as live. There is no reducer arm that
/// clears `flags.superseded`, so replay is monotone on the flag and a
/// second independent replay reproduces the superseded state bit-for-bit.
/// (The proposal-store hydration path `replayed_projection` is not used
/// here — these fixtures seed genesis directly — so the property is
/// asserted on the Project state, which the task permits.)
#[test]
fn superseded_finding_never_renders_live() {
    let frontier_idx = 991;
    let findings = supersession_pair(frontier_idx);
    let a_id = findings[0].id.clone();
    let log = normalize_event_log(
        frontier_idx,
        build_supersession_propagation_log(frontier_idx, &findings),
    );

    let replay = || {
        replay_from_genesis(
            findings.clone(),
            log.clone(),
            "supersession-propagation",
            "no-zombie test",
            "2026-05-02T00:00:00Z",
            "vela-cross-impl/0",
        )
        .expect("replay must succeed")
    };

    let first = replay();
    let a1 = first.findings.iter().find(|f| f.id == a_id).unwrap();
    assert!(a1.flags.superseded, "A is superseded after replay");

    // A second, independent replay never resurrects A as live: the
    // superseded flag persists and the finding projection (finding_hash,
    // which excludes links) is byte-stable across replays.
    let second = replay();
    let a2 = second.findings.iter().find(|f| f.id == a_id).unwrap();
    assert!(
        a2.flags.superseded,
        "A stays superseded across an independent replay (no zombie)"
    );
    assert_eq!(
        events::finding_hash(a1),
        events::finding_hash(a2),
        "the superseded finding's projection is stable — it never re-renders as live"
    );

    // Belnap-honest: superseded is a distinct terminal state. A is not
    // silently flipped back to an active (un-superseded, un-flagged) cell
    // by any projection in the replay path.
    assert!(
        !(!a2.flags.superseded && !a2.flags.retracted && !a2.flags.contested),
        "a superseded finding must never appear as a clean live cell"
    );
}
