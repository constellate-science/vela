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
    Evidence, Extraction, FindingBundle, Flags, Link, NegativeResult, NegativeResultKind,
    Provenance, Trajectory, TrajectoryStep, TrajectoryStepKind,
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

fn pin_negative_result(
    mut nr: NegativeResult,
    frontier_idx: usize,
    object_idx: usize,
) -> NegativeResult {
    nr.created = fixture_object_timestamp(frontier_idx, object_idx);
    nr.id =
        NegativeResult::content_address(&nr.kind, &nr.deposited_by, &nr.created, &nr.conditions);
    nr
}

fn pin_trajectory(mut traj: Trajectory, frontier_idx: usize, object_idx: usize) -> Trajectory {
    traj.created = fixture_object_timestamp(frontier_idx, object_idx);
    traj.id = Trajectory::content_address(&traj.target_findings, &traj.deposited_by, &traj.created);
    traj
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
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Cross-impl paper {frontier_idx}-{finding_idx}"),
        authors: vec![Author {
            name: "Cross-Impl A".into(),
            orcid: None,
        }],
        year: Some(2026),
        journal: Some("Cross Journal".into()),
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
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Cross-impl paper {frontier_idx}-{finding_idx}"),
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
        }));
    }
    log
}

/// v0.49 — Coverage fixture: exercises every NegativeResult lifecycle
/// arm. Each frontier deposits two NegativeResults (one
/// `registered_trial`, one `exploratory`), reviews one as contested,
/// and retracts the other.
///
/// Cross-impl note: the post-replay digest in `finding_state` covers
/// finding-state only. A second-implementation reducer that ignores
/// `negative_result.*` events will pass this fixture's expected_states
/// because no field in `Finding[]` mutates. v0.50 introduces a
/// negative-result digest that closes that gap; for v0.49 the fixture's
/// job is registering the kinds for coverage, not enforcing cross-impl
/// agreement on the new state collection.
fn build_negative_results_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let mut log = Vec::new();
    let actor_id = format!("reviewer:negative-results-{frontier_idx}");
    // Genesis: all findings asserted so the surface is comparable to
    // the other fixtures.
    for f in findings {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "negative-results-fixture genesis",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id}),
            caveats: vec![],
        }));
    }
    // First null: registered trial against findings[0] — adequately
    // powered, CI excludes the pre-registered MCID. The "informative
    // null" canonical shape.
    let trial_conditions = Conditions {
        text: format!("Phase III RCT, frontier {frontier_idx}"),
        species_verified: vec!["Homo sapiens".into()],
        species_unverified: vec![],
        in_vitro: false,
        in_vivo: true,
        human_data: true,
        clinical_trial: true,
        concentration_range: None,
        duration: Some("18 months".into()),
        age_group: Some("65+".into()),
        cell_type: None,
    };
    let trial_provenance = Provenance {
        source_type: "clinical_trial".into(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Trial readout, frontier {frontier_idx}"),
        authors: vec![],
        year: Some(2026),
        journal: None,
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
        citation_count: Some(0),
    };
    let trial_kind = NegativeResultKind::RegisteredTrial {
        endpoint: format!("Primary endpoint frontier {frontier_idx}"),
        intervention: "intervention-arm".into(),
        comparator: "placebo".into(),
        population: "early symptomatic, biomarker-positive".into(),
        n_enrolled: 1200,
        power: 0.9,
        effect_size_ci: (-0.05, 0.05),
        effect_size_threshold: Some(0.4),
        registry_id: Some(format!("NCT{frontier_idx:08}")),
    };
    let trial_null = pin_negative_result(
        NegativeResult::new(
            trial_kind,
            vec![findings[0].id.clone()],
            format!("trial-pi:cross-impl-{frontier_idx}"),
            trial_conditions,
            trial_provenance,
            "Pre-registered primary endpoint did not meet MCID; CI excludes it.",
        ),
        frontier_idx,
        100,
    );
    let trial_id = trial_null.id.clone();
    let trial_proposal = format!("vpr_nr_{frontier_idx}_trial");
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "negative_result.asserted".to_string(),
        target: StateTarget {
            r#type: "negative_result".to_string(),
            id: trial_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "deposit informative null from pre-registered trial".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": trial_proposal,
            "negative_result": trial_null,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    // Second null: exploratory wet-lab dead end. No statistical bound;
    // captures the reagent + observation tuple.
    let lab_conditions = Conditions {
        text: format!("In vitro, frontier {frontier_idx} synthesis attempts"),
        species_verified: vec![],
        species_unverified: vec![],
        in_vitro: true,
        in_vivo: false,
        human_data: false,
        clinical_trial: false,
        concentration_range: Some("1-10 mM".into()),
        duration: Some("72h".into()),
        age_group: None,
        cell_type: None,
    };
    let lab_provenance = Provenance {
        source_type: "lab_notebook".into(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Lab notebook excerpt, frontier {frontier_idx}"),
        authors: vec![],
        year: Some(2026),
        journal: None,
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
        citation_count: Some(0),
    };
    let lab_kind = NegativeResultKind::Exploratory {
        reagent: format!("CompoundX-{frontier_idx}"),
        observation: "no measurable binding under any tested condition".into(),
        attempts: 4,
    };
    let lab_null = pin_negative_result(
        NegativeResult::new(
            lab_kind,
            vec![],
            format!("lab:cross-impl-{frontier_idx}"),
            lab_conditions,
            lab_provenance,
            "Exhausted reasonable parameter sweep; documenting before scope expansion.",
        ),
        frontier_idx,
        101,
    );
    let lab_id = lab_null.id.clone();
    let lab_proposal = format!("vpr_nr_{frontier_idx}_lab");
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "negative_result.asserted".to_string(),
        target: StateTarget {
            r#type: "negative_result".to_string(),
            id: lab_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "deposit exploratory wet-lab dead end".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": lab_proposal,
            "negative_result": lab_null,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    // Review the trial null as contested (a second reviewer thinks the
    // CI is consistent with a smaller subgroup effect).
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "negative_result.reviewed".to_string(),
        target: StateTarget {
            r#type: "negative_result".to_string(),
            id: trial_id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:second-reader-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "subgroup analysis suggests effect concentrated in APOE4-positive".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_nr_{frontier_idx}_trial_review"),
            "status": "contested",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    // Retract the lab null (the reagent batch turned out to have been
    // miscatalogued; the failure was not what was claimed).
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "negative_result.retracted".to_string(),
        target: StateTarget {
            r#type: "negative_result".to_string(),
            id: lab_id,
        },
        actor: StateActor {
            id: actor_id,
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "reagent batch miscatalogued; retract and re-deposit pending".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_nr_{frontier_idx}_lab_retract"),
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    log
}

/// v0.50 — Coverage fixture: exercises every Trajectory lifecycle
/// arm. Each frontier opens one trajectory targeting findings[0],
/// appends three steps (hypothesis → tried → ruled_out), reviews the
/// trajectory as needs_revision, and retracts a second trajectory
/// opened for findings[1] without steps.
///
/// Cross-impl note: same finding-state-only digest situation as the
/// negative_result fixture. v0.50 follow-up tightens the digest.
fn build_trajectories_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let mut log = Vec::new();
    let actor_id = format!("reviewer:trajectories-{frontier_idx}");
    for f in findings {
        let proposal_id = format!("vpr_{}_{}", frontier_idx, &f.id[3..]);
        log.push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &f.id,
            actor_id: &actor_id,
            actor_type: "human",
            reason: "trajectories-fixture genesis",
            before_hash: NULL_HASH,
            after_hash: NULL_HASH,
            payload: json!({"proposal_id": proposal_id}),
            caveats: vec![],
        }));
    }

    // Trajectory 1: opens against findings[0], gets three steps,
    // is then reviewed as needs_revision.
    let traj1 = pin_trajectory(
        Trajectory::new(
            vec![findings[0].id.clone()],
            format!("agent:scout-{frontier_idx}"),
            format!(
                "Search path that arrived at finding {}",
                &findings[0].id[..8]
            ),
        ),
        frontier_idx,
        200,
    );
    let traj1_id = traj1.id.clone();
    let traj1_value = serde_json::to_value(&traj1).expect("serialize trajectory");
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "trajectory.created".to_string(),
        target: StateTarget {
            r#type: "trajectory".to_string(),
            id: traj1_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "open trajectory for cross-impl fixture".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_traj_{frontier_idx}_open"),
            "trajectory": traj1_value,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    let step_kinds = [
        (
            TrajectoryStepKind::Hypothesis,
            "Considered: protein-X is the key regulator.",
        ),
        (
            TrajectoryStepKind::Tried,
            "Ran knockout in mouse model; observed partial phenotype.",
        ),
        (
            TrajectoryStepKind::RuledOut,
            "Ruled out: knockout phenotype attributable to compensating paralog, not protein-X.",
        ),
    ];
    for (i, (kind, desc)) in step_kinds.iter().enumerate() {
        let step = TrajectoryStep::new(
            &traj1_id,
            kind.clone(),
            desc.to_string(),
            format!("agent:scout-{frontier_idx}"),
            Some(format!("2026-05-04T0{i}:00:00Z")),
            vec![],
        );
        let step_value = serde_json::to_value(&step).expect("serialize step");
        log.push(StateEvent {
            schema: events::EVENT_SCHEMA.to_string(),
            id: String::new(),
            kind: "trajectory.step_appended".to_string(),
            target: StateTarget {
                r#type: "trajectory".to_string(),
                id: traj1_id.clone(),
            },
            actor: StateActor {
                id: format!("agent:scout-{frontier_idx}"),
                r#type: "agent".to_string(),
            },
            timestamp: chrono::Utc::now().to_rfc3339(),
            reason: format!("append step {i}"),
            before_hash: NULL_HASH.to_string(),
            after_hash: NULL_HASH.to_string(),
            payload: json!({
                "proposal_id": format!("vpr_step_{frontier_idx}_{i}"),
                "parent_trajectory_id": traj1_id,
                "step": step_value,
            }),
            caveats: vec![],
            signature: None,
            schema_artifact_id: None,
        });
    }

    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "trajectory.reviewed".to_string(),
        target: StateTarget {
            r#type: "trajectory".to_string(),
            id: traj1_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "step 3 needs more support before this is canonical".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_traj_{frontier_idx}_review"),
            "status": "needs_revision",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    // Trajectory 2: opened, then immediately retracted (the search
    // turned out to be misframed; keep it in replay history).
    let traj2 = pin_trajectory(
        Trajectory::new(
            vec![findings[1].id.clone()],
            format!("agent:scout-{frontier_idx}"),
            format!("Misframed search against finding {}", &findings[1].id[..8]),
        ),
        frontier_idx,
        201,
    );
    let traj2_id = traj2.id.clone();
    let traj2_value = serde_json::to_value(&traj2).expect("serialize trajectory");
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "trajectory.created".to_string(),
        target: StateTarget {
            r#type: "trajectory".to_string(),
            id: traj2_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "open trajectory before noticing reframe".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_traj_{frontier_idx}_open2"),
            "trajectory": traj2_value,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "trajectory.retracted".to_string(),
        target: StateTarget {
            r#type: "trajectory".to_string(),
            id: traj2_id,
        },
        actor: StateActor {
            id: actor_id,
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "premise of the search was wrong; reframing".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_traj_{frontier_idx}_retract"),
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

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
        }));
    }

    let provenance = |title: String| Provenance {
        source_type: "clinical_trial".into(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: Some(format!("https://example.org/frontier-{frontier_idx}/trial")),
        title,
        authors: vec![],
        year: Some(2026),
        journal: None,
        license: Some("CC0-1.0".into()),
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
        citation_count: Some(0),
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
        kind: "artifact.asserted".to_string(),
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
        kind: "artifact.reviewed".to_string(),
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
        kind: "tier.set".to_string(),
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
        kind: "artifact.asserted".to_string(),
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
        kind: "artifact.retracted".to_string(),
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
/// across all three tierable kernel object types (finding,
/// negative_result, trajectory). Asserts findings, opens a
/// negative_result + trajectory targeting findings[0], then issues
/// `tier.set` events to reclassify each at restricted/classified
/// tiers. Cross-impl note: the post-replay digest in `finding_state`
/// covers finding-state only — this fixture exists for kind-coverage
/// of the `tier.set` arm; v0.51.x can extend the digest to include
/// the access_tier field on each kernel object.
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
        }));
    }

    // Open one NegativeResult against findings[0] so we have one of
    // each tierable kind to reclassify.
    let nr_kind = NegativeResultKind::Exploratory {
        reagent: format!("ReagentX-{frontier_idx}"),
        observation: "no detectable activity at any tested concentration".into(),
        attempts: 2,
    };
    let nr_conditions = Conditions {
        text: "in vitro fixture".into(),
        species_verified: vec![],
        species_unverified: vec![],
        in_vitro: true,
        in_vivo: false,
        human_data: false,
        clinical_trial: false,
        concentration_range: None,
        duration: None,
        age_group: None,
        cell_type: None,
    };
    let nr_provenance = Provenance {
        source_type: "lab_notebook".into(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Tier fixture lab note {frontier_idx}"),
        authors: vec![],
        year: Some(2026),
        journal: None,
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
        citation_count: Some(0),
    };
    let nr = pin_negative_result(
        NegativeResult::new(
            nr_kind,
            vec![findings[0].id.clone()],
            format!("lab:tier-fixture-{frontier_idx}"),
            nr_conditions,
            nr_provenance,
            "Fixture exploratory null for tier.set coverage.",
        ),
        frontier_idx,
        300,
    );
    let nr_id = nr.id.clone();
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "negative_result.asserted".to_string(),
        target: StateTarget {
            r#type: "negative_result".to_string(),
            id: nr_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "deposit null for tier-set fixture".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_tier_{frontier_idx}_nr"),
            "negative_result": nr,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    // Open a Trajectory against findings[0].
    let traj = pin_trajectory(
        Trajectory::new(
            vec![findings[0].id.clone()],
            format!("agent:tier-fixture-{frontier_idx}"),
            "Fixture trajectory for tier.set coverage.",
        ),
        frontier_idx,
        301,
    );
    let traj_id = traj.id.clone();
    log.push(StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "trajectory.created".to_string(),
        target: StateTarget {
            r#type: "trajectory".to_string(),
            id: traj_id.clone(),
        },
        actor: StateActor {
            id: actor_id.clone(),
            r#type: "human".to_string(),
        },
        timestamp: chrono::Utc::now().to_rfc3339(),
        reason: "open trajectory for tier-set fixture".into(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_tier_{frontier_idx}_traj"),
            "trajectory": traj,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    });

    // Reclassify findings[0] to restricted, the negative_result to
    // restricted, and the trajectory to classified.
    let reclassifications = [
        (
            "finding",
            findings[0].id.clone(),
            "restricted",
            "Finding reclassified for IBC review.",
        ),
        (
            "negative_result",
            nr_id,
            "restricted",
            "Null reclassified — readout includes capability-relevant detail.",
        ),
        (
            "trajectory",
            traj_id,
            "classified",
            "Trajectory reclassified — search path documents synthesis steps above DURC threshold.",
        ),
    ];
    for (i, (object_type, object_id, new_tier, reason)) in reclassifications.iter().enumerate() {
        log.push(StateEvent {
            schema: events::EVENT_SCHEMA.to_string(),
            id: String::new(),
            kind: "tier.set".to_string(),
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
        kind: "evidence_atom.locator_repaired".to_string(),
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
        kind: "finding.span_repaired".to_string(),
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

/// v0.57: Coverage fixture for the `finding.entity_resolved` reducer
/// arm. Builds an event targeting an entity by name on the first
/// fixture finding.
fn build_entity_resolve_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let target_finding = &findings[0];
    // make_finding seeds at least one entity; pick the first by name.
    let entity_name = target_finding
        .assertion
        .entities
        .first()
        .map(|e| e.name.clone())
        .unwrap_or_else(|| format!("fixture-entity-{frontier_idx}"));
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "finding.entity_resolved".to_string(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: target_finding.id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:entity-resolve-fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Mechanical entity resolution".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_entity_resolve_{frontier_idx}"),
            "entity_name": entity_name,
            "source": "fixture",
            "id": format!("F-{frontier_idx}"),
            "confidence": 0.95,
            "resolution_method": "manual",
            "resolution_provenance": "delegated_human_curation",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// v0.79: build a `finding.entity_added` log. Adds a new entity
/// tag to a finding that the make_finding seed didn't include,
/// proving the v0.79.1 reducer arm is exercised in cross-impl
/// fixtures. Idempotent: re-applying with the same name is a
/// no-op so the cross-impl byte-equivalence promise holds.
fn build_entity_added_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let target_finding = &findings[0];
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "finding.entity_added".to_string(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: target_finding.id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:entity-add-fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture-level entity-add".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_entity_add_{frontier_idx}"),
            "entity_name": format!("fixture-tag-{frontier_idx}"),
            "entity_type": "other",
            "reason": "cross-impl fixture",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// v0.64: federation event fixture builder. Exercises the no-op
/// contract for `frontier.synced_with_peer`,
/// `frontier.conflict_detected`, and `frontier.conflict_resolved`
/// at the cross-impl fixture level. Each event lands at the
/// frontier-observation level; reducer arms are no-ops on
/// finding state. The cross-impl finding-effects digest covers
/// findings only, so these contribute zero to the digest by
/// design. The fixture's job is to prove that adding them to a
/// log doesn't perturb the cross-impl byte-equivalence promise.
fn build_federation_events_log(
    frontier_idx: usize,
    _findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let frontier_id = format!("vfr_fixture_{frontier_idx:08x}");
    let conflict_event_id = format!("vev_fixture_conflict_{frontier_idx}");
    let synced = StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "frontier.synced_with_peer".to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.clone(),
        },
        actor: StateActor {
            id: "federation".to_string(),
            r#type: "system".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture sync pass".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "peer_id": format!("peer:fixture-east-{frontier_idx}"),
            "peer_snapshot_hash": "fixture_peer_snapshot",
            "our_snapshot_hash": "fixture_our_snapshot",
            "divergence_count": 1,
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };
    let detected = StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: conflict_event_id.clone(),
        kind: "frontier.conflict_detected".to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.clone(),
        },
        actor: StateActor {
            id: "federation".to_string(),
            r#type: "system".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 1),
        reason: "Fixture conflict".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "peer_id": format!("peer:fixture-east-{frontier_idx}"),
            "finding_id": format!("vf_fixture_{frontier_idx}"),
            "kind": "verdict_disagreement",
            "detail": "Fixture peer disagrees on review_state",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };
    let resolved = StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "frontier.conflict_resolved".to_string(),
        target: StateTarget {
            r#type: "frontier_observation".to_string(),
            id: frontier_id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 2),
        reason: "Fixture resolution".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "proposal_id": format!("vpr_fixture_resolve_{frontier_idx}"),
            "conflict_event_id": conflict_event_id,
            "resolved_by": format!("reviewer:fixture-{frontier_idx}"),
            "resolution_note": "Reviewer accepts our view",
        }),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };
    vec![synced, detected, resolved]
}

/// v0.67: bridge.reviewed fixture builder. The reducer arm is a
/// no-op on `Project.findings`; bridges live in `.vela/bridges/` as
/// a side table and the verdict is projected onto `Bridge.status` at
/// read time. The fixture's job is to prove that adding a
/// bridge.reviewed event to a log doesn't perturb the cross-impl
/// finding-effects digest.
fn build_bridge_reviewed_log(
    frontier_idx: usize,
    _findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    let bridge_id = format!("vbr_fixture_{frontier_idx:08x}");
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "bridge.reviewed".to_string(),
        target: StateTarget {
            r#type: "bridge".to_string(),
            id: bridge_id.clone(),
        },
        actor: StateActor {
            id: format!("reviewer:bridge-fixture-{frontier_idx}"),
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture bridge review verdict".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload: json!({
            "bridge_id": bridge_id,
            "status": "confirmed",
            "note": "Fixture verdict for cross-impl coverage",
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
        kind: "finding.superseded".to_string(),
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
        kind: "assertion.reinterpreted_causal".to_string(),
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
        kind: "statement.attested".to_string(),
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
        kind: "diff_pack.released".to_string(),
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
        kind: "diff_pack.reviewed".to_string(),
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
        kind: "verdict_conflict.resolved".to_string(),
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
        kind: "contradiction.resolved".to_string(),
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

/// v0.70: replication.deposited fixture builder. The reducer arm
/// appends a `Replication` to `Project.replications`. It does NOT
/// touch `Project.findings`, so the cross-impl finding-effects digest
/// is unchanged. The payload carries a real, content-addressed
/// `Replication` so the deposit succeeds and matches the v0.70
/// validator.
fn build_replication_deposited_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    use vela_protocol::bundle::Replication;

    let target_finding = &findings[0];
    let attempted_by = format!("lab:fixture-replication-{frontier_idx}");
    let outcome = "replicated".to_string();
    let conditions = Conditions {
        text: format!("Fixture replication conditions {frontier_idx}"),
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
    let evidence = Evidence {
        evidence_type: "experimental".into(),
        model_system: "mouse".into(),
        species: Some("Mus musculus".into()),
        method: "Independent replication, Western blot".into(),
        sample_size: Some("n=24".into()),
        effect_size: None,
        p_value: Some("p<0.05".into()),
        replicated: true,
        replication_count: Some(1),
        evidence_spans: vec![],
    };
    let provenance = Provenance {
        source_type: "preprint".into(),
        doi: Some(format!(
            "10.0000/crossimpl.replication.frontier{frontier_idx:04}"
        )),
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: format!("Fixture replication report {frontier_idx}"),
        authors: vec![Author {
            name: "Cross-Impl Replicator".into(),
            orcid: None,
        }],
        year: Some(2026),
        journal: Some("Cross Replications".into()),
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
        citation_count: Some(0),
    };
    // Build by hand so `created` is deterministic. `Replication::new`
    // would stamp `Utc::now()` and break fixture stability.
    let id = Replication::content_address(&target_finding.id, &attempted_by, &conditions, &outcome);
    let rep = Replication {
        id,
        target_finding: target_finding.id.clone(),
        attempted_by: attempted_by.clone(),
        outcome: outcome.clone(),
        evidence,
        conditions,
        provenance,
        notes: "Fixture replication note".to_string(),
        created: fixture_object_timestamp(frontier_idx, 0),
        previous_attempt: None,
    };
    let payload = json!({
        "proposal_id": format!("vpr_replication_deposit_{frontier_idx}"),
        "replication": rep,
    });
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "replication.deposited".to_string(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: target_finding.id.clone(),
        },
        actor: StateActor {
            id: attempted_by,
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture replication deposit".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload,
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }]
}

/// v0.70: prediction.deposited fixture builder. The reducer arm
/// appends a `Prediction` to `Project.predictions`. It does NOT
/// touch `Project.findings`, so the cross-impl finding-effects digest
/// is unchanged. The payload carries a real, content-addressed
/// `Prediction` so the deposit succeeds and matches the v0.70
/// validator.
fn build_prediction_deposited_log(
    frontier_idx: usize,
    findings: &[FindingBundle],
) -> Vec<events::StateEvent> {
    use vela_protocol::bundle::{ExpectedOutcome, Prediction};

    let target_finding = &findings[0];
    let made_by = format!("forecaster:fixture-prediction-{frontier_idx}");
    let claim_text =
        format!("Fixture prediction {frontier_idx}: replication will confirm at p<0.05.");
    let predicted_at = fixture_object_timestamp(frontier_idx, 0);
    let resolution_criterion =
        "An independent lab posts a replication with the same outcome.".to_string();
    let expected_outcome = ExpectedOutcome::Affirmed;
    let conditions = Conditions {
        text: format!("Fixture prediction conditions {frontier_idx}"),
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
    let id = Prediction::content_address(
        &claim_text,
        &made_by,
        &predicted_at,
        &resolution_criterion,
        &expected_outcome,
    );
    let pred = Prediction {
        id,
        claim_text,
        target_findings: vec![target_finding.id.clone()],
        predicted_at,
        resolves_by: Some("2027-05-02T00:00:00Z".to_string()),
        resolution_criterion,
        expected_outcome,
        made_by: made_by.clone(),
        confidence: 0.6,
        conditions,
        expired_unresolved: false,
    };
    let payload = json!({
        "proposal_id": format!("vpr_prediction_deposit_{frontier_idx}"),
        "prediction": pred,
    });
    vec![StateEvent {
        schema: events::EVENT_SCHEMA.to_string(),
        id: String::new(),
        kind: "prediction.deposited".to_string(),
        target: StateTarget {
            r#type: "finding".to_string(),
            id: target_finding.id.clone(),
        },
        actor: StateActor {
            id: made_by,
            r#type: "human".to_string(),
        },
        timestamp: fixture_timestamp(frontier_idx, 0),
        reason: "Fixture prediction deposit".to_string(),
        before_hash: NULL_HASH.to_string(),
        after_hash: NULL_HASH.to_string(),
        payload,
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

/// v0.53: Reducer-effects digest per NegativeResult. Captures only
/// what the reducer mutates: review_state, retracted, access_tier.
/// The kind+conditions+provenance fields are static after deposit.
fn negative_result_state(n: &vela_protocol::bundle::NegativeResult) -> Value {
    let review_state = n
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
        "id": n.id,
        "retracted": n.retracted,
        "review_state": review_state,
        "access_tier": n.access_tier.canonical(),
    })
}

/// v0.53: Reducer-effects digest per Trajectory. Captures
/// review_state, retracted, access_tier, and the ordered list of
/// step ids so a divergent step-append produces a visible diff at
/// the digest level.
fn trajectory_state(t: &vela_protocol::bundle::Trajectory) -> Value {
    let review_state = t
        .review_state
        .as_ref()
        .map(|s| match s {
            vela_protocol::bundle::ReviewState::Accepted => "accepted",
            vela_protocol::bundle::ReviewState::Contested => "contested",
            vela_protocol::bundle::ReviewState::NeedsRevision => "needs_revision",
            vela_protocol::bundle::ReviewState::Rejected => "rejected",
        })
        .unwrap_or("none");
    let step_ids: Vec<String> = t.steps.iter().map(|s| s.id.clone()).collect();
    json!({
        "id": t.id,
        "retracted": t.retracted,
        "review_state": review_state,
        "access_tier": t.access_tier.canonical(),
        "step_ids": step_ids,
    })
}

/// v0.106.5: Reducer-effects digest per Replication. The v0.70
/// replication.deposited reducer arm is idempotent-append on
/// state["replications"]; the digest captures id, target_finding,
/// and outcome so a divergent deposit (different bucket, missed
/// idempotency check, dropped entry) becomes visible at the
/// digest level.
fn replication_state(r: &vela_protocol::bundle::Replication) -> Value {
    json!({
        "id": r.id,
        "target_finding": r.target_finding,
        "outcome": r.outcome,
    })
}

/// v0.106.5: Reducer-effects digest per Prediction. Same shape
/// rationale as Replication. Captures id, made_by, and
/// expired_unresolved so calibration drift (an implementation
/// flipping expired_unresolved differently) becomes visible.
fn prediction_state(p: &vela_protocol::bundle::Prediction) -> Value {
    json!({
        "id": p.id,
        "made_by": p.made_by,
        "expired_unresolved": p.expired_unresolved,
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

    // v0.53: extended digest covers negative_results and trajectories
    // so tier.set, negative_result.*, and trajectory.* events
    // participate in the cross-impl byte-equivalence promise.
    let mut sorted_nrs = post.negative_results.clone();
    sorted_nrs.sort_by(|a, b| a.id.cmp(&b.id));
    let expected_negative_results: Vec<Value> =
        sorted_nrs.iter().map(negative_result_state).collect();

    let mut sorted_trajs = post.trajectories.clone();
    sorted_trajs.sort_by(|a, b| a.id.cmp(&b.id));
    let expected_trajectories: Vec<Value> = sorted_trajs.iter().map(trajectory_state).collect();

    let mut sorted_artifacts = post.artifacts.clone();
    sorted_artifacts.sort_by(|a, b| a.id.cmp(&b.id));
    let expected_artifacts: Vec<Value> = sorted_artifacts.iter().map(artifact_state).collect();

    // v0.106.5: extend the digest to cover replications and
    // predictions. The v0.70 deposit arms idempotent-append to
    // state["replications"] / state["predictions"]; pre-v0.106.5
    // these collections were not part of the cross-impl
    // byte-equivalence promise, so a Python or third-language
    // implementation could silently drop a deposit and still pass
    // verify.py.
    let mut sorted_replications = post.replications.clone();
    sorted_replications.sort_by(|a, b| a.id.cmp(&b.id));
    let expected_replications: Vec<Value> =
        sorted_replications.iter().map(replication_state).collect();

    let mut sorted_predictions = post.predictions.clone();
    sorted_predictions.sort_by(|a, b| a.id.cmp(&b.id));
    let expected_predictions: Vec<Value> =
        sorted_predictions.iter().map(prediction_state).collect();

    // Inventory which event kinds appear in this fixture. Lets a
    // reviewer spot-check that the coverage promise is real per
    // fixture, not just "we ship some events."
    let mut kinds_seen: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for ev in &event_log {
        *kinds_seen.entry(ev.kind.clone()).or_insert(0) += 1;
    }
    let kinds_value: Value = serde_json::to_value(&kinds_seen).unwrap();

    let fixture = json!({
        // v0.106.5: bumped from "3" to "4". The digest now includes
        // expected_replications and expected_predictions, covering
        // the v0.70 deposit reducer arms. v3 readers see five
        // collections; v4 readers see seven and fail loud on
        // divergence in either deposit collection.
        //
        // v0.55: bumped from "2" to "3". The digest now includes
        // expected_artifacts, covering artifact.asserted/reviewed/
        // retracted and artifact tier changes.
        //
        // v0.53: bumped from "1" to "2". The digest added
        // expected_negative_results, expected_trajectories, and
        // access_tier on each finding. Older v1 readers that only
        // check expected_states will still match the findings array
        // but won't see the new fields; v2 readers fail loud on a
        // mismatch in any of the three collections.
        "fixture_version": "4",
        "schema_url": "https://vela.science/schema/cross-impl-reducer-fixture/v4",
        "doctrine": "every reducer implementation must agree on per-kind mutation rules across findings, negative_results, trajectories, artifacts, replications, and predictions",
        "scenario": scenario,
        "frontier_idx": fixture_idx,
        "stats": {
            "findings": findings.len(),
            "negative_results": post.negative_results.len(),
            "trajectories": post.trajectories.len(),
            "artifacts": post.artifacts.len(),
            "replications": post.replications.len(),
            "predictions": post.predictions.len(),
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
        "expected_negative_results": expected_negative_results,
        "expected_trajectories": expected_trajectories,
        "expected_artifacts": expected_artifacts,
        "expected_replications": expected_replications,
        "expected_predictions": expected_predictions,
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

    // Fixture 05 — NegativeResult lifecycle scenario. Exercises
    // negative_result.asserted (registered_trial + exploratory),
    // negative_result.reviewed, and negative_result.retracted.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 2;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_negative_results_log(frontier_idx, &findings);
        export_one(
            &out_dir,
            frontier_idx,
            "negative_results",
            findings,
            event_log,
        );
    }

    // Fixture 06 — Trajectory lifecycle scenario (v0.50). Exercises
    // trajectory.created (twice), trajectory.step_appended (3 steps:
    // hypothesis, tried, ruled_out), trajectory.reviewed
    // (needs_revision), and trajectory.retracted.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 3;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_trajectories_log(frontier_idx, &findings);
        export_one(&out_dir, frontier_idx, "trajectories", findings, event_log);
    }

    // Fixture 07 — tier.set lifecycle scenario (v0.51). Exercises
    // the dual-use access tier reclassification across all three
    // tierable object types (finding, negative_result, trajectory).
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
    //
    // v0.73: also appends `bridge.reviewed`, `replication.deposited`,
    // and `prediction.deposited` events so the v0.67/v0.70/v0.71 event
    // kinds round-trip through Rust to JSON to Python at file level
    // (not just in-process). All three are no-ops on
    // findings/negative_results/trajectories/artifacts, so the existing
    // expected_* digests stay byte-identical and the no-op invariant is
    // proven across implementations. The replication/prediction
    // deposits land on Project.replications / Project.predictions; the
    // cross-impl finding-effects digest covers findings only, so digest
    // unchanged is the right invariant. A standalone deposits digest
    // is left for a future bump.
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 5;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let mut event_log = build_artifacts_log(frontier_idx, &findings);
        event_log.extend(build_bridge_reviewed_log(frontier_idx, &findings));
        event_log.extend(build_replication_deposited_log(frontier_idx, &findings));
        event_log.extend(build_prediction_deposited_log(frontier_idx, &findings));
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

    // Fixture 10 — finding.entity_resolved scenario (v0.57).
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 7;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_entity_resolve_log(frontier_idx, &findings);
        export_one(
            &out_dir,
            frontier_idx,
            "entity_resolve",
            findings,
            event_log,
        );
    }

    // Fixture 11 — finding.entity_added scenario (v0.79).
    {
        let frontier_idx = FIXTURE_FRONTIER_COUNT + 8;
        let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
            .map(|i| make_finding(frontier_idx, i))
            .collect();
        let event_log = build_entity_added_log(frontier_idx, &findings);
        export_one(&out_dir, frontier_idx, "entity_added", findings, event_log);
    }

    // Fixture 12 — side-table / federation events. Pins the reducer
    // arms that mutate side tables outside the finding-effects digest
    // (released_diff_packs, verdict_conflicts, contradictions) plus the
    // federation observation trio into the public conformance set, so
    // all three reducers are exercised on `diff_pack.released`,
    // `diff_pack.reviewed`, `verdict_conflict.resolved`,
    // `contradiction.resolved`, `frontier.synced_with_peer`,
    // `frontier.conflict_detected`, and `frontier.conflict_resolved`.
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
        event_log.extend(build_federation_events_log(frontier_idx, &findings));
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
        all_kinds.insert(ev.kind);
    }
    for ev in build_review_branches_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_annotations_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_negative_results_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_trajectories_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_tier_set_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_artifacts_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_locator_repair_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_span_repair_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_entity_resolve_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_entity_added_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_diff_pack_released_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_diff_pack_reviewed_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_verdict_conflict_resolved_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_contradiction_resolved_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_superseded_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_reinterpreted_causal_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
    }
    for ev in build_statement_attested_log(frontier_idx, &findings) {
        all_kinds.insert(ev.kind);
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

/// v0.64: federation event fixture builder smoke. The fixture is
/// intentionally not part of the cross-impl finding-effects digest
/// (federation events are no-ops on finding state). This test
/// proves the builder produces a well-formed three-event log
/// with the expected kinds and the conflict + resolved events
/// pair correctly by `conflict_event_id`.
#[test]
fn federation_events_fixture_pairs_conflict_with_resolution() {
    let frontier_idx = 7;
    let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
        .map(|i| make_finding(frontier_idx, i))
        .collect();
    let log = build_federation_events_log(frontier_idx, &findings);
    assert_eq!(log.len(), 3, "expected synced + detected + resolved");

    let kinds: Vec<&str> = log.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        vec![
            "frontier.synced_with_peer",
            "frontier.conflict_detected",
            "frontier.conflict_resolved",
        ]
    );

    let detected = &log[1];
    let resolved = &log[2];
    assert_eq!(
        detected.id,
        resolved
            .payload
            .get("conflict_event_id")
            .and_then(|v| v.as_str())
            .unwrap_or(""),
        "resolved event must reference detected event by id"
    );
}

/// v0.72 polish: the v0.67 + v0.70 + v0.71 event kinds
/// (`bridge.reviewed`, `replication.deposited`,
/// `prediction.deposited`) all leave `Project.findings` untouched.
/// This mirrors the v0.59 federation no-op test in
/// `reducer.rs::tests::federation_events_are_finding_state_noops` at
/// the cross-impl fixture level: each builder's event log applies to
/// an empty Project without error and leaves the finding-state
/// fingerprint identical. Replication and prediction events DO
/// mutate `Project.replications` / `Project.predictions`; the
/// cross-impl finding-effects digest covers findings only, so digest
/// unchanged is the right invariant.
#[test]
fn v067_v071_events_are_finding_state_noops() {
    use vela_protocol::project;
    use vela_protocol::reducer::apply_event;

    let frontier_idx = 8;
    let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
        .map(|i| make_finding(frontier_idx, i))
        .collect();

    let cases: Vec<(&str, Vec<events::StateEvent>)> = vec![
        (
            "bridge.reviewed",
            normalize_event_log(
                frontier_idx,
                build_bridge_reviewed_log(frontier_idx, &findings),
            ),
        ),
        (
            "replication.deposited",
            normalize_event_log(
                frontier_idx,
                build_replication_deposited_log(frontier_idx, &findings),
            ),
        ),
        (
            "prediction.deposited",
            normalize_event_log(
                frontier_idx,
                build_prediction_deposited_log(frontier_idx, &findings),
            ),
        ),
    ];

    for (label, log) in cases {
        let mut state = project::assemble(
            "v072-noop-fixture",
            findings.clone(),
            0,
            0,
            "Cross-impl no-op coverage for v0.67 + v0.70 + v0.71 event kinds",
        );
        let findings_before: Vec<FindingBundle> = state.findings.clone();
        let findings_before_bytes =
            serde_json::to_vec(&findings_before).expect("canonicalize findings_before");

        for event in &log {
            apply_event(&mut state, event)
                .unwrap_or_else(|e| panic!("{label} rejected by reducer: {e}"));
        }

        let findings_after_bytes =
            serde_json::to_vec(&state.findings).expect("canonicalize findings_after");
        assert_eq!(
            findings_before_bytes, findings_after_bytes,
            "{label} mutated Project.findings; expected no-op on finding state"
        );
    }
}

/// v0.72 polish: smoke test for each new builder. Each builder
/// produces a single, well-typed event of the expected kind. The
/// cross-impl harness already proves byte-equivalence on the
/// finding-state digest; this asserts the builder shape so a
/// regression in payload schema fails loudly here rather than
/// downstream in a Python parse error.
#[test]
fn v067_v071_builders_produce_well_typed_events() {
    let frontier_idx = 9;
    let findings: Vec<FindingBundle> = (0..FINDINGS_PER_FRONTIER)
        .map(|i| make_finding(frontier_idx, i))
        .collect();

    let bridge_log = build_bridge_reviewed_log(frontier_idx, &findings);
    assert_eq!(bridge_log.len(), 1);
    assert_eq!(bridge_log[0].kind, "bridge.reviewed");
    assert_eq!(bridge_log[0].target.r#type, "bridge");
    assert!(
        bridge_log[0]
            .payload
            .get("status")
            .and_then(|v| v.as_str())
            .map(|s| s == "confirmed" || s == "refuted")
            .unwrap_or(false),
        "bridge.reviewed payload.status must be 'confirmed' or 'refuted'"
    );

    let rep_log = build_replication_deposited_log(frontier_idx, &findings);
    assert_eq!(rep_log.len(), 1);
    assert_eq!(rep_log[0].kind, "replication.deposited");
    let rep_id = rep_log[0]
        .payload
        .get("replication")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        rep_id.starts_with("vrep_"),
        "replication.deposited payload.replication.id must start with 'vrep_', got {rep_id:?}"
    );

    let pred_log = build_prediction_deposited_log(frontier_idx, &findings);
    assert_eq!(pred_log.len(), 1);
    assert_eq!(pred_log[0].kind, "prediction.deposited");
    let pred_id = pred_log[0]
        .payload
        .get("prediction")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        pred_id.starts_with("vpred_"),
        "prediction.deposited payload.prediction.id must start with 'vpred_', got {pred_id:?}"
    );
}
