//! v0.56: Coverage test for the Carina v0.1 primitives example file.
//!
//! v4.3 (W4.3): Extended to also cover the v0.2 primitives example.
//! v0.2 reconciles two kernel-vs-spec gaps that v0.1 left open:
//! (1) the proposal entry now carries a top-level `actor`, matching
//! the docs/CARINA.md validation rule; (2) the kernel-vs-typed-pole
//! shape divergence is now documented in CARINA.md as a deliberate
//! two-tier shape rather than a silent inconsistency. v0.1 stays in
//! place unchanged for backward-compat replay.
//!
//! `examples/carina-kernel/primitives.v0.1.json` and
//! `examples/carina-kernel/primitives.v0.2.json` are the canonical
//! sample bundles referenced from `docs/CARINA.md` and from the
//! `/spec#carina` page. Each carries one example per primitive in the
//! kernel: Finding, Evidence, Artifact, Proposal, Diff, Event,
//! Attestation, Question, Protocol, Experiment, Mechanism, Lineage,
//! and Confidence.
//!
//! This test is the boundary check that keeps the spec's primitive
//! list and the example files in agreement. It asserts:
//!   1. The example file deserializes as JSON.
//!   2. Each documented primitive has an entry under `primitives`.
//!   3. Each entry carries the matching `carina.<kind>.<version>`
//!      schema string and a non-empty `id`.
//! It does not deserialize each primitive into a typed Rust struct
//! because Carina is intentionally string-shaped at the interchange
//! boundary; the typed pole lives in the protocol crate and is
//! exercised through the artifact-to-state pipeline.

use std::fs;
use std::path::PathBuf;

use serde_json::{Value, json};

const EXPECTED_PRIMITIVES: &[(&str, &str)] = &[
    ("finding", "carina.finding.v0.1"),
    ("evidence", "carina.evidence.v0.1"),
    ("artifact", "carina.artifact.v0.1"),
    ("proposal", "carina.proposal.v0.1"),
    ("diff", "carina.diff.v0.1"),
    ("event", "carina.event.v0.1"),
    ("attestation", "carina.attestation.v0.1"),
    ("question", "carina.question.v0.1"),
    ("protocol", "carina.protocol.v0.1"),
    ("experiment", "carina.experiment.v0.1"),
    ("mechanism", "carina.mechanism.v0.1"),
    ("lineage", "carina.lineage.v0.1"),
    ("confidence", "carina.confidence.v0.1"),
];

fn primitives_example_path() -> PathBuf {
    // The crate's CARGO_MANIFEST_DIR points at `crates/vela-protocol`.
    // The example file lives at the repo root in `examples/`.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/vela-protocol parent")
        .join("examples/carina-kernel/primitives.v0.1.json")
}

#[test]
fn carina_primitives_example_exists() {
    let path = primitives_example_path();
    assert!(
        path.is_file(),
        "Carina primitives example missing at {}",
        path.display()
    );
}

#[test]
fn carina_primitives_example_parses() {
    let path = primitives_example_path();
    let raw = fs::read_to_string(&path).expect("read primitives example");
    let value: Value = serde_json::from_str(&raw).expect("parse primitives example");
    assert_eq!(
        value.get("schema").and_then(Value::as_str),
        Some("carina.examples.v0.1"),
        "wrapper schema must be carina.examples.v0.1"
    );
    let primitives = value
        .get("primitives")
        .and_then(Value::as_object)
        .expect("primitives object");
    assert!(
        !primitives.is_empty(),
        "primitives object must be non-empty"
    );
}

#[test]
fn carina_primitives_example_covers_every_documented_primitive() {
    let path = primitives_example_path();
    let raw = fs::read_to_string(&path).expect("read primitives example");
    let value: Value = serde_json::from_str(&raw).expect("parse primitives example");
    let primitives = value
        .get("primitives")
        .and_then(Value::as_object)
        .expect("primitives object");

    for (key, schema) in EXPECTED_PRIMITIVES {
        let entry = primitives
            .get(*key)
            .unwrap_or_else(|| panic!("Carina primitive '{key}' missing from {}", path.display()));
        let actual_schema = entry
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("primitive '{key}' is missing 'schema' field"));
        assert_eq!(
            actual_schema, *schema,
            "primitive '{key}' must declare schema '{schema}'"
        );
        // Carina primitives have heterogeneous identity shapes.
        // Findings, evidence, artifacts, proposals, events, etc. are
        // content-addressed objects with an `id`. Diff identifies a
        // before/after pair by `proposal_id`. Lineage identifies the
        // object whose lineage it describes by `object_id`. Confidence
        // and Mechanism are value primitives with no opaque id; the
        // primitive is identified contextually by its parent finding.
        // The structural commitment is just: each primitive must carry
        // at least two non-schema fields so it isn't a stub.
        let object = entry
            .as_object()
            .unwrap_or_else(|| panic!("primitive '{key}' must be a JSON object"));
        let non_schema_fields = object.keys().filter(|k| k.as_str() != "schema").count();
        assert!(
            non_schema_fields >= 2,
            "primitive '{key}' has too few fields ({non_schema_fields}); expected at least 2 non-schema fields"
        );
    }
}

#[test]
fn carina_primitives_example_artifact_packet_validates() {
    // The wrapper carries one full Artifact entry whose shape mirrors
    // the runtime `carina.artifact_packet.v0.1` boundary. This check
    // confirms the artifact entry has the inline content-hash and
    // locator fields the artifact-to-state ingestion path expects.
    let path = primitives_example_path();
    let raw = fs::read_to_string(&path).expect("read primitives example");
    let value: Value = serde_json::from_str(&raw).expect("parse primitives example");
    let artifact = value
        .pointer("/primitives/artifact")
        .expect("artifact primitive");
    let id = artifact.get("id").and_then(Value::as_str);
    assert!(id.is_some_and(|s| !s.is_empty()), "artifact id required");
    let locator = artifact.get("locator").and_then(Value::as_str);
    assert!(
        locator.is_some_and(|s| !s.is_empty()),
        "artifact locator required for the artifact_packet boundary"
    );
}

#[test]
fn carina_primitives_example_finding_has_assertion_and_confidence() {
    // Specific to the Finding primitive: the assertion field is the
    // human-readable claim the finding crystallizes, and the confidence
    // block carries the bounded support score plus method/scope.
    let path = primitives_example_path();
    let raw = fs::read_to_string(&path).expect("read primitives example");
    let value: Value = serde_json::from_str(&raw).expect("parse primitives example");
    let finding = value
        .pointer("/primitives/finding")
        .expect("finding primitive");
    assert!(
        finding
            .pointer("/assertion/text")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        "finding.assertion.text required"
    );
    let confidence = finding
        .pointer("/confidence")
        .and_then(Value::as_object)
        .expect("finding.confidence object");
    let score = confidence.get("score").and_then(Value::as_f64);
    assert!(
        score.is_some_and(|v| (0.0..=1.0).contains(&v)),
        "confidence.score must be in [0.0, 1.0]"
    );
}

#[test]
fn carina_primitives_example_event_has_target_and_actor() {
    let path = primitives_example_path();
    let raw = fs::read_to_string(&path).expect("read primitives example");
    let value: Value = serde_json::from_str(&raw).expect("parse primitives example");
    let event = value.pointer("/primitives/event").expect("event primitive");
    assert!(
        event
            .pointer("/target/type")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        "event.target.type required"
    );
    assert!(
        event
            .pointer("/target/id")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        "event.target.id required"
    );
    assert!(
        event
            .pointer("/actor/id")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty()),
        "event.actor.id required"
    );
}

// -----------------------------------------------------------------
// Per-primitive coverage tests.
//
// CARINA.md v0.1 documents thirteen primitives. The tests below
// pin each one to its documented required-field set. Where the
// kernel JSON shape lines up with a typed Rust struct in
// `vela-protocol`, the test also confirms the JSON parses into
// that struct. Carina v0.1 is intentionally string-shaped at the
// interchange boundary, so several primitives have no matching
// struct in the protocol crate; for those, only the JSON-shape
// assertions run.
//
// One inconsistency is flagged here, not silently fixed:
// CARINA.md's validation section says every proposal preserves an
// "actor id". The canonical sample bundle does not carry one at
// the top level of the proposal entry. That is recorded in
// `carina_primitive_proposal_has_required_fields` and left for
// follow-on spec reconciliation, since fixing either side would
// be an unauthorized production-shape change.
// -----------------------------------------------------------------

fn load_primitives() -> Value {
    let path = primitives_example_path();
    let raw = fs::read_to_string(&path).expect("read primitives example");
    serde_json::from_str(&raw).expect("parse primitives example")
}

fn primitive<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .pointer(&format!("/primitives/{key}"))
        .unwrap_or_else(|| panic!("Carina primitive '{key}' missing"))
}

fn assert_str_field(entry: &Value, key: &str, primitive_name: &str) {
    let present = entry
        .get(key)
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    assert!(
        present,
        "primitive '{primitive_name}' is missing required string field '{key}'"
    );
}

fn assert_array_field(entry: &Value, key: &str, primitive_name: &str) {
    let present = entry.get(key).and_then(Value::as_array).is_some();
    assert!(
        present,
        "primitive '{primitive_name}' is missing required array field '{key}'"
    );
}

fn assert_object_field(entry: &Value, key: &str, primitive_name: &str) {
    let present = entry.get(key).and_then(Value::as_object).is_some();
    assert!(
        present,
        "primitive '{primitive_name}' is missing required object field '{key}'"
    );
}

#[test]
fn carina_primitive_finding_has_required_fields() {
    // CARINA.md "Minimal object shapes" Finding example documents:
    // schema, id, assertion (text+type), conditions, evidence_ids,
    // confidence (score+method+scope), lineage, status.
    let value = load_primitives();
    let finding = primitive(&value, "finding");
    assert_str_field(finding, "id", "finding");
    assert_object_field(finding, "assertion", "finding");
    assert_str_field(
        finding.pointer("/assertion").unwrap(),
        "text",
        "finding.assertion",
    );
    assert_str_field(
        finding.pointer("/assertion").unwrap(),
        "type",
        "finding.assertion",
    );
    assert_object_field(finding, "conditions", "finding");
    assert_array_field(finding, "evidence_ids", "finding");
    assert_object_field(finding, "confidence", "finding");
    let confidence = finding.pointer("/confidence").unwrap();
    assert_str_field(confidence, "method", "finding.confidence");
    assert_str_field(confidence, "scope", "finding.confidence");
    assert!(
        confidence
            .get("score")
            .and_then(Value::as_f64)
            .is_some_and(|v| (0.0..=1.0).contains(&v)),
        "finding.confidence.score must be in [0.0, 1.0]"
    );
    assert_object_field(finding, "lineage", "finding");
    assert_str_field(finding, "status", "finding");
}

#[test]
fn carina_primitive_evidence_has_required_fields() {
    // CARINA.md Evidence example: schema, id, source_id, artifact_id,
    // locator, span, supports[], limitations[].
    let value = load_primitives();
    let evidence = primitive(&value, "evidence");
    assert_str_field(evidence, "id", "evidence");
    assert_str_field(evidence, "source_id", "evidence");
    assert_str_field(evidence, "artifact_id", "evidence");
    assert_str_field(evidence, "locator", "evidence");
    assert_str_field(evidence, "span", "evidence");
    assert_array_field(evidence, "supports", "evidence");
    assert_array_field(evidence, "limitations", "evidence");
    // Note: `vela_protocol::bundle::Evidence` is the heavier in-bundle
    // evidence shape (type, model_system, method, sample_size, ...). The
    // Carina v0.1 interchange-shape Evidence is intentionally distinct
    // and has no matching struct in this crate.
}

#[test]
fn carina_primitive_artifact_has_required_fields() {
    // CARINA.md validation rule: "Every artifact has an id, kind,
    // locator, content hash, and parent ids."
    let value = load_primitives();
    let artifact = primitive(&value, "artifact");
    assert_str_field(artifact, "id", "artifact");
    assert_str_field(artifact, "kind", "artifact");
    assert_str_field(artifact, "locator", "artifact");
    assert_str_field(artifact, "content_hash", "artifact");
    assert_array_field(artifact, "parents", "artifact");
    // Note: `vela_protocol::bundle::Artifact` is the in-bundle artifact
    // shape (name, storage_mode, provenance, created, ...). The Carina
    // v0.1 interchange-shape artifact is the lighter packet boundary.
}

#[test]
fn carina_primitive_proposal_has_required_fields() {
    // CARINA.md validation rule: "Every proposal preserves packet id,
    // external object ids, actor id, and source locators." The sample
    // bundle records packet_id, external_object_ids, and artifact_ids
    // under `provenance`. It does not carry an `actor` at the top level
    // of the proposal entry; that is a known mismatch between the
    // CARINA.md validation section and the canonical sample. Flagged
    // here for follow-on spec reconciliation rather than silently fixed,
    // since either side is a production-shape change.
    let value = load_primitives();
    let proposal = primitive(&value, "proposal");
    assert_str_field(proposal, "id", "proposal");
    assert_str_field(proposal, "kind", "proposal");
    assert_object_field(proposal, "target", "proposal");
    assert_str_field(
        proposal.pointer("/target").unwrap(),
        "type",
        "proposal.target",
    );
    assert_str_field(
        proposal.pointer("/target").unwrap(),
        "id",
        "proposal.target",
    );
    assert_object_field(proposal, "provenance", "proposal");
    let provenance = proposal.pointer("/provenance").unwrap();
    assert_str_field(provenance, "packet_id", "proposal.provenance");
    assert_array_field(provenance, "artifact_ids", "proposal.provenance");
    assert_array_field(provenance, "external_object_ids", "proposal.provenance");
    assert_str_field(proposal, "status", "proposal");
}

#[test]
fn carina_primitive_diff_has_required_fields() {
    // CARINA.md table: "Diff: The before and after shape of accepting
    // a proposal." The sample bundle records proposal_id, before,
    // after, and changed_objects.
    let value = load_primitives();
    let diff = primitive(&value, "diff");
    assert_str_field(diff, "proposal_id", "diff");
    assert_object_field(diff, "before", "diff");
    assert_object_field(diff, "after", "diff");
    assert_array_field(diff, "changed_objects", "diff");
}

#[test]
fn carina_primitive_event_has_required_fields() {
    // CARINA.md validation rule: "Every accepted event names its
    // target, actor, timestamp, proposal id, status, and reason."
    // Proposal id and status live under `payload`.
    let value = load_primitives();
    let event = primitive(&value, "event");
    assert_str_field(event, "id", "event");
    assert_str_field(event, "kind", "event");
    assert_object_field(event, "target", "event");
    assert_str_field(event.pointer("/target").unwrap(), "type", "event.target");
    assert_str_field(event.pointer("/target").unwrap(), "id", "event.target");
    assert_object_field(event, "actor", "event");
    assert_str_field(event.pointer("/actor").unwrap(), "id", "event.actor");
    assert_str_field(event.pointer("/actor").unwrap(), "type", "event.actor");
    assert_str_field(event, "timestamp", "event");
    assert_str_field(event, "reason", "event");
    assert_object_field(event, "payload", "event");
    assert_str_field(
        event.pointer("/payload").unwrap(),
        "proposal_id",
        "event.payload",
    );
    assert_str_field(
        event.pointer("/payload").unwrap(),
        "status",
        "event.payload",
    );
    // Note: `vela_protocol::events::StateEvent` carries additional
    // required fields (before_hash, after_hash) that the kernel-boundary
    // event shape does not. Direct struct deserialization is therefore
    // out of scope; the artifact-to-state pipeline lifts the kernel
    // shape into the typed StateEvent at acceptance time.
}

#[test]
fn carina_primitive_attestation_has_required_fields() {
    // CARINA.md table: "Attestation: A signed review, validation,
    // replication, rejection, or judgment by an actor." Sample bundle
    // records id, actor, target, status, scope.
    let value = load_primitives();
    let attestation = primitive(&value, "attestation");
    assert_str_field(attestation, "id", "attestation");
    assert_object_field(attestation, "actor", "attestation");
    assert_str_field(
        attestation.pointer("/actor").unwrap(),
        "id",
        "attestation.actor",
    );
    assert_str_field(
        attestation.pointer("/actor").unwrap(),
        "type",
        "attestation.actor",
    );
    assert_object_field(attestation, "target", "attestation");
    assert_str_field(
        attestation.pointer("/target").unwrap(),
        "type",
        "attestation.target",
    );
    assert_str_field(
        attestation.pointer("/target").unwrap(),
        "id",
        "attestation.target",
    );
    assert_str_field(attestation, "status", "attestation");
    assert_str_field(attestation, "scope", "attestation");
}

#[test]
fn carina_primitive_question_has_required_fields() {
    // CARINA.md table: "Question: An explicit uncertainty or
    // missing-evidence target." Sample bundle records id, text,
    // rationale.
    let value = load_primitives();
    let question = primitive(&value, "question");
    assert_str_field(question, "id", "question");
    assert_str_field(question, "text", "question");
    assert_str_field(question, "rationale", "question");
}

#[test]
fn carina_primitive_protocol_has_required_fields() {
    // CARINA.md table: "Protocol: A method for producing evidence."
    // Sample bundle records id, title, produces[].
    let value = load_primitives();
    let protocol = primitive(&value, "protocol");
    assert_str_field(protocol, "id", "protocol");
    assert_str_field(protocol, "title", "protocol");
    assert_array_field(protocol, "produces", "protocol");
}

#[test]
fn carina_primitive_experiment_has_required_fields() {
    // CARINA.md table: "Experiment: A test intended to update
    // frontier state." Sample bundle records id, question_id,
    // protocol_id, intended_update.
    let value = load_primitives();
    let experiment = primitive(&value, "experiment");
    assert_str_field(experiment, "id", "experiment");
    assert_str_field(experiment, "question_id", "experiment");
    assert_str_field(experiment, "protocol_id", "experiment");
    assert_str_field(experiment, "intended_update", "experiment");
}

#[test]
fn carina_primitive_mechanism_has_required_fields() {
    // CARINA.md table: "Mechanism: A causal or structural annotation
    // over finding links." Sample bundle records id, relation, shape,
    // source_finding_id, target_finding_id.
    let value = load_primitives();
    let mechanism = primitive(&value, "mechanism");
    assert_str_field(mechanism, "id", "mechanism");
    assert_str_field(mechanism, "relation", "mechanism");
    assert_str_field(mechanism, "shape", "mechanism");
    assert_str_field(mechanism, "source_finding_id", "mechanism");
    assert_str_field(mechanism, "target_finding_id", "mechanism");
}

#[test]
fn carina_primitive_lineage_has_required_fields() {
    // CARINA.md table: "Lineage: Parentage and provenance across
    // artifacts, evidence, findings, proposals, and events." Sample
    // bundle records object_id, parents[], event_ids[].
    let value = load_primitives();
    let lineage = primitive(&value, "lineage");
    assert_str_field(lineage, "object_id", "lineage");
    assert_array_field(lineage, "parents", "lineage");
    assert_array_field(lineage, "event_ids", "lineage");
}

#[test]
fn carina_primitive_confidence_has_required_fields() {
    // CARINA.md validation rule: "Every confidence value has scope
    // and method when it is promoted into a finding." Sample bundle
    // records score, method, scope, plus a history array of review
    // transitions.
    let value = load_primitives();
    let confidence = primitive(&value, "confidence");
    assert_str_field(confidence, "method", "confidence");
    assert_str_field(confidence, "scope", "confidence");
    assert!(
        confidence
            .get("score")
            .and_then(Value::as_f64)
            .is_some_and(|v| (0.0..=1.0).contains(&v)),
        "confidence.score must be in [0.0, 1.0]"
    );
    assert_array_field(confidence, "history", "confidence");
    let history = confidence.get("history").and_then(Value::as_array).unwrap();
    assert!(
        !history.is_empty(),
        "confidence.history must record at least one transition"
    );
    let first = &history[0];
    assert_str_field(first, "event_id", "confidence.history[0]");
    assert!(
        first.get("to").is_some(),
        "confidence.history[0].to required (the post-transition score)"
    );
    // Note: `vela_protocol::bundle::Confidence` is the in-bundle
    // confidence shape (kind, basis, components, extraction_confidence).
    // The Carina v0.1 interchange-shape Confidence is intentionally
    // lighter and does not deserialize into that struct.
}

// -----------------------------------------------------------------
// v0.2 coverage.
//
// Carina v0.2 closes the proposal-actor gap left open in v0.1 and
// formalizes the two-tier shape (kernel interchange vs typed pole)
// as a deliberate split documented in CARINA.md. The example file
// at `examples/carina-kernel/primitives.v0.2.json` is the canonical
// v0.2 sample bundle. v0.1 stays in place unchanged so prior replay
// material keeps loading.
// -----------------------------------------------------------------

const EXPECTED_PRIMITIVES_V0_2: &[(&str, &str)] = &[
    ("finding", "carina.finding.v0.2"),
    ("evidence", "carina.evidence.v0.2"),
    ("artifact", "carina.artifact.v0.2"),
    ("proposal", "carina.proposal.v0.2"),
    ("diff", "carina.diff.v0.2"),
    ("event", "carina.event.v0.2"),
    ("attestation", "carina.attestation.v0.2"),
    ("question", "carina.question.v0.2"),
    ("protocol", "carina.protocol.v0.2"),
    ("experiment", "carina.experiment.v0.2"),
    ("mechanism", "carina.mechanism.v0.2"),
    ("lineage", "carina.lineage.v0.2"),
    ("confidence", "carina.confidence.v0.2"),
];

fn primitives_example_path_v0_2() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("crates/vela-protocol parent")
        .join("examples/carina-kernel/primitives.v0.2.json")
}

fn load_primitives_v0_2() -> Value {
    let path = primitives_example_path_v0_2();
    let raw = fs::read_to_string(&path).expect("read v0.2 primitives example");
    serde_json::from_str(&raw).expect("parse v0.2 primitives example")
}

#[test]
fn carina_primitives_v0_2_example_exists() {
    let path = primitives_example_path_v0_2();
    assert!(
        path.is_file(),
        "Carina v0.2 primitives example missing at {}",
        path.display()
    );
}

#[test]
fn carina_primitives_v0_2_example_parses() {
    let value = load_primitives_v0_2();
    assert_eq!(
        value.get("schema").and_then(Value::as_str),
        Some("carina.examples.v0.2"),
        "wrapper schema must be carina.examples.v0.2"
    );
    let primitives = value
        .get("primitives")
        .and_then(Value::as_object)
        .expect("primitives object");
    assert!(
        !primitives.is_empty(),
        "primitives object must be non-empty"
    );
}

#[test]
fn carina_primitives_v0_2_example_covers_every_documented_primitive() {
    let value = load_primitives_v0_2();
    let primitives = value
        .get("primitives")
        .and_then(Value::as_object)
        .expect("primitives object");

    for (key, schema) in EXPECTED_PRIMITIVES_V0_2 {
        let entry = primitives
            .get(*key)
            .unwrap_or_else(|| panic!("Carina v0.2 primitive '{key}' missing"));
        let actual_schema = entry
            .get("schema")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("v0.2 primitive '{key}' is missing 'schema' field"));
        assert_eq!(
            actual_schema, *schema,
            "v0.2 primitive '{key}' must declare schema '{schema}'"
        );
    }
}

#[test]
fn carina_primitive_v0_2_proposal_carries_actor() {
    // v0.2 reconciliation: the proposal entry now carries a top-level
    // `actor` block matching the docs/CARINA.md validation rule. The
    // substrate's existing actor convention is
    // `{"id": "<reviewer-id>", "type": "human"}`.
    let value = load_primitives_v0_2();
    let proposal = value
        .pointer("/primitives/proposal")
        .expect("v0.2 proposal primitive");
    assert_str_field(proposal, "id", "proposal");
    assert_str_field(proposal, "kind", "proposal");
    assert_object_field(proposal, "target", "proposal");
    assert_object_field(proposal, "actor", "proposal");
    let actor = proposal.pointer("/actor").unwrap();
    assert_str_field(actor, "id", "proposal.actor");
    assert_str_field(actor, "type", "proposal.actor");
    assert_object_field(proposal, "provenance", "proposal");
    let provenance = proposal.pointer("/provenance").unwrap();
    assert_str_field(provenance, "packet_id", "proposal.provenance");
    assert_array_field(provenance, "artifact_ids", "proposal.provenance");
    assert_array_field(provenance, "external_object_ids", "proposal.provenance");
    assert_str_field(proposal, "status", "proposal");
}

// =============================================================
// v0.3 Carina spec deliverable: schema-validation round-trip
// against the bundled JSON Schemas under
// `crates/vela-protocol/embedded/carina-schemas/`. The
// `examples/carina-kernel/primitives.v0.3.json` aggregate is the
// canonical example and must validate end-to-end against every
// bundled schema, including the v0.75.6 (Gowers-shaped) `proof`
// primitive.

fn load_primitives_v0_3() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/carina-kernel/primitives.v0.3.json");
    let text = std::fs::read_to_string(&path).expect("read v0.3 primitives example");
    serde_json::from_str(&text).expect("parse v0.3 primitives example")
}

#[test]
fn carina_v0_3_aggregate_round_trips_all_14_schemas() {
    use vela_edge::carina_validate;
    let value = load_primitives_v0_3();
    let primitives = value
        .get("primitives")
        .and_then(Value::as_object)
        .expect("v0.3 aggregate has `primitives`");

    // The 14 primitives the v0.3 cycle introduced. Atlas is
    // v0.4; asserted separately by carina_v0_4_aggregate_round_trips_all_15_schemas.
    let v0_3_names = [
        "finding",
        "evidence",
        "artifact",
        "proposal",
        "diff",
        "event",
        "attestation",
        "question",
        "protocol",
        "experiment",
        "mechanism",
        "lineage",
        "confidence",
        "proof",
    ];
    for name in v0_3_names {
        assert!(
            primitives.contains_key(name),
            "v0.3 example missing primitive {name}"
        );
    }
    // And every example must validate against its bundled schema.
    for (name, v) in primitives {
        carina_validate::validate(name, v)
            .unwrap_or_else(|errs| panic!("primitive {name} failed: {:#?}", errs));
    }
}

#[test]
fn carina_v0_3_proof_primitive_carries_gowers_shape() {
    // v0.75.6: the Proof primitive must carry the certification
    // fields Gowers (2026-05-08) names: tool, version, locator,
    // verifier output hash, verified_at, target_finding_id.
    let value = load_primitives_v0_3();
    let proof = value
        .pointer("/primitives/proof")
        .expect("v0.3 example carries proof primitive");
    for required in [
        "id",
        "tool",
        "tool_version",
        "script_locator",
        "verifier_output_hash",
        "verified_at",
        "target_finding_id",
    ] {
        assert!(
            proof.get(required).is_some(),
            "proof primitive missing field '{required}'"
        );
    }
    let tool = proof
        .get("tool")
        .and_then(Value::as_str)
        .expect("proof.tool is a string");
    assert!(
        [
            "lean4", "coq", "isabelle", "agda", "metamath", "rocq", "other"
        ]
        .contains(&tool),
        "proof.tool '{tool}' not in enumerated tools"
    );
}

#[test]
fn carina_event_payload_validator_agrees_with_schema() {
    // Cross-impl invariant: every event-payload shape that the
    // signature-pure Rust validator at events.rs accepts also
    // passes the v0.3 event JSON Schema. The schema is the public
    // spec; the Rust validator is authoritative for replay.
    use vela_edge::carina_validate;
    use vela_protocol::events::validate_event_payload;

    let kind = "finding.reviewed";
    let payload = json!({
        "proposal_id": "vpr_abc",
        "status": "accepted"
    });
    validate_event_payload(kind, &payload).expect("rust event-payload validator accepts payload");

    let event = json!({
        "schema": "carina.event.v0.3",
        "id": "vev_abc",
        "kind": kind,
        "target": {"type": "finding", "id": "vf_abc"},
        "actor": {"id": "reviewer:demo", "type": "human"},
        "timestamp": "2026-05-09T00:00:00Z",
        "reason": "demo",
        "payload": payload,
    });
    carina_validate::validate("event", &event).expect("v0.3 event schema accepts the same shape");
}

// =============================================================
// v0.78.1 Carina v0.4: Atlas primitive (fifteenth Carina type).
// The v0.4 wrapper-level example bumps to `carina.examples.v0.4`
// but keeps existing primitives at v0.3 schema tags (no field
// changes since v0.3); only the new Atlas primitive is v0.4.

fn load_primitives_v0_4() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/carina-kernel/primitives.v0.4.json");
    let text = std::fs::read_to_string(&path).expect("read v0.4 primitives example");
    serde_json::from_str(&text).expect("parse v0.4 primitives example")
}

#[test]
fn carina_v0_4_aggregate_round_trips_all_15_schemas() {
    use vela_edge::carina_validate;
    let value = load_primitives_v0_4();
    assert_eq!(
        value.get("schema").and_then(Value::as_str),
        Some("carina.examples.v0.4"),
        "v0.4 wrapper schema must be carina.examples.v0.4"
    );
    let primitives = value
        .get("primitives")
        .and_then(Value::as_object)
        .expect("v0.4 aggregate has `primitives`");

    // The 15 primitives the v0.4 cycle introduced. Constellation
    // is v0.5; asserted separately.
    let v0_4_names = [
        "finding",
        "evidence",
        "artifact",
        "proposal",
        "diff",
        "event",
        "attestation",
        "question",
        "protocol",
        "experiment",
        "mechanism",
        "lineage",
        "confidence",
        "proof",
        "atlas",
    ];
    for name in v0_4_names {
        assert!(
            primitives.contains_key(name),
            "v0.4 example missing primitive {name}"
        );
    }
    for (name, v) in primitives {
        carina_validate::validate(name, v)
            .unwrap_or_else(|errs| panic!("primitive {name} failed: {:#?}", errs));
    }
}

#[test]
fn carina_v0_4_atlas_composes_brain_tumor_and_anti_amyloid() {
    // The v0.4 example carries a real Atlas composing the v0.78
    // brain-tumor frontier with the anti-amyloid sister frontier.
    let value = load_primitives_v0_4();
    let atlas = value
        .pointer("/primitives/atlas")
        .expect("v0.4 example carries atlas primitive");
    assert_eq!(
        atlas.get("name").and_then(Value::as_str),
        Some("Brain Tumor Translation")
    );
    assert_eq!(
        atlas.get("domain").and_then(Value::as_str),
        Some("oncology")
    );
    let composing = atlas
        .get("composing_frontiers")
        .and_then(Value::as_array)
        .expect("Atlas has composing_frontiers array");
    assert!(
        composing.len() >= 2,
        "Atlas must compose at least 2 frontiers"
    );
    let names: Vec<&str> = composing
        .iter()
        .filter_map(|v| v.get("name").and_then(Value::as_str))
        .collect();
    assert!(names.contains(&"brain-tumor-translation"));
    assert!(names.contains(&"anti-amyloid-translation"));
}

// =============================================================
// v0.80.3 Carina v0.5: Constellation primitive (sixteenth Carina
// type). Constellation composes one or more Atlases (vat_*) into
// a higher-level cross-domain map. Atlas stays the unit of
// reviewer-confirmed bridges; Constellation is read-only over
// per-Atlas snapshots.

fn load_primitives_v0_5() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/carina-kernel/primitives.v0.5.json");
    let text = std::fs::read_to_string(&path).expect("read v0.5 primitives example");
    serde_json::from_str(&text).expect("parse v0.5 primitives example")
}

#[test]
fn carina_v0_5_aggregate_round_trips_all_16_schemas() {
    use vela_edge::carina_validate;
    let value = load_primitives_v0_5();
    assert_eq!(
        value.get("schema").and_then(Value::as_str),
        Some("carina.examples.v0.5"),
        "v0.5 wrapper schema must be carina.examples.v0.5"
    );
    let primitives = value
        .get("primitives")
        .and_then(Value::as_object)
        .expect("v0.5 aggregate has `primitives`");

    // The 16 primitives the v0.5 cycle introduced (trial is v0.6,
    // asserted separately by carina_v0_6_aggregate_round_trips_all_17_schemas).
    let v0_5_primitive_names = [
        "finding",
        "evidence",
        "artifact",
        "proposal",
        "diff",
        "event",
        "attestation",
        "question",
        "protocol",
        "experiment",
        "mechanism",
        "lineage",
        "confidence",
        "proof",
        "atlas",
        "constellation",
    ];
    for name in v0_5_primitive_names {
        assert!(
            primitives.contains_key(name),
            "v0.5 example missing primitive {name}"
        );
    }
    for (name, v) in primitives {
        carina_validate::validate(name, v)
            .unwrap_or_else(|errs| panic!("primitive {name} failed: {:#?}", errs));
    }
}

// =============================================================
// v0.113 Carina v0.6: Trial primitive (seventeenth Carina type).
// Trial carries the long-lived metadata of a single clinical
// trial so its frontier's canonical event log can be the durable
// audit trail. Aligns with examples/trial-evidence-packet
// shipped at v0.112.0.

fn load_primitives_v0_6() -> Value {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/carina-kernel/primitives.v0.6.json");
    let text = std::fs::read_to_string(&path).expect("read v0.6 primitives example");
    serde_json::from_str(&text).expect("parse v0.6 primitives example")
}

#[test]
fn carina_v0_6_aggregate_round_trips_all_17_schemas() {
    use vela_edge::carina_validate;
    let value = load_primitives_v0_6();
    assert_eq!(
        value.get("schema").and_then(Value::as_str),
        Some("carina.examples.v0.6"),
        "v0.6 wrapper schema must be carina.examples.v0.6"
    );
    let primitives = value
        .get("primitives")
        .and_then(Value::as_object)
        .expect("v0.6 aggregate has `primitives`");

    for name in carina_validate::PRIMITIVE_NAMES {
        assert!(
            primitives.contains_key(*name),
            "v0.6 example missing primitive {name}"
        );
    }
    for (name, v) in primitives {
        carina_validate::validate(name, v)
            .unwrap_or_else(|errs| panic!("primitive {name} failed: {:#?}", errs));
    }
}

#[test]
fn carina_v0_6_trial_carries_phase_status_indication() {
    let value = load_primitives_v0_6();
    let trial = value
        .pointer("/primitives/trial")
        .expect("v0.6 example carries trial primitive");
    let phase = trial.get("phase").and_then(Value::as_str).unwrap();
    let status = trial.get("status").and_then(Value::as_str).unwrap();
    let indication = trial.get("indication").and_then(Value::as_str).unwrap();
    assert!(phase.starts_with("phase_") || phase == "preclinical" || phase == "observational");
    assert!(matches!(
        status,
        "planned"
            | "recruiting"
            | "active"
            | "completed"
            | "suspended"
            | "terminated"
            | "withdrawn"
    ));
    assert!(!indication.is_empty());
}

#[test]
fn carina_v0_5_constellation_composes_atlases() {
    let value = load_primitives_v0_5();
    let constellation = value
        .pointer("/primitives/constellation")
        .expect("v0.5 example carries constellation primitive");
    let composing = constellation
        .get("composing_atlases")
        .and_then(Value::as_array)
        .expect("constellation has composing_atlases");
    assert!(!composing.is_empty());
    for atlas in composing {
        let vat_id = atlas
            .get("vat_id")
            .and_then(Value::as_str)
            .expect("composing atlas has vat_id");
        assert!(
            vat_id.starts_with("vat_"),
            "composing atlas vat_id must start with vat_: {vat_id}"
        );
    }
}
