//! v0.56: Integration tests for the evidence-atom locator-repair
//! primitive. Cover the full path from a frontier on disk through a
//! persisted proposal, an applied canonical event, and a replay round
//! trip that confirms the locator survives.

use serde_json::json;
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
};
use vela_protocol::project::{self, Project};
use vela_protocol::sources::{EvidenceAtom, SourceRecord};
use vela_protocol::{events, repo, state};

fn finding_with_doi(slot: &str, doi: &str) -> FindingBundle {
    FindingBundle::new(
        Assertion {
            text: format!("Locator-repair fixture finding {slot}"),
            assertion_type: "mechanism".to_string(),
            entities: Vec::new(),
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        },
        Evidence {
            evidence_type: "experimental".to_string(),
            model_system: "human".to_string(),
            method: "manual".to_string(),
            replicated: false,
            replication_count: None,
            evidence_spans: Vec::new(),
        },
        Conditions {
            text: "BBB locator-repair fixture context".to_string(),
            duration: None,
        },
        Confidence::raw(0.5, "operator-supplied frontier prior", 0.8),
        Provenance {
            source_type: "published_paper".to_string(),
            doi: Some(doi.to_string()),
            url: None,
            title: format!("Locator-repair fixture {slot}"),
            authors: Vec::new(),
            year: Some(2026),
            license: None,
            publisher: None,
            funders: Vec::new(),
            extraction: Extraction::default(),
            review: None,
        },
        Flags {
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
    )
}

/// Build a tiny frontier whose single evidence atom is missing its
/// locator but whose parent source carries the resolvable identifier.
/// This mirrors the BBB curation shape: source.locator is populated,
/// atom.locator is None, repair copies the value down.
fn frontier_with_one_atom_missing_locator() -> Project {
    let mut state = project::assemble(
        "locator-repair-fixture",
        vec![finding_with_doi(
            "alpha",
            "10.1038/s41586-2026-locator-fixture-alpha",
        )],
        0,
        0,
        "Locator-repair fixture",
    );
    state.sources.push(SourceRecord {
        id: "vs_locator_fixture_source".to_string(),
        source_type: "paper".to_string(),
        locator: "doi:10.1038/s41586-2026-locator-fixture-alpha".to_string(),
        content_hash: None,
        title: "Locator-repair fixture source".to_string(),
        authors: Vec::new(),
        year: Some(2026),
        doi: Some("10.1038/s41586-2026-locator-fixture-alpha".to_string()),
        pmid: None,
        imported_at: "2026-01-01T00:00:00Z".to_string(),
        extraction_mode: "manual".to_string(),
        source_quality: "declared".to_string(),
        caveats: Vec::new(),
        finding_ids: vec![state.findings[0].id.clone()],
    });
    state.evidence_atoms.push(EvidenceAtom {
        id: "vea_locator_fixture_atom".to_string(),
        source_id: "vs_locator_fixture_source".to_string(),
        finding_id: state.findings[0].id.clone(),
        locator: None,
        evidence_type: "experimental".to_string(),
        measurement_or_claim: "fixture measurement".to_string(),
        supports_or_challenges: "supports".to_string(),
        condition_refs: Vec::new(),
        extraction_method: "manual".to_string(),
        human_verified: false,
        caveats: vec!["missing evidence locator".to_string()],
    });
    state
}

fn atom_locator(state: &Project, atom_id: &str) -> Option<String> {
    state
        .evidence_atoms
        .iter()
        .find(|atom| atom.id == atom_id)
        .and_then(|atom| atom.locator.clone())
}

#[test]
fn locator_repair_apply_sets_locator_and_emits_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let frontier = frontier_with_one_atom_missing_locator();
    repo::save_to_path(&path, &frontier).expect("save frontier");

    let report = state::repair_evidence_atom_locator(
        &path,
        "vea_locator_fixture_atom",
        None,
        "agent:vela-curation-bot-test",
        "Mechanical repair from parent source",
        true,
    )
    .expect("repair applies");

    assert_eq!(report.command, "locator-repair");
    assert_eq!(report.proposal_status, "applied");
    assert!(report.applied_event_id.is_some());

    let reloaded = repo::load_from_path(&path).expect("reload");
    assert_eq!(
        atom_locator(&reloaded, "vea_locator_fixture_atom").as_deref(),
        Some("doi:10.1038/s41586-2026-locator-fixture-alpha")
    );
    let event_count = reloaded
        .events
        .iter()
        .filter(|event| event.kind == "evidence_atom.locator_repaired")
        .count();
    assert_eq!(event_count, 1);
    let event = reloaded
        .events
        .iter()
        .find(|event| event.kind == "evidence_atom.locator_repaired")
        .expect("event exists");
    assert_eq!(event.target.r#type, "evidence_atom");
    assert_eq!(event.target.id, "vea_locator_fixture_atom");
    assert_eq!(
        event
            .payload
            .get("source_id")
            .and_then(|v| v.as_str())
            .unwrap(),
        "vs_locator_fixture_source"
    );
}

#[test]
fn locator_repair_pending_does_not_set_locator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let frontier = frontier_with_one_atom_missing_locator();
    repo::save_to_path(&path, &frontier).expect("save frontier");

    let report = state::repair_evidence_atom_locator(
        &path,
        "vea_locator_fixture_atom",
        None,
        "agent:vela-curation-bot-test",
        "Queued for review",
        false,
    )
    .expect("queue ok");
    assert_eq!(report.proposal_status, "pending_review");
    assert!(report.applied_event_id.is_none());

    let reloaded = repo::load_from_path(&path).expect("reload");
    assert!(atom_locator(&reloaded, "vea_locator_fixture_atom").is_none());
}

#[test]
fn locator_repair_refuses_when_atom_already_has_locator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let mut frontier = frontier_with_one_atom_missing_locator();
    let atom_idx = frontier
        .evidence_atoms
        .iter()
        .position(|atom| atom.id == "vea_locator_fixture_atom")
        .unwrap();
    frontier.evidence_atoms[atom_idx].locator = Some("doi:already-set".to_string());
    repo::save_to_path(&path, &frontier).expect("save frontier");

    let result = state::repair_evidence_atom_locator(
        &path,
        "vea_locator_fixture_atom",
        None,
        "agent:vela-curation-bot-test",
        "noop attempt",
        true,
    );
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("already carries locator"));
}

#[test]
fn locator_repair_refuses_when_atom_missing_from_frontier() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let frontier = frontier_with_one_atom_missing_locator();
    repo::save_to_path(&path, &frontier).expect("save frontier");

    let result = state::repair_evidence_atom_locator(
        &path,
        "vea_does_not_exist",
        Some("doi:10.1/test"),
        "agent:vela-curation-bot-test",
        "missing atom",
        true,
    );
    assert!(result.is_err());
}

#[test]
fn locator_repair_event_validates() {
    // Exercises the events::validate_event_payload arm directly so a
    // hand-built event with missing payload fields fails at the
    // validator boundary rather than slipping through replay.
    let payload_ok = json!({
        "proposal_id": "vpr_test",
        "source_id": "vs_x",
        "locator": "doi:10.1/test",
    });
    events::validate_event_payload("evidence_atom.locator_repaired", &payload_ok)
        .expect("valid payload");

    let payload_missing_locator = json!({
        "proposal_id": "vpr_test",
        "source_id": "vs_x",
    });
    let r =
        events::validate_event_payload("evidence_atom.locator_repaired", &payload_missing_locator);
    assert!(r.is_err());

    let payload_empty_source = json!({
        "proposal_id": "vpr_test",
        "source_id": "",
        "locator": "doi:10.1/test",
    });
    let r = events::validate_event_payload("evidence_atom.locator_repaired", &payload_empty_source);
    assert!(r.is_err());
}
