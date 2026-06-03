//! v0.57: Integration tests for the finding-level span-repair primitive.

use serde_json::json;
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Provenance,
};
use vela_protocol::project::{self, Project};
use vela_protocol::{events, repo, state};

fn fixture_finding() -> FindingBundle {
    FindingBundle::new(
        Assertion {
            text: "Span-repair fixture finding".to_string(),
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
            species: Some("Homo sapiens".to_string()),
            method: "manual".to_string(),
            sample_size: None,
            effect_size: None,
            p_value: None,
            replicated: false,
            replication_count: None,
            evidence_spans: Vec::new(),
        },
        Conditions {
            text: "fixture context".to_string(),
            species_verified: vec!["Homo sapiens".to_string()],
            species_unverified: Vec::new(),
            in_vitro: false,
            in_vivo: false,
            human_data: true,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        },
        Confidence::raw(0.5, "fixture", 0.8),
        Provenance {
            source_type: "published_paper".to_string(),
            doi: Some("10.1/test-span-repair".to_string()),
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Span-repair fixture source".to_string(),
            authors: Vec::new(),
            year: Some(2026),
            journal: None,
            license: None,
            publisher: None,
            funders: Vec::new(),
            extraction: Extraction::default(),
            review: None,
            citation_count: None,
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

fn frontier_with_one_finding_no_spans() -> Project {
    project::assemble("span-repair-fixture", vec![fixture_finding()], 0, 0, "test")
}

#[test]
fn span_repair_apply_appends_span_and_emits_event() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let frontier = frontier_with_one_finding_no_spans();
    repo::save_to_path(&path, &frontier).expect("save frontier");
    let finding_id = frontier.findings[0].id.clone();

    let report = state::repair_finding_span(
        &path,
        &finding_id,
        "abstract",
        "Bounded human evidence span body.",
        "reviewer:test",
        "Mechanical span repair",
        true,
    )
    .expect("repair applies");

    assert_eq!(report.command, "span-repair");
    assert_eq!(report.proposal_status, "applied");
    assert!(report.applied_event_id.is_some());

    let reloaded = repo::load_from_path(&path).expect("reload");
    let f = reloaded
        .findings
        .iter()
        .find(|f| f.id == finding_id)
        .unwrap();
    let spans = &f.evidence.evidence_spans;
    assert!(spans.iter().any(
        |s| s.get("section").and_then(|v| v.as_str()) == Some("abstract")
            && s.get("text").and_then(|v| v.as_str()) == Some("Bounded human evidence span body.")
    ));
    let event_count = reloaded
        .events
        .iter()
        .filter(|e| e.kind == "finding.span_repaired")
        .count();
    assert_eq!(event_count, 1);
}

#[test]
fn span_repair_refuses_duplicate_span() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let mut frontier = frontier_with_one_finding_no_spans();
    let finding_id = frontier.findings[0].id.clone();
    frontier.findings[0]
        .evidence
        .evidence_spans
        .push(json!({"section": "abstract", "text": "already there"}));
    repo::save_to_path(&path, &frontier).expect("save frontier");

    let result = state::repair_finding_span(
        &path,
        &finding_id,
        "abstract",
        "already there",
        "reviewer:test",
        "duplicate attempt",
        true,
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("already carries an identical"));
}

#[test]
fn span_repair_refuses_when_finding_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let frontier = frontier_with_one_finding_no_spans();
    repo::save_to_path(&path, &frontier).expect("save frontier");

    let result = state::repair_finding_span(
        &path,
        "vf_does_not_exist",
        "abstract",
        "text",
        "reviewer:test",
        "missing finding",
        true,
    );
    assert!(result.is_err());
}

#[test]
fn span_repair_event_validates() {
    let payload_ok = json!({
        "proposal_id": "vpr_test",
        "section": "abstract",
        "text": "real text",
    });
    events::validate_event_payload("finding.span_repaired", &payload_ok).expect("ok");

    let payload_missing_text = json!({
        "proposal_id": "vpr_test",
        "section": "abstract",
    });
    let r = events::validate_event_payload("finding.span_repaired", &payload_missing_text);
    assert!(r.is_err());
}
