//! v0.57: Integration tests for the entity-resolve primitive.

use serde_json::json;
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, Entity, Evidence, Extraction, FindingBundle, Flags,
    Provenance,
};
use vela_protocol::project::{self, Project};
use vela_protocol::{events, repo, state};

fn fixture_finding() -> FindingBundle {
    FindingBundle::new(
        Assertion {
            text: "Entity-resolve fixture finding".to_string(),
            assertion_type: "mechanism".to_string(),
            entities: vec![Entity {
                name: "PDGFRB".to_string(),
                entity_type: "gene".to_string(),
                identifiers: serde_json::Map::new(),
                canonical_id: None,
                candidates: vec![],
                aliases: vec![],
                resolution_provenance: None,
                resolution_confidence: 0.6,
                resolution_method: None,
                species_context: None,
                needs_review: true,
            }],
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
            doi: Some("10.1/test-entity".to_string()),
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Entity-resolve fixture source".to_string(),
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

fn frontier_with_unresolved_entity() -> Project {
    project::assemble(
        "entity-resolve-fixture",
        vec![fixture_finding()],
        0,
        0,
        "test",
    )
}

#[test]
fn entity_resolve_apply_sets_canonical_id_and_clears_needs_review() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let frontier = frontier_with_unresolved_entity();
    repo::save_to_path(&path, &frontier).expect("save frontier");
    let finding_id = frontier.findings[0].id.clone();

    let report = state::resolve_finding_entity(
        &path,
        &finding_id,
        "PDGFRB",
        "hgnc",
        "8804",
        0.95,
        Some("PDGFRB"),
        "manual",
        "reviewer:test",
        "Resolved against HGNC",
        true,
    )
    .expect("resolve applies");
    assert_eq!(report.command, "entity-resolve");
    assert_eq!(report.proposal_status, "applied");

    let reloaded = repo::load_from_path(&path).expect("reload");
    let f = reloaded
        .findings
        .iter()
        .find(|f| f.id == finding_id)
        .unwrap();
    let e = f
        .assertion
        .entities
        .iter()
        .find(|e| e.name == "PDGFRB")
        .unwrap();
    assert!(!e.needs_review);
    assert!(e.canonical_id.is_some());
    assert_eq!(e.resolution_confidence, 0.95);
    let canonical = e.canonical_id.as_ref().unwrap();
    assert_eq!(canonical.source, "hgnc");
    assert_eq!(canonical.id, "8804");
}

#[test]
fn entity_resolve_refuses_unknown_entity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let frontier = frontier_with_unresolved_entity();
    repo::save_to_path(&path, &frontier).expect("save frontier");
    let finding_id = frontier.findings[0].id.clone();

    let result = state::resolve_finding_entity(
        &path,
        &finding_id,
        "NOT_AN_ENTITY",
        "hgnc",
        "8804",
        0.95,
        None,
        "manual",
        "reviewer:test",
        "should fail",
        true,
    );
    assert!(result.is_err());
}

#[test]
fn entity_resolve_event_validates() {
    let payload_ok = json!({
        "proposal_id": "vpr_test",
        "entity_name": "PDGFRB",
        "source": "hgnc",
        "id": "8804",
        "confidence": 0.95,
    });
    events::validate_event_payload("finding.entity_resolved", &payload_ok).expect("ok");

    let payload_bad_confidence = json!({
        "proposal_id": "vpr_test",
        "entity_name": "PDGFRB",
        "source": "hgnc",
        "id": "8804",
        "confidence": 1.5,
    });
    let r = events::validate_event_payload("finding.entity_resolved", &payload_bad_confidence);
    assert!(r.is_err());
}
