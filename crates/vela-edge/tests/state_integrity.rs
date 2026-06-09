use serde_json::json;
use vela_protocol::bundle::{
    Assertion, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Evidence, Extraction,
    FindingBundle, Flags, Provenance,
};
use vela_protocol::events::{self, FindingEventInput, NULL_HASH};
use vela_protocol::project::{self, Project};
use vela_protocol::proposals::{
    ProofPacketRecord, StateProposal, new_proposal, record_proof_export,
};
use vela_protocol::repo;
use vela_edge::state_integrity;
fn finding(id_text: &str) -> FindingBundle {
    let assertion = Assertion {
        text: format!("BBB integrity test finding {id_text}"),
        assertion_type: "mechanism".to_string(),
        entities: Vec::new(),
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let provenance = Provenance {
        source_type: "published_paper".to_string(),
        doi: Some(format!("10.0000/integrity.{id_text}")),
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: Some(format!("https://example.org/{id_text}")),
        title: format!("Integrity fixture {id_text}"),
        authors: Vec::new(),
        year: Some(2026),
        journal: None,
        license: None,
        publisher: None,
        funders: Vec::new(),
        extraction: Extraction::default(),
        review: None,
        citation_count: None,
    };
    let mut bundle = FindingBundle::new(
        assertion,
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
            text: "human BBB context".to_string(),
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
        Confidence {
            kind: ConfidenceKind::FrontierEpistemic,
            score: 0.5,
            basis: "fixture".to_string(),
            method: ConfidenceMethod::ExpertJudgment,
            components: None,
            extraction_confidence: 1.0,
        },
        provenance,
        Flags::default(),
    );
    bundle.created = "2026-05-07T00:00:00Z".to_string();
    bundle
}

fn frontier_with_one_finding() -> Project {
    let finding = finding("one");
    let mut frontier = project::assemble("integrity frontier", vec![finding.clone()], 0, 0, "test");
    frontier.frontier_id = Some("vfr_integrity_test".to_string());
    frontier
        .events
        .push(events::new_finding_event(FindingEventInput {
            kind: "finding.asserted",
            finding_id: &finding.id,
            actor_id: "reviewer:test",
            actor_type: "human",
            reason: "fixture genesis",
            before_hash: NULL_HASH,
            after_hash: &events::finding_hash(&finding),
            payload: json!({"proposal_id": "vpr_fixture", "finding": finding}),
            caveats: Vec::new(),
        }));
    frontier
}

#[test]
fn state_integrity_reports_duplicate_events_as_structural_failure() {
    let mut frontier = frontier_with_one_finding();
    frontier.events.push(frontier.events[0].clone());

    let report = state_integrity::analyze(&frontier);

    assert_eq!(report.schema, "vela.state_integrity_report.v0.1");
    assert_eq!(report.status, "fail");
    assert!(
        report
            .structural_errors
            .iter()
            .any(|error| error.rule_id == "duplicate_event_id")
    );
    assert_eq!(report.proof_freshness, "unknown");
}

#[test]
fn state_integrity_reports_applied_proposal_without_event() {
    let mut frontier = frontier_with_one_finding();
    let proposal = StateProposal {
        status: "applied".to_string(),
        applied_event_id: None,
        reviewed_by: Some("reviewer:test".to_string()),
        reviewed_at: Some("2026-05-07T00:00:00Z".to_string()),
        decision_reason: Some("fixture".to_string()),
        ..new_proposal(
            "finding.note",
            events::StateTarget {
                r#type: "finding".to_string(),
                id: frontier.findings[0].id.clone(),
            },
            "reviewer:test",
            "human",
            "fixture",
            json!({"text": "reviewed note"}),
            Vec::new(),
            Vec::new(),
        )
    };
    frontier.proposals.push(proposal);

    let report = state_integrity::analyze(&frontier);

    assert_eq!(report.status, "fail");
    assert!(
        report
            .structural_errors
            .iter()
            .any(|error| error.rule_id == "applied_proposal_missing_event")
    );
}

#[test]
fn state_integrity_reports_stale_proof_after_accepted_event() {
    let mut frontier = frontier_with_one_finding();
    let snapshot_hash = events::snapshot_hash(&frontier);
    let event_log_hash = events::event_log_hash(&frontier.events);
    record_proof_export(
        &mut frontier,
        ProofPacketRecord {
            generated_at: "2026-05-07T00:00:00Z".to_string(),
            snapshot_hash,
            event_log_hash,
            packet_manifest_hash:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
        },
    );
    frontier
        .events
        .push(events::new_finding_event(FindingEventInput {
            kind: "finding.reviewed",
            finding_id: &frontier.findings[0].id,
            actor_id: "reviewer:test",
            actor_type: "human",
            reason: "new event after proof export",
            before_hash: &events::finding_hash(&frontier.findings[0]),
            after_hash: &events::finding_hash(&frontier.findings[0]),
            payload: json!({"proposal_id": "vpr_after_proof", "status": "accepted"}),
            caveats: Vec::new(),
        }));

    let report = state_integrity::analyze(&frontier);

    assert_eq!(report.status, "fail");
    assert_eq!(report.proof_freshness, "stale");
    assert!(
        report
            .structural_errors
            .iter()
            .any(|error| error.rule_id == "stale_proof_packet")
    );
}

#[test]
fn integrity_cli_json_reports_state_integrity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("frontier.json");
    let mut frontier = frontier_with_one_finding();
    frontier.events.push(frontier.events[0].clone());
    repo::save_to_path(&path, &frontier).expect("save frontier");

    let report = state_integrity::analyze_path(&path).expect("integrity report");

    assert_eq!(report.status, "fail");
    assert!(
        report
            .structural_errors
            .iter()
            .any(|error| error.rule_id == "duplicate_event_id")
    );
}
