use std::fs;
use std::path::Path;

use serde_json::Value;
use tempfile::tempdir;
use vela_edge::artifact_to_state;
use vela_protocol::project;
use vela_protocol::proposals;
use vela_protocol::repo;
fn write_empty_frontier(path: &Path) {
    let frontier = project::assemble("artifact-to-state test", vec![], 0, 0, "test frontier");
    repo::save_to_path(path, &frontier).expect("save frontier");
}

fn write_packet(path: &Path) {
    let packet = serde_json::json!({
        "schema": "carina.artifact_packet.v0.1",
        "packet_id": "cap_sidon_a309370_agent_demo",
        "producer": {
            "kind": "agent",
            "id": "agent:scienceclaw-demo",
            "name": "ScienceClaw-shaped demo agent"
        },
        "topic": "Sidon set lower bounds for OEIS A309370",
        "created_at": "2026-05-06T00:00:00Z",
        "artifacts": [
            {
                "id": "ext_artifact_001",
                "kind": "model_output",
                "title": "Agent search output",
                "locator": "https://example.org/agent-output.json",
                "content_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "parents": [],
                "metadata": {"tool": "search"}
            },
            {
                "id": "ext_artifact_002",
                "kind": "table",
                "title": "Bound comparison table",
                "locator": "https://example.org/bounds.csv",
                "content_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "parents": ["ext_artifact_001"],
                "metadata": {"rows": 7}
            },
            {
                "id": "ext_artifact_003",
                "kind": "registry_record",
                "title": "OEIS sequence pull",
                "locator": "https://oeis.org/A309370",
                "content_hash": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "parents": ["ext_artifact_001"],
                "metadata": {"oeis_id": "A309370"}
            }
        ],
        "candidate_claims": [
            {
                "id": "claim_001",
                "assertion": "Agent search proposes a Sidon set witnessing a(14) >= 79.",
                "assertion_type": "combinatorial",
                "evidence_artifact_ids": ["ext_artifact_001", "ext_artifact_002"],
                "source_refs": ["https://example.org/agent-output.json"],
                "conditions": ["all pairwise sums distinct", "witness independently checkable"],
                "confidence": 0.55,
                "caveats": ["Agent-generated; requires reviewer acceptance."]
            },
            {
                "id": "claim_002",
                "assertion": "Agent search flags witness re-verification as a condition on the proposed bound.",
                "assertion_type": "combinatorial",
                "evidence_artifact_ids": ["ext_artifact_003"],
                "source_refs": ["https://oeis.org/A309370"],
                "conditions": ["deterministic verifier available", "witness re-runs to the same result"],
                "confidence": 0.5,
                "caveats": ["Registry-derived summary; verify against the canonical sequence entry."]
            }
        ],
        "open_needs": [
            {
                "id": "need_001",
                "question": "Which independent verifier re-checks the proposed witness against the Sidon-set definition?",
                "rationale": "This would separate a claimed bound from a re-checked, witness-backed bound."
            }
        ],
        "caveats": ["ScienceClaw-shaped packet used as source material, not accepted truth."]
    });
    fs::write(path, serde_json::to_string_pretty(&packet).unwrap()).expect("write packet");
}

#[test]
fn artifact_to_state_writes_pending_artifact_claim_and_gap_proposals() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let packet_path = dir.path().join("packet.json");
    write_empty_frontier(&frontier_path);
    write_packet(&packet_path);

    let report = artifact_to_state::import_packet_at_path(
        &frontier_path,
        &packet_path,
        "agent:scienceclaw-demo",
        false,
    )
    .expect("import packet");

    assert_eq!(report.packet_id, "cap_sidon_a309370_agent_demo");
    assert_eq!(report.artifact_proposals, 3);
    assert_eq!(report.finding_proposals, 2);
    assert_eq!(report.gap_proposals, 1);
    assert_eq!(report.applied_artifact_events, 0);
    assert_eq!(report.trusted_state_effect, "none");
    assert!(!report.idempotency.duplicate_packet);
    assert!(report.idempotency.packet_hash.starts_with("sha256:"));

    let frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(frontier.artifacts.len(), 0);
    assert_eq!(frontier.proposals.len(), 6);
    assert_eq!(
        frontier
            .proposals
            .iter()
            .filter(|p| p.kind == "artifact.assert")
            .count(),
        3
    );
    assert!(
        frontier.proposals.iter().any(|p| p.kind == "finding.add"
            && p.payload["finding"]["flags"]["gap"] == Value::Bool(true))
    );
}

#[test]
fn artifact_to_state_apply_artifacts_only_leaves_truth_changes_pending() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let packet_path = dir.path().join("packet.json");
    write_empty_frontier(&frontier_path);
    write_packet(&packet_path);

    let report = artifact_to_state::import_packet_at_path(
        &frontier_path,
        &packet_path,
        "agent:scienceclaw-demo",
        true,
    )
    .expect("import packet");

    assert_eq!(report.applied_artifact_events, 3);
    assert_eq!(report.pending_truth_proposals, 3);
    assert_eq!(report.trusted_state_effect, "artifact_only");

    let frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(frontier.artifacts.len(), 3);
    assert_eq!(
        frontier
            .proposals
            .iter()
            .filter(|p| p.kind == "artifact.assert" && p.status == "applied")
            .count(),
        3
    );
    assert_eq!(
        frontier
            .proposals
            .iter()
            .filter(|p| p.kind == "finding.add" && p.status == "pending_review")
            .count(),
        3
    );
}

#[test]
fn artifact_to_state_rerun_skips_duplicate_proposals() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let packet_path = dir.path().join("packet.json");
    write_empty_frontier(&frontier_path);
    write_packet(&packet_path);

    let first = artifact_to_state::import_packet_at_path(
        &frontier_path,
        &packet_path,
        "agent:scienceclaw-demo",
        false,
    )
    .expect("first import");
    let second = artifact_to_state::import_packet_at_path(
        &frontier_path,
        &packet_path,
        "agent:scienceclaw-demo",
        false,
    )
    .expect("second import");

    // First import creates 6 proposals; a re-run of the same packet creates
    // NONE — every target is already present, so all 6 are skipped (the dedup
    // key is the content-addressed target id, not the per-call proposal id).
    assert_eq!(first.proposal_ids.len(), 6);
    assert_eq!(second.proposal_ids.len(), 0);
    assert!(second.idempotency.duplicate_packet);
    assert_eq!(
        second.idempotency.skipped_existing_proposals.len()
            + second.idempotency.skipped_existing_artifacts.len(),
        6
    );

    let frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(frontier.proposals.len(), 6);
}

#[test]
fn artifact_to_state_rejects_missing_artifact_references_and_bad_parents() {
    let dir = tempdir().expect("tempdir");
    let packet_path = dir.path().join("bad-packet.json");
    write_packet(&packet_path);

    let mut packet: Value =
        serde_json::from_slice(&fs::read(&packet_path).expect("read packet")).unwrap();
    packet["candidate_claims"][0]["evidence_artifact_ids"] =
        serde_json::json!(["ext_artifact_missing"]);
    fs::write(&packet_path, serde_json::to_string_pretty(&packet).unwrap())
        .expect("write bad packet");
    let err = artifact_to_state::ArtifactPacket::from_path(&packet_path)
        .and_then(|packet| packet.validate())
        .expect_err("missing artifact ref should fail");
    assert!(err.contains("unknown artifact ext_artifact_missing"));

    packet["candidate_claims"][0]["evidence_artifact_ids"] =
        serde_json::json!(["ext_artifact_001"]);
    packet["artifacts"][1]["parents"] = serde_json::json!(["ext_artifact_missing"]);
    fs::write(&packet_path, serde_json::to_string_pretty(&packet).unwrap())
        .expect("write bad parent packet");
    let err = artifact_to_state::ArtifactPacket::from_path(&packet_path)
        .and_then(|packet| packet.validate())
        .expect_err("bad parent should fail");
    assert!(err.contains("parent ext_artifact_missing"));
}

#[test]
fn bridge_kit_validate_reports_valid_packet() {
    let dir = tempdir().expect("tempdir");
    let packet_path = dir.path().join("packet.json");
    write_packet(&packet_path);

    let report = artifact_to_state::validate_bridge_kit_path(&packet_path);

    assert!(report.ok);
    assert_eq!(report.command, "bridge-kit.validate");
    assert_eq!(report.packet_count, 1);
    assert_eq!(report.valid_packet_count, 1);
    assert_eq!(report.invalid_packet_count, 0);
    assert_eq!(
        report.packets[0].packet_id.as_deref(),
        Some("cap_sidon_a309370_agent_demo")
    );
    assert_eq!(report.packets[0].artifact_count, 3);
    assert_eq!(report.packets[0].candidate_claim_count, 2);
    assert_eq!(report.packets[0].open_need_count, 1);
}

#[test]
fn bridge_kit_validate_reports_invalid_packet_without_importing() {
    let dir = tempdir().expect("tempdir");
    let packet_path = dir.path().join("bad-packet.json");
    write_packet(&packet_path);

    let mut packet: Value =
        serde_json::from_slice(&fs::read(&packet_path).expect("read packet")).unwrap();
    packet["candidate_claims"][0]["evidence_artifact_ids"] =
        serde_json::json!(["ext_artifact_missing"]);
    fs::write(&packet_path, serde_json::to_string_pretty(&packet).unwrap())
        .expect("write bad packet");

    let report = artifact_to_state::validate_bridge_kit_path(dir.path());

    assert!(!report.ok);
    assert_eq!(report.packet_count, 1);
    assert_eq!(report.valid_packet_count, 0);
    assert_eq!(report.invalid_packet_count, 1);
    assert!(
        report.packets[0].errors[0].contains("unknown artifact ext_artifact_missing"),
        "unexpected errors: {:?}",
        report.packets[0].errors
    );
}

#[test]
fn proposals_preview_reports_in_memory_count_deltas_without_mutation() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let packet_path = dir.path().join("packet.json");
    write_empty_frontier(&frontier_path);
    write_packet(&packet_path);
    artifact_to_state::import_packet_at_path(
        &frontier_path,
        &packet_path,
        "agent:scienceclaw-demo",
        false,
    )
    .expect("import packet");

    let before = repo::load_from_path(&frontier_path).expect("reload frontier");
    let proposal_id = before
        .proposals
        .iter()
        .find(|p| p.kind == "finding.add")
        .expect("finding proposal")
        .id
        .clone();
    let preview =
        proposals::preview_at_path(&frontier_path, &proposal_id, "reviewer:test").expect("preview");

    assert_eq!(preview.proposal_id, proposal_id);
    assert_eq!(preview.kind, "finding.add");
    assert_eq!(preview.findings_delta, 1);
    assert_eq!(preview.events_delta, 1);
    assert!(preview.proof_would_be_stale);

    let after = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(before.findings.len(), after.findings.len());
    assert_eq!(before.events.len(), after.events.len());
    assert_eq!(before.proposals, after.proposals);
}

#[test]
fn proposals_preview_reports_applied_proposal_event_without_mutation() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let packet_path = dir.path().join("packet.json");
    write_empty_frontier(&frontier_path);
    write_packet(&packet_path);
    artifact_to_state::import_packet_at_path(
        &frontier_path,
        &packet_path,
        "agent:scienceclaw-demo",
        false,
    )
    .expect("import packet");

    let before_accept = repo::load_from_path(&frontier_path).expect("reload frontier");
    let proposal_id = before_accept
        .proposals
        .iter()
        .find(|p| p.kind == "finding.add")
        .expect("finding proposal")
        .id
        .clone();
    let event_id = proposals::accept_at_path(
        &frontier_path,
        &proposal_id,
        "reviewer:test",
        "Accepted bounded preview regression test.",
    )
    .expect("accept proposal");
    let before_preview = repo::load_from_path(&frontier_path).expect("reload accepted frontier");

    let preview = proposals::preview_at_path(&frontier_path, &proposal_id, "reviewer:test")
        .expect("preview applied proposal");

    assert_eq!(preview.applied_event_id, event_id);
    assert_eq!(preview.findings_delta, 0);
    assert_eq!(preview.events_delta, 0);
    assert_eq!(preview.artifacts_delta, 0);
    assert!(!preview.proof_would_be_stale);

    let after_preview = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(before_preview.findings.len(), after_preview.findings.len());
    assert_eq!(before_preview.events.len(), after_preview.events.len());
    assert_eq!(before_preview.proposals, after_preview.proposals);
}
