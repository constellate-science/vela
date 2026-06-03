use std::fs;
use std::path::Path;

use serde_json::{Value, json};
use tempfile::tempdir;
use vela_protocol::{project, proposals, repo, runtime_adapters};

fn write_empty_frontier(path: &Path) {
    let frontier = project::assemble("runtime adapter test", vec![], 0, 0, "test frontier");
    repo::save_to_path(path, &frontier).expect("save frontier");
}

fn write_scienceclaw_export(path: &Path) {
    let export = json!({
        "schema": "scienceclaw.artifact_export.v1",
        "run_id": "scienceclaw_anti_amyloid_demo",
        "producer": {
            "kind": "agent",
            "id": "agent:scienceclaw-demo",
            "name": "ScienceClaw-shaped demo agent"
        },
        "topic": "Anti-amyloid translation in Alzheimer's disease",
        "created_at": "2026-05-06T00:00:00Z",
        "artifacts": [
            {
                "id": "sc_artifact_001",
                "kind": "model_output",
                "title": "Agent anti-amyloid synthesis",
                "locator": "https://example.org/scienceclaw/anti-amyloid/synthesis.json",
                "content_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "parents": [],
                "metadata": {"skill": "synthesis"}
            },
            {
                "id": "sc_artifact_002",
                "kind": "table",
                "title": "Trial endpoint comparison",
                "locator": "https://example.org/scienceclaw/anti-amyloid/endpoints.csv",
                "content_hash": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                "parents": ["sc_artifact_001"],
                "metadata": {"rows": 7}
            }
        ],
        "candidate_claims": [
            {
                "id": "claim_001",
                "assertion": "Runtime synthesis proposes that anti-amyloid clinical benefit remains bounded by early symptomatic disease stage.",
                "assertion_type": "therapeutic",
                "evidence_artifact_ids": ["sc_artifact_001", "sc_artifact_002"],
                "source_refs": ["https://example.org/scienceclaw/anti-amyloid/synthesis.json"],
                "conditions": ["early symptomatic Alzheimer's disease", "amyloid confirmation required"],
                "confidence": 0.55,
                "caveats": ["External runtime output; requires reviewer acceptance."]
            }
        ],
        "open_needs": [
            {
                "id": "need_001",
                "question": "Which public dataset links amyloid clearance, ARIA, and cognitive endpoints at patient level?",
                "rationale": "This is decision-critical for benefit-risk interpretation."
            }
        ],
        "caveats": ["Runtime output is source material until Vela review."]
    });
    fs::write(path, serde_json::to_string_pretty(&export).unwrap()).expect("write export");
}

fn write_agent_discourse_export(path: &Path, target_finding_id: &str) {
    let export = json!({
        "schema": "agent_discourse.v1",
        "thread_id": "disc_anti_amyloid_demo",
        "runtime": {
            "id": "agent4science-demo",
            "name": "Agent discourse demo"
        },
        "topic": "Anti-amyloid translation in Alzheimer's disease",
        "created_at": "2026-05-06T00:00:00Z",
        "posts": [
            {
                "id": "post_001",
                "title": "Bounded anti-amyloid translation claim",
                "assertion": "Discourse post proposes that APOE4 and ARIA monitoring narrow the eligible anti-amyloid population.",
                "body": "The post cites label-style risk-management constraints and asks for review.",
                "locator": "https://example.org/discourse/post_001",
                "content_hash": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
                "conditions": ["monoclonal antibody treatment", "MRI monitoring available"],
                "confidence": 0.5,
                "source_refs": ["https://example.org/discourse/post_001"],
                "target_finding_id": target_finding_id
            }
        ],
        "comments": [
            {
                "id": "comment_001",
                "post_id": "post_001",
                "body": "Reviewer asks for label and protocol support before accepting the narrowed scope.",
                "locator": "https://example.org/discourse/comment_001",
                "content_hash": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
                "target_finding_id": target_finding_id
            }
        ],
        "reviews": [
            {
                "id": "review_001",
                "post_id": "post_001",
                "decision": "needs_revision",
                "body": "Treat the post as a review signal, not a canonical state update.",
                "locator": "https://example.org/discourse/review_001",
                "content_hash": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
                "target_finding_id": target_finding_id
            }
        ],
        "open_needs": []
    });
    fs::write(path, serde_json::to_string_pretty(&export).unwrap()).expect("write export");
}

fn options(
    adapter: &str,
    input: &Path,
    apply_artifacts: bool,
) -> runtime_adapters::RuntimeAdapterRunOptions {
    runtime_adapters::RuntimeAdapterRunOptions {
        adapter: adapter.to_string(),
        input: input.to_path_buf(),
        actor: "agent:runtime-demo".to_string(),
        dry_run: false,
        apply_artifacts,
        write_inbox: false,
    }
}

#[test]
fn runtime_adapter_rejects_missing_locator_bad_hash_and_unknown_parent() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let input_path = dir.path().join("scienceclaw.json");
    write_empty_frontier(&frontier_path);
    write_scienceclaw_export(&input_path);

    let mut export: Value =
        serde_json::from_slice(&fs::read(&input_path).expect("read export")).unwrap();
    export["artifacts"][0]["locator"] = json!("");
    fs::write(&input_path, serde_json::to_string_pretty(&export).unwrap()).expect("write export");
    let err = runtime_adapters::run(
        &frontier_path,
        options("scienceclaw-artifact-v1", &input_path, false),
    )
    .expect_err("missing locator should fail");
    assert!(err.contains("locator must be non-empty"));

    export["artifacts"][0]["locator"] =
        json!("https://example.org/scienceclaw/anti-amyloid/synthesis.json");
    export["artifacts"][0]["content_hash"] = json!("sha256:not-a-real-hash");
    fs::write(&input_path, serde_json::to_string_pretty(&export).unwrap()).expect("write export");
    let err = runtime_adapters::run(
        &frontier_path,
        options("scienceclaw-artifact-v1", &input_path, false),
    )
    .expect_err("bad hash should fail");
    assert!(err.contains("sha256"));

    export["artifacts"][0]["content_hash"] =
        json!("sha256:1111111111111111111111111111111111111111111111111111111111111111");
    export["artifacts"][1]["parents"] = json!(["missing_parent"]);
    fs::write(&input_path, serde_json::to_string_pretty(&export).unwrap()).expect("write export");
    let err = runtime_adapters::run(
        &frontier_path,
        options("scienceclaw-artifact-v1", &input_path, false),
    )
    .expect_err("bad parent should fail");
    assert!(err.contains("unknown parent missing_parent"));
}

#[test]
fn scienceclaw_runtime_adapter_emits_artifact_and_truth_proposals() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let input_path = dir.path().join("scienceclaw.json");
    write_empty_frontier(&frontier_path);
    write_scienceclaw_export(&input_path);

    let report = runtime_adapters::run(
        &frontier_path,
        options("scienceclaw-artifact-v1", &input_path, false),
    )
    .expect("run adapter");

    assert_eq!(report.command, "runtime-adapter.run");
    assert_eq!(report.adapter, "scienceclaw-artifact-v1");
    assert_eq!(report.artifact_proposals, 2);
    assert_eq!(report.finding_proposals, 1);
    assert_eq!(report.gap_proposals, 1);
    assert_eq!(report.pending_truth_proposals, 2);
    assert_eq!(report.trusted_state_effect, "none");
    assert!(report.idempotency.packet_hash.starts_with("sha256:"));
    assert!(
        report
            .packet_id
            .as_deref()
            .is_some_and(|id| id.starts_with("cap_"))
    );
    assert!(report.run_path.is_some());

    let frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(frontier.artifacts.len(), 0);
    assert_eq!(frontier.proposals.len(), 4);
    assert!(frontier.proposals.iter().any(|proposal| {
        proposal
            .agent_run
            .as_ref()
            .is_some_and(|run| run.model == "runtime-adapter:scienceclaw-artifact-v1")
    }));
}

#[test]
fn runtime_adapter_apply_artifacts_only_leaves_truth_pending() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let input_path = dir.path().join("scienceclaw.json");
    write_empty_frontier(&frontier_path);
    write_scienceclaw_export(&input_path);

    let report = runtime_adapters::run(
        &frontier_path,
        options("scienceclaw-artifact-v1", &input_path, true),
    )
    .expect("run adapter");

    assert_eq!(report.applied_artifact_events, 2);
    assert_eq!(report.pending_truth_proposals, 2);
    assert_eq!(report.trusted_state_effect, "artifact_only");
    let frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(frontier.artifacts.len(), 2);
    assert!(
        frontier
            .artifacts
            .iter()
            .all(|artifact| artifact.target_findings.is_empty()),
        "applied runtime artifacts must not target non-canonical proposal findings"
    );
    assert_eq!(
        frontier
            .proposals
            .iter()
            .filter(|proposal| proposal.kind == "finding.add"
                && proposal.status == "pending_review")
            .count(),
        2
    );
}

#[test]
fn runtime_adapter_rerun_reports_duplicate_packet_without_duplicate_proposals() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let input_path = dir.path().join("scienceclaw.json");
    write_empty_frontier(&frontier_path);
    write_scienceclaw_export(&input_path);

    let first = runtime_adapters::run(
        &frontier_path,
        options("scienceclaw-artifact-v1", &input_path, false),
    )
    .expect("first run");
    let second = runtime_adapters::run(
        &frontier_path,
        options("scienceclaw-artifact-v1", &input_path, false),
    )
    .expect("second run");

    assert_eq!(first.proposal_ids.len(), 4);
    assert_eq!(second.proposal_ids.len(), 0);
    assert!(second.idempotency.duplicate_packet);
    assert_eq!(
        second.idempotency.skipped_existing_proposals.len()
            + second.idempotency.skipped_existing_artifacts.len(),
        4
    );

    let frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(frontier.proposals.len(), 4);
}

#[test]
fn agent_discourse_runtime_adapter_maps_comments_to_review_notes() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let input_path = dir.path().join("discourse.json");
    write_empty_frontier(&frontier_path);
    write_scienceclaw_export(&dir.path().join("seed.json"));
    let seed_report = runtime_adapters::run(
        &frontier_path,
        options(
            "scienceclaw-artifact-v1",
            &dir.path().join("seed.json"),
            false,
        ),
    )
    .expect("seed proposals");
    let seed_frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    let target_finding_id = seed_frontier
        .proposals
        .iter()
        .find(|proposal| proposal.kind == "finding.add")
        .map(|proposal| proposal.target.id.clone())
        .expect("finding proposal");
    assert_eq!(seed_report.finding_proposals, 1);
    let seed_proposal_id = seed_frontier
        .proposals
        .iter()
        .find(|proposal| proposal.kind == "finding.add")
        .map(|proposal| proposal.id.clone())
        .expect("finding proposal id");
    proposals::accept_at_path(
        &frontier_path,
        &seed_proposal_id,
        "reviewer:runtime-test",
        "Accept bounded seed finding for discourse-note target",
    )
    .expect("accept seed finding");
    write_agent_discourse_export(&input_path, &target_finding_id);

    let report = runtime_adapters::run(
        &frontier_path,
        options("agent-discourse-v1", &input_path, false),
    )
    .expect("run adapter");

    assert_eq!(report.adapter, "agent-discourse-v1");
    assert_eq!(report.artifact_proposals, 3);
    assert_eq!(report.finding_proposals, 1);
    assert_eq!(report.review_note_proposals, 2);
    assert_eq!(report.pending_truth_proposals, 1);

    let frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert_eq!(
        frontier
            .proposals
            .iter()
            .filter(|proposal| proposal.kind == "finding.note")
            .count(),
        2
    );
    assert!(frontier.proposals.iter().any(|proposal| {
        proposal
            .source_refs
            .iter()
            .any(|source| source.starts_with("runtime_packet:"))
    }));
}

#[test]
fn runtime_adapter_dry_run_does_not_mutate_frontier_or_write_run() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let input_path = dir.path().join("scienceclaw.json");
    write_empty_frontier(&frontier_path);
    write_scienceclaw_export(&input_path);

    let mut run_options = options("scienceclaw-artifact-v1", &input_path, true);
    run_options.dry_run = true;
    let report = runtime_adapters::run(&frontier_path, run_options).expect("dry run");

    assert!(report.dry_run);
    assert_eq!(report.artifact_proposals, 0);
    assert_eq!(report.proposal_ids.len(), 0);
    assert!(report.packet_path.is_none());
    assert!(report.run_path.is_none());
    let frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    assert!(frontier.proposals.is_empty());
    assert!(frontier.artifacts.is_empty());
}

// v0.76.2: Agent4Science review-packet adapter stub.
//
// The Gowers (2026-05-08) post argues for a path where AI-produced
// research lands in a venue moderated by human certification. This
// test pins the wire format and shows that the substrate produces
// review-note proposals (not auto-applied accept events). A human
// reviewer still has to sign the verdict separately.

fn write_agent4science_review_packet(path: &Path, target_finding_id: &str) {
    let packet = json!({
        "schema": "carina.review_packet.v0.1",
        "review_id": "rev_a4s_demo_001",
        "target_finding_id": target_finding_id,
        "verdict": "needs_revision",
        "reasoning": "The bound proven is correct under the stated hypothesis but the hypothesis itself overreaches; the paper would need to narrow scope to APOE4-positive prodromal AD before the finding can be accepted.",
        "reviewer": {
            "id": "agent:agent4science-reviewer-2026-05-09",
            "type": "agent"
        },
        "evidence": [
            {
                "locator": "doi:10.1038/s41586-020-2247-3",
                "span": "Section 3.2, lines 14 to 22"
            }
        ],
        "signature": "ed25519:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
    });
    fs::write(
        path,
        serde_json::to_string_pretty(&packet).expect("packet json"),
    )
    .expect("write packet");
}

#[test]
fn agent4science_runtime_adapter_emits_review_note_for_human_adjudication() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let input_path = dir.path().join("a4s-review.json");
    write_empty_frontier(&frontier_path);

    // Seed a finding the review packet can target.
    write_scienceclaw_export(&dir.path().join("seed.json"));
    runtime_adapters::run(
        &frontier_path,
        options(
            "scienceclaw-artifact-v1",
            &dir.path().join("seed.json"),
            false,
        ),
    )
    .expect("seed proposals");
    let seed_frontier = repo::load_from_path(&frontier_path).expect("reload frontier");
    let target_finding_id = seed_frontier
        .proposals
        .iter()
        .find(|p| p.kind == "finding.add")
        .map(|p| p.target.id.clone())
        .expect("finding proposal");
    let seed_proposal_id = seed_frontier
        .proposals
        .iter()
        .find(|p| p.kind == "finding.add")
        .map(|p| p.id.clone())
        .expect("finding proposal id");
    proposals::accept_at_path(
        &frontier_path,
        &seed_proposal_id,
        "reviewer:runtime-test",
        "Accept seed for agent4science target",
    )
    .expect("accept seed");

    write_agent4science_review_packet(&input_path, &target_finding_id);
    let report = runtime_adapters::run(
        &frontier_path,
        options("agent4science-review-v1", &input_path, false),
    )
    .expect("run agent4science adapter");

    assert_eq!(report.adapter, "agent4science-review-v1");
    // Doctrine: the adapter writes a review-note proposal under
    // the agent reviewer. It does NOT write a finding.review accept
    // event. A human reviewer must sign that separately.
    assert!(
        report.review_note_proposals >= 1,
        "expected at least one review-note proposal, got {}",
        report.review_note_proposals
    );
    let frontier = repo::load_from_path(&frontier_path).expect("reload");
    let review_notes: Vec<_> = frontier
        .proposals
        .iter()
        .filter(|p| p.kind == "finding.note")
        .collect();
    assert!(
        !review_notes.is_empty(),
        "expected finding.note proposals from agent4science adapter"
    );
}

#[test]
fn agent4science_adapter_rejects_unknown_verdict() {
    let dir = tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let input_path = dir.path().join("a4s-bad.json");
    write_empty_frontier(&frontier_path);
    let bad = json!({
        "schema": "carina.review_packet.v0.1",
        "review_id": "rev_bad_001",
        "target_finding_id": "vf_demo",
        "verdict": "amazing",
        "reasoning": "x",
        "reviewer": {"id": "agent:bot", "type": "agent"}
    });
    fs::write(&input_path, serde_json::to_string_pretty(&bad).unwrap()).expect("write packet");
    let err = runtime_adapters::run(
        &frontier_path,
        options("agent4science-review-v1", &input_path, false),
    )
    .expect_err("unknown verdict must reject");
    assert!(
        err.contains("verdict"),
        "error should mention verdict: {err}"
    );
}
