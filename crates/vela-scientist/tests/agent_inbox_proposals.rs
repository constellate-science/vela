//! v0.52: End-to-end test of the agent inbox emitting NegativeResult
//! and Trajectory proposals through the same review-gated flow as
//! findings.
//!
//! Demonstrates that:
//! 1. An agent can build a `negative_result.assert` proposal via
//!    `agent::build_negative_result_assert_proposal`.
//! 2. The proposal validates through `proposals::validate_proposal_shape`.
//! 3. Accepting the proposal pushes the NegativeResult to
//!    `state.negative_results` and emits a canonical
//!    `negative_result.asserted` event.
//! 4. The same path works for Trajectory creation and step append.
//!
//! Without this test the "agents propose, humans review, CLI signs"
//! doctrine extends only to findings, not to the v0.49/v0.50
//! primitives.

use std::path::PathBuf;
use tempfile::TempDir;

use vela_protocol::bundle::{
    Conditions, Extraction, NegativeResult, NegativeResultKind, Provenance, Trajectory,
    TrajectoryStep, TrajectoryStepKind,
};
use vela_protocol::project::{Project, ProjectMeta, ProjectStats};
use vela_protocol::proposals::{self, AgentRun};
use vela_protocol::repo;

use vela_scientist::agent::{
    AgentContext, build_negative_result_assert_proposal, build_trajectory_create_proposal,
    build_trajectory_step_append_proposal,
};

fn empty_frontier(name: &str) -> Project {
    Project {
        vela_version: "0.52.0".to_string(),
        schema: "test".to_string(),
        frontier_id: None,
        project: ProjectMeta {
            name: name.to_string(),
            description: "agent-inbox-proposals fixture".to_string(),
            compiled_at: "2026-05-04T00:00:00Z".to_string(),
            compiler: "vela-scientist-test/0".to_string(),
            papers_processed: 0,
            errors: 0,
            dependencies: vec![],
        },
        stats: ProjectStats::default(),
        findings: vec![],
        sources: vec![],
        evidence_atoms: vec![],
        condition_records: vec![],
        review_events: vec![],
        confidence_updates: vec![],
        events: vec![],
        proposals: vec![],
        attempts: vec![],
        attempt_resolutions: vec![],
        proof_state: Default::default(),
        signatures: vec![],
        actors: vec![],
        replications: vec![],
        datasets: vec![],
        code_artifacts: vec![],
        artifacts: vec![],
        contradictions: vec![],
        verifier_attachments: vec![],
        transfers: vec![],
        endorsements: vec![],
        predictions: vec![],
        resolutions: vec![],
        peers: vec![],
        negative_results: vec![],
        trajectories: vec![],
        released_diff_packs: vec![],
        verdict_conflicts: vec![],
    }
}

fn save(project: &Project, dir: &TempDir, name: &str) -> PathBuf {
    let path = dir.path().join(name);
    repo::save_to_path(&path, project).expect("save");
    path
}

fn agent_ctx() -> AgentContext {
    AgentContext::new(
        "literature-scout",
        PathBuf::from("/tmp/test-frontier.json"),
        PathBuf::from("/tmp/papers"),
        Some("claude-sonnet-4-6".to_string()),
        "claude".to_string(),
    )
}

fn agent_run() -> AgentRun {
    AgentRun {
        agent: "literature-scout".to_string(),
        model: "claude-sonnet-4-6".to_string(),
        run_id: "run-test-001".to_string(),
        started_at: "2026-05-04T00:00:00Z".to_string(),
        finished_at: Some("2026-05-04T00:00:30Z".to_string()),
        context: Default::default(),
        tool_calls: vec![],
        permissions: None,
    }
}

fn sample_conditions() -> Conditions {
    Conditions {
        text: "Phase III RCT, 18 months, early symptomatic AD".to_string(),
        species_verified: vec!["Homo sapiens".to_string()],
        species_unverified: vec![],
        in_vitro: false,
        in_vivo: true,
        human_data: true,
        clinical_trial: true,
        concentration_range: None,
        duration: Some("18 months".to_string()),
        age_group: Some("65+".to_string()),
        cell_type: None,
    }
}

fn sample_provenance() -> Provenance {
    Provenance {
        source_type: "clinical_trial".to_string(),
        doi: None,
        pmid: None,
        pmc: None,
        openalex_id: None,
        url: None,
        title: "Test trial readout".to_string(),
        authors: vec![],
        year: Some(2026),
        journal: None,
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Extraction::default(),
        review: None,
        citation_count: Some(0),
    }
}

#[test]
fn agent_proposes_negative_result_then_human_accepts() {
    let dir = TempDir::new().expect("tempdir");
    let project = empty_frontier("agent-inbox-nr");
    let path = save(&project, &dir, "frontier.json");

    let nr = NegativeResult::new(
        NegativeResultKind::RegisteredTrial {
            endpoint: "CDR-SB at 18mo".to_string(),
            intervention: "drug-X 100mg".to_string(),
            comparator: "placebo".to_string(),
            population: "early AD, biomarker-positive".to_string(),
            n_enrolled: 1000,
            power: 0.9,
            effect_size_ci: (-0.05, 0.05),
            effect_size_threshold: Some(0.4),
            registry_id: Some("NCT00000000".to_string()),
        },
        vec![],
        "agent:literature-scout",
        sample_conditions(),
        sample_provenance(),
        "Pre-registered primary endpoint not met; CI excludes MCID.",
    );
    let nr_id = nr.id.clone();

    let proposal = build_negative_result_assert_proposal(
        &nr,
        &agent_ctx(),
        "trial-readout-2026.pdf",
        "Trial reports null on primary endpoint, CI excludes MCID under adequate power.",
        &["informative_null".to_string()],
        &agent_run(),
    );
    assert_eq!(proposal.kind, "negative_result.assert");
    assert_eq!(proposal.target.r#type, "negative_result");
    assert_eq!(proposal.target.id, nr_id);

    // Submit pending. Should validate without error.
    let pending_result =
        proposals::create_or_apply(&path, proposal.clone(), false).expect("create pending");
    assert_eq!(pending_result.status, "pending_review");

    // Verify the frontier still has zero NRs (proposal pending, not applied).
    let mid = repo::load_from_path(&path).expect("reload");
    assert_eq!(mid.negative_results.len(), 0);
    assert_eq!(mid.proposals.len(), 1);
    assert_eq!(mid.proposals[0].kind, "negative_result.assert");

    // v0.339: a negative_result is a truth-bearing null claim. The agent
    // may NOT self-apply it — the bounded trusted-reviewer-agent policy
    // refuses agent acceptance of truth-bearing kinds.
    let denied = proposals::create_or_apply(&path, proposal.clone(), true);
    assert!(
        denied.is_err(),
        "agent:literature-scout must not auto-apply a truth-bearing negative_result"
    );

    // A named human reviewer accepts the pending proposal. Now the NR lands
    // in state and a canonical negative_result.asserted event appends.
    proposals::accept_at_path(
        &path,
        &proposal.id,
        "reviewer:will-blair",
        "Reviewed: pre-registered primary endpoint null, CI excludes MCID under adequate power.",
    )
    .expect("human accept");

    let post = repo::load_from_path(&path).expect("reload");
    assert_eq!(
        post.negative_results.len(),
        1,
        "human-accepted proposal should push NR to state"
    );
    assert_eq!(post.negative_results[0].id, nr_id);
    assert!(
        post.events
            .iter()
            .any(|e| e.kind == "negative_result.asserted"),
        "accepted proposal should emit canonical event"
    );
}

#[test]
fn agent_can_propose_and_apply_trajectory_with_steps() {
    let dir = TempDir::new().expect("tempdir");
    let project = empty_frontier("agent-inbox-traj");
    let path = save(&project, &dir, "frontier.json");

    let traj = Trajectory::new(
        vec![],
        "agent:literature-scout",
        "Search path documented in Methods section.",
    );
    let traj_id = traj.id.clone();

    let proposal = build_trajectory_create_proposal(
        &traj,
        &agent_ctx(),
        "methods-paper-2026.pdf",
        "Paper documents iterative reagent screen with explicit ruled-out conditions.",
        &[],
        &agent_run(),
    );
    let applied =
        proposals::create_or_apply(&path, proposal, true).expect("apply trajectory.create");
    assert_eq!(applied.status, "applied");

    let mid = repo::load_from_path(&path).expect("reload");
    assert_eq!(mid.trajectories.len(), 1);
    assert_eq!(mid.trajectories[0].id, traj_id);
    assert_eq!(mid.trajectories[0].steps.len(), 0);

    // Append a step.
    let step = TrajectoryStep::new(
        &traj_id,
        TrajectoryStepKind::RuledOut,
        "Ruled out: TfR Kd > 500 nM, no transcytosis above isotype.",
        "agent:literature-scout",
        Some("2026-05-04T01:00:00Z".to_string()),
        vec![],
    );
    let step_proposal = build_trajectory_step_append_proposal(
        &traj_id,
        &step,
        &agent_ctx(),
        "methods-paper-2026.pdf",
        "Methods section explicitly rules out the high-Kd condition.",
        &[],
        &agent_run(),
    );
    let applied_step = proposals::create_or_apply(&path, step_proposal, true).expect("apply step");
    assert_eq!(applied_step.status, "applied");

    let post = repo::load_from_path(&path).expect("reload");
    let traj_post = post
        .trajectories
        .iter()
        .find(|t| t.id == traj_id)
        .expect("trajectory present");
    assert_eq!(traj_post.steps.len(), 1, "step should append");
    assert!(
        post.events
            .iter()
            .any(|e| e.kind == "trajectory.step_appended"),
        "step proposal should emit canonical event"
    );
}
