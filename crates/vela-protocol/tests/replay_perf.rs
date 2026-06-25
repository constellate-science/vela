//! Replay performance regression test.
//!
//! Builds a synthetic large frontier (N findings + N review events) and
//! times the reducer's replay. Establishes a wall-clock baseline so
//! future hot-path changes can detect regressions.
//!
//! ## Characterization (v0.96)
//!
//! Per-event time grows roughly linearly with N, indicating O(N^2)
//! reducer scaling. The hot path is `state.findings.iter().position(|f|
//! f.id == id)` in every per-kind apply function (finding.asserted,
//! finding.reviewed, finding.noted, etc.).
//!
//! Sample timings on Apple Silicon, release profile:
//!   N =  1,000   ~15ms     (15us / event)
//!   N =  5,000   ~100ms    (20us / event)
//!   N = 10,000   ~310ms    (31us / event)
//!   N = 20,000   ~1.1s     (56us / event)
//!
//! Real frontiers today (low hundreds of findings each) are ~3 orders
//! of magnitude smaller and replay in single-digit ms. The O(N^2)
//! characterization matters for infrastructure-grade scaling (100K+
//! event histories), not for current load.
//!
//! ## Future optimization (deferred)
//!
//! The fix is a HashMap<finding_id, position> index built once at the
//! start of replay_from_genesis and updated in lockstep with mutations.
//! That requires either threading the index as an argument through
//! every per-kind apply function (wide change) or adding an internal
//! cached-index field on Project (also wide due to struct-literal
//! initialization sites). Deferred to a future cycle when a real
//! frontier crosses ~1K events and the optimization becomes
//! user-visible.
//!
//! Run with `cargo test --release -p vela-protocol --test replay_perf
//! -- --nocapture` to see the timing report.

use std::time::Instant;

use serde_json::json;
use vela_protocol::bundle::{
    Assertion, Author, Conditions, Confidence, ConfidenceKind, ConfidenceMethod, Evidence,
    FindingBundle, Flags, Provenance,
};
use vela_protocol::events::{NULL_HASH, StateActor, StateEvent, StateTarget};
use vela_protocol::reducer::replay_from_genesis;

fn make_finding(idx: usize) -> FindingBundle {
    let assertion = Assertion {
        text: format!("synthetic finding number {idx}"),
        assertion_type: "mechanism".into(),
        entities: vec![],
        relation: None,
        direction: None,
        causal_claim: None,
        causal_evidence_grade: None,
    };
    let provenance = Provenance {
        source_type: "expert_assertion".into(),
        doi: None,
        url: None,
        title: format!("synthetic source {idx}"),
        authors: vec![Author {
            name: "perf test".into(),
            orcid: None,
        }],
        year: None,
        license: None,
        publisher: None,
        funders: vec![],
        extraction: Default::default(),
        review: None,
    };
    let evidence = Evidence {
        evidence_type: "experimental".into(),
        model_system: "synthetic".into(),
        method: "test".into(),
        replicated: false,
        replication_count: None,
        evidence_spans: vec![],
    };
    let conditions = Conditions {
        text: String::new(),
        duration: None,
    };
    let confidence = Confidence {
        kind: ConfidenceKind::FrontierEpistemic,
        score: 0.5,
        basis: "synthetic".into(),
        method: ConfidenceMethod::LlmInitial,
        components: None,
        extraction_confidence: 0.5,
    };
    let mut f = FindingBundle::new(
        assertion,
        evidence,
        conditions,
        confidence,
        provenance,
        Flags::default(),
    );
    // Override the content-addressed id to a stable synthetic form so
    // we can cheaply build event targets in O(1) rather than re-deriving.
    f.id = format!("vf_synth_{idx:08x}");
    f
}

fn make_review_event(idx: usize, finding_id: &str) -> StateEvent {
    StateEvent {
        schema: "vela.event.v0.1".into(),
        id: format!("vev_synth_{idx:08x}"),
        kind: "finding.reviewed".into(),
        target: StateTarget {
            r#type: "finding".into(),
            id: finding_id.to_string(),
        },
        actor: StateActor {
            id: "reviewer:perf".into(),
            r#type: "human".into(),
        },
        timestamp: "2026-05-10T00:00:00Z".into(),
        reason: "perf test review".into(),
        before_hash: NULL_HASH.into(),
        after_hash: NULL_HASH.into(),
        payload: json!({"status": "accepted"}),
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    }
}

fn run_replay(n: usize) -> std::time::Duration {
    let genesis: Vec<FindingBundle> = (0..n).map(make_finding).collect();
    let events: Vec<StateEvent> = (0..n)
        .map(|i| make_review_event(i, &format!("vf_synth_{i:08x}")))
        .collect();
    let start = Instant::now();
    let project = replay_from_genesis(
        genesis,
        events,
        "perf-frontier",
        "synthetic perf test",
        "2026-05-10T00:00:00Z",
        "vela-perf-test",
    )
    .expect("replay should succeed");
    let elapsed = start.elapsed();
    assert_eq!(project.findings.len(), n);
    elapsed
}

#[test]
fn replay_scaling_curve() {
    // Probe at multiple N to characterize scaling. O(N^2) paths
    // become obvious here. Print timings; the assertion is just a
    // smoke check that none of the runs hangs.
    println!();
    println!("=== replay scaling curve ===");
    for &n in &[1_000usize, 5_000, 10_000, 20_000] {
        let elapsed = run_replay(n);
        let per_event = elapsed.as_nanos() as f64 / n as f64;
        println!("  N = {n:>5}   elapsed = {elapsed:?}   per-event = {per_event:.0} ns");
    }
    println!();
}

#[test]
fn replay_10k_events_scales_acceptably() {
    // N findings, N events. O(N^2) hot paths in the reducer become
    // visible at this scale.
    const N: usize = 10_000;

    let genesis: Vec<FindingBundle> = (0..N).map(make_finding).collect();
    let events: Vec<StateEvent> = (0..N)
        .map(|i| make_review_event(i, &format!("vf_synth_{i:08x}")))
        .collect();

    let start = Instant::now();
    let project = replay_from_genesis(
        genesis,
        events,
        "perf-frontier",
        "synthetic perf test",
        "2026-05-10T00:00:00Z",
        "vela-perf-test",
    )
    .expect("replay should succeed");
    let elapsed = start.elapsed();

    println!();
    println!("=== replay perf ===");
    println!("  findings:     {N}");
    println!("  events:       {N}");
    println!("  elapsed:      {elapsed:?}");
    println!("  per-event:    {:?}", elapsed / N as u32);
    println!("  events/sec:   {:.0}", N as f64 / elapsed.as_secs_f64());
    println!();

    // Sanity: every finding should now be reviewed=accepted.
    assert_eq!(project.findings.len(), N);
    let accepted = project
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.flags.review_state,
                Some(vela_protocol::bundle::ReviewState::Accepted)
            )
        })
        .count();
    assert_eq!(accepted, N);

    // Regression guard: 10K events should not take more than 60s
    // even on the slowest CI hardware. Adjust upward only with a
    // clear regression-acceptance reason.
    assert!(
        elapsed.as_secs() < 60,
        "10k-event replay took {elapsed:?}, exceeds 60s budget"
    );
}
