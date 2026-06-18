//! Cross-implementation conformance for the Sidon-profile kernel + evaluator.
//!
//! Mirrors the replay core of
//! `research/sidon-producer-profile/conformance/check_fixture.py` in Rust: for
//! every snapshot in the loop fixture, the Rust kernel re-derives the four
//! roots and the canonical output from the presentation and active view and
//! confirms they match the observation packet; the bound trace recomputes to
//! `6, 7, 7, 6, 7`; the human-restrict kill and the append-repair are checked
//! through the bag-lineage environments. If any root rule, the environment
//! semantics, or the evaluator diverged from Python, these fail.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde_json::Value;
use vela_protocol::sidon_profile::{
    Presentation, active_environments, active_view_root, compile_gamma, is_hitting_set,
    lineage_root, minimal_environments, state_commitment, verify_observation_replay,
};

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/sidon-producer-profile/fixtures")
        .join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn disabled_set(snap: &Value) -> BTreeSet<String> {
    snap["disabled_atoms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn str_vec(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn every_snapshot_replays_and_the_bound_trace_matches() {
    let fx = load("sidon-root-pinned-loop.json");
    let by_id: BTreeMap<String, Value> = fx["packets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["packet_id"].as_str().unwrap().to_string(), p.clone()))
        .collect();

    let mut trace = Vec::new();
    for snap in fx["snapshots"].as_array().unwrap() {
        let presentation = Presentation::from_json(&snap["presentation"]).expect("presentation");
        let disabled = disabled_set(snap);
        let obs = &by_id[snap["observation_packet_id"].as_str().unwrap()];

        // The full authoritative-read replay: roots, output, and both digests.
        verify_observation_replay(obs, &presentation, &disabled)
            .unwrap_or_else(|e| panic!("snapshot {} replay: {e}", snap["name"]));

        // Lineage root is independently recomputed (belt and suspenders).
        let gamma = compile_gamma(&presentation).unwrap();
        assert_eq!(
            obs["lineage_root"].as_str().unwrap(),
            lineage_root(&gamma).unwrap()
        );

        // n = 4 best bound feeds the trace.
        let b = obs["canonical_output"]["bounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["n"].as_i64() == Some(4))
            .expect("bound for n=4")["best_lower_bound"]
            .as_i64()
            .unwrap();
        trace.push(b);
    }

    let expected: Vec<i64> = fx["expected"]["best_bound_trace"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_i64().unwrap())
        .collect();
    assert_eq!(trace, expected, "bound trace must be 6,7,7,6,7");
    assert_eq!(trace, vec![6, 7, 7, 6, 7]);
}

#[test]
fn tasks_pin_an_exact_observation_state() {
    let fx = load("sidon-root-pinned-loop.json");
    let observations: BTreeMap<String, Value> = fx["packets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["packet_type"].as_str() == Some("observation"))
        .map(|p| (p["packet_id"].as_str().unwrap().to_string(), p.clone()))
        .collect();

    let mut tasks = 0;
    for task in fx["packets"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["packet_type"].as_str() == Some("task"))
    {
        let obs_id = task["base_state"]["observation_id"].as_str().unwrap();
        let base = &observations[obs_id];
        assert_eq!(
            state_commitment(base).unwrap(),
            task["base_state"],
            "task base_state must equal the named observation's commitment"
        );
        tasks += 1;
    }
    assert!(
        tasks >= 2,
        "fixture should issue at least two root-pinned tasks"
    );
}

#[test]
fn human_restrict_kills_and_append_repairs_the_target_through_environments() {
    let fx = load("sidon-root-pinned-loop.json");
    let by_id: BTreeMap<String, Value> = fx["packets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["packet_id"].as_str().unwrap().to_string(), p.clone()))
        .collect();
    let snaps: BTreeMap<String, Value> = fx["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["name"].as_str().unwrap().to_string(), s.clone()))
        .collect();

    // The challenge is a hitting set over the support's active environments.
    let challenge = &by_id[fx["expected"]["challenge_packet_id"].as_str().unwrap()];
    let decision = &by_id[fx["expected"]["view_decision_packet_id"].as_str().unwrap()];
    let support = &by_id[challenge["support_function_packet_id"].as_str().unwrap()];
    let active: Vec<Vec<String>> = support["active_minimal_environments"]
        .as_array()
        .unwrap()
        .iter()
        .map(str_vec)
        .collect();
    let proposed = str_vec(&challenge["proposed_disabled_atoms"]);
    assert!(
        is_hitting_set(&active, &proposed),
        "challenge atoms must hit every active environment"
    );

    // The accepted view decision commits to exactly prior ∪ proposed.
    let mut expected_disabled: BTreeSet<String> = str_vec(&decision["prior_disabled_atoms"])
        .into_iter()
        .collect();
    expected_disabled.extend(proposed.iter().cloned());
    assert_eq!(
        decision["resulting_active_view_root"].as_str().unwrap(),
        active_view_root(&expected_disabled, "vela.view.public.v1").unwrap()
    );

    let target = fx["expected"]["target_cell_id"].as_str().unwrap();

    // Under the restricted view the target has no active environment (killed).
    let killed = &snaps["accepted_restriction_falls_back_to_6"];
    let killed_p = Presentation::from_json(&killed["presentation"]).unwrap();
    let killed_gamma = compile_gamma(&killed_p).unwrap();
    assert!(
        active_environments(&killed_gamma[target], &disabled_set(killed)).is_empty(),
        "hitting-set restriction must kill the target cell"
    );

    // After an appended alternative route, the target is active again (repaired).
    let repaired = &snaps["alternative_route_repairs_bound_7"];
    let repaired_p = Presentation::from_json(&repaired["presentation"]).unwrap();
    let repaired_gamma = compile_gamma(&repaired_p).unwrap();
    assert!(
        !active_environments(&repaired_gamma[target], &disabled_set(repaired)).is_empty(),
        "append repair must restore the target cell"
    );

    // The composed bound environment retains witness-artifact and rule provenance.
    for env in minimal_environments(&repaired_gamma[target]) {
        assert!(
            env.iter().any(|a| a.starts_with("artifact:sha256:")),
            "composed environment lost witness artifact provenance"
        );
        assert!(
            env.iter().any(|a| a == "rule:vela.sidon.lower-bound.v1"),
            "composed environment lost the rule atom"
        );
    }
}
