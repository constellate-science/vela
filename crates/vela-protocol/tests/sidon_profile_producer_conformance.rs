//! Conformance: the Rust producer constructors must *emit* byte-identical
//! packets to the Python reference.
//!
//! `generate_fixture.py` builds the genesis authoritative observation from an
//! empty presentation: it appends the genesis verified route (witness cell at
//! rank 0, lower-bound cell at rank 1), then emits a `SupportFunctionPacket`
//! and an `ObservationPacket` signed by the deterministic "observer" key. Here
//! the Rust constructors reproduce that genesis state and the two packets, and
//! we assert full structural equality with the committed fixture — same roots,
//! same canonical output, same packet IDs, and the same Ed25519 signatures
//! (signing is deterministic). This is the production half of the slice: Rust
//! does not just verify the authoritative read, it produces it.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{Value, json};
use vela_protocol::sidon_profile::canonical::content_id;
use vela_protocol::sidon_profile::{
    Presentation, append_verified_route, bound_cell, claim, deterministic_signing_key, digest,
    make_observation, make_result, make_support_function, make_task, register_bound_metadata,
    verify_observation_replay, verify_signed_packet,
};

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/sidon-producer-profile/fixtures")
        .join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// The genesis witness from `generate_fixture.py` (A309370, n=4, a 6-point
/// Sidon set in the binary cube).
fn witness_base() -> Value {
    json!({
        "kind": "sidon",
        "n": 4,
        "claimed_size": 6,
        "points": [
            [0, 0, 0, 0],
            [1, 0, 0, 0],
            [0, 1, 0, 0],
            [0, 0, 1, 0],
            [1, 1, 1, 0],
            [1, 0, 0, 1]
        ],
    })
}

/// Rebuild the fixture's genesis state in Rust: the genesis presentation, the
/// genesis support function, and the genesis observation. Returns
/// `(presentation, sf0, obs0, base_event)`.
fn genesis(fx: &Value) -> (Presentation, Value, Value, String) {
    let mut p = Presentation {
        cell_ranks: Default::default(),
        clauses: Vec::new(),
        accepted_events: Vec::new(),
        cell_metadata: Default::default(),
    };
    let base_artifact = digest(&witness_base()).unwrap();
    let base_claim = digest(&claim(4, 6)).unwrap();
    let base_event = content_id(
        "vev_",
        &json!({ "fixture_genesis": "A309370-n4-k6", "artifact": base_artifact }),
    )
    .unwrap();
    assert_eq!(
        base_event,
        fx["genesis"]["accepted_event_id"].as_str().unwrap()
    );

    register_bound_metadata(&mut p, 4, 6).unwrap();
    append_verified_route(
        &mut p,
        4,
        6,
        &base_artifact,
        &base_claim,
        &[
            "verifier:fixture-genesis-pairsum".to_string(),
            "verifier:fixture-genesis-base3".to_string(),
            "probe:fixture-genesis-negative-controls".to_string(),
            "gate:fixture-genesis".to_string(),
        ],
        &base_event,
    )
    .unwrap();

    let observer = deterministic_signing_key("observer");
    let disabled = BTreeSet::new();
    let cell = bound_cell(4, 6).unwrap();
    let sf0 = make_support_function(&p, &disabled, &cell, &observer, "hub:observer", 0).unwrap();
    let obs0 = make_observation(
        &p,
        &disabled,
        std::slice::from_ref(&sf0),
        Some(&base_event),
        &observer,
        "hub:observer",
        1,
    )
    .unwrap();
    (p, sf0, obs0, base_event)
}

#[test]
fn rust_regenerates_the_genesis_observation_byte_for_byte() {
    let fx = load("sidon-root-pinned-loop.json");
    let (p, sf0, obs0, _base_event) = genesis(&fx);
    let disabled = BTreeSet::new();

    // The fixture's first support_function and first observation are genesis.
    let fx_sf0 = fx["packets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["packet_type"].as_str() == Some("support_function"))
        .unwrap();
    let fx_obs0 = fx["packets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["packet_type"].as_str() == Some("observation"))
        .unwrap();

    // Full structural equality: roots, canonical output, packet IDs, AND the
    // Ed25519 signatures (deterministic signing => identical bytes).
    assert_eq!(&sf0, fx_sf0, "regenerated support function diverges");
    assert_eq!(&obs0, fx_obs0, "regenerated observation diverges");

    // And the produced observation independently replays.
    verify_signed_packet(&obs0).unwrap();
    verify_observation_replay(&obs0, &p, &disabled).unwrap();
    assert_eq!(
        obs0["canonical_output"]["bounds"][0]["best_lower_bound"],
        json!(6)
    );
}

/// The producer's own submission path — a `TaskPacket` and the `ResultPacket`
/// answering it (the `vela sidon submit` payload) — regenerates byte for byte.
#[test]
fn rust_regenerates_the_task_and_result_byte_for_byte() {
    let fx = load("sidon-root-pinned-loop.json");
    let (_p, _sf0, obs0, _base_event) = genesis(&fx);

    let task_key = deterministic_signing_key("task-issuer");
    let producer_a = deterministic_signing_key("producer-alpha");

    // task_a: strict-improvement task at n=4 pinned to the genesis observation.
    let task_a = make_task(&obs0, 4, "strict_improvement", &task_key, "hub:task-issuer", 2).unwrap();
    // result_a: producer alpha's 7-point witness answering task_a.
    let witness_a = fx["witnesses"]["route_a"].clone();
    let result_a = make_result(&task_a, &witness_a, &producer_a, "producer:alpha", 4).unwrap();

    let find = |id: &Value| -> Value {
        fx["packets"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| &p["packet_id"] == id)
            .unwrap_or_else(|| panic!("packet {id} not in fixture"))
            .clone()
    };

    assert_eq!(task_a, find(&task_a["packet_id"]), "task diverges");
    assert_eq!(result_a, find(&result_a["packet_id"]), "result diverges");

    // The task is root-pinned to the genesis observation; the result repeats it.
    assert_eq!(task_a["base_state"]["observation_id"], obs0["packet_id"]);
    assert_eq!(result_a["base_state"], task_a["base_state"]);
    assert_eq!(result_a["claim"]["value"], json!(7));
    assert_eq!(task_a["objective"]["required_minimum"], json!(7));

    verify_signed_packet(&task_a).unwrap();
    verify_signed_packet(&result_a).unwrap();
}
