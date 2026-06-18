//! Conformance for the map layer: the obligation lifecycle and frontier
//! migration over the LIVE Sidon cells, driven by the committed loop fixture.
//!
//! This is the `record -> map -> extend` first production proof in the cheapest
//! verifier domain. The fixture's presentation snapshots walk the bound at n=4
//! through 6 -> 7 (route A) -> 6 (restrict) -> 7 (repair). An obligation whose
//! target is the bound-7 cell must track that exactly:
//!
//! ```text
//! genesis (bound 6)   : target-7 OPEN,       successor-8 LATENT
//! route A (bound 7)   : target-7 DISCHARGED,  successor-8 OPEN     (frontier advanced)
//! restrict (back to 6): target-7 OPEN,        successor-8 LATENT   (frontier retreated)
//! repair (bound 7)    : target-7 DISCHARGED,  successor-8 OPEN     (frontier re-advanced)
//! ```
//!
//! The map roots are content ids on the PRODUCTION canonical
//! (`vela.canonical-json-subset.v1`), not the fabric reference tag.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::Value;
use serde_json::json;
use vela_protocol::sidon_profile::{
    Obligation, Presentation, bound_cell, build_frontier_map, frontier::SUPPORT_EXISTS_EVALUATOR,
    obligation_status, verify_positive_gap_monotonicity,
};

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../research/sidon-producer-profile/fixtures")
        .join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn snapshot_presentation(fx: &Value, name: &str) -> (Presentation, BTreeSet<String>) {
    let snap = fx["snapshots"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("snapshot {name} not in fixture"));
    let p = Presentation::from_json(&snap["presentation"]).unwrap();
    let disabled: BTreeSet<String> = snap["disabled_atoms"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    (p, disabled)
}

fn obligation(n: i64, k: i64, deps: &[String]) -> Obligation {
    Obligation::make(
        "exact_combinatorics.v1",
        &bound_cell(n, k).unwrap(),
        "coverage",
        json!({ "sequence": "oeis:A309370", "n": n, "target_k": k }),
        SUPPORT_EXISTS_EVALUATOR,
        "vela.sidon.gate.v1",
        "sidon.next-bound.v1",
        deps,
        &format!("reach A309370(n={n}) >= {k}"),
    )
    .unwrap()
}

#[test]
fn frontier_migrates_open_to_discharged_and_back_over_live_sidon_cells() {
    let fx = load("sidon-root-pinned-loop.json");
    let target7 = obligation(4, 7, &[]);
    let successor8 = obligation(4, 8, &[bound_cell(4, 7).unwrap()]);
    let obls = [target7.clone(), successor8.clone()];

    let st = |snap: &str| {
        let (p, d) = snapshot_presentation(&fx, snap);
        (
            obligation_status(&target7, &p, &d).unwrap(),
            obligation_status(&successor8, &p, &d).unwrap(),
        )
    };

    assert_eq!(st("genesis_bound_6"), ("open", "latent"));
    assert_eq!(st("route_a_bound_7"), ("discharged", "open"));
    assert_eq!(
        st("accepted_restriction_falls_back_to_6"),
        ("open", "latent")
    );
    assert_eq!(
        st("alternative_route_repairs_bound_7"),
        ("discharged", "open")
    );

    // A positive append (genesis -> route A) advances the frontier without
    // reopening anything discharged.
    let (genesis, gd) = snapshot_presentation(&fx, "genesis_bound_6");
    let (route_a, rd) = snapshot_presentation(&fx, "route_a_bound_7");
    assert_eq!(gd, rd, "no view change across this append");
    verify_positive_gap_monotonicity(&genesis, &route_a, &obls, &gd).unwrap();

    // The frontier map at route A: exactly one open (successor-8), one
    // discharged (target-7), bound to the presentation root.
    let map = build_frontier_map(&route_a, &obls, &rd).unwrap();
    assert_eq!(map["open_obligations"].as_array().unwrap().len(), 1);
    assert_eq!(map["discharged_obligations"].as_array().unwrap().len(), 1);
    assert_eq!(
        map["presentation_root"],
        route_a.presentation_root().unwrap(),
        "frontier map is bound to the live presentation root"
    );
    assert!(
        map["frontier_map_root"]
            .as_str()
            .unwrap()
            .starts_with("vfm_")
    );
}
