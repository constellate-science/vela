//! The Sidon lower-bound evaluator and observation replay — the profile-specific
//! layer over the kernel.
//!
//! Ports the pure operations of
//! `research/sidon-producer-profile/reference/sidon.py` and `profile.py`: the
//! claim/cell scheme, the `vela.sidon.best-lower-bound.v1` evaluator
//! ([`best_bounds`]), the route appended on acceptance ([`append_verified_route`]),
//! and the authoritative-read replay check ([`verify_observation_replay`]).
//! The packet-construction helpers (`make_task`, `make_observation`, ...) live
//! with the CLI surface; this module is the deterministic compute the roots and
//! the canonical output commit to.

use std::collections::BTreeSet;

use serde_json::{Value, json};

use super::canonical::{canonical_bytes, content_id, digest};
use super::kernel::{
    Clause, Presentation, active_view_root, compile_gamma, evaluator_digest, lineage_root,
    supported,
};

pub const SEQUENCE: &str = "oeis:A309370";
pub const CONTEXT: &str = "binary-cube-sidon-exact-v1";
pub const RULE_ATOM: &str = "rule:vela.sidon.lower-bound.v1";
pub const FRONTIER_ID: &str = "vfr_496956067dc5ad79";
pub const EVALUATOR_ID: &str = "vela.sidon.best-lower-bound.v1";
pub const VIEW_POLICY_ID: &str = "vela.view.public.v1";
pub const PROFILE_ID: &str = "vela.sidon-producer-profile.v1";
const EVALUATOR_SEMANTICS: &str = "max supported lower-bound cell per n";

/// The `>=` lower-bound claim on A309370 at dimension `n` with value `k`.
pub fn claim(n: i64, k: i64) -> Value {
    json!({
        "namespace": "oeis",
        "sequence": "A309370",
        "context": CONTEXT,
        "n": n,
        "relation": ">=",
        "value": k,
        "polarity": "support",
    })
}

pub fn witness_cell(artifact_digest: &str) -> Result<String, String> {
    content_id(
        "vsc_",
        &json!({ "kind": "verified_sidon_witness", "artifact_digest": artifact_digest }),
    )
}

pub fn bound_cell(n: i64, k: i64) -> Result<String, String> {
    content_id(
        "vsc_",
        &json!({ "kind": "sidon_lower_bound", "claim": claim(n, k) }),
    )
}

/// Append the two clauses an accepted result emits: a rank-0 verified-witness
/// cell and a rank-1 lower-bound cell that depends on it. Returns
/// `(witness_cell, bound_cell)`. Mutates the presentation in place.
#[allow(clippy::too_many_arguments)]
pub fn append_verified_route(
    presentation: &mut Presentation,
    n: i64,
    k: i64,
    artifact_digest: &str,
    claim_digest: &str,
    verification_atoms: &[String],
    accepted_event_id: &str,
) -> Result<(String, String), String> {
    let wcell = witness_cell(artifact_digest)?;
    let bcell = bound_cell(n, k)?;
    presentation.cell_ranks.entry(wcell.clone()).or_insert(0);
    presentation.cell_ranks.entry(bcell.clone()).or_insert(1);

    let mut witness_atoms = vec![format!("artifact:{artifact_digest}")];
    witness_atoms.extend(verification_atoms.iter().cloned());
    witness_atoms.push(format!("acceptance-event:{accepted_event_id}"));
    let witness_clause = Clause::make(&wcell, 0, Vec::new(), witness_atoms, accepted_event_id)?;

    let bound_clause = Clause::make(
        &bcell,
        1,
        vec![wcell.clone()],
        vec![format!("statement:{claim_digest}"), RULE_ATOM.to_string()],
        accepted_event_id,
    )?;

    presentation.clauses.push(witness_clause);
    presentation.clauses.push(bound_clause);
    presentation
        .accepted_events
        .push(accepted_event_id.to_string());
    presentation.validate()?;
    Ok((wcell, bcell))
}

pub fn register_bound_metadata(presentation: &mut Presentation, n: i64, k: i64) -> Result<(), String> {
    let cell = bound_cell(n, k)?;
    presentation.cell_metadata.insert(
        cell,
        json!({ "kind": "sidon_lower_bound", "n": n, "k": k }),
    );
    Ok(())
}

/// `vela.sidon.best-lower-bound.v1`: for each `n`, retain lower-bound cells with
/// at least one active environment, take the maximum `k`, and emit the
/// supporting cell IDs. Rows are sorted by `n`.
pub fn best_bounds(
    presentation: &Presentation,
    disabled: &BTreeSet<String>,
) -> Result<Vec<Value>, String> {
    let gamma = compile_gamma(presentation)?;
    // n -> [(k, cell_id)]
    let mut candidates: std::collections::BTreeMap<i64, Vec<(i64, String)>> =
        std::collections::BTreeMap::new();
    for (cell_id, meta) in &presentation.cell_metadata {
        if meta.get("kind").and_then(Value::as_str) != Some("sidon_lower_bound") {
            continue;
        }
        let Some(poly) = gamma.get(cell_id) else {
            continue;
        };
        if supported(poly, disabled) {
            let n = meta["n"].as_i64().ok_or("bound metadata n not an integer")?;
            let k = meta["k"].as_i64().ok_or("bound metadata k not an integer")?;
            candidates.entry(n).or_default().push((k, cell_id.clone()));
        }
    }
    let mut out = Vec::new();
    for (n, rows) in &candidates {
        let best = rows.iter().map(|(k, _)| *k).max().unwrap();
        let mut cells: Vec<String> = rows
            .iter()
            .filter(|(k, _)| *k == best)
            .map(|(_, c)| c.clone())
            .collect();
        cells.sort();
        out.push(json!({ "n": n, "best_lower_bound": best, "supported_cell_ids": cells }));
    }
    Ok(out)
}

/// The best lower bound the observation records for dimension `n`.
pub fn current_bound(observation: &Value, n: i64) -> Result<i64, String> {
    let bounds = observation["canonical_output"]["bounds"]
        .as_array()
        .ok_or("observation has no bounds array")?;
    for row in bounds {
        if row["n"].as_i64() == Some(n) {
            return row["best_lower_bound"]
                .as_i64()
                .ok_or_else(|| "best_lower_bound not an integer".to_string());
        }
    }
    Err(format!("observation has no bound for n={n}"))
}

/// The root-pinned base-state commitment derived from an observation packet.
pub fn state_commitment(observation: &Value) -> Result<Value, String> {
    Ok(json!({
        "observation_id": observation["packet_id"],
        "presentation_root": observation["presentation_root"],
        "circuit_root": observation["circuit_root"],
        "lineage_root": observation["lineage_root"],
        "active_view_root": observation["active_view_root"],
        "evaluator_id": observation["evaluator_id"],
        "evaluator_inputs_digest": digest(&observation["evaluator_inputs"])?,
        "canonical_output_digest": digest(&observation["canonical_output"])?,
    }))
}

/// Re-derive an observation's roots and canonical output from the presentation
/// and active view, and confirm they match what the packet committed to. This
/// is what makes an `ObservationPacket` an authoritative read.
pub fn verify_observation_replay(
    observation: &Value,
    presentation: &Presentation,
    disabled: &BTreeSet<String>,
) -> Result<(), String> {
    let gamma = compile_gamma(presentation)?;
    let expected_roots = json!({
        "presentation_root": presentation.presentation_root()?,
        "circuit_root": presentation.circuit_root()?,
        "lineage_root": lineage_root(&gamma)?,
        "active_view_root": active_view_root(disabled, VIEW_POLICY_ID)?,
    });
    for key in [
        "presentation_root",
        "circuit_root",
        "lineage_root",
        "active_view_root",
    ] {
        if observation[key] != expected_roots[key] {
            return Err(format!("observation {key} does not replay"));
        }
    }

    let support_ids = observation["canonical_output"]["support_function_packet_ids"].clone();
    let expected_output = json!({
        "sequence": "oeis:A309370",
        "bounds": best_bounds(presentation, disabled)?,
        "support_function_packet_ids": support_ids,
    });
    if canonical_bytes(&observation["canonical_output"])? != canonical_bytes(&expected_output)? {
        return Err("observation output does not replay".to_string());
    }

    let receipt = &observation["replay_receipt"];
    if receipt["output_digest"].as_str() != Some(digest(&expected_output)?.as_str()) {
        return Err("observation output digest mismatch".to_string());
    }
    if receipt["input_roots_digest"].as_str() != Some(digest(&expected_roots)?.as_str()) {
        return Err("observation input roots digest mismatch".to_string());
    }
    let _ = evaluator_digest(EVALUATOR_ID, EVALUATOR_SEMANTICS)?; // exercised by make_observation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_and_bound_cell_are_stable() {
        let c1 = bound_cell(4, 6).unwrap();
        let c2 = bound_cell(4, 6).unwrap();
        assert_eq!(c1, c2);
        assert!(c1.starts_with("vsc_"));
        assert_ne!(bound_cell(4, 6).unwrap(), bound_cell(4, 7).unwrap());
    }

    #[test]
    fn append_route_builds_ranked_witness_to_bound_dependency() {
        let mut p = Presentation {
            cell_ranks: Default::default(),
            clauses: Vec::new(),
            accepted_events: Vec::new(),
            cell_metadata: Default::default(),
        };
        let (wcell, bcell) = append_verified_route(
            &mut p,
            4,
            6,
            "sha256:aa",
            "sha256:bb",
            &["verifier:v1".to_string(), "gate:g1".to_string()],
            "vev_e1",
        )
        .unwrap();
        register_bound_metadata(&mut p, 4, 6).unwrap();
        assert_eq!(p.cell_ranks[&wcell], 0);
        assert_eq!(p.cell_ranks[&bcell], 1);
        let disabled = BTreeSet::new();
        let bounds = best_bounds(&p, &disabled).unwrap();
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0]["best_lower_bound"], json!(6));
    }
}
