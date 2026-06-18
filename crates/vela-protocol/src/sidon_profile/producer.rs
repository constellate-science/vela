//! Producer-side packet constructors — the operations that *emit* the profile's
//! signed packets (as opposed to [`super::evaluator`], which evaluates state).
//!
//! Ports the constructors from
//! `research/sidon-producer-profile/reference/profile.py`. This is the layer the
//! `vela sidon` CLI and the hub observation endpoint call to produce authoritative
//! reads and proposals. Each constructor is deterministic given its inputs and a
//! signing key, so a Rust producer emits byte-identical packets to the Python
//! reference (Ed25519 signing is deterministic per RFC 8032).
//!
//! This commit lands the authoritative-read constructors —
//! [`make_support_function`] and [`make_observation`] — and proves them by
//! regenerating the fixture's genesis observation byte for byte. The remaining
//! constructors (task/result/gate/acceptance/challenge/view/repair) layer on top.

use ed25519_dalek::SigningKey;
use serde_json::{Value, json};

use std::collections::BTreeSet;

use super::canonical::{content_id, digest};
use super::evaluator::{
    EVALUATOR_ID, FRONTIER_ID, VIEW_POLICY_ID, best_bounds,
};
use super::kernel::{
    Presentation, active_environments, active_view_root, compile_gamma, evaluator_digest,
    lineage_root, minimal_environments,
};
use super::packets::signed_packet;

const EVALUATOR_SEMANTICS: &str = "max supported lower-bound cell per n";

/// The fixture's deterministic timestamp for an orchestration step. Real
/// producers stamp wall-clock time; the fixture pins these so regeneration is
/// byte-exact.
pub fn fixture_time(step: u32) -> String {
    format!("2026-06-18T14:{step:02}:00+00:00")
}

fn fields_of(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// A `SupportFunctionPacket`: the minimal historical and active assumption
/// environments for one cell at the current presentation and view.
pub fn make_support_function(
    presentation: &Presentation,
    disabled: &BTreeSet<String>,
    cell_id: &str,
    signing_key: &SigningKey,
    actor: &str,
    step: u32,
) -> Result<Value, String> {
    let gamma = compile_gamma(presentation)?;
    let poly = gamma
        .get(cell_id)
        .ok_or_else(|| format!("unknown cell: {cell_id}"))?;
    let historical = minimal_environments(poly);
    let active = active_environments(poly, disabled);

    let presentation_root = presentation.presentation_root()?;
    let circuit_root = presentation.circuit_root()?;
    let historical_lineage_root = lineage_root(&gamma)?;
    let view_root = active_view_root(disabled, VIEW_POLICY_ID)?;
    let support_function_digest =
        digest(&json!({ "cell_id": cell_id, "historical": historical.clone() }))?;

    let fields = json!({
        "frontier_id": FRONTIER_ID,
        "cell_id": cell_id,
        "presentation_root": presentation_root,
        "circuit_root": circuit_root,
        "historical_lineage_root": historical_lineage_root,
        "active_view_root": view_root,
        "historical_minimal_environments": historical,
        "active_minimal_environments": active,
        "support_function_digest": support_function_digest,
        "created_at": fixture_time(step),
    });
    signed_packet("support_function", fields_of(fields), signing_key, actor)
}

/// An `ObservationPacket`: the authoritative read. It carries the four roots,
/// the evaluator inputs and canonical output, and a replay receipt binding the
/// input-root digest, evaluator digest, and output digest. An observation is
/// authoritative only because every part of it replays from the presentation
/// and active view (see [`super::verify_observation_replay`]).
pub fn make_observation(
    presentation: &Presentation,
    disabled: &BTreeSet<String>,
    support_packets: &[Value],
    caused_by_event_id: Option<&str>,
    signing_key: &SigningKey,
    actor: &str,
    step: u32,
) -> Result<Value, String> {
    let gamma = compile_gamma(presentation)?;
    let roots = json!({
        "presentation_root": presentation.presentation_root()?,
        "circuit_root": presentation.circuit_root()?,
        "lineage_root": lineage_root(&gamma)?,
        "active_view_root": active_view_root(disabled, VIEW_POLICY_ID)?,
    });
    let evaluator_inputs = json!({
        "sequence": "oeis:A309370",
        "support_policy": "positive-existence-under-active-view",
        "selection": "maximum-k-per-n",
        "view_policy_id": VIEW_POLICY_ID,
    });
    let mut sf_ids: Vec<String> = support_packets
        .iter()
        .map(|p| p["packet_id"].as_str().unwrap_or_default().to_string())
        .collect();
    sf_ids.sort();
    let output = json!({
        "sequence": "oeis:A309370",
        "bounds": best_bounds(presentation, disabled)?,
        "support_function_packet_ids": sf_ids,
    });

    // replay_core = { **roots, evaluator_id, evaluator_inputs, canonical_output }
    let mut replay_core = fields_of(roots.clone());
    replay_core.insert("evaluator_id".into(), json!(EVALUATOR_ID));
    replay_core.insert("evaluator_inputs".into(), evaluator_inputs.clone());
    replay_core.insert("canonical_output".into(), output.clone());

    let replay_receipt = json!({
        "receipt_id": content_id("vor_", &Value::Object(replay_core))?,
        "input_roots_digest": digest(&roots)?,
        "evaluator_digest": evaluator_digest(EVALUATOR_ID, EVALUATOR_SEMANTICS)?,
        "output_digest": digest(&output)?,
        "caused_by_event_id": caused_by_event_id.map_or(Value::Null, |s| json!(s)),
        "circuit_semantics": "expanded-lineage-equals-ranked-circuit-on-this-fixture",
    });

    // fields = { frontier_id, **roots, evaluator_id, evaluator_inputs,
    //            canonical_output, replay_receipt, created_at }
    let mut fields = serde_json::Map::new();
    fields.insert("frontier_id".into(), json!(FRONTIER_ID));
    for (k, v) in fields_of(roots) {
        fields.insert(k, v);
    }
    fields.insert("evaluator_id".into(), json!(EVALUATOR_ID));
    fields.insert("evaluator_inputs".into(), evaluator_inputs);
    fields.insert("canonical_output".into(), output);
    fields.insert("replay_receipt".into(), replay_receipt);
    fields.insert("created_at".into(), json!(fixture_time(step)));

    signed_packet("observation", fields, signing_key, actor)
}
