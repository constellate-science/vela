//! The map layer: adapter-relative obligations and frontier maps over the
//! ranked lineage kernel (`record -> map -> extend`, the Constellate side).
//!
//! Ports the obligation/frontier-map semantics from
//! `research/frontier-fabric-v2/reference/frontier.py` onto the PRODUCTION
//! canonical (`super::canonical`, `vela.canonical-json-subset.v1`) and the
//! production kernel (`super::kernel`). An obligation is typed missingness: a
//! target cell that should become actively supported, plus the dependencies
//! that gate when it is actionable. Its status is derived, never stored:
//!
//! ```text
//! discharged   the target cell is actively supported
//! open         the target is unsupported and every dependency is supported
//! latent       a dependency is not yet supported
//! ```
//!
//! A frontier map is a replayable planning view over state: it is bound to the
//! presentation root, so as accepted state grows the actionable edge moves
//! outward (`latent -> open -> discharged`), and a restriction moves it back
//! without erasing history. This is the surface a producer reads to choose work.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};

use super::canonical::{content_id, digest};
use super::evaluator::bound_cell;
use super::kernel::{Presentation, compile_gamma, supported};

/// The only discharge evaluator this profile recognizes: a cell is discharged
/// when it has at least one active support environment.
pub const SUPPORT_EXISTS_EVALUATOR: &str = "vela.support-exists.v1";

/// An obligation: a target cell that should become supported, with the
/// dependencies that gate when the work is actionable.
#[derive(Debug, Clone)]
pub struct Obligation {
    pub obligation_id: String,
    pub adapter_id: String,
    pub target_cell: String,
    pub kind: String,
    pub context: Value,
    pub discharge_evaluator_id: String,
    pub verifier_profile_id: String,
    pub generator_id: String,
    pub dependencies: Vec<String>,
    pub rationale: String,
}

impl Obligation {
    #[allow(clippy::too_many_arguments)]
    pub fn make(
        adapter_id: &str,
        target_cell: &str,
        kind: &str,
        context: Value,
        discharge_evaluator_id: &str,
        verifier_profile_id: &str,
        generator_id: &str,
        dependencies: &[String],
        rationale: &str,
    ) -> Result<Self, String> {
        let mut deps: Vec<String> = dependencies.to_vec();
        deps.sort();
        deps.dedup();
        let core = json!({
            "adapter_id": adapter_id,
            "target_cell": target_cell,
            "kind": kind,
            "context": context,
            "discharge_evaluator_id": discharge_evaluator_id,
            "verifier_profile_id": verifier_profile_id,
            "generator_id": generator_id,
            "dependencies": deps,
            "rationale": rationale,
        });
        Ok(Obligation {
            obligation_id: content_id("vobl_", &core)?,
            adapter_id: adapter_id.to_string(),
            target_cell: target_cell.to_string(),
            kind: kind.to_string(),
            context,
            discharge_evaluator_id: discharge_evaluator_id.to_string(),
            verifier_profile_id: verifier_profile_id.to_string(),
            generator_id: generator_id.to_string(),
            dependencies: deps,
            rationale: rationale.to_string(),
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "obligation_id": self.obligation_id,
            "adapter_id": self.adapter_id,
            "target_cell": self.target_cell,
            "kind": self.kind,
            "context": self.context,
            "discharge_evaluator_id": self.discharge_evaluator_id,
            "verifier_profile_id": self.verifier_profile_id,
            "generator_id": self.generator_id,
            "dependencies": self.dependencies,
            "rationale": self.rationale,
        })
    }
}

fn cell_supported(
    cell: &str,
    presentation: &Presentation,
    disabled: &BTreeSet<String>,
) -> Result<bool, String> {
    if !presentation.cell_ranks.contains_key(cell) {
        return Ok(false);
    }
    let gamma = compile_gamma(presentation)?;
    Ok(gamma.get(cell).map(|p| supported(p, disabled)).unwrap_or(false))
}

pub fn obligation_discharged(
    obligation: &Obligation,
    presentation: &Presentation,
    disabled: &BTreeSet<String>,
) -> Result<bool, String> {
    if obligation.discharge_evaluator_id != SUPPORT_EXISTS_EVALUATOR {
        return Err(format!(
            "unsupported discharge evaluator: {}",
            obligation.discharge_evaluator_id
        ));
    }
    cell_supported(&obligation.target_cell, presentation, disabled)
}

/// `latent`, `open`, or `discharged`. The target takes precedence, so a
/// historical route stays recognized even if a stricter view later hides a
/// prerequisite used only to expose the work item.
pub fn obligation_status(
    obligation: &Obligation,
    presentation: &Presentation,
    disabled: &BTreeSet<String>,
) -> Result<&'static str, String> {
    if obligation_discharged(obligation, presentation, disabled)? {
        return Ok("discharged");
    }
    for dep in &obligation.dependencies {
        if !cell_supported(dep, presentation, disabled)? {
            return Ok("latent");
        }
    }
    Ok("open")
}

/// A replayable planning view bound to the presentation root.
pub fn build_frontier_map(
    presentation: &Presentation,
    obligations: &[Obligation],
    disabled: &BTreeSet<String>,
) -> Result<Value, String> {
    let mut ordered: Vec<&Obligation> = obligations.iter().collect();
    ordered.sort_by(|a, b| a.obligation_id.cmp(&b.obligation_id));

    let mut rows = Vec::new();
    let mut open = Vec::new();
    let mut latent = Vec::new();
    let mut discharged = Vec::new();
    for obl in ordered {
        let status = obligation_status(obl, presentation, disabled)?;
        let mut row = obl.to_json();
        row.as_object_mut()
            .unwrap()
            .insert("status".into(), json!(status));
        rows.push(row);
        match status {
            "open" => open.push(json!(obl.obligation_id)),
            "latent" => latent.push(json!(obl.obligation_id)),
            "discharged" => discharged.push(json!(obl.obligation_id)),
            _ => {}
        }
    }
    let disabled_sorted: Vec<&String> = disabled.iter().collect();
    let payload = json!({
        "presentation_root": presentation.presentation_root()?,
        "disabled_atoms": disabled_sorted,
        "obligations": rows,
    });
    let mut out = payload.as_object().cloned().unwrap();
    out.insert(
        "frontier_map_root".into(),
        json!(content_id("vfm_", &payload)?),
    );
    out.insert("open_obligations".into(), json!(open));
    out.insert("latent_obligations".into(), json!(latent));
    out.insert("discharged_obligations".into(), json!(discharged));
    Ok(Value::Object(out))
}

/// Explain how the actionable frontier moved between two map roots.
pub fn frontier_transition(before: &Value, after: &Value) -> Result<Value, String> {
    let status_map = |m: &Value| -> std::collections::BTreeMap<String, String> {
        m["obligations"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| {
                        Some((
                            r["obligation_id"].as_str()?.to_string(),
                            r["status"].as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let b = status_map(before);
    let a = status_map(after);
    let mut ids: BTreeSet<String> = BTreeSet::new();
    ids.extend(b.keys().cloned());
    ids.extend(a.keys().cloned());
    let mut transitions = Vec::new();
    for id in ids {
        let old = b.get(&id).map(String::as_str).unwrap_or("absent");
        let new = a.get(&id).map(String::as_str).unwrap_or("absent");
        if old != new {
            transitions.push(json!({ "obligation_id": id, "before": old, "after": new }));
        }
    }
    let payload = json!({
        "before_frontier_map_root": before["frontier_map_root"],
        "after_frontier_map_root": after["frontier_map_root"],
        "transitions": transitions,
    });
    let mut out = payload.as_object().cloned().unwrap();
    out.insert("transition_digest".into(), json!(digest(&payload)?));
    Ok(Value::Object(out))
}

/// A positive append cannot reopen a discharged monotone-support obligation
/// (it may expose a successor by moving it `latent -> open`).
pub fn verify_positive_gap_monotonicity(
    before_presentation: &Presentation,
    after_presentation: &Presentation,
    obligations: &[Obligation],
    disabled: &BTreeSet<String>,
) -> Result<(), String> {
    let before = build_frontier_map(before_presentation, obligations, disabled)?;
    let after = build_frontier_map(after_presentation, obligations, disabled)?;
    let status_of = |m: &Value, id: &str| -> Option<String> {
        m["obligations"]
            .as_array()?
            .iter()
            .find(|r| r["obligation_id"].as_str() == Some(id))
            .and_then(|r| r["status"].as_str())
            .map(str::to_string)
    };
    let mut reopened = Vec::new();
    for obl in obligations {
        if status_of(&before, &obl.obligation_id).as_deref() == Some("discharged")
            && status_of(&after, &obl.obligation_id).as_deref() != Some("discharged")
        {
            reopened.push(obl.obligation_id.clone());
        }
    }
    if !reopened.is_empty() {
        return Err(format!("positive append reopened obligations: {reopened:?}"));
    }
    Ok(())
}

/// Derive the open frontier from the presentation's registered bounds: for each
/// dimension `n`, the current best lower bound `k` induces one open obligation,
/// "beat it" (reach `k+1`), gated on the current `(n,k)` cell. This is the
/// auto-derived "what is the next bound to beat at each n" map a producer reads
/// to choose work. Obligations are returned sorted by `n`.
pub fn next_bound_obligations(presentation: &Presentation) -> Result<Vec<Obligation>, String> {
    let mut best: BTreeMap<i64, i64> = BTreeMap::new();
    for meta in presentation.cell_metadata.values() {
        if meta.get("kind").and_then(Value::as_str) != Some("sidon_lower_bound") {
            continue;
        }
        let (Some(n), Some(k)) = (
            meta.get("n").and_then(Value::as_i64),
            meta.get("k").and_then(Value::as_i64),
        ) else {
            continue;
        };
        best.entry(n).and_modify(|e| *e = (*e).max(k)).or_insert(k);
    }
    let mut out = Vec::new();
    for (n, k) in best {
        out.push(Obligation::make(
            "exact_combinatorics.v1",
            &bound_cell(n, k + 1)?,
            "coverage",
            json!({ "sequence": "oeis:A309370", "n": n, "target_k": k + 1, "current_k": k }),
            SUPPORT_EXISTS_EVALUATOR,
            "vela.sidon.gate.v1",
            "sidon.next-bound.v1",
            &[bound_cell(n, k)?],
            &format!("beat the current A309370(n={n}) >= {k} bound"),
        )?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidon_profile::{append_verified_route, bound_cell, register_bound_metadata};

    fn sidon_obligation(n: i64, k: i64, deps: &[String]) -> Obligation {
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
    fn obligation_lifecycle_over_a_built_presentation() {
        let mut p = Presentation {
            cell_ranks: Default::default(),
            clauses: Vec::new(),
            accepted_events: Vec::new(),
            cell_metadata: Default::default(),
        };
        let disabled = BTreeSet::new();
        // target: reach bound 7 at n=4; successor: reach 8 (depends on the 7 cell).
        let obl7 = sidon_obligation(4, 7, &[]);
        let obl8 = sidon_obligation(4, 8, &[bound_cell(4, 7).unwrap()]);

        // Empty state: 7 open, 8 latent.
        assert_eq!(obligation_status(&obl7, &p, &disabled).unwrap(), "open");
        assert_eq!(obligation_status(&obl8, &p, &disabled).unwrap(), "latent");

        // Append a verified route discharging the bound-7 cell.
        register_bound_metadata(&mut p, 4, 7).unwrap();
        append_verified_route(
            &mut p,
            4,
            7,
            "sha256:aa",
            "sha256:bb",
            &["verifier:v1".to_string(), "gate:g1".to_string()],
            "vev_e1",
        )
        .unwrap();

        // Frontier moved: 7 discharged, 8 now open.
        assert_eq!(obligation_status(&obl7, &p, &disabled).unwrap(), "discharged");
        assert_eq!(obligation_status(&obl8, &p, &disabled).unwrap(), "open");
    }

    #[test]
    fn frontier_map_partitions_and_roots() {
        let p = Presentation {
            cell_ranks: Default::default(),
            clauses: Vec::new(),
            accepted_events: Vec::new(),
            cell_metadata: Default::default(),
        };
        let disabled = BTreeSet::new();
        let obls = [sidon_obligation(4, 7, &[])];
        let map = build_frontier_map(&p, &obls, &disabled).unwrap();
        assert!(map["frontier_map_root"].as_str().unwrap().starts_with("vfm_"));
        assert_eq!(map["open_obligations"].as_array().unwrap().len(), 1);
        assert_eq!(map["discharged_obligations"].as_array().unwrap().len(), 0);
    }
}
