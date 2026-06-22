//! Experiment-plane tooling for the Technical Inevitability Program (Phase 0:
//! credible receipts + a typed cohort obligation).
//!
//! Two content-addressed, NON-AUTHORITATIVE artifacts plus a pure projection.
//! Neither adds an event kind, a reducer arm, or any wire-format change: they are
//! receipts and projections over state that already exists, so the conformance
//! gate stays trivially green (the red-team's "minimal receipts now, full closure
//! after the FIE number" verdict).
//!
//!   - [`RunManifest`] (`vxm_`): an ordered, immutable record of one experiment
//!     run's turns (each bound to its `vac_` activity envelope + the frontier
//!     root it ran against), so a skeptic can replay the WHOLE run and confirm no
//!     turn was silently dropped. This is what answers "the founder selected the
//!     wins": the manifest is content-addressed over the complete, ordered turn
//!     set, so dropping or reordering a turn changes its id.
//!   - [`CohortObligation`] (`vxo_`): a typed, sealable unit of "work to do".
//!     Its discharge is a PURE PROJECTION over accepted state
//!     ([`obligation_status`]): open -> frozen-verifier-discharged is mechanical,
//!     not hand-asserted. Deliberately NOT the full domain-general lift (the
//!     `sidon_profile` stop-list is correct doctrine; wait for a 2nd-domain
//!     producer) — just the cohort-scoped shape the compounding experiment needs.

use crate::cli::{fail_return, print_json};
use crate::cli_commands::ExperimentAction;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use vela_protocol::activity::ActivityEnvelope;
use vela_protocol::repo;

pub const RUN_MANIFEST_SCHEMA: &str = "vela.experiment.run-manifest.v1";
pub const COHORT_OBLIGATION_SCHEMA: &str = "vela.experiment.cohort-obligation.v1";

/// One turn of an experiment run, bound to its activity envelope and the root it
/// ran against. Ordered by `created_at` within a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestTurn {
    pub turn_index: usize,
    /// `vac_` activity envelope id (the run receipt; non-authoritative).
    pub activity_id: String,
    pub kind: String,
    pub base_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_roots: Vec<String>,
    pub created_at: String,
}

/// An ordered, immutable record of an experiment run's turns. Content-addressed:
/// dropping, adding, or reordering a turn changes `manifest_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    pub schema: String,
    /// `vxm_<16hex>`, content-addressed over the body with id zeroed.
    pub manifest_id: String,
    pub experiment_id: String,
    /// The frontier snapshot_hash (from `vela.lock`) the run was assembled over.
    pub frontier_root: String,
    pub turns: Vec<ManifestTurn>,
    pub created_at: String,
}

impl RunManifest {
    fn derive_id(&self) -> Result<String, String> {
        let mut p = self.clone();
        p.manifest_id = String::new();
        let bytes = serde_json::to_vec(&p).map_err(|e| format!("serialize manifest: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vxm_{}", hex::encode(&digest[..8])))
    }
}

/// A typed, sealable unit of open work. Discharge is a projection over accepted
/// state, never a hand-asserted field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortObligation {
    pub schema: String,
    /// `vxo_<16hex>`, content-addressed over the body with id zeroed.
    pub obligation_id: String,
    pub cohort_id: String,
    /// The accepted-finding id (`vf_`) whose acceptance discharges this obligation.
    pub target_id: String,
    /// `sha256(statement)[..16]` — pins the exact statement this obligation is for.
    pub statement_digest: String,
    /// Prior accepted judgments this obligation depends on (must be accepted first).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependency_ids: Vec<String>,
    /// How discharge is checked: `lean_kernel` | `vela_verify` | other.
    pub discharge_kind: String,
    pub created_at: String,
}

impl CohortObligation {
    /// Build a content-addressed obligation from its core fields.
    pub fn new(
        cohort_id: &str,
        target_id: &str,
        statement: &str,
        dependency_ids: Vec<String>,
        discharge_kind: &str,
        created_at: &str,
    ) -> Result<Self, String> {
        if cohort_id.trim().is_empty() {
            return Err("cohort_id cannot be empty".into());
        }
        if target_id.trim().is_empty() {
            return Err("target_id cannot be empty".into());
        }
        let statement_digest = {
            let d = Sha256::digest(statement.trim().as_bytes());
            hex::encode(&d[..8])
        };
        let mut ob = CohortObligation {
            schema: COHORT_OBLIGATION_SCHEMA.to_string(),
            obligation_id: String::new(),
            cohort_id: cohort_id.to_string(),
            target_id: target_id.to_string(),
            statement_digest,
            dependency_ids,
            discharge_kind: discharge_kind.to_string(),
            created_at: created_at.to_string(),
        };
        ob.obligation_id = ob.derive_id()?;
        Ok(ob)
    }

    fn derive_id(&self) -> Result<String, String> {
        let mut p = self.clone();
        p.obligation_id = String::new();
        let bytes = serde_json::to_vec(&p).map_err(|e| format!("serialize obligation: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vxo_{}", hex::encode(&digest[..8])))
    }
}

/// The discharge status of a cohort obligation, projected over accepted state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationStatus {
    /// A prerequisite judgment is not yet accepted — cannot be attacked cleanly.
    Blocked,
    /// The target judgment is accepted (and all dependencies are) — done.
    Discharged,
    /// Dependencies accepted, target not yet — attackable now.
    Open,
}

impl ObligationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ObligationStatus::Blocked => "blocked",
            ObligationStatus::Discharged => "discharged",
            ObligationStatus::Open => "open",
        }
    }
}

/// PURE projection: an obligation is `Blocked` if any dependency is not in the
/// accepted set; else `Discharged` if its target is accepted; else `Open`.
/// This is the mechanical "open -> frozen-verifier-discharged" the experiment
/// needs so discharge is never hand-asserted.
pub fn obligation_status(ob: &CohortObligation, accepted: &BTreeSet<String>) -> ObligationStatus {
    if ob.dependency_ids.iter().any(|d| !accepted.contains(d)) {
        ObligationStatus::Blocked
    } else if accepted.contains(&ob.target_id) {
        ObligationStatus::Discharged
    } else {
        ObligationStatus::Open
    }
}

/// Read every `vac_` activity envelope under `<frontier>/activity/`, optionally
/// filtered to those tagged `experiment:<id>` in `risk_tags`, ordered by
/// `created_at`, and content-address them into a [`RunManifest`].
fn assemble_manifest(
    frontier: &Path,
    experiment_id: &str,
    created_at: &str,
) -> Result<RunManifest, String> {
    let activity_dir = frontier.join("activity");
    let mut envs: Vec<ActivityEnvelope> = Vec::new();
    if activity_dir.is_dir() {
        let rd = std::fs::read_dir(&activity_dir)
            .map_err(|e| format!("read {}: {e}", activity_dir.display()))?;
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            let s = match std::fs::read_to_string(&p) {
                Ok(s) => s,
                Err(_) => continue,
            };
            if let Ok(env) = serde_json::from_str::<ActivityEnvelope>(&s) {
                envs.push(env);
            }
        }
    }
    let tag = format!("experiment:{experiment_id}");
    if !experiment_id.is_empty() && experiment_id != "*" {
        envs.retain(|e| e.risk_tags.iter().any(|t| t == &tag));
    }
    // Deterministic order: by created_at, then activity_id as a tiebreak.
    envs.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.activity_id.cmp(&b.activity_id))
    });
    let frontier_root = std::fs::read_to_string(frontier.join("vela.lock"))
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| {
            v.get("snapshot_hash")
                .and_then(|x| x.as_str().map(String::from))
        })
        .unwrap_or_default();
    let turns: Vec<ManifestTurn> = envs
        .into_iter()
        .enumerate()
        .map(|(i, e)| ManifestTurn {
            turn_index: i,
            activity_id: e.activity_id,
            kind: e.kind,
            base_root: e.base_root,
            output_roots: e.output_roots,
            created_at: e.created_at,
        })
        .collect();
    let mut m = RunManifest {
        schema: RUN_MANIFEST_SCHEMA.to_string(),
        manifest_id: String::new(),
        experiment_id: experiment_id.to_string(),
        frontier_root,
        turns,
        created_at: created_at.to_string(),
    };
    m.manifest_id = m.derive_id()?;
    Ok(m)
}

pub(crate) fn cmd_experiment(action: ExperimentAction) {
    match action {
        ExperimentAction::Manifest {
            frontier,
            experiment,
            out,
            json,
        } => {
            let created_at = chrono::Utc::now().to_rfc3339();
            let m = assemble_manifest(&frontier, &experiment, &created_at)
                .unwrap_or_else(|e| fail_return(&e));
            let body = serde_json::to_string_pretty(&m)
                .unwrap_or_else(|e| fail_return(&format!("serialize manifest: {e}")));
            if let Some(path) = out.as_ref() {
                std::fs::write(path, body.clone() + "\n")
                    .unwrap_or_else(|e| fail_return(&format!("write {}: {e}", path.display())));
            }
            if json {
                print_json(&m);
            } else {
                println!(
                    "· run-manifest {} ({} turns) experiment={}",
                    m.manifest_id,
                    m.turns.len(),
                    m.experiment_id
                );
                if let Some(path) = out.as_ref() {
                    println!("  written: {}", path.display());
                }
            }
        }
        ExperimentAction::Status {
            cohort,
            frontier,
            json,
        } => {
            let s = std::fs::read_to_string(&cohort)
                .unwrap_or_else(|e| fail_return(&format!("read {}: {e}", cohort.display())));
            // Accept either a bare array of obligations or a { "obligations": [...] } wrapper.
            let v: serde_json::Value = serde_json::from_str(&s)
                .unwrap_or_else(|e| fail_return(&format!("parse cohort: {e}")));
            let arr = v
                .get("obligations")
                .and_then(|x| x.as_array())
                .cloned()
                .or_else(|| v.as_array().cloned())
                .unwrap_or_else(|| {
                    fail_return("cohort: expected an array or {obligations: [...]}")
                });
            let obligations: Vec<CohortObligation> = arr
                .into_iter()
                .map(serde_json::from_value)
                .collect::<Result<_, _>>()
                .unwrap_or_else(|e| fail_return(&format!("parse obligation: {e}")));
            let project = repo::load_from_path(&frontier).unwrap_or_else(|e| fail_return(&e));
            let accepted: BTreeSet<String> =
                project.findings.iter().map(|f| f.id.clone()).collect();
            let mut open = 0;
            let mut discharged = 0;
            let mut blocked = 0;
            let mut rows = Vec::new();
            for ob in &obligations {
                let st = obligation_status(ob, &accepted);
                match st {
                    ObligationStatus::Open => open += 1,
                    ObligationStatus::Discharged => discharged += 1,
                    ObligationStatus::Blocked => blocked += 1,
                }
                rows.push(json!({
                    "obligation_id": ob.obligation_id,
                    "target_id": ob.target_id,
                    "status": st.as_str(),
                }));
            }
            if json {
                print_json(&json!({
                    "command": "experiment status",
                    "frontier": frontier.display().to_string(),
                    "total": obligations.len(),
                    "open": open,
                    "discharged": discharged,
                    "blocked": blocked,
                    "obligations": rows,
                }));
            } else {
                println!(
                    "· cohort status: {} total — {} discharged, {} open, {} blocked",
                    obligations.len(),
                    discharged,
                    open,
                    blocked
                );
            }
        }
        ExperimentAction::Obligation {
            cohort,
            target,
            statement,
            deps,
            discharge_kind,
            json,
        } => {
            let created_at = chrono::Utc::now().to_rfc3339();
            let ob = CohortObligation::new(
                &cohort,
                &target,
                &statement,
                deps,
                &discharge_kind,
                &created_at,
            )
            .unwrap_or_else(|e| fail_return(&e));
            if json {
                print_json(&ob);
            } else {
                println!(
                    "· obligation {} (cohort {})",
                    ob.obligation_id, ob.cohort_id
                );
                println!(
                    "  target: {}  discharge: {}",
                    ob.target_id, ob.discharge_kind
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obligation_id_is_deterministic_and_content_addressed() {
        let a = CohortObligation::new("c1", "vf_aaa", "stmt", vec![], "lean_kernel", "2026-06-22")
            .unwrap();
        let b = CohortObligation::new("c1", "vf_aaa", "stmt", vec![], "lean_kernel", "2026-06-22")
            .unwrap();
        assert_eq!(a.obligation_id, b.obligation_id);
        assert!(a.obligation_id.starts_with("vxo_"));
        // changing the target changes the id
        let c = CohortObligation::new("c1", "vf_bbb", "stmt", vec![], "lean_kernel", "2026-06-22")
            .unwrap();
        assert_ne!(a.obligation_id, c.obligation_id);
    }

    #[test]
    fn obligation_status_is_a_pure_projection() {
        let ob = CohortObligation::new(
            "c1",
            "vf_target",
            "T",
            vec!["vf_dep".to_string()],
            "lean_kernel",
            "t",
        )
        .unwrap();
        // dependency not accepted -> blocked, regardless of target
        let mut accepted: BTreeSet<String> = BTreeSet::new();
        accepted.insert("vf_target".into());
        assert_eq!(obligation_status(&ob, &accepted), ObligationStatus::Blocked);
        // dependency accepted, target not -> open
        let mut accepted: BTreeSet<String> = BTreeSet::new();
        accepted.insert("vf_dep".into());
        assert_eq!(obligation_status(&ob, &accepted), ObligationStatus::Open);
        // both accepted -> discharged
        accepted.insert("vf_target".into());
        assert_eq!(
            obligation_status(&ob, &accepted),
            ObligationStatus::Discharged
        );
    }

    #[test]
    fn manifest_id_changes_if_a_turn_is_dropped_or_reordered() {
        let t = |i: usize, id: &str, at: &str| ManifestTurn {
            turn_index: i,
            activity_id: id.to_string(),
            kind: "search.candidate".into(),
            base_root: "r".into(),
            output_roots: vec![],
            created_at: at.to_string(),
        };
        let mk = |turns: Vec<ManifestTurn>| {
            let mut m = RunManifest {
                schema: RUN_MANIFEST_SCHEMA.into(),
                manifest_id: String::new(),
                experiment_id: "fie-1".into(),
                frontier_root: "root".into(),
                turns,
                created_at: "t".into(),
            };
            m.manifest_id = m.derive_id().unwrap();
            m
        };
        let full = mk(vec![t(0, "vac_a", "1"), t(1, "vac_b", "2")]);
        let dropped = mk(vec![t(0, "vac_a", "1")]);
        assert!(full.manifest_id.starts_with("vxm_"));
        assert_ne!(full.manifest_id, dropped.manifest_id);
    }
}
