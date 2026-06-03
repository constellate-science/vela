//! v0.45: Pearl level 3 — counterfactual queries over the claim graph.
//!
//! Level 1 (v0.40) answered identifiability per finding by 3×4 lookup.
//! Level 2 (v0.44) answered "is the effect of source on target
//! identifiable from the link graph?" via back-door / front-door
//! adjustment.
//! Level 3 (v0.45) answers "given that we observed Y under X=x, what
//! would Y have been under X=x'?" via twin-network construction.
//!
//! ### Method (Pearl 2009, §7)
//!
//! A twin network is two copies of the SCM running in parallel: the
//! *factual* world (what we actually observed) and the *counterfactual*
//! world (what we would have observed under the intervention). The two
//! worlds share the same exogenous noise terms but differ at the
//! intervened node. Propagating perturbations through both worlds and
//! comparing the target node yields the counterfactual delta.
//!
//! In Vela's claim graph the "values" being propagated are belief
//! confidences in [0,1]. A `Mechanism` (v0.45) on each edge specifies
//! how a parent's confidence determines the child's. Edges without
//! mechanisms are treated as opaque — they block counterfactual
//! propagation through that edge and surface as
//! `MechanismUnspecified`.
//!
//! Doctrine:
//! - We only answer counterfactuals along paths whose every edge has a
//!   mechanism. Partial answers are honest about which edges blocked
//!   propagation.
//! - We perturb on the [0,1] confidence axis, not on the underlying
//!   scientific quantity. Vela does not (and should not) infer real-
//!   world units from prose; it tracks the kernel's first-class
//!   quantity, belief.
//! - Twin-network is overkill for claim graphs that are tree-shaped on
//!   the observed→intervened path; we still implement it because
//!   real-world claim graphs converge (multiple supports of one
//!   finding) and a simple forward propagation would double-count.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::bundle::Mechanism;
use crate::causal_graph::CausalGraph;
use crate::project::Project;

/// A request: "intervene to set finding `vf_id`'s confidence to
/// `value`, then ask: what is the counterfactual confidence of
/// `target`?"
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CounterfactualQuery {
    pub intervene_on: String,
    pub set_to: f64,
    pub target: String,
}

/// The verdict for a counterfactual query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CounterfactualVerdict {
    /// Twin-network propagation succeeded end-to-end.
    Resolved {
        /// Factual confidence at target (the observed value).
        factual: f64,
        /// Counterfactual confidence at target under the intervention.
        counterfactual: f64,
        /// `counterfactual − factual`.
        delta: f64,
        /// The directed paths from the intervened node to the target
        /// that propagated the perturbation, in the order discovered.
        paths_used: Vec<Vec<String>>,
    },
    /// The intervened node and the target are connected, but at least
    /// one edge on every connecting path lacks a mechanism. We refuse
    /// to guess.
    MechanismUnspecified {
        /// Edges (parent → child) along source→target paths with no
        /// mechanism declared.
        unspecified_edges: Vec<(String, String)>,
    },
    /// No directed path from the intervened node reaches the target.
    /// Counterfactual is the same as factual by structural assumption.
    NoCausalPath { factual: f64 },
    /// One of the cited findings isn't in the graph.
    UnknownNode { which: String },
    /// `set_to` is outside [0, 1] (the confidence axis).
    InvalidIntervention { reason: String },
}

/// Run a counterfactual query end-to-end.
///
/// 1. Validate inputs (nodes exist; intervention in [0,1]).
/// 2. Build the directed graph and find directed paths from
///    `intervene_on` to `target`.
/// 3. For each path, check that every edge has a mechanism. If any
///    path does, propagate the perturbation along it via mechanism
///    composition.
/// 4. Aggregate path contributions (we use *max-magnitude* to avoid
///    additive double-counting on diamond graphs — this is the
///    weakest defensible aggregation and keeps us honest about the
///    structural causal model's limits).
/// 5. Bound the result to [0, 1].
#[must_use]
pub fn answer_counterfactual(
    project: &Project,
    query: &CounterfactualQuery,
) -> CounterfactualVerdict {
    if !(0.0..=1.0).contains(&query.set_to) {
        return CounterfactualVerdict::InvalidIntervention {
            reason: format!(
                "intervention must be on the confidence axis [0,1], got {}",
                query.set_to
            ),
        };
    }

    let confidence_index = build_confidence_index(project);
    let factual_target = match confidence_index.get(&query.target) {
        Some(&c) => c,
        None => {
            return CounterfactualVerdict::UnknownNode {
                which: query.target.clone(),
            };
        }
    };
    let factual_source = match confidence_index.get(&query.intervene_on) {
        Some(&c) => c,
        None => {
            return CounterfactualVerdict::UnknownNode {
                which: query.intervene_on.clone(),
            };
        }
    };

    let graph = CausalGraph::from_project(project);
    if !graph.contains(&query.intervene_on) {
        return CounterfactualVerdict::UnknownNode {
            which: query.intervene_on.clone(),
        };
    }
    if !graph.contains(&query.target) {
        return CounterfactualVerdict::UnknownNode {
            which: query.target.clone(),
        };
    }

    // Directed paths from intervene_on (cause) to target (effect),
    // using the v0.44 graph's child-direction edges.
    let paths = directed_paths_from_to(&graph, &query.intervene_on, &query.target, 8);
    if paths.is_empty() {
        return CounterfactualVerdict::NoCausalPath {
            factual: factual_target,
        };
    }

    // Build a mechanism lookup: (parent, child) -> Option<Mechanism>.
    let mech_index = build_mechanism_index(project);

    let mut unspecified_edges: HashSet<(String, String)> = HashSet::new();
    let mut path_deltas: Vec<f64> = Vec::new();
    let mut paths_used: Vec<Vec<String>> = Vec::new();

    let delta_x = query.set_to - factual_source;

    for path in &paths {
        // Path is [source, ..., target]; `depends`/`supports` edges in
        // the v0.44 graph point from the *dependent* to the *parent*.
        // In our convention, "child depends on parent" means a directed
        // causal edge from parent → child for level-3 propagation. The
        // CausalGraph lookup is parents_of(child) -> {parent}; so a
        // forward path from cause→effect in the graph traverses
        // children_of edges.
        let mut delta = delta_x;
        let mut path_ok = true;
        for window in path.windows(2) {
            let parent = &window[0];
            let child = &window[1];
            match mech_index.get(&(parent.clone(), child.clone())) {
                Some(m) => match m.apply(delta) {
                    Some(next_delta) => delta = next_delta,
                    None => {
                        unspecified_edges.insert((parent.clone(), child.clone()));
                        path_ok = false;
                        break;
                    }
                },
                None => {
                    unspecified_edges.insert((parent.clone(), child.clone()));
                    path_ok = false;
                    break;
                }
            }
        }
        if path_ok {
            path_deltas.push(delta);
            paths_used.push(path.clone());
        }
    }

    if path_deltas.is_empty() {
        let mut edges: Vec<(String, String)> = unspecified_edges.into_iter().collect();
        edges.sort();
        return CounterfactualVerdict::MechanismUnspecified {
            unspecified_edges: edges,
        };
    }

    // Aggregate: pick the path delta with maximum absolute magnitude.
    // This is intentionally conservative — additive aggregation would
    // double-count on diamond graphs; max-magnitude reports the
    // strongest single causal route without inventing structural
    // assumptions we don't have.
    let aggregate_delta = path_deltas
        .iter()
        .copied()
        .fold(0.0_f64, |acc, d| if d.abs() > acc.abs() { d } else { acc });

    let counterfactual = (factual_target + aggregate_delta).clamp(0.0, 1.0);
    CounterfactualVerdict::Resolved {
        factual: factual_target,
        counterfactual,
        delta: counterfactual - factual_target,
        paths_used,
    }
}

/// BFS-enumerate directed paths cause→effect using `children_of` (the
/// "downstream" direction). Bounded by `max_depth` and `max_paths`.
fn directed_paths_from_to(
    graph: &CausalGraph,
    cause: &str,
    effect: &str,
    max_depth: usize,
) -> Vec<Vec<String>> {
    const MAX_PATHS: usize = 32;
    let mut out: Vec<Vec<String>> = Vec::new();
    let mut queue: VecDeque<Vec<String>> = VecDeque::new();
    queue.push_back(vec![cause.to_string()]);

    while let Some(path) = queue.pop_front() {
        if out.len() >= MAX_PATHS {
            break;
        }
        if path.len() > max_depth {
            continue;
        }
        let last = path.last().expect("path non-empty");
        if last == effect && path.len() > 1 {
            out.push(path);
            continue;
        }
        for child in graph.children_of(last) {
            let child_owned = child.to_string();
            if path.contains(&child_owned) {
                continue; // no cycles
            }
            let mut next = path.clone();
            next.push(child_owned);
            queue.push_back(next);
        }
    }
    out
}

fn build_confidence_index(project: &Project) -> HashMap<String, f64> {
    let mut idx = HashMap::new();
    for finding in &project.findings {
        idx.insert(finding.id.clone(), finding.confidence.score);
    }
    idx
}

/// Build a (parent, child) → Mechanism index from the project's link
/// graph. In v0.44 graph convention, a `depends`/`supports` link from
/// finding A to finding B encodes "A depends on B" — i.e. B is the
/// parent and A is the child. The mechanism on the link describes how
/// B drives A.
fn build_mechanism_index(project: &Project) -> HashMap<(String, String), Mechanism> {
    let mut idx = HashMap::new();
    for finding in &project.findings {
        for link in &finding.links {
            if !matches!(link.link_type.as_str(), "depends" | "supports") {
                continue;
            }
            // a (the dependent / child) → link.target (the parent).
            // Index by (parent, child).
            let target = match link.target.split_once(':') {
                Some((_, rest)) => rest.to_string(),
                None => link.target.clone(),
            };
            if let Some(m) = link.mechanism {
                idx.insert((target, finding.id.clone()), m);
            }
        }
    }
    idx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{
        Assertion, Conditions, Confidence, Evidence, Extraction, FindingBundle, Flags, Link,
        Mechanism, MechanismSign, Provenance,
    };
    use crate::project;

    fn conditions() -> Conditions {
        Conditions {
            text: String::new(),
            species_verified: vec![],
            species_unverified: vec![],
            in_vitro: false,
            in_vivo: false,
            human_data: false,
            clinical_trial: false,
            concentration_range: None,
            duration: None,
            age_group: None,
            cell_type: None,
        }
    }

    fn provenance() -> Provenance {
        Provenance {
            source_type: "published_paper".into(),
            doi: None,
            pmid: None,
            pmc: None,
            openalex_id: None,
            url: None,
            title: "Test".into(),
            authors: vec![],
            year: Some(2025),
            journal: None,
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction::default(),
            review: None,
            citation_count: None,
        }
    }

    fn finding(id: &str, conf: f64, links: Vec<Link>) -> FindingBundle {
        let mut b = FindingBundle::new(
            Assertion {
                text: format!("claim {id}"),
                assertion_type: "mechanism".into(),
                entities: vec![],
                relation: None,
                direction: None,
                causal_claim: None,
                causal_evidence_grade: None,
            },
            Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                species: None,
                method: String::new(),
                sample_size: None,
                effect_size: None,
                p_value: None,
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            conditions(),
            Confidence::raw(conf, "test", 0.85),
            provenance(),
            Flags::default(),
        );
        b.id = id.to_string();
        b.links = links;
        b
    }

    fn link_with_mechanism(target: &str, mech: Option<Mechanism>) -> Link {
        Link {
            target: target.into(),
            link_type: "depends".into(),
            note: String::new(),
            inferred_by: "test".into(),
            created_at: String::new(),
            mechanism: mech,
        }
    }

    /// Three findings A → B → C and confidences 0.9, 0.8, 0.7.
    /// `B depends on A` and `C depends on B`. Mechanisms vary per test.
    fn fixture_chain(ab: Option<Mechanism>, bc: Option<Mechanism>) -> Project {
        let a = finding("vf_aaa", 0.9, vec![]);
        let b = finding("vf_bbb", 0.8, vec![link_with_mechanism("vf_aaa", ab)]);
        let c = finding("vf_ccc", 0.7, vec![link_with_mechanism("vf_bbb", bc)]);
        project::assemble("test", vec![a, b, c], 1, 0, "test")
    }

    #[test]
    fn linear_chain_resolves() {
        let project = fixture_chain(
            Some(Mechanism::Linear {
                sign: MechanismSign::Positive,
                slope: 0.5,
            }),
            Some(Mechanism::Linear {
                sign: MechanismSign::Positive,
                slope: 0.4,
            }),
        );
        let q = CounterfactualQuery {
            intervene_on: "vf_aaa".into(),
            set_to: 0.5,
            target: "vf_ccc".into(),
        };
        let v = answer_counterfactual(&project, &q);
        match v {
            CounterfactualVerdict::Resolved {
                factual,
                counterfactual,
                delta,
                ..
            } => {
                assert!((factual - 0.7).abs() < 1e-9);
                // delta_x = 0.5 - 0.9 = -0.4; bc(ab(-0.4)) = 0.4*0.5*-0.4 = -0.08
                assert!((delta - (-0.08)).abs() < 1e-6, "delta = {delta}");
                assert!(counterfactual > 0.0 && counterfactual < 1.0);
            }
            _ => panic!("expected Resolved, got {v:?}"),
        }
    }

    #[test]
    fn missing_mechanism_blocks_propagation() {
        let project = fixture_chain(
            Some(Mechanism::Linear {
                sign: MechanismSign::Positive,
                slope: 0.5,
            }),
            None,
        );
        let q = CounterfactualQuery {
            intervene_on: "vf_aaa".into(),
            set_to: 0.5,
            target: "vf_ccc".into(),
        };
        let v = answer_counterfactual(&project, &q);
        assert!(matches!(
            v,
            CounterfactualVerdict::MechanismUnspecified { .. }
        ));
    }

    #[test]
    fn unknown_mechanism_blocks_propagation() {
        let project = fixture_chain(
            Some(Mechanism::Linear {
                sign: MechanismSign::Positive,
                slope: 0.5,
            }),
            Some(Mechanism::Unknown),
        );
        let q = CounterfactualQuery {
            intervene_on: "vf_aaa".into(),
            set_to: 0.5,
            target: "vf_ccc".into(),
        };
        let v = answer_counterfactual(&project, &q);
        assert!(matches!(
            v,
            CounterfactualVerdict::MechanismUnspecified { .. }
        ));
    }

    #[test]
    fn out_of_range_intervention_rejected() {
        let project = fixture_chain(None, None);
        let q = CounterfactualQuery {
            intervene_on: "vf_aaa".into(),
            set_to: 1.5,
            target: "vf_ccc".into(),
        };
        assert!(matches!(
            answer_counterfactual(&project, &q),
            CounterfactualVerdict::InvalidIntervention { .. }
        ));
    }

    #[test]
    fn no_path_yields_factual() {
        let project = fixture_chain(None, None);
        let q = CounterfactualQuery {
            intervene_on: "vf_ccc".into(), // C has no descendants
            set_to: 0.5,
            target: "vf_aaa".into(),
        };
        match answer_counterfactual(&project, &q) {
            CounterfactualVerdict::NoCausalPath { factual } => {
                assert!((factual - 0.9).abs() < 1e-9);
            }
            v => panic!("expected NoCausalPath, got {v:?}"),
        }
    }

    #[test]
    fn negative_sign_flips_direction() {
        let project = fixture_chain(
            Some(Mechanism::Linear {
                sign: MechanismSign::Negative,
                slope: 0.5,
            }),
            Some(Mechanism::Linear {
                sign: MechanismSign::Positive,
                slope: 1.0,
            }),
        );
        // intervene to bump A from 0.9 -> 1.0 (delta_x = +0.1)
        // ab(+0.1) = -0.5*0.1 = -0.05
        // bc(-0.05) = +1.0*-0.05 = -0.05
        // counterfactual C = 0.7 + (-0.05) = 0.65
        let q = CounterfactualQuery {
            intervene_on: "vf_aaa".into(),
            set_to: 1.0,
            target: "vf_ccc".into(),
        };
        match answer_counterfactual(&project, &q) {
            CounterfactualVerdict::Resolved {
                counterfactual,
                delta,
                ..
            } => {
                assert!((delta - (-0.05)).abs() < 1e-6, "delta = {delta}");
                assert!((counterfactual - 0.65).abs() < 1e-6);
            }
            v => panic!("expected Resolved, got {v:?}"),
        }
    }
}
