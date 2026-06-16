//! The dark-matter boundary query (memo §3, §7.3): the productive edges of a
//! frontier — the work that is one step from done, the results that rest on
//! thin ground, the places the record disagrees, and the open findings with
//! no scaffolding yet.
//!
//! "Dark matter" is the memo's name for the latent work a frontier implies but
//! has not yet surfaced as a task: an open finding whose every premise is
//! already established (so closing it is one verifier-run away), an
//! established result resting on a single thread (fragile), a live
//! contradiction, an isolated open question nobody has started. This module is
//! a pure projection over the typed [`FrontierGraph`] and the findings' review
//! state — it classifies, it never adjudicates, and every item points back at
//! a real finding the caller can open a submission against.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use crate::frontier_graph::{EdgeKind, FindingState, FrontierGraph};
use crate::pathfind::SUPPORT_KINDS;
use crate::project::Project;

/// One boundary finding: the finding itself, why it sits on the boundary, and
/// the related findings that explain the classification (its established
/// premises, its thin support, or its contradiction partner).
#[derive(Debug, Clone, Serialize)]
pub struct BoundaryItem {
    pub finding: String,
    pub label: String,
    pub reason: String,
    pub related: Vec<String>,
}

/// A finding whose support funnels entirely through one load-bearing
/// dependency that is not itself established (GPT §11): a single point of
/// failure. If that dependency falls, the finding's whole support falls with
/// it. The kintsugi crack — where the frontier is one correction from a cascade.
#[derive(Debug, Clone, Serialize)]
pub struct BrittleItem {
    pub finding: String,
    pub label: String,
    /// The load-bearing dependency every support path runs through.
    pub dominator: String,
    pub dominator_label: String,
    /// The dominator's own state (why it is a risk).
    pub dominator_state: String,
    /// How many support nodes vanish if the dominator is removed.
    pub support_size: usize,
}

/// The boundary of a frontier, partitioned into the dark-matter categories.
/// Each list is sorted by finding id for stable output.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Boundary {
    /// Open findings whose every in-frontier premise is already established —
    /// closing them is one step away (the highest-value queue).
    pub one_premise_away: Vec<BoundaryItem>,
    /// Established findings resting on thin ground (low confidence, or a
    /// single supporting thread).
    pub fragile: Vec<BoundaryItem>,
    /// Findings whose entire support funnels through one un-established
    /// load-bearing dependency (a single point of failure).
    pub brittle: Vec<BrittleItem>,
    /// Findings in live disagreement — a contradiction partner or a contested
    /// review verdict. Never auto-resolved.
    pub contested: Vec<BoundaryItem>,
    /// Open findings with no scaffolding: no premises, no support, nobody has
    /// started building toward or away from them.
    pub stale_open: Vec<BoundaryItem>,
}

impl Boundary {
    /// Derive the boundary from a project. Pure and deterministic.
    #[must_use]
    pub fn derive(project: &Project) -> Self {
        let graph = FrontierGraph::from_project(project);

        // Per-node incidence: outgoing premises (depends/derived/discharges),
        // outgoing/incoming support, for the scaffolding and one-premise tests.
        let mut out_premise: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        let mut out_support: BTreeMap<&str, usize> = BTreeMap::new();
        let mut in_support: BTreeMap<&str, usize> = BTreeMap::new();
        for e in graph.all_edges() {
            match e.kind {
                EdgeKind::DependsOn | EdgeKind::DerivedFrom | EdgeKind::Discharges => {
                    out_premise.entry(&e.source).or_default().push(&e.target);
                }
                EdgeKind::Supports | EdgeKind::Improves => {
                    *out_support.entry(&e.source).or_default() += 1;
                    *in_support.entry(&e.target).or_default() += 1;
                }
                _ => {}
            }
        }

        let mut boundary = Boundary::default();

        for node in graph.nodes() {
            let id = node.id.as_str();
            match node.state {
                FindingState::Open => {
                    let premises = out_premise.get(id).cloned().unwrap_or_default();
                    let has_support_scaffolding = out_support.contains_key(id)
                        || in_support.contains_key(id)
                        || !premises.is_empty();
                    if premises.is_empty() {
                        if !has_support_scaffolding {
                            boundary.stale_open.push(BoundaryItem {
                                finding: node.id.clone(),
                                label: node.label.clone(),
                                reason: "open with no premises, support, or dependents".into(),
                                related: vec![],
                            });
                        }
                        continue;
                    }
                    // One-premise-away: every in-frontier premise is
                    // established. An out-of-frontier or unestablished premise
                    // disqualifies it (we can only certify what we can see).
                    let all_established = premises.iter().all(|t| {
                        graph
                            .node(t)
                            .is_some_and(|n| n.state == FindingState::Established)
                    });
                    if all_established {
                        boundary.one_premise_away.push(BoundaryItem {
                            finding: node.id.clone(),
                            label: node.label.clone(),
                            reason: format!(
                                "open; all {} premise(s) established",
                                premises.len()
                            ),
                            related: premises.iter().map(|s| (*s).to_string()).collect(),
                        });
                    }
                }
                FindingState::Fragile => {
                    let support = out_support.get(id).copied().unwrap_or(0);
                    boundary.fragile.push(BoundaryItem {
                        finding: node.id.clone(),
                        label: node.label.clone(),
                        reason: if support <= 1 {
                            format!(
                                "established but thin (confidence {:.2}, {support} supporting link)",
                                node.confidence
                            )
                        } else {
                            format!("established but thin (confidence {:.2})", node.confidence)
                        },
                        related: vec![],
                    });
                }
                FindingState::Contested => {
                    boundary.contested.push(BoundaryItem {
                        finding: node.id.clone(),
                        label: node.label.clone(),
                        reason: "contested review verdict".into(),
                        related: vec![],
                    });
                }
                FindingState::Established | FindingState::Refuted => {}
            }
        }

        // Brittle: a finding whose support funnels entirely through one
        // load-bearing dependency that is not itself established. Computed over
        // the support-bearing edge kinds; only single-points-of-failure with a
        // risky dominator surface (an established dominator is sound footing).
        for node in graph.nodes() {
            let doms = graph.support_dominators(&node.id, &SUPPORT_KINDS);
            let Some(spof) = doms.iter().find(|d| d.single_point_of_failure) else {
                continue;
            };
            let dom_state = spof.state.unwrap_or(FindingState::Open);
            if dom_state == FindingState::Established {
                continue;
            }
            boundary.brittle.push(BrittleItem {
                finding: node.id.clone(),
                label: node.label.clone(),
                dominator: spof.node.clone(),
                dominator_label: spof.label.clone(),
                dominator_state: dom_state.as_str().to_string(),
                support_size: spof.weight,
            });
        }
        boundary.brittle.sort_by(|a, b| {
            b.support_size
                .cmp(&a.support_size)
                .then(a.finding.cmp(&b.finding))
        });

        // Contradiction pairs add any node not already flagged contested, with
        // its partner as the related finding. Each endpoint is listed once.
        let already: BTreeSet<String> =
            boundary.contested.iter().map(|i| i.finding.clone()).collect();
        let mut added: BTreeSet<String> = already.clone();
        for (a, b) in graph.contradiction_pairs() {
            for (node_id, partner) in [(&a, &b), (&b, &a)] {
                if added.insert(node_id.clone()) {
                    let label = graph.label_of(node_id).unwrap_or("").to_string();
                    boundary.contested.push(BoundaryItem {
                        finding: node_id.clone(),
                        label,
                        reason: "in a recorded contradiction".into(),
                        related: vec![partner.clone()],
                    });
                }
            }
        }
        boundary.contested.sort_by(|x, y| x.finding.cmp(&y.finding));

        boundary
    }

    /// Total findings on the boundary across all categories.
    #[must_use]
    pub fn total(&self) -> usize {
        self.one_premise_away.len()
            + self.fragile.len()
            + self.brittle.len()
            + self.contested.len()
            + self.stale_open.len()
    }

    /// Stable JSON for the web boundary view and the Dark Matter Queue.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": "vela.boundary.v0.1",
            "summary": {
                "one_premise_away": self.one_premise_away.len(),
                "fragile": self.fragile.len(),
                "brittle": self.brittle.len(),
                "contested": self.contested.len(),
                "stale_open": self.stale_open.len(),
                "total": self.total(),
            },
            "one_premise_away": self.one_premise_away,
            "fragile": self.fragile,
            "brittle": self.brittle,
            "contested": self.contested,
            "stale_open": self.stale_open,
            "boundary_is_derived": true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::ReviewState;
    use crate::project::assemble;
    use crate::project::reverse_dep_index_tests::{link_to, synth_finding};

    fn link_typed(target: &str, link_type: &str) -> crate::bundle::Link {
        let mut link = link_to(target);
        link.link_type = link_type.into();
        link
    }

    #[test]
    fn one_premise_away_needs_all_premises_established() {
        // established premise `a`; open `b` depends_on a → one premise away.
        let mut a = synth_finding(0, vec![]);
        a.flags.review_state = Some(ReviewState::Accepted);
        a.confidence.score = 0.9;
        let b = synth_finding(1, vec![link_typed(&a.id, "depends")]);
        let (a_id, b_id) = (a.id.clone(), b.id.clone());
        let mut project = assemble("bd", vec![], 0, 0, "test");
        project.findings = vec![a, b];

        let boundary = Boundary::derive(&project);
        assert_eq!(boundary.one_premise_away.len(), 1);
        assert_eq!(boundary.one_premise_away[0].finding, b_id);
        assert_eq!(boundary.one_premise_away[0].related, vec![a_id]);
    }

    #[test]
    fn open_premise_disqualifies_one_premise_away() {
        // premise `a` is itself open → `b` is not one-premise-away.
        let a = synth_finding(0, vec![]);
        let b = synth_finding(1, vec![link_typed(&a.id, "depends")]);
        let mut project = assemble("bd2", vec![], 0, 0, "test");
        project.findings = vec![a, b];
        let boundary = Boundary::derive(&project);
        assert!(boundary.one_premise_away.is_empty());
    }

    #[test]
    fn isolated_open_is_stale_open() {
        let a = synth_finding(0, vec![]);
        let a_id = a.id.clone();
        let mut project = assemble("bd3", vec![], 0, 0, "test");
        project.findings = vec![a];
        let boundary = Boundary::derive(&project);
        assert_eq!(boundary.stale_open.len(), 1);
        assert_eq!(boundary.stale_open[0].finding, a_id);
    }

    #[test]
    fn fragile_is_accepted_but_low_confidence() {
        let mut a = synth_finding(0, vec![]);
        a.flags.review_state = Some(ReviewState::Accepted);
        a.confidence.score = 0.4; // below FRAGILE_CONFIDENCE
        let mut project = assemble("bd4", vec![], 0, 0, "test");
        project.findings = vec![a];
        let boundary = Boundary::derive(&project);
        assert_eq!(boundary.fragile.len(), 1);
        assert!(boundary.stale_open.is_empty());
    }

    #[test]
    fn brittle_when_support_funnels_through_one_open_dependency() {
        // z depends_on a depends_on b, none established: z's whole support
        // funnels through a (a single point of failure that is itself open).
        let b = synth_finding(0, vec![]);
        let a = synth_finding(1, vec![link_typed(&b.id, "depends")]);
        let z = synth_finding(2, vec![link_typed(&a.id, "depends")]);
        let (a_id, z_id) = (a.id.clone(), z.id.clone());
        let mut project = assemble("brit", vec![], 0, 0, "test");
        project.findings = vec![b, a, z];

        let boundary = Boundary::derive(&project);
        let item = boundary
            .brittle
            .iter()
            .find(|i| i.finding == z_id)
            .expect("z is brittle");
        assert_eq!(item.dominator, a_id);
        assert_eq!(item.dominator_state, "open");
        assert_eq!(item.support_size, 2);
    }

    #[test]
    fn not_brittle_when_load_bearing_dependency_is_established() {
        let mut a = synth_finding(0, vec![]);
        a.flags.review_state = Some(ReviewState::Accepted);
        a.confidence.score = 0.9;
        let z = synth_finding(1, vec![link_typed(&a.id, "depends")]);
        let z_id = z.id.clone();
        let mut project = assemble("brit2", vec![], 0, 0, "test");
        project.findings = vec![a, z];
        let boundary = Boundary::derive(&project);
        // a is established → z is one-premise-away, not brittle.
        assert!(boundary.brittle.iter().all(|i| i.finding != z_id));
    }

    #[test]
    fn contradiction_pair_marks_both_contested() {
        let x = synth_finding(0, vec![]);
        let y = synth_finding(1, vec![link_typed(&x.id, "contradicts")]);
        let mut project = assemble("bd5", vec![], 0, 0, "test");
        project.findings = vec![x, y];
        let boundary = Boundary::derive(&project);
        assert_eq!(boundary.contested.len(), 2);
        // each endpoint names the other as related
        assert!(boundary.contested.iter().all(|i| i.related.len() == 1));
    }
}
