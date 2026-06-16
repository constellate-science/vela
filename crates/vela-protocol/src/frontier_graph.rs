//! T7: the typed claim-level edge layer — the FrontierGraph substrate.
//!
//! The full `.vela/graph/frontier-graph.v1.json` export is a broad
//! provenance graph (findings, sources, events, proposals, evidence
//! atoms — tens of thousands of nodes) built by the Python tooling.
//! This module is the *claim-level* view T7 reasons over: findings as
//! nodes (Claim nodes), and the typed relations between them
//! (`SUPPORTS / CONTRADICTS / DEPENDS_ON / DERIVED_FROM / IMPROVES /
//! GENERALIZES / SPECIALIZES / SUPERSEDES`, plus the legacy `EXTENDS`
//! and `REPLICATES`) as typed edges.
//!
//! It is a derived view, like [`crate::causal_graph::CausalGraph`] and
//! [`crate::project::ReverseDepIndex`]: built from the canonical
//! findings + links, never an authority. The CausalGraph keeps only
//! the causal subset (`depends`/`supports`); the FrontierGraph keeps
//! *every* typed relation so queries like "which contradictions are
//! open" and "what improves this result" are first-class.
//!
//! Cross-frontier (`vf_…@vfr_…`) targets are recorded as edges to an
//! external node id but are not resolved here — cross-frontier
//! traversal is a separate step (P2). Within a single merged Project,
//! though, every endpoint that exists is linked.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::Serialize;

use crate::project::Project;

/// The canonical T7 relation vocabulary. Each variant maps to one or
/// more `link_type` strings from [`crate::bundle::VALID_LINK_TYPES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Supports,
    Contradicts,
    DependsOn,
    DerivedFrom,
    Improves,
    Generalizes,
    Specializes,
    Supersedes,
    Extends,
    Replicates,
    /// A cross-domain transfer (`vtr_`): the source claim discharges a premise
    /// of the target claim via a kernel-verified verifier-homomorphism.
    Discharges,
}

impl EdgeKind {
    /// Map a stored `link_type` string to its canonical edge kind.
    /// `depends` is DEPENDS_ON and `synthesized_from` is DERIVED_FROM;
    /// unknown strings return `None` (the link is skipped from the
    /// typed graph rather than silently mis-categorized).
    #[must_use]
    pub fn from_link_type(link_type: &str) -> Option<Self> {
        Some(match link_type {
            "supports" => Self::Supports,
            "contradicts" => Self::Contradicts,
            "depends" => Self::DependsOn,
            "synthesized_from" | "derived_from" => Self::DerivedFrom,
            "improves" => Self::Improves,
            "generalizes" => Self::Generalizes,
            "specializes" => Self::Specializes,
            "supersedes" => Self::Supersedes,
            "extends" => Self::Extends,
            "replicates" => Self::Replicates,
            "discharges" => Self::Discharges,
            _ => return None,
        })
    }

    /// Lowercase canonical string for this edge kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Supports => "supports",
            Self::Contradicts => "contradicts",
            Self::DependsOn => "depends_on",
            Self::DerivedFrom => "derived_from",
            Self::Improves => "improves",
            Self::Generalizes => "generalizes",
            Self::Specializes => "specializes",
            Self::Supersedes => "supersedes",
            Self::Extends => "extends",
            Self::Replicates => "replicates",
            Self::Discharges => "discharges",
        }
    }

    /// Every edge kind, for enumeration and parsing.
    pub const ALL: [EdgeKind; 11] = [
        Self::Supports,
        Self::Contradicts,
        Self::DependsOn,
        Self::DerivedFrom,
        Self::Improves,
        Self::Generalizes,
        Self::Specializes,
        Self::Supersedes,
        Self::Extends,
        Self::Replicates,
        Self::Discharges,
    ];

    /// Parse from either the canonical string ([`Self::as_str`]) or a
    /// raw `link_type` ([`Self::from_link_type`]).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|k| k.as_str() == s)
            .or_else(|| Self::from_link_type(s))
    }
}

/// A typed, directed edge between two claim nodes. `target` may be a
/// cross-frontier id (`vf_…@vfr_…`); `target_in_frontier` records
/// whether the endpoint resolves to a node present in this graph.
#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
    pub note: String,
    pub target_in_frontier: bool,
}

/// The product-facing state of a finding (memo §6). A pure, derived
/// classification of a finding's review verdict + confidence into the
/// five words the platform speaks — never persisted, recomputed on read.
/// `Refuted`/`Contested` are live disagreement; `Fragile` is established
/// but thin; `Established` is accepted with real support; `Open` is the
/// default working state. State is orthogonal to the verifier gate: it
/// reads the *review* verdict, not the trust gate, and never collapses
/// to green/red (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingState {
    Open,
    Established,
    Refuted,
    Contested,
    Fragile,
}

impl FindingState {
    /// Lowercase canonical string.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Established => "established",
            Self::Refuted => "refuted",
            Self::Contested => "contested",
            Self::Fragile => "fragile",
        }
    }

    /// Derive a finding's state from its flags + confidence + verifier gate.
    /// Pure and total. The gate is the substrate's establishment signal on a
    /// verifier-gated frontier (most math findings carry no human "accept" but
    /// a passing frozen-verifier attachment), so it is folded in alongside the
    /// review verdict. Precedence, strongest disqualifier first:
    /// 1. an adversarial probe refuted the claim (`gate == Refuted`) → `Refuted`;
    /// 2. a rejected review verdict → `Refuted`;
    /// 3. a contested/needs-revision verdict or the legacy `contested` flag →
    ///    `Contested`;
    /// 4. the verifier gate passed, or the verdict is accepted → `Established`,
    ///    or `Fragile` when confidence sits below `FRAGILE_CONFIDENCE`;
    /// 5. everything else → `Open`.
    ///
    /// `gate` is `None` when no gate was computed (e.g. a graph built without
    /// attachment context); then only the review verdict drives the state.
    #[must_use]
    pub fn derive(
        flags: &crate::bundle::Flags,
        confidence: f64,
        gate: Option<crate::verifier_attachment::GateStatus>,
    ) -> Self {
        use crate::bundle::ReviewState;
        use crate::verifier_attachment::GateStatus;
        if gate == Some(GateStatus::Refuted) {
            return Self::Refuted;
        }
        match flags.review_state {
            Some(ReviewState::Rejected) => return Self::Refuted,
            Some(ReviewState::Contested) | Some(ReviewState::NeedsRevision) => {
                return Self::Contested;
            }
            None if flags.contested => return Self::Contested,
            _ => {}
        }
        let established =
            gate == Some(GateStatus::Verified) || flags.review_state == Some(ReviewState::Accepted);
        if established {
            if confidence < FRAGILE_CONFIDENCE {
                Self::Fragile
            } else {
                Self::Established
            }
        } else {
            Self::Open
        }
    }

    /// Verdict-only state derivation (no verifier gate). Equivalent to
    /// [`Self::derive`] with `gate = None`.
    #[must_use]
    pub fn of(flags: &crate::bundle::Flags, confidence: f64) -> Self {
        Self::derive(flags, confidence, None)
    }
}

/// An accepted finding below this confidence is `Fragile` rather than
/// `Established` — established support exists but rests on thin ground.
pub const FRAGILE_CONFIDENCE: f64 = 0.6;

/// A claim node: a finding plus the small slice of state the graph
/// queries report.
#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub id: String,
    pub label: String,
    pub contested: bool,
    pub gap: bool,
    pub confidence: f64,
    /// The product-facing finding state (§6), derived from the verdict +
    /// confidence at build time so the graph is self-describing for the
    /// map's state lens and the boundary query.
    pub state: FindingState,
}

/// A load-bearing dependency of a claim (GPT §11): a node every (or much) of
/// the claim's support funnels through. `weight` is how many support nodes
/// vanish if it is removed; `single_point_of_failure` is true when that is the
/// claim's entire support.
#[derive(Debug, Clone, Serialize)]
pub struct Dominator {
    pub node: String,
    pub label: String,
    /// The dominator's own finding state, when it is a finding in this graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<FindingState>,
    pub weight: usize,
    pub single_point_of_failure: bool,
}

/// The typed claim-level graph for one frontier (or one merged
/// multi-frontier Project).
#[derive(Debug, Clone, Default)]
pub struct FrontierGraph {
    nodes: BTreeMap<String, Node>,
    edges: Vec<Edge>,
}

impl FrontierGraph {
    /// Build the typed graph from a project's findings and links.
    /// Every finding becomes a node; every link whose type maps to a
    /// known [`EdgeKind`] becomes a typed edge.
    #[must_use]
    pub fn from_project(project: &Project) -> Self {
        // Index verifier attachments by target so each finding's state can
        // fold in its derived gate status — the establishment signal on a
        // verifier-gated frontier. The gate is recomputed (never a stored
        // flag), so the graph never trusts a persisted "verified" bit.
        let mut attachments_by_target: HashMap<&str, Vec<crate::verifier_attachment::VerifierAttachment>> =
            HashMap::new();
        for a in &project.verifier_attachments {
            attachments_by_target
                .entry(a.target.as_str())
                .or_default()
                .push(a.clone());
        }

        let mut nodes = BTreeMap::new();
        for f in &project.findings {
            let label = f.assertion.text.chars().take(120).collect::<String>();
            let gate = attachments_by_target.get(f.id.as_str()).map(|atts| {
                crate::verifier_attachment::derive_gate_status(
                    &crate::verifier_attachment::claim_digest(&f.assertion.text),
                    atts,
                )
                .status
            });
            nodes.insert(
                f.id.clone(),
                Node {
                    id: f.id.clone(),
                    label,
                    contested: f.flags.contested,
                    gap: f.flags.gap,
                    confidence: f.confidence.score,
                    state: FindingState::derive(&f.flags, f.confidence.score, gate),
                },
            );
        }

        let mut edges = Vec::new();
        for f in &project.findings {
            for link in &f.links {
                let Some(kind) = EdgeKind::from_link_type(&link.link_type) else {
                    continue;
                };
                // P2 cross-frontier resolution: a `vf_X@vfr_Y` target
                // resolves to the bare `vf_X` node when that node is
                // present — which it is under `serve --frontiers <dir>`,
                // since the merge pulls every frontier's findings into
                // one Project. Content-addressed ids are globally unique
                // by content, so collapsing to the bare id is sound and
                // lets typed traversal compose across frontiers. A
                // target whose bare id is absent keeps its raw form and
                // is flagged out-of-frontier.
                let bare = crate::bundle::bare_finding_id(&link.target);
                let (target, target_in_frontier) = if nodes.contains_key(bare) {
                    (bare.to_string(), true)
                } else {
                    (link.target.clone(), false)
                };
                edges.push(Edge {
                    source: f.id.clone(),
                    target,
                    kind,
                    note: link.note.clone(),
                    target_in_frontier,
                });
            }
        }

        Self { nodes, edges }
    }

    /// Number of claim nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of typed edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// True iff the node exists in the graph.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.nodes.contains_key(id)
    }

    /// All edges of a given kind.
    pub fn edges_of_kind(&self, kind: EdgeKind) -> impl Iterator<Item = &Edge> {
        self.edges.iter().filter(move |e| e.kind == kind)
    }

    /// All typed edges, in build order. The read accessor the boundary
    /// query and the path-finder traverse over (they live in sibling
    /// modules and cannot see the private field).
    #[must_use]
    pub fn all_edges(&self) -> &[Edge] {
        &self.edges
    }

    /// One node by id, if present.
    #[must_use]
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.get(id)
    }

    /// Every node, in stable id order.
    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    /// Per-edge-kind counts, for summaries.
    #[must_use]
    pub fn edge_kind_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for e in &self.edges {
            *counts.entry(e.kind.as_str()).or_default() += 1;
        }
        counts
    }

    /// Unordered, deduplicated contradiction pairs. Because
    /// `contradicts` is conceptually symmetric but stored as a directed
    /// link, an `A→B` and a `B→A` contradiction collapse to one pair.
    /// Endpoints are sorted so the pair is stable.
    #[must_use]
    pub fn contradiction_pairs(&self) -> Vec<(String, String)> {
        let mut pairs = BTreeSet::new();
        for e in self.edges_of_kind(EdgeKind::Contradicts) {
            let (a, b) = if e.source <= e.target {
                (e.source.clone(), e.target.clone())
            } else {
                (e.target.clone(), e.source.clone())
            };
            pairs.insert((a, b));
        }
        pairs.into_iter().collect()
    }

    /// The transitive closure reachable from `start` following only
    /// edges of one kind (e.g. the full `improves` or `supersedes`
    /// lineage downstream of a result). Excludes `start` itself.
    #[must_use]
    pub fn closure_of_kind(&self, start: &str, kind: EdgeKind) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![start.to_string()];
        while let Some(node) = stack.pop() {
            for e in self
                .edges
                .iter()
                .filter(|e| e.kind == kind && e.source == node)
            {
                if seen.insert(e.target.clone()) {
                    stack.push(e.target.clone());
                }
            }
        }
        seen
    }

    /// Breadth-first exploration outward from `start`, treating edges
    /// as undirected for reach, up to `max_hops`. Returns each reached
    /// node's hop distance and the edges wholly inside the explored
    /// subgraph. This is the engine for multi-hop "deep" queries — the
    /// counterpart to single-hop neighbor lookups.
    #[must_use]
    pub fn explore(&self, start: &str, max_hops: usize) -> Exploration {
        if !self.nodes.contains_key(start) {
            return Exploration::default();
        }
        // Build undirected adjacency once (O(E)) so the BFS costs
        // O(reached + incident edges), not a full edge rescan per
        // frontier node per hop.
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for e in &self.edges {
            adj.entry(e.source.as_str()).or_default().push(&e.target);
            adj.entry(e.target.as_str()).or_default().push(&e.source);
        }
        let mut node_hops: BTreeMap<String, usize> = BTreeMap::new();
        node_hops.insert(start.to_string(), 0);
        let mut frontier = vec![start.to_string()];
        for hop in 1..=max_hops {
            let mut next = Vec::new();
            for n in &frontier {
                for &neighbor in adj.get(n.as_str()).into_iter().flatten() {
                    if !node_hops.contains_key(neighbor) {
                        node_hops.insert(neighbor.to_string(), hop);
                        next.push(neighbor.to_string());
                    }
                }
            }
            if next.is_empty() {
                break;
            }
            frontier = next;
        }
        let edges = self
            .edges
            .iter()
            .filter(|e| node_hops.contains_key(&e.source) && node_hops.contains_key(&e.target))
            .cloned()
            .collect();
        Exploration { node_hops, edges }
    }

    /// Look up a node's label (assertion snippet), if present.
    #[must_use]
    pub fn label_of(&self, id: &str) -> Option<&str> {
        self.nodes.get(id).map(|n| n.label.as_str())
    }

    /// Support-reachable nodes from `start` following only `kinds`, in stored
    /// `source → target` direction (the premises `start` rests on), optionally
    /// removing one node from the graph. Excludes `start` itself.
    fn support_reach(
        &self,
        start: &str,
        kinds: &[EdgeKind],
        remove: Option<&str>,
    ) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![start.to_string()];
        while let Some(node) = stack.pop() {
            for e in &self.edges {
                if e.source != node || !kinds.contains(&e.kind) {
                    continue;
                }
                if remove == Some(e.target.as_str()) {
                    continue;
                }
                if e.target.as_str() == start {
                    continue;
                }
                if seen.insert(e.target.clone()) {
                    stack.push(e.target.clone());
                }
            }
        }
        seen
    }

    /// The support-graph dominators of a claim (GPT §11): the load-bearing
    /// dependencies its support funnels through. A node `d` (≠ `z`) is a
    /// dominator with `weight` = how many of `z`'s support-reachable nodes
    /// vanish if `d` is removed (including `d` itself). A dominator whose
    /// weight equals the full support size is a single point of failure —
    /// every support path out of `z` runs through it. Sorted by weight
    /// descending, then id. Pure; recomputed on read.
    #[must_use]
    pub fn support_dominators(&self, z: &str, kinds: &[EdgeKind]) -> Vec<Dominator> {
        let full = self.support_reach(z, kinds, None);
        if full.is_empty() {
            return vec![];
        }
        let total = full.len();
        let mut doms: Vec<Dominator> = full
            .iter()
            .map(|d| {
                let without = self.support_reach(z, kinds, Some(d));
                let weight = full.iter().filter(|n| !without.contains(*n)).count();
                Dominator {
                    node: d.clone(),
                    label: self.label_of(d).unwrap_or("").to_string(),
                    state: self.nodes.get(d).map(|n| n.state),
                    weight,
                    single_point_of_failure: weight == total && total >= 2,
                }
            })
            .collect();
        doms.sort_by(|a, b| b.weight.cmp(&a.weight).then(a.node.cmp(&b.node)));
        doms
    }

    /// Serialize to a stable claim-level JSON view. This is a focused
    /// `vela.frontier_graph.claims.v0.1` artifact — deliberately
    /// distinct from the broad provenance `vela.frontier_graph.v0.1`
    /// export so the two are never confused. Always marked derived.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let nodes: Vec<&Node> = self.nodes.values().collect();
        serde_json::json!({
            "schema": "vela.frontier_graph.claims.v0.1",
            "summary": {
                "nodes": self.node_count(),
                "edges": self.edge_count(),
                "edge_kinds": self.edge_kind_counts(),
                "contradiction_pairs": self.contradiction_pairs().len(),
            },
            "nodes": nodes,
            "edges": self.edges,
            "claim_boundary": {
                "graph_is_derived": true,
                "edges_are_declared_links": true,
                "relations_are_candidates_not_adjudicated": true,
            },
        })
    }
}

/// Result of a multi-hop [`FrontierGraph::explore`]: each reached node
/// keyed to its hop distance, plus the edges inside the explored
/// subgraph.
#[derive(Debug, Clone, Default)]
pub struct Exploration {
    node_hops: BTreeMap<String, usize>,
    pub edges: Vec<Edge>,
}

impl Exploration {
    /// Total nodes reached (including the start node at hop 0).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.node_hops.len()
    }

    /// The greatest hop distance reached.
    #[must_use]
    pub fn max_hop(&self) -> usize {
        self.node_hops.values().copied().max().unwrap_or(0)
    }

    /// Sorted node ids at exactly `hop` distance from the start.
    #[must_use]
    pub fn nodes_at(&self, hop: usize) -> Vec<&str> {
        self.node_hops
            .iter()
            .filter(|(_, h)| **h == hop)
            .map(|(id, _)| id.as_str())
            .collect()
    }

    /// Per-edge-kind counts within the explored subgraph.
    #[must_use]
    pub fn edge_kind_counts(&self) -> BTreeMap<&'static str, usize> {
        let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
        for e in &self.edges {
            *counts.entry(e.kind.as_str()).or_default() += 1;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::assemble;
    use crate::project::reverse_dep_index_tests::{link_to, synth_finding};

    fn link_typed(target: &str, link_type: &str) -> crate::bundle::Link {
        let mut link = link_to(target);
        link.link_type = link_type.into();
        link
    }

    #[test]
    fn every_valid_link_type_maps_to_an_edge_kind() {
        // Drift guard: a link type accepted by validation but unmapped
        // here would be silently dropped from the typed graph.
        for lt in crate::bundle::VALID_LINK_TYPES {
            assert!(
                EdgeKind::from_link_type(lt).is_some(),
                "VALID_LINK_TYPES has '{lt}' with no EdgeKind mapping"
            );
        }
    }

    #[test]
    fn maps_all_t7_link_types_to_edge_kinds() {
        for (s, k) in [
            ("supports", EdgeKind::Supports),
            ("contradicts", EdgeKind::Contradicts),
            ("depends", EdgeKind::DependsOn),
            ("synthesized_from", EdgeKind::DerivedFrom),
            ("derived_from", EdgeKind::DerivedFrom),
            ("improves", EdgeKind::Improves),
            ("generalizes", EdgeKind::Generalizes),
            ("specializes", EdgeKind::Specializes),
            ("supersedes", EdgeKind::Supersedes),
            ("extends", EdgeKind::Extends),
            ("replicates", EdgeKind::Replicates),
        ] {
            assert_eq!(EdgeKind::from_link_type(s), Some(k));
        }
        assert_eq!(EdgeKind::from_link_type("nonsense"), None);
    }

    #[test]
    fn builds_typed_nodes_and_edges_from_project() {
        let base = synth_finding(0, vec![]);
        let a = synth_finding(1, vec![link_typed(&base.id, "improves")]);
        let b = synth_finding(2, vec![link_typed(&a.id, "supersedes")]);
        let (base_id, a_id, b_id) = (base.id.clone(), a.id.clone(), b.id.clone());

        let mut project = assemble("fg", vec![], 0, 0, "test");
        project.findings = vec![base, a, b];

        let g = FrontierGraph::from_project(&project);
        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);
        assert!(g.contains(&base_id));

        let improves: Vec<&Edge> = g.edges_of_kind(EdgeKind::Improves).collect();
        assert_eq!(improves.len(), 1);
        assert_eq!(improves[0].source, a_id);
        assert_eq!(improves[0].target, base_id);
        assert!(improves[0].target_in_frontier);

        // a improves base, b supersedes a — closure of `improves` from
        // `a` reaches base; supersedes is a different kind.
        assert!(
            g.closure_of_kind(&a_id, EdgeKind::Improves)
                .contains(&base_id)
        );
        assert!(
            g.closure_of_kind(&b_id, EdgeKind::Supersedes)
                .contains(&a_id)
        );
    }

    #[test]
    fn explore_walks_multiple_hops_with_distances() {
        let base = synth_finding(0, vec![]);
        let a = synth_finding(1, vec![link_typed(&base.id, "improves")]);
        let b = synth_finding(2, vec![link_typed(&a.id, "supersedes")]);
        let (base_id, a_id, b_id) = (base.id.clone(), a.id.clone(), b.id.clone());
        let mut project = assemble("explore", vec![], 0, 0, "test");
        project.findings = vec![base, a, b];

        let g = FrontierGraph::from_project(&project);
        let ex = g.explore(&base_id, 2);
        assert_eq!(ex.node_count(), 3);
        assert_eq!(ex.node_hops[&base_id], 0);
        assert_eq!(ex.node_hops[&a_id], 1);
        assert_eq!(ex.node_hops[&b_id], 2);
        assert_eq!(ex.max_hop(), 2);
        assert_eq!(ex.nodes_at(1), vec![a_id.as_str()]);

        // Bounded by max_hops: depth 1 reaches only the immediate neighbor.
        assert_eq!(g.explore(&base_id, 1).node_count(), 2);
    }

    #[test]
    fn support_dominators_find_the_single_point_of_failure() {
        // z depends_on a depends_on b: every support path out of z funnels
        // through a, so a is a single point of failure (weight = full = 2);
        // b is a leaf (weight 1).
        let b = synth_finding(0, vec![]);
        let a = synth_finding(1, vec![link_typed(&b.id, "depends")]);
        let z = synth_finding(2, vec![link_typed(&a.id, "depends")]);
        let (a_id, b_id, z_id) = (a.id.clone(), b.id.clone(), z.id.clone());
        let mut project = assemble("dom", vec![], 0, 0, "test");
        project.findings = vec![b, a, z];

        let g = FrontierGraph::from_project(&project);
        let doms = g.support_dominators(&z_id, &[EdgeKind::DependsOn]);
        // a and b are both reachable; a dominates everything.
        let a_dom = doms.iter().find(|d| d.node == a_id).unwrap();
        let b_dom = doms.iter().find(|d| d.node == b_id).unwrap();
        assert_eq!(a_dom.weight, 2);
        assert!(a_dom.single_point_of_failure);
        assert_eq!(b_dom.weight, 1);
        assert!(!b_dom.single_point_of_failure);
        // top dominator is `a`.
        assert_eq!(doms.first().unwrap().node, a_id);
    }

    #[test]
    fn support_dominators_empty_for_unsupported_claim() {
        let z = synth_finding(0, vec![]);
        let z_id = z.id.clone();
        let mut project = assemble("dom2", vec![], 0, 0, "test");
        project.findings = vec![z];
        let g = FrontierGraph::from_project(&project);
        assert!(g.support_dominators(&z_id, &[EdgeKind::DependsOn]).is_empty());
    }

    #[test]
    fn contradiction_pairs_dedupe_symmetrically() {
        let x = synth_finding(0, vec![]);
        let y = synth_finding(1, vec![link_typed(&x.id, "contradicts")]);
        // x also contradicts y (the reverse direction): one pair, not two.
        let mut x = x;
        x.links.push(link_typed(&y.id, "contradicts"));
        let (x_id, y_id) = (x.id.clone(), y.id.clone());

        let mut project = assemble("fg-contra", vec![], 0, 0, "test");
        project.findings = vec![x, y];

        let g = FrontierGraph::from_project(&project);
        let pairs = g.contradiction_pairs();
        assert_eq!(pairs.len(), 1);
        let expected = if x_id <= y_id {
            (x_id, y_id)
        } else {
            (y_id, x_id)
        };
        assert_eq!(pairs[0], expected);
    }

    #[test]
    fn cross_frontier_target_is_flagged_out_of_frontier() {
        let f = synth_finding(
            0,
            vec![link_typed("vf_abcdef0123456789@vfr_remote", "supports")],
        );
        let mut project = assemble("fg-xf", vec![], 0, 0, "test");
        project.findings = vec![f];

        let g = FrontierGraph::from_project(&project);
        let edge = g.edges_of_kind(EdgeKind::Supports).next().unwrap();
        assert!(!edge.target_in_frontier);
    }

    #[test]
    fn cross_frontier_link_resolves_in_merged_project() {
        // Simulates `serve --frontiers <dir>`: the remote target's
        // finding is present in the merged Project, so a `@vfr_…` link
        // resolves to the bare node and composes for traversal (P2).
        let remote = synth_finding(0, vec![]);
        let cross_target = format!("{}@vfr_remote", remote.id);
        let local = synth_finding(1, vec![link_typed(&cross_target, "depends")]);
        let (remote_id, local_id) = (remote.id.clone(), local.id.clone());

        let mut project = assemble("fg-merge", vec![], 0, 0, "test");
        project.findings = vec![remote, local];

        let g = FrontierGraph::from_project(&project);
        let edge = g.edges_of_kind(EdgeKind::DependsOn).next().unwrap();
        assert!(edge.target_in_frontier, "bare id present → resolves");
        assert_eq!(edge.target, remote_id, "target rewritten to bare id");
        // Traversal now composes across the former frontier boundary.
        assert!(
            g.closure_of_kind(&local_id, EdgeKind::DependsOn)
                .contains(&remote_id)
        );
    }

    #[test]
    fn to_json_is_marked_derived_with_claim_boundary() {
        let project = assemble("fg-json", vec![], 0, 0, "test");
        let g = FrontierGraph::from_project(&project);
        let v = g.to_json();
        assert_eq!(v["schema"], "vela.frontier_graph.claims.v0.1");
        assert_eq!(v["claim_boundary"]["graph_is_derived"], true);
        assert_eq!(
            v["claim_boundary"]["relations_are_candidates_not_adjudicated"],
            true
        );
    }
}
