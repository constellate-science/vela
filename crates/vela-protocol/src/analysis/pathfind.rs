//! The golden-thread engine (memo §11.7): the shortest support/reduction
//! path between two findings over the typed [`FrontierGraph`].
//!
//! A "golden thread" is the chain of reasoning that connects one result to
//! another — the sequence of supports, dependencies, and verifier-homomorphism
//! discharges that carries trust from a premise to a conclusion. This module
//! is a pure breadth-first search over the typed claim graph: it follows only
//! the support-bearing edge kinds (in their stored `source → target`
//! direction, i.e. "this rests on that"), so the first path it finds is a
//! shortest one. It is a derived view — it reports the declared links, it does
//! not adjudicate them.

use serde::Serialize;
use std::collections::{HashMap, VecDeque};

use crate::frontier_graph::{Edge, EdgeKind, FrontierGraph};

/// The edge kinds that carry support or reduction. Following these from a
/// finding walks toward the premises it rests on (`A depends_on B`,
/// `A derived_from B`, `A discharges B`'s premise, `A improves/supports B`).
/// This is the default thread vocabulary; callers may pass a narrower set.
pub const SUPPORT_KINDS: [EdgeKind; 5] = [
    EdgeKind::Supports,
    EdgeKind::DependsOn,
    EdgeKind::DerivedFrom,
    EdgeKind::Discharges,
    EdgeKind::Improves,
];

/// One edge traversed on a path.
#[derive(Debug, Clone, Serialize)]
pub struct PathStep {
    pub from: String,
    pub to: String,
    pub kind: &'static str,
    pub note: String,
}

/// A shortest support/reduction path from `from` to `to`.
#[derive(Debug, Clone, Serialize)]
pub struct Path {
    pub from: String,
    pub to: String,
    /// Node ids in order, `from` first and `to` last.
    pub nodes: Vec<String>,
    /// The edges traversed, one per hop.
    pub steps: Vec<PathStep>,
    /// Number of edges (= `nodes.len() - 1`).
    pub hops: usize,
}

impl Path {
    /// Stable JSON for the web golden-thread surface and the CLI.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema": "vela.golden_thread.v0.1",
            "from": self.from,
            "to": self.to,
            "hops": self.hops,
            "nodes": self.nodes,
            "steps": self.steps,
            "derived": true,
        })
    }
}

/// Shortest directed path from `from` to `to` following only edges whose
/// kind is in `kinds`, in their stored `source → target` direction. BFS, so
/// the first path discovered is a shortest one (fewest hops). Returns `None`
/// when either endpoint is absent or no such path exists.
#[must_use]
pub fn shortest_path(
    graph: &FrontierGraph,
    from: &str,
    to: &str,
    kinds: &[EdgeKind],
) -> Option<Path> {
    if !graph.contains(from) || !graph.contains(to) {
        return None;
    }
    if from == to {
        return Some(Path {
            from: from.to_string(),
            to: to.to_string(),
            nodes: vec![from.to_string()],
            steps: vec![],
            hops: 0,
        });
    }

    // Directed adjacency restricted to the requested kinds, built once.
    let mut adj: HashMap<&str, Vec<&Edge>> = HashMap::new();
    for e in graph.all_edges() {
        if kinds.contains(&e.kind) {
            adj.entry(e.source.as_str()).or_default().push(e);
        }
    }

    // BFS, recording the edge that first reached each node so the path can
    // be reconstructed backward from `to`.
    let mut prev: HashMap<&str, &Edge> = HashMap::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    let mut seen: HashMap<&str, ()> = HashMap::new();
    queue.push_back(from);
    seen.insert(from, ());
    while let Some(node) = queue.pop_front() {
        for &e in adj.get(node).into_iter().flatten() {
            let next = e.target.as_str();
            if seen.contains_key(next) {
                continue;
            }
            seen.insert(next, ());
            prev.insert(next, e);
            if next == to {
                return Some(reconstruct(from, to, &prev));
            }
            queue.push_back(next);
        }
    }
    None
}

/// Walk the predecessor map backward from `to` to `from`, then reverse.
fn reconstruct(from: &str, to: &str, prev: &HashMap<&str, &Edge>) -> Path {
    let mut steps_rev: Vec<PathStep> = Vec::new();
    let mut nodes_rev: Vec<String> = vec![to.to_string()];
    let mut cur = to;
    while cur != from {
        let e = prev[cur];
        steps_rev.push(PathStep {
            from: e.source.clone(),
            to: e.target.clone(),
            kind: e.kind.as_str(),
            note: e.note.clone(),
        });
        nodes_rev.push(e.source.clone());
        cur = e.source.as_str();
    }
    nodes_rev.reverse();
    steps_rev.reverse();
    Path {
        from: from.to_string(),
        to: to.to_string(),
        hops: steps_rev.len(),
        nodes: nodes_rev,
        steps: steps_rev,
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
    fn finds_shortest_support_chain() {
        // c depends_on b depends_on a — the thread from c reaches a in 2 hops.
        let a = synth_finding(0, vec![]);
        let b = synth_finding(1, vec![link_typed(&a.id, "depends")]);
        let c = synth_finding(2, vec![link_typed(&b.id, "depends")]);
        let (a_id, c_id) = (a.id.clone(), c.id.clone());
        let mut project = assemble("pf", vec![], 0, 0, "test");
        project.findings = vec![a, b, c];

        let g = FrontierGraph::from_project(&project);
        let p = shortest_path(&g, &c_id, &a_id, &SUPPORT_KINDS).expect("path exists");
        assert_eq!(p.hops, 2);
        assert_eq!(p.nodes.first().unwrap(), &c_id);
        assert_eq!(p.nodes.last().unwrap(), &a_id);
        assert_eq!(p.steps.len(), 2);
    }

    #[test]
    fn no_path_when_unconnected_or_wrong_direction() {
        let a = synth_finding(0, vec![]);
        let b = synth_finding(1, vec![link_typed(&a.id, "depends")]);
        let (a_id, b_id) = (a.id.clone(), b.id.clone());
        let mut project = assemble("pf2", vec![], 0, 0, "test");
        project.findings = vec![a, b];

        let g = FrontierGraph::from_project(&project);
        // b depends_on a, so a → b is against the edge direction: no path.
        assert!(shortest_path(&g, &a_id, &b_id, &SUPPORT_KINDS).is_none());
        // Absent endpoint.
        assert!(shortest_path(&g, &a_id, "vf_absent", &SUPPORT_KINDS).is_none());
    }

    #[test]
    fn same_node_is_zero_hops() {
        let a = synth_finding(0, vec![]);
        let a_id = a.id.clone();
        let mut project = assemble("pf3", vec![], 0, 0, "test");
        project.findings = vec![a];
        let g = FrontierGraph::from_project(&project);
        let p = shortest_path(&g, &a_id, &a_id, &SUPPORT_KINDS).unwrap();
        assert_eq!(p.hops, 0);
        assert_eq!(p.nodes, vec![a_id]);
    }

    #[test]
    fn kind_filter_excludes_other_relations() {
        // c contradicts b depends_on a — a contradicts edge is not a support
        // edge, so no support thread from c to a.
        let a = synth_finding(0, vec![]);
        let b = synth_finding(1, vec![link_typed(&a.id, "depends")]);
        let c = synth_finding(2, vec![link_typed(&b.id, "contradicts")]);
        let (a_id, c_id) = (a.id.clone(), c.id.clone());
        let mut project = assemble("pf4", vec![], 0, 0, "test");
        project.findings = vec![a, b, c];
        let g = FrontierGraph::from_project(&project);
        assert!(shortest_path(&g, &c_id, &a_id, &SUPPORT_KINDS).is_none());
    }
}
