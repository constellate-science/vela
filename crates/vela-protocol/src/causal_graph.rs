//! Dependency graph over the frontier's claim-to-claim link graph.
//!
//! Nodes are findings; edges come from the typed link graph. The
//! graph exposes the directed dependency structure (parents,
//! children) and its transitive closure (ancestors, descendants),
//! which the lens / blast-radius / atlas layers read to reason about
//! how findings depend on one another.
//!
//! Doctrine for this module:
//! - `depends`/`supports`: directed edge from the source finding
//!   *to* the target it relies on. A finding's parents are the
//!   findings it depends on (its evidence base); its children are the
//!   findings that build on it.
//! - `contradicts` is undirected and excluded from the dependency DAG.
//! - The substrate does not infer direction from prose; it only
//!   encodes what the link graph already declares.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use crate::project::Project;

/// v0.44: a directed acyclic graph over findings, derived from the
/// link graph. Edges point from a finding to its declared parent
/// (the finding it depends on / supports / cites as evidence).
///
/// We materialize parents and children both for fast lookup. The
/// graph is built lazily from a Project; updates require rebuilding.
#[derive(Debug, Clone)]
pub struct CausalGraph {
    /// Every finding id present in the source project.
    nodes: BTreeSet<String>,
    /// `parents[a]` = set of findings `a` directly depends on.
    parents: HashMap<String, BTreeSet<String>>,
    /// `children[a]` = set of findings that directly depend on `a`.
    children: HashMap<String, BTreeSet<String>>,
}

impl CausalGraph {
    /// Build the causal graph from a project's link graph. Walks
    /// every finding's `links` array; `depends` and `supports` link
    /// types contribute directed edges from source to target.
    /// `contradicts`, `extends`, and other link types are excluded —
    /// they don't encode causal dependency.
    #[must_use]
    pub fn from_project(project: &Project) -> Self {
        let mut nodes = BTreeSet::new();
        let mut parents: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut children: HashMap<String, BTreeSet<String>> = HashMap::new();

        for f in &project.findings {
            nodes.insert(f.id.clone());
            parents.entry(f.id.clone()).or_default();
            children.entry(f.id.clone()).or_default();
        }

        for f in &project.findings {
            for link in &f.links {
                if !matches!(link.link_type.as_str(), "depends" | "supports") {
                    continue;
                }
                // Cross-frontier resolution (T7/P2): a `vf_X@vfr_Y`
                // target resolves to the bare `vf_X` node when present —
                // which it is under `serve --frontiers <dir>`, where the
                // merge pulls every frontier's findings into one
                // Project. Content-addressed ids are globally unique, so
                // collapsing to the bare id is sound and lets the causal
                // closure compose across the former frontier boundary. A
                // target whose bare id is absent is still skipped.
                let resolved = crate::bundle::bare_finding_id(&link.target);
                if !nodes.contains(resolved) {
                    continue;
                }
                let resolved = resolved.to_string();
                parents
                    .entry(f.id.clone())
                    .or_default()
                    .insert(resolved.clone());
                children.entry(resolved).or_default().insert(f.id.clone());
            }
        }

        Self {
            nodes,
            parents,
            children,
        }
    }

    /// Number of nodes in the graph.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Number of directed edges in the graph.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.parents.values().map(BTreeSet::len).sum()
    }

    /// True iff the node exists in the graph.
    #[must_use]
    pub fn contains(&self, node: &str) -> bool {
        self.nodes.contains(node)
    }

    /// Direct parents of `node` (findings that `node` depends on).
    #[must_use]
    pub fn parents_of(&self, node: &str) -> impl Iterator<Item = &str> {
        self.parents
            .get(node)
            .into_iter()
            .flat_map(|s| s.iter().map(String::as_str))
    }

    /// Direct children of `node` (findings that depend on `node`).
    #[must_use]
    pub fn children_of(&self, node: &str) -> impl Iterator<Item = &str> {
        self.children
            .get(node)
            .into_iter()
            .flat_map(|s| s.iter().map(String::as_str))
    }

    /// All ancestors of `node` (transitive closure of parents).
    #[must_use]
    pub fn ancestors(&self, node: &str) -> HashSet<String> {
        let mut seen = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        if let Some(ps) = self.parents.get(node) {
            for p in ps {
                queue.push_back(p.clone());
            }
        }
        while let Some(n) = queue.pop_front() {
            if !seen.insert(n.clone()) {
                continue;
            }
            if let Some(ps) = self.parents.get(&n) {
                for p in ps {
                    if !seen.contains(p) {
                        queue.push_back(p.clone());
                    }
                }
            }
        }
        seen
    }

    /// All descendants of `node` (transitive closure of children).
    /// Includes `node` itself only if requested.
    #[must_use]
    pub fn descendants(&self, node: &str) -> HashSet<String> {
        let mut seen = HashSet::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        if let Some(cs) = self.children.get(node) {
            for c in cs {
                queue.push_back(c.clone());
            }
        }
        while let Some(n) = queue.pop_front() {
            if !seen.insert(n.clone()) {
                continue;
            }
            if let Some(cs) = self.children.get(&n) {
                for c in cs {
                    if !seen.contains(c) {
                        queue.push_back(c.clone());
                    }
                }
            }
        }
        seen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::*;
    use crate::project;

    fn finding(id: &str) -> FindingBundle {
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
                method: String::new(),
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            Conditions::default_for_test(),
            Confidence::raw(0.7, "test", 0.85),
            Provenance::default_for_test(),
            Flags::default(),
        );
        b.id = id.to_string();
        b
    }

    fn link(target: &str, kind: &str) -> Link {
        Link {
            target: target.into(),
            link_type: kind.into(),
            note: String::new(),
            inferred_by: "test".into(),
            created_at: String::new(),
            mechanism: None,
        }
    }

    impl Conditions {
        fn default_for_test() -> Self {
            Self {
                text: String::new(),
                duration: None,
            }
        }
    }
    impl Provenance {
        fn default_for_test() -> Self {
            Self {
                source_type: "published_paper".into(),
                doi: None,
                url: None,
                title: "Test".into(),
                authors: vec![],
                year: Some(2025),
                license: None,
                publisher: None,
                funders: vec![],
                extraction: Extraction::default(),
                review: None,
            }
        }
    }

    fn proj(findings: Vec<FindingBundle>) -> Project {
        project::assemble("test", findings, 1, 0, "test")
    }

    /// Cross-frontier resolution (T7/P2): a `vf_X@vfr_Y` `depends` link
    /// resolves to the bare node when present in a merged Project, so
    /// the causal closure composes across the former frontier boundary.
    #[test]
    fn cross_frontier_depends_resolves_in_merged_project() {
        let remote = finding("vf_remote");
        let mut local = finding("vf_local");
        local.links.push(link("vf_remote@vfr_other", "depends"));
        let g = CausalGraph::from_project(&proj(vec![remote, local]));
        assert!(g.ancestors("vf_local").contains("vf_remote"));
        assert!(g.descendants("vf_remote").contains("vf_local"));
    }

    #[test]
    fn graph_basic_construction() {
        let a = finding("vf_a");
        let mut b = finding("vf_b");
        b.links.push(link("vf_a", "depends"));
        let p = proj(vec![a, b]);
        let g = CausalGraph::from_project(&p);
        assert_eq!(g.node_count(), 2);
        assert_eq!(g.edge_count(), 1);
        assert!(g.parents_of("vf_b").any(|p| p == "vf_a"));
        assert!(g.children_of("vf_a").any(|c| c == "vf_b"));
    }

    #[test]
    fn descendants_transitive() {
        let a = finding("vf_a");
        let mut b = finding("vf_b");
        b.links.push(link("vf_a", "depends"));
        let mut c = finding("vf_c");
        c.links.push(link("vf_b", "depends"));
        let p = proj(vec![a, b, c]);
        let g = CausalGraph::from_project(&p);
        let desc = g.descendants("vf_a");
        assert!(desc.contains("vf_b"));
        assert!(desc.contains("vf_c"));
    }
}
