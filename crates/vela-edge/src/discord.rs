//! Discord assignment and frontier support.
//!
//! Implements `docs/THEORY.md` Section 4 and Theorem 4
//! (detector monotonicity implies frontier support monotonicity).
//!
//! Discord is the substrate's representation of where local
//! scientific state fails to assemble into stable global
//! knowledge. It comes in finitely many kinds. A frontier is the
//! set of contexts where any discord kind fires.
//!
//! ## What this module ships
//!
//! - [`DiscordKind`]: the enum of discord kinds named in the theory
//!   doc Section 4 (`Conflict`, `ConflictingConfidence`,
//!   `MissingOverlap`, ...).
//! - [`DiscordSet`]: a subset of `DiscordKind` (an element of the
//!   lattice `L = P(K)`).
//! - [`Detector`]: the trait that detector implementations satisfy.
//!   Each detector checks whether a single discord kind fires at a
//!   given context.
//! - [`DiscordAssignment`]: the context-indexed map `D_A` that
//!   records which discord kinds fire at each context.
//! - [`FrontierSupport`]: the set of contexts where `D_A(c)` is
//!   non-empty.
//!
//! ## What this module does NOT do
//!
//! Real detectors require the Atlas-as-presheaf primitive (target
//! v0.8). This module ships the algebraic substrate and the
//! Theorem 4 invariant test scaffolding. Domain-specific detector
//! implementations that read live Atlas state come in subsequent
//! cycles.
//!
//! For the purposes of Theorem 4, contexts are modeled as strings
//! and the refinement relation is supplied externally as a
//! [`ContextRefinement`] trait. This lets us test Theorem 4 over
//! arbitrary refinement orders without committing to a specific
//! context-category implementation.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// A discord kind from `docs/THEORY.md` Section 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscordKind {
    /// Polarity disagreement: support and refute both populated.
    Conflict,
    /// Confidence disagreement without polarity disagreement.
    ConflictingConfidence,
    /// Local sections without overlap evidence to relate them.
    MissingOverlap,
    /// Cross-context translation cannot be made consistent.
    TranslationFail,
    /// No evidence in scope for a context that requires it.
    EvidenceGap,
    /// A claimed result has not replicated under repeat conditions.
    ReplicationFail,
    /// Provenance polynomial is fragile under realistic retractions.
    ProvenanceFragile,
    /// Status diverges between Atlas projections that should agree.
    StatusDivergent,
    /// Methods differ in ways that prevent direct evidence
    /// comparison.
    MethodMismatch,
}

impl DiscordKind {
    /// All discord kinds, in ordering.
    pub const ALL: &'static [DiscordKind] = &[
        DiscordKind::Conflict,
        DiscordKind::ConflictingConfidence,
        DiscordKind::MissingOverlap,
        DiscordKind::TranslationFail,
        DiscordKind::EvidenceGap,
        DiscordKind::ReplicationFail,
        DiscordKind::ProvenanceFragile,
        DiscordKind::StatusDivergent,
        DiscordKind::MethodMismatch,
    ];

    /// Substrate-display string form (snake_case).
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Conflict => "conflict",
            Self::ConflictingConfidence => "conflicting_confidence",
            Self::MissingOverlap => "missing_overlap",
            Self::TranslationFail => "translation_fail",
            Self::EvidenceGap => "evidence_gap",
            Self::ReplicationFail => "replication_fail",
            Self::ProvenanceFragile => "provenance_fragile",
            Self::StatusDivergent => "status_divergent",
            Self::MethodMismatch => "method_mismatch",
        }
    }
}

impl std::fmt::Display for DiscordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A subset of `DiscordKind`. An element of the lattice `L = P(K)`.
///
/// Empty means agreement / no detected discord at this context.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DiscordSet {
    kinds: BTreeSet<DiscordKind>,
}

impl DiscordSet {
    /// Empty set: no discord detected.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Single-kind discord set.
    #[must_use]
    pub fn singleton(kind: DiscordKind) -> Self {
        let mut s = Self::default();
        s.kinds.insert(kind);
        s
    }

    /// Build from any iterable of kinds.
    pub fn from_kinds(kinds: impl IntoIterator<Item = DiscordKind>) -> Self {
        Self {
            kinds: kinds.into_iter().collect(),
        }
    }

    /// Whether this set is empty (no discord detected).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    /// Number of kinds in this set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    /// Whether `kind` is in this set.
    #[must_use]
    pub fn contains(&self, kind: DiscordKind) -> bool {
        self.kinds.contains(&kind)
    }

    /// Insert a kind. Returns `true` if newly inserted.
    pub fn insert(&mut self, kind: DiscordKind) -> bool {
        self.kinds.insert(kind)
    }

    /// Pointwise union (the lattice join).
    pub fn join(&self, other: &Self) -> Self {
        Self {
            kinds: self.kinds.union(&other.kinds).copied().collect(),
        }
    }

    /// Pointwise intersection (the lattice meet).
    pub fn meet(&self, other: &Self) -> Self {
        Self {
            kinds: self.kinds.intersection(&other.kinds).copied().collect(),
        }
    }

    /// Whether `self` is a subset of `other`.
    #[must_use]
    pub fn is_subset(&self, other: &Self) -> bool {
        self.kinds.is_subset(&other.kinds)
    }

    /// Iterate kinds in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = DiscordKind> + '_ {
        self.kinds.iter().copied()
    }
}

impl std::fmt::Display for DiscordSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.kinds.is_empty() {
            return write!(f, "{{}}");
        }
        write!(f, "{{")?;
        let mut first = true;
        for kind in &self.kinds {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "{kind}")?;
        }
        write!(f, "}}")
    }
}

/// Context identifier. Modeled as a string so this module does not
/// commit to a specific Atlas context-category implementation.
pub type ContextId = String;

/// External refinement relation: which contexts refine which.
///
/// `refines(c_prime, c)` returns true iff `c_prime -> c` in the
/// context category. The relation must be reflexive and transitive
/// for Theorem 4 to apply.
pub trait ContextRefinement {
    /// Whether `c_prime` refines `c` (i.e., `c_prime -> c`).
    fn refines(&self, c_prime: &str, c: &str) -> bool;
}

/// A detector for a single discord kind. Implementations check
/// whether the kind fires at a given context.
///
/// **Monotonicity obligation.** A detector is *monotone* if
///
/// ```text
/// c_prime -> c  and  fires(c_prime) = true  =>  fires(c) = true
/// ```
///
/// Theorem 4 only applies if every detector in the registry is
/// monotone. Detector authors must establish this property at
/// design time. The substrate cannot prove monotonicity for
/// arbitrary detector implementations; it can only assume the
/// property and report frontier support accordingly.
pub trait Detector {
    /// The discord kind this detector reports.
    fn kind(&self) -> DiscordKind;

    /// Whether the kind fires at `context`.
    fn fires(&self, context: &str) -> bool;
}

/// Discord assignment `D_A : C -> P(K)`.
///
/// In v0.83 this is a materialized map from context id to discord
/// set. Production builds will compute this lazily from a registry
/// of detectors against an Atlas; that wiring lands when the Atlas
/// presheaf does (target v0.8).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscordAssignment {
    by_context: BTreeMap<ContextId, DiscordSet>,
}

impl DiscordAssignment {
    /// Empty assignment: no discord at any context.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build from a registry of detectors evaluated over a finite
    /// set of contexts.
    ///
    /// Each detector is invoked once per context. If `fires`
    /// returns true, the corresponding kind is added to that
    /// context's discord set.
    pub fn build_from_detectors<D: Detector>(detectors: &[D], contexts: &[ContextId]) -> Self {
        let mut by_context = BTreeMap::new();
        for context in contexts {
            let mut set = DiscordSet::default();
            for detector in detectors {
                if detector.fires(context) {
                    set.insert(detector.kind());
                }
            }
            by_context.insert(context.clone(), set);
        }
        Self { by_context }
    }

    /// Set the discord set at a single context.
    pub fn set(&mut self, context: impl Into<ContextId>, kinds: DiscordSet) {
        self.by_context.insert(context.into(), kinds);
    }

    /// Get the discord set at a context, or empty if absent.
    pub fn get(&self, context: &str) -> DiscordSet {
        self.by_context.get(context).cloned().unwrap_or_default()
    }

    /// Iterate `(context, discord_set)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&ContextId, &DiscordSet)> {
        self.by_context.iter()
    }

    /// Frontier support: the set of contexts where any discord
    /// kind fires.
    pub fn frontier_support(&self) -> FrontierSupport {
        let contexts = self
            .by_context
            .iter()
            .filter(|(_, set)| !set.is_empty())
            .map(|(c, _)| c.clone())
            .collect();
        FrontierSupport { contexts }
    }
}

/// Frontier support: the set of contexts where the discord
/// assignment is non-empty.
///
/// Per Theorem 4, this set is upward closed under context
/// refinement when every detector in the underlying registry is
/// monotone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierSupport {
    contexts: BTreeSet<ContextId>,
}

impl FrontierSupport {
    /// Whether `context` is in the support.
    pub fn contains(&self, context: &str) -> bool {
        self.contexts.contains(context)
    }

    /// Number of contexts.
    pub fn len(&self) -> usize {
        self.contexts.len()
    }

    /// Whether the support is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contexts.is_empty()
    }

    /// Iterate contexts in canonical order.
    pub fn iter(&self) -> impl Iterator<Item = &ContextId> {
        self.contexts.iter()
    }

    /// Whether this support is upward closed under the given
    /// refinement relation.
    ///
    /// Returns `true` iff for every `c_prime` in the support and
    /// every `c` in `universe` with `c_prime -> c`, `c` is also in
    /// the support.
    ///
    /// This is the empirical Theorem 4 check: given a refinement
    /// relation and the set of contexts the assignment was built
    /// over, verify that the support set has the upward-closed
    /// property the theorem predicts.
    pub fn is_upward_closed<R: ContextRefinement>(
        &self,
        refinement: &R,
        universe: &[ContextId],
    ) -> bool {
        for c_prime in &self.contexts {
            for c in universe {
                if c_prime != c && refinement.refines(c_prime, c) && !self.contexts.contains(c) {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock context refinement: a poset given as a list of edges.
    /// The transitive closure is computed at construction.
    struct PosetRefinement {
        // Map from context to all contexts it refines (transitively).
        refines_map: BTreeMap<ContextId, BTreeSet<ContextId>>,
    }

    impl PosetRefinement {
        fn new(direct_edges: &[(&str, &str)], universe: &[&str]) -> Self {
            // direct_edges: (c_prime, c) means c_prime -> c (c_prime
            // is a refinement of c).
            let mut refines_map: BTreeMap<ContextId, BTreeSet<ContextId>> = BTreeMap::new();
            // Reflexive
            for c in universe {
                refines_map
                    .entry(c.to_string())
                    .or_default()
                    .insert(c.to_string());
            }
            // Direct edges
            for (cp, c) in direct_edges {
                refines_map
                    .entry(cp.to_string())
                    .or_default()
                    .insert(c.to_string());
            }
            // Transitive closure (Floyd-Warshall style)
            let all: Vec<ContextId> = universe.iter().map(|s| s.to_string()).collect();
            for k in &all {
                for i in &all {
                    for j in &all {
                        if refines_map.get(i).is_some_and(|s| s.contains(k))
                            && refines_map.get(k).is_some_and(|s| s.contains(j))
                        {
                            refines_map.entry(i.clone()).or_default().insert(j.clone());
                        }
                    }
                }
            }
            Self { refines_map }
        }
    }

    impl ContextRefinement for PosetRefinement {
        fn refines(&self, c_prime: &str, c: &str) -> bool {
            self.refines_map
                .get(c_prime)
                .is_some_and(|set| set.contains(c))
        }
    }

    /// A mock detector that fires on a fixed set of contexts.
    struct FixedDetector {
        kind: DiscordKind,
        fires_on: BTreeSet<String>,
    }

    impl FixedDetector {
        fn new(kind: DiscordKind, fires_on: &[&str]) -> Self {
            Self {
                kind,
                fires_on: fires_on.iter().map(|s| (*s).to_string()).collect(),
            }
        }
    }

    impl Detector for FixedDetector {
        fn kind(&self) -> DiscordKind {
            self.kind
        }
        fn fires(&self, context: &str) -> bool {
            self.fires_on.contains(context)
        }
    }

    fn ctxs(names: &[&str]) -> Vec<ContextId> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn discord_kinds_round_trip_serde() {
        for kind in DiscordKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: DiscordKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn discord_set_join_is_union() {
        let a = DiscordSet::from_kinds([DiscordKind::Conflict, DiscordKind::EvidenceGap]);
        let b = DiscordSet::from_kinds([DiscordKind::EvidenceGap, DiscordKind::MethodMismatch]);
        let joined = a.join(&b);
        assert_eq!(joined.len(), 3);
        assert!(joined.contains(DiscordKind::Conflict));
        assert!(joined.contains(DiscordKind::EvidenceGap));
        assert!(joined.contains(DiscordKind::MethodMismatch));
    }

    #[test]
    fn discord_set_meet_is_intersection() {
        let a = DiscordSet::from_kinds([DiscordKind::Conflict, DiscordKind::EvidenceGap]);
        let b = DiscordSet::from_kinds([DiscordKind::EvidenceGap, DiscordKind::MethodMismatch]);
        let met = a.meet(&b);
        assert_eq!(met.len(), 1);
        assert!(met.contains(DiscordKind::EvidenceGap));
    }

    #[test]
    fn empty_assignment_has_empty_support() {
        let assignment = DiscordAssignment::empty();
        assert!(assignment.frontier_support().is_empty());
    }

    #[test]
    fn theorem_4_monotone_detector_yields_upward_closed_support() {
        // Universe: c1 -> c2 -> c3.
        // c1 is the most refined, c3 is the broadest.
        let universe = ctxs(&["c1", "c2", "c3"]);
        let refinement = PosetRefinement::new(&[("c1", "c2"), ("c2", "c3")], &["c1", "c2", "c3"]);

        // A monotone detector that fires at c1 must fire at c2 and
        // c3 (upward propagation). Build that detector explicitly.
        let monotone_conflict = FixedDetector::new(DiscordKind::Conflict, &["c1", "c2", "c3"]);
        let assignment = DiscordAssignment::build_from_detectors(&[monotone_conflict], &universe);

        let support = assignment.frontier_support();
        assert!(support.is_upward_closed(&refinement, &universe));
        assert!(support.contains("c1"));
        assert!(support.contains("c2"));
        assert!(support.contains("c3"));
    }

    #[test]
    fn theorem_4_violation_when_detector_is_not_monotone() {
        // A non-monotone detector fires only at the refined context
        // c1 but not at the broader c2 or c3. This violates the
        // detector-design obligation, so frontier support is NOT
        // upward closed.
        let universe = ctxs(&["c1", "c2", "c3"]);
        let refinement = PosetRefinement::new(&[("c1", "c2"), ("c2", "c3")], &["c1", "c2", "c3"]);

        let buggy = FixedDetector::new(DiscordKind::Conflict, &["c1"]);
        let assignment = DiscordAssignment::build_from_detectors(&[buggy], &universe);
        let support = assignment.frontier_support();

        // The support is {c1}; it does NOT contain c2 or c3 even
        // though c1 -> c2 and c1 -> c3. Theorem 4 requires monotone
        // detectors; this one fails the obligation, so the
        // theorem's conclusion does not hold.
        assert!(!support.is_upward_closed(&refinement, &universe));
        assert!(support.contains("c1"));
        assert!(!support.contains("c2"));
        assert!(!support.contains("c3"));
    }

    #[test]
    fn theorem_4_holds_for_pointwise_union_of_monotone_detectors() {
        // Two monotone detectors. Their pointwise union should
        // produce an upward-closed support set.
        let universe = ctxs(&["c1", "c2", "c3", "c4"]);
        let refinement = PosetRefinement::new(
            &[("c1", "c2"), ("c2", "c4"), ("c3", "c4")],
            &["c1", "c2", "c3", "c4"],
        );
        // Monotone: fires at c1, c2, c4 (consistent with c1->c2->c4).
        let det1 = FixedDetector::new(DiscordKind::Conflict, &["c1", "c2", "c4"]);
        // Monotone: fires at c3, c4 (consistent with c3->c4).
        let det2 = FixedDetector::new(DiscordKind::EvidenceGap, &["c3", "c4"]);

        let assignment = DiscordAssignment::build_from_detectors(&[det1, det2], &universe);
        let support = assignment.frontier_support();
        assert!(support.is_upward_closed(&refinement, &universe));
        assert_eq!(support.len(), 4);
    }

    #[test]
    fn frontier_support_contains_only_nonempty_contexts() {
        let universe = ctxs(&["c1", "c2", "c3"]);
        let det = FixedDetector::new(DiscordKind::Conflict, &["c1", "c3"]);
        let assignment = DiscordAssignment::build_from_detectors(&[det], &universe);
        let support = assignment.frontier_support();
        assert!(support.contains("c1"));
        assert!(!support.contains("c2"));
        assert!(support.contains("c3"));
        assert_eq!(support.len(), 2);
    }

    #[test]
    fn manual_assignment_set_and_get() {
        let mut a = DiscordAssignment::empty();
        a.set("c1", DiscordSet::singleton(DiscordKind::ReplicationFail));
        assert_eq!(a.get("c1").len(), 1);
        assert!(a.get("c1").contains(DiscordKind::ReplicationFail));
        assert!(a.get("c2").is_empty());
    }

    #[test]
    fn poset_refinement_is_reflexive() {
        let r = PosetRefinement::new(&[("c1", "c2")], &["c1", "c2"]);
        assert!(r.refines("c1", "c1"));
        assert!(r.refines("c2", "c2"));
    }

    #[test]
    fn poset_refinement_is_transitive() {
        let r = PosetRefinement::new(&[("a", "b"), ("b", "c")], &["a", "b", "c"]);
        assert!(r.refines("a", "b"));
        assert!(r.refines("b", "c"));
        assert!(r.refines("a", "c"));
    }

    #[test]
    fn discord_kind_display() {
        assert_eq!(DiscordKind::Conflict.to_string(), "conflict");
        assert_eq!(
            DiscordKind::ConflictingConfidence.to_string(),
            "conflicting_confidence"
        );
        assert_eq!(DiscordKind::MethodMismatch.to_string(), "method_mismatch");
    }

    #[test]
    fn assignment_serde_round_trip() {
        let mut a = DiscordAssignment::empty();
        a.set(
            "c1",
            DiscordSet::from_kinds([DiscordKind::Conflict, DiscordKind::EvidenceGap]),
        );
        let json = serde_json::to_string(&a).unwrap();
        let back: DiscordAssignment = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);
    }
}
