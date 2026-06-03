//! Belnap contextual status derived from support/refute provenance.
//!
//! Implements `docs/THEORY.md` Section 7 and Theorem 3
//! (status-provenance soundness).
//!
//! For each claim-context pair `(q, c)`, the substrate maintains
//! two provenance polynomials:
//!
//! - `support`: polynomial of derivations that support the claim.
//! - `refute`: polynomial of derivations that refute the claim.
//!
//! Belnap status is derived from non-empty support:
//!
//! ```text
//! T  if  supp(support) is nonempty  and  supp(refute) is empty
//! F  if  supp(support) is empty     and  supp(refute) is nonempty
//! B  if  supp(support) is nonempty  and  supp(refute) is nonempty
//! N  if  supp(support) is empty     and  supp(refute) is empty
//! ```
//!
//! Status is not truth. It is substrate-visible evidence polarity
//! under a review policy. Review policy decides which evidence is
//! admitted into `support` and `refute`. The substrate then
//! propagates consequences.
//!
//! ## Theorem 3 invariant
//!
//! If `status == T` and a retraction removes every monomial in
//! `support`, then after deterministic recomputation the status
//! cannot remain `T`. It becomes `N`, `F`, or another non-`T`
//! state under policy. This is "no zombie findings."
//!
//! This module enforces the invariant by deriving status from
//! support sets at every read. Status is never persisted
//! independently of the polynomials that justify it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::provenance_poly::ProvenancePoly;

/// Belnap four-valued status.
///
/// Status records evidence polarity. It is orthogonal to Bayesian
/// confidence (the strength of that evidence), per
/// `docs/THEORY.md` Section 2.1 and counterexample 11.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BelnapStatus {
    /// Neither supported nor refuted.
    None,
    /// Supported and not refuted.
    True,
    /// Refuted and not supported.
    False,
    /// Both supported and refuted.
    Both,
}

impl BelnapStatus {
    /// One-letter substrate-display form: N, T, F, B.
    #[must_use]
    pub fn letter(&self) -> char {
        match self {
            Self::None => 'N',
            Self::True => 'T',
            Self::False => 'F',
            Self::Both => 'B',
        }
    }

    /// Whether this status admits at least one supporting derivation.
    #[must_use]
    pub fn has_support(&self) -> bool {
        matches!(self, Self::True | Self::Both)
    }

    /// Whether this status admits at least one refuting derivation.
    #[must_use]
    pub fn has_refute(&self) -> bool {
        matches!(self, Self::False | Self::Both)
    }
}

impl std::fmt::Display for BelnapStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.letter())
    }
}

/// Support and refute provenance polynomials for a single
/// claim-context pair.
///
/// The status field is *derived*, not persisted. Reading
/// `derive_status()` computes the Belnap status from the current
/// support sets, which guarantees Theorem 3 by construction:
/// status cannot drift out of sync with the polynomials.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusProvenance {
    /// Polynomial of supporting derivations (`pi_T(q, c)` in the
    /// theory doc).
    #[serde(default)]
    pub support: ProvenancePoly,
    /// Polynomial of refuting derivations (`pi_F(q, c)` in the
    /// theory doc).
    #[serde(default)]
    pub refute: ProvenancePoly,
}

impl StatusProvenance {
    /// Empty: no supporting or refuting derivations recorded.
    /// Derives to `BelnapStatus::None`.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build with given support and refute polynomials.
    #[must_use]
    pub fn new(support: ProvenancePoly, refute: ProvenancePoly) -> Self {
        Self { support, refute }
    }

    /// Add a supporting derivation polynomial.
    pub fn add_support(&mut self, derivation: &ProvenancePoly) {
        self.support += derivation;
    }

    /// Add a refuting derivation polynomial.
    pub fn add_refute(&mut self, derivation: &ProvenancePoly) {
        self.refute += derivation;
    }

    /// Derive the Belnap status from the current support sets.
    ///
    /// This is the substrate status rule from
    /// `docs/THEORY.md` Section 7. Status is a function of the
    /// polynomials, not an independently-stored field, so Theorem 3
    /// holds by construction.
    pub fn derive_status(&self) -> BelnapStatus {
        let has_support = !self.support.is_zero();
        let has_refute = !self.refute.is_zero();
        match (has_support, has_refute) {
            (false, false) => BelnapStatus::None,
            (true, false) => BelnapStatus::True,
            (false, true) => BelnapStatus::False,
            (true, true) => BelnapStatus::Both,
        }
    }

    /// Retract a set of source/event identifiers from both
    /// support and refute polynomials.
    ///
    /// Operationally: any derivation path involving a retracted
    /// source is dropped. The remaining polynomials may then yield
    /// a different Belnap status under `derive_status()`.
    pub fn retract<S: AsRef<str>>(&self, retracted: &BTreeSet<S>) -> Self {
        Self {
            support: self.support.retract(retracted),
            refute: self.refute.retract(retracted),
        }
    }

    /// Whether the support set contains the given variable.
    pub fn support_contains(&self, var: &str) -> bool {
        self.support.support().contains(var)
    }

    /// Whether the refute set contains the given variable.
    pub fn refute_contains(&self, var: &str) -> bool {
        self.refute.support().contains(var)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn empty_derives_to_none() {
        assert_eq!(
            StatusProvenance::empty().derive_status(),
            BelnapStatus::None
        );
    }

    #[test]
    fn support_only_derives_to_t() {
        let sp = StatusProvenance::new(ProvenancePoly::singleton("p1"), ProvenancePoly::zero());
        assert_eq!(sp.derive_status(), BelnapStatus::True);
    }

    #[test]
    fn refute_only_derives_to_f() {
        let sp = StatusProvenance::new(ProvenancePoly::zero(), ProvenancePoly::singleton("r1"));
        assert_eq!(sp.derive_status(), BelnapStatus::False);
    }

    #[test]
    fn both_derives_to_b() {
        let sp = StatusProvenance::new(
            ProvenancePoly::singleton("p1"),
            ProvenancePoly::singleton("r1"),
        );
        assert_eq!(sp.derive_status(), BelnapStatus::Both);
    }

    #[test]
    fn theorem_3_t_with_full_retract_cannot_stay_t() {
        // sigma(q, c) = T because support has {p1*d3, r7} and refute is empty.
        let support = &(&ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3"))
            + &ProvenancePoly::singleton("r7");
        let sp = StatusProvenance::new(support, ProvenancePoly::zero());
        assert_eq!(sp.derive_status(), BelnapStatus::True);

        // Retract every variable in support: {p1, d3, r7}.
        let retracted = sp.retract(&vars(&["d3", "p1", "r7"]));
        // Theorem 3: status is no longer T.
        assert_ne!(retracted.derive_status(), BelnapStatus::True);
        // No refute, so it is N.
        assert_eq!(retracted.derive_status(), BelnapStatus::None);
    }

    #[test]
    fn theorem_3_t_with_partial_retract_keeps_t_if_alternate_path() {
        // Two derivation paths support the claim; only one is retracted.
        let support = &(&ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3"))
            + &(&ProvenancePoly::singleton("r7") * &ProvenancePoly::singleton("e2"));
        let sp = StatusProvenance::new(support, ProvenancePoly::zero());
        assert_eq!(sp.derive_status(), BelnapStatus::True);

        // Retract p1: the p1*d3 monomial drops; r7*e2 remains.
        let retracted = sp.retract(&vars(&["p1"]));
        assert_eq!(retracted.derive_status(), BelnapStatus::True);
        assert_eq!(retracted.support.term_count(), 1);
    }

    #[test]
    fn theorem_3_t_to_f_when_refute_remains() {
        // sigma starts at T (only supporting path).
        let mut sp = StatusProvenance::new(ProvenancePoly::singleton("p1"), ProvenancePoly::zero());
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        // Add a refuting derivation. Status becomes B.
        sp.add_refute(&ProvenancePoly::singleton("r1"));
        assert_eq!(sp.derive_status(), BelnapStatus::Both);
        // Retract p1: support empty, refute remains. Status: F.
        let retracted = sp.retract(&vars(&["p1"]));
        assert_eq!(retracted.derive_status(), BelnapStatus::False);
    }

    #[test]
    fn b_to_n_when_both_polynomials_retracted_to_zero() {
        let sp = StatusProvenance::new(
            ProvenancePoly::singleton("p1"),
            ProvenancePoly::singleton("r1"),
        );
        assert_eq!(sp.derive_status(), BelnapStatus::Both);
        let retracted = sp.retract(&vars(&["p1", "r1"]));
        assert_eq!(retracted.derive_status(), BelnapStatus::None);
    }

    #[test]
    fn add_support_accumulates() {
        let mut sp = StatusProvenance::empty();
        sp.add_support(&ProvenancePoly::singleton("p1"));
        sp.add_support(&ProvenancePoly::singleton("d3"));
        // Both terms recorded; status is T.
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.support.term_count(), 2);
    }

    #[test]
    fn add_refute_accumulates() {
        let mut sp = StatusProvenance::empty();
        sp.add_refute(&ProvenancePoly::singleton("r1"));
        sp.add_refute(&ProvenancePoly::singleton("r2"));
        assert_eq!(sp.derive_status(), BelnapStatus::False);
        assert_eq!(sp.refute.term_count(), 2);
    }

    #[test]
    fn belnap_status_predicates() {
        assert!(BelnapStatus::True.has_support());
        assert!(BelnapStatus::Both.has_support());
        assert!(!BelnapStatus::False.has_support());
        assert!(!BelnapStatus::None.has_support());

        assert!(BelnapStatus::False.has_refute());
        assert!(BelnapStatus::Both.has_refute());
        assert!(!BelnapStatus::True.has_refute());
        assert!(!BelnapStatus::None.has_refute());
    }

    #[test]
    fn belnap_status_letters() {
        assert_eq!(BelnapStatus::None.letter(), 'N');
        assert_eq!(BelnapStatus::True.letter(), 'T');
        assert_eq!(BelnapStatus::False.letter(), 'F');
        assert_eq!(BelnapStatus::Both.letter(), 'B');
    }

    #[test]
    fn serde_round_trip() {
        let sp = StatusProvenance::new(
            ProvenancePoly::singleton("p1"),
            ProvenancePoly::singleton("r1"),
        );
        let json = serde_json::to_string(&sp).expect("serialize");
        let restored: StatusProvenance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, sp);
        assert_eq!(restored.derive_status(), BelnapStatus::Both);
    }

    #[test]
    fn status_is_pure_function_of_polynomials() {
        // Theorem 3 holds by construction: status is derived,
        // never persisted independently. Any two StatusProvenance
        // instances with equal support and refute polynomials yield
        // the same status.
        let sp1 = StatusProvenance::new(ProvenancePoly::singleton("p1"), ProvenancePoly::zero());
        let sp2 = StatusProvenance::new(ProvenancePoly::singleton("p1"), ProvenancePoly::zero());
        assert_eq!(sp1.derive_status(), sp2.derive_status());
    }

    #[test]
    fn retract_does_not_invent_support() {
        // Theorem 2 + Theorem 3 composition: retraction never adds
        // derivations, so it cannot move N or F into T or B.
        let sp = StatusProvenance::new(ProvenancePoly::zero(), ProvenancePoly::singleton("r1"));
        assert_eq!(sp.derive_status(), BelnapStatus::False);
        let retracted = sp.retract(&vars(&["r1"]));
        // Cannot become T from F by retraction alone.
        assert_ne!(retracted.derive_status(), BelnapStatus::True);
        assert_eq!(retracted.derive_status(), BelnapStatus::None);
    }
}
