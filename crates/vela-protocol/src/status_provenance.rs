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

use crate::access_tier::AccessTier;
use crate::provenance_poly::ProvenancePoly;

/// Separator between a provenance variable and its visibility tag. `#` cannot
/// appear in a `vev_`/`vf_` id (`[a-z0-9_]`), so the split is unambiguous and
/// round-trips. A bare variable (no separator) is `Public` — so every
/// pre-existing polynomial is already correctly public-tagged at zero cost.
pub const VISIBILITY_SEP: char = '#';

/// Tag a provenance variable with the originating object's access tier. `Public`
/// is left bare (the canonical, unsuffixed form); `Restricted`/`Classified`
/// append `#restricted` / `#classified`. This is the ONLY place visibility
/// enters a variable, and it happens at build time, never mutating a stored
/// polynomial. The public projection is then a literal instance of the proven
/// retraction homomorphism (`docs/THEORY.md`, Theorem 3): "private memory is not
/// public truth" becomes a derived fact, not a slogan.
#[must_use]
pub fn tag_visibility(var: &str, tier: AccessTier) -> String {
    match tier {
        AccessTier::Public => var.to_string(),
        other => format!("{var}{VISIBILITY_SEP}{}", other.canonical()),
    }
}

/// The visibility tier carried by a (possibly tagged) variable. A bare variable
/// is `Public`; an unrecognized suffix is treated as the most-restrictive tier
/// (fail-closed — a malformed tag never leaks as public support).
#[must_use]
pub fn variable_tier(var: &str) -> AccessTier {
    match var.rsplit_once(VISIBILITY_SEP) {
        None => AccessTier::Public,
        Some((_, suffix)) => AccessTier::parse(suffix).unwrap_or(AccessTier::Classified),
    }
}

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

    /// The v2 graded status (frontier calculus): one bilattice point
    /// `(support_degree, opposition_degree)` derived from the SAME two
    /// polynomials by the kappa projection, with per-source confidence.
    ///
    /// Conservative extension of [`Self::derive_status`]: for every confidence
    /// map, `self.derive_graded_status(conf).corner() == self.derive_status()`,
    /// so the corner sublattice reproduces v1 Belnap exactly and v1 readers are
    /// unaffected. Like the Belnap status, this is derived, never persisted.
    /// Sources absent from `confidence` default to confidence 1.
    pub fn derive_graded_status(
        &self,
        confidence: &std::collections::BTreeMap<String, crate::frontier_calculus::Rational>,
    ) -> crate::frontier_calculus::BilatticePoint {
        crate::frontier_calculus::status_point(&self.support, &self.refute, confidence)
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

    /// Variables across support+refute tagged ABOVE `clearance` (the set a
    /// public/lower-clearance reader may not count).
    fn over_clearance_vars(&self, clearance: AccessTier) -> BTreeSet<String> {
        self.support
            .support()
            .into_iter()
            .chain(self.refute.support())
            .filter(|v| variable_tier(v) > clearance)
            .collect()
    }

    /// Project the support polynomial to what a reader at `clearance` may count:
    /// every monomial touching an over-clearance variable is dropped. This is a
    /// LITERAL instance of [`Self::retract`] (the proven homomorphism `rho_Y`),
    /// so its subset bound holds for free — there is nothing new to prove about
    /// the algebra. **The canonical `self.support` is never mutated**; visibility
    /// filtering happens only at projection time (auditability preserved). With
    /// `clearance = Public` this is the law's `State_public`; with `Classified`
    /// it returns the full support unchanged (`State_private`).
    #[must_use]
    pub fn derive_public_support(&self, clearance: AccessTier) -> ProvenancePoly {
        self.support.retract(&self.over_clearance_vars(clearance))
    }

    /// The refute analogue of [`Self::derive_public_support`].
    #[must_use]
    pub fn derive_public_refute(&self, clearance: AccessTier) -> ProvenancePoly {
        self.refute.retract(&self.over_clearance_vars(clearance))
    }

    /// The whole status-provenance projected to a clearance: both polynomials
    /// filtered of over-clearance variables. The public Belnap corner
    /// (`project_to_clearance(Public).derive_status()`) is exactly the law's
    /// public truth — a restricted-only-supported claim reads `N` publicly while
    /// a cleared reader sees `T`.
    #[must_use]
    pub fn project_to_clearance(&self, clearance: AccessTier) -> Self {
        let over = self.over_clearance_vars(clearance);
        Self {
            support: self.support.retract(&over),
            refute: self.refute.retract(&over),
        }
    }

    /// The graded (bilattice) status a reader at `clearance` derives — the
    /// visibility-scoped analogue of [`Self::derive_graded_status`]. Feeds the
    /// clearance-filtered support/refute polynomials into the same `status_point`
    /// evaluation, so the public graded corner differs from the private one
    /// exactly when a restricted derivation is the only thing holding a claim up.
    #[must_use]
    pub fn derive_public_graded_status(
        &self,
        clearance: AccessTier,
        confidence: &std::collections::BTreeMap<String, crate::frontier_calculus::Rational>,
    ) -> crate::frontier_calculus::BilatticePoint {
        crate::frontier_calculus::status_point(
            &self.derive_public_support(clearance),
            &self.derive_public_refute(clearance),
            confidence,
        )
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

    /// The v2 conservative-extension theorem: the corner of the graded status
    /// reproduces the v1 Belnap status for EVERY confidence map and every
    /// support/refute shape. v1 readers are provably unaffected.
    ///
    /// This is a fixture witness for a *machine-checked* theorem: the universal
    /// statement is proven in Lean as `graded_corner_conservative`
    /// (`lean/Vela/Frontier/FrontierCalculus.lean`, Theorem 20), over all polynomials and
    /// all positive confidence assignments — not just the cases enumerated here.
    #[test]
    fn graded_status_corner_is_conservative_over_v1() {
        use crate::frontier_calculus::Rational;
        let p = |s: &str| ProvenancePoly::singleton(s);
        let cases = [
            StatusProvenance::empty(),
            StatusProvenance::new(&p("a") + &p("b"), ProvenancePoly::zero()),
            StatusProvenance::new(ProvenancePoly::zero(), p("c")),
            StatusProvenance::new(p("a"), p("c")),
        ];
        let confs: [std::collections::BTreeMap<String, Rational>; 3] = [
            std::collections::BTreeMap::new(),
            [("a".to_string(), Rational::new(1, 2))].into(),
            [
                ("a".to_string(), Rational::new(1, 100)),
                ("c".to_string(), Rational::new(99, 100)),
            ]
            .into(),
        ];
        for sp in &cases {
            for conf in &confs {
                assert_eq!(
                    sp.derive_graded_status(conf).corner(),
                    sp.derive_status(),
                    "graded corner must equal the v1 Belnap status"
                );
            }
        }
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

    // ── Visibility-scoped provenance: "private memory is not public truth" ──

    #[test]
    fn variable_tag_round_trips() {
        assert_eq!(tag_visibility("vev_x", AccessTier::Public), "vev_x");
        assert_eq!(
            tag_visibility("vev_x", AccessTier::Restricted),
            "vev_x#restricted"
        );
        assert_eq!(variable_tier("vev_x"), AccessTier::Public);
        assert_eq!(variable_tier("vev_x#restricted"), AccessTier::Restricted);
        assert_eq!(variable_tier("vev_x#classified"), AccessTier::Classified);
        // fail-closed: a malformed tag never leaks as public
        assert_eq!(variable_tier("vev_x#garbage"), AccessTier::Classified);
    }

    #[test]
    fn public_projection_drops_restricted_support_keeps_public() {
        let mut sp = StatusProvenance::empty();
        sp.add_support(&ProvenancePoly::singleton(tag_visibility(
            "vev_pub",
            AccessTier::Public,
        )));
        sp.add_support(&ProvenancePoly::singleton(tag_visibility(
            "vev_priv",
            AccessTier::Restricted,
        )));

        // Public reader: the restricted derivation is projected OUT.
        let pubs = sp.derive_public_support(AccessTier::Public).support();
        assert!(pubs.contains("vev_pub"));
        assert!(!pubs.iter().any(|v| v.starts_with("vev_priv")));

        // Classified reader: the full support set is visible.
        let clss = sp.derive_public_support(AccessTier::Classified).support();
        assert!(clss.iter().any(|v| v.starts_with("vev_priv")));

        // The canonical stored support is NEVER mutated (auditability).
        assert_eq!(sp.support.support().len(), 2);
    }

    #[test]
    fn restricted_only_support_is_none_publicly_true_privately() {
        let mut sp = StatusProvenance::empty();
        sp.add_support(&ProvenancePoly::singleton(tag_visibility(
            "vev_priv",
            AccessTier::Restricted,
        )));
        // The law's State_public vs State_private: a claim held up only by a
        // private derivation reads N to the public, T to a cleared reader.
        assert_eq!(
            sp.project_to_clearance(AccessTier::Public).derive_status(),
            BelnapStatus::None
        );
        assert_eq!(
            sp.project_to_clearance(AccessTier::Classified)
                .derive_status(),
            BelnapStatus::True
        );
    }

    #[test]
    fn public_graded_corner_differs_from_private_for_restricted_support() {
        let conf = std::collections::BTreeMap::new();
        let mut sp = StatusProvenance::empty();
        sp.add_support(&ProvenancePoly::singleton(tag_visibility(
            "vev_priv",
            AccessTier::Restricted,
        )));
        let public_corner = sp
            .derive_public_graded_status(AccessTier::Public, &conf)
            .corner();
        let private_corner = sp
            .derive_public_graded_status(AccessTier::Classified, &conf)
            .corner();
        assert_ne!(public_corner, private_corner);
        assert_eq!(public_corner, BelnapStatus::None);
        assert_eq!(private_corner, BelnapStatus::True);
    }
}
