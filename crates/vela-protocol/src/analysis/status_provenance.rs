//! Belnap contextual status derived from support/refute provenance.
//!
//! Implements `docs/THEORY.md` Section 7 and Theorem 3
//! (status-provenance soundness).
//!
//! For each claim-context pair `(q, c)`, the substrate maintains two
//! provenance support sets:
//!
//! - `support`: the variable ids (source / event ids) that support the claim.
//! - `refute`: the variable ids that refute the claim.
//!
//! Belnap status is derived from non-empty support:
//!
//! ```text
//! T  if  support is nonempty  and  refute is empty
//! F  if  support is empty     and  refute is nonempty
//! B  if  support is nonempty  and  refute is nonempty
//! N  if  support is empty     and  refute is empty
//! ```
//!
//! Status is not truth. It is substrate-visible evidence polarity
//! under a review policy. Review policy decides which evidence is
//! admitted into `support` and `refute`. The substrate then
//! propagates consequences.
//!
//! ## Theorem 3 invariant
//!
//! If `status == T` and a retraction removes every supporting id, then
//! after deterministic recomputation the status cannot remain `T`. It
//! becomes `N`, `F`, or another non-`T` state under policy. This is
//! "no zombie findings."
//!
//! This module enforces the invariant by deriving status from the
//! support sets at every read. Status is never persisted independently
//! of the sets that justify it.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::access_tier::AccessTier;

/// Separator between a provenance variable and its visibility tag. `#` cannot
/// appear in a `vev_`/`vf_` id (`[a-z0-9_]`), so the split is unambiguous and
/// round-trips. A bare variable (no separator) is `Public` — so every
/// pre-existing support id is already correctly public-tagged at zero cost.
pub const VISIBILITY_SEP: char = '#';

/// Tag a provenance variable with the originating object's access tier. `Public`
/// is left bare (the canonical, unsuffixed form); `Restricted`/`Classified`
/// append `#restricted` / `#classified`. This is the ONLY place visibility
/// enters a variable, and it happens at build time, never mutating a stored
/// id. The public projection is then a literal instance of the proven
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

/// Support and refute provenance support sets for a single
/// claim-context pair.
///
/// The status field is *derived*, not persisted. Reading
/// `derive_status()` computes the Belnap status from the current
/// support sets, which guarantees Theorem 3 by construction:
/// status cannot drift out of sync with the sets.
///
/// A variable id sits in `support` iff some accepted event adds
/// supporting provenance for it and it has survived every retraction;
/// likewise for `refute`. The Belnap status depends only on whether the
/// two sets are non-empty.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusProvenance {
    /// Supporting source/event ids (`pi_T(q, c)` in the theory doc).
    #[serde(default)]
    pub support: BTreeSet<String>,
    /// Refuting source/event ids (`pi_F(q, c)` in the theory doc).
    #[serde(default)]
    pub refute: BTreeSet<String>,
}

impl StatusProvenance {
    /// Empty: no supporting or refuting ids recorded.
    /// Derives to `BelnapStatus::None`.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build with given support and refute id sets.
    #[must_use]
    pub fn new(support: BTreeSet<String>, refute: BTreeSet<String>) -> Self {
        Self { support, refute }
    }

    /// Add one supporting source/event id.
    pub fn add_support(&mut self, var: impl Into<String>) {
        self.support.insert(var.into());
    }

    /// Add one refuting source/event id.
    pub fn add_refute(&mut self, var: impl Into<String>) {
        self.refute.insert(var.into());
    }

    /// Derive the Belnap status from the current support sets.
    ///
    /// This is the substrate status rule from
    /// `docs/THEORY.md` Section 7. Status is a function of the support
    /// sets, not an independently-stored field, so Theorem 3 holds by
    /// construction.
    pub fn derive_status(&self) -> BelnapStatus {
        let has_support = !self.support.is_empty();
        let has_refute = !self.refute.is_empty();
        match (has_support, has_refute) {
            (false, false) => BelnapStatus::None,
            (true, false) => BelnapStatus::True,
            (false, true) => BelnapStatus::False,
            (true, true) => BelnapStatus::Both,
        }
    }

    /// Retract a set of source/event identifiers from both
    /// support and refute sets.
    ///
    /// Operationally: any supporting or refuting id that is retracted is
    /// dropped. The remaining sets may then yield a different Belnap
    /// status under `derive_status()`.
    pub fn retract<S: AsRef<str>>(&self, retracted: &BTreeSet<S>) -> Self {
        let drop: BTreeSet<&str> = retracted.iter().map(AsRef::as_ref).collect();
        let keep = |s: &BTreeSet<String>| -> BTreeSet<String> {
            s.iter()
                .filter(|v| !drop.contains(v.as_str()))
                .cloned()
                .collect()
        };
        Self {
            support: keep(&self.support),
            refute: keep(&self.refute),
        }
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
        let sp = StatusProvenance::new(vars(&["p1"]), BTreeSet::new());
        assert_eq!(sp.derive_status(), BelnapStatus::True);
    }

    #[test]
    fn refute_only_derives_to_f() {
        let sp = StatusProvenance::new(BTreeSet::new(), vars(&["r1"]));
        assert_eq!(sp.derive_status(), BelnapStatus::False);
    }

    #[test]
    fn both_derives_to_b() {
        let sp = StatusProvenance::new(vars(&["p1"]), vars(&["r1"]));
        assert_eq!(sp.derive_status(), BelnapStatus::Both);
    }

    #[test]
    fn theorem_3_t_with_full_retract_cannot_stay_t() {
        // sigma(q, c) = T because support has {p1, d3, r7} and refute is empty.
        let sp = StatusProvenance::new(vars(&["d3", "p1", "r7"]), BTreeSet::new());
        assert_eq!(sp.derive_status(), BelnapStatus::True);

        // Retract every supporting id: {p1, d3, r7}.
        let retracted = sp.retract(&vars(&["d3", "p1", "r7"]));
        // Theorem 3: status is no longer T.
        assert_ne!(retracted.derive_status(), BelnapStatus::True);
        // No refute, so it is N.
        assert_eq!(retracted.derive_status(), BelnapStatus::None);
    }

    #[test]
    fn theorem_3_t_with_partial_retract_keeps_t_if_alternate_path() {
        // Two supporting ids; only one is retracted.
        let sp = StatusProvenance::new(vars(&["p1", "r7"]), BTreeSet::new());
        assert_eq!(sp.derive_status(), BelnapStatus::True);

        // Retract p1: r7 remains.
        let retracted = sp.retract(&vars(&["p1"]));
        assert_eq!(retracted.derive_status(), BelnapStatus::True);
        assert_eq!(retracted.support.len(), 1);
    }

    #[test]
    fn theorem_3_t_to_f_when_refute_remains() {
        // sigma starts at T (only supporting path).
        let mut sp = StatusProvenance::new(vars(&["p1"]), BTreeSet::new());
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        // Add a refuting id. Status becomes B.
        sp.add_refute("r1");
        assert_eq!(sp.derive_status(), BelnapStatus::Both);
        // Retract p1: support empty, refute remains. Status: F.
        let retracted = sp.retract(&vars(&["p1"]));
        assert_eq!(retracted.derive_status(), BelnapStatus::False);
    }

    #[test]
    fn b_to_n_when_both_sets_retracted_to_empty() {
        let sp = StatusProvenance::new(vars(&["p1"]), vars(&["r1"]));
        assert_eq!(sp.derive_status(), BelnapStatus::Both);
        let retracted = sp.retract(&vars(&["p1", "r1"]));
        assert_eq!(retracted.derive_status(), BelnapStatus::None);
    }

    #[test]
    fn add_support_accumulates() {
        let mut sp = StatusProvenance::empty();
        sp.add_support("p1");
        sp.add_support("d3");
        // Both ids recorded; status is T.
        assert_eq!(sp.derive_status(), BelnapStatus::True);
        assert_eq!(sp.support.len(), 2);
    }

    #[test]
    fn add_refute_accumulates() {
        let mut sp = StatusProvenance::empty();
        sp.add_refute("r1");
        sp.add_refute("r2");
        assert_eq!(sp.derive_status(), BelnapStatus::False);
        assert_eq!(sp.refute.len(), 2);
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
        let sp = StatusProvenance::new(vars(&["p1"]), vars(&["r1"]));
        let json = serde_json::to_string(&sp).expect("serialize");
        let restored: StatusProvenance = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, sp);
        assert_eq!(restored.derive_status(), BelnapStatus::Both);
    }

    #[test]
    fn status_is_pure_function_of_support_sets() {
        // Theorem 3 holds by construction: status is derived,
        // never persisted independently. Any two StatusProvenance
        // instances with equal support and refute sets yield the same
        // status.
        let sp1 = StatusProvenance::new(vars(&["p1"]), BTreeSet::new());
        let sp2 = StatusProvenance::new(vars(&["p1"]), BTreeSet::new());
        assert_eq!(sp1.derive_status(), sp2.derive_status());
    }

    #[test]
    fn retract_does_not_invent_support() {
        // Theorem 2 + Theorem 3 composition: retraction never adds
        // ids, so it cannot move N or F into T or B.
        let sp = StatusProvenance::new(BTreeSet::new(), vars(&["r1"]));
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
}
