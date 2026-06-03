//! Provenance polynomials in the semiring N[X].
//!
//! Implements the algebraic provenance type defined in
//! `docs/THEORY.md` Sections 2.2, 6, and Theorem 2.
//!
//! Each derived object carries a polynomial `p in N[X]` where `X`
//! is the set of source and event identifiers. The semiring
//! operations are:
//!
//! - **Multiplication.** Joint dependence: `p1 * d3` means a
//!   derivation needed both p1 and d3.
//! - **Addition.** Alternative derivation paths: `p1 * d3 + r7 * e2`
//!   means either path supports the derived object.
//! - **Coefficients.** Natural-number coefficients count distinct
//!   derivation events. `2 * p1 * d3` means the substrate observed
//!   two distinct derivations through the same source combination.
//!   Idempotent collapse is not assumed.
//!
//! ## Retraction
//!
//! For a set `Y` of retracted variables, the retraction
//! homomorphism `rho_Y` maps `x -> 0` for `x in Y` and `x -> x`
//! otherwise, extended homomorphically over `+` and `*`.
//!
//! Retraction is the load-bearing operation behind Theorem 2
//! (provenance retraction monotonicity): the support set of
//! `rho_Y(p)` is always a subset of `supp(p)`.
//!
//! ## What this module does NOT do
//!
//! This module is the abstract algebraic type and its operations.
//! It does NOT:
//!
//! - Wire into Carina event payloads (target v0.85+).
//! - Compute provenance from the event log (target v0.85+).
//! - Track support vs refute polynomials per claim-context pair
//!   (target v0.85+ via a separate `StatusProvenance` type).
//!
//! Those wirings ride on top of this primitive in later substrate
//! cycles.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::{Add, AddAssign, Mul, MulAssign};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A monomial is a finite multiset of variables (each variable
/// optionally raised to a positive exponent). Stored as a sorted
/// map so equality and ordering are deterministic and `serde` is
/// stable.
///
/// The empty monomial represents `1`.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Monomial {
    factors: BTreeMap<String, u32>,
}

impl Monomial {
    /// The empty monomial, representing the multiplicative identity `1`.
    #[must_use]
    pub fn one() -> Self {
        Self::default()
    }

    /// A single variable with exponent 1.
    pub fn singleton(var: impl Into<String>) -> Self {
        let mut m = Self::default();
        m.factors.insert(var.into(), 1);
        m
    }

    /// Build from `(variable, exponent)` pairs. Exponents must be
    /// strictly positive; pairs with exponent 0 are dropped.
    pub fn from_factors(factors: impl IntoIterator<Item = (impl Into<String>, u32)>) -> Self {
        let mut m = Self::default();
        for (var, exp) in factors {
            if exp > 0 {
                let entry = m.factors.entry(var.into()).or_insert(0);
                *entry = entry.saturating_add(exp);
            }
        }
        m
    }

    /// Variables appearing in this monomial (with exponents).
    pub fn factors(&self) -> &BTreeMap<String, u32> {
        &self.factors
    }

    /// Set of variable names appearing in this monomial.
    pub fn variables(&self) -> BTreeSet<String> {
        self.factors.keys().cloned().collect()
    }

    /// Whether `var` appears in this monomial with positive exponent.
    pub fn contains(&self, var: &str) -> bool {
        self.factors.contains_key(var)
    }

    /// Whether this is the empty (identity) monomial.
    #[must_use]
    pub fn is_one(&self) -> bool {
        self.factors.is_empty()
    }

    /// Multiply two monomials by adding exponents.
    pub fn mul(&self, other: &Self) -> Self {
        let mut result = self.clone();
        for (var, exp) in &other.factors {
            let entry = result.factors.entry(var.clone()).or_insert(0);
            *entry = entry.saturating_add(*exp);
        }
        result
    }
}

impl fmt::Display for Monomial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.factors.is_empty() {
            return write!(f, "1");
        }
        let mut first = true;
        for (var, exp) in &self.factors {
            if !first {
                write!(f, "*")?;
            }
            first = false;
            if *exp == 1 {
                write!(f, "{var}")?;
            } else {
                write!(f, "{var}^{exp}")?;
            }
        }
        Ok(())
    }
}

/// A provenance polynomial: a finite sum of monomials with
/// natural-number coefficients.
///
/// Stored in normal form: monomials with zero coefficient are
/// dropped; like terms are merged.
///
/// The empty polynomial is `0` (additive identity). The polynomial
/// `{Monomial::one() -> 1}` is the multiplicative identity `1`.
///
/// Custom serde: serialized as a sorted array of
/// `{"monomial": ..., "coefficient": n}` entries, since JSON
/// objects require string keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProvenancePoly {
    /// Map from monomial to its (positive) natural-number coefficient.
    /// Entries with zero coefficient are removed eagerly.
    terms: BTreeMap<Monomial, u64>,
}

#[derive(Serialize, Deserialize)]
struct PolyTerm {
    monomial: Monomial,
    coefficient: u64,
}

impl Serialize for ProvenancePoly {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let entries: Vec<PolyTerm> = self
            .terms
            .iter()
            .map(|(m, c)| PolyTerm {
                monomial: m.clone(),
                coefficient: *c,
            })
            .collect();
        entries.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProvenancePoly {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let entries: Vec<PolyTerm> = Vec::deserialize(deserializer)?;
        let mut poly = Self::default();
        for entry in entries {
            poly.insert_term(entry.monomial, entry.coefficient);
        }
        Ok(poly)
    }
}

impl ProvenancePoly {
    /// Additive identity: the polynomial `0`.
    #[must_use]
    pub fn zero() -> Self {
        Self::default()
    }

    /// Multiplicative identity: the polynomial `1`.
    #[must_use]
    pub fn one() -> Self {
        let mut p = Self::default();
        p.terms.insert(Monomial::one(), 1);
        p
    }

    /// Polynomial consisting of a single variable with coefficient 1.
    pub fn singleton(var: impl Into<String>) -> Self {
        let mut p = Self::default();
        p.terms.insert(Monomial::singleton(var), 1);
        p
    }

    /// Polynomial consisting of a single monomial with the given
    /// coefficient. If the coefficient is 0, returns `zero()`.
    pub fn from_monomial(monomial: Monomial, coefficient: u64) -> Self {
        let mut p = Self::default();
        if coefficient > 0 {
            p.terms.insert(monomial, coefficient);
        }
        p
    }

    /// Iterate `(monomial, coefficient)` in monomial-sorted order.
    pub fn terms(&self) -> impl Iterator<Item = (&Monomial, &u64)> {
        self.terms.iter()
    }

    /// Number of distinct monomials with positive coefficient.
    pub fn term_count(&self) -> usize {
        self.terms.len()
    }

    /// Whether this is the additive identity.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.terms.is_empty()
    }

    /// Coefficient of a specific monomial, or 0 if not present.
    pub fn coefficient(&self, monomial: &Monomial) -> u64 {
        self.terms.get(monomial).copied().unwrap_or(0)
    }

    /// Support: the set of variables appearing in any monomial with
    /// positive coefficient.
    ///
    /// This is what Theorem 2 bounds under retraction: for any
    /// retracted set `Y`, `support(retract(p, Y))` is a subset of
    /// `support(p)`.
    pub fn support(&self) -> BTreeSet<String> {
        let mut result = BTreeSet::new();
        for monomial in self.terms.keys() {
            for var in monomial.factors.keys() {
                result.insert(var.clone());
            }
        }
        result
    }

    /// Add a single term in place, merging like monomials.
    pub fn insert_term(&mut self, monomial: Monomial, coefficient: u64) {
        if coefficient == 0 {
            return;
        }
        let entry = self.terms.entry(monomial).or_insert(0);
        *entry = entry.saturating_add(coefficient);
    }

    /// Retract every variable in `retracted` by the substitution
    /// `x -> 0`. This is the homomorphism `rho_Y` from
    /// `docs/THEORY.md` Section 6.
    ///
    /// Operationally: any monomial containing a retracted variable
    /// is dropped. Monomials with no retracted variables are kept
    /// with their coefficients unchanged.
    pub fn retract<S: AsRef<str>>(&self, retracted: &BTreeSet<S>) -> Self {
        let retracted_set: BTreeSet<&str> = retracted.iter().map(AsRef::as_ref).collect();
        let mut result = Self::default();
        for (monomial, coefficient) in &self.terms {
            let touches_retracted = monomial
                .factors
                .keys()
                .any(|v| retracted_set.contains(v.as_str()));
            if !touches_retracted {
                result.terms.insert(monomial.clone(), *coefficient);
            }
        }
        result
    }
}

impl fmt::Display for ProvenancePoly {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.terms.is_empty() {
            return write!(f, "0");
        }
        let mut first = true;
        for (monomial, coefficient) in &self.terms {
            if !first {
                write!(f, " + ")?;
            }
            first = false;
            if *coefficient == 1 {
                write!(f, "{monomial}")?;
            } else if monomial.is_one() {
                write!(f, "{coefficient}")?;
            } else {
                write!(f, "{coefficient}*{monomial}")?;
            }
        }
        Ok(())
    }
}

// Operator overloads for ergonomics. Owned versions take ownership;
// reference versions are used in tests and examples.

impl Add<&ProvenancePoly> for &ProvenancePoly {
    type Output = ProvenancePoly;

    fn add(self, other: &ProvenancePoly) -> ProvenancePoly {
        let mut result = self.clone();
        for (monomial, coefficient) in &other.terms {
            result.insert_term(monomial.clone(), *coefficient);
        }
        result
    }
}

impl Add for ProvenancePoly {
    type Output = ProvenancePoly;

    fn add(self, other: ProvenancePoly) -> ProvenancePoly {
        &self + &other
    }
}

impl AddAssign<&ProvenancePoly> for ProvenancePoly {
    fn add_assign(&mut self, other: &ProvenancePoly) {
        for (monomial, coefficient) in &other.terms {
            self.insert_term(monomial.clone(), *coefficient);
        }
    }
}

impl Mul<&ProvenancePoly> for &ProvenancePoly {
    type Output = ProvenancePoly;

    fn mul(self, other: &ProvenancePoly) -> ProvenancePoly {
        let mut result = ProvenancePoly::zero();
        for (m1, c1) in &self.terms {
            for (m2, c2) in &other.terms {
                let product_monomial = m1.mul(m2);
                let product_coefficient = c1.saturating_mul(*c2);
                result.insert_term(product_monomial, product_coefficient);
            }
        }
        result
    }
}

impl Mul for ProvenancePoly {
    type Output = ProvenancePoly;

    fn mul(self, other: ProvenancePoly) -> ProvenancePoly {
        &self * &other
    }
}

impl MulAssign<&ProvenancePoly> for ProvenancePoly {
    fn mul_assign(&mut self, other: &ProvenancePoly) {
        *self = &*self * other;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn zero_is_additive_identity() {
        let p = ProvenancePoly::singleton("p1");
        let zero = ProvenancePoly::zero();
        assert_eq!(&p + &zero, p);
        assert_eq!(&zero + &p, p);
    }

    #[test]
    fn one_is_multiplicative_identity() {
        let p = ProvenancePoly::singleton("p1");
        let one = ProvenancePoly::one();
        assert_eq!(&p * &one, p);
        assert_eq!(&one * &p, p);
    }

    #[test]
    fn multiplication_combines_factors() {
        let p1 = ProvenancePoly::singleton("p1");
        let d3 = ProvenancePoly::singleton("d3");
        let product = &p1 * &d3;
        // p1 * d3 is a single monomial with coefficient 1
        assert_eq!(product.term_count(), 1);
        assert_eq!(product.support(), vars(&["d3", "p1"]));
        assert_eq!(format!("{product}"), "d3*p1");
    }

    #[test]
    fn addition_records_alternative_paths() {
        // p1*d3 + r7*e2
        let path1 = &ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3");
        let path2 = &ProvenancePoly::singleton("r7") * &ProvenancePoly::singleton("e2");
        let combined = &path1 + &path2;
        assert_eq!(combined.term_count(), 2);
        assert_eq!(combined.support(), vars(&["d3", "e2", "p1", "r7"]));
    }

    #[test]
    fn coefficient_counts_distinct_derivations() {
        // Two reviewers independently derive the same finding through p1*d3.
        let derivation = &ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3");
        let combined = &derivation + &derivation;
        assert_eq!(combined.term_count(), 1);
        let key = Monomial::from_factors([("d3", 1u32), ("p1", 1)]);
        assert_eq!(combined.coefficient(&key), 2);
        // Idempotent collapse is NOT assumed: p + p != p.
        assert_ne!(combined, derivation);
    }

    #[test]
    fn theorem_2_retraction_support_is_subset() {
        // p = p1*d3 + r7*e2
        let p = &(&ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3"))
            + &(&ProvenancePoly::singleton("r7") * &ProvenancePoly::singleton("e2"));

        let original_support = p.support();
        // Retract p1
        let retracted = p.retract(&vars(&["p1"]));
        let retracted_support = retracted.support();
        // Theorem 2: supp(rho_Y(p)) is a subset of supp(p)
        assert!(retracted_support.is_subset(&original_support));
    }

    #[test]
    fn theorem_2_monomials_with_retracted_var_are_deleted() {
        let p = &(&ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3"))
            + &(&ProvenancePoly::singleton("r7") * &ProvenancePoly::singleton("e2"));

        let retracted = p.retract(&vars(&["p1"]));
        // The p1*d3 monomial should be gone; r7*e2 remains.
        assert_eq!(retracted.term_count(), 1);
        assert_eq!(retracted.support(), vars(&["e2", "r7"]));
        // The p1*d3 monomial coefficient is now 0.
        let p1d3 = Monomial::from_factors([("d3", 1u32), ("p1", 1)]);
        assert_eq!(retracted.coefficient(&p1d3), 0);
        // The r7*e2 monomial coefficient is unchanged.
        let r7e2 = Monomial::from_factors([("e2", 1u32), ("r7", 1)]);
        assert_eq!(retracted.coefficient(&r7e2), 1);
    }

    #[test]
    fn theorem_2_monomials_without_retracted_var_are_unchanged() {
        // p = 2*p1*d3 + r7
        let mut p = ProvenancePoly::zero();
        p.insert_term(Monomial::from_factors([("p1", 1u32), ("d3", 1)]), 2);
        p.insert_term(Monomial::singleton("r7"), 1);

        let retracted = p.retract(&vars(&["p1"]));
        // The 2*p1*d3 monomial is dropped; r7 remains with coefficient 1.
        assert_eq!(retracted.term_count(), 1);
        assert_eq!(retracted.coefficient(&Monomial::singleton("r7")), 1);
    }

    #[test]
    fn theorem_2_no_new_monomials_after_retraction() {
        // Build a complex polynomial: 3*p1*d3 + 2*p1*d3*e2 + r7
        let mut p = ProvenancePoly::zero();
        p.insert_term(Monomial::from_factors([("p1", 1u32), ("d3", 1)]), 3);
        p.insert_term(
            Monomial::from_factors([("p1", 1u32), ("d3", 1), ("e2", 1)]),
            2,
        );
        p.insert_term(Monomial::singleton("r7"), 1);

        let original_monomials: BTreeSet<Monomial> = p.terms.keys().cloned().collect();
        let retracted = p.retract(&vars(&["p1"]));
        let retracted_monomials: BTreeSet<Monomial> = retracted.terms.keys().cloned().collect();

        // Every retracted monomial must already be in the original
        // (no new monomials introduced by substitution).
        assert!(retracted_monomials.is_subset(&original_monomials));
    }

    #[test]
    fn retract_empty_set_is_identity() {
        let p = &(&ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3"))
            + &(&ProvenancePoly::singleton("r7") * &ProvenancePoly::singleton("e2"));
        let retracted = p.retract(&BTreeSet::<String>::new());
        assert_eq!(retracted, p);
    }

    #[test]
    fn retract_all_support_yields_zero() {
        let p = &(&ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3"))
            + &(&ProvenancePoly::singleton("r7") * &ProvenancePoly::singleton("e2"));
        let retracted = p.retract(&vars(&["d3", "e2", "p1", "r7"]));
        assert!(retracted.is_zero());
    }

    #[test]
    fn retract_is_idempotent() {
        let p = &(&ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3"))
            + &(&ProvenancePoly::singleton("r7") * &ProvenancePoly::singleton("e2"));
        let once = p.retract(&vars(&["p1"]));
        let twice = once.retract(&vars(&["p1"]));
        assert_eq!(once, twice);
    }

    #[test]
    fn retract_is_homomorphism_over_addition() {
        // rho(p + q) == rho(p) + rho(q)
        let p = &ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3");
        let q = &ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("e2");
        let retracted_combined = (&p + &q).retract(&vars(&["p1"]));
        let combined_retracted = &p.retract(&vars(&["p1"])) + &q.retract(&vars(&["p1"]));
        assert_eq!(retracted_combined, combined_retracted);
    }

    #[test]
    fn retract_is_homomorphism_over_multiplication() {
        // rho(p * q) == rho(p) * rho(q)
        let p = ProvenancePoly::singleton("p1");
        let q = ProvenancePoly::singleton("d3");
        let retracted_product = (&p * &q).retract(&vars(&["p1"]));
        let product_retracted = &p.retract(&vars(&["p1"])) * &q.retract(&vars(&["p1"]));
        assert_eq!(retracted_product, product_retracted);
    }

    #[test]
    fn display_renders_canonical_form() {
        // 2*p1*d3 + r7
        let mut p = ProvenancePoly::zero();
        p.insert_term(Monomial::from_factors([("p1", 1u32), ("d3", 1)]), 2);
        p.insert_term(Monomial::singleton("r7"), 1);
        // Monomials are sorted alphabetically by their first variable name:
        // d3*p1 (sorts before r7), then r7.
        assert_eq!(format!("{p}"), "2*d3*p1 + r7");
    }

    #[test]
    fn distributivity_holds() {
        // p * (q + r) = p*q + p*r
        let p = ProvenancePoly::singleton("p1");
        let q = ProvenancePoly::singleton("d3");
        let r = ProvenancePoly::singleton("e2");
        let lhs = &p * &(&q + &r);
        let rhs = &(&p * &q) + &(&p * &r);
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn associativity_of_addition() {
        let p = ProvenancePoly::singleton("p1");
        let q = ProvenancePoly::singleton("d3");
        let r = ProvenancePoly::singleton("e2");
        assert_eq!(&(&p + &q) + &r, &p + &(&q + &r));
    }

    #[test]
    fn commutativity_of_addition() {
        let p = ProvenancePoly::singleton("p1");
        let q = ProvenancePoly::singleton("d3");
        assert_eq!(&p + &q, &q + &p);
    }

    #[test]
    fn associativity_of_multiplication() {
        let p = ProvenancePoly::singleton("p1");
        let q = ProvenancePoly::singleton("d3");
        let r = ProvenancePoly::singleton("e2");
        assert_eq!(&(&p * &q) * &r, &p * &(&q * &r));
    }

    #[test]
    fn commutativity_of_multiplication() {
        let p = ProvenancePoly::singleton("p1");
        let q = ProvenancePoly::singleton("d3");
        assert_eq!(&p * &q, &q * &p);
    }

    #[test]
    fn serde_round_trip() {
        let p = &(&ProvenancePoly::singleton("p1") * &ProvenancePoly::singleton("d3"))
            + &(&ProvenancePoly::singleton("r7") * &ProvenancePoly::singleton("e2"));
        let json = serde_json::to_string(&p).expect("serialize");
        let restored: ProvenancePoly = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, p);
    }
}
