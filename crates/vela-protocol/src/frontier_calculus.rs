//! Frontier calculus v2 (live surface): the discount kappa and the graded
//! bilattice status that feed `vela claim state`. The load-bearing laws
//! (conservativity, and the kappa / context / transfer-closure properties) are
//! machine-checked in `lean/Vela/Frontier/FrontierCalculus.lean`, which is ground
//! truth; this module is the executable Rust reading of that calculus.
//!
//! The kernel stores ONE free object, the provenance polynomial in N[X]
//! ([`crate::provenance_poly::ProvenancePoly`]), and derives the finding status by
//! the unique homomorphism `Eval_v` into the Viterbi confidence semiring
//! (Green-Karvounarakis-Tannen, PODS 2007). v1's Belnap status is the corner
//! sublattice of the graded `[0,1] ⊙ [0,1]` bilattice (Avron's representation
//! theorem, 1996); thresholding each coordinate recovers v1 exactly, so this is a
//! *conservative extension*: a derived read, no protocol change.
//!
//! Determinism: confidence scalars are exact [`Rational`]s (matching the
//! reference's `Fraction`), never floats, so the Rust and Python projections agree
//! exactly.
//!
//! Scope: this module is just the kappa/bilattice STATUS read ([`status_point`] →
//! `status_provenance` → `evidence_diff` → `vela claim state`). The full
//! provenance-semiring calculus (the other named semirings, the cost / existence /
//! count projections, the admission and replay-tier boundaries) is specified in the
//! Lean kernel and the Python reference, not carried in production Rust.

use crate::provenance_poly::ProvenancePoly;
use crate::status_provenance::BelnapStatus;
use std::cmp::Ordering;
use std::collections::BTreeMap;

// ===========================================================================
// Exact non-negative rationals (confidence scalars)
// ===========================================================================

/// An exact rational `num/den` in lowest terms with `den > 0`. `i128` is ample
/// for the shallow derivation chains the calculus evaluates (a depth-38 chain
/// at denominator 10 still fits); deeper chains are not a realistic fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rational {
    num: i128,
    den: i128,
}

fn gcd(a: i128, b: i128) -> i128 {
    let (mut a, mut b) = (a.abs(), b.abs());
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.max(1)
}

impl Rational {
    /// Reduce to lowest terms with a positive denominator.
    pub fn new(num: i128, den: i128) -> Self {
        assert!(den != 0, "rational with zero denominator");
        let sign = if (num < 0) ^ (den < 0) { -1 } else { 1 };
        let g = gcd(num, den);
        Rational {
            num: sign * (num.abs() / g),
            den: den.abs() / g,
        }
    }
    pub fn zero() -> Self {
        Rational { num: 0, den: 1 }
    }
    pub fn one() -> Self {
        Rational { num: 1, den: 1 }
    }
    pub fn numer(&self) -> i128 {
        self.num
    }
    pub fn denom(&self) -> i128 {
        self.den
    }
    pub fn to_f64(&self) -> f64 {
        self.num as f64 / self.den as f64
    }
    pub fn add(&self, o: &Rational) -> Rational {
        Rational::new(self.num * o.den + o.num * self.den, self.den * o.den)
    }
    pub fn sub(&self, o: &Rational) -> Rational {
        Rational::new(self.num * o.den - o.num * self.den, self.den * o.den)
    }
    pub fn mul(&self, o: &Rational) -> Rational {
        Rational::new(self.num * o.num, self.den * o.den)
    }
    pub fn min(self, o: Rational) -> Rational {
        if self <= o { self } else { o }
    }
    pub fn max(self, o: Rational) -> Rational {
        if self >= o { self } else { o }
    }
}

impl PartialOrd for Rational {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Rational {
    fn cmp(&self, o: &Self) -> Ordering {
        // den > 0 always, so cross-multiplication preserves the order.
        (self.num * o.den).cmp(&(o.num * self.den))
    }
}

// ===========================================================================
// The kappa readout (Viterbi confidence, square-free environment quotient)
// ===========================================================================

/// `Eval_v` into the Viterbi confidence semiring `(max, ·, 0, 1)`, evaluating
/// each monomial over its variable SET (`x^k` read as `x`) — the square-free
/// collapse that makes kappa correlation-aware. Natural-number coefficients
/// collapse to `1` under the idempotent `max` (a thousand citations of one
/// source count once). This is the single concrete reading the calculus needs;
/// the general provenance-semiring family is specified in the Lean kernel and
/// the Python reference, not carried in production Rust.
fn eval_poly_viterbi<F: Fn(&str) -> Rational>(valuation: F, poly: &ProvenancePoly) -> Rational {
    let mut total = Rational::zero();
    for (mono, &coeff) in poly.terms() {
        if coeff == 0 {
            continue;
        }
        let mut term = Rational::one();
        for var in mono.factors().keys() {
            term = term.mul(&valuation(var));
        }
        total = total.max(term);
    }
    total
}

/// The discount coordinate kappa: best-derivation confidence, correlation-aware
/// (Viterbi with the square-free / collapse-exponents correction). Variables
/// absent from the confidence map default to 1 (assumptions carry conditions,
/// not decay).
///
/// v3 framing (`lean/Vela/Frontier/FrontierCalculus.lean`): the square-free
/// collapse is `kappa` reading the *environment quotient* `EnvProv = Env(p)`
/// rather than raw `N[X]`. On that layer `env` is the homomorphism
/// (multiplication is assumption-set union) and `kappa = weight . env` is the
/// TERMINAL weighted readout (max over environments of the product of
/// assumption weights), NOT a homomorphism into scalar Viterbi (that would
/// force `w^2 = w`). The square-free collapse (`envWeight_idem`) and the env
/// quotient's multiplicativity (`env_mul_support`, T4) are machine-checked
/// there.
pub fn kappa(p: &ProvenancePoly, conf: &BTreeMap<String, Rational>) -> Rational {
    eval_poly_viterbi(|v| conf.get(v).copied().unwrap_or_else(Rational::one), p)
}

// ===========================================================================
// The product bilattice [0,1] ⊙ [0,1] (Avron) and v1 corner conservativity
// ===========================================================================

/// The v2 status: one point `(x, y)` in the unit square. `x` = support degree
/// (kappa of the support polynomial), `y` = opposition degree (kappa of refute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BilatticePoint {
    pub x: Rational,
    pub y: Rational,
}

impl BilatticePoint {
    pub fn new(x: Rational, y: Rational) -> Self {
        BilatticePoint { x, y }
    }
    /// Knowledge order: coordinatewise (evidence accumulates upward).
    pub fn leq_k(&self, o: &Self) -> bool {
        self.x <= o.x && self.y <= o.y
    }
    pub fn join_k(&self, o: &Self) -> Self {
        BilatticePoint::new(self.x.max(o.x), self.y.max(o.y))
    }
    /// Information content `x + y`.
    pub fn information(&self) -> Rational {
        self.x.add(&self.y)
    }
    /// Conflict degree `min(x, y)` — the graded reading that subsumes "Both".
    pub fn conflict(&self) -> Rational {
        self.x.min(self.y)
    }
    /// The v1 Belnap corner this point thresholds to.
    pub fn corner(&self) -> BelnapStatus {
        let zero = Rational::zero();
        match (self.x > zero, self.y > zero) {
            (true, true) => BelnapStatus::Both,
            (true, false) => BelnapStatus::True,
            (false, true) => BelnapStatus::False,
            (false, false) => BelnapStatus::None,
        }
    }
}

/// The v2 status of a claim: one bilattice point derived from the two
/// provenance polynomials by the kappa projection.
pub fn status_point(
    support: &ProvenancePoly,
    refute: &ProvenancePoly,
    conf: &BTreeMap<String, Rational>,
) -> BilatticePoint {
    BilatticePoint::new(kappa(support, conf), kappa(refute, conf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(n: i128, d: i128) -> Rational {
        Rational::new(n, d)
    }
    fn var(name: &str) -> ProvenancePoly {
        ProvenancePoly::singleton(name)
    }
    fn conf(pairs: &[(&str, (i128, i128))]) -> BTreeMap<String, Rational> {
        pairs
            .iter()
            .map(|(k, (n, d))| (k.to_string(), r(*n, *d)))
            .collect()
    }

    #[test]
    fn rational_is_exact_and_reduced() {
        assert_eq!(r(2, 4), r(1, 2));
        assert_eq!(r(9, 10).mul(&r(9, 10)), r(81, 100));
        assert_eq!(r(1, 3).add(&r(1, 6)), r(1, 2));
        assert!(r(72, 100) > r(56, 100));
    }

    // --- correlated provenance: kappa collapses exponents, doesn't double-count -
    #[test]
    fn correlated_provenance_collapses_exponents() {
        // a^2 : a single derivation that depends on source `a` twice (correlated).
        let a2 = &var("a") * &var("a");
        let cmap = conf(&[("a", (1, 2))]);
        // kappa reads a^2 over its variable SET, so conf(a) = 1/2 (counts a once),
        // NOT the double-counted conf(a)^2 = 1/4 a free reading would give.
        assert_eq!(kappa(&a2, &cmap), r(1, 2));
        assert!(
            kappa(&a2, &cmap) > r(1, 4),
            "kappa must not double-count correlated evidence"
        );
    }

    // --- kappa <= weakest premise on a chain; citations don't add -------------
    #[test]
    fn kappa_bounds_and_citation_invariance() {
        // chain a·b·c : kappa = product = bounded by the min premise.
        let chain = &(&var("a") * &var("b")) * &var("c");
        let cmap = conf(&[("a", (9, 10)), ("b", (1, 2)), ("c", (7, 10))]);
        let k = kappa(&chain, &cmap);
        let min_premise = r(9, 10).min(r(1, 2)).min(r(7, 10));
        assert!(k <= min_premise, "kappa never exceeds the weakest premise");
        assert_eq!(k, r(9, 10).mul(&r(1, 2)).mul(&r(7, 10)));

        // 1000 citations of one source == one citation (idempotent coefficient).
        let single = var("a");
        let mut thousand = ProvenancePoly::zero();
        for _ in 0..1000 {
            thousand = &thousand + &single;
        }
        let cmap_a = conf(&[("a", (3, 4))]);
        assert_eq!(kappa(&thousand, &cmap_a), kappa(&single, &cmap_a));
        assert_eq!(kappa(&single, &cmap_a), r(3, 4));
    }

    // --- corner operations reproduce the v1 Belnap status exactly -------------
    #[test]
    fn corner_conservativity() {
        use BelnapStatus::*;
        let (z, o) = (Rational::zero(), Rational::one());
        // The canonical corner point of each v1 Belnap status.
        let corner_point = |s| match s {
            None => BilatticePoint::new(z, z),
            True => BilatticePoint::new(o, z),
            False => BilatticePoint::new(z, o),
            Both => BilatticePoint::new(o, o),
        };
        for s in [None, True, False, Both] {
            // each corner point thresholds back to its v1 status.
            assert_eq!(corner_point(s).corner(), s);
        }
        // knowledge order on corners reproduces Belnap's lattice:
        // N is the bottom, Both the top, T and F incomparable.
        let leq_k = |a, b| corner_point(a).leq_k(&corner_point(b));
        assert!(leq_k(None, True));
        assert!(leq_k(None, Both));
        assert!(leq_k(True, Both));
        assert!(!leq_k(True, False));
        assert!(!leq_k(False, True));

        // a graded interior point still thresholds to the right corner, and a
        // status-point fold reproduces the v1 derivation (support+refute -> Both).
        let support = &var("a") + &var("b");
        let refute = var("c");
        let cmap = conf(&[("a", (9, 10)), ("b", (1, 2)), ("c", (8, 10))]);
        let pt = status_point(&support, &refute, &cmap);
        assert_eq!(pt.x, r(9, 10)); // best support derivation
        assert_eq!(pt.y, r(8, 10)); // refute confidence
        assert_eq!(pt.corner(), Both);
        assert_eq!(pt.conflict(), r(8, 10).min(r(9, 10)));
    }
}
