//! Frontier calculus v2: the projection machinery, the discount kappa, and the
//! graded bilattice status — the Rust port of `research/frontier-calculus/
//! frontier_calculus_kernel.py` (sessions 5-6 of the consolidation program).
//!
//! The kernel stores ONE free object, the provenance polynomial in N[X]
//! ([`crate::provenance_poly::ProvenancePoly`]), and derives every finding flag
//! by the unique homomorphism `Eval_v` into a named commutative semiring
//! (Green-Karvounarakis-Tannen, PODS 2007). v1's Belnap status is the corner
//! sublattice of the v2 graded `[0,1] ⊙ [0,1]` bilattice (Avron's
//! representation theorem, 1996); thresholding each coordinate recovers v1
//! exactly, so this is a *conservative extension* — a derived read, no protocol
//! change.
//!
//! Determinism: confidence/cost scalars are exact [`Rational`]s (matching the
//! reference's `Fraction`), never floats, so the Rust and Python projections
//! agree exactly. The kernel's cross-implementation check fixtures (checks
//! 15-20) are ported as the test module below.

use crate::provenance_poly::ProvenancePoly;
use crate::status_provenance::BelnapStatus;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

// ===========================================================================
// Exact non-negative rationals (confidence and cost scalars)
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
    pub fn from_int(n: i128) -> Self {
        Rational { num: n, den: 1 }
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

/// Tropical cost: a finite rational or `∞` (no derivation / no verifier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cost {
    Finite(Rational),
    Inf,
}

impl Cost {
    fn min(self, o: Cost) -> Cost {
        match (self, o) {
            (Cost::Inf, b) => b,
            (a, Cost::Inf) => a,
            (Cost::Finite(a), Cost::Finite(b)) => Cost::Finite(a.min(b)),
        }
    }
    fn add(self, o: Cost) -> Cost {
        match (self, o) {
            (Cost::Inf, _) | (_, Cost::Inf) => Cost::Inf,
            (Cost::Finite(a), Cost::Finite(b)) => Cost::Finite(a.add(&b)),
        }
    }
}

// ===========================================================================
// Commutative semirings and the Eval_v homomorphism
// ===========================================================================

/// A commutative semiring `(K, add, mul, zero, one)`.
///
/// `idempotent_add` marks the class where path-style readings are DAG-safe: a
/// shared sub-derivation reused by several alternative paths contributes once,
/// because `add(a, a) = a` (Jøsang's discount is canonical on series-parallel
/// graphs only; idempotent `max` repairs general DAGs).
pub trait Semiring {
    type Elem: Clone + PartialEq;
    fn name(&self) -> &'static str;
    fn zero(&self) -> Self::Elem;
    fn one(&self) -> Self::Elem;
    fn add(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn mul(&self, a: &Self::Elem, b: &Self::Elem) -> Self::Elem;
    fn idempotent_add(&self) -> bool;
}

/// Boolean existence: "is there any supporting derivation from trusted sources".
pub struct Boolean;
impl Semiring for Boolean {
    type Elem = bool;
    fn name(&self) -> &'static str {
        "boolean"
    }
    fn zero(&self) -> bool {
        false
    }
    fn one(&self) -> bool {
        true
    }
    fn add(&self, a: &bool, b: &bool) -> bool {
        *a || *b
    }
    fn mul(&self, a: &bool, b: &bool) -> bool {
        *a && *b
    }
    fn idempotent_add(&self) -> bool {
        true
    }
}

/// Attribution / counting: "how many derivations" — multiplicity, never credibility.
pub struct Counting;
impl Semiring for Counting {
    type Elem = u64;
    fn name(&self) -> &'static str {
        "counting"
    }
    fn zero(&self) -> u64 {
        0
    }
    fn one(&self) -> u64 {
        1
    }
    fn add(&self, a: &u64, b: &u64) -> u64 {
        a.saturating_add(*b)
    }
    fn mul(&self, a: &u64, b: &u64) -> u64 {
        a.saturating_mul(*b)
    }
    fn idempotent_add(&self) -> bool {
        false
    }
}

/// Viterbi confidence: best-path confidence (`max`, `·`) — the kappa carrier.
pub struct Viterbi;
impl Semiring for Viterbi {
    type Elem = Rational;
    fn name(&self) -> &'static str {
        "viterbi"
    }
    fn zero(&self) -> Rational {
        Rational::zero()
    }
    fn one(&self) -> Rational {
        Rational::one()
    }
    fn add(&self, a: &Rational, b: &Rational) -> Rational {
        (*a).max(*b)
    }
    fn mul(&self, a: &Rational, b: &Rational) -> Rational {
        a.mul(b)
    }
    fn idempotent_add(&self) -> bool {
        true
    }
}

/// Bottleneck: "a chain is as strong as its weakest premise" (`max`, `min`).
pub struct Bottleneck;
impl Semiring for Bottleneck {
    type Elem = Rational;
    fn name(&self) -> &'static str {
        "bottleneck"
    }
    fn zero(&self) -> Rational {
        Rational::zero()
    }
    fn one(&self) -> Rational {
        Rational::one()
    }
    fn add(&self, a: &Rational, b: &Rational) -> Rational {
        (*a).max(*b)
    }
    fn mul(&self, a: &Rational, b: &Rational) -> Rational {
        (*a).min(*b)
    }
    fn idempotent_add(&self) -> bool {
        true
    }
}

/// Tropical cost: cheapest derivation (`min`, `+`, `0` = one, `∞` = zero).
pub struct Tropical;
impl Semiring for Tropical {
    type Elem = Cost;
    fn name(&self) -> &'static str {
        "tropical_cost"
    }
    fn zero(&self) -> Cost {
        Cost::Inf
    }
    fn one(&self) -> Cost {
        Cost::Finite(Rational::zero())
    }
    fn add(&self, a: &Cost, b: &Cost) -> Cost {
        (*a).min(*b)
    }
    fn mul(&self, a: &Cost, b: &Cost) -> Cost {
        (*a).add(*b)
    }
    fn idempotent_add(&self) -> bool {
        true
    }
}

/// Probabilistic sum (`a + b - a·b`). NON-idempotent: it double-counts
/// correlated evidence on DAGs with shared sub-derivations. Kept only as the
/// unsafe foil for the DAG-safety check; never a confidence projection.
pub struct ProbSum;
impl Semiring for ProbSum {
    type Elem = Rational;
    fn name(&self) -> &'static str {
        "probabilistic_sum"
    }
    fn zero(&self) -> Rational {
        Rational::zero()
    }
    fn one(&self) -> Rational {
        Rational::one()
    }
    fn add(&self, a: &Rational, b: &Rational) -> Rational {
        a.add(b).sub(&a.mul(b))
    }
    fn mul(&self, a: &Rational, b: &Rational) -> Rational {
        a.mul(b)
    }
    fn idempotent_add(&self) -> bool {
        false
    }
}

/// The canonical image of a natural-number coefficient in `K`.
fn nat_image<K: Semiring>(k: &K, n: u64) -> K::Elem {
    if n == 0 {
        return k.zero();
    }
    if k.idempotent_add() {
        return k.one();
    }
    let mut acc = k.zero();
    for _ in 0..n {
        acc = k.add(&acc, &k.one());
    }
    acc
}

/// `Eval_v`: the unique homomorphism `N[X] -> K` extending the valuation.
///
/// `collapse_exponents = true` evaluates each monomial over its variable SET
/// (`x^k` read as `x`) — the correlated-provenance correction used by kappa.
pub fn eval_poly<K: Semiring, F: Fn(&str) -> K::Elem>(
    k: &K,
    valuation: F,
    poly: &ProvenancePoly,
    collapse_exponents: bool,
) -> K::Elem {
    let mut total = k.zero();
    for (mono, coeff) in poly.terms() {
        let mut term = nat_image(k, *coeff);
        for (var, exp) in mono.factors() {
            let v = valuation(var);
            let reps = if collapse_exponents { 1 } else { *exp };
            for _ in 0..reps {
                term = k.mul(&term, &v);
            }
        }
        total = k.add(&total, &term);
    }
    total
}

// ===========================================================================
// The commutation boundary: negation/aggregation tagging and refusal
// ===========================================================================

pub const NEGATION_TAG: &str = "negation";
pub const AGGREGATION_TAG: &str = "aggregation";

/// A provenance polynomial that crossed a non-positive derivation step.
/// Homomorphism commutation holds for positive relational algebra only;
/// negation/difference and aggregation tag the polynomial and `Eval_v` refuses.
#[derive(Debug, Clone)]
pub struct TaggedPoly {
    pub poly: ProvenancePoly,
    pub tags: BTreeSet<String>,
}

impl TaggedPoly {
    /// A negation/difference step taints the polynomial.
    pub fn negation(poly: ProvenancePoly) -> TaggedPoly {
        TaggedPoly {
            poly,
            tags: BTreeSet::from([NEGATION_TAG.to_string()]),
        }
    }
    /// An aggregation step over many polynomials taints their sum.
    pub fn aggregation(polys: impl IntoIterator<Item = ProvenancePoly>) -> TaggedPoly {
        let mut acc = ProvenancePoly::zero();
        for p in polys {
            acc = &acc + &p;
        }
        TaggedPoly {
            poly: acc,
            tags: BTreeSet::from([AGGREGATION_TAG.to_string()]),
        }
    }
}

/// `Eval_v` refused past the commutation boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRefused(pub String);

/// Project a tagged polynomial: refuses with the tag set, never evaluates past
/// the boundary. The only permitted reading of a tagged polynomial is the bare
/// Boolean existence degrade below.
pub fn eval_tagged<K: Semiring, F: Fn(&str) -> K::Elem>(
    k: &K,
    valuation: F,
    tp: &TaggedPoly,
    collapse_exponents: bool,
) -> Result<K::Elem, ProjectionRefused> {
    if !tp.tags.is_empty() {
        return Err(ProjectionRefused(format!(
            "Eval_{} refused: polynomial is tagged {:?}; projection only commutes \
             with positive derivation steps",
            k.name(),
            tp.tags
        )));
    }
    Ok(eval_poly(k, valuation, &tp.poly, collapse_exponents))
}

/// The one permitted reading of a tagged polynomial: bare existence.
pub fn boolean_existence_degrade(tp: &TaggedPoly) -> bool {
    !tp.poly.is_zero()
}

/// Path-style confidence readings are only safe with idempotent addition.
pub fn assert_dag_safe_for_confidence<K: Semiring>(k: &K) -> Result<(), ProjectionRefused> {
    if k.idempotent_add() {
        Ok(())
    } else {
        Err(ProjectionRefused(format!(
            "semiring {} has non-idempotent addition: unsafe as a confidence \
             projection on DAGs with shared sub-derivations",
            k.name()
        )))
    }
}

// ===========================================================================
// The named projections (doctrine theorem 13: every flag is one of these)
// ===========================================================================

/// "Is there any supporting derivation from trusted sources?"
pub fn project_existence(p: &ProvenancePoly, trusted: impl Fn(&str) -> bool) -> bool {
    eval_poly(&Boolean, |v| trusted(v), p, false)
}

/// "How many derivations?" — multiplicity, never credibility.
pub fn project_count(p: &ProvenancePoly) -> u64 {
    eval_poly(&Counting, |_| 1u64, p, false)
}

/// "Cheapest derivation cost." Variables absent from the cost map default to 0
/// (already-paid sources).
pub fn project_cost(p: &ProvenancePoly, cost: &BTreeMap<String, Rational>) -> Cost {
    eval_poly(
        &Tropical,
        |v| Cost::Finite(cost.get(v).copied().unwrap_or_else(Rational::zero)),
        p,
        false,
    )
}

/// "Best-path confidence" (free Viterbi, exponents kept).
pub fn project_confidence(p: &ProvenancePoly, conf: &BTreeMap<String, Rational>) -> Rational {
    eval_poly(
        &Viterbi,
        |v| conf.get(v).copied().unwrap_or_else(Rational::one),
        p,
        false,
    )
}

/// The discount coordinate kappa: best-derivation confidence, correlation-aware
/// (Viterbi with the square-free / collapse-exponents correction). Variables
/// absent from the confidence map default to 1 (assumptions carry conditions,
/// not decay).
pub fn kappa(p: &ProvenancePoly, conf: &BTreeMap<String, Rational>) -> Rational {
    eval_poly(
        &Viterbi,
        |v| conf.get(v).copied().unwrap_or_else(Rational::one),
        p,
        true,
    )
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
    /// Truth order: more support, less opposition.
    pub fn leq_t(&self, o: &Self) -> bool {
        self.x <= o.x && self.y >= o.y
    }
    pub fn meet_k(&self, o: &Self) -> Self {
        BilatticePoint::new(self.x.min(o.x), self.y.min(o.y))
    }
    pub fn join_k(&self, o: &Self) -> Self {
        BilatticePoint::new(self.x.max(o.x), self.y.max(o.y))
    }
    pub fn meet_t(&self, o: &Self) -> Self {
        BilatticePoint::new(self.x.min(o.x), self.y.max(o.y))
    }
    pub fn join_t(&self, o: &Self) -> Self {
        BilatticePoint::new(self.x.max(o.x), self.y.min(o.y))
    }
    /// Negation swaps coordinates (inverts truth, preserves knowledge).
    pub fn neg(&self) -> Self {
        BilatticePoint::new(self.y, self.x)
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

/// The canonical corner point of each v1 Belnap status.
pub fn corner_point(s: BelnapStatus) -> BilatticePoint {
    let (z, o) = (Rational::zero(), Rational::one());
    match s {
        BelnapStatus::None => BilatticePoint::new(z, z),
        BelnapStatus::True => BilatticePoint::new(o, z),
        BelnapStatus::False => BilatticePoint::new(z, o),
        BelnapStatus::Both => BilatticePoint::new(o, o),
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

/// v1 Belnap knowledge order, read through the corner embedding.
pub fn corner_leq_k(a: BelnapStatus, b: BelnapStatus) -> bool {
    corner_point(a).leq_k(&corner_point(b))
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

    // --- check 15: every named projection commutes with retraction ----------
    // Retraction theorem: Eval_v(retract(p, Y)) == Eval_{v'}(p) where v' sends
    // the retracted variables to the semiring zero. Demonstrated on a small DAG.
    #[test]
    fn check15_projections_commute_with_retraction() {
        // p = a·b + c  (two alternative derivations)
        let p = &(&var("a") * &var("b")) + &var("c");
        let retracted: BTreeSet<String> = BTreeSet::from(["b".to_string()]);
        let pr = p.retract(&retracted);
        let cmap = conf(&[("a", (9, 10)), ("b", (8, 10)), ("c", (7, 10))]);

        // Confidence (Viterbi): retract-then-project.
        let lhs = project_confidence(&pr, &cmap);
        // project-then-retract: value b at the semiring zero (0).
        let mut cmap0 = cmap.clone();
        cmap0.insert("b".to_string(), Rational::zero());
        let rhs = project_confidence(&p, &cmap0);
        assert_eq!(lhs, rhs, "Viterbi must commute with retraction");

        // Counting: same identity (b -> 0 kills the a·b derivation).
        let lhs_c = project_count(&pr);
        assert_eq!(lhs_c, 1, "retract(b) leaves one derivation (c)");

        // Boolean existence with b untrusted equals existence on the retraction.
        let exists_retract = project_existence(&pr, |_| true);
        let exists_b_untrusted = project_existence(&p, |v| v != "b");
        assert_eq!(exists_retract, exists_b_untrusted);
        assert!(exists_retract);
    }

    // --- check 16: a negation-tagged polynomial makes Eval_v refuse ----------
    #[test]
    fn check16_tagged_polynomial_is_refused() {
        let tagged = TaggedPoly::negation(&var("a") + &var("b"));
        let cmap = conf(&[("a", (9, 10)), ("b", (8, 10))]);
        let result = eval_tagged(
            &Viterbi,
            |v| cmap.get(v).copied().unwrap_or_else(Rational::one),
            &tagged,
            true,
        );
        assert!(result.is_err(), "tagged polynomial must be refused");
        // The only permitted reading is bare existence.
        assert!(boolean_existence_degrade(&tagged));
    }

    // --- check 17: shared/repeated variable counted twice by confidence, ------
    // once by kappa (the square-free correction); double-counting forbidden.
    #[test]
    fn check17_correlated_provenance_diverges() {
        // a^2 : a single derivation that depends on source `a` twice (correlated).
        let a2 = &var("a") * &var("a");
        let cmap = conf(&[("a", (1, 2))]);
        // free confidence reads a^2 as conf(a)^2 = 1/4 (double-counts a).
        assert_eq!(project_confidence(&a2, &cmap), r(1, 4));
        // kappa collapses exponents: reads a^2 as conf(a) = 1/2 (counts a once).
        assert_eq!(kappa(&a2, &cmap), r(1, 2));
        assert!(
            kappa(&a2, &cmap) > project_confidence(&a2, &cmap),
            "kappa must not double-count correlated evidence"
        );
    }

    // --- check 18: Viterbi on a diamond DAG is DAG-safe; ProbSum is not -------
    #[test]
    fn check18_dag_safety() {
        // Diamond: two alternative paths a·b and a·c sharing sub-derivation a.
        let diamond = &(&var("a") * &var("b")) + &(&var("a") * &var("c"));
        let cmap = conf(&[("a", (9, 10)), ("b", (1, 2)), ("c", (1, 4))]);
        // Viterbi (idempotent max) = best path = a·b = 9/10 · 1/2 = 9/20.
        assert_eq!(project_confidence(&diamond, &cmap), r(9, 20));
        // The confidence role accepts Viterbi, refuses ProbSum.
        assert!(assert_dag_safe_for_confidence(&Viterbi).is_ok());
        assert!(assert_dag_safe_for_confidence(&ProbSum).is_err());
    }

    // --- check 19: kappa <= weakest premise on a chain; citations don't add ---
    #[test]
    fn check19_kappa_bounds_and_citation_invariance() {
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

    // --- check 20: corner operations reproduce the v1 Belnap status exactly ---
    #[test]
    fn check20_corner_conservativity() {
        use BelnapStatus::*;
        for s in [None, True, False, Both] {
            // each corner point thresholds back to its v1 status.
            assert_eq!(corner_point(s).corner(), s);
        }
        // knowledge order on corners reproduces Belnap's lattice:
        // N is the bottom, Both the top, T and F incomparable.
        assert!(corner_leq_k(None, True));
        assert!(corner_leq_k(None, Both));
        assert!(corner_leq_k(True, Both));
        assert!(!corner_leq_k(True, False));
        assert!(!corner_leq_k(False, True));

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
