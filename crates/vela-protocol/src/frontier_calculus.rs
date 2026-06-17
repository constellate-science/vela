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
///
/// v3 framing (`lean/Vela/Frontier/FrontierCalculus.lean`): the `collapse_exponents`
/// flag is `kappa` reading the *environment quotient* `EnvProv = Env(p)` rather
/// than raw `N[X]`. On that layer `env` is the homomorphism (multiplication is
/// assumption-set union) and `kappa = weight . env` is the TERMINAL weighted
/// readout (max over environments of the product of assumption weights), NOT a
/// homomorphism into scalar Viterbi (that would force `w^2 = w`). The square-free
/// collapse (`envWeight_idem`) and the env quotient's multiplicativity
/// (`env_mul_support`, T4) are machine-checked there.
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

// ===========================================================================
// Verification cost and the admission boundary (session 7, doctrine law 18)
//
// v(q, c) is the cost of verifying a claim; admission requirements are a
// monotone increasing function of v. Permissionless iff verification is cheap;
// gated otherwise; refused outright at v = ∞. The cheap-verifier scope boundary
// is DERIVED, not asserted — a clinical-shaped claim (no in-software verifier,
// v = ∞) has no admission path through any policy.
// ===========================================================================

/// `v(q, c)` for a derived claim: the cheapest-derivation (tropical) cost.
/// Sources absent from `cost` default to 0 (already paid); the empty polynomial
/// (no derivation at all) is `∞` — nothing to verify cheaply.
pub fn verification_cost(p: &ProvenancePoly, cost: &BTreeMap<String, Rational>) -> Cost {
    project_cost(p, cost)
}

/// `v = ∞`: no in-software verifier, so no policy admits the claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoAdmissionPath(pub String);

/// The outcome of an admission check: whether the writer may write without a
/// reviewer, and which trust coordinates the record must carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionDecision {
    pub permissionless: bool,
    pub required_trust_coordinates: BTreeSet<String>,
}

/// Required trust coordinates as a monotone increasing function of `v`.
#[derive(Debug, Clone, Copy)]
pub struct AdmissionPolicy {
    pub name: &'static str,
    pub cheap_threshold: i128,
    pub gated_threshold: i128,
}

impl AdmissionPolicy {
    fn coords(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    /// The trust coordinates required to admit a claim at cost `v`. Monotone:
    /// a higher cost never requires fewer coordinates. `∞` has no admission path.
    pub fn required_trust_coordinates(&self, v: Cost) -> Result<BTreeSet<String>, NoAdmissionPath> {
        let c = match v {
            Cost::Inf => {
                return Err(NoAdmissionPath(format!(
                    "policy {}: no in-software verifier (v = ∞); no admission path \
                     through the verifier gate",
                    self.name
                )));
            }
            Cost::Finite(c) => c,
        };
        let mut req = Self::coords(&["log_integrity", "verifier_gate"]);
        if c > Rational::from_int(self.cheap_threshold) {
            req.extend(Self::coords(&["artifact_replay", "human_review"]));
        }
        if c > Rational::from_int(self.gated_threshold) {
            req.extend(Self::coords(&[
                "statement_faithfulness",
                "significance_endorsement",
            ]));
        }
        Ok(req)
    }

    /// Admit a claim at cost `v`: permissionless iff verification is cheap.
    pub fn admit(&self, v: Cost) -> Result<AdmissionDecision, NoAdmissionPath> {
        let required_trust_coordinates = self.required_trust_coordinates(v)?;
        let permissionless =
            matches!(v, Cost::Finite(c) if c <= Rational::from_int(self.cheap_threshold));
        Ok(AdmissionDecision {
            permissionless,
            required_trust_coordinates,
        })
    }
}

/// The standard admission registry.
pub const ADMISSION_DEFAULT: AdmissionPolicy = AdmissionPolicy {
    name: "default",
    cheap_threshold: 10,
    gated_threshold: 100,
};
pub const ADMISSION_STRICT: AdmissionPolicy = AdmissionPolicy {
    name: "strict",
    cheap_threshold: 1,
    gated_threshold: 10,
};

// ===========================================================================
// Replay tiers: bitwise vs semantic-within-tolerance (session 7, law 17)
//
// Two equivalence relations replace the scalar artifact_replay reading. The
// load-bearing rule: a tolerance spec is an attestation, never a proof —
// someone SIGNS "within tau is the same result"; the kernel never invents tau,
// and a semantic receipt can never produce a bitwise-grade trust coordinate.
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayTier {
    Bitwise,
    Semantic,
}

/// Replay refused: a tier upgrade without a new bitwise event, or a semantic
/// claim without a signed tolerance attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayRefused(pub String);

/// "Within tau is the same result" — a signed attestation carrying the signer's
/// responsibility, never a proof the kernel can derive.
#[derive(Debug, Clone, PartialEq)]
pub struct ToleranceAttestation {
    pub tau: f64,
    pub signer: String,
    pub signature: String,
}

impl ToleranceAttestation {
    pub fn is_signed(&self) -> bool {
        !self.signer.is_empty() && !self.signature.is_empty()
    }
}

/// A replay outcome: the tier, the observed and reference outputs as canonical
/// bytes (bitwise equality; parsed as `f64` for the semantic comparison), and
/// the signed tolerance for a semantic receipt.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayReceipt {
    pub tier: ReplayTier,
    pub observed: String,
    pub reference: String,
    pub tolerance: Option<ToleranceAttestation>,
}

/// Whether a replay passes at its declared tier. Semantic replay refuses
/// without a signed, nonnegative tolerance — the kernel never invents tau.
pub fn replay_passes(r: &ReplayReceipt) -> Result<bool, ReplayRefused> {
    match r.tier {
        ReplayTier::Bitwise => Ok(r.observed == r.reference),
        ReplayTier::Semantic => {
            let tol = r
                .tolerance
                .as_ref()
                .filter(|t| t.is_signed())
                .ok_or_else(|| {
                    ReplayRefused(
                        "semantic replay requires a signed tolerance attestation; a \
                     tolerance spec is an attestation, never a proof"
                            .to_string(),
                    )
                })?;
            if tol.tau < 0.0 {
                return Err(ReplayRefused("tolerance must be nonnegative".to_string()));
            }
            let o: f64 = r
                .observed
                .parse()
                .map_err(|_| ReplayRefused("semantic observed is not numeric".to_string()))?;
            let f: f64 = r
                .reference
                .parse()
                .map_err(|_| ReplayRefused("semantic reference is not numeric".to_string()))?;
            Ok((o - f).abs() <= tol.tau)
        }
    }
}

/// Derive the artifact-replay trust coordinate from a typed receipt. Tier
/// monotonicity: bitwise implies semantic at every tau >= 0, and a tier is
/// never upgraded without a new replay event — a semantic receipt can never
/// yield the bitwise-grade coordinate.
pub fn replay_trust_grade(
    r: &ReplayReceipt,
    requested: ReplayTier,
) -> Result<&'static str, ReplayRefused> {
    if requested == ReplayTier::Bitwise && r.tier != ReplayTier::Bitwise {
        return Err(ReplayRefused(
            "a semantic receipt can never produce a bitwise-grade trust \
             coordinate; tier upgrade requires a new bitwise replay event"
                .to_string(),
        ));
    }
    if !replay_passes(r)? {
        return Err(ReplayRefused(format!("replay failed at tier {:?}", r.tier)));
    }
    if r.tier == ReplayTier::Bitwise && requested == ReplayTier::Bitwise {
        Ok("bitwise_replay")
    } else {
        Ok("semantic_replay_within_attested_tolerance")
    }
}

// ===========================================================================
// Assumption environments (ATMS-lite, session 7) — defeasible transfer layer 1
//
// Environments are assumption sets: the variable set of each monomial.
// Invalidating an assumption removes every environment containing it. Because
// monomials already ARE variable sets, this is the same homomorphism as
// variable zeroing — retraction generalizes to assumption-set invalidation with
// no new operator, and supersession cascades by the retraction theorem applied
// transitively.
// ===========================================================================

/// The ATMS environments of a polynomial: the variable set of each monomial.
pub fn environments(p: &ProvenancePoly) -> BTreeSet<BTreeSet<String>> {
    p.terms().map(|(mono, _)| mono.variables()).collect()
}

/// Invalidate an assumption set: drop every environment (monomial) containing
/// an invalidated assumption. Extensionally equal to [`ProvenancePoly::retract`];
/// implemented independently so the subsumption is checked, not assumed.
pub fn invalidate_environments(p: &ProvenancePoly, invalid: &BTreeSet<String>) -> ProvenancePoly {
    let mut out = ProvenancePoly::zero();
    for (mono, coeff) in p.terms() {
        if mono.variables().is_disjoint(invalid) {
            out.insert_term(mono.clone(), *coeff);
        }
    }
    out
}

// ===========================================================================
// Statement-faithfulness strength relation (session 7)
//
// Six values for how a formal statement relates to the informal claim it
// attests, with composition along formalization chains. Composition is an
// associative monoid with EQUIVALENT as identity and UNFAITHFUL absorbing;
// mixed or incomparable directions compose to AMBIGUOUS — information loss is
// explicit, never silently resolved. (Distinct from the binary
// `statement_attestation::FaithfulnessVerdict`: this is the graded relation.)
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaithfulnessStrength {
    Equivalent,
    FormalStronger,
    FormalWeaker,
    Incomparable,
    Ambiguous,
    Unfaithful,
}

/// Compose two faithfulness strengths along a formalization chain.
pub fn compose_faithfulness(
    a: FaithfulnessStrength,
    b: FaithfulnessStrength,
) -> FaithfulnessStrength {
    use FaithfulnessStrength::*;
    if a == Unfaithful || b == Unfaithful {
        return Unfaithful; // absorbing
    }
    if a == Equivalent {
        return b; // identity
    }
    if b == Equivalent {
        return a;
    }
    if a == Ambiguous || b == Ambiguous {
        return Ambiguous;
    }
    match (a, b) {
        (FormalStronger, FormalStronger) => FormalStronger,
        (FormalWeaker, FormalWeaker) => FormalWeaker,
        // mixed directions or any INCOMPARABLE leg: strength info is lost.
        _ => Ambiguous,
    }
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

    // --- check 21: admission is a monotone function of verification cost ------
    #[test]
    fn check21_admission_monotone_in_cost() {
        let pol = ADMISSION_DEFAULT;
        let cheap = pol.admit(Cost::Finite(Rational::from_int(2))).unwrap();
        let costly = pol.admit(Cost::Finite(Rational::from_int(500))).unwrap();
        assert!(
            cheap.permissionless,
            "SAT-shaped (cheap) admits permissionless"
        );
        assert!(!costly.permissionless, "exhaustive (costly) is gated");
        assert!(
            cheap
                .required_trust_coordinates
                .is_subset(&costly.required_trust_coordinates)
                && cheap.required_trust_coordinates != costly.required_trust_coordinates,
            "cheaper verification requires strictly fewer trust coordinates"
        );

        // A clinical-shaped claim (v = ∞) is refused by every policy.
        for p in [ADMISSION_DEFAULT, ADMISSION_STRICT] {
            assert!(p.admit(Cost::Inf).is_err());
            // monotone: more cost never requires fewer coordinates.
            let mut prev: BTreeSet<String> = BTreeSet::new();
            for c in [0i128, 1, 5, 10, 50, 100, 1000] {
                let req = p
                    .required_trust_coordinates(Cost::Finite(Rational::from_int(c)))
                    .unwrap();
                assert!(prev.is_subset(&req), "admission must be monotone in v");
                prev = req;
            }
        }

        // v for a derived claim is the cheapest derivation (tropical).
        let support = &(&var("sat_cert") * &var("replay")) + &var("exhaustive_run");
        let cost = conf(&[
            ("sat_cert", (2, 1)),
            ("replay", (1, 1)),
            ("exhaustive_run", (500, 1)),
        ]);
        assert_eq!(
            verification_cost(&support, &cost),
            Cost::Finite(Rational::from_int(3))
        );
        assert!(
            ADMISSION_DEFAULT
                .admit(verification_cost(&support, &cost))
                .unwrap()
                .permissionless
        );
        // no derivation at all: nothing to verify cheaply -> ∞.
        assert_eq!(
            verification_cost(&ProvenancePoly::zero(), &BTreeMap::new()),
            Cost::Inf
        );
    }

    // --- check 22: replay tiers; tolerance is an attestation, never a proof ---
    #[test]
    fn check22_replay_tiers() {
        let attn = |tau: f64| ToleranceAttestation {
            tau,
            signer: "will".to_string(),
            signature: "sig-demo".to_string(),
        };
        let bitwise = ReplayReceipt {
            tier: ReplayTier::Bitwise,
            observed: "2.0".to_string(),
            reference: "2.0".to_string(),
            tolerance: None,
        };
        assert!(replay_passes(&bitwise).unwrap());
        // bitwise implies semantic at every tolerance.
        for tau in [0.0, 1e-9, 1e-3, 1.0] {
            let sem = ReplayReceipt {
                tier: ReplayTier::Semantic,
                observed: "2.0".to_string(),
                reference: "2.0".to_string(),
                tolerance: Some(attn(tau)),
            };
            assert!(replay_passes(&sem).unwrap());
        }
        assert_eq!(
            replay_trust_grade(&bitwise, ReplayTier::Bitwise).unwrap(),
            "bitwise_replay"
        );
        let semantic_only = ReplayReceipt {
            tier: ReplayTier::Semantic,
            observed: "2.0000001".to_string(),
            reference: "2.0".to_string(),
            tolerance: Some(attn(1e-3)),
        };
        assert_eq!(
            replay_trust_grade(&semantic_only, ReplayTier::Semantic).unwrap(),
            "semantic_replay_within_attested_tolerance"
        );
        // a semantic receipt can never produce a bitwise-grade coordinate.
        assert!(replay_trust_grade(&semantic_only, ReplayTier::Bitwise).is_err());
        // the kernel never invents tau: no tolerance, or unsigned, is refused.
        let no_tol = ReplayReceipt {
            tier: ReplayTier::Semantic,
            observed: "2.0".to_string(),
            reference: "2.0".to_string(),
            tolerance: None,
        };
        assert!(replay_passes(&no_tol).is_err());
        let unsigned = ReplayReceipt {
            tier: ReplayTier::Semantic,
            observed: "2.0".to_string(),
            reference: "2.0".to_string(),
            tolerance: Some(ToleranceAttestation {
                tau: 1e-3,
                signer: String::new(),
                signature: String::new(),
            }),
        };
        assert!(replay_passes(&unsigned).is_err());
    }

    // --- check 23: assumption invalidation subsumes variable zeroing ----------
    #[test]
    fn check23_assumption_invalidation_subsumes_zeroing() {
        // transfer-shaped support: asm·src·thm (one derivation through an
        // assumption) plus an independent alternative.
        let p = &(&(&var("asm") * &var("src")) * &var("thm")) + &var("alt");
        let invalid: BTreeSet<String> = BTreeSet::from(["asm".to_string()]);

        // invalidate_environments is extensionally equal to retract.
        assert_eq!(invalidate_environments(&p, &invalid), p.retract(&invalid));
        // no surviving environment contains the invalidated assumption.
        for env in environments(&invalidate_environments(&p, &invalid)) {
            assert!(env.is_disjoint(&invalid));
        }

        // the support coordinate of the bilattice point moves DOWN on
        // invalidation (the cascade reaches the derived claim).
        let cmap = conf(&[
            ("asm", (9, 10)),
            ("src", (9, 10)),
            ("thm", (9, 10)),
            ("alt", (1, 2)),
        ]);
        let before = status_point(&p, &ProvenancePoly::zero(), &cmap);
        let after = status_point(
            &invalidate_environments(&p, &invalid),
            &ProvenancePoly::zero(),
            &cmap,
        );
        assert!(
            after.x < before.x,
            "invalidation must lower the support degree"
        );

        // the singleton case is exactly variable zeroing (retraction theorem).
        let single = var("asm");
        assert_eq!(
            invalidate_environments(&single, &invalid),
            single.retract(&invalid)
        );
        assert!(invalidate_environments(&single, &invalid).is_zero());
    }

    // --- faithfulness strength is an associative monoid -----------------------
    #[test]
    fn faithfulness_strength_monoid() {
        use FaithfulnessStrength::*;
        let all = [
            Equivalent,
            FormalStronger,
            FormalWeaker,
            Incomparable,
            Ambiguous,
            Unfaithful,
        ];
        // EQUIVALENT is the identity; UNFAITHFUL absorbs.
        for s in all {
            assert_eq!(compose_faithfulness(Equivalent, s), s);
            assert_eq!(compose_faithfulness(s, Equivalent), s);
            assert_eq!(compose_faithfulness(Unfaithful, s), Unfaithful);
            assert_eq!(compose_faithfulness(s, Unfaithful), Unfaithful);
        }
        // same direction composes; mixed / incomparable lose to AMBIGUOUS.
        assert_eq!(
            compose_faithfulness(FormalStronger, FormalStronger),
            FormalStronger
        );
        assert_eq!(
            compose_faithfulness(FormalWeaker, FormalWeaker),
            FormalWeaker
        );
        assert_eq!(
            compose_faithfulness(FormalStronger, FormalWeaker),
            Ambiguous
        );
        assert_eq!(
            compose_faithfulness(FormalStronger, Incomparable),
            Ambiguous
        );
        // associativity over every triple.
        for a in all {
            for b in all {
                for c in all {
                    assert_eq!(
                        compose_faithfulness(compose_faithfulness(a, b), c),
                        compose_faithfulness(a, compose_faithfulness(b, c)),
                        "compose must be associative"
                    );
                }
            }
        }
    }
}
