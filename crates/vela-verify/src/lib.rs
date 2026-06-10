//! Frozen, independent exact verifiers for combinatorial and
//! coding-theory witnesses.
//!
//! The discovery loop's proposers are **untrusted**: an agent returns an
//! explicit construction (a set of points, a ruler, a generator matrix),
//! and this crate re-checks it deterministically before any claim is
//! recorded. A witness that does not pass here is discarded no matter
//! what the proposer reported. Corrupting a witness must fail the
//! verifier — that is the property the self-tests pin.
//!
//! This is the reference verifier registry the trust gate
//! ([`vela_protocol::verifier_attachment`]) and `vela reproduce` build
//! on: a passing verify here is the *evidence* an `exact_construction`
//! verifier attachment attests to. The verifiers are intentionally
//! dependency-light (serde only) and pure — no I/O, no randomness — so a
//! third party can re-run them and get byte-identical verdicts.
//!
//! Ported from the campaign's `scripts/verify_construction.py`; the
//! Python reference and this Rust port must agree on every witness.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// The outcome of verifying one witness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Whether the witness passed its exact verifier.
    pub ok: bool,
    /// Human-readable detail (what was checked, or why it failed).
    pub message: String,
    /// A recomputed numeric quantity for "value-to-beat" problems
    /// (currently unused by the boolean verifiers; reserved).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<f64>,
}

impl VerifyResult {
    pub fn ok(message: impl Into<String>) -> Self {
        Self {
            ok: true,
            message: message.into(),
            value: None,
        }
    }
    pub fn fail(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: message.into(),
            value: None,
        }
    }
}

/// A witness to verify. Tagged by `kind` on the wire, so a witness file
/// is `{"kind": "sidon", "n": 8, "points": [[...], ...], ...}`.
///
/// `claimed_size` (where present) lets a record assert "this construction
/// has N elements" — `verify_witness` confirms the verifier passes *and*
/// the construction has exactly that size, so a record can't claim a
/// bigger set than the witness it ships.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Witness {
    /// A Sidon set in `{0,1}^n` under componentwise integer addition:
    /// all pairwise sums distinct.
    Sidon {
        n: usize,
        points: Vec<Vec<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claimed_size: Option<usize>,
    },
    /// A Golomb ruler: integer marks with all pairwise differences
    /// distinct.
    Golomb { marks: Vec<i64> },
    /// A cap set in `F_3^n`: no three distinct points collinear.
    Cap {
        n: usize,
        points: Vec<Vec<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claimed_size: Option<usize>,
    },
    /// A `B_h` set in `{0,1}^n`: all `h`-fold sums distinct (`h = 2` is
    /// Sidon).
    Bh {
        n: usize,
        h: usize,
        points: Vec<Vec<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claimed_size: Option<usize>,
    },
    /// A covering design `C(v, k, t)`: every `t`-subset of `[0, v)` lies
    /// in at least one `k`-block.
    Covering {
        v: usize,
        k: usize,
        t: usize,
        blocks: Vec<Vec<usize>>,
    },
    /// A constant-weight binary code `A(n, d, w)`: codewords of weight
    /// exactly `w`, pairwise Hamming distance `>= d`.
    ConstantWeight {
        n: usize,
        d: usize,
        w: usize,
        words: Vec<Vec<i64>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        claimed_size: Option<usize>,
    },
    /// A Costas array: a permutation whose displacement vectors are all
    /// distinct.
    Costas { perm: Vec<i64> },
    /// A linear `[n, k, d]_q` code given by a `k x n` generator matrix
    /// over a prime field `GF(q)`.
    LinearCode {
        q: u64,
        claimed_d: usize,
        generator: Vec<Vec<i64>>,
    },
    /// An Erdős #1056 cut-equality certificate: a prime `p` and strictly
    /// increasing cuts `c_0 < ... < c_k` such that every consecutive
    /// interval `(c_{i-1}, c_i]` has integer product `== 1 (mod p)`.
    IntervalProduct { p: u64, cuts: Vec<u64> },
    /// A balanced r-coloring of K_n (Erdős #617 shape): every
    /// (r+1)-vertex subset must see all r colors among its internal
    /// edges. `edge_colors` keys are "i,j" with i<j, 0-indexed; colors
    /// are 1..=r. For K_26 r=5 this is C(26,6)=230,230 subset checks —
    /// instant.
    BalancedColoring {
        n: usize,
        r: usize,
        edge_colors: std::collections::BTreeMap<String, u32>,
    },
    /// An Erdős #203 partial CRT covering certificate: a modulus `m`
    /// (decimal string, coprime to 6) and prime rows, each pinning the
    /// multiplicative orders of 2 and 3 mod `p` and an affine line
    /// `(alpha, beta, gamma, h)` such that `p | 2^k 3^l m + 1` iff
    /// `alpha*k + beta*l == gamma (mod h)`, checked exhaustively over
    /// `(k, l) in [0, h)^2`.
    CrtPartialCover { m: String, rows: Vec<CrtCoverRow> },
    /// An Erdős #684 effective lower-bound certificate: for each entry
    /// `(k, m)`, `m = prod_{p<=k} p^(floor(log_p k)+1)` is recomputed and
    /// adding `j + (m-1-j)` in base `p` produces zero Kummer carries for
    /// all `2 <= j <= k`, `p <= j` — hence `f(m-1) > k`.
    KummerNoCarry { entries: Vec<KummerEntry> },
    /// An Erdős #700 value certificate: for each `(n, f)`,
    /// `f = min_{1<k<=n/2} gcd(n, C(n,k))`, recomputed via Kummer
    /// (`gcd(n, C(n,k)) = prod_{p|n} p^min(v_p(n), carries_p(k, n-k))`)
    /// so no big integers ever materialize.
    MinBinomGcd { cases: Vec<MinGcdCase> },
    /// An Erdős #1093 (ELS93) deficiency certificate: for each entry,
    /// `C(N,k)` is Kummer-defined (no prime `p <= k` divides it) and the
    /// deficiency `delta(N,k) = #{1<=i<=k : (N-k+i) | i*C(k,i)}` equals
    /// the claimed value (and slot positions, when given). Divisibility
    /// is decided by smooth factorization + Legendre — `i*C(k,i)` is
    /// never materialized.
    BinomDeficiency { entries: Vec<DeficiencyEntry> },
    /// An Erdős #1094 exception-enumeration certificate: every
    /// counterexample with `N >= 2k`, `k <= k_max` arises as
    /// `N = x + k - r` with `x | gcd(lcm(1..k), r*C(k,r))`, `k | x`.
    /// The verifier re-enumerates all candidates and confirms the found
    /// exception set equals the claimed `(N, k)` list exactly.
    /// Fail-closed: an unresolved candidate aborts rather than claims.
    BinomExceptionEnum {
        k_max: u64,
        exceptions: Vec<(u64, u64)>,
    },
    /// An UNSAT certificate: a CNF formula plus an LRAT-style clausal
    /// proof. Each proof step adds a clause justified by reverse unit
    /// propagation (RUP) over named antecedent clauses; the proof is
    /// accepted only if it derives the empty clause. A propositional
    /// claim (e.g. an Erdős finite case reduced to SAT) is verified by
    /// replaying this proof — the solver is untrusted, the certificate
    /// is checked. RUP only: a proof whose hints carry RAT structure is
    /// refused, never guessed.
    UnsatCert {
        cnf: Vec<Vec<i64>>,
        proof: Vec<LratStep>,
    },
}

/// One addition step of an LRAT proof: clause `id` is the listed
/// `literals` (empty = the empty clause = the proof goal), justified by
/// reverse unit propagation over the antecedent clause `hints` in order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LratStep {
    pub id: u64,
    pub literals: Vec<i64>,
    pub hints: Vec<u64>,
    /// RAT justification, used only when the direct RUP check fails:
    /// for EVERY db clause containing the negated pivot (the step's
    /// FIRST literal), a `(clause_id, resolvent_hints)` pair whose
    /// resolvent must itself be RUP. Tautological resolvents are
    /// vacuously fine. Deletion lines remain unsupported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rat_hints: Vec<(u64, Vec<u64>)>,
}

/// One prime row of an Erdős #203 partial-cover certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CrtCoverRow {
    pub p: u64,
    pub ord2: u64,
    pub ord3: u64,
    pub h: u64,
    pub t_p: u64,
    pub m_mod_p: u64,
    /// `(alpha, beta, gamma, modulus)` with `modulus == h`.
    pub line: [u64; 4],
}

/// One `(k, m)` entry of an Erdős #684 certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KummerEntry {
    pub k: u64,
    pub m: u64,
}

/// One `(n, f)` case of an Erdős #700 certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MinGcdCase {
    pub n: u64,
    pub f: u64,
}

/// One `(k, N, delta, slots)` entry of an Erdős #1093 deficiency
/// certificate. `n` is a decimal string (up to 38 digits / u128);
/// `slots` is optional — when absent only the count is checked.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeficiencyEntry {
    pub k: u64,
    pub n: String,
    pub delta: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slots: Option<Vec<u64>>,
}

impl Witness {
    /// The verifier name (matches the `kind` tag).
    pub fn kind(&self) -> &'static str {
        match self {
            Witness::Sidon { .. } => "sidon",
            Witness::Golomb { .. } => "golomb",
            Witness::Cap { .. } => "cap",
            Witness::Bh { .. } => "bh",
            Witness::Covering { .. } => "covering",
            Witness::ConstantWeight { .. } => "constant_weight",
            Witness::Costas { .. } => "costas",
            Witness::LinearCode { .. } => "linear_code",
            Witness::IntervalProduct { .. } => "interval_product",
            Witness::BalancedColoring { .. } => "balanced_coloring",
            Witness::CrtPartialCover { .. } => "crt_partial_cover",
            Witness::KummerNoCarry { .. } => "kummer_no_carry",
            Witness::MinBinomGcd { .. } => "min_binom_gcd",
            Witness::BinomDeficiency { .. } => "binom_deficiency",
            Witness::BinomExceptionEnum { .. } => "binom_exception_enum",
            Witness::UnsatCert { .. } => "unsat_cert",
        }
    }
}

/// Verify a witness against its exact verifier, plus the optional
/// `claimed_size` cross-check.
/// Machine-checked novelty: does `new` strictly dominate `prior` for
/// kinds with a natural order? Conservative: kinds without an obvious
/// dominance order return Err (the caller reports "not comparable") —
/// never a silent pass. This is the anti-AI-novelty-judge: dominance is
/// arithmetic, not opinion.
pub fn dominates(new: &Witness, prior: &Witness) -> Result<bool, String> {
    use Witness::*;
    match (new, prior) {
        (
            Sidon {
                n: n1, points: p1, ..
            },
            Sidon {
                n: n2, points: p2, ..
            },
        ) => {
            if n1 != n2 {
                return Err(format!("different n ({n1} vs {n2}); not comparable"));
            }
            Ok(p1.len() > p2.len())
        }
        (Golomb { marks: m1, .. }, Golomb { marks: m2, .. }) => Ok(m1.len() > m2.len()),
        (BalancedColoring { n: n1, r: r1, .. }, BalancedColoring { n: n2, r: r2, .. }) => {
            if r1 != r2 {
                return Err(format!("different r ({r1} vs {r2}); not comparable"));
            }
            Ok(n1 > n2)
        }
        (IntervalProduct { p: p1, cuts: c1 }, IntervalProduct { p: p2, cuts: c2 }) => {
            if p1 == p2 {
                Ok(c1.len() > c2.len())
            } else {
                // a longer chain at ANY prime is a new k-record
                Ok(c1.len() > c2.len())
            }
        }
        _ => Err(format!(
            "no dominance order defined between {} and {}",
            new.kind(),
            prior.kind()
        )),
    }
}

pub fn verify_witness(witness: &Witness) -> VerifyResult {
    match witness {
        Witness::Sidon {
            n,
            points,
            claimed_size,
        } => with_size(verify_sidon(points, *n), points.len(), *claimed_size),
        Witness::Golomb { marks } => verify_golomb(marks),
        Witness::Cap {
            n,
            points,
            claimed_size,
        } => with_size(verify_cap(points, *n), points.len(), *claimed_size),
        Witness::Bh {
            n,
            h,
            points,
            claimed_size,
        } => with_size(verify_bh(points, *n, *h), points.len(), *claimed_size),
        Witness::Covering { v, k, t, blocks } => verify_covering(blocks, *v, *k, *t),
        Witness::IntervalProduct { p, cuts } => verify_interval_product(*p, cuts),
        Witness::BalancedColoring { n, r, edge_colors } => {
            verify_balanced_coloring(*n, *r, edge_colors)
        }
        Witness::CrtPartialCover { m, rows } => verify_crt_partial_cover(m, rows),
        Witness::KummerNoCarry { entries } => verify_kummer_no_carry(entries),
        Witness::MinBinomGcd { cases } => verify_min_binom_gcd(cases),
        Witness::BinomDeficiency { entries } => verify_binom_deficiency(entries),
        Witness::BinomExceptionEnum { k_max, exceptions } => {
            verify_binom_exception_enum(*k_max, exceptions)
        }
        Witness::UnsatCert { cnf, proof } => verify_unsat_cert(cnf, proof),
        Witness::ConstantWeight {
            n,
            d,
            w,
            words,
            claimed_size,
        } => with_size(
            verify_constant_weight(words, *n, *d, *w),
            words.len(),
            *claimed_size,
        ),
        Witness::Costas { perm } => verify_costas(perm),
        Witness::LinearCode {
            q,
            claimed_d,
            generator,
        } => verify_linear_code(generator, *q, *claimed_d),
    }
}

/// Fold a `claimed_size` cross-check into a verifier result: the witness
/// must pass AND have exactly the claimed number of elements.
fn with_size(mut r: VerifyResult, actual: usize, claimed: Option<usize>) -> VerifyResult {
    if r.ok
        && let Some(c) = claimed
    {
        if actual != c {
            return VerifyResult::fail(format!(
                "verifier passed but construction size {actual} != claimed_size {c}"
            ));
        }
        r.message = format!("{} (size {actual} = claimed)", r.message);
    }
    r
}

// --- combinatorial verifiers ---------------------------------------------

fn binary_points_ok(points: &[Vec<i64>], n: usize) -> Option<VerifyResult> {
    let set: HashSet<&Vec<i64>> = points.iter().collect();
    if set.len() != points.len() {
        return Some(VerifyResult::fail("duplicate points"));
    }
    if !points
        .iter()
        .all(|p| p.len() == n && p.iter().all(|&x| x == 0 || x == 1))
    {
        return Some(VerifyResult::fail(format!("points not binary length-{n}")));
    }
    None
}

/// A Sidon subset of `{0,1}^n` under componentwise integer addition: all
/// pairwise sums `a+b` (`a <= b`) distinct.
pub fn verify_sidon(points: &[Vec<i64>], n: usize) -> VerifyResult {
    if let Some(bad) = binary_points_ok(points, n) {
        return bad;
    }
    let m = points.len();
    let mut sums: HashSet<Vec<i64>> = HashSet::new();
    let mut count = 0usize;
    for i in 0..m {
        for j in i..m {
            let s: Vec<i64> = (0..n).map(|k| points[i][k] + points[j][k]).collect();
            if !sums.insert(s) {
                return VerifyResult::fail("pairwise-sum collision (not Sidon)");
            }
            count += 1;
        }
    }
    VerifyResult::ok(format!(
        "Sidon verified: {m} points, {count} pairwise sums all distinct"
    ))
}

/// A Golomb ruler: integer marks with all `C(m,2)` pairwise differences
/// distinct.
/// Verify an Erdős #1056 cut-equality certificate: a prime `p` and
/// strictly increasing cuts `c_0 < ... < c_k` such that every consecutive
/// interval `(c_{i-1}, c_i]` has integer product `== 1 (mod p)`. Pure
/// modular arithmetic — deterministic and total, no search.
/// Erdős #617 witness shape: a balanced r-coloring of K_n. Checks that
/// every edge {i,j} (i<j, 0-indexed) is colored in 1..=r and that every
/// (r+1)-subset of vertices sees ALL r colors among its internal edges.
pub fn verify_balanced_coloring(
    n: usize,
    r: usize,
    edge_colors: &std::collections::BTreeMap<String, u32>,
) -> VerifyResult {
    if r < 2 || n < r + 1 {
        return VerifyResult::fail(format!("need r >= 2 and n >= r+1 (got n={n}, r={r})"));
    }
    // Dense lookup table from the string-keyed map.
    let mut color = vec![vec![0u32; n]; n];
    for (key, &c) in edge_colors {
        let Some((a, b)) = key.split_once(',') else {
            return VerifyResult::fail(format!("bad edge key '{key}' (want \"i,j\")"));
        };
        let (Ok(i), Ok(j)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) else {
            return VerifyResult::fail(format!("bad edge key '{key}'"));
        };
        if i >= n || j >= n || i >= j {
            return VerifyResult::fail(format!("edge '{key}' out of range or not i<j for n={n}"));
        }
        if c == 0 || c as usize > r {
            return VerifyResult::fail(format!("edge '{key}' color {c} outside 1..={r}"));
        }
        color[i][j] = c;
    }
    for (i, row) in color.iter().enumerate() {
        for (j, &c) in row.iter().enumerate().skip(i + 1) {
            if c == 0 {
                return VerifyResult::fail(format!("edge {i},{j} is uncolored"));
            }
        }
    }
    // Every (r+1)-subset must see all r colors. Iterate subsets via a
    // simple combinations walker (k = r+1).
    let k = r + 1;
    let mut idx: Vec<usize> = (0..k).collect();
    let mut checked = 0u64;
    loop {
        let mut seen = vec![false; r + 1];
        for x in 0..k {
            for y in (x + 1)..k {
                seen[color[idx[x]][idx[y]] as usize] = true;
            }
        }
        if let Some(missing) = (1..=r).find(|&c| !seen[c]) {
            return VerifyResult::fail(format!("subset {:?} sees no edge of color {missing}", idx));
        }
        checked += 1;
        // next combination
        let mut pos = k;
        while pos > 0 {
            pos -= 1;
            if idx[pos] != pos + n - k {
                idx[pos] += 1;
                for q in (pos + 1)..k {
                    idx[q] = idx[q - 1] + 1;
                }
                break;
            }
            if pos == 0 {
                return VerifyResult::ok(format!(
                    "balanced {r}-coloring of K_{n} verified: {checked} {k}-subsets each see all {r} colors"
                ));
            }
        }
    }
}

pub fn verify_interval_product(p: u64, cuts: &[u64]) -> VerifyResult {
    if !is_prime(p) {
        return VerifyResult::fail(format!("modulus p={p} must be prime"));
    }
    if cuts.len() < 2 {
        return VerifyResult::fail("need at least two cuts (one interval)");
    }
    for w in cuts.windows(2) {
        if w[0] >= w[1] {
            return VerifyResult::fail("cuts must be strictly increasing");
        }
    }
    for w in cuts.windows(2) {
        let mut prod: u64 = 1;
        for m in (w[0] + 1)..=w[1] {
            prod = ((prod as u128 * (m % p) as u128) % p as u128) as u64;
        }
        if prod != 1 {
            return VerifyResult::fail(format!(
                "interval ({}, {}] has product {prod} mod {p} != 1",
                w[0], w[1]
            ));
        }
    }
    VerifyResult::ok(format!(
        "Erdos #1056 certificate: prime p={p}, {} consecutive interval(s) each with product 1 mod p",
        cuts.len() - 1
    ))
}

// --- shared exact number theory -------------------------------------------

/// Number of carries when adding `a + b` in base `p` (Kummer's theorem:
/// this equals `v_p(C(a+b, a))`).
fn carries_base_p(mut a: u128, mut b: u128, p: u128) -> u64 {
    let mut carry: u128 = 0;
    let mut count: u64 = 0;
    while a > 0 || b > 0 || carry > 0 {
        let s = a % p + b % p + carry;
        carry = u128::from(s >= p);
        count += carry as u64;
        a /= p;
        b /= p;
    }
    count
}

/// Legendre: `v_p(n!)`.
fn vp_factorial(n: u64, p: u64) -> u64 {
    let mut s = 0u64;
    let mut pk = p;
    while pk <= n {
        s += n / pk;
        pk = pk.saturating_mul(p);
    }
    s
}

/// `v_p(C(n, k))` via Legendre.
fn vp_binom(n: u64, k: u64, p: u64) -> u64 {
    vp_factorial(n, p) - vp_factorial(k, p) - vp_factorial(n - k, p)
}

/// `v_p(n)` for `n >= 1`.
fn vp_of(mut n: u64, p: u64) -> u64 {
    let mut v = 0u64;
    while n.is_multiple_of(p) {
        n /= p;
        v += 1;
    }
    v
}

fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

/// Primes up to `n` inclusive (trial division; `n` is small here).
fn primes_upto(n: u64) -> Vec<u64> {
    (2..=n).filter(|&q| is_prime(q)).collect()
}

/// Parse a decimal string into u128 (guard: 1..=38 digits, all ASCII).
fn parse_decimal_u128(s: &str) -> Result<u128, String> {
    if s.is_empty() || s.len() > 38 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("`{s}` is not a 1..=38 digit decimal string"));
    }
    s.parse::<u128>().map_err(|e| format!("parse `{s}`: {e}"))
}

/// A decimal string mod a small modulus, by digit streaming — handles
/// integers far beyond u128 without big-int arithmetic.
fn decimal_mod(s: &str, m: u64) -> Result<u64, String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("`{s}` is not a decimal string"));
    }
    let mut acc: u64 = 0;
    for b in s.bytes() {
        acc = (acc * 10 + u64::from(b - b'0')) % m;
    }
    Ok(acc)
}

/// Multiplicative order of `base` mod prime `p` (`base` not divisible
/// by `p`); iterates at most `p - 1` steps.
fn multiplicative_order(base: u64, p: u64) -> Result<u64, String> {
    if base.is_multiple_of(p) {
        return Err(format!("{base} is 0 mod {p}; order undefined"));
    }
    let mut acc = base % p;
    let mut ord = 1u64;
    while acc != 1 {
        acc = acc * base % p;
        ord += 1;
        if ord >= p {
            return Err(format!("order of {base} mod {p} did not divide p-1"));
        }
    }
    Ok(ord)
}

// --- Erdős #203: partial CRT cover ----------------------------------------

/// Verify an Erdős #203 partial CRT covering certificate. `m` is a
/// decimal string coprime to 6; each row pins a prime `p`, the orders of
/// 2 and 3 mod `p`, `h = lcm(ord2, ord3)`, `t_p = (-m^-1) mod p`,
/// `m mod p`, and an affine line such that `p | 2^k 3^l m + 1` iff
/// `alpha*k + beta*l == gamma (mod h)` — checked exhaustively over
/// `(k, l) in [0, h)^2`. Deterministic and total.
pub fn verify_crt_partial_cover(m: &str, rows: &[CrtCoverRow]) -> VerifyResult {
    if rows.is_empty() {
        return VerifyResult::fail("need at least one prime row");
    }
    match (decimal_mod(m, 2), decimal_mod(m, 3)) {
        (Ok(r2), Ok(r3)) => {
            if r2 == 0 || r3 == 0 {
                return VerifyResult::fail("m must be coprime to 6");
            }
        }
        (Err(e), _) | (_, Err(e)) => return VerifyResult::fail(e),
    }
    for row in rows {
        let p = row.p;
        if !(5..=1_000_000).contains(&p) || !is_prime(p) {
            return VerifyResult::fail(format!("row p={p} must be a prime in [5, 10^6]"));
        }
        let ord2 = match multiplicative_order(2, p) {
            Ok(v) => v,
            Err(e) => return VerifyResult::fail(e),
        };
        let ord3 = match multiplicative_order(3, p) {
            Ok(v) => v,
            Err(e) => return VerifyResult::fail(e),
        };
        if ord2 != row.ord2 || ord3 != row.ord3 {
            return VerifyResult::fail(format!(
                "row p={p}: ord(2)={ord2}, ord(3)={ord3} != claimed ({}, {})",
                row.ord2, row.ord3
            ));
        }
        let h = ord2 / gcd_u64(ord2, ord3) * ord3;
        if h != row.h || row.line[3] != h {
            return VerifyResult::fail(format!(
                "row p={p}: lcm(ord2, ord3)={h} != claimed h={} / line modulus {}",
                row.h, row.line[3]
            ));
        }
        if h > 5_000 {
            return VerifyResult::fail(format!("row p={p}: h={h} exceeds the 5000 guard"));
        }
        let mm = match decimal_mod(m, p) {
            Ok(v) => v,
            Err(e) => return VerifyResult::fail(e),
        };
        if mm != row.m_mod_p || mm == 0 {
            return VerifyResult::fail(format!(
                "row p={p}: m mod p = {mm} != claimed {} (and must be nonzero)",
                row.m_mod_p
            ));
        }
        let t = (p - mod_pow(mm, p - 2, p)) % p;
        if t != row.t_p {
            return VerifyResult::fail(format!(
                "row p={p}: (-m^-1) mod p = {t} != claimed t_p={}",
                row.t_p
            ));
        }
        let (al, be, ga) = (row.line[0], row.line[1], row.line[2]);
        for k in 0..h {
            for l in 0..h {
                let lhs = (mod_pow(2, k, p) * mod_pow(3, l, p) % p * mm % p + 1).is_multiple_of(p);
                let rhs = (al * k + be * l) % h == ga % h; // affine line mod h
                if lhs != rhs {
                    return VerifyResult::fail(format!(
                        "row p={p}: congruence line fails at (k, l) = ({k}, {l})"
                    ));
                }
            }
        }
    }
    VerifyResult::ok(format!(
        "Erdos #203 partial CRT cover: m coprime to 6, {} prime row(s) verified (p | 2^k 3^l m + 1 <=> affine line mod h)",
        rows.len()
    ))
}

// --- Erdős #684: Kummer no-carry lower bound -------------------------------

/// Verify an Erdős #684 certificate: for each `(k, m)`, recompute
/// `m = prod_{p<=k} p^(floor(log_p k)+1)` and confirm zero Kummer carries
/// adding `j + (m-1-j)` in base `p` for all `2 <= j <= k`, `p <= j` —
/// hence no prime `p <= j` divides `C(m-1, j)` and `f(m-1) > k`.
pub fn verify_kummer_no_carry(entries: &[KummerEntry]) -> VerifyResult {
    if entries.is_empty() {
        return VerifyResult::fail("need at least one (k, m) entry");
    }
    for e in entries {
        let k = e.k;
        if !(3..=20).contains(&k) {
            return VerifyResult::fail(format!("k={k} outside the [3, 20] guard"));
        }
        let mut m: u64 = 1;
        for p in primes_upto(k) {
            let mut pe = 1u64;
            let mut exp = 0u64;
            while pe * p <= k {
                pe *= p;
                exp += 1;
            }
            for _ in 0..=exp {
                m = match m.checked_mul(p) {
                    Some(v) => v,
                    None => return VerifyResult::fail(format!("M_{k} overflows u64")),
                };
            }
        }
        if m != e.m {
            return VerifyResult::fail(format!("k={k}: recomputed M_k={m} != claimed {}", e.m));
        }
        let n = m - 1;
        for j in 2..=k {
            for p in primes_upto(j) {
                if carries_base_p(u128::from(j), u128::from(n - j), u128::from(p)) != 0 {
                    return VerifyResult::fail(format!(
                        "k={k}: carry adding {j} + (M-1-{j}) base {p} — C(M-1, {j}) not p-free"
                    ));
                }
            }
        }
    }
    VerifyResult::ok(format!(
        "Erdos #684 certificate: f(M_k - 1) > k verified for {} value(s) of k (zero Kummer carries)",
        entries.len()
    ))
}

// --- Erdős #700: min gcd(n, C(n,k)) ----------------------------------------

/// Verify an Erdős #700 value certificate: for each `(n, f)`, recompute
/// `f(n) = min_{1<k<=n/2} gcd(n, C(n,k))` via the Kummer identity
/// `gcd(n, C(n,k)) = prod_{p|n} p^min(v_p(n), carries_p(k, n-k))`.
pub fn verify_min_binom_gcd(cases: &[MinGcdCase]) -> VerifyResult {
    if cases.is_empty() {
        return VerifyResult::fail("need at least one (n, f) case");
    }
    for c in cases {
        let n = c.n;
        if !(4..=10_000).contains(&n) {
            return VerifyResult::fail(format!("n={n} outside the [4, 10000] guard"));
        }
        let mut factors: Vec<(u64, u64)> = Vec::new();
        let mut rem = n;
        let mut p = 2u64;
        while p * p <= rem {
            if rem.is_multiple_of(p) {
                factors.push((p, vp_of(rem, p)));
                while rem.is_multiple_of(p) {
                    rem /= p;
                }
            }
            p += 1;
        }
        if rem > 1 {
            factors.push((rem, 1));
        }
        let mut best = u64::MAX;
        for k in 2..=n / 2 {
            let mut g = 1u64;
            for &(p, vn) in &factors {
                let carries = carries_base_p(u128::from(k), u128::from(n - k), u128::from(p));
                g *= p.pow(vn.min(carries) as u32);
            }
            best = best.min(g);
        }
        if best != c.f {
            return VerifyResult::fail(format!("n={n}: recomputed f(n)={best} != claimed {}", c.f));
        }
    }
    VerifyResult::ok(format!(
        "Erdos #700 certificate: f(n) = min gcd(n, C(n,k)) verified for {} case(s)",
        cases.len()
    ))
}

// --- Erdős #1093: ELS93 deficiency -----------------------------------------

/// Does `x | i * C(k, i)`? Every prime factor of `i * C(k, i)` is `<= k`,
/// so trial-divide `x` by primes `<= k`; a residual `> 1` means no.
/// Otherwise check `v_p(i) + v_p(C(k,i)) >= e` for each `p^e || x` —
/// `i * C(k, i)` itself is never materialized.
fn divides_smooth(mut x: u128, i: u64, k: u64) -> bool {
    for p in primes_upto(k) {
        if x == 1 {
            break;
        }
        let pp = u128::from(p);
        let mut e = 0u64;
        while x.is_multiple_of(pp) {
            x /= pp;
            e += 1;
        }
        if e > 0 && vp_of(i, p) + vp_binom(k, i, p) < e {
            return false;
        }
    }
    x == 1
}

/// Verify an Erdős #1093 (ELS93) deficiency certificate: each entry's
/// `C(N,k)` is Kummer-defined and `delta(N,k)` (and slot positions, when
/// given) recompute exactly. `N` may be up to 38 decimal digits.
pub fn verify_binom_deficiency(entries: &[DeficiencyEntry]) -> VerifyResult {
    if entries.is_empty() {
        return VerifyResult::fail("need at least one entry");
    }
    for e in entries {
        let k = e.k;
        if !(2..=150).contains(&k) {
            return VerifyResult::fail(format!("k={k} outside the [2, 150] guard"));
        }
        let n = match parse_decimal_u128(&e.n) {
            Ok(v) => v,
            Err(err) => return VerifyResult::fail(err),
        };
        if n < 2 * u128::from(k) {
            return VerifyResult::fail(format!("entry k={k}: need N >= 2k"));
        }
        for p in primes_upto(k) {
            if carries_base_p(u128::from(k), n - u128::from(k), u128::from(p)) != 0 {
                return VerifyResult::fail(format!(
                    "entry k={k}: prime {p} divides C(N,k) — not Kummer-defined"
                ));
            }
        }
        let mut slots: Vec<u64> = Vec::new();
        for i in 1..=k {
            let x = n - u128::from(k) + u128::from(i);
            if divides_smooth(x, i, k) {
                slots.push(i);
            }
        }
        if slots.len() as u64 != e.delta {
            return VerifyResult::fail(format!(
                "entry k={k}: recomputed delta={} != claimed {}",
                slots.len(),
                e.delta
            ));
        }
        if let Some(claimed) = &e.slots
            && &slots != claimed
        {
            return VerifyResult::fail(format!(
                "entry k={k}: smooth slots {slots:?} != claimed {claimed:?}"
            ));
        }
    }
    VerifyResult::ok(format!(
        "Erdos #1093 deficiency certificate: {} entr(ies) Kummer-defined with delta and slots recomputed exactly",
        entries.len()
    ))
}

// --- Erdős #1094: exception enumeration ------------------------------------

/// `C(k, r)` for `k <= 40` — exact in u64.
fn binom_u64(k: u64, r: u64) -> u64 {
    let r = r.min(k - r);
    let mut res = 1u64;
    for i in 1..=r {
        res = res * (k - r + i) / i;
    }
    res
}

/// All divisors of `g`, where `g | lcm(1..k)` so every prime factor is
/// `<= k`. Returns None if `g` does not fully factor over primes `<= k`
/// or the divisor count exceeds the guard.
fn divisors_smooth(g: u64, k: u64) -> Option<Vec<u64>> {
    let mut rem = g;
    let mut pf: Vec<(u64, u64)> = Vec::new();
    for p in primes_upto(k) {
        if rem.is_multiple_of(p) {
            pf.push((p, vp_of(rem, p)));
            while rem.is_multiple_of(p) {
                rem /= p;
            }
        }
    }
    if rem != 1 {
        return None;
    }
    let mut divs: Vec<u64> = vec![1];
    for (p, e) in pf {
        let prev = divs.clone();
        let mut pe = 1u64;
        for _ in 0..e {
            pe *= p;
            for d in &prev {
                divs.push(d * pe);
            }
        }
        if divs.len() > 200_000 {
            return None;
        }
    }
    Some(divs)
}

/// Is `(N, k)` a #1094 exception — no prime `p <= max(N/k, k)` divides
/// `C(N, k)`? Early-exits on the first dividing prime. Returns None
/// (fail-closed) if a candidate survives past the 10^7 prime guard
/// without a verdict — that can only happen for a would-be NEW
/// exception, where refusing to claim is the correct behavior.
fn is_exception_guarded(n: u64, k: u64) -> Option<bool> {
    let mut p = 2u64;
    // Condition `p <= max(N/k, k)` without floats: p <= k || p*k <= N.
    while p <= k || p.saturating_mul(k) <= n {
        if is_prime(p) && vp_binom(n, k, p) > 0 {
            return Some(false);
        }
        if p > 10_000_000 {
            return None;
        }
        p += 1;
    }
    Some(true)
}

/// Verify an Erdős #1094 exception-enumeration certificate: re-enumerate
/// every candidate `N = x + k - r` (`x | gcd(lcm(1..k), r*C(k,r))`,
/// `k | x`, `N >= 2k`) for `k <= k_max` and confirm the exception set
/// equals the claimed `(N, k)` list exactly.
pub fn verify_binom_exception_enum(k_max: u64, exceptions: &[(u64, u64)]) -> VerifyResult {
    if !(3..=40).contains(&k_max) {
        return VerifyResult::fail(format!("k_max={k_max} outside the [3, 40] guard"));
    }
    let claimed: std::collections::BTreeSet<(u64, u64)> = exceptions.iter().copied().collect();
    for &(n, k) in &claimed {
        if k > k_max || n < 2 * k {
            return VerifyResult::fail(format!(
                "claimed exception (N={n}, k={k}) outside k <= k_max / N >= 2k"
            ));
        }
    }
    let mut found: std::collections::BTreeSet<(u64, u64)> = std::collections::BTreeSet::new();
    let mut lambda: u64 = 1;
    let mut candidates: u64 = 0;
    for k in 2..=k_max {
        lambda = lambda / gcd_u64(lambda, k) * k;
        for r in 1..=k {
            let g = gcd_u64(lambda, r * binom_u64(k, r));
            let divs = match divisors_smooth(g, k) {
                Some(d) => d,
                None => {
                    return VerifyResult::fail(format!(
                        "divisor enumeration guard exceeded at k={k}, r={r}"
                    ));
                }
            };
            for x in divs {
                if !x.is_multiple_of(k) {
                    continue;
                }
                let n = x + k - r;
                if n < 2 * k {
                    continue;
                }
                candidates += 1;
                match is_exception_guarded(n, k) {
                    Some(true) => {
                        found.insert((n, k));
                    }
                    Some(false) => {}
                    None => {
                        return VerifyResult::fail(format!(
                            "exception test guard exceeded at (N={n}, k={k}) — refusing to claim"
                        ));
                    }
                }
            }
        }
    }
    if found != claimed {
        let extra: Vec<_> = found.difference(&claimed).collect();
        let missing: Vec<_> = claimed.difference(&found).collect();
        return VerifyResult::fail(format!(
            "exception set mismatch: extra {extra:?}, missing {missing:?}"
        ));
    }
    VerifyResult::ok(format!(
        "Erdos #1094 enumeration: {candidates} candidate(s) checked for k <= {k_max}; exception set of {} matches exactly",
        claimed.len()
    ))
}

// --- UNSAT certificate (LRAT / RUP) ----------------------------------------

/// Check that adding clause `c` is justified by reverse unit propagation
/// over the antecedent `hints` (in order) against `db`. Returns true iff
/// propagating `¬c` through the hinted clauses reaches a conflict — i.e.
/// `c` is RUP-implied by the current clause set. Hints that are satisfied,
/// non-unit, or unknown are rejected (a malformed proof never passes).
/// RAT check on the step's FIRST literal (the LRAT convention): the
/// step is a Resolution Asymmetric Tautology iff for every db clause D
/// containing the negated pivot, the resolvent (step ∪ D minus the
/// pivot pair) is RUP using the hints the step supplies for D's id.
/// Tautological resolvents pass vacuously. A clause with -pivot that
/// has no supplied hints fails the whole step — nothing is guessed.
fn rat_check(step: &LratStep, db: &std::collections::HashMap<u64, Vec<i64>>) -> bool {
    let Some(&pivot) = step.literals.first() else {
        return false; // the empty clause can never be RAT
    };
    let supplied: std::collections::HashMap<u64, &Vec<u64>> =
        step.rat_hints.iter().map(|(id, h)| (*id, h)).collect();
    for (&cid, clause) in db {
        if !clause.contains(&-pivot) {
            continue;
        }
        let mut resolvent: Vec<i64> = step.literals.clone();
        for &l in clause {
            if l != -pivot && l != 0 && !resolvent.contains(&l) {
                resolvent.push(l);
            }
        }
        if resolvent.iter().any(|&l| resolvent.contains(&-l) && l > 0) {
            continue; // tautological resolvent: vacuously implied
        }
        let Some(hints) = supplied.get(&cid) else {
            return false;
        };
        if !rup_checks(&resolvent, hints, db) {
            return false;
        }
    }
    true
}

fn rup_checks(c: &[i64], hints: &[u64], db: &std::collections::HashMap<u64, Vec<i64>>) -> bool {
    // Falsify every literal of c: var |l| takes the value that makes l false.
    let mut assign: std::collections::HashMap<i64, bool> = std::collections::HashMap::new();
    for &l in c {
        if l == 0 {
            return false;
        }
        let v = l.abs();
        let want = l < 0; // l<0 ⇒ var true makes l false
        if let Some(&prev) = assign.get(&v)
            && prev != want
        {
            return false; // c is a tautology (l and ¬l) — not a real clause
        }
        assign.insert(v, want);
    }
    for &h in hints {
        let Some(cl) = db.get(&h) else {
            return false; // unknown antecedent
        };
        let mut unassigned: Vec<i64> = Vec::new();
        let mut satisfied = false;
        for &l in cl {
            if l == 0 {
                continue;
            }
            match assign.get(&l.abs()) {
                None => unassigned.push(l),
                Some(&val) => {
                    // l true under assign? l>0 wants var true; l<0 wants var false.
                    if (l > 0) == val {
                        satisfied = true;
                    }
                }
            }
        }
        if satisfied {
            return false; // a satisfied antecedent can neither propagate nor conflict
        }
        match unassigned.len() {
            0 => return true, // all literals falsified ⇒ conflict ⇒ c is RUP
            1 => {
                let l = unassigned[0];
                assign.insert(l.abs(), l > 0); // propagate the forced literal
            }
            _ => return false, // not unit ⇒ this hint cannot fire
        }
    }
    false // ran out of hints without a conflict
}

/// Verify an UNSAT certificate: replay the LRAT proof over the CNF and
/// confirm it derives the empty clause. Each step's added clause must be
/// RUP-implied by the clauses available so far (original + previously
/// added). Deterministic and total; bounded by explicit guards.
pub fn verify_unsat_cert(cnf: &[Vec<i64>], proof: &[LratStep]) -> VerifyResult {
    if cnf.is_empty() {
        return VerifyResult::fail("empty CNF: nothing to refute");
    }
    if cnf.len() > 5_000_000 || proof.len() > 20_000_000 {
        return VerifyResult::fail("certificate exceeds the size guard");
    }
    let mut db: std::collections::HashMap<u64, Vec<i64>> = std::collections::HashMap::new();
    for (i, clause) in cnf.iter().enumerate() {
        let id = (i + 1) as u64; // original clauses are 1-indexed
        if db.insert(id, clause.clone()).is_some() {
            return VerifyResult::fail(format!("duplicate clause id {id}"));
        }
    }
    let mut derived_empty = false;
    for step in proof {
        if step.id == 0 {
            return VerifyResult::fail("proof clause id 0 is reserved");
        }
        if !rup_checks(&step.literals, &step.hints, &db) && !rat_check(step, &db) {
            return VerifyResult::fail(format!(
                "LRAT step {} is neither RUP-implied nor RAT on its first literal",
                step.id
            ));
        }
        let empty = step.literals.is_empty();
        if db.insert(step.id, step.literals.clone()).is_some() {
            return VerifyResult::fail(format!("clause id {} added twice", step.id));
        }
        if empty {
            derived_empty = true;
            break;
        }
    }
    if !derived_empty {
        return VerifyResult::fail("proof never derives the empty clause (UNSAT not established)");
    }
    VerifyResult::ok(format!(
        "UNSAT certificate: {} clause(s), {} LRAT step(s), empty clause derived by RUP",
        cnf.len(),
        proof.len()
    ))
}

pub fn verify_golomb(marks: &[i64]) -> VerifyResult {
    let set: HashSet<&i64> = marks.iter().collect();
    if set.len() != marks.len() {
        return VerifyResult::fail("duplicate marks");
    }
    let mut diffs: HashSet<i64> = HashSet::new();
    let mut count = 0usize;
    for i in 0..marks.len() {
        for j in (i + 1)..marks.len() {
            if !diffs.insert((marks[j] - marks[i]).abs()) {
                return VerifyResult::fail("repeated pairwise difference (not a Golomb ruler)");
            }
            count += 1;
        }
    }
    let (lo, hi) = (marks.iter().min().copied(), marks.iter().max().copied());
    let length = match (lo, hi) {
        (Some(a), Some(b)) => b - a,
        _ => 0,
    };
    VerifyResult::ok(format!(
        "Golomb ruler: {} marks, length {length}, all {count} differences distinct",
        marks.len()
    ))
}

/// A cap in `F_3^n`: no three distinct points sum to 0 mod 3 (no three
/// collinear). For each pair, the unique line-completion must be absent.
pub fn verify_cap(points: &[Vec<i64>], n: usize) -> VerifyResult {
    let set: HashSet<&Vec<i64>> = points.iter().collect();
    if set.len() != points.len() {
        return VerifyResult::fail("duplicate points");
    }
    if !points
        .iter()
        .all(|p| p.len() == n && p.iter().all(|&x| (0..=2).contains(&x)))
    {
        return VerifyResult::fail(format!("points not in (0,1,2)^{n}"));
    }
    let owned: HashSet<Vec<i64>> = points.iter().cloned().collect();
    let m = points.len();
    for i in 0..m {
        let a = &points[i];
        for b in points.iter().take(m).skip(i + 1) {
            let c: Vec<i64> = (0..n).map(|k| (-(a[k] + b[k])).rem_euclid(3)).collect();
            if owned.contains(&c) && &c != a && &c != b {
                return VerifyResult::fail("3 collinear points found (not a cap)");
            }
        }
    }
    VerifyResult::ok(format!(
        "cap verified: {m} points in F_3^{n}, no 3 collinear"
    ))
}

/// A `B_h` set in `{0,1}^n`: all sums of `h` elements (with repetition,
/// non-decreasing index order) distinct. `h = 2` is Sidon.
pub fn verify_bh(points: &[Vec<i64>], n: usize, h: usize) -> VerifyResult {
    if let Some(bad) = binary_points_ok(points, n) {
        return bad;
    }
    let m = points.len();
    if m == 0 || h == 0 {
        return VerifyResult::ok(format!("B_{h} verified: {m} points, 0 sums"));
    }
    let mut sums: HashSet<Vec<i64>> = HashSet::new();
    let mut count = 0usize;
    let mut idx = vec![0usize; h];
    loop {
        let mut s = vec![0i64; n];
        for &i in &idx {
            for k in 0..n {
                s[k] += points[i][k];
            }
        }
        if !sums.insert(s) {
            return VerifyResult::fail(format!("B_{h} violated: a repeated {h}-fold sum"));
        }
        count += 1;
        if !advance_with_replacement(&mut idx, m) {
            break;
        }
    }
    VerifyResult::ok(format!(
        "B_{h} verified: {m} points, {count} h-fold sums all distinct"
    ))
}

/// A covering design `C(v, k, t)`: blocks are `k`-subsets of `[0, v)`
/// such that every `t`-subset of `[0, v)` is contained in at least one.
pub fn verify_covering(blocks: &[Vec<usize>], v: usize, k: usize, t: usize) -> VerifyResult {
    let norm: Vec<Vec<usize>> = blocks
        .iter()
        .map(|b| {
            let s: std::collections::BTreeSet<usize> = b.iter().copied().collect();
            s.into_iter().collect()
        })
        .collect();
    if !norm
        .iter()
        .all(|b| b.len() == k && b.iter().all(|&x| x < v))
    {
        return VerifyResult::fail(format!("blocks not valid {k}-subsets of [0,{v})"));
    }
    let mut covered: HashSet<Vec<usize>> = HashSet::new();
    for b in &norm {
        each_combination(b.len(), t, &mut |sub| {
            covered.insert(sub.iter().map(|&i| b[i]).collect());
        });
    }
    let mut need = 0usize;
    let mut missing = 0usize;
    each_combination(v, t, &mut |sub| {
        need += 1;
        if !covered.contains(sub) {
            missing += 1;
        }
    });
    if missing > 0 {
        return VerifyResult::fail(format!(
            "not a covering: {missing} of {need} t-subsets uncovered"
        ));
    }
    VerifyResult::ok(format!(
        "valid C({v},{k},{t}) covering with {} blocks",
        norm.len()
    ))
}

/// A constant-weight binary code `A(n, d, w)`: codewords of weight
/// exactly `w`, pairwise Hamming distance `>= d`.
pub fn verify_constant_weight(words: &[Vec<i64>], n: usize, d: usize, w: usize) -> VerifyResult {
    let set: HashSet<&Vec<i64>> = words.iter().collect();
    if set.len() != words.len() {
        return VerifyResult::fail("duplicate codewords");
    }
    if !words
        .iter()
        .all(|c| c.len() == n && c.iter().all(|&x| x == 0 || x == 1))
    {
        return VerifyResult::fail(format!("words not binary length-{n}"));
    }
    if let Some(c) = words.iter().find(|c| c.iter().sum::<i64>() as usize != w) {
        return VerifyResult::fail(format!(
            "a codeword has weight {} != {w}",
            c.iter().sum::<i64>()
        ));
    }
    for i in 0..words.len() {
        for j in (i + 1)..words.len() {
            let dist = (0..n).filter(|&k| words[i][k] != words[j][k]).count();
            if dist < d {
                return VerifyResult::fail(format!("a pair has Hamming distance {dist} < {d}"));
            }
        }
    }
    VerifyResult::ok(format!(
        "constant-weight code A({n},{d},{w}): {} words, all weight {w}, min dist >= {d}",
        words.len()
    ))
}

/// A Costas array: a permutation `p` of consecutive integers such that
/// the displacement vectors `(j-i, p[j]-p[i])` for `i < j` are distinct.
pub fn verify_costas(perm: &[i64]) -> VerifyResult {
    let n = perm.len();
    let mut sorted = perm.to_vec();
    sorted.sort_unstable();
    let min = perm.iter().min().copied().unwrap_or(0);
    let expected: Vec<i64> = (0..n as i64).map(|i| min + i).collect();
    if sorted != expected {
        return VerifyResult::fail("not a permutation");
    }
    let mut vecs: HashSet<(i64, i64)> = HashSet::new();
    let mut count = 0usize;
    for i in 0..n {
        for j in (i + 1)..n {
            if !vecs.insert(((j - i) as i64, perm[j] - perm[i])) {
                return VerifyResult::fail("repeated displacement vector (not a Costas array)");
            }
            count += 1;
        }
    }
    VerifyResult::ok(format!(
        "Costas array of order {n} verified ({count} displacement vectors all distinct)"
    ))
}

/// A linear `[n, k, d]_q` code given by a `k x n` generator matrix over a
/// prime field `GF(q)`. Verifies `rank(G) = k` and that the true minimum
/// distance (min nonzero codeword weight, by exhaustive enumeration of
/// the `q^k` codewords, guarded) is `>= claimed_d`. Prime-power `GF(q)`
/// is refused rather than mis-verified.
// Frozen exact verifier: the range loops index multiple parallel arrays
// (codeword/weight); the explicit index is the faithful expression, not a
// refactor target.
#[allow(clippy::needless_range_loop)]
pub fn verify_linear_code(generator: &[Vec<i64>], q: u64, claimed_d: usize) -> VerifyResult {
    const MAX_ENUM: u64 = 1_000_000;
    if !is_prime(q) {
        return VerifyResult::fail(format!(
            "q={q} not prime; prime-power GF(q) not implemented — refusing to claim"
        ));
    }
    let k = generator.len();
    if k == 0 {
        return VerifyResult::fail("empty generator");
    }
    let n = generator[0].len();
    if !generator.iter().all(|row| row.len() == n) {
        return VerifyResult::fail("ragged generator matrix");
    }
    let g: Vec<Vec<u64>> = generator
        .iter()
        .map(|row| row.iter().map(|&x| x.rem_euclid(q as i64) as u64).collect())
        .collect();
    if gf_rank(&g, q) != k {
        return VerifyResult::fail(format!(
            "generator rank < k={k} (rows dependent — not an [n,{k}] code)"
        ));
    }
    let qk = (q).checked_pow(k as u32);
    match qk {
        Some(v) if v <= MAX_ENUM => {}
        _ => {
            return VerifyResult::fail(format!(
                "q^k exceeds enum guard {MAX_ENUM}; distance not exhaustively verifiable — refusing to claim"
            ));
        }
    }
    let qk = qk.unwrap();
    let mut dmin = n + 1;
    // Enumerate all nonzero message vectors msg in GF(q)^k.
    let mut msg = vec![0u64; k];
    for code in 1..qk {
        // decode `code` as a base-q digit vector
        let mut x = code;
        for m in msg.iter_mut() {
            *m = x % q;
            x /= q;
        }
        let mut weight = 0usize;
        for c in 0..n {
            let mut s = 0u64;
            for i in 0..k {
                if msg[i] != 0 {
                    s = (s + msg[i] * g[i][c]) % q;
                }
            }
            if s != 0 {
                weight += 1;
            }
        }
        if weight < dmin {
            dmin = weight;
        }
    }
    let ok = dmin >= claimed_d;
    let rel = if ok { ">=" } else { "<" };
    VerifyResult {
        ok,
        message: format!(
            "[{n},{k},{dmin}]_{q} verified (min weight {dmin} {rel} claimed {claimed_d})"
        ),
        value: Some(dmin as f64),
    }
}

// --- small numeric / combinatorial helpers -------------------------------

/// Advance an index tuple to the next combination-with-replacement over
/// `[0, m)`. Returns false when exhausted.
fn advance_with_replacement(idx: &mut [usize], m: usize) -> bool {
    let h = idx.len();
    let mut i = h;
    loop {
        if i == 0 {
            return false;
        }
        i -= 1;
        if idx[i] != m - 1 {
            let nv = idx[i] + 1;
            for slot in idx.iter_mut().take(h).skip(i) {
                *slot = nv;
            }
            return true;
        }
    }
}

/// Visit every strictly-increasing `t`-combination of indices in
/// `[0, n)`.
fn each_combination(n: usize, t: usize, f: &mut impl FnMut(&[usize])) {
    if t > n {
        return;
    }
    let mut idx: Vec<usize> = (0..t).collect();
    loop {
        f(&idx);
        // advance
        let mut i = t;
        loop {
            if i == 0 {
                return;
            }
            i -= 1;
            if idx[i] != i + n - t {
                idx[i] += 1;
                for j in (i + 1)..t {
                    idx[j] = idx[j - 1] + 1;
                }
                break;
            }
        }
    }
}

fn is_prime(q: u64) -> bool {
    if q < 2 {
        return false;
    }
    let mut p = 2u64;
    while p * p <= q {
        if q.is_multiple_of(p) {
            return false;
        }
        p += 1;
    }
    true
}

/// Rank over `GF(q)` (q prime) of an integer matrix (entries already
/// reduced mod q).
// Gaussian elimination over GF(q): the inner loops index two rows by the same
// column, so a range loop is the honest form (iterator pairs would obscure it).
#[allow(clippy::needless_range_loop)]
fn gf_rank(rows: &[Vec<u64>], q: u64) -> usize {
    let mut m: Vec<Vec<u64>> = rows.to_vec();
    if m.is_empty() {
        return 0;
    }
    let ncols = m[0].len();
    let mut rank = 0usize;
    for col in 0..ncols {
        let piv = (rank..m.len()).find(|&r| !m[r][col].is_multiple_of(q));
        let Some(piv) = piv else { continue };
        m.swap(rank, piv);
        let inv = mod_inv(m[rank][col] % q, q);
        for c in 0..ncols {
            m[rank][c] = (m[rank][c] * inv) % q;
        }
        for r in 0..m.len() {
            if r != rank && !m[r][col].is_multiple_of(q) {
                let f = m[r][col] % q;
                for c in 0..ncols {
                    m[r][c] = (m[r][c] + q - (f * m[rank][c]) % q) % q;
                }
            }
        }
        rank += 1;
        if rank == m.len() {
            break;
        }
    }
    rank
}

/// Modular inverse of `a` mod prime `q` via Fermat's little theorem.
fn mod_inv(a: u64, q: u64) -> u64 {
    mod_pow(a, q - 2, q)
}

fn mod_pow(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = (result * base) % modulus;
        }
        exp >>= 1;
        base = (base * base) % modulus;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // A genuine a(8) >= 33 Sidon witness fragment is large; use a small
    // hand-checked Sidon set for the unit test, plus corrupt-it checks.
    fn small_sidon() -> Vec<Vec<i64>> {
        // In {0,1}^3: {000, 100, 010, 001} — pairwise sums all distinct?
        // sums include 000,100,010,001 (i=j) and 110,101,011 (i<j) — all
        // distinct. A valid (small) Sidon set.
        vec![vec![0, 0, 0], vec![1, 0, 0], vec![0, 1, 0], vec![0, 0, 1]]
    }

    #[test]
    fn unsat_cert_accepts_rup_proofs_and_rejects_corruption() {
        // (x) ∧ (¬x): the empty clause is RUP from clauses 1, 2.
        let w = Witness::UnsatCert {
            cnf: vec![vec![1], vec![-1]],
            proof: vec![LratStep {
                id: 3,
                literals: vec![],
                hints: vec![1, 2],
                rat_hints: vec![],
            }],
        };
        assert!(verify_witness(&w).ok);
        // (a) ∧ (b) ∧ (¬a ∨ ¬b): empty clause RUP from 1, 2, 3.
        let w2 = Witness::UnsatCert {
            cnf: vec![vec![1], vec![2], vec![-1, -2]],
            proof: vec![LratStep {
                id: 4,
                literals: vec![],
                hints: vec![1, 2, 3],
                rat_hints: vec![],
            }],
        };
        assert!(verify_witness(&w2).ok);
        // Drop the conflict-producing antecedent → no conflict → rejected.
        let bad = Witness::UnsatCert {
            cnf: vec![vec![1], vec![2], vec![-1, -2]],
            proof: vec![LratStep {
                id: 4,
                literals: vec![],
                hints: vec![1, 2],
                rat_hints: vec![],
            }],
        };
        assert!(!verify_witness(&bad).ok);
        // A satisfiable CNF cannot derive the empty clause with any RUP step.
        let sat = Witness::UnsatCert {
            cnf: vec![vec![1, 2]],
            proof: vec![LratStep {
                id: 2,
                literals: vec![],
                hints: vec![1],
                rat_hints: vec![],
            }],
        };
        assert!(!verify_witness(&sat).ok);
    }

    #[test]
    fn crt_partial_cover_accepts_real_rows_and_rejects_corruption() {
        let m = "8168305011630835886634520238999";
        let rows = vec![
            CrtCoverRow {
                p: 5,
                ord2: 4,
                ord3: 4,
                h: 4,
                t_p: 1,
                m_mod_p: 4,
                line: [1, 3, 0, 4],
            },
            CrtCoverRow {
                p: 7,
                ord2: 3,
                ord3: 6,
                h: 6,
                t_p: 1,
                m_mod_p: 6,
                line: [2, 1, 0, 6],
            },
        ];
        assert!(verify_crt_partial_cover(m, &rows).ok);
        // Corrupt t_p.
        let mut bad = rows.clone();
        bad[0].t_p = 2;
        assert!(!verify_crt_partial_cover(m, &bad).ok);
        // Corrupt the affine line.
        let mut bad = rows.clone();
        bad[1].line = [2, 1, 1, 6];
        assert!(!verify_crt_partial_cover(m, &bad).ok);
        // m divisible by 3 is rejected.
        assert!(!verify_crt_partial_cover("9", &rows).ok);
    }

    #[test]
    fn kummer_no_carry_accepts_erdos684_table_and_rejects_corruption() {
        let entries = vec![
            KummerEntry { k: 3, m: 36 },
            KummerEntry { k: 7, m: 88200 },
            KummerEntry { k: 12, m: 64033200 },
        ];
        assert!(verify_kummer_no_carry(&entries).ok);
        // Wrong M_k.
        let bad = vec![KummerEntry { k: 3, m: 72 }];
        assert!(!verify_kummer_no_carry(&bad).ok);
        // Out of guard range.
        assert!(!verify_kummer_no_carry(&[KummerEntry { k: 25, m: 1 }]).ok);
    }

    #[test]
    fn min_binom_gcd_accepts_erdos700_cases_and_rejects_corruption() {
        let cases = vec![
            MinGcdCase { n: 30, f: 6 },
            MinGcdCase { n: 77, f: 7 },
            MinGcdCase { n: 49, f: 7 },
        ];
        assert!(verify_min_binom_gcd(&cases).ok);
        assert!(!verify_min_binom_gcd(&[MinGcdCase { n: 30, f: 5 }]).ok);
    }

    #[test]
    fn binom_deficiency_accepts_els93_row_and_rejects_corruption() {
        // ELS93 table row k=8, N=44: delta=2 at slots [4, 6].
        let good = DeficiencyEntry {
            k: 8,
            n: "44".to_string(),
            delta: 2,
            slots: Some(vec![4, 6]),
        };
        assert!(verify_binom_deficiency(&[good.clone()]).ok);
        // Count-only form.
        let count_only = DeficiencyEntry {
            slots: None,
            ..good.clone()
        };
        assert!(verify_binom_deficiency(&[count_only]).ok);
        // Wrong delta.
        let bad = DeficiencyEntry {
            delta: 1,
            slots: None,
            ..good.clone()
        };
        assert!(!verify_binom_deficiency(&[bad]).ok);
        // Wrong slots.
        let bad = DeficiencyEntry {
            slots: Some(vec![4, 7]),
            ..good
        };
        assert!(!verify_binom_deficiency(&[bad]).ok);
        // A big-N entry (the k=129 delta=1 example) exercises the u128 path.
        let big = DeficiencyEntry {
            k: 129,
            n: "3180883073384828665489".to_string(),
            delta: 1,
            slots: Some(vec![65]),
        };
        assert!(verify_binom_deficiency(&[big]).ok);
    }

    #[test]
    fn binom_exception_enum_matches_els_for_small_k_and_rejects_corruption() {
        // Re-derived ELS exceptions with k <= 8 (49 candidates).
        let els8: Vec<(u64, u64)> = vec![(7, 3), (13, 4), (14, 4), (23, 5), (62, 6), (44, 8)];
        assert!(verify_binom_exception_enum(8, &els8).ok);
        // Missing one exception fails.
        assert!(!verify_binom_exception_enum(8, &els8[1..]).ok);
        // A fabricated extra exception fails.
        let mut padded = els8.clone();
        padded.push((100, 5));
        assert!(!verify_binom_exception_enum(8, &padded).ok);
    }

    #[test]
    fn interval_product_accepts_erdos1056_example_and_rejects_corruption() {
        // erdosproblems.com/1056 example: p=11, cuts [2,4,7].
        // (3·4)=12≡1, (5·6·7)=210≡1 (mod 11).
        assert!(verify_interval_product(11, &[2, 4, 7]).ok);
        // A non-prime modulus is rejected.
        assert!(!verify_interval_product(12, &[2, 4, 7]).ok);
        // Perturb a cut so an interval product is no longer 1 mod p.
        assert!(!verify_interval_product(11, &[2, 4, 8]).ok);
        // Non-increasing cuts are rejected.
        assert!(!verify_interval_product(11, &[4, 4, 7]).ok);
    }

    #[test]
    fn sidon_accepts_valid_and_rejects_corrupted() {
        assert!(verify_sidon(&small_sidon(), 3).ok);
        // Corrupt: add a 4th point that creates a sum collision.
        // 110 + 000 = 110 and 100 + 010 = 110 -> collision.
        let mut bad = small_sidon();
        bad.push(vec![1, 1, 0]);
        assert!(!verify_sidon(&bad, 3).ok, "corrupted Sidon must fail");
    }

    #[test]
    fn sidon_rejects_non_binary_and_dups() {
        assert!(!verify_sidon(&[vec![0, 2, 0]], 3).ok);
        assert!(!verify_sidon(&[vec![1, 0, 0], vec![1, 0, 0]], 3).ok);
    }

    #[test]
    fn claimed_size_mismatch_fails() {
        let w = Witness::Sidon {
            n: 3,
            points: small_sidon(),
            claimed_size: Some(99),
        };
        let r = verify_witness(&w);
        assert!(!r.ok, "claimed_size 99 != actual 4 must fail");
        assert!(r.message.contains("claimed_size"));
    }

    #[test]
    fn golomb_accepts_valid_and_rejects_corrupted() {
        // {0,1,4,6} is a perfect Golomb ruler (differences 1,4,6,3,5,2).
        assert!(verify_golomb(&[0, 1, 4, 6]).ok);
        // {0,1,2,4}: differences 1,2,4,1,... -> repeat -> fail.
        assert!(!verify_golomb(&[0, 1, 2, 4]).ok);
    }

    #[test]
    fn cap_accepts_valid_and_rejects_collinear() {
        // {0,1} along one axis in F_3^1 is a cap (need 3 for a line).
        assert!(verify_cap(&[vec![0], vec![1]], 1).ok);
        // {0,1,2} in F_3^1: 0+1+2 = 0 mod 3 -> collinear -> fail.
        assert!(!verify_cap(&[vec![0], vec![1], vec![2]], 1).ok);
    }

    #[test]
    fn bh_h2_matches_sidon() {
        assert!(verify_bh(&small_sidon(), 3, 2).ok);
        let mut bad = small_sidon();
        bad.push(vec![1, 1, 0]);
        assert!(!verify_bh(&bad, 3, 2).ok);
    }

    #[test]
    fn covering_accepts_full_and_rejects_gap() {
        // C(4,3,2): blocks {0,1,2},{0,1,3},{0,2,3},{1,2,3} cover every pair.
        let full = vec![vec![0, 1, 2], vec![0, 1, 3], vec![0, 2, 3], vec![1, 2, 3]];
        assert!(verify_covering(&full, 4, 3, 2).ok);
        // Drop a block: pair {2,3} only in {0,2,3} and {1,2,3}; remove both.
        let gap = vec![vec![0, 1, 2], vec![0, 1, 3]];
        assert!(!verify_covering(&gap, 4, 3, 2).ok);
    }

    #[test]
    fn constant_weight_checks_weight_and_distance() {
        // A(4,2,2): {1100, 0011} weight 2, distance 4 >= 2.
        let ok = vec![vec![1, 1, 0, 0], vec![0, 0, 1, 1]];
        assert!(verify_constant_weight(&ok, 4, 2, 2).ok);
        // wrong weight
        assert!(!verify_constant_weight(&[vec![1, 1, 1, 0]], 4, 2, 2).ok);
    }

    #[test]
    fn costas_accepts_valid_and_rejects_nonpermutation() {
        // {0,2,3,1} is a Costas array of order 4.
        assert!(verify_costas(&[0, 2, 3, 1]).ok);
        assert!(!verify_costas(&[0, 0, 1, 2]).ok);
    }

    #[test]
    fn linear_code_verifies_distance_and_refuses_nonprime() {
        // [3,1,3]_2 repetition code: generator [1,1,1], min weight 3.
        let g = vec![vec![1, 1, 1]];
        let r = verify_linear_code(&g, 2, 3);
        assert!(r.ok, "{}", r.message);
        // claim d=4 on a min-weight-3 code must fail.
        assert!(!verify_linear_code(&g, 2, 4).ok);
        // non-prime q refused.
        assert!(!verify_linear_code(&g, 4, 1).ok);
    }

    #[test]
    fn witness_serde_round_trip() {
        let w = Witness::Sidon {
            n: 3,
            points: small_sidon(),
            claimed_size: Some(4),
        };
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("\"kind\":\"sidon\""));
        let back: Witness = serde_json::from_str(&json).unwrap();
        assert_eq!(back, w);
        assert!(verify_witness(&back).ok);
    }
}

#[cfg(test)]
mod balanced_coloring_tests {
    use super::*;
    use std::collections::BTreeMap;

    fn pentagon_k5() -> BTreeMap<String, u32> {
        let pent = [(0, 1), (1, 2), (2, 3), (3, 4), (0, 4)];
        let mut ec = BTreeMap::new();
        for i in 0..5usize {
            for j in (i + 1)..5 {
                let c = if pent.contains(&(i, j)) { 1 } else { 2 };
                ec.insert(format!("{i},{j}"), c);
            }
        }
        ec
    }

    #[test]
    fn pentagon_coloring_is_balanced() {
        let r = verify_balanced_coloring(5, 2, &pentagon_k5());
        assert!(r.ok, "{}", r.message);
    }

    #[test]
    fn flipped_edge_breaks_balance() {
        let mut ec = pentagon_k5();
        ec.insert("0,1".to_string(), 2);
        let r = verify_balanced_coloring(5, 2, &ec);
        assert!(!r.ok);
    }

    #[test]
    fn dominates_orders_by_n_at_same_r() {
        let w5 = Witness::BalancedColoring {
            n: 5,
            r: 2,
            edge_colors: pentagon_k5(),
        };
        let w4 = Witness::BalancedColoring {
            n: 4,
            r: 2,
            edge_colors: BTreeMap::new(),
        };
        assert_eq!(dominates(&w5, &w4), Ok(true));
        assert_eq!(dominates(&w4, &w5), Ok(false));
    }
}

#[cfg(test)]
mod rat_tests {
    use super::*;

    /// cnf: (1 2)(-1 3)(2)(-2) — UNSAT via the unit pair. Step 5 adds
    /// the blocked clause (-1 -2): NOT RUP (clause (2) is satisfied
    /// under the falsifying assignment, blocking propagation) but RAT
    /// on pivot -1 — the only clause containing 1 is (1 2), whose
    /// resolvent {-1,-2,2} is tautological. Step 6 derives empty.
    fn rat_cert() -> (Vec<Vec<i64>>, Vec<LratStep>) {
        let cnf = vec![vec![1, 2], vec![-1, 3], vec![2], vec![-2]];
        let proof = vec![
            LratStep {
                id: 5,
                literals: vec![-1, -2],
                hints: vec![],
                rat_hints: vec![],
            },
            LratStep {
                id: 6,
                literals: vec![],
                hints: vec![3, 4],
                rat_hints: vec![],
            },
        ];
        (cnf, proof)
    }

    #[test]
    fn blocked_clause_step_verifies_as_rat() {
        let (cnf, proof) = rat_cert();
        let r = verify_unsat_cert(&cnf, &proof);
        assert!(r.ok, "{}", r.message);
    }

    #[test]
    fn rat_step_with_unhinted_resolvent_is_rejected() {
        // Add (1 -3) to the cnf: now clauses containing pivot-negation 1
        // are (1 2) [tautological resolvent, fine] AND (1 -3), whose
        // resolvent (-1 -2 -3) is NOT tautological and has no supplied
        // hints — the step must be refused, never guessed through.
        let (mut cnf, proof) = rat_cert();
        cnf.push(vec![1, -3]);
        let r = verify_unsat_cert(&cnf, &proof);
        assert!(!r.ok);
        assert!(
            r.message.contains("neither RUP-implied nor RAT"),
            "{}",
            r.message
        );
    }

    #[test]
    fn rat_with_supplied_resolvent_hints_verifies() {
        // Same extended cnf, but the step now supplies hints proving the
        // (1 -3) resolvent (-1 -2 -3) is RUP: falsify 1=T,2=T,3=T; then
        // clause (-2) [id 4] conflicts immediately.
        let (mut cnf, mut proof) = rat_cert();
        cnf.push(vec![1, -3]); // becomes clause id 5
        proof[0].id = 6;
        proof[0].rat_hints = vec![(5, vec![4])];
        proof[1].id = 7;
        let r = verify_unsat_cert(&cnf, &proof);
        assert!(r.ok, "{}", r.message);
    }
}
