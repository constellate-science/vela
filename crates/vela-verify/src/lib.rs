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
    fn ok(message: impl Into<String>) -> Self {
        Self { ok: true, message: message.into(), value: None }
    }
    fn fail(message: impl Into<String>) -> Self {
        Self { ok: false, message: message.into(), value: None }
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
        }
    }
}

/// Verify a witness against its exact verifier, plus the optional
/// `claimed_size` cross-check.
pub fn verify_witness(witness: &Witness) -> VerifyResult {
    match witness {
        Witness::Sidon { n, points, claimed_size } => {
            with_size(verify_sidon(points, *n), points.len(), *claimed_size)
        }
        Witness::Golomb { marks } => verify_golomb(marks),
        Witness::Cap { n, points, claimed_size } => {
            with_size(verify_cap(points, *n), points.len(), *claimed_size)
        }
        Witness::Bh { n, h, points, claimed_size } => {
            with_size(verify_bh(points, *n, *h), points.len(), *claimed_size)
        }
        Witness::Covering { v, k, t, blocks } => verify_covering(blocks, *v, *k, *t),
        Witness::ConstantWeight { n, d, w, words, claimed_size } => {
            with_size(verify_constant_weight(words, *n, *d, *w), words.len(), *claimed_size)
        }
        Witness::Costas { perm } => verify_costas(perm),
        Witness::LinearCode { q, claimed_d, generator } => {
            verify_linear_code(generator, *q, *claimed_d)
        }
    }
}

/// Fold a `claimed_size` cross-check into a verifier result: the witness
/// must pass AND have exactly the claimed number of elements.
fn with_size(mut r: VerifyResult, actual: usize, claimed: Option<usize>) -> VerifyResult {
    if r.ok {
        if let Some(c) = claimed {
            if actual != c {
                return VerifyResult::fail(format!(
                    "verifier passed but construction size {actual} != claimed_size {c}"
                ));
            }
            r.message = format!("{} (size {actual} = claimed)", r.message);
        }
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
    VerifyResult::ok(format!("cap verified: {m} points in F_3^{n}, no 3 collinear"))
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
    if !norm.iter().all(|b| b.len() == k && b.iter().all(|&x| x < v)) {
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
        if !covered.contains(&sub.to_vec()) {
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
        if q % p == 0 {
            return false;
        }
        p += 1;
    }
    true
}

/// Rank over `GF(q)` (q prime) of an integer matrix (entries already
/// reduced mod q).
fn gf_rank(rows: &[Vec<u64>], q: u64) -> usize {
    let mut m: Vec<Vec<u64>> = rows.to_vec();
    if m.is_empty() {
        return 0;
    }
    let ncols = m[0].len();
    let mut rank = 0usize;
    for col in 0..ncols {
        let piv = (rank..m.len()).find(|&r| m[r][col] % q != 0);
        let Some(piv) = piv else { continue };
        m.swap(rank, piv);
        let inv = mod_inv(m[rank][col] % q, q);
        for c in 0..ncols {
            m[rank][c] = (m[rank][c] * inv) % q;
        }
        for r in 0..m.len() {
            if r != rank && m[r][col] % q != 0 {
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
        vec![
            vec![0, 0, 0],
            vec![1, 0, 0],
            vec![0, 1, 0],
            vec![0, 0, 1],
        ]
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
