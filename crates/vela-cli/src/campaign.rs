//! The discovery engine: deterministic search for verifier-gated combinatorial
//! witnesses. Search *produces* candidate constructions; the frozen
//! `vela-verify` crate is the gate. No candidate ever leaves this module
//! unverified — `search` re-checks its own best find with `verify_witness`
//! before returning it, so a `Found` is always a witness the frozen verifier
//! accepts.
//!
//! Determinism is load-bearing (the substrate pins it everywhere else too): the
//! search draws from a seeded xorshift RNG, never system entropy, so
//! `(kind, n, h, restarts, seed)` reproduces the same witness bit-for-bit. This
//! is what lets a discovery be re-run and re-verified by anyone.
//!
//! Search is heuristic (greedy with randomized restarts, plus local search for
//! permutation kinds); it certifies LOWER bounds. It will match small/medium
//! cases and the less-explored sequences, and it will *under*-perform the
//! algebraic constructions behind the large Sidon terms — that is reported
//! honestly, never papered over.

use std::collections::HashSet;
use vela_verify::{Witness, verify_witness};

/// A verified construction found by the engine. `score` is the maximized
/// quantity (set size, or distinct-direction count for rook placements).
pub struct Found {
    pub witness: Witness,
    pub score: usize,
    pub iterations: u64,
}

/// Deterministic xorshift64* PRNG. Seeded, no system entropy — same seed
/// reproduces the same search, which is what makes a find re-runnable.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Avoid the xorshift fixed point at 0.
        let s = seed.wrapping_mul(0x9E3779B97F4A7C15);
        Self(if s == 0 { 0x9E3779B97F4A7C15 } else { s })
    }
    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    #[inline]
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    /// In-place Fisher-Yates shuffle.
    fn shuffle<T>(&mut self, v: &mut [T]) {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1);
            v.swap(i, j);
        }
    }
}

/// Run the discovery engine for one target. `kind` is the verifier kind
/// (`gf2_sidon`, `union_free`, `rook_directions`, `cap`, `sidon`, `bh`,
/// `golomb`, `costas`). `n`/`h` parameterize the target; `restarts` bounds the work;
/// `seed` fixes the draw. Returns the best verified witness, or `None` if the
/// engine found nothing checkable (and `Err` for an unsupported kind).
pub fn search(
    kind: &str,
    n: usize,
    h: usize,
    restarts: u64,
    seed: u64,
) -> Result<Option<Found>, String> {
    let mut rng = Rng::new(seed);
    let found = match kind {
        "gf2_sidon" => search_gf2_sidon(n, restarts, &mut rng),
        "union_free" => search_union_free(n, restarts, &mut rng),
        "rook_directions" => search_rook_directions(n, restarts, &mut rng),
        "cap" => search_cap(n, restarts, &mut rng),
        // Sidon is B_2; share the B_h constructor.
        "sidon" => search_bh(n, 2, restarts, &mut rng),
        "bh" => {
            if h < 2 {
                return Err("bh requires h >= 2".into());
            }
            search_bh(n, h, restarts, &mut rng)
        }
        "golomb" => search_golomb(n, restarts, &mut rng),
        "costas" => search_costas(n, restarts, &mut rng),
        other => {
            return Err(format!(
                "kind `{other}` is not searchable by the engine yet (searchable: gf2_sidon, union_free, rook_directions, cap, sidon, bh, golomb, costas)"
            ));
        }
    };
    // Re-check the engine's own output through the frozen verifier. A find that
    // does not verify is a search bug, not a discovery — surface it, never ship.
    if let Some(f) = &found {
        let r = verify_witness(&f.witness);
        if !r.ok {
            return Err(format!(
                "INTERNAL: engine produced an unverified {kind} witness (score {}): {}",
                f.score, r.message
            ));
        }
    }
    Ok(found)
}

// ---------------------------------------------------------------------------
// gf2_sidon — a Sidon set in GF(2)^n under XOR (OEIS A394031).
// A set is Sidon iff all pairwise XORs are distinct. Greedy: add an element iff
// every new pairwise XOR is fresh; randomized element order + restarts.
// ---------------------------------------------------------------------------
fn search_gf2_sidon(n: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    if !(1..=20).contains(&n) {
        return None; // 2^n element space; keep enumeration tractable.
    }
    let space = 1u64 << n;
    let mut best: Vec<u64> = Vec::new();
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        let mut order: Vec<u64> = (0..space).collect();
        rng.shuffle(&mut order);
        let mut set: Vec<u64> = Vec::new();
        let mut xors: HashSet<u64> = HashSet::new();
        for &x in &order {
            let mut addable = true;
            for &s in &set {
                let d = x ^ s;
                if d == 0 || xors.contains(&d) {
                    addable = false;
                    break;
                }
            }
            if addable {
                for &s in &set {
                    xors.insert(x ^ s);
                }
                set.push(x);
            }
        }
        if set.len() > best.len() {
            best = set;
        }
    }
    if best.is_empty() {
        return None;
    }
    let score = best.len();
    best.sort_unstable();
    Some(Found {
        witness: Witness::Gf2Sidon {
            elements: best,
            claimed_size: Some(score),
        },
        score,
        iterations,
    })
}

// ---------------------------------------------------------------------------
// union_free — nonempty subsets of {1..n}, no member equal to a union of a
// sub-collection of the others (OEIS A347025). Key fact: a candidate C is
// "covered" by a family iff the OR of all current members that are subsets of C
// already equals C. Greedy add guards both directions (C not covered; C does
// not make an existing member covered).
// ---------------------------------------------------------------------------
fn search_union_free(n: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    if !(1..=16).contains(&n) {
        return None;
    }
    let full = 1u32 << n;
    let is_sub = |a: u32, b: u32| (a & b) == a; // a subset of b
    // OR of every member strictly inside `c` (members of `fam` that are subsets
    // of c but not c itself).
    let cover = |fam: &[u32], c: u32| -> u32 {
        let mut u = 0u32;
        for &m in fam {
            if m != c && is_sub(m, c) {
                u |= m;
            }
        }
        u
    };
    let mut best: Vec<u32> = Vec::new();
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        let mut order: Vec<u32> = (1..full).collect();
        rng.shuffle(&mut order);
        let mut fam: Vec<u32> = Vec::new();
        for &c in &order {
            // (1) c must not already be a union of existing members.
            if cover(&fam, c) == c {
                continue;
            }
            // (2) adding c must not turn an existing superset d into a union.
            let mut breaks = false;
            for &d in &fam {
                if d != c && is_sub(c, d) {
                    // recompute d's cover with c present
                    let mut u = c;
                    for &m in &fam {
                        if m != d && is_sub(m, d) {
                            u |= m;
                        }
                    }
                    if u == d {
                        breaks = true;
                        break;
                    }
                }
            }
            if breaks {
                continue;
            }
            fam.push(c);
        }
        if fam.len() > best.len() {
            best = fam;
        }
    }
    if best.is_empty() {
        return None;
    }
    let score = best.len();
    best.sort_unstable();
    let sets: Vec<Vec<u32>> = best
        .iter()
        .map(|&m| {
            (0..n as u32)
                .filter(|b| (m >> b) & 1 == 1)
                .map(|b| b + 1) // 1-based elements
                .collect()
        })
        .collect();
    Some(Found {
        witness: Witness::UnionFree {
            n,
            sets,
            claimed_size: Some(score),
        },
        score,
        iterations,
    })
}

// ---------------------------------------------------------------------------
// rook_directions — n rooks (one per row), maximize distinct direction classes
// sorted(|Δcol|,|Δrow|)/gcd over all pairs (OEIS A321531). Randomized restarts
// + 2-swap hill-climbing on the column permutation.
// ---------------------------------------------------------------------------
fn gcd(mut a: i64, mut b: i64) -> i64 {
    a = a.abs();
    b = b.abs();
    while b != 0 {
        let t = a % b;
        a = b;
        b = t;
    }
    a
}

fn rook_directions_count(perm: &[i64]) -> usize {
    let n = perm.len();
    let mut classes: HashSet<(i64, i64)> = HashSet::new();
    for i in 0..n {
        for j in (i + 1)..n {
            let dr = (j as i64) - (i as i64); // > 0
            let dc = (perm[j] - perm[i]).abs();
            let g = gcd(dc, dr).max(1);
            let (a, b) = (dc / g, dr / g);
            let key = if a <= b { (a, b) } else { (b, a) };
            classes.insert(key);
        }
    }
    classes.len()
}

fn search_rook_directions(n: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    if !(2..=60).contains(&n) {
        return None;
    }
    let mut best_perm: Vec<i64> = (1..=n as i64).collect();
    let mut best_score = rook_directions_count(&best_perm);
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        let mut perm: Vec<i64> = (1..=n as i64).collect();
        rng.shuffle(&mut perm);
        // Steepest-ascent 2-opt: scan every transposition, apply the single best
        // improving swap, repeat to a local optimum. Then a few random kicks +
        // re-ascent to escape that optimum within the restart.
        let mut score = rook_directions_count(&perm);
        for _kick in 0..(6 + n / 2) {
            loop {
                let mut best_gain = 0i64;
                let (mut bi, mut bj) = (0usize, 0usize);
                for i in 0..n {
                    for j in (i + 1)..n {
                        perm.swap(i, j);
                        let s = rook_directions_count(&perm) as i64;
                        perm.swap(i, j);
                        if s - score as i64 > best_gain {
                            best_gain = s - score as i64;
                            bi = i;
                            bj = j;
                        }
                    }
                }
                if best_gain > 0 {
                    perm.swap(bi, bj);
                    score = (score as i64 + best_gain) as usize;
                } else {
                    break; // local optimum
                }
            }
            if score > best_score {
                best_score = score;
                best_perm = perm.clone();
            }
            // random double-kick to leave the basin
            for _ in 0..2 {
                let i = rng.below(n);
                let mut j = rng.below(n);
                if i == j {
                    j = (j + 1) % n;
                }
                perm.swap(i, j);
            }
            score = rook_directions_count(&perm);
        }
    }
    Some(Found {
        witness: Witness::RookDirections {
            n,
            perm: best_perm,
            claimed_directions: Some(best_score),
        },
        score: best_score,
        iterations,
    })
}

// ---------------------------------------------------------------------------
// cap — a cap set in F_3^n: no three distinct points collinear, equivalently no
// three distinct points summing to 0 mod 3 (OEIS A090245 / the FunSearch
// problem). Greedy: a point is addable iff it neither sits in the set nor
// completes a line through two existing points; on add, mark the third point of
// every new pair forbidden. Certifies a LOWER bound on the cap number.
// ---------------------------------------------------------------------------
fn search_cap(n: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    if !(1..=8).contains(&n) {
        return None; // 3^n point space; n<=8 (6561) stays tractable.
    }
    let pow3: Vec<usize> = (0..n).map(|i| 3usize.pow(i as u32)).collect();
    let space = 3usize.pow(n as u32);
    // The third collinear point of a, b in F_3^n: t_i = -(a_i + b_i) mod 3.
    let third = |a: usize, b: usize| -> usize {
        let mut t = 0usize;
        for (i, &p) in pow3.iter().enumerate() {
            let ai = (a / p) % 3;
            let bi = (b / p) % 3;
            t += ((3 - (ai + bi) % 3) % 3) * pow3[i];
        }
        t
    };
    let mut best: Vec<usize> = Vec::new();
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        let mut order: Vec<usize> = (0..space).collect();
        rng.shuffle(&mut order);
        let mut set: Vec<usize> = Vec::new();
        let mut inset = vec![false; space];
        let mut forbidden = vec![false; space];
        for &p in &order {
            if inset[p] || forbidden[p] {
                continue;
            }
            for &a in &set {
                forbidden[third(p, a)] = true;
            }
            set.push(p);
            inset[p] = true;
        }
        if set.len() > best.len() {
            best = set;
        }
    }
    if best.is_empty() {
        return None;
    }
    let score = best.len();
    best.sort_unstable();
    let points: Vec<Vec<i64>> = best
        .iter()
        .map(|&c| pow3.iter().map(|&p| ((c / p) % 3) as i64).collect())
        .collect();
    Some(Found {
        witness: Witness::Cap {
            n,
            points,
            claimed_size: Some(score),
        },
        score,
        iterations,
    })
}

// ---------------------------------------------------------------------------
// B_h in {0,1}^n — all h-fold sums (with repetition, as multisets) distinct;
// h = 2 is a Sidon set (OEIS A309370). Greedy over binary vectors: add a vector
// iff the full h-fold sum-multiset stays collision-free. Correct over fast: we
// recompute the sum-set on each trial add, which is fine at the sizes greedy
// reaches for the n we can enumerate.
// ---------------------------------------------------------------------------
fn vec_to_points(set: &[u64], n: usize) -> Vec<Vec<i64>> {
    set.iter()
        .map(|&m| (0..n).map(|b| ((m >> b) & 1) as i64).collect())
        .collect()
}

/// All h-fold sums (combinations with repetition) of the chosen vectors, each
/// encoded as the coordinate tuple. Returns None on the first collision.
fn bh_sumset_ok(set: &[u64], n: usize, h: usize) -> bool {
    let k = set.len();
    if k == 0 {
        return true;
    }
    // coordinate sums: each vector is a u64 bitmask; the h-fold sum is a vector
    // of small integers in [0, h]. Encode as Vec<u8> for hashing.
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    // iterate multisets of size h over indices 0..k (combinations w/ repetition)
    let mut idx = vec![0usize; h];
    loop {
        // build the coordinate sum for this multiset
        let mut coord = vec![0u8; n];
        for &ix in &idx {
            let m = set[ix];
            for (b, c) in coord.iter_mut().enumerate() {
                *c += ((m >> b) & 1) as u8;
            }
        }
        if !seen.insert(coord) {
            return false; // collision -> not B_h
        }
        // advance the non-decreasing index multiset
        let mut p = h;
        while p > 0 {
            p -= 1;
            if idx[p] < k - 1 {
                let v = idx[p] + 1;
                idx[p..h].fill(v);
                break;
            }
            if p == 0 {
                return true; // exhausted
            }
        }
        if h == 0 {
            return true;
        }
    }
}

fn search_bh(n: usize, h: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    if !(1..=18).contains(&n) || h < 2 {
        return None;
    }
    let space = 1u64 << n;
    let mut best: Vec<u64> = Vec::new();
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        let mut order: Vec<u64> = (0..space).collect();
        rng.shuffle(&mut order);
        let mut set: Vec<u64> = Vec::new();
        for &x in &order {
            set.push(x);
            if !bh_sumset_ok(&set, n, h) {
                set.pop();
            }
        }
        if set.len() > best.len() {
            best = set;
        }
    }
    if best.is_empty() {
        return None;
    }
    let score = best.len();
    best.sort_unstable();
    let points = vec_to_points(&best, n);
    let witness = if h == 2 {
        Witness::Sidon {
            n,
            points,
            claimed_size: Some(score),
        }
    } else {
        Witness::Bh {
            n,
            h,
            points,
            claimed_size: Some(score),
        }
    };
    Some(Found {
        witness,
        score,
        iterations,
    })
}

// ---------------------------------------------------------------------------
// Golomb ruler — integer marks with all pairwise differences distinct. Greedy
// from 0 with randomized next-mark choices; `n` is the target order (mark
// count). Reports the shortest ruler found of that order (best = min length).
// Heuristic: it will validate small orders and under-perform the known optimal
// rulers at larger orders.
// ---------------------------------------------------------------------------
fn search_golomb(order: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    if !(2..=40).contains(&order) {
        return None;
    }
    // length cap grows with order; optimal length ~ order^2.
    let cap = (order * order * 2).max(8) as i64;
    let mut best: Option<Vec<i64>> = None;
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        let mut marks: Vec<i64> = vec![0];
        let mut diffs: HashSet<i64> = HashSet::new();
        while marks.len() < order {
            // candidate next marks beyond the current max, in randomized order
            let cur_max = *marks.last().unwrap();
            let mut cands: Vec<i64> = ((cur_max + 1)..=cap).collect();
            rng.shuffle(&mut cands);
            let mut placed = false;
            for &c in &cands {
                let mut ok = true;
                let mut nd = Vec::with_capacity(marks.len());
                for &m in &marks {
                    let d = c - m;
                    if diffs.contains(&d) || nd.contains(&d) {
                        ok = false;
                        break;
                    }
                    nd.push(d);
                }
                if ok {
                    for d in nd {
                        diffs.insert(d);
                    }
                    marks.push(c);
                    placed = true;
                    break;
                }
            }
            if !placed {
                break; // dead end; restart
            }
        }
        if marks.len() == order {
            let len = *marks.last().unwrap();
            if best.as_ref().map(|b| len < *b.last().unwrap()).unwrap_or(true) {
                best = Some(marks);
            }
        }
    }
    best.map(|marks| Found {
        score: marks.len(),
        witness: Witness::Golomb { marks },
        iterations,
    })
}

// ---------------------------------------------------------------------------
// Costas array — a permutation whose displacement vectors are all distinct.
// Randomized restarts over permutations (existence search for order n).
// ---------------------------------------------------------------------------
fn is_costas(perm: &[i64]) -> bool {
    let n = perm.len();
    for d in 1..n {
        let mut seen: HashSet<i64> = HashSet::new();
        for i in 0..(n - d) {
            let disp = perm[i + d] - perm[i];
            if !seen.insert(disp) {
                return false;
            }
        }
    }
    true
}

fn search_costas(n: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    if !(2..=30).contains(&n) {
        return None;
    }
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        let mut perm: Vec<i64> = (1..=n as i64).collect();
        rng.shuffle(&mut perm);
        if is_costas(&perm) {
            return Some(Found {
                score: n,
                witness: Witness::Costas { perm },
                iterations,
            });
        }
    }
    None // no Costas array found within the restart budget
}

#[cfg(test)]
mod tests {
    use super::*;

    // The engine's contract: every returned find verifies under the frozen
    // verifier. We assert that directly across kinds.
    fn assert_verifies(found: &Option<Found>) {
        let f = found.as_ref().expect("engine found a witness");
        let r = verify_witness(&f.witness);
        assert!(r.ok, "engine find must verify: {}", r.message);
    }

    #[test]
    fn gf2_sidon_finds_verified() {
        let f = search("gf2_sidon", 6, 0, 40, 0xABC).unwrap();
        assert_verifies(&f);
        assert!(f.unwrap().score >= 4);
    }

    #[test]
    fn union_free_finds_verified() {
        let f = search("union_free", 6, 0, 40, 0xDEF).unwrap();
        assert_verifies(&f);
    }

    #[test]
    fn rook_directions_finds_verified() {
        let f = search("rook_directions", 8, 0, 60, 0x111).unwrap();
        assert_verifies(&f);
        assert!(f.unwrap().score >= 8);
    }

    #[test]
    fn sidon_finds_verified() {
        let f = search("sidon", 7, 0, 30, 0x222).unwrap();
        assert_verifies(&f);
    }

    #[test]
    fn cap_finds_verified() {
        // n=4: the maximum cap in F_3^4 is 20; greedy should find a sizeable one.
        let f = search("cap", 4, 0, 80, 0x444).unwrap();
        assert_verifies(&f);
        assert!(f.unwrap().score >= 12);
    }

    #[test]
    fn b3_finds_verified() {
        let f = search("bh", 6, 3, 30, 0x333).unwrap();
        assert_verifies(&f);
    }

    #[test]
    fn determinism_same_seed_same_score() {
        let a = search("gf2_sidon", 7, 0, 50, 42).unwrap().unwrap();
        let b = search("gf2_sidon", 7, 0, 50, 42).unwrap().unwrap();
        assert_eq!(a.score, b.score);
        assert_eq!(
            serde_json::to_string(&a.witness).unwrap(),
            serde_json::to_string(&b.witness).unwrap()
        );
    }

    #[test]
    fn unknown_kind_errs() {
        assert!(search("not_a_kind", 5, 0, 1, 1).is_err());
    }
}
