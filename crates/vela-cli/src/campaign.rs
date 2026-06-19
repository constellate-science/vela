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

/// A full target spec. Most kinds need only `n` (and `h` for `bh`); the code
/// families need more — `constant_weight` uses `d`/`w`, `covering` uses `k`/`t`
/// (with `n` as the ground-set size `v`).
#[derive(Default)]
pub struct Target {
    pub kind: String,
    pub n: usize,
    pub h: usize,
    pub d: usize,
    pub w: usize,
    pub k: usize,
    pub t: usize,
}

/// Run the discovery engine for one target. `kind` is the verifier kind
/// (`gf2_sidon`, `union_free`, `rook_directions`, `cap`, `sidon`, `bh`,
/// `golomb`, `costas`). `n`/`h` parameterize the target; `restarts` bounds the work;
/// `seed` fixes the draw. Returns the best verified witness, or `None` if the
/// engine found nothing checkable (and `Err` for an unsupported kind). Thin
/// wrapper over [`search_target`] for the common `n`/`h`-only kinds.
#[allow(dead_code)] // convenience API exercised by the unit tests
pub fn search(
    kind: &str,
    n: usize,
    h: usize,
    restarts: u64,
    seed: u64,
) -> Result<Option<Found>, String> {
    search_target(
        &Target {
            kind: kind.into(),
            n,
            h,
            ..Default::default()
        },
        restarts,
        seed,
    )
}

/// Full-spec entry point (handles the code families that need `d`/`w`/`k`/`t`).
pub fn search_target(tg: &Target, restarts: u64, seed: u64) -> Result<Option<Found>, String> {
    let mut rng = Rng::new(seed);
    let (n, h) = (tg.n, tg.h);
    let found = match tg.kind.as_str() {
        "gf2_sidon" => search_gf2_sidon(n, restarts, &mut rng),
        "union_free" => search_union_free(n, restarts, &mut rng),
        "rook_directions" => search_rook_directions(n, restarts, &mut rng),
        "cap" => search_cap(n, restarts, &mut rng),
        "constant_weight" => search_constant_weight(n, tg.d, tg.w, restarts, &mut rng),
        "covering" => search_covering(n, tg.k, tg.t, restarts, &mut rng),
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
        // DTS(I, J): n = rows (I), k = within-row order (J), J+1 marks per row.
        "diff_triangle" => search_diff_triangle(n, tg.k, restarts, &mut rng),
        other => {
            return Err(format!(
                "kind `{other}` is not searchable by the engine yet (searchable: gf2_sidon, union_free, rook_directions, cap, constant_weight, covering, sidon, bh, golomb, costas, diff_triangle)"
            ));
        }
    };
    // Re-check the engine's own output through the frozen verifier. A find that
    // does not verify is a search bug, not a discovery — surface it, never ship.
    if let Some(f) = &found {
        let r = verify_witness(&f.witness);
        if !r.ok {
            return Err(format!(
                "INTERNAL: engine produced an unverified {} witness (score {}): {}",
                tg.kind, f.score, r.message
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
// constant_weight — a binary constant-weight code A(n, d, w): codewords of
// length n, weight exactly w, pairwise Hamming distance >= d. Greedy: enumerate
// the weight-w words, add a word iff it is >= d from every chosen word.
// Certifies a LOWER bound on A(n, d, w).
// ---------------------------------------------------------------------------
fn search_constant_weight(
    n: usize,
    d: usize,
    w: usize,
    restarts: u64,
    rng: &mut Rng,
) -> Option<Found> {
    if !(1..=20).contains(&n) || w == 0 || w > n || d == 0 || d > 2 * w {
        return None;
    }
    // Enumerate weight-w words once (as bitmasks). Bail if the space is huge.
    let mut words: Vec<u64> = Vec::new();
    for x in 0u64..(1u64 << n) {
        if x.count_ones() as usize == w {
            words.push(x);
            if words.len() > 1_000_000 {
                return None; // C(n,w) too large to enumerate; keep it bounded.
            }
        }
    }
    if words.is_empty() {
        return None;
    }
    let mut best: Vec<u64> = Vec::new();
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        let mut order = words.clone();
        rng.shuffle(&mut order);
        let mut code: Vec<u64> = Vec::new();
        for &x in &order {
            if code.iter().all(|&c| (x ^ c).count_ones() as usize >= d) {
                code.push(x);
            }
        }
        if code.len() > best.len() {
            best = code;
        }
    }
    let score = best.len();
    best.sort_unstable();
    let words_vec: Vec<Vec<i64>> = best
        .iter()
        .map(|&x| (0..n).map(|b| ((x >> b) & 1) as i64).collect())
        .collect();
    Some(Found {
        witness: Witness::ConstantWeight {
            n,
            d,
            w,
            words: words_vec,
            claimed_size: Some(score),
        },
        score,
        iterations,
    })
}

// ---------------------------------------------------------------------------
// covering — a covering design C(v, k, t): k-blocks of [v] so every t-subset of
// [v] lies in at least one block. This is a MINIMIZATION (fewest blocks);
// greedy set-cover repeatedly takes the block covering the most still-uncovered
// t-subsets, yielding a valid covering (an UPPER bound on the covering number).
// `score` is the block count — lower is better, the opposite of the set kinds.
// ---------------------------------------------------------------------------
fn search_covering(v: usize, k: usize, t: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    if !(1..=14).contains(&v) || k == 0 || k > v || t == 0 || t > k {
        return None;
    }
    let mask = |x: u32| x as usize;
    let tsubs: Vec<u32> = (0u32..(1u32 << v))
        .filter(|x| x.count_ones() as usize == t)
        .collect();
    let blocks: Vec<u32> = (0u32..(1u32 << v))
        .filter(|x| x.count_ones() as usize == k)
        .collect();
    if tsubs.is_empty() || blocks.is_empty() {
        return None;
    }
    let mut best: Option<Vec<u32>> = None;
    let iterations = restarts.max(1);
    for _ in 0..iterations {
        // Randomize block order so greedy ties break differently per restart.
        let mut bl = blocks.clone();
        rng.shuffle(&mut bl);
        let mut covered = vec![false; 1usize << v];
        let mut uncovered = tsubs.len();
        let mut chosen: Vec<u32> = Vec::new();
        while uncovered > 0 {
            // pick the block covering the most uncovered t-subsets
            let mut best_block = 0u32;
            let mut best_gain = 0usize;
            for &b in &bl {
                let mut gain = 0usize;
                for &ts in &tsubs {
                    if (ts & b) == ts && !covered[mask(ts)] {
                        gain += 1;
                    }
                }
                if gain > best_gain {
                    best_gain = gain;
                    best_block = b;
                }
            }
            if best_gain == 0 {
                break; // cannot cover (shouldn't happen for valid params)
            }
            for &ts in &tsubs {
                if (ts & best_block) == ts && !covered[mask(ts)] {
                    covered[mask(ts)] = true;
                    uncovered -= 1;
                }
            }
            chosen.push(best_block);
        }
        if uncovered == 0
            && best
                .as_ref()
                .map(|b| chosen.len() < b.len())
                .unwrap_or(true)
        {
            best = Some(chosen);
        }
    }
    let blocks_chosen = best?;
    let score = blocks_chosen.len();
    let blocks_vec: Vec<Vec<usize>> = blocks_chosen
        .iter()
        .map(|&b| (0..v).filter(|&i| (b >> i) & 1 == 1).collect())
        .collect();
    Some(Found {
        witness: Witness::Covering {
            v,
            k,
            t,
            blocks: blocks_vec,
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
            if best
                .as_ref()
                .map(|b| len < *b.last().unwrap())
                .unwrap_or(true)
            {
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
// Difference triangle set DTS(I, J): I rows of J+1 strictly-increasing marks
// from 0, every within-row pairwise difference GLOBALLY distinct. Objective:
// minimize the scope (largest mark). Randomized-greedy over restarts, keep the
// lowest-scope complete set. This is a baseline producer — it yields VALID
// constructions, not necessarily record-beating ones (the record is the open
// problem); the frozen verifier and the value-to-beat are what make a real
// improvement provable when a stronger solver finds one.
// ---------------------------------------------------------------------------
fn search_diff_triangle(rows: usize, j: usize, restarts: u64, rng: &mut Rng) -> Option<Found> {
    let marks_per_row = j + 1;
    if rows == 0 || marks_per_row < 2 || rows > 64 || marks_per_row > 64 {
        return None;
    }
    // generous scope cap: a greedy DTS scope sits well above the optimum.
    let cap = (rows * marks_per_row * marks_per_row * 4).max(32) as i64;
    let iterations = restarts.max(1);
    let mut best: Option<(Vec<Vec<i64>>, i64)> = None;
    for _ in 0..iterations {
        let mut all_diffs: HashSet<i64> = HashSet::new();
        let mut grid: Vec<Vec<i64>> = Vec::with_capacity(rows);
        let mut scope: i64 = 0;
        let mut complete = true;
        for _r in 0..rows {
            let mut marks: Vec<i64> = vec![0];
            while marks.len() < marks_per_row {
                let cur_max = *marks.last().unwrap();
                // Greedy-SMALLEST with a small randomized window: scan ascending
                // and collect up to W valid next-marks, then pick one at random.
                // Placing each mark as small as possible directly minimizes the
                // scope (vs the old full-shuffle, which scattered marks high);
                // the window keeps restart-to-restart variety so the engine can
                // escape a greedy dead-end and find a lower-scope set.
                const W: usize = 4;
                let mut valid: Vec<(i64, Vec<i64>)> = Vec::with_capacity(W);
                for c in (cur_max + 1)..=cap {
                    let mut nd = Vec::with_capacity(marks.len());
                    let mut good = true;
                    for &m in &marks {
                        let d = c - m;
                        if all_diffs.contains(&d) || nd.contains(&d) {
                            good = false;
                            break;
                        }
                        nd.push(d);
                    }
                    if good {
                        valid.push((c, nd));
                        if valid.len() >= W {
                            break;
                        }
                    }
                }
                let placed = !valid.is_empty();
                if placed {
                    let pick = rng.below(valid.len());
                    let (c, nd) = valid.swap_remove(pick);
                    for d in nd {
                        all_diffs.insert(d);
                    }
                    marks.push(c);
                }
                if !placed {
                    complete = false;
                    break;
                }
            }
            if !complete {
                break;
            }
            scope = scope.max(*marks.last().unwrap());
            grid.push(marks);
        }
        if complete && grid.len() == rows && best.as_ref().map(|(_, s)| scope < *s).unwrap_or(true)
        {
            best = Some((grid, scope));
        }
    }
    // The greedy result seeds a branch-and-bound pass (a DIVERSE method): it
    // searches for a strictly tighter scope within a node budget scaled by
    // restarts. The frozen `verify_diff_triangle` re-checks whichever wins, so a
    // solver bug can only yield a worse-or-rejected witness, never a false one.
    let make = |grid: Vec<Vec<i64>>, scope: i64| Found {
        score: scope as usize,
        witness: Witness::DiffTriangle {
            rows: grid,
            claimed_scope: Some(scope as usize),
        },
        iterations,
    };
    let seed_scope = best.as_ref().map(|(_, s)| *s).unwrap_or(cap);
    let node_budget = iterations
        .saturating_mul(200_000)
        .clamp(200_000, 10_000_000);
    let bt = search_diff_triangle_bt(rows, j, seed_scope, node_budget);
    match (best, bt) {
        (Some((g_grid, g_scope)), Some(bt_found)) => {
            if (bt_found.score as i64) < g_scope {
                Some(bt_found)
            } else {
                Some(make(g_grid, g_scope))
            }
        }
        (Some((g_grid, g_scope)), None) => Some(make(g_grid, g_scope)),
        (None, bt) => bt,
    }
}

/// Branch-and-bound DTS solver: a DIVERSE method (vs the greedy above). Places
/// marks smallest-first with the global difference-set as the propagated
/// constraint and prunes any partial whose marks reach the incumbent scope
/// (`best_scope`), so every completed grid strictly improves on it. Seeded with
/// the greedy scope, it then searches for a tighter one within a node budget, and
/// stops early if it hits the information-theoretic lower bound (rows*C(J+1,2)
/// distinct positive differences, each <= the max mark). The frozen
/// `verify_diff_triangle` re-checks every returned witness, so the solver is only
/// a candidate producer, never the trust.
#[allow(clippy::too_many_arguments)]
fn dts_place(
    rows: usize,
    mpr: usize,
    lb: i64,
    marks: &mut Vec<i64>,
    cur_scope: i64,
    diffs: &mut HashSet<i64>,
    grid: &mut Vec<Vec<i64>>,
    best_scope: &mut i64,
    best_grid: &mut Option<Vec<Vec<i64>>>,
    nodes: &mut u64,
    budget: u64,
) {
    if *nodes >= budget || *best_scope <= lb {
        return; // budget exhausted, or optimum already reached
    }
    if marks.len() == mpr {
        let row_max = *marks.last().unwrap();
        let new_scope = cur_scope.max(row_max);
        grid.push(marks.clone());
        if grid.len() == rows {
            if new_scope < *best_scope {
                *best_scope = new_scope;
                *best_grid = Some(grid.clone());
            }
        } else {
            let mut next = vec![0];
            dts_place(
                rows, mpr, lb, &mut next, new_scope, diffs, grid, best_scope, best_grid, nodes,
                budget,
            );
        }
        grid.pop();
        return;
    }
    let last = *marks.last().unwrap();
    // smallest-first; a mark must stay strictly below the incumbent scope.
    for c in (last + 1)..*best_scope {
        *nodes += 1;
        if *nodes >= budget {
            return;
        }
        let mut nd: Vec<i64> = Vec::with_capacity(marks.len());
        let mut ok = true;
        for &m in marks.iter() {
            let d = c - m;
            if diffs.contains(&d) || nd.contains(&d) {
                ok = false;
                break;
            }
            nd.push(d);
        }
        if !ok {
            continue;
        }
        for &d in &nd {
            diffs.insert(d);
        }
        marks.push(c);
        dts_place(
            rows,
            mpr,
            lb,
            marks,
            cur_scope.max(c),
            diffs,
            grid,
            best_scope,
            best_grid,
            nodes,
            budget,
        );
        marks.pop();
        for &d in &nd {
            diffs.remove(&d);
        }
    }
}

fn search_diff_triangle_bt(
    rows: usize,
    j: usize,
    seed_scope: i64,
    node_budget: u64,
) -> Option<Found> {
    let mpr = j + 1;
    if rows == 0 || mpr < 2 || rows > 64 || mpr > 64 {
        return None;
    }
    let lb = (rows * (mpr * (mpr - 1) / 2)) as i64;
    let mut best_scope = seed_scope;
    let mut best_grid: Option<Vec<Vec<i64>>> = None;
    let mut diffs: HashSet<i64> = HashSet::new();
    let mut grid: Vec<Vec<i64>> = Vec::with_capacity(rows);
    let mut nodes = 0u64;
    let mut first = vec![0];
    dts_place(
        rows,
        mpr,
        lb,
        &mut first,
        0,
        &mut diffs,
        &mut grid,
        &mut best_scope,
        &mut best_grid,
        &mut nodes,
        node_budget,
    );
    best_grid.map(|grid| Found {
        score: best_scope as usize,
        witness: Witness::DiffTriangle {
            rows: grid,
            claimed_scope: Some(best_scope as usize),
        },
        iterations: nodes,
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
    fn constant_weight_finds_verified() {
        // A(6,4,3): codewords of length 6, weight 3, pairwise distance >= 4.
        let tg = Target {
            kind: "constant_weight".into(),
            n: 6,
            d: 4,
            w: 3,
            ..Default::default()
        };
        let f = search_target(&tg, 60, 0x555).unwrap();
        assert_verifies(&f);
        assert!(f.unwrap().score >= 4);
    }

    #[test]
    fn covering_finds_verified() {
        // C(6,3,2): cover every pair of [6] with triples; greedy yields a valid
        // covering (the minimum is 6).
        let tg = Target {
            kind: "covering".into(),
            n: 6,
            k: 3,
            t: 2,
            ..Default::default()
        };
        let f = search_target(&tg, 40, 0x666).unwrap();
        assert_verifies(&f);
    }

    #[test]
    fn b3_finds_verified() {
        let f = search("bh", 6, 3, 30, 0x333).unwrap();
        assert_verifies(&f);
    }

    #[test]
    fn diff_triangle_portfolio_finds_verified_and_improves() {
        // DTS(3,3): 3 rows, 4 marks each. The portfolio (greedy + branch-and-bound)
        // returns a frozen-verified set.
        let tg = Target {
            kind: "diff_triangle".into(),
            n: 3,
            k: 3,
            ..Default::default()
        };
        let f = search_target(&tg, 50, 0x777).unwrap();
        assert_verifies(&f);
        // B&B in isolation: seeded generously, returns a valid set strictly below
        // the seed scope (a diverse method that the frozen verifier re-checks).
        let seed = 200;
        let bt = search_diff_triangle_bt(3, 3, seed, 2_000_000).expect("bt finds a DTS");
        assert!(verify_witness(&bt.witness).ok, "bt witness must verify");
        assert!((bt.score as i64) < seed, "bt improves on the seed scope");
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
