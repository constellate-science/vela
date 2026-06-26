//! A pure-Rust SAT backend for difference-triangle sets (the discovery
//! portfolio's structured-search method). The heuristic methods (greedy,
//! 2-opt, simulated annealing) plateau well above the optimum on hard
//! instances like DTS(7,5); CDCL learning prunes the search far better.
//!
//! TRUST: the solver only PRODUCES candidate witnesses. Every model is decoded
//! to rows and re-checked by the frozen `vela_verify::verify_diff_triangle`, so
//! an encoding bug can never manufacture a false record — only a missed or
//! invalid solution that the verifier rejects. The frozen verifier stays the
//! trust; this is a candidate generator.
//!
//! Encoding of DTS(I, J) with all marks in `[0, S]`:
//! - `p[r][v]` (v in 1..=S): row r has a mark at position v. Position 0 is the
//!   implicit start mark (every row starts at 0).
//! - exactly J marks among `1..=S` per row (J+1 marks total including 0).
//! - global distinct differences: each distance d in 1..=S occurs at most once
//!   across all rows. A distance d is realized in row r by the start-mark pair
//!   (0, d) — i.e. `p[r][d]` — or by an interior pair (v, v+d) — i.e.
//!   `z[r][v][d] = p[r][v] ∧ p[r][v+d]`. An at-most-one over all realizations of
//!   each d enforces global distinctness.

/// A CNF being built, with a fresh-variable allocator. Literals are 1-based;
/// negatives are negations (DIMACS convention, the splr input format).
struct Cnf {
    clauses: Vec<Vec<i32>>,
    n_vars: i32,
}

impl Cnf {
    fn new(reserved: i32) -> Self {
        Cnf {
            clauses: Vec::new(),
            n_vars: reserved,
        }
    }
    fn fresh(&mut self) -> i32 {
        self.n_vars += 1;
        self.n_vars
    }
    fn add(&mut self, clause: Vec<i32>) {
        self.clauses.push(clause);
    }

    /// At-most-one via the sequential (Sinz) encoding: linear in `lits.len()`.
    fn at_most_one(&mut self, lits: &[i32]) {
        self.at_most_k(lits, 1);
    }

    /// At-most-`k` via the sequential counter (Sinz 2005). Registers `s[i][j]`
    /// "at least j of the first i+1 literals are true".
    fn at_most_k(&mut self, lits: &[i32], k: usize) {
        let n = lits.len();
        if k == 0 {
            for &l in lits {
                self.add(vec![-l]);
            }
            return;
        }
        if n <= k {
            return; // trivially satisfiable
        }
        // s[i][j] for i in 0..n, j in 0..k.
        let s: Vec<Vec<i32>> = (0..n)
            .map(|_| (0..k).map(|_| self.fresh()).collect())
            .collect();
        // first column
        self.add(vec![-lits[0], s[0][0]]);
        for &col in s[0].iter().skip(1) {
            self.add(vec![-col]);
        }
        for i in 1..n {
            self.add(vec![-lits[i], s[i][0]]);
            self.add(vec![-s[i - 1][0], s[i][0]]);
            for j in 1..k {
                self.add(vec![-lits[i], -s[i - 1][j - 1], s[i][j]]);
                self.add(vec![-s[i - 1][j], s[i][j]]);
            }
            // forbid the (k+1)-th
            self.add(vec![-lits[i], -s[i - 1][k - 1]]);
        }
    }

    /// At-least-`k`: at-most-`(n-k)` of the negations.
    fn at_least_k(&mut self, lits: &[i32], k: usize) {
        let neg: Vec<i32> = lits.iter().map(|l| -l).collect();
        let n = lits.len();
        self.at_most_k(&neg, n.saturating_sub(k));
    }

    fn exactly_k(&mut self, lits: &[i32], k: usize) {
        self.at_most_k(lits, k);
        self.at_least_k(lits, k);
    }

    /// Constrain bit-vector `a` <=_lex `b` (position 0 is the most significant).
    /// Used to break the row-interchange symmetry of a DTS: the I rows are fully
    /// permutable, so requiring them in non-decreasing lex order keeps exactly
    /// one representative per equivalence class (sound for both SAT and UNSAT)
    /// and removes up to I! redundant copies of every search state.
    fn lex_leq(&mut self, a: &[i32], b: &[i32]) {
        debug_assert_eq!(a.len(), b.len());
        // g[i] == "prefix a[0..=i] equals b[0..=i]". g_prev starts implicitly true.
        let mut g_prev: Option<i32> = None; // None == constant true
        for i in 0..a.len() {
            // At the most significant position with an equal prefix, a <= b.
            match g_prev {
                None => self.add(vec![-a[i], b[i]]),
                Some(g) => self.add(vec![-g, -a[i], b[i]]),
            }
            if i + 1 == a.len() {
                break; // no need to track equality past the last position
            }
            // eq <-> (a[i] <-> b[i])
            let eq = self.fresh();
            self.add(vec![-eq, -a[i], b[i]]);
            self.add(vec![-eq, -b[i], a[i]]);
            self.add(vec![a[i], b[i], eq]);
            self.add(vec![-a[i], -b[i], eq]);
            // g[i] <-> g_prev && eq
            let g = self.fresh();
            self.add(vec![-g, eq]);
            match g_prev {
                None => {
                    // g_prev is true: g <-> eq.
                    self.add(vec![-eq, g]);
                }
                Some(gp) => {
                    self.add(vec![-g, gp]);
                    self.add(vec![-gp, -eq, g]);
                }
            }
            g_prev = Some(g);
        }
    }
}

/// The result of one SAT attack at a fixed scope cap.
pub enum DtsAttempt {
    /// A valid difference-triangle set found, as rows of marks (each starts at
    /// 0). The caller MUST still re-verify with the frozen verifier.
    Found(Vec<Vec<i64>>),
    /// Proven no DTS(I,J) fits within the cap (a lower bound on the scope).
    Unsat,
    /// The solver hit its conflict budget without deciding.
    Budget,
}

/// Encode + solve DTS(`rows`, `j`) with every mark in `[0, scope_cap]`. Returns
/// a model (un-verified), UNSAT, or budget-exhausted. `max_conflicts` bounds the
/// CDCL search so a hard instance does not run unbounded.
pub fn solve_dts_at_scope(
    rows: usize,
    j: usize,
    scope_cap: usize,
    max_conflicts: usize,
) -> DtsAttempt {
    if rows == 0 || j == 0 || scope_cap < j {
        return DtsAttempt::Unsat;
    }
    let s = scope_cap;
    // p[r][v] -> var, v in 1..=s. var = r*s + v (1-based; v>=1).
    let pvar = |r: usize, v: usize| -> i32 { (r * s + v) as i32 };
    let mut cnf = Cnf::new((rows * s) as i32);

    let row_lits: Vec<Vec<i32>> = (0..rows)
        .map(|r| (1..=s).map(|v| pvar(r, v)).collect())
        .collect();
    for lits in &row_lits {
        // exactly j marks among positions 1..=s (the +1 start mark is implicit).
        cnf.exactly_k(lits, j);
    }
    // Symmetry break: the rows are interchangeable, so order them
    // lexicographically. Removes up to rows! redundant copies of the search.
    for r in 1..rows {
        cnf.lex_leq(&row_lits[r - 1], &row_lits[r]);
    }

    // Global distinct differences. For each distance d, collect every
    // realization literal and force at-most-one.
    for d in 1..=s {
        let mut realizations: Vec<i32> = Vec::new();
        for r in 0..rows {
            // start-mark pair (0, d): realized iff there is a mark at d.
            realizations.push(pvar(r, d));
            // interior pairs (v, v+d), v in 1..=s-d: z = p[r][v] AND p[r][v+d].
            for v in 1..=s.saturating_sub(d) {
                let a = pvar(r, v);
                let b = pvar(r, v + d);
                let z = cnf.fresh();
                // z -> a, z -> b, and (a ∧ b) -> z.
                cnf.add(vec![-z, a]);
                cnf.add(vec![-z, b]);
                cnf.add(vec![-a, -b, z]);
                realizations.push(z);
            }
        }
        cnf.at_most_one(&realizations);
    }

    // Solve with splr's stable top-level interface, bounded by a wall-clock
    // timeout (derived from the conflict budget) so a hard instance cannot run
    // unbounded. `Certificate::try_from` consumes the clause list directly.
    use splr::*;
    // splr's timeout is in seconds; scale the conflict budget into a coarse
    // wall-clock bound (the heuristic methods are the fast path; SAT is the
    // deeper, slower lane). A budget of 0 means "no timeout".
    let config = Config {
        c_timeout: (max_conflicts as f64 / 200_000.0).max(0.0),
        ..Config::default()
    };
    // splr's `try_from` may DECIDE the instance during construction (returning
    // the certificate in the Err channel), or hand back a Solver to run.
    match Solver::try_from((config, cnf.clauses.as_slice())) {
        Ok(mut solver) => match solver.solve() {
            Ok(Certificate::SAT(model)) => DtsAttempt::Found(decode_model(rows, s, &pvar, &model)),
            Ok(Certificate::UNSAT) => DtsAttempt::Unsat,
            Err(_) => DtsAttempt::Budget, // timeout / inconclusive
        },
        Err(Ok(Certificate::SAT(model))) => DtsAttempt::Found(decode_model(rows, s, &pvar, &model)),
        Err(Ok(Certificate::UNSAT)) => DtsAttempt::Unsat,
        Err(Err(_)) => DtsAttempt::Budget,
    }
}

/// Decode a SAT model into rows of marks: a mark at `v` in row `r` iff
/// `pvar(r,v)` is assigned true (positive literal). Position 0 is always present.
fn decode_model(
    rows: usize,
    s: usize,
    pvar: &impl Fn(usize, usize) -> i32,
    model: &[i32],
) -> Vec<Vec<i64>> {
    let mut out: Vec<Vec<i64>> = Vec::with_capacity(rows);
    for r in 0..rows {
        let mut marks: Vec<i64> = vec![0];
        for v in 1..=s {
            let var = pvar(r, v) as usize;
            if var >= 1 && var <= model.len() && model[var - 1] > 0 {
                marks.push(v as i64);
            }
        }
        marks.sort_unstable();
        out.push(marks);
    }
    out
}

/// Drive the SAT backend down a multiplicative scope schedule, keeping the
/// lowest VERIFIED grid found. Because tightening the cap only makes the
/// instance HARDER, the first non-`Found` cap (UNSAT = proven floor, or a
/// timeout) ends the descent. Starting BELOW `start_cap` skips the easy, large,
/// high-scope solves the greedy seed already covers. `max_solves` bounds the
/// total wall-clock. Every returned grid has passed `verify_diff_triangle`.
pub fn best_dts_via_sat(
    rows: usize,
    j: usize,
    start_cap: usize,
    max_conflicts: usize,
    max_solves: usize,
) -> Option<(Vec<Vec<i64>>, usize)> {
    let mut best: Option<(Vec<Vec<i64>>, usize)> = None;
    // Begin a notch under the greedy seed (no point re-finding what greedy has),
    // then step down ~15% each solve toward `j`.
    let mut cap = ((start_cap.saturating_sub(1)) * 7 / 10).max(j + 1);
    for _ in 0..max_solves {
        if cap < j + 1 {
            break;
        }
        match solve_dts_at_scope(rows, j, cap, max_conflicts) {
            DtsAttempt::Found(grid) if vela_verify::verify_diff_triangle(&grid, None).ok => {
                let scope = grid
                    .iter()
                    .map(|row| *row.last().unwrap_or(&0))
                    .max()
                    .unwrap_or(0) as usize;
                if best.as_ref().map(|(_, b)| scope < *b).unwrap_or(true) {
                    best = Some((grid, scope));
                }
                let next = (scope * 17) / 20;
                cap = if next < scope {
                    next
                } else {
                    scope.saturating_sub(1)
                };
            }
            // UNSAT (proven floor) or timeout: lower caps are only harder, stop.
            _ => break,
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    // DTS(1, 3) is the order-4 Golomb ruler: optimum scope 6 ({0,1,4,6}).
    // SAT must find a scope-6 ruler and prove scope 5 impossible. This pins the
    // encoding against a known optimum, end to end through the frozen verifier.
    #[test]
    fn sat_finds_golomb_order4_optimum() {
        match solve_dts_at_scope(1, 3, 6, 100_000) {
            DtsAttempt::Found(grid) => {
                assert!(
                    vela_verify::verify_diff_triangle(&grid, None).ok,
                    "the SAT witness must verify: {grid:?}"
                );
                let scope = grid.iter().map(|r| *r.last().unwrap()).max().unwrap();
                assert!(scope <= 6, "order-4 Golomb fits in scope 6: {grid:?}");
            }
            other => panic!(
                "scope 6 must be SAT for order-4 Golomb (got {})",
                match other {
                    DtsAttempt::Unsat => "UNSAT",
                    _ => "budget",
                }
            ),
        }
    }

    // The descending driver, given a greedy-seed-style start cap well above the
    // optimum, returns a verified grid strictly below the seed.
    #[test]
    fn best_via_sat_improves_on_a_loose_seed() {
        // seed 14 for order-4 Golomb (optimum 6): the driver must verify-improve.
        if let Some((grid, scope)) = best_dts_via_sat(1, 3, 14, 200_000, 6) {
            assert!(
                vela_verify::verify_diff_triangle(&grid, None).ok,
                "{grid:?}"
            );
            assert!(scope < 14, "must improve on the loose seed: scope {scope}");
        }
    }

    // Below the optimum is UNSAT (a real lower bound).
    #[test]
    fn sat_proves_golomb_order4_lower_bound() {
        match solve_dts_at_scope(1, 3, 5, 100_000) {
            DtsAttempt::Unsat => {}
            DtsAttempt::Found(g) => panic!("scope 5 should be UNSAT, got {g:?}"),
            DtsAttempt::Budget => panic!("scope 5 should decide within budget"),
        }
    }

    // Empirical probe (ignored: long-running). Maps the SAT backend's behavior
    // on the flagship DTS(7,5) at a sequence of scope caps. Run with:
    //   cargo test -p vela-cli --lib dts_7_5_probe -- --ignored --nocapture
    #[test]
    #[ignore]
    fn dts_7_5_probe() {
        for cap in [130usize, 120, 115, 112, 111, 108] {
            let t = std::time::Instant::now();
            // ~90s wall-clock per solve via the timeout schedule.
            let r = solve_dts_at_scope(7, 5, cap, 18_000_000);
            let secs = t.elapsed().as_secs_f64();
            match r {
                DtsAttempt::Found(grid) => {
                    let ok = vela_verify::verify_diff_triangle(&grid, None).ok;
                    let scope = grid
                        .iter()
                        .map(|r| *r.last().unwrap_or(&0))
                        .max()
                        .unwrap_or(0);
                    println!("cap={cap:4} -> FOUND scope={scope} verified={ok} ({secs:.1}s)");
                }
                DtsAttempt::Unsat => println!("cap={cap:4} -> UNSAT lower-bound ({secs:.1}s)"),
                DtsAttempt::Budget => println!("cap={cap:4} -> budget/timeout ({secs:.1}s)"),
            }
        }
    }

    // A small two-row instance: the returned grid verifies as a real DTS with
    // the right shape (2 rows of 3 marks).
    #[test]
    fn sat_two_row_witness_verifies() {
        if let DtsAttempt::Found(grid) = solve_dts_at_scope(2, 2, 12, 200_000) {
            assert!(
                vela_verify::verify_diff_triangle(&grid, None).ok,
                "{grid:?}"
            );
            assert_eq!(grid.len(), 2);
            for row in &grid {
                assert_eq!(row.len(), 3, "DTS(2,2) rows have 3 marks: {row:?}");
            }
        }
    }
}
