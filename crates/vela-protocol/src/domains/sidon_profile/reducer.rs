//! The live-frontier reducer: compile the accepted Sidon record into a
//! [`Presentation`].
//!
//! The earlier conformance work proved the kernel/evaluator/producer against a
//! hand-built fixture. This is the production path: read the real accepted
//! findings of a live Sidon frontier (the materialized, event-replayed
//! [`crate::project::Project`]) and fold them into the composed lineage the
//! observation and frontier map are computed over. The record becomes live —
//! `bounds.json`, the constellation, and the frontier map all derive from this.
//!
//! For each accepted bound `a(n) >= k` with a witness artifact, we append the
//! profile's verified route: a rank-0 verified-witness cell (identified by the
//! witness's content hash) and a rank-1 lower-bound cell that depends on it.
//! Per dimension `n` only the best (maximum-`k`) bound is routed; lower bounds
//! at the same `n` are superseded.
//!
//! The core logic is written over plain `(finding_id, assertion_text,
//! content_hash)` rows so it is unit-testable without constructing a full
//! `Project`; the live entry points load the project and extract those rows.

use std::collections::BTreeMap;

use super::{Presentation, append_verified_route, claim, digest, register_bound_metadata};

/// One accepted, witness-backed lower bound from the live record.
#[derive(Debug, Clone)]
pub struct LiveBound {
    pub n: i64,
    pub k: i64,
    /// The witness's content address (e.g. `sha256:...`) — its identity in the record.
    pub artifact_digest: String,
    pub finding_id: String,
}

/// Parse the first `a(n) >= k` bound out of an assertion string. Anchors on
/// `a(` so the sequence id (`A309370`) and the cube dimension (`{0,1}^9`) are
/// not mistaken for the bound.
pub fn parse_bound(text: &str) -> Option<(i64, i64)> {
    let mut rest = text;
    while let Some(idx) = rest.find("a(") {
        let after = &rest[idx + 2..];
        if let Some(close) = after.find(')')
            && let Ok(n) = after[..close].trim().parse::<i64>()
        {
            let tail = &after[close + 1..];
            if let Some(ge) = tail.find(">=") {
                let kpart = tail[ge + 2..].trim_start();
                let kdigits: String = kpart.chars().take_while(char::is_ascii_digit).collect();
                if let Ok(k) = kdigits.parse::<i64>() {
                    return Some((n, k));
                }
            }
        }
        rest = &rest[idx + 2..];
    }
    None
}

/// Collect the best witness-backed bound per dimension from `(finding_id,
/// assertion_text, content_hash)` rows. Rows whose assertion is not a bound, or
/// which have no witness artifact, are skipped. Returns one bound per `n`
/// (maximum `k`), sorted by `n`.
pub fn collect_live_bounds(rows: &[(String, String, Option<String>)]) -> Vec<LiveBound> {
    let mut best: BTreeMap<i64, LiveBound> = BTreeMap::new();
    for (id, text, hash) in rows {
        let Some((n, k)) = parse_bound(text) else {
            continue;
        };
        let Some(h) = hash else {
            continue; // a verified route needs the witness's identity
        };
        let cand = LiveBound {
            n,
            k,
            artifact_digest: h.clone(),
            finding_id: id.clone(),
        };
        best.entry(n)
            .and_modify(|e| {
                if k > e.k {
                    *e = cand.clone();
                }
            })
            .or_insert(cand);
    }
    best.into_values().collect()
}

/// Build the composed-lineage presentation from collected live bounds.
pub fn presentation_from_bounds(bounds: &[LiveBound]) -> Result<Presentation, String> {
    let mut p = Presentation {
        cell_ranks: Default::default(),
        clauses: Vec::new(),
        accepted_events: Vec::new(),
        cell_metadata: Default::default(),
    };
    for b in bounds {
        register_bound_metadata(&mut p, b.n, b.k)?;
        let claim_digest = digest(&claim(b.n, b.k))?;
        append_verified_route(
            &mut p,
            b.n,
            b.k,
            &b.artifact_digest,
            &claim_digest,
            &["verifier:vela-verify.sidon".to_string()],
            &format!("acceptance:{}", b.finding_id),
        )?;
    }
    Ok(p)
}

/// Compile a loaded frontier [`Project`](crate::project::Project) into the live
/// Sidon presentation: the best witness-backed bound per `n`, as composed lineage.
pub fn live_presentation(project: &crate::project::Project) -> Result<Presentation, String> {
    // finding id -> witness content hash (first non-retracted artifact targeting it)
    let mut witness: BTreeMap<&str, &str> = BTreeMap::new();
    for a in &project.artifacts {
        if a.retracted {
            continue;
        }
        for fid in &a.target_findings {
            witness
                .entry(fid.as_str())
                .or_insert(a.content_hash.as_str());
        }
    }
    let rows: Vec<(String, String, Option<String>)> = project
        .findings
        .iter()
        .map(|f| {
            (
                f.id.clone(),
                f.assertion.text.clone(),
                witness.get(f.id.as_str()).map(|s| s.to_string()),
            )
        })
        .collect();
    presentation_from_bounds(&collect_live_bounds(&rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sidon_profile::best_bounds;
    use std::collections::BTreeSet;

    #[test]
    fn parses_bound_not_the_sequence_id_or_cube() {
        assert_eq!(
            parse_bound("OEIS A309370 a(9) >= 47: a Sidon set in {0,1}^9 ..."),
            Some((9, 47))
        );
        assert_eq!(parse_bound("a(24) >= 7179: ..."), Some((24, 7179)));
        assert_eq!(parse_bound("no bound here, A309370"), None);
    }

    #[test]
    fn keeps_best_bound_per_n_and_needs_a_witness() {
        let rows = vec![
            ("vf_a".into(), "a(7) >= 24".into(), Some("sha256:aa".into())),
            ("vf_b".into(), "a(7) >= 20".into(), Some("sha256:bb".into())), // superseded
            ("vf_c".into(), "a(9) >= 47".into(), Some("sha256:cc".into())),
            ("vf_d".into(), "a(11) >= 99".into(), None), // no witness → skipped
        ];
        let bounds = collect_live_bounds(&rows);
        assert_eq!(bounds.len(), 2); // n=7 (best 24), n=9; n=11 dropped (no witness)
        let n7 = bounds.iter().find(|b| b.n == 7).unwrap();
        assert_eq!(n7.k, 24);
        assert_eq!(n7.artifact_digest, "sha256:aa");
    }

    #[test]
    fn presentation_routes_best_bounds_and_replays() {
        let rows = vec![
            ("vf_a".into(), "a(7) >= 24".into(), Some("sha256:aa".into())),
            ("vf_c".into(), "a(9) >= 47".into(), Some("sha256:cc".into())),
        ];
        let p = presentation_from_bounds(&collect_live_bounds(&rows)).unwrap();
        let bounds = best_bounds(&p, &BTreeSet::new()).unwrap();
        // one supported lower-bound row per n, at the best k
        let by_n: std::collections::BTreeMap<i64, i64> = bounds
            .iter()
            .map(|r| {
                (
                    r["n"].as_i64().unwrap(),
                    r["best_lower_bound"].as_i64().unwrap(),
                )
            })
            .collect();
        assert_eq!(by_n.get(&7), Some(&24));
        assert_eq!(by_n.get(&9), Some(&47));
        // roots compute (presentation is well-formed)
        assert!(p.presentation_root().unwrap().starts_with("vpr_"));
    }
}
