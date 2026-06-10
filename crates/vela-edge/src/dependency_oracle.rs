//! The retro-impact dependency oracle: a deterministic, replayable measure of
//! how much downstream verified state rests on a record.
//!
//! ## Why this exists
//!
//! Retroactive-impact funding (fund what turned out to be useful) needs a
//! credible, neutral measure of *what was depended upon*. Impact is litigated
//! today through citations and prestige, which are gameable and slow. Vela's
//! records already carry their dependencies (`Attempt.depends_on`, and a
//! `Transfer` makes its target depend on its source), every one signed and
//! gate-tracked. So "X rests on Y" is mechanically true, not asserted, and the
//! dependency graph is the measurement substrate the steward can operate.
//!
//! ## What it is, and is NOT
//!
//! This is an **oracle over declared structural dependency among gate-tracked
//! records**, recomputed on read like every other derived status in the
//! substrate. It is NOT a popularity score: there is no view count, no citation
//! sentiment, no attention signal. A record only contributes to another's
//! weight if it *declares* that it depends on it. `verified_weight` counts only
//! those dependents that themselves cleared the gate (a Verified head
//! resolution), so the headline number is "verified state resting on this," not
//! "mentions of this."

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use vela_protocol::project::Project;

/// The dependency impact of one record: who rests on it, transitively.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DependencyImpact {
    pub record: String,
    /// Records that declare a direct dependency on `record` (sorted, unique).
    pub direct_dependents: Vec<String>,
    /// The full transitive set that rests on `record` (sorted, unique),
    /// excluding `record` itself.
    pub transitive_dependents: Vec<String>,
    /// `|transitive_dependents|` — total downstream records resting on this.
    pub weight: u64,
    /// Of the transitive dependents, how many are gate-verified (a Verified
    /// head resolution). The honest headline: verified state resting on this.
    pub verified_weight: u64,
}

/// Build the reverse-dependency adjacency (depended-upon -> {dependents}) from
/// the two declared dependency sources: `Attempt.depends_on` and `Transfer`
/// (the target's premise is discharged BY the source, so target depends on
/// source). Deterministic: `BTree*` keep ordering stable.
fn reverse_dep_map(project: &Project) -> BTreeMap<String, BTreeSet<String>> {
    let mut rev: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for a in &project.attempts {
        for dep in &a.depends_on {
            rev.entry(dep.clone())
                .or_default()
                .insert(a.attempt_id.clone());
        }
    }
    for t in &project.transfers {
        rev.entry(t.source_claim.clone())
            .or_default()
            .insert(t.target_claim.clone());
    }
    rev
}

fn is_verified(project: &Project, id: &str) -> bool {
    matches!(
        project.head_resolution(id).map(|r| &r.resolution),
        Some(vela_protocol::attempt::AttemptResolution::Verified { .. })
    )
}

/// Compute the dependency impact of `record_id`: a pure function of the
/// project's signed records, reproducible across runs.
#[must_use]
pub fn dependency_impact(project: &Project, record_id: &str) -> DependencyImpact {
    let rev = reverse_dep_map(project);
    let direct: Vec<String> = rev
        .get(record_id)
        .map(|s| s.iter().cloned().collect())
        .unwrap_or_default();

    // BFS the reverse closure, ignoring cycles via the `seen` guard.
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut q: VecDeque<String> = direct.iter().cloned().collect();
    while let Some(x) = q.pop_front() {
        if !seen.insert(x.clone()) {
            continue;
        }
        if let Some(deps) = rev.get(&x) {
            for d in deps {
                if !seen.contains(d) {
                    q.push_back(d.clone());
                }
            }
        }
    }
    // A dependency cycle could route back to record_id; never count itself.
    seen.remove(record_id);

    let transitive: Vec<String> = seen.iter().cloned().collect();
    let verified_weight = transitive
        .iter()
        .filter(|id| is_verified(project, id))
        .count() as u64;
    DependencyImpact {
        record: record_id.to_string(),
        direct_dependents: direct,
        weight: transitive.len() as u64,
        verified_weight,
        transitive_dependents: transitive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use vela_protocol::attempt::{Attempt, AttemptDraft, AttemptResolution, ResolutionEvent};

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn att(problem: u32, claim: &str, depends_on: Vec<String>) -> Attempt {
        Attempt::build(
            AttemptDraft {
                problem,
                frontier: "f".into(),
                kind: "search".into(),
                claim: claim.into(),
                detail: String::new(),
                claimed_status: String::new(),
                reproduction: Default::default(),
                cost: Default::default(),
                insight: String::new(),
                depends_on,
                related_problems: vec![],
                reusable_for: String::new(),
                verifier_attachments: vec![],
                deliverable_grade: None,
                provenance: Default::default(),
            },
            &key(),
        )
        .unwrap()
    }

    #[test]
    fn transitive_weight_counts_the_reverse_closure() {
        let mut p = vela_protocol::test_support::make_project("dep", vec![]);
        // a <- b <- c (c depends on b, b depends on a)
        let a = att(1, "base", vec![]);
        let b = att(2, "mid", vec![a.attempt_id.clone()]);
        let c = att(3, "top", vec![b.attempt_id.clone()]);
        let (aid, bid) = (a.attempt_id.clone(), b.attempt_id.clone());
        p.attempts = vec![a, b, c];

        let impact = dependency_impact(&p, &aid);
        assert_eq!(impact.weight, 2, "b and c rest on a");
        assert_eq!(impact.direct_dependents, vec![bid]);
        assert_eq!(impact.verified_weight, 0, "no resolutions yet");
    }

    #[test]
    fn verified_weight_counts_only_gate_verified_dependents() {
        let mut p = vela_protocol::test_support::make_project("dep", vec![]);
        let a = att(1, "base", vec![]);
        let b = att(2, "mid", vec![a.attempt_id.clone()]);
        let (aid, bid) = (a.attempt_id.clone(), b.attempt_id.clone());
        p.attempts = vec![a, b];
        p.attempt_resolutions = vec![
            ResolutionEvent::new(
                &bid,
                AttemptResolution::Verified {
                    gate_ref: "gate@vva_x".into(),
                },
                "reviewer:test",
                "2026-06-09T00:00:00Z",
                "",
            )
            .unwrap(),
        ];
        let impact = dependency_impact(&p, &aid);
        assert_eq!(impact.weight, 1);
        assert_eq!(impact.verified_weight, 1, "b is verified");
    }

    #[test]
    fn unknown_record_has_zero_impact() {
        let p = vela_protocol::test_support::make_project("dep", vec![]);
        assert_eq!(dependency_impact(&p, "vat_nope").weight, 0);
    }
}
