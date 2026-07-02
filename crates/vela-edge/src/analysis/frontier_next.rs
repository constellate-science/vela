//! `vela frontier next` — the "what should I work on" projection.
//!
//! The swarm runs proved the gap: agents picked targets by convention
//! (reading a generated markdown file) because the substrate had no
//! answer to the first question every worker asks. This module derives
//! one, read-only, from state the frontier already carries:
//!
//! - **review** — undecided packs and loose pending proposals: the
//!   human's decisions, listed first because a decision unblocks
//!   everything behind it.
//! - **attack** — open campaign seeds (`campaign.yaml`, when the
//!   frontier carries one): problems in non-terminal batches with no
//!   live lease and no landed statement finding. Batch order is kept —
//!   the file IS the curated ranking.
//! - **verify** — accepted findings the gate still holds at
//!   `needs_verification`: the honest accepted-but-unverified gap,
//!   closest-to-the-bar first.
//!
//! A ranking is advice, never authority: nothing here mutates state,
//! and claiming a target still goes through the lease tool.

use std::path::Path;

use serde::Serialize;
use vela_protocol::project::Project;
use vela_protocol::verifier_attachment::{GateStatus, claim_digest, derive_gate_status};

#[derive(Debug, Clone, Serialize)]
pub struct NextTarget {
    /// "review" | "attack" | "verify"
    pub lane: String,
    /// The target handle: `vsd_…` / `vpr_…` / a seed obligation id / `vf_…`.
    pub id: String,
    pub title: String,
    pub why: String,
    pub next_command: String,
}

/// A pack awaits a decision only while it has no verdict AND at least
/// one member proposal is still pending. A reviewer who accepts the
/// members individually (`--all-pending`) leaves the pack verdict-less
/// but decided in substance — listing it as blocked would be a lie.
pub fn pack_awaits_decision(
    rec: &vela_protocol::released_diff_pack::ReleasedDiffPackRecord,
    project: &Project,
) -> bool {
    rec.verdict.is_none()
        && !rec.member_proposals.is_empty()
        && rec.member_proposals.iter().any(|m| {
            project
                .proposals
                .iter()
                .any(|p| &p.id == m && p.status == "pending_review" && p.applied_event_id.is_none())
        })
}

/// Is this lease still live at `now` (RFC3339 comparison via chrono)?
fn lease_live(claimed_at: &str, ttl_seconds: u64) -> bool {
    chrono::DateTime::parse_from_rfc3339(claimed_at)
        .map(|t| t + chrono::Duration::seconds(ttl_seconds as i64) > chrono::Utc::now())
        .unwrap_or(false)
}

/// Does any assertion reference seed `n` as a `#n` token
/// (word-boundary on the right, so `#44` does not cover `#443`)?
fn seed_covered<'a>(mut assertions: impl Iterator<Item = &'a str>, n: &str) -> bool {
    let token = format!("#{n}");
    assertions.any(|text| {
        text.match_indices(&token).any(|(i, _)| {
            text[i + token.len()..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_ascii_digit())
        })
    })
}

/// Campaign seeds from `<dir>/campaign.yaml`: `batches: [{name, state,
/// problems: […]}]`. Terminal batch states are skipped; anything else is
/// an open seed. Returns `(batch_name, problem)` in file order.
fn campaign_seeds(dir: &Path) -> Vec<(String, String)> {
    // Terminal AND in-flight states are both skipped: a batch sitting in
    // an open upstream PR is claimed work, not an open seed.
    const TERMINAL: &[&str] = &[
        "merged",
        "landed",
        "done",
        "closed",
        "accepted",
        "retired",
        "pr-open",
        "packeted",
        "submitted",
        "in-review",
    ];
    let Ok(body) = std::fs::read_to_string(dir.join("campaign.yaml")) else {
        return Vec::new();
    };
    let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&body) else {
        return Vec::new();
    };
    let mut seeds = Vec::new();
    let Some(batches) = doc.get("batches").and_then(|b| b.as_sequence()) else {
        return seeds;
    };
    for batch in batches {
        let state = batch
            .get("state")
            .and_then(|s| s.as_str())
            .unwrap_or("open");
        if TERMINAL.contains(&state) {
            continue;
        }
        let name = batch
            .get("name")
            .and_then(|s| s.as_str())
            .unwrap_or("batch")
            .to_string();
        if let Some(problems) = batch.get("problems").and_then(|p| p.as_sequence()) {
            for p in problems {
                let id = match (p.as_i64(), p.as_str()) {
                    (Some(n), _) => n.to_string(),
                    (_, Some(s)) => s.to_string(),
                    _ => continue,
                };
                seeds.push((name.clone(), id));
            }
        }
    }
    seeds
}

/// The obligation namespace in live use: the modal prefix of existing
/// lease ids (`erdos:443` → `erdos`), falling back to `seed`.
fn lease_namespace(project: &Project) -> String {
    let mut counts = std::collections::HashMap::<&str, usize>::new();
    for l in &project.attempt_claims {
        if let Some((ns, _)) = l.obligation_id.split_once(':') {
            *counts.entry(ns).or_default() += 1;
        }
    }
    counts
        .into_iter()
        .max_by_key(|(_, n)| *n)
        .map(|(ns, _)| ns.to_string())
        .unwrap_or_else(|| "seed".to_string())
}

pub fn frontier_next(
    project: &Project,
    frontier_dir: Option<&Path>,
    limit: usize,
) -> Vec<NextTarget> {
    let mut targets = Vec::new();

    // ── review: undecided packs, then loose pending proposals ─────────
    let mut packs: Vec<_> = project
        .released_diff_packs
        .iter()
        .filter(|r| pack_awaits_decision(r, project))
        .collect();
    packs.sort_by(|a, b| a.summary.cmp(&b.summary));
    let in_pack: std::collections::BTreeSet<&str> = packs
        .iter()
        .flat_map(|r| r.member_proposals.iter().map(String::as_str))
        .collect();
    for r in &packs {
        targets.push(NextTarget {
            lane: "review".into(),
            id: r.pack_id.clone(),
            title: r.summary.chars().take(80).collect(),
            why: format!(
                "{} member proposal(s) blocked on one key-custody decision",
                r.member_proposals.len()
            ),
            next_command: format!("vela accept . --pack {}", r.pack_id),
        });
    }
    for p in &project.proposals {
        if p.status == "pending_review"
            && p.applied_event_id.is_none()
            && !in_pack.contains(p.id.as_str())
        {
            targets.push(NextTarget {
                lane: "review".into(),
                id: p.id.clone(),
                title: p.reason.chars().take(80).collect(),
                why: format!("pending {} awaiting a human key", p.kind),
                next_command: format!("vela diff {}", p.id),
            });
        }
    }

    // ── attack: open campaign seeds, unleased and unlanded ─────────────
    if let Some(dir) = frontier_dir {
        let ns = lease_namespace(project);
        let live_leases: std::collections::BTreeSet<String> = project
            .attempt_claims
            .iter()
            .filter(|l| lease_live(&l.claimed_at, l.lease_ttl_seconds))
            .map(|l| l.obligation_id.clone())
            .collect();
        for (batch, seed) in campaign_seeds(dir) {
            let obligation = format!("{ns}:{seed}");
            if live_leases.contains(&obligation) || live_leases.contains(&seed) {
                continue;
            }
            if seed_covered(
                project.findings.iter().map(|b| b.assertion.text.as_str()),
                &seed,
            ) {
                continue;
            }
            targets.push(NextTarget {
                lane: "attack".into(),
                id: obligation.clone(),
                title: format!("{batch} seed {seed}"),
                why: "open campaign seed: no live lease, no landed statement".into(),
                next_command: format!(
                    "lease {obligation} via the vela_claim_task MCP tool, then draft → gate → pack"
                ),
            });
        }
    }

    // ── verify: accepted findings the gate refuses ─────────────────────
    let mut by_target: std::collections::HashMap<&str, Vec<_>> = std::collections::HashMap::new();
    for a in &project.verifier_attachments {
        by_target.entry(a.target.as_str()).or_default().push(a);
    }
    let mut verify: Vec<(usize, NextTarget)> = Vec::new();
    for bundle in &project.findings {
        use vela_protocol::bundle::ReviewState;
        if !matches!(bundle.flags.review_state, Some(ReviewState::Accepted)) {
            continue;
        }
        let attachments: Vec<_> = by_target
            .get(bundle.id.as_str())
            .map(|v| v.iter().map(|a| (*a).clone()).collect())
            .unwrap_or_default();
        let outcome = derive_gate_status(&claim_digest(&bundle.assertion.text), &attachments);
        if outcome.status == GateStatus::NeedsVerification {
            verify.push((
                attachments.len(),
                NextTarget {
                    lane: "verify".into(),
                    id: bundle.id.clone(),
                    title: bundle.assertion.text.chars().take(80).collect(),
                    why: outcome
                        .reasons
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "accepted but unverified".into()),
                    next_command: format!("vela attach . --target {} …", bundle.id),
                },
            ));
        }
    }
    // Closest to the bar first: more attachments = one run from verified.
    verify.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.id.cmp(&b.1.id)));
    targets.extend(verify.into_iter().map(|(_, t)| t));

    targets.truncate(limit);
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_token_matching_respects_digit_boundary() {
        let texts = ["FC statement draft for Erdős #443: gate green"];
        assert!(seed_covered(texts.iter().copied(), "443"));
        assert!(!seed_covered(texts.iter().copied(), "44"));
        assert!(!seed_covered(texts.iter().copied(), "4"));
    }

    #[test]
    fn expired_lease_is_not_live() {
        assert!(!lease_live("2020-01-01T00:00:00+00:00", 60));
    }
}
