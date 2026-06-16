//! The cross-frontier Math Atlas projection (spec `docs/research/MATH_ATLAS.md`,
//! build step 3). It unions per-frontier claim cells into **AtlasCells**:
//! equivalence classes of findings joined by `HardIdentity` anchors, **context-
//! indexed** (the frontier-calculus context wall, §20 — a shared anchor across
//! different contexts does NOT merge; that is a transfer edge, handled later).
//!
//! This is a pure, deterministic projection over already-accepted state (no new
//! authority, no writes): same frontiers in → same atlas out. It reuses the
//! calculus directly: per-finding Belnap status and the graded bilattice point
//! `(x, y) = (κ(π_T), κ(π_F))` come from `status_provenance` / `frontier_calculus`,
//! computed in exact `Rational`s and serialized as `"num/den"`. (κ here uses the
//! unit-confidence valuation, so the coordinates sit on the Belnap corners; the
//! interior-graded κ with per-source confidence is the boundary step, step 5.)
//!
//! Step 3 scope: cells only — no equivalence overlays, no edges, no obligations.
//! Those are steps 4+ (the hypergraph and the boundary).

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::anchor::{Anchor, JoinPolicy};
use crate::evidence_diff::derive_status_provenance;
use crate::frontier_calculus::Rational;
use crate::project::Project;
use crate::status_provenance::BelnapStatus;

pub const ATLAS_SCHEMA: &str = "vela.atlas.v0.1";
/// Bumped whenever the projection logic changes; folds into `projection_hash`
/// so a cell from a different projector version is never mistaken as identical.
pub const ATLAS_PROJECTION_VERSION: &str = "atlas-proj-v0.1";

/// One node of the atlas: an equivalence class of `vf_` claims (across frontiers)
/// that share a `HardIdentity` anchor in the same context.
#[derive(Debug, Clone, Serialize)]
pub struct AtlasCell {
    /// Deterministic, projection-local id (hash of sorted members).
    pub class_id: String,
    /// Primary `HardIdentity` anchor as a citable handle ("oeis:A309370#role"),
    /// `None` for an anchorless singleton.
    pub stable_handle: Option<String>,
    /// Hash of exact membership + projection version (stable URLs key off the
    /// `stable_handle`; this detects membership/projector drift).
    pub projection_hash: String,
    /// Constituent claims, `vf_@vfr_`, sorted.
    pub members: Vec<String>,
    /// Union of the `HardIdentity` anchors across members.
    pub anchors: Vec<Anchor>,
    /// Joined Belnap status over members ("T"|"F"|"B"|"N"). `B` exposes
    /// disagreement (one member supported, another refuted) rather than hiding it.
    pub belnap: &'static str,
    /// Joined support coordinate (knowledge-order max over members), exact "num/den".
    pub support_kappa: String,
    /// Joined refutation coordinate, exact "num/den".
    pub refutation_kappa: String,
    /// A human label (a member's assertion, truncated).
    pub label: String,
    /// The claim's **self-declared** resolution status, read descriptively from
    /// the claim text ("open" | "solved" | "proved" | "disproved"), `None` when
    /// undeclared. This is NOT the verifier gate: `belnap` is the verifier-backed
    /// support state; `status` is what the claim says about the problem. Both are
    /// shown so the solved/unsolved boundary is legible without conflating
    /// "supported claim" with "solved problem".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Atlas {
    pub schema: String,
    pub projection_version: String,
    /// The frontier ids unioned into this atlas.
    pub frontiers: Vec<String>,
    pub cells: Vec<AtlasCell>,
}

struct Member {
    global_id: String,
    label: String,
    context_key: String,
    hard_anchors: Vec<Anchor>,
    support_x: Rational,
    refute_y: Rational,
    belnap: BelnapStatus,
    status: Option<&'static str>,
}

/// The identity-bearing key of an anchor (must mirror `anchor::anchors_equal`).
fn anchor_join_key(a: &Anchor) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        a.namespace,
        a.id,
        a.role,
        a.namespace_version.as_deref().unwrap_or(""),
        a.statement_fingerprint.as_deref().unwrap_or(""),
    )
}

/// The context key: a hash of the finding's conditions. Two claims sharing an
/// anchor but differing in scope are different contexts (the context wall) and
/// do NOT merge.
fn context_key_of(conditions: &crate::bundle::Conditions) -> String {
    match crate::canonical::to_canonical_bytes(conditions) {
        Ok(bytes) => hex::encode(Sha256::digest(bytes))[..16].to_string(),
        Err(_) => "ctx_unkeyable".to_string(),
    }
}

fn rat_str(r: &Rational) -> String {
    format!("{}/{}", r.numer(), r.denom())
}

/// `a >= b` for non-negative rationals with positive denominators.
fn rat_geq(a: &Rational, b: &Rational) -> bool {
    a.numer() * b.denom() >= b.numer() * a.denom()
}

fn rat_max(a: Rational, b: Rational) -> Rational {
    if rat_geq(&a, &b) { a } else { b }
}

fn belnap_str(b: BelnapStatus) -> &'static str {
    match b {
        BelnapStatus::True => "T",
        BelnapStatus::False => "F",
        BelnapStatus::Both => "B",
        BelnapStatus::None => "N",
    }
}

/// The claim's self-declared resolution status, read descriptively from its text.
/// NOT the verifier gate (that is `belnap`); this is what the claim asserts about
/// the problem. `disproved` is checked before `proved` because it contains it.
fn declared_status(text: &str) -> Option<&'static str> {
    let t = text.to_ascii_lowercase();
    if t.contains("disproved") || t.contains("disproven") {
        Some("disproved")
    } else if t.contains("solved") {
        Some("solved")
    } else if t.contains("proved") || t.contains("proven") {
        Some("proved")
    } else if t.contains("open") {
        Some("open")
    } else {
        None
    }
}

/// Project the cross-frontier atlas over a set of loaded frontiers.
#[must_use]
pub fn project(projects: &[&Project]) -> Atlas {
    let mut members: Vec<Member> = Vec::new();
    let mut frontiers: Vec<String> = Vec::new();
    let empty_conf: BTreeMap<String, Rational> = BTreeMap::new();

    for proj in projects {
        let vfr = proj
            .frontier_id
            .clone()
            .unwrap_or_else(|| proj.project.name.clone());
        frontiers.push(vfr.clone());
        for f in &proj.findings {
            let sp = derive_status_provenance(&proj.events, &f.id);
            let belnap = sp.derive_status();
            let pt = sp.derive_graded_status(&empty_conf);
            let hard_anchors: Vec<Anchor> = proj
                .anchor_links
                .iter()
                .filter(|l| l.target == f.id && l.anchor.join_policy == JoinPolicy::HardIdentity)
                .map(|l| l.anchor.clone())
                .collect();
            members.push(Member {
                global_id: format!("{}@{}", f.id, vfr),
                label: f.assertion.text.chars().take(120).collect(),
                context_key: context_key_of(&f.conditions),
                hard_anchors,
                support_x: pt.x,
                refute_y: pt.y,
                belnap,
                status: declared_status(&f.assertion.text),
            });
        }
    }
    frontiers.sort();
    frontiers.dedup();

    // Union members sharing an (anchor identity key, context key).
    let mut parent: Vec<usize> = (0..members.len()).collect();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut seen: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (i, m) in members.iter().enumerate() {
        for a in &m.hard_anchors {
            // A ProblemEntry anchor IS the problem's identity, so it joins by
            // anchor alone — the same problem in different databases phrases its
            // conditions differently, and that incidental difference must not
            // fragment the node ("one location per problem"). Claim-level anchors
            // (a specific statement) stay context-indexed: the calculus context
            // wall still forbids merging a claim across genuinely different scopes.
            let ctx = if a.kind == crate::anchor::AnchorKind::ProblemEntry {
                String::new()
            } else {
                m.context_key.clone()
            };
            let key = (anchor_join_key(a), ctx);
            if let Some(&j) = seen.get(&key) {
                let (ri, rj) = (find(&mut parent, i), find(&mut parent, j));
                if ri != rj {
                    parent[ri] = rj;
                }
            } else {
                seen.insert(key, i);
            }
        }
    }

    // Group by root, build a cell per group.
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for i in 0..members.len() {
        let r = find(&mut parent, i);
        groups.entry(r).or_default().push(i);
    }

    let mut cells: Vec<AtlasCell> = groups
        .values()
        .map(|idxs| {
            let mut member_ids: Vec<String> =
                idxs.iter().map(|&i| members[i].global_id.clone()).collect();
            member_ids.sort();

            // Union the HardIdentity anchors, dedup by identity key.
            let mut anchors: Vec<Anchor> = Vec::new();
            let mut anchor_keys: std::collections::BTreeSet<String> =
                std::collections::BTreeSet::new();
            for &i in idxs {
                for a in &members[i].hard_anchors {
                    if anchor_keys.insert(anchor_join_key(a)) {
                        anchors.push(a.clone());
                    }
                }
            }
            anchors.sort_by_key(anchor_join_key);

            // Joined Belnap: supported if any member is supported, refuted if any
            // is refuted (this is the knowledge-order join; B reveals disagreement).
            let support = idxs
                .iter()
                .any(|&i| matches!(members[i].belnap, BelnapStatus::True | BelnapStatus::Both));
            let refute = idxs
                .iter()
                .any(|&i| matches!(members[i].belnap, BelnapStatus::False | BelnapStatus::Both));
            let belnap = match (support, refute) {
                (true, true) => BelnapStatus::Both,
                (true, false) => BelnapStatus::True,
                (false, true) => BelnapStatus::False,
                (false, false) => BelnapStatus::None,
            };

            // Coordinatewise knowledge-order max over members.
            let support_kappa = idxs
                .iter()
                .map(|&i| members[i].support_x)
                .reduce(rat_max)
                .unwrap_or_else(Rational::zero);
            let refutation_kappa = idxs
                .iter()
                .map(|&i| members[i].refute_y)
                .reduce(rat_max)
                .unwrap_or_else(Rational::zero);

            let stable_handle = anchors
                .first()
                .map(|a| format!("{}:{}#{}", a.namespace, a.id, a.role));
            let label = idxs
                .iter()
                .map(|&i| members[i].label.clone())
                .min()
                .unwrap_or_default();

            // Joined declared status: the distinct non-None statuses across
            // members. One status → that; several → "contested" (the members
            // disagree about resolution); none → None.
            let statuses: std::collections::BTreeSet<&str> =
                idxs.iter().filter_map(|&i| members[i].status).collect();
            let status = match statuses.len() {
                0 => None,
                1 => statuses.iter().next().map(|s| s.to_string()),
                _ => Some("contested".to_string()),
            };

            let class_id = format!(
                "vac_{}",
                &hex::encode(Sha256::digest(member_ids.join(",").as_bytes()))[..16]
            );
            let projection_hash = hex::encode(Sha256::digest(
                format!("{}|{}", member_ids.join(","), ATLAS_PROJECTION_VERSION).as_bytes(),
            ));

            AtlasCell {
                class_id,
                stable_handle,
                projection_hash,
                members: member_ids,
                anchors,
                belnap: belnap_str(belnap),
                support_kappa: rat_str(&support_kappa),
                refutation_kappa: rat_str(&refutation_kappa),
                label,
                status,
            }
        })
        .collect();
    cells.sort_by(|a, b| a.class_id.cmp(&b.class_id));

    Atlas {
        schema: ATLAS_SCHEMA.to_string(),
        projection_version: ATLAS_PROJECTION_VERSION.to_string(),
        frontiers,
        cells,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anchor::AnchorKind;

    fn anchor(ns: &str, id: &str, role: &str, policy: JoinPolicy) -> Anchor {
        Anchor {
            namespace: ns.to_string(),
            id: id.to_string(),
            role: role.to_string(),
            kind: AnchorKind::Sequence,
            join_policy: policy,
            namespace_version: None,
            source_revision: None,
            statement_fingerprint: None,
        }
    }

    // A minimal one-finding project carrying one anchor link, asserted (so it
    // has support). Findings share the default conditions = same context.
    fn proj_with(vfr: &str, vf: &str, text: &str, a: Anchor) -> Project {
        let mut f = crate::test_support::make_finding(vf, 0.9, "math");
        f.assertion.text = text.to_string();
        let mut p = crate::test_support::make_project(vfr, vec![f]);
        p.frontier_id = Some(vfr.to_string());
        // a support event so Belnap = T
        let ev = crate::events::new_finding_event(crate::events::FindingEventInput {
            kind: "finding.asserted",
            finding_id: vf,
            actor_id: "reviewer:t",
            actor_type: "human",
            reason: "seed",
            before_hash: "sha256:null",
            after_hash: "sha256:null",
            payload: serde_json::json!({}),
            caveats: Vec::new(),
            timestamp: None,
        });
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let link = crate::anchor::AnchorLink::build(
            crate::anchor::AnchorLinkDraft {
                target: vf.to_string(),
                anchor: a,
                attached_by: "reviewer:t".to_string(),
                attached_at: "2026-06-15T00:00:00Z".to_string(),
            },
            &key,
        )
        .unwrap();
        p.events.push(ev);
        p.anchor_links.push(link);
        p
    }

    #[test]
    fn same_hard_anchor_across_frontiers_joins() {
        let a = anchor(
            "oeis",
            "A309370",
            "lower-bound a(10)",
            JoinPolicy::HardIdentity,
        );
        let p1 = proj_with("vfr_one", "vf_aaaa", "claim one", a.clone());
        let p2 = proj_with("vfr_two", "vf_bbbb", "claim two", a);
        let atlas = project(&[&p1, &p2]);
        // Two findings, one shared HardIdentity anchor → ONE cell with 2 members.
        assert_eq!(
            atlas.cells.len(),
            1,
            "shared anchor must collapse to one cell"
        );
        assert_eq!(atlas.cells[0].members.len(), 2);
        assert_eq!(
            atlas.cells[0].stable_handle.as_deref(),
            Some("oeis:A309370#lower-bound a(10)")
        );
    }

    #[test]
    fn different_role_does_not_join() {
        let p1 = proj_with(
            "vfr_one",
            "vf_aaaa",
            "lower",
            anchor(
                "oeis",
                "A309370",
                "lower-bound a(10)",
                JoinPolicy::HardIdentity,
            ),
        );
        let p2 = proj_with(
            "vfr_two",
            "vf_bbbb",
            "upper",
            anchor(
                "oeis",
                "A309370",
                "upper-bound a(10)",
                JoinPolicy::HardIdentity,
            ),
        );
        let atlas = project(&[&p1, &p2]);
        assert_eq!(
            atlas.cells.len(),
            2,
            "different role = different sub-claim = two cells"
        );
    }

    #[test]
    fn search_only_never_joins() {
        let p1 = proj_with(
            "vfr_one",
            "vf_aaaa",
            "one",
            anchor("arxiv", "2401.1", "cite", JoinPolicy::SearchOnly),
        );
        let p2 = proj_with(
            "vfr_two",
            "vf_bbbb",
            "two",
            anchor("arxiv", "2401.1", "cite", JoinPolicy::SearchOnly),
        );
        let atlas = project(&[&p1, &p2]);
        assert_eq!(
            atlas.cells.len(),
            2,
            "SearchOnly anchors never induce identity"
        );
    }
}
