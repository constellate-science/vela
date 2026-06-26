//! The cross-frontier Math Atlas projection (spec `docs/research/MATH_ATLAS.md`,
//! build step 3). It unions per-frontier claim cells into **AtlasCells**:
//! equivalence classes of findings joined by `HardIdentity` anchors, **context-
//! indexed** (the frontier-calculus context wall, §20 — a shared anchor across
//! different contexts does NOT merge; that is a transfer edge, handled later).
//!
//! This is a pure, deterministic projection over already-accepted state (no new
//! authority, no writes): same frontiers in → same atlas out. It reuses the
//! status layer directly: per-finding Belnap status comes from
//! `status_provenance`, and the two coordinates `(support, refutation)` are the
//! trivial `{0,1}` reading of that status (`1/1` when the corresponding support
//! set is non-empty, `0/1` when empty), serialized as `"num/den"`. The status
//! is a function only of whether the support/refute sets are non-empty
//! (`docs/THEORY.md` Section 7), so the cell coordinates sit exactly on the
//! Belnap corners.
//!
//! Step 3 scope: cells only — no equivalence overlays, no edges, no obligations.
//! Those are steps 4+ (the hypergraph and the boundary).

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::anchor::{Anchor, JoinPolicy};
use crate::evidence_diff::derive_status_provenance;
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

/// A typed edge between two atlas cells, lifted from finding links. `depends`
/// is state-carrying (the target's support rests on the source); the rest are
/// organizational until the calculus licenses them. Sparse today (the reduction
/// structure between problems is mostly un-ingested); grows as sources are added.
#[derive(Debug, Clone, Serialize)]
pub struct AtlasEdge {
    pub source: String,
    pub target: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Atlas {
    pub schema: String,
    pub projection_version: String,
    /// The frontier ids unioned into this atlas.
    pub frontiers: Vec<String>,
    pub cells: Vec<AtlasCell>,
    pub edges: Vec<AtlasEdge>,
}

struct Member {
    global_id: String,
    label: String,
    context_key: String,
    hard_anchors: Vec<Anchor>,
    /// The `{0,1}` support coordinate: `true` iff the support set is non-empty.
    support_x: bool,
    /// The `{0,1}` refutation coordinate: `true` iff the refute set is non-empty.
    refute_y: bool,
    belnap: BelnapStatus,
    status: Option<&'static str>,
    /// Outgoing links as (target_global_id, kind).
    links: Vec<(String, String)>,
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

/// Serialize a `{0,1}` coordinate as the exact `"num/den"` string the cell has
/// always carried (`"1/1"` for present support, `"0/1"` for absent). The status
/// layer is corner-valued, so these are the only two coordinates that occur.
fn coord_str(present: bool) -> String {
    if present {
        "1/1".to_string()
    } else {
        "0/1".to_string()
    }
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

    for proj in projects {
        let vfr = proj
            .frontier_id
            .clone()
            .unwrap_or_else(|| proj.project.name.clone());
        frontiers.push(vfr.clone());
        for f in &proj.findings {
            let sp = derive_status_provenance(&proj.events, &f.id);
            let belnap = sp.derive_status();
            // The {0,1} corner coordinates: support present iff the support set
            // is non-empty, refutation present iff the refute set is non-empty.
            let support_x = !sp.support.is_empty();
            let refute_y = !sp.refute.is_empty();
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
                support_x,
                refute_y,
                belnap,
                status: declared_status(&f.assertion.text),
                links: f
                    .links
                    .iter()
                    .map(|l| {
                        // Link targets are within-frontier vf ids unless they
                        // already carry an @vfr qualifier.
                        let tgt = if l.target.contains('@') {
                            l.target.clone()
                        } else {
                            format!("{}@{}", l.target, vfr)
                        };
                        (tgt, l.link_type.clone())
                    })
                    .collect(),
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

            // Coordinatewise knowledge-order max over members: on `{0,1}`
            // coordinates this is boolean OR (any member with that polarity).
            let support_kappa = idxs.iter().any(|&i| members[i].support_x);
            let refutation_kappa = idxs.iter().any(|&i| members[i].refute_y);

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
                support_kappa: coord_str(support_kappa),
                refutation_kappa: coord_str(refutation_kappa),
                label,
                status,
            }
        })
        .collect();
    cells.sort_by(|a, b| a.class_id.cmp(&b.class_id));

    // Lift finding links to cell edges: map each member's global id to its class,
    // then re-target each link to the class graph (dropping intra-cell self-loops
    // and deduping). Sparse today; the projection is ready as reduction data grows.
    let mut global_to_class: BTreeMap<&str, &str> = BTreeMap::new();
    for c in &cells {
        for m in &c.members {
            global_to_class.insert(m.as_str(), c.class_id.as_str());
        }
    }
    let mut edge_set: std::collections::BTreeSet<(String, String, String)> =
        std::collections::BTreeSet::new();
    for m in &members {
        let Some(&src) = global_to_class.get(m.global_id.as_str()) else {
            continue;
        };
        for (tgt_global, kind) in &m.links {
            if let Some(&tgt) = global_to_class.get(tgt_global.as_str())
                && src != tgt
            {
                edge_set.insert((src.to_string(), tgt.to_string(), kind.clone()));
            }
        }
    }
    let edges: Vec<AtlasEdge> = edge_set
        .into_iter()
        .map(|(source, target, kind)| AtlasEdge {
            source,
            target,
            kind,
        })
        .collect();

    Atlas {
        schema: ATLAS_SCHEMA.to_string(),
        projection_version: ATLAS_PROJECTION_VERSION.to_string(),
        frontiers,
        cells,
        edges,
    }
}

/// One math domain's aggregate frontier state. `belnap` is the knowledge-order
/// join (`join_k`) of the domain's claims — a field reads `B` (contested) iff
/// some claim in it is contested, `T` iff something is supported and nothing
/// refuted, etc. The distributions give the field's *shape* (how many open vs
/// resolved, how many T/F/B/N). This is frontier calculus lifted from a single
/// claim to a whole field.
#[derive(Debug, Clone, Serialize)]
pub struct DomainState {
    pub name: String,
    /// Atlas cells (problems) attributed to this domain.
    pub claim_count: usize,
    /// Aggregate Belnap from `join_k` over the cells' bilattice points.
    pub belnap: &'static str,
    /// Joined support / refutation coordinates (knowledge-order max), exact "num/den".
    pub support_kappa: String,
    pub refutation_kappa: String,
    /// Per-claim Belnap distribution (the trust shape): keys "T"|"F"|"B"|"N".
    pub belnap_counts: BTreeMap<String, usize>,
    /// Self-declared status distribution (the resolution shape).
    pub status_counts: BTreeMap<String, usize>,
    /// Claims individually contested (Belnap "B").
    pub contested: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainAtlas {
    pub schema: String,
    pub projection_version: String,
    /// Domains, sorted by claim count descending.
    pub domains: Vec<DomainState>,
}

/// Whether a `"num/den"` coordinate string carries present support (`"1/1"`).
/// On the corner-valued status layer the only coordinates are `"1/1"` and
/// `"0/1"`, so a non-`"0/1"` string is present support.
fn coord_present(s: &str) -> bool {
    s != "0/1"
}

/// The Belnap corner of a `(support, refutation)` `{0,1}` pair.
fn corner(support: bool, refute: bool) -> BelnapStatus {
    match (support, refute) {
        (true, true) => BelnapStatus::Both,
        (true, false) => BelnapStatus::True,
        (false, true) => BelnapStatus::False,
        (false, false) => BelnapStatus::None,
    }
}

/// Project a per-domain frontier state from an atlas. `problem_domains` maps an
/// Erdős problem id (the `erdos` anchor id, e.g. "102") to the domains it lives
/// in; each cell is attributed to every domain of its `erdos` anchor. The state
/// folds the cells' `{0,1}` coordinates by the knowledge-order join (boolean OR
/// per coordinate) and tallies the Belnap + status distributions. The status
/// that gives one claim a trust state now gives a whole field one — the
/// load-bearing step toward the math atlas as the trusted *state* of a domain,
/// not a list of problems.
pub fn project_domains(
    atlas: &Atlas,
    problem_domains: &BTreeMap<String, Vec<String>>,
) -> DomainAtlas {
    struct Acc {
        support: bool,
        refute: bool,
        belnap: BTreeMap<String, usize>,
        status: BTreeMap<String, usize>,
        contested: usize,
        count: usize,
    }
    let mut acc: BTreeMap<String, Acc> = BTreeMap::new();
    for cell in &atlas.cells {
        let Some(pid) = cell
            .anchors
            .iter()
            .find(|a| a.namespace == "erdos")
            .map(|a| a.id.clone())
        else {
            continue;
        };
        let Some(domains) = problem_domains.get(&pid) else {
            continue;
        };
        let support = coord_present(&cell.support_kappa);
        let refute = coord_present(&cell.refutation_kappa);
        for dom in domains {
            let e = acc.entry(dom.clone()).or_insert_with(|| Acc {
                support: false,
                refute: false,
                belnap: BTreeMap::new(),
                status: BTreeMap::new(),
                contested: 0,
                count: 0,
            });
            e.support |= support;
            e.refute |= refute;
            *e.belnap.entry(cell.belnap.to_string()).or_insert(0) += 1;
            if cell.belnap == "B" {
                e.contested += 1;
            }
            if let Some(s) = &cell.status {
                *e.status.entry(s.clone()).or_insert(0) += 1;
            }
            e.count += 1;
        }
    }
    let mut domains: Vec<DomainState> = acc
        .into_iter()
        .map(|(name, a)| DomainState {
            name,
            claim_count: a.count,
            belnap: belnap_str(corner(a.support, a.refute)),
            support_kappa: coord_str(a.support),
            refutation_kappa: coord_str(a.refute),
            belnap_counts: a.belnap,
            status_counts: a.status,
            contested: a.contested,
        })
        .collect();
    domains.sort_by(|a, b| b.claim_count.cmp(&a.claim_count).then(a.name.cmp(&b.name)));
    DomainAtlas {
        schema: "vela.atlas.domains.v0.1".to_string(),
        projection_version: ATLAS_PROJECTION_VERSION.to_string(),
        domains,
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

    #[test]
    fn project_domains_lifts_state_to_a_field() {
        // Two Erdős problems, both anchored + supported (Belnap T).
        let p1 = proj_with(
            "vfr_a",
            "vf_1",
            "Erdős #1",
            anchor("erdos", "1", "problem", JoinPolicy::HardIdentity),
        );
        let p2 = proj_with(
            "vfr_b",
            "vf_2",
            "Erdős #2",
            anchor("erdos", "2", "problem", JoinPolicy::HardIdentity),
        );
        let atlas = project(&[&p1, &p2]);
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        map.insert("1".into(), vec!["number theory".into()]);
        map.insert(
            "2".into(),
            vec!["number theory".into(), "additive combinatorics".into()],
        );
        let da = project_domains(&atlas, &map);
        // domains sorted by claim count: number theory (2) first.
        assert_eq!(da.domains[0].name, "number theory");
        let nt = da
            .domains
            .iter()
            .find(|d| d.name == "number theory")
            .unwrap();
        assert_eq!(nt.claim_count, 2);
        // both claims supported → the field's join_k corner is T.
        assert_eq!(nt.belnap, "T");
        assert_eq!(nt.contested, 0);
        let ac = da
            .domains
            .iter()
            .find(|d| d.name == "additive combinatorics")
            .unwrap();
        assert_eq!(ac.claim_count, 1); // only #2 is in additive combinatorics
    }
}
