//! T7: the first-class Contradiction object (`vcx_`).
//!
//! A `contradicts` edge is a *signal*. The Contradiction object gives
//! that signal a stable identity so review state can accrete against
//! it: "is this a real contradiction, and what did an expert decide?"
//!
//! Doctrine guardrail (from the goal memo): the platform NEVER presents
//! a contradiction as authoritatively resolved. A freshly derived
//! object is a `Candidate` — an automatically detected signal pending
//! expert review. Even an `ExpertConfirmed` or `Resolved` object
//! records *a named reviewer's judgment*, not platform-adjudicated
//! truth. [`Contradiction::claim_boundary`] encodes this at every
//! status, and `authoritative` is always `false`.
//!
//! Identity is content-addressed over the unordered finding pair plus
//! the frontier, so re-deriving candidates across runs yields the same
//! `vcx_` ids — a persistence layer can match prior review state by id
//! while resolution state evolves on top of a fixed identity.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::frontier_graph::{EdgeKind, FrontierGraph};

pub const CONTRADICTION_SCHEMA: &str = "vela.contradiction.v0.1";

/// Honest resolution state. Defaults to [`Candidate`](Self::Candidate)
/// — an unreviewed signal. The "adjudicated" states all carry the
/// named actor and timestamp so the judgment is attributable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ContradictionStatus {
    /// Auto-detected from a `contradicts` edge. Not reviewed.
    #[default]
    Candidate,
    /// A reviewer has taken it up but not yet adjudicated.
    UnderReview { by: String, at: String },
    /// A named expert confirms the contradiction is real.
    ExpertConfirmed {
        by: String,
        at: String,
        note: String,
    },
    /// Adjudicated with an outcome (one side scoped/retracted/reconciled).
    Resolved {
        by: String,
        at: String,
        resolution: String,
    },
    /// Judged not a genuine contradiction (e.g. different conditions).
    Dismissed {
        by: String,
        at: String,
        reason: String,
    },
}

impl ContradictionStatus {
    /// True once a named reviewer has rendered a judgment (confirmed,
    /// resolved, or dismissed). `Candidate` and `UnderReview` are not
    /// adjudicated.
    #[must_use]
    pub fn is_adjudicated(&self) -> bool {
        matches!(
            self,
            Self::ExpertConfirmed { .. } | Self::Resolved { .. } | Self::Dismissed { .. }
        )
    }
}

/// A candidate-or-reviewed contradiction between two findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contradiction {
    pub schema: String,
    /// `vcx_<16hex>`, content-addressed over `frontier_id | a | b`
    /// (endpoints sorted). Stable across status transitions.
    pub contradiction_id: String,
    pub frontier_id: String,
    /// The two findings in conflict, sorted so the pair is canonical.
    pub finding_a: String,
    pub finding_b: String,
    /// Why they are flagged as conflicting (edge note / shared axis).
    pub basis: String,
    #[serde(default)]
    pub status: ContradictionStatus,
    /// Bi-temporal *valid time* (distinct from the event log's
    /// transaction time). `opened_at` is when a reviewer affirmed the
    /// conflict was genuinely open in the world; `closed_at` is when it
    /// ceased (resolved or dismissed). Borrowed from Graphiti's
    /// bi-temporal model, but set ONLY by explicit human transitions —
    /// never auto-invalidated. Both `None` for an unreviewed candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
}

impl Contradiction {
    /// `vcx_<16hex>` over the sorted pair and frontier. Identity does
    /// not depend on `basis` or `status`.
    #[must_use]
    pub fn content_address(frontier_id: &str, finding_a: &str, finding_b: &str) -> String {
        let (a, b) = sorted_pair(finding_a, finding_b);
        let preimage = format!("contradiction|{frontier_id}|{a}|{b}");
        let hash = Sha256::digest(preimage.as_bytes());
        format!("vcx_{}", &hex::encode(hash)[..16])
    }

    /// Build a fresh candidate (unreviewed) contradiction.
    #[must_use]
    pub fn candidate(frontier_id: &str, finding_a: &str, finding_b: &str, basis: &str) -> Self {
        let (a, b) = sorted_pair(finding_a, finding_b);
        Self {
            schema: CONTRADICTION_SCHEMA.to_string(),
            contradiction_id: Self::content_address(frontier_id, &a, &b),
            frontier_id: frontier_id.to_string(),
            finding_a: a,
            finding_b: b,
            basis: basis.to_string(),
            status: ContradictionStatus::Candidate,
            opened_at: None,
            closed_at: None,
        }
    }

    /// Mint a CANDIDATE contradiction recording a formalism-fidelity
    /// failure: a `FormalismFidelity` adversarial probe found the formalized
    /// statement and its negation both provable (or the statement trivially
    /// true / proof using no hypothesis), so the formalization does not
    /// capture the intended claim. `formalization_ref` is the offending
    /// proof/verification id (`vlv_`/`vpv_`/`vva_`). Per the doctrine this is
    /// only ever a `Candidate` — a signal for human review, `authoritative`
    /// never true, minted at the producer seam, never inside the gate.
    #[must_use]
    pub fn from_misformalization(
        frontier_id: &str,
        finding_id: &str,
        formalization_ref: &str,
        basis: &str,
    ) -> Self {
        Self::candidate(frontier_id, finding_id, formalization_ref, basis)
    }

    /// True if the contradiction is open (unresolved) as of world-time
    /// `at`: it had been opened on or before `at` (or has no explicit
    /// open time yet) and was not closed on or before `at`. This is the
    /// bi-temporal "as-of" query — answered against valid time, not the
    /// order events landed in the log.
    #[must_use]
    pub fn is_open_at(&self, at: &str) -> bool {
        let opened = self.opened_at.as_deref().is_none_or(|o| o <= at);
        let not_closed = self.closed_at.as_deref().is_none_or(|c| c > at);
        opened && not_closed
    }

    /// True if the contradiction is currently open (never closed and
    /// not adjudicated to a terminal state).
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.closed_at.is_none()
            && !matches!(
                self.status,
                ContradictionStatus::Resolved { .. } | ContradictionStatus::Dismissed { .. }
            )
    }

    /// True once a named reviewer has rendered a judgment.
    #[must_use]
    pub fn is_adjudicated(&self) -> bool {
        self.status.is_adjudicated()
    }

    /// Transition helpers. Each preserves `contradiction_id` (identity
    /// is the pair, not the state) and returns the updated object.
    #[must_use]
    pub fn with_status(mut self, status: ContradictionStatus) -> Self {
        self.status = status;
        self
    }

    /// A named expert confirms the contradiction is real. Marks it open
    /// as of `at` if not already opened.
    #[must_use]
    pub fn expert_confirm(mut self, by: &str, at: &str, note: &str) -> Self {
        self.opened_at.get_or_insert_with(|| at.to_string());
        self.with_status(ContradictionStatus::ExpertConfirmed {
            by: by.to_string(),
            at: at.to_string(),
            note: note.to_string(),
        })
    }

    /// A named reviewer adjudicates the contradiction with an outcome.
    /// Closes the validity window at `at`.
    #[must_use]
    pub fn resolve(mut self, by: &str, at: &str, resolution: &str) -> Self {
        self.closed_at = Some(at.to_string());
        self.with_status(ContradictionStatus::Resolved {
            by: by.to_string(),
            at: at.to_string(),
            resolution: resolution.to_string(),
        })
    }

    /// A named reviewer dismisses it as not a genuine contradiction.
    /// Closes the validity window at `at`.
    #[must_use]
    pub fn dismiss(mut self, by: &str, at: &str, reason: &str) -> Self {
        self.closed_at = Some(at.to_string());
        self.with_status(ContradictionStatus::Dismissed {
            by: by.to_string(),
            at: at.to_string(),
            reason: reason.to_string(),
        })
    }

    /// Build the canonical `contradiction.resolved` event that persists
    /// this object's current state to the frontier event log. The full
    /// object travels in `payload.contradiction`; [`crate::reducer`]
    /// upserts it into `Project.contradictions` on replay.
    #[must_use]
    pub fn resolution_event(
        &self,
        actor_id: &str,
        actor_type: &str,
        reason: &str,
    ) -> crate::events::StateEvent {
        let payload = serde_json::json!({
            "contradiction": serde_json::to_value(self).unwrap_or_default(),
        });
        crate::events::new_contradiction_resolved_event(
            &self.contradiction_id,
            actor_id,
            actor_type,
            reason,
            payload,
            vec![
                "Records a named reviewer's judgment on a candidate contradiction, not platform-adjudicated truth."
                    .to_string(),
            ],
        )
    }

    /// The honest claim boundary for the current status. `authoritative`
    /// is always `false`: the platform records reviewer judgments, it
    /// never adjudicates truth itself.
    #[must_use]
    pub fn claim_boundary(&self) -> serde_json::Value {
        let (reviewed, note): (bool, &str) = match &self.status {
            ContradictionStatus::Candidate => (
                false,
                "Auto-detected candidate from a declared `contradicts` edge. Not reviewed, not adjudicated. Requires expert review before it can be treated as a real contradiction.",
            ),
            ContradictionStatus::UnderReview { .. } => (
                false,
                "Claimed by a reviewer; not yet adjudicated. Still a candidate signal.",
            ),
            ContradictionStatus::ExpertConfirmed { .. } => (
                true,
                "Confirmed real by the named reviewer. Reflects that reviewer's judgment, not platform-adjudicated truth.",
            ),
            ContradictionStatus::Resolved { .. } => (
                true,
                "Resolved by the named reviewer. Records the reviewer's resolution, not an automated verdict.",
            ),
            ContradictionStatus::Dismissed { .. } => (
                true,
                "Dismissed by the named reviewer as not a genuine contradiction. Reflects that reviewer's judgment.",
            ),
        };
        serde_json::json!({
            "reviewed": reviewed,
            "authoritative": false,
            "note": note,
        })
    }

    /// Serialize with the claim boundary attached.
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::to_value(self).unwrap_or_else(|_| serde_json::json!({}));
        if let serde_json::Value::Object(map) = &mut v {
            map.insert("claim_boundary".to_string(), self.claim_boundary());
        }
        v
    }
}

fn sorted_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

/// Derive candidate contradictions from a frontier's typed claim graph.
/// One object per unordered contradicting pair; `basis` is taken from
/// the first non-empty `contradicts` edge note between the pair, or a
/// default when none is recorded. All returned objects are
/// `Candidate` — derivation never adjudicates.
#[must_use]
pub fn derive_candidates(graph: &FrontierGraph, frontier_id: &str) -> Vec<Contradiction> {
    // First non-empty note per unordered pair, collected in one pass —
    // avoids rescanning every contradicts edge once per pair.
    let mut notes: std::collections::HashMap<(&str, &str), &str> = std::collections::HashMap::new();
    for e in graph.edges_of_kind(EdgeKind::Contradicts) {
        if e.note.is_empty() {
            continue;
        }
        let key = if e.source <= e.target {
            (e.source.as_str(), e.target.as_str())
        } else {
            (e.target.as_str(), e.source.as_str())
        };
        notes.entry(key).or_insert(e.note.as_str());
    }
    graph
        .contradiction_pairs()
        .into_iter()
        .map(|(a, b)| {
            // contradiction_pairs() returns sorted (a <= b) pairs, so
            // the key matches the note map's ordering.
            let basis = notes
                .get(&(a.as_str(), b.as_str()))
                .copied()
                .unwrap_or("declared contradiction edge");
            Contradiction::candidate(frontier_id, &a, &b, basis)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::assemble;
    use crate::project::reverse_dep_index_tests::{link_to, synth_finding};

    fn contradicts_to(target: &str, note: &str) -> crate::bundle::Link {
        let mut link = link_to(target);
        link.link_type = "contradicts".into();
        link.note = note.into();
        link
    }

    #[test]
    fn id_is_stable_across_order_and_status() {
        let a = "vf_1111111111111111";
        let b = "vf_2222222222222222";
        let id1 = Contradiction::content_address("vfr_x", a, b);
        let id2 = Contradiction::content_address("vfr_x", b, a);
        assert_eq!(id1, id2, "pair order must not change identity");
        assert!(id1.starts_with("vcx_"));

        let c = Contradiction::candidate("vfr_x", a, b, "basis");
        let resolved = c.clone().with_status(ContradictionStatus::Resolved {
            by: "actor:expert".into(),
            at: "2026-05-31T00:00:00Z".into(),
            resolution: "scoped to in-vitro".into(),
        });
        assert_eq!(
            c.contradiction_id, resolved.contradiction_id,
            "status transition must preserve identity"
        );
    }

    #[test]
    fn misformalization_mints_a_candidate_only() {
        // A formalism-fidelity failure mints a Candidate contradiction
        // pointing at the offending proof, never auto-adjudicated.
        let c = Contradiction::from_misformalization(
            "vfr_x",
            "vf_finding",
            "vlv_badproof00000000",
            "formalism fidelity: statement and negation both provable",
        );
        assert_eq!(c.status, ContradictionStatus::Candidate);
        assert!(!c.is_adjudicated());
        assert_eq!(c.claim_boundary()["authoritative"], false);
        // Re-deriving the same misformalization yields the same id (stable).
        let c2 = Contradiction::from_misformalization(
            "vfr_x",
            "vf_finding",
            "vlv_badproof00000000",
            "different basis text",
        );
        assert_eq!(c.contradiction_id, c2.contradiction_id);
    }

    #[test]
    fn candidate_is_not_adjudicated_and_boundary_is_honest() {
        let c = Contradiction::candidate("vfr_x", "vf_a", "vf_b", "basis");
        assert_eq!(c.status, ContradictionStatus::Candidate);
        assert!(!c.is_adjudicated());
        let cb = c.claim_boundary();
        assert_eq!(cb["reviewed"], false);
        assert_eq!(cb["authoritative"], false);

        let confirmed = c.with_status(ContradictionStatus::ExpertConfirmed {
            by: "actor:neuro".into(),
            at: "2026-05-31T00:00:00Z".into(),
            note: "real under matched assay".into(),
        });
        assert!(confirmed.is_adjudicated());
        // Even confirmed, the platform never claims authority.
        assert_eq!(confirmed.claim_boundary()["authoritative"], false);
        assert_eq!(confirmed.claim_boundary()["reviewed"], true);
    }

    #[test]
    fn derive_candidates_matches_graph_pairs_with_basis() {
        let x = synth_finding(0, vec![]);
        let mut y = synth_finding(
            1,
            vec![contradicts_to(&x.id, "opposite sign on shared entity")],
        );
        // Add the reverse edge too — still one candidate.
        y.links.push(contradicts_to(&x.id, ""));
        let (x_id, y_id) = (x.id.clone(), y.id.clone());

        let mut project = assemble("contra", vec![], 0, 0, "test");
        project.findings = vec![x, y];
        let graph = FrontierGraph::from_project(&project);

        let cands = derive_candidates(&graph, "vfr_test");
        assert_eq!(cands.len(), 1);
        assert!(cands[0].contradiction_id.starts_with("vcx_"));
        assert_eq!(cands[0].basis, "opposite sign on shared entity");
        // Endpoints sorted and matching the pair.
        let expected = if x_id <= y_id {
            (x_id, y_id)
        } else {
            (y_id, x_id)
        };
        assert_eq!(
            (cands[0].finding_a.clone(), cands[0].finding_b.clone()),
            expected
        );
        assert!(!cands[0].is_adjudicated());
    }

    #[test]
    fn resolution_event_persists_through_the_reducer() {
        let mut project = assemble("contra-ev", vec![], 0, 0, "test");
        let fid = project.frontier_id();
        let c = Contradiction::candidate(&fid, "vf_aaaa", "vf_bbbb", "basis").expert_confirm(
            "actor:neuro",
            "2026-05-31T00:00:00Z",
            "real under matched assay",
        );
        let event = c.resolution_event("actor:neuro", "human", "confirmed after review");
        assert_eq!(event.kind, "contradiction.resolved");
        assert_eq!(event.target.id, c.contradiction_id);

        crate::reducer::apply_event(&mut project, &event).unwrap();
        assert_eq!(project.contradictions.len(), 1);
        assert_eq!(
            project.contradictions[0].contradiction_id,
            c.contradiction_id
        );
        assert!(project.contradictions[0].is_adjudicated());

        // Idempotent: re-applying the same event does not duplicate.
        crate::reducer::apply_event(&mut project, &event).unwrap();
        assert_eq!(project.contradictions.len(), 1);
    }

    #[test]
    fn latest_resolution_wins_on_replay() {
        let mut project = assemble("contra-latest", vec![], 0, 0, "test");
        let fid = project.frontier_id();
        let base = Contradiction::candidate(&fid, "vf_aaaa", "vf_bbbb", "basis");

        let confirmed = base
            .clone()
            .expert_confirm("actor:x", "2026-05-31T00:00:00Z", "real");
        let dismissed = base.dismiss("actor:y", "2026-05-31T01:00:00Z", "different conditions");

        crate::reducer::apply_event(
            &mut project,
            &confirmed.resolution_event("actor:x", "human", "confirm"),
        )
        .unwrap();
        crate::reducer::apply_event(
            &mut project,
            &dismissed.resolution_event("actor:y", "human", "dismiss"),
        )
        .unwrap();

        assert_eq!(project.contradictions.len(), 1);
        assert!(matches!(
            project.contradictions[0].status,
            ContradictionStatus::Dismissed { .. }
        ));
    }

    #[test]
    fn forged_id_is_rejected_by_the_reducer() {
        let mut project = assemble("contra-forge", vec![], 0, 0, "test");
        let fid = project.frontier_id();
        let mut c = Contradiction::candidate(&fid, "vf_aaaa", "vf_bbbb", "basis");
        c.contradiction_id = "vcx_0000000000000000".to_string(); // does not match pair
        let event = c.resolution_event("actor:x", "human", "bad");
        assert!(crate::reducer::apply_event(&mut project, &event).is_err());
        assert!(project.contradictions.is_empty());
    }

    #[test]
    fn bitemporal_validity_window_tracks_open_and_close() {
        let c = Contradiction::candidate("vfr_x", "vf_a", "vf_b", "basis");
        assert!(c.is_open(), "fresh candidate is open");
        assert!(c.opened_at.is_none() && c.closed_at.is_none());

        let confirmed = c.expert_confirm("actor:e", "2026-03-01T00:00:00Z", "real");
        assert_eq!(confirmed.opened_at.as_deref(), Some("2026-03-01T00:00:00Z"));
        assert!(confirmed.is_open());

        let resolved = confirmed.resolve("actor:e", "2026-05-01T00:00:00Z", "scoped to in-vitro");
        assert_eq!(resolved.closed_at.as_deref(), Some("2026-05-01T00:00:00Z"));
        assert!(!resolved.is_open(), "resolved is closed");

        // As-of queries answer against valid time, not log order:
        assert!(
            !resolved.is_open_at("2026-01-01T00:00:00Z"),
            "before it opened"
        );
        assert!(
            resolved.is_open_at("2026-04-01T00:00:00Z"),
            "open mid-window"
        );
        assert!(
            !resolved.is_open_at("2026-06-01T00:00:00Z"),
            "after it closed"
        );
    }

    #[test]
    fn round_trips_through_serde() {
        let c = Contradiction::candidate("vfr_x", "vf_a", "vf_b", "basis").with_status(
            ContradictionStatus::Dismissed {
                by: "actor:r".into(),
                at: "2026-05-31T00:00:00Z".into(),
                reason: "different conditions".into(),
            },
        );
        let s = serde_json::to_string(&c).unwrap();
        let back: Contradiction = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }
}
