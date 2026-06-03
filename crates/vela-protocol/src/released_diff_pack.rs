//! v0.213: ReleasedDiffPackRecord — first-class replay state for the
//! v0.201 `diff_pack.released` and v0.205 `diff_pack.reviewed` event
//! arms.
//!
//! Prior cycles left these arms metadata-only (the reducer returned
//! `Ok(())` and nothing on the Project struct changed). That kept the
//! initial implementations small but left a gap: a consumer walking
//! the canonical event log alone cannot answer "what packs have been
//! released on this frontier?" — they had to read sibling
//! `.vela/diff_packs/` directories independently. Three consumers
//! (workbench, site-next, search) each duplicated that walk.
//!
//! v0.213 makes the arms mutate `Project.released_diff_packs` so the
//! event log is self-sufficient for replay. Theorem 29 pins the
//! algebra: replay of N `diff_pack.released` events produces an
//! array of length N with no duplicates by pack_id; subsequent
//! `diff_pack.reviewed` events update verdict + verdict_event_id
//! in place without changing length.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReleasedVerdict {
    Accept,
    Reject,
    Revise,
}

impl ReleasedVerdict {
    pub fn canonical(&self) -> &'static str {
        match self {
            ReleasedVerdict::Accept => "accept",
            ReleasedVerdict::Reject => "reject",
            ReleasedVerdict::Revise => "revise",
        }
    }

    pub fn from_str_ci(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "accept" | "accepted" => Some(ReleasedVerdict::Accept),
            "reject" | "rejected" => Some(ReleasedVerdict::Reject),
            "revise" | "revision" | "needs_revision" => Some(ReleasedVerdict::Revise),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReleasedDiffPackRecord {
    /// `vsd_<16hex>` content-addressed pack id.
    pub pack_id: String,
    /// `vfr_<16hex>` frontier the pack targets.
    pub frontier_id: String,
    pub summary: String,
    pub aggregate_kind: String,
    /// RFC 3339 timestamp the pack was released onto this log.
    pub released_at: String,
    /// `vev_*` id of the `diff_pack.released` event.
    pub released_event_id: String,
    /// Set once a `diff_pack.reviewed` event lands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<ReleasedVerdict>,
    /// `vev_*` id of the `diff_pack.reviewed` event when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict_event_id: Option<String>,
    /// Reviewer actor on the verdict event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_actor: Option<String>,
    /// Members the verdict applied (canonical proposals) and members
    /// it did not (SDK-only stubs). Empty until `diff_pack.reviewed`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_members: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sdk_only_members: Vec<String>,
}

impl ReleasedDiffPackRecord {
    /// Build a fresh record from a `diff_pack.released` event payload.
    pub fn from_released_event(
        pack_id: String,
        frontier_id: String,
        summary: String,
        aggregate_kind: String,
        released_at: String,
        released_event_id: String,
    ) -> Self {
        Self {
            pack_id,
            frontier_id,
            summary,
            aggregate_kind,
            released_at,
            released_event_id,
            verdict: None,
            verdict_event_id: None,
            reviewer_actor: None,
            applied_members: Vec::new(),
            sdk_only_members: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_from_str_lenient() {
        assert_eq!(
            ReleasedVerdict::from_str_ci("Accepted"),
            Some(ReleasedVerdict::Accept)
        );
        assert_eq!(
            ReleasedVerdict::from_str_ci("needs_revision"),
            Some(ReleasedVerdict::Revise)
        );
        assert_eq!(ReleasedVerdict::from_str_ci("yes"), None);
    }

    #[test]
    fn record_serializes_with_optional_verdict() {
        let r = ReleasedDiffPackRecord::from_released_event(
            "vsd_test".to_string(),
            "vfr_test".to_string(),
            "summary".to_string(),
            "kind".to_string(),
            "2026-05-13T00:00:00Z".to_string(),
            "vev_test".to_string(),
        );
        let s = serde_json::to_string(&r).unwrap();
        // No verdict set yet — should not serialize verdict / verdict_event_id.
        assert!(!s.contains("verdict"), "verdict elided when None: {s}");

        let back: ReleasedDiffPackRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(back.pack_id, "vsd_test");
        assert!(back.verdict.is_none());
    }
}
