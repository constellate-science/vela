//! v0.158: versioned frontier releases. Each release is a
//! content-addressed snapshot pin: `vfrr_*` over
//! `(frontier_id, snapshot_hash, event_log_hash, owner_epoch,
//! name, notes)`. Immutable: once written, releases are never
//! edited. New releases produce new vfrr_* ids and link to the
//! previous via `previous_release`.
//!
//! Releases are the substrate-side equivalent of a paper
//! edition or a software version tag. A consumer who cites a
//! Vela frontier should cite a specific release; the release id
//! pins the exact bytes the citation points at.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RELEASE_SCHEMA: &str = "vela.frontier_release.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierRelease {
    pub schema: String,
    pub release_id: String,
    pub frontier_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub owner_epoch: u64,
    pub snapshot_hash: String,
    pub event_log_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_policy_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_release: Option<String>,
    pub released_at: String,
    /// Archived-deposit DOI (e.g. Zenodo), recorded AFTER the deposit is
    /// minted. Optional and outside the release id derivation: the DOI
    /// names the archive of this release, it is not part of its content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doi: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ReleaseDraft {
    pub frontier_id: String,
    pub name: String,
    pub notes: Option<String>,
    pub owner_epoch: u64,
    pub snapshot_hash: String,
    pub event_log_hash: String,
    pub governance_policy_id: Option<String>,
    pub previous_release: Option<String>,
    pub released_at: String,
}

impl FrontierRelease {
    /// Build a release from a draft, deriving the content-
    /// addressed `vfrr_*` id from canonical bytes of the body
    /// with `release_id` excluded from the preimage.
    pub fn from_draft(draft: ReleaseDraft) -> Result<Self, String> {
        if draft.name.trim().is_empty() {
            return Err("release name must be non-empty".to_string());
        }
        if !draft.frontier_id.starts_with("vfr_") {
            return Err(format!(
                "frontier_id must start with `vfr_`, got `{}`",
                draft.frontier_id
            ));
        }
        let mut release = FrontierRelease {
            schema: RELEASE_SCHEMA.to_string(),
            release_id: String::new(),
            frontier_id: draft.frontier_id,
            name: draft.name,
            notes: draft.notes,
            owner_epoch: draft.owner_epoch,
            snapshot_hash: draft.snapshot_hash,
            event_log_hash: draft.event_log_hash,
            governance_policy_id: draft.governance_policy_id,
            previous_release: draft.previous_release,
            released_at: draft.released_at,
            doi: None,
        };
        release.release_id = release.derive_id()?;
        Ok(release)
    }

    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.release_id = String::new();
        // The DOI names the archive of this release after the fact; it is
        // never part of the content address (recording it must not
        // change the vfrr_ id).
        preimage.doi = None;
        let bytes = vela_protocol::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize release: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vfrr_{}", &hex::encode(digest)[..16]))
    }

    /// Re-derive the id and assert it matches the stored value.
    pub fn verify_content_address(&self) -> Result<(), String> {
        let derived = self.derive_id()?;
        if derived != self.release_id {
            return Err(format!(
                "release_id mismatch: stored `{}`, derived `{}`",
                self.release_id, derived
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> ReleaseDraft {
        ReleaseDraft {
            frontier_id: "vfr_abc123".to_string(),
            name: "v1.0".to_string(),
            notes: Some("First public release".to_string()),
            owner_epoch: 1,
            snapshot_hash: "0".repeat(64),
            event_log_hash: "1".repeat(64),
            governance_policy_id: None,
            previous_release: None,
            released_at: "2026-05-11T00:00:00+00:00".to_string(),
        }
    }

    #[test]
    fn id_starts_with_vfrr_and_round_trips() {
        let r = FrontierRelease::from_draft(draft()).unwrap();
        assert!(r.release_id.starts_with("vfrr_"));
        r.verify_content_address().unwrap();
    }

    #[test]
    fn id_changes_with_name() {
        let a = FrontierRelease::from_draft(draft()).unwrap();
        let mut d2 = draft();
        d2.name = "v2.0".to_string();
        let b = FrontierRelease::from_draft(d2).unwrap();
        assert_ne!(a.release_id, b.release_id);
    }

    #[test]
    fn id_changes_with_owner_epoch() {
        let a = FrontierRelease::from_draft(draft()).unwrap();
        let mut d2 = draft();
        d2.owner_epoch = 2;
        let b = FrontierRelease::from_draft(d2).unwrap();
        assert_ne!(a.release_id, b.release_id);
    }

    #[test]
    fn empty_name_rejected() {
        let mut d = draft();
        d.name = "".to_string();
        let err = FrontierRelease::from_draft(d).unwrap_err();
        assert!(err.contains("non-empty"), "got: {err}");
    }
}
