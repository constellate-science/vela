//! v0.203: Diff Pack workbench-side review surface.
//!
//! A reviewer opens a `vsd_*` Scientific Diff Pack in the workbench,
//! inspects every member proposal inline, and issues a verdict:
//! accept / reject / revise. The verdict is signed by the workbench
//! actor and written to `.vela/pending_verdicts/<vpv_id>.json`.
//!
//! Substrate-honest framing: at v0.203, a *pending* verdict is not
//! yet a canonical event. The reducer-side `diff_pack.reviewed` arm
//! lands at v0.205 along with Theorem 26 (verdict atomicity). Until
//! then, pending verdicts sit in a sibling directory and are picked
//! up by v0.205's migration path. This separation keeps the v0.193
//! replay path unperturbed while the reviewer flow is built out.
//!
//! Pending verdict id derivation:
//!   `vpv_<16hex>` over sha256("|"-joined preimage of
//!   pack_id | verdict_outcome | reviewer_actor | reason | at).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const PENDING_VERDICT_SCHEMA: &str = "vela.pending_diff_pack_verdict.v0.1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DiffPackVerdict {
    Accept,
    Reject,
    Revise,
}

impl DiffPackVerdict {
    pub fn canonical(&self) -> &'static str {
        match self {
            DiffPackVerdict::Accept => "accept",
            DiffPackVerdict::Reject => "reject",
            DiffPackVerdict::Revise => "revise",
        }
    }

    pub fn from_str_ci(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "accept" | "accepted" => Some(DiffPackVerdict::Accept),
            "reject" | "rejected" => Some(DiffPackVerdict::Reject),
            "revise" | "revision" | "needs_revision" => Some(DiffPackVerdict::Revise),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingVerdict {
    pub schema: String,
    pub verdict_id: String,
    pub pack_id: String,
    pub verdict: DiffPackVerdict,
    pub reviewer_actor: String,
    pub reason: String,
    pub at: String,
}

impl PendingVerdict {
    /// Build a pending verdict. The verdict_id is content-addressed
    /// over the body; identical inputs always produce the same id.
    pub fn build(
        pack_id: impl Into<String>,
        verdict: DiffPackVerdict,
        reviewer_actor: impl Into<String>,
        reason: impl Into<String>,
        at: impl Into<String>,
    ) -> Result<Self, String> {
        let pack_id = pack_id.into();
        if !pack_id.starts_with("vsd_") {
            return Err(format!("pack_id must start with `vsd_`, got `{pack_id}`"));
        }
        let reviewer_actor = reviewer_actor.into();
        if reviewer_actor.is_empty() {
            return Err("reviewer_actor cannot be empty".to_string());
        }
        let at = at.into();
        if at.is_empty() {
            return Err("at cannot be empty".to_string());
        }
        let mut pv = Self {
            schema: PENDING_VERDICT_SCHEMA.to_string(),
            verdict_id: String::new(),
            pack_id,
            verdict,
            reviewer_actor,
            reason: reason.into(),
            at,
        };
        pv.verdict_id = pv.derive_id();
        Ok(pv)
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.pack_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.verdict.canonical().as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.reviewer_actor.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.reason.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.at.as_bytes());
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        format!("vpv_{}", &hex::encode(hasher.finalize())[..16])
    }

    /// Verify: the declared verdict_id matches a fresh re-derivation.
    pub fn verify(&self) -> Result<(), String> {
        let rederived = self.derive_id();
        if rederived != self.verdict_id {
            return Err(format!(
                "verdict_id mismatch: declared {}, rebuilt {}",
                self.verdict_id, rederived
            ));
        }
        Ok(())
    }
}

/// Directory where pending verdicts are stored under a frontier
/// repo. Sibling of `.vela/events/`; never re-played by the v0.193
/// reducer.
pub fn pending_verdicts_dir(repo_path: &Path) -> PathBuf {
    repo_path.join(".vela").join("pending_verdicts")
}

/// Write a freshly-built pending verdict for the given pack. Returns
/// the verdict_id on success. The verdict is workbench-only: it does
/// not pass through the reducer in v0.203 and never becomes part of
/// `frontier.events` at this cycle.
pub fn record_at_path(
    repo_path: &Path,
    pack_id: &str,
    verdict: DiffPackVerdict,
    reviewer_actor: &str,
    reason: &str,
    at: &str,
) -> Result<String, String> {
    // Validate the pack exists in the frontier's .vela/diff_packs/
    // directory before writing a verdict for it. A verdict on a
    // missing pack is meaningless.
    let pack_path = repo_path
        .join(".vela")
        .join("diff_packs")
        .join(format!("{pack_id}.json"));
    if !pack_path.is_file() {
        return Err(format!(
            "pack {pack_id} not found at {}; cannot record verdict",
            pack_path.display()
        ));
    }

    let pv = PendingVerdict::build(pack_id, verdict, reviewer_actor, reason, at)?;

    let dir = pending_verdicts_dir(repo_path);
    fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let out = dir.join(format!("{}.json", pv.verdict_id));

    // Idempotent: re-recording the same (pack, verdict, reviewer,
    // reason, at) tuple is a no-op. Content-addressing means the
    // file path is the same.
    let body = serde_json::to_string_pretty(&pv).map_err(|e| format!("serialize: {e}"))?;
    fs::write(&out, format!("{body}\n")).map_err(|e| format!("write {}: {e}", out.display()))?;
    Ok(pv.verdict_id)
}

/// List every pending verdict on disk, newest first by `at`.
pub fn list_at_path(repo_path: &Path) -> Vec<PendingVerdict> {
    let dir = pending_verdicts_dir(repo_path);
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<PendingVerdict> = Vec::new();
    for e in entries.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        if let Ok(body) = fs::read_to_string(&p)
            && let Ok(pv) = serde_json::from_str::<PendingVerdict>(&body)
        {
            out.push(pv);
        }
    }
    out.sort_by(|a, b| b.at.cmp(&a.at));
    out
}

/// Return the pending verdict for `pack_id`, if any. If multiple
/// verdicts exist for the same pack (a reviewer changed their mind),
/// the most recent by `at` is returned.
pub fn latest_for_pack(repo_path: &Path, pack_id: &str) -> Option<PendingVerdict> {
    list_at_path(repo_path)
        .into_iter()
        .find(|v| v.pack_id == pack_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fixture_pack(repo: &Path, pack_id: &str) {
        let dir = repo.join(".vela").join("diff_packs");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("{pack_id}.json")),
            r#"{"schema":"vela.scientific_diff.v0.1","pack_id":"vsd_test"}"#,
        )
        .unwrap();
    }

    #[test]
    fn verdict_id_is_deterministic() {
        let v1 = PendingVerdict::build(
            "vsd_aaaaaaaaaaaaaaaa",
            DiffPackVerdict::Accept,
            "reviewer:workbench",
            "lgtm",
            "2026-05-12T00:00:00Z",
        )
        .unwrap();
        let v2 = PendingVerdict::build(
            "vsd_aaaaaaaaaaaaaaaa",
            DiffPackVerdict::Accept,
            "reviewer:workbench",
            "lgtm",
            "2026-05-12T00:00:00Z",
        )
        .unwrap();
        assert_eq!(v1.verdict_id, v2.verdict_id);
        assert!(v1.verdict_id.starts_with("vpv_"));
        assert_eq!(v1.verdict_id.len(), 4 + 16);
    }

    #[test]
    fn different_verdict_outcome_changes_id() {
        let v1 = PendingVerdict::build(
            "vsd_aaaaaaaaaaaaaaaa",
            DiffPackVerdict::Accept,
            "reviewer:workbench",
            "ok",
            "2026-05-12T00:00:00Z",
        )
        .unwrap();
        let v2 = PendingVerdict::build(
            "vsd_aaaaaaaaaaaaaaaa",
            DiffPackVerdict::Reject,
            "reviewer:workbench",
            "ok",
            "2026-05-12T00:00:00Z",
        )
        .unwrap();
        assert_ne!(v1.verdict_id, v2.verdict_id);
    }

    #[test]
    fn non_vsd_pack_id_rejected() {
        assert!(
            PendingVerdict::build(
                "vpr_not_a_pack",
                DiffPackVerdict::Accept,
                "reviewer:workbench",
                "",
                "2026-05-12T00:00:00Z"
            )
            .is_err()
        );
    }

    #[test]
    fn from_str_ci_is_lenient() {
        assert_eq!(
            DiffPackVerdict::from_str_ci("Accept"),
            Some(DiffPackVerdict::Accept)
        );
        assert_eq!(
            DiffPackVerdict::from_str_ci("accepted"),
            Some(DiffPackVerdict::Accept)
        );
        assert_eq!(
            DiffPackVerdict::from_str_ci("Needs_Revision"),
            Some(DiffPackVerdict::Revise)
        );
        assert_eq!(DiffPackVerdict::from_str_ci("yes please"), None);
    }

    #[test]
    fn record_at_path_round_trip() {
        let tmp = tempdir().unwrap();
        fixture_pack(tmp.path(), "vsd_be61da0cdcba08ed");
        let id = record_at_path(
            tmp.path(),
            "vsd_be61da0cdcba08ed",
            DiffPackVerdict::Accept,
            "reviewer:workbench",
            "lgtm",
            "2026-05-12T00:00:00Z",
        )
        .unwrap();
        assert!(id.starts_with("vpv_"));
        let written = pending_verdicts_dir(tmp.path()).join(format!("{id}.json"));
        assert!(written.is_file());
        let pv: PendingVerdict =
            serde_json::from_str(&fs::read_to_string(&written).unwrap()).unwrap();
        pv.verify().unwrap();
    }

    #[test]
    fn record_at_path_requires_pack_on_disk() {
        let tmp = tempdir().unwrap();
        // No fixture pack on disk; record should fail.
        let res = record_at_path(
            tmp.path(),
            "vsd_aaaaaaaaaaaaaaaa",
            DiffPackVerdict::Accept,
            "reviewer:workbench",
            "",
            "2026-05-12T00:00:00Z",
        );
        assert!(res.is_err());
    }

    #[test]
    fn list_and_latest_return_expected() {
        let tmp = tempdir().unwrap();
        fixture_pack(tmp.path(), "vsd_be61da0cdcba08ed");
        record_at_path(
            tmp.path(),
            "vsd_be61da0cdcba08ed",
            DiffPackVerdict::Revise,
            "reviewer:workbench",
            "needs more context",
            "2026-05-12T00:00:00Z",
        )
        .unwrap();
        record_at_path(
            tmp.path(),
            "vsd_be61da0cdcba08ed",
            DiffPackVerdict::Accept,
            "reviewer:workbench",
            "addressed",
            "2026-05-12T01:00:00Z",
        )
        .unwrap();
        let listed = list_at_path(tmp.path());
        assert_eq!(listed.len(), 2);
        // Newest first.
        assert_eq!(listed[0].at, "2026-05-12T01:00:00Z");
        let latest = latest_for_pack(tmp.path(), "vsd_be61da0cdcba08ed").unwrap();
        assert_eq!(latest.verdict, DiffPackVerdict::Accept);
    }
}
