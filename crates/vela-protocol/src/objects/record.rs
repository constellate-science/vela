//! Activity records (v0): the portable claim packet — `vela record`.
//!
//! A record is a structured PROPOSAL to change frontier state — emitted by
//! any workbench (an AI agent, a notebook, an HPC job, a lab system),
//! carried anywhere (a PR, an email, an artifact store), and landed on a
//! frontier as a pending proposal for a human key to accept. It lives in
//! the ACTIVITY plane ("activity is not state"; the claim-centric sibling
//! of the action-centric `ActivityEnvelope`): a record is NOT truth; it is
//! activity shaped so the merge layer can judge it.
//!
//! Design, deliberately git-small:
//! - content-addressed (`vrc_` + sha256(canonical body, id="")[:16]) so a
//!   receipt is immutable and citable the moment it exists;
//! - frontier-pinned: it names the `vfr_` it proposes against AND the
//!   `event_log_hash` head it was emitted against, so a reviewer sees
//!   exactly how stale it is (the decision-delta);
//! - evidence-bound: every artifact ref carries a sha256 the validator
//!   re-derives from bytes, so a receipt can't cite what it can't show;
//! - signature optional at emit (an agent without a key may still emit;
//!   `signed=false` is loud), MANDATORY judgment at accept (the human key,
//!   as everywhere in Vela). Trust enters at the gate, not the emitter.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ACTIVITY_RECORD_SCHEMA: &str = "vela.activity-record.v0.1";

/// One evidence artifact the claim rests on. `locator` is where the bytes
/// live (a path relative to the receipt, a URL, a content-addressed blob);
/// `sha256` is what makes the reference binding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordArtifact {
    /// What kind of artifact: `witness`, `log`, `dataset`, `notebook`,
    /// `proof`, `analysis` — free-form, one word.
    pub kind: String,
    pub locator: String,
    /// sha256 (hex) of the artifact's exact bytes.
    pub sha256: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// A verifier run the emitter already performed (mechanical provenance,
/// not a verdict): `method` names the verifier, `outcome` its result,
/// `output_hash` content-addresses its output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordVerifierRun {
    pub method: String,
    pub outcome: String,
    pub output_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub solver: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivityRecord {
    pub schema: String,
    /// Content-addressed id: `vrc_` + sha256(canonical body, id = "")[:16].
    pub id: String,
    /// The frontier this proposes against.
    pub frontier_id: String,
    /// The frontier head (`event_log_hash`) at emit time — the staleness pin.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub against_head: String,
    /// The claim: what the emitter asserts is now known / bounded / refuted.
    pub assertion: String,
    /// Claim type, mirroring finding types: `theoretical`, `computational`,
    /// `empirical`, `negative`.
    pub assertion_type: String,
    pub artifacts: Vec<RecordArtifact>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_runs: Vec<RecordVerifierRun>,
    /// What this claim does NOT establish. Required non-empty: a receipt
    /// with no stated limits is advertising, not science.
    pub caveats: Vec<String>,
    /// Who emitted (agent:…, ci:…, reviewer:…). Agents welcome — emitting
    /// is proposing, never deciding.
    pub emitted_by: String,
    pub emitted_at: String,
    /// Ed25519 over the canonical body with `signature` empty. OPTIONAL:
    /// an unsigned receipt is still validatable and landable; `validate`
    /// reports `signed=false` loudly.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signer_pubkey_hex: String,
}

pub struct ActivityRecordDraft {
    pub frontier_id: String,
    pub against_head: String,
    pub assertion: String,
    pub assertion_type: String,
    pub artifacts: Vec<RecordArtifact>,
    pub verifier_runs: Vec<RecordVerifierRun>,
    pub caveats: Vec<String>,
    pub emitted_by: String,
    pub emitted_at: String,
}

impl ActivityRecord {
    /// Build and content-address; sign iff a key is supplied.
    pub fn build(
        draft: ActivityRecordDraft,
        key: Option<&ed25519_dalek::SigningKey>,
    ) -> Result<Self, String> {
        if draft.assertion.trim().is_empty() {
            return Err("record assertion cannot be empty".to_string());
        }
        if !draft.frontier_id.starts_with("vfr_") {
            return Err(format!(
                "record frontier_id must be a vfr_… id, got '{}'",
                draft.frontier_id
            ));
        }
        if draft.artifacts.is_empty() {
            return Err("a record with no artifacts is a slogan; attach at least one".to_string());
        }
        for atom in &draft.artifacts {
            if atom.sha256.len() != 64 || hex::decode(&atom.sha256).is_err() {
                return Err(format!(
                    "evidence '{}' sha256 must be 32 bytes of hex",
                    atom.locator
                ));
            }
        }
        if draft.caveats.iter().all(|c| c.trim().is_empty()) {
            return Err(
                "a record must state at least one caveat (what this does NOT establish)"
                    .to_string(),
            );
        }
        if draft.emitted_by.trim().is_empty() {
            return Err("emitted_by is required (agent:…, ci:…, or reviewer:…)".to_string());
        }
        let mut rc = ActivityRecord {
            schema: ACTIVITY_RECORD_SCHEMA.to_string(),
            id: String::new(),
            frontier_id: draft.frontier_id,
            against_head: draft.against_head,
            assertion: draft.assertion,
            assertion_type: draft.assertion_type,
            artifacts: draft.artifacts,
            verifier_runs: draft.verifier_runs,
            caveats: draft.caveats,
            emitted_by: draft.emitted_by,
            emitted_at: draft.emitted_at,
            signature: String::new(),
            signer_pubkey_hex: key
                .map(|k| hex::encode(k.verifying_key().to_bytes()))
                .unwrap_or_default(),
        };
        rc.id = rc.derive_id()?;
        if let Some(k) = key {
            use ed25519_dalek::Signer;
            rc.signature = hex::encode(k.sign(&rc.signing_bytes()?).to_bytes());
        }
        Ok(rc)
    }

    /// Canonical bytes with `signature` cleared (the id is signed content;
    /// the signature is not part of the id).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut c = self.clone();
        c.signature = String::new();
        let body = crate::canonical::to_canonical_bytes(&c)?;
        Ok(crate::signing_input::signing_input(
            crate::signing_input::SigVersion::V0,
            crate::signing_input::payload_type::ACTIVITY_RECORD,
            &body,
        ))
    }

    pub fn derive_id(&self) -> Result<String, String> {
        let mut c = self.clone();
        c.id = String::new();
        c.signature = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&c)?;
        Ok(format!("vrc_{}", &hex::encode(Sha256::digest(bytes))[..16]))
    }

    /// Shape this record into the standard `finding.add` proposal draft —
    /// the ONE conversion every landing surface (CLI, MCP, future
    /// workbenches) uses, so a record always lands identically: pending,
    /// authored by the record's emitter, caveats and staleness in the
    /// conditions text a reviewer reads at accept time.
    pub fn to_finding_draft(
        &self,
        staleness: &str,
        signed: bool,
    ) -> crate::state::FindingDraftOptions {
        let conditions = format!(
            "Record {} ({}; {}). Caveats: {}. Artifacts: {} hash-verified at propose.",
            self.id,
            if signed { "signed" } else { "unsigned" },
            staleness,
            self.caveats.join(" | "),
            self.artifacts.len(),
        );
        crate::state::FindingDraftOptions {
            text: self.assertion.clone(),
            assertion_type: self.assertion_type.clone(),
            source: format!("record:{}", self.id),
            source_type: "model_output".to_string(),
            author: self.emitted_by.clone(),
            confidence: 0.3,
            evidence_type: self.assertion_type.clone(),
            doi: None,
            year: None,
            url: None,
            source_authors: vec![],
            conditions_text: Some(conditions),
            evidence_spans: vec![],
            gap: false,
            negative_space: false,
            replication_attestation: None,
        }
    }

    /// Full integrity check: schema, id re-derivation, namespace, and —
    /// when a signature is present — verification under the embedded
    /// pubkey. Returns whether the receipt is signed.
    pub fn verify(&self) -> Result<bool, String> {
        if self.schema != ACTIVITY_RECORD_SCHEMA {
            return Err(format!(
                "record schema must be {ACTIVITY_RECORD_SCHEMA}, got {}",
                self.schema
            ));
        }
        let derived = self.derive_id()?;
        if derived != self.id {
            return Err(format!(
                "record id does not re-derive: stored {}, derived {derived}",
                self.id
            ));
        }
        if self.signature.is_empty() {
            return Ok(false);
        }
        use ed25519_dalek::Verifier;
        let pk_bytes: [u8; 32] = hex::decode(&self.signer_pubkey_hex)
            .map_err(|e| format!("pubkey hex: {e}"))?
            .try_into()
            .map_err(|_| "pubkey must be 32 bytes".to_string())?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("pubkey: {e}"))?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|e| format!("signature hex: {e}"))?
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        vk.verify(&self.signing_bytes()?, &sig)
            .map_err(|_| "record signature does not verify".to_string())?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> ActivityRecordDraft {
        ActivityRecordDraft {
            frontier_id: "vfr_0123456789abcdef".into(),
            against_head: "sha256:abc".into(),
            assertion: "a(17) >= 292 for the Sidon frontier".into(),
            assertion_type: "computational".into(),
            artifacts: vec![RecordArtifact {
                kind: "witness".into(),
                locator: "witnesses/a17.json".into(),
                sha256: "a".repeat(64),
                note: String::new(),
            }],
            verifier_runs: vec![],
            caveats: vec!["lower bound only; optimality not established".into()],
            emitted_by: "agent:claude".into(),
            emitted_at: "2026-07-01T00:00:00Z".into(),
        }
    }

    fn key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn unsigned_record_builds_and_verifies_as_unsigned() {
        let r = ActivityRecord::build(draft(), None).unwrap();
        assert!(r.id.starts_with("vrc_"));
        assert!(!r.verify().unwrap());
    }

    #[test]
    fn signed_record_verifies_and_tamper_fails() {
        let r = ActivityRecord::build(draft(), Some(&key())).unwrap();
        assert!(r.verify().unwrap());
        let mut bad = r.clone();
        bad.assertion = "a(17) >= 300".into();
        assert!(bad.verify().is_err()); // id no longer re-derives
    }

    #[test]
    fn record_without_artifacts_or_caveats_refused() {
        let mut d = draft();
        d.artifacts.clear();
        assert!(ActivityRecord::build(d, None).is_err());
        let mut d = draft();
        d.caveats = vec!["".into()];
        assert!(ActivityRecord::build(d, None).is_err());
    }
}
