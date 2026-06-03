//! v0.151: signed verification records for Carina Proof artifacts.
//!
//! Substrate-honest split: the substrate stores attested
//! verification records; the verifier (Lean kernel, Coq, etc.)
//! runs outside the substrate. Consumers verify the attestation's
//! signature against the verifier_actor's pubkey and trust the
//! verifier's judgment for the named (tool, tool_version,
//! lake_manifest_hash) tuple.
//!
//! See `docs/PROOF_VERIFICATION.md` (shipped at v0.153) for the
//! end-to-end pipeline and `.github/workflows/verify-carina-proofs.yml`
//! for the canonical GitHub Action implementation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERIFICATION_SCHEMA: &str = "vela.proof_verification.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofVerification {
    pub schema: String,
    pub verification_id: String,
    pub proof_id: String,
    pub tool: String,
    pub tool_version: String,
    pub script_locator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lake_manifest_hash: Option<String>,
    pub verifier_output_hash: String,
    pub status: String,
    pub verified_at: String,
    pub verifier_actor: String,
    pub verifier_pubkey: String,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct VerificationDraft {
    pub proof_id: String,
    pub tool: String,
    pub tool_version: String,
    pub script_locator: String,
    pub lake_manifest_hash: Option<String>,
    pub verifier_output_hash: String,
    pub status: String,
    pub verified_at: String,
    pub verifier_actor: String,
}

impl ProofVerification {
    /// Build + sign a verification record. The signature covers
    /// the canonical preimage with `signature` and `verification_id`
    /// zeroed. The id is then derived from the signed body, so a
    /// tampered signature surfaces as an id mismatch on `verify`.
    pub fn build(
        draft: VerificationDraft,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, String> {
        if !draft.proof_id.starts_with("vpf_") {
            return Err(format!(
                "proof_id must start with `vpf_`, got `{}`",
                draft.proof_id
            ));
        }
        if !matches!(
            draft.tool.as_str(),
            "lean4" | "coq" | "isabelle" | "agda" | "metamath" | "rocq" | "other"
        ) {
            return Err(format!(
                "tool must be one of lean4|coq|isabelle|agda|metamath|rocq|other; got `{}`",
                draft.tool
            ));
        }
        if !matches!(
            draft.status.as_str(),
            "verified" | "failed" | "toolchain_mismatch"
        ) {
            return Err(format!(
                "status must be one of verified|failed|toolchain_mismatch; got `{}`",
                draft.status
            ));
        }
        let mut record = ProofVerification {
            schema: VERIFICATION_SCHEMA.to_string(),
            verification_id: String::new(),
            proof_id: draft.proof_id,
            tool: draft.tool,
            tool_version: draft.tool_version,
            script_locator: draft.script_locator,
            lake_manifest_hash: draft.lake_manifest_hash,
            verifier_output_hash: draft.verifier_output_hash,
            status: draft.status,
            verified_at: draft.verified_at,
            verifier_actor: draft.verifier_actor,
            verifier_pubkey: hex::encode(signing_key.verifying_key().to_bytes()),
            signature: String::new(),
        };
        let preimage = record.preimage_bytes()?;
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(&preimage);
        record.signature = hex::encode(sig.to_bytes());
        record.verification_id = record.derive_id()?;
        Ok(record)
    }

    pub fn preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut preimage = self.clone();
        preimage.signature = String::new();
        preimage.verification_id = String::new();
        crate::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize verification preimage: {e}"))
    }

    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.verification_id = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize verification id preimage: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vpv_{}", &hex::encode(digest)[..16]))
    }

    /// Verify the attestation: re-derive the id, verify the
    /// Ed25519 signature against `verifier_pubkey`. Optional
    /// caller check: the caller may additionally assert that the
    /// `script_locator` matches a known proof artifact's locator
    /// (the substrate does not have a global proof index at
    /// v0.151; consumers cross-link manually).
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != VERIFICATION_SCHEMA {
            return Err(format!(
                "verification.schema must be `{VERIFICATION_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        let derived = self.derive_id()?;
        if derived != self.verification_id {
            return Err(format!(
                "verification_id mismatch: stored `{}`, derived `{}`",
                self.verification_id, derived
            ));
        }
        let pk_bytes = hex::decode(&self.verifier_pubkey)
            .map_err(|e| format!("verifier_pubkey not hex: {e}"))?;
        if pk_bytes.len() != 32 {
            return Err(format!(
                "verifier_pubkey must be 32 bytes (got {})",
                pk_bytes.len()
            ));
        }
        let pk = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes
                .as_slice()
                .try_into()
                .map_err(|e| format!("verifier_pubkey: {e}"))?,
        )
        .map_err(|e| format!("verifier_pubkey malformed: {e}"))?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| format!("signature not hex: {e}"))?;
        if sig_bytes.len() != 64 {
            return Err(format!(
                "signature must be 64 bytes (got {})",
                sig_bytes.len()
            ));
        }
        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|e| format!("signature: {e}"))?,
        );
        let preimage = self.preimage_bytes()?;
        use ed25519_dalek::Verifier;
        pk.verify(&preimage, &sig)
            .map_err(|e| format!("verification signature does not verify: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key() -> ed25519_dalek::SigningKey {
        use rand::rngs::OsRng;
        ed25519_dalek::SigningKey::generate(&mut OsRng)
    }

    fn good_draft() -> VerificationDraft {
        VerificationDraft {
            proof_id: "vpf_egz_n2".to_string(),
            tool: "lean4".to_string(),
            tool_version: "4.29.1".to_string(),
            script_locator:
                "sha256:58dec20d4f8c474d222009c9d3b7cae2ef010bfac48fd5c2ad7c9c8d894428ec"
                    .to_string(),
            lake_manifest_hash: Some("sha256:0".repeat(64)),
            verifier_output_hash: format!("sha256:{}", "0".repeat(64)),
            status: "verified".to_string(),
            verified_at: "2026-05-11T00:00:00+00:00".to_string(),
            verifier_actor: "github-action:vela/.github/workflows/verify-carina-proofs.yml"
                .to_string(),
        }
    }

    #[test]
    fn build_roundtrip() {
        let sk = make_key();
        let record = ProofVerification::build(good_draft(), &sk).unwrap();
        assert!(record.verification_id.starts_with("vpv_"));
        record.verify().unwrap();
    }

    #[test]
    fn id_changes_when_status_changes() {
        let sk = make_key();
        let a = ProofVerification::build(good_draft(), &sk).unwrap();
        let mut draft = good_draft();
        draft.status = "failed".to_string();
        let b = ProofVerification::build(draft, &sk).unwrap();
        assert_ne!(a.verification_id, b.verification_id);
    }

    #[test]
    fn tampered_signature_rejected() {
        let sk = make_key();
        let mut record = ProofVerification::build(good_draft(), &sk).unwrap();
        record.signature = "0".repeat(128);
        let err = record.verify().unwrap_err();
        assert!(
            err.contains("mismatch") || err.contains("does not verify"),
            "got: {err}"
        );
    }

    #[test]
    fn invalid_status_rejected() {
        let sk = make_key();
        let mut draft = good_draft();
        draft.status = "bogus".to_string();
        let err = ProofVerification::build(draft, &sk).unwrap_err();
        assert!(err.contains("status must be"), "got: {err}");
    }
}
