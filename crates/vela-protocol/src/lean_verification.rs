//! v0.170: Lean theorem verification records. A `vlv_*` record
//! is an Ed25519-signed attestation that a specific Lean module
//! built cleanly under a specific toolchain, tying back to the
//! v0.164 `vla_*` anchor that pins the source bytes.
//!
//! Substrate-honest framing: the substrate does NOT run lake
//! itself. A trusted verifier (typically the project's GitHub
//! Action) runs `lake build`, captures the verifier output,
//! and signs the record. Consumers verify the signature
//! against the verifier's published pubkey and accept the
//! record only when the anchor's module_sha256 still matches
//! the source. Two consumers reading the same vlv_* + anchor
//! reach the same verdict.
//!
//! Composition: vla_* (v0.164) pins source bytes; vlv_*
//! (v0.170) attests that those bytes built under a specific
//! toolchain.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERIFICATION_SCHEMA: &str = "vela.lean_verification.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeanVerification {
    pub schema: String,
    pub verification_id: String,
    /// The `vla_*` anchor this verification attests to.
    pub anchor_id: String,
    pub theorem_id: u32,
    pub module: String,
    /// The module_sha256 the anchor pinned; the verifier confirms
    /// it matched at verification time.
    pub module_sha256: String,
    /// Lean toolchain pin (e.g. "leanprover/lean4:v4.29.1").
    pub lean_toolchain: String,
    /// Mathlib revision (commit or tag) the build used.
    pub mathlib_revision: String,
    /// sha256 over the verifier's full stdout+stderr+exit-code
    /// canonical bytes. Lets a re-verifier confirm byte-for-byte
    /// they got the same output.
    pub verifier_output_hash: String,
    /// "verified" | "failed" | "toolchain_mismatch".
    pub status: String,
    pub verified_at: String,
    /// Free-form verifier identity (e.g. "github-action:vela-science/vela:verify-lean-bundle").
    pub verifier_actor: String,
    pub verifier_pubkey_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone)]
pub struct VerificationDraft {
    pub anchor_id: String,
    pub theorem_id: u32,
    pub module: String,
    pub module_sha256: String,
    pub lean_toolchain: String,
    pub mathlib_revision: String,
    pub verifier_output_hash: String,
    pub status: String,
    pub verified_at: String,
    pub verifier_actor: String,
}

impl LeanVerification {
    pub fn build(draft: VerificationDraft, key: &SigningKey) -> Result<Self, String> {
        if !draft.anchor_id.starts_with("vla_") {
            return Err(format!(
                "anchor_id must start with `vla_`, got `{}`",
                draft.anchor_id
            ));
        }
        if !matches!(
            draft.status.as_str(),
            "verified" | "failed" | "toolchain_mismatch"
        ) {
            return Err(format!(
                "status must be one of verified|failed|toolchain_mismatch, got `{}`",
                draft.status
            ));
        }
        if draft.verifier_output_hash.len() != 64
            || !draft
                .verifier_output_hash
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err("verifier_output_hash must be 64 hex chars".to_string());
        }
        if draft.module_sha256.len() != 64
            || !draft.module_sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err("module_sha256 must be 64 hex chars".to_string());
        }
        let mut record = LeanVerification {
            schema: VERIFICATION_SCHEMA.to_string(),
            verification_id: String::new(),
            anchor_id: draft.anchor_id,
            theorem_id: draft.theorem_id,
            module: draft.module,
            module_sha256: draft.module_sha256,
            lean_toolchain: draft.lean_toolchain,
            mathlib_revision: draft.mathlib_revision,
            verifier_output_hash: draft.verifier_output_hash,
            status: draft.status,
            verified_at: draft.verified_at,
            verifier_actor: draft.verifier_actor,
            verifier_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: String::new(),
        };
        let preimage = record.preimage_bytes();
        let sig = key.sign(&preimage);
        record.signature_hex = hex::encode(sig.to_bytes());
        record.verification_id = record.derive_id();
        Ok(record)
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.anchor_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.module.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.module_sha256.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.lean_toolchain.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.mathlib_revision.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.verifier_output_hash.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.status.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.verified_at.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.verifier_actor.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.verifier_pubkey_hex.as_bytes());
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        hasher.update(b"|");
        hasher.update(self.signature_hex.as_bytes());
        format!("vlv_{}", &hex::encode(hasher.finalize())[..16])
    }

    /// Verify signature and id derivation. Returns Ok(()) iff
    /// both the Ed25519 signature is valid under the declared
    /// pubkey AND the verification_id was derived from the
    /// signed body.
    pub fn verify(&self) -> Result<(), String> {
        let pubkey_bytes =
            hex::decode(&self.verifier_pubkey_hex).map_err(|e| format!("decode pubkey: {e}"))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| "pubkey must be 32 bytes".to_string())?;
        let verifying =
            VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| format!("verifying key: {e}"))?;
        let sig_bytes =
            hex::decode(&self.signature_hex).map_err(|e| format!("decode signature: {e}"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying
            .verify(&self.preimage_bytes(), &sig)
            .map_err(|e| format!("signature verify: {e}"))?;
        let rederived = self.derive_id();
        if rederived != self.verification_id {
            return Err(format!(
                "verification_id mismatch: declared {}, rebuilt {}",
                self.verification_id, rederived
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn ok_draft() -> VerificationDraft {
        VerificationDraft {
            anchor_id: "vla_abc123def4567890".to_string(),
            theorem_id: 1,
            module: "Vela/Log.lean".to_string(),
            module_sha256: "a".repeat(64),
            lean_toolchain: "leanprover/lean4:v4.29.1".to_string(),
            mathlib_revision: "v4.29.1".to_string(),
            verifier_output_hash: "b".repeat(64),
            status: "verified".to_string(),
            verified_at: "2026-05-11T00:00:00Z".to_string(),
            verifier_actor: "github-action:test".to_string(),
        }
    }

    #[test]
    fn builds_signs_verifies() {
        let r = LeanVerification::build(ok_draft(), &key()).expect("build");
        assert!(r.verification_id.starts_with("vlv_"));
        r.verify().expect("verify");
    }

    #[test]
    fn tampered_body_fails_verify() {
        let mut r = LeanVerification::build(ok_draft(), &key()).expect("build");
        r.module_sha256 = "c".repeat(64);
        assert!(r.verify().is_err());
    }

    #[test]
    fn bad_status_rejected() {
        let mut d = ok_draft();
        d.status = "maybe".to_string();
        assert!(LeanVerification::build(d, &key()).is_err());
    }

    #[test]
    fn bad_hash_length_rejected() {
        let mut d = ok_draft();
        d.verifier_output_hash = "short".to_string();
        assert!(LeanVerification::build(d, &key()).is_err());
    }

    #[test]
    fn roundtrips_through_json() {
        let r = LeanVerification::build(ok_draft(), &key()).expect("build");
        let s = serde_json::to_string(&r).expect("ser");
        let back: LeanVerification = serde_json::from_str(&s).expect("de");
        assert_eq!(r, back);
        back.verify().expect("verify after roundtrip");
    }
}
