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

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::tcb_policy::AxiomVerdict;

/// The frozen v0.1 schema. Records carrying this schema use the original
/// nine-field preimage (no axiom block), so their historical Ed25519
/// signatures stay valid forever. Never change the v0.1 preimage layout.
pub const VERIFICATION_SCHEMA_V1: &str = "vela.lean_verification.v0.1";

/// The current schema. v0.2 records append the axiom-hardening block
/// (`tcb_id`, axioms, axiom verdict, kernel re-check, axioms-output hash) to
/// the signed preimage. `build` always mints v0.2.
pub const VERIFICATION_SCHEMA: &str = "vela.lean_verification.v0.2";

/// Outcome of an external kernel re-check (lean4checker / Lean4Lean) over the
/// compiled artifact, independent of the `lake build` elaboration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelRecheck {
    /// An independent kernel checker re-validated the proof term.
    Passed,
    /// The independent checker rejected the proof term.
    Failed,
    /// No external re-check ran (e.g. no checker built for the toolchain).
    NotRun,
}

impl KernelRecheck {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::NotRun => "not_run",
        }
    }
}

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
    /// "verified" | "failed" | "toolchain_mismatch" | "failed_axiom_check"
    /// | "compiler_checked". `"verified"` requires `axiom_verdict =
    /// kernel_clean` and `kernel_recheck != failed`.
    pub status: String,
    pub verified_at: String,
    /// Free-form verifier identity (e.g. "github-action:vela-science/vela:verify-lean-bundle").
    pub verifier_actor: String,
    // --- axiom hardening (v0.2) ---
    /// The `vtcb_` policy this verification was judged against. Empty on
    /// legacy v0.1 records.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tcb_id: String,
    /// The exact axiom names `#print axioms <decl>` reported, sorted. Empty
    /// on legacy records (axioms unknown).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub axioms: Vec<String>,
    /// Verdict of `TcbPolicy::classify(axioms)`. None on legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub axiom_verdict: Option<AxiomVerdict>,
    /// Outcome of the external kernel re-check. None on legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_recheck: Option<KernelRecheck>,
    /// sha256 over the `#print axioms` stdout for this decl. Empty on legacy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub axioms_output_hash: String,
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
    // --- axiom hardening (v0.2); pass empty/None for an axiom-unknown record ---
    pub tcb_id: String,
    pub axioms: Vec<String>,
    pub axiom_verdict: Option<AxiomVerdict>,
    pub kernel_recheck: Option<KernelRecheck>,
    pub axioms_output_hash: String,
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
            "verified"
                | "failed"
                | "toolchain_mismatch"
                | "failed_axiom_check"
                | "compiler_checked"
        ) {
            return Err(format!(
                "status must be one of verified|failed|toolchain_mismatch|failed_axiom_check|compiler_checked, got `{}`",
                draft.status
            ));
        }
        // `verified` is reserved for a kernel-clean axiom set whose external
        // re-check did not fail. A compiler-trust / sorry proof cannot be
        // minted as verified.
        if draft.status == "verified" {
            match draft.axiom_verdict {
                Some(AxiomVerdict::KernelClean) => {}
                Some(other) => {
                    return Err(format!(
                        "status `verified` requires axiom_verdict=kernel_clean, got `{}`",
                        other.as_str()
                    ));
                }
                None => {} // axioms unknown (legacy-style build); allowed but not asserting cleanliness
            }
            if draft.kernel_recheck == Some(KernelRecheck::Failed) {
                return Err(
                    "status `verified` cannot accompany a failed external kernel re-check"
                        .to_string(),
                );
            }
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
            tcb_id: draft.tcb_id,
            axioms: draft.axioms,
            axiom_verdict: draft.axiom_verdict,
            kernel_recheck: draft.kernel_recheck,
            axioms_output_hash: draft.axioms_output_hash,
            verifier_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: String::new(),
        };
        let preimage = record.preimage_bytes();
        record.signature_hex = hex::encode(crate::sign::sign_bytes(key, &preimage));
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
        // v0.2+ appends the axiom-hardening block. A v0.1 record omits it
        // entirely, so its preimage — and therefore its historical Ed25519
        // signature and `vlv_` id — is byte-for-byte unchanged. The schema
        // string is what selects the layout; never alter the v0.1 branch.
        if self.schema != VERIFICATION_SCHEMA_V1 {
            out.push(b'|');
            out.extend_from_slice(self.tcb_id.as_bytes());
            out.push(b'|');
            out.extend_from_slice(self.axioms.join(",").as_bytes());
            out.push(b'|');
            out.extend_from_slice(
                self.axiom_verdict
                    .map(AxiomVerdict::as_str)
                    .unwrap_or("")
                    .as_bytes(),
            );
            out.push(b'|');
            out.extend_from_slice(
                self.kernel_recheck
                    .map(KernelRecheck::as_str)
                    .unwrap_or("")
                    .as_bytes(),
            );
            out.push(b'|');
            out.extend_from_slice(self.axioms_output_hash.as_bytes());
        }
        out
    }

    /// Map this verification's axiom result to the method integrity the gate
    /// consumes (G5). A kernel-clean axiom set with no failed external
    /// re-check is `Sound`; a forbidden/unlisted axiom or a failed re-check is
    /// `Compromised`; an axiom-unknown (legacy) record is `Unattested`. The
    /// gate never imports Lean types — only this `MethodIntegrity`.
    #[must_use]
    pub fn to_attachment_integrity(&self) -> crate::verifier_attachment::MethodIntegrity {
        use crate::verifier_attachment::MethodIntegrity;
        if self.kernel_recheck == Some(KernelRecheck::Failed) {
            return MethodIntegrity::Compromised;
        }
        match self.axiom_verdict {
            Some(AxiomVerdict::KernelClean) => MethodIntegrity::Sound,
            Some(_) => MethodIntegrity::Compromised,
            None => MethodIntegrity::Unattested,
        }
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
        if !crate::sign::verify_action_signature(
            &self.preimage_bytes(),
            &self.signature_hex,
            &self.verifier_pubkey_hex,
        )? {
            return Err(
                "lean verification signature does not verify under the declared pubkey".to_string(),
            );
        }
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
            tcb_id: "vtcb_0123456789abcdef".to_string(),
            axioms: vec!["Classical.choice".to_string(), "propext".to_string()],
            axiom_verdict: Some(AxiomVerdict::KernelClean),
            kernel_recheck: Some(KernelRecheck::Passed),
            axioms_output_hash: "d".repeat(64),
        }
    }

    /// Hand-build a v0.1 record exactly as the pre-axiom builder would have:
    /// schema v0.1, no axiom fields, signed over the original 10-field
    /// preimage. Used to prove the migration preserves historical signatures.
    fn legacy_v01_record(key: &SigningKey) -> LeanVerification {
        let mut r = LeanVerification {
            schema: VERIFICATION_SCHEMA_V1.to_string(),
            verification_id: String::new(),
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
            tcb_id: String::new(),
            axioms: vec![],
            axiom_verdict: None,
            kernel_recheck: None,
            axioms_output_hash: String::new(),
            verifier_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
            signature_hex: String::new(),
        };
        let preimage = r.preimage_bytes();
        r.signature_hex = hex::encode(crate::sign::sign_bytes(key, &preimage));
        r.verification_id = r.derive_id();
        r
    }

    #[test]
    fn builds_signs_verifies() {
        let r = LeanVerification::build(ok_draft(), &key()).expect("build");
        assert!(r.verification_id.starts_with("vlv_"));
        assert_eq!(r.schema, VERIFICATION_SCHEMA); // v0.2
        r.verify().expect("verify");
    }

    #[test]
    fn v01_record_still_verifies_under_v02_schema() {
        // The migration guarantee: a record minted before the axiom block
        // existed still verifies, and its preimage omits the v0.2 block
        // byte-for-byte (so its historical signature/id are unchanged).
        let k = key();
        let r = legacy_v01_record(&k);
        r.verify().expect("legacy v0.1 record must still verify");

        let expected_old = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            r.anchor_id,
            r.module,
            r.module_sha256,
            r.lean_toolchain,
            r.mathlib_revision,
            r.verifier_output_hash,
            r.status,
            r.verified_at,
            r.verifier_actor,
            r.verifier_pubkey_hex,
        );
        assert_eq!(
            r.preimage_bytes(),
            expected_old.as_bytes(),
            "v0.1 preimage must equal the original 10-field layout (no axiom block)"
        );
    }

    #[test]
    fn axiom_fields_enter_preimage() {
        // Flipping an axiom field on a signed v0.2 record breaks verify(),
        // proving the axiom result is covered by the signature.
        let mut r = LeanVerification::build(ok_draft(), &key()).expect("build");
        assert!(r.verify().is_ok());
        r.axiom_verdict = Some(AxiomVerdict::ForbiddenAxiom);
        assert!(
            r.verify().is_err(),
            "axiom_verdict must be inside the signed preimage"
        );
    }

    #[test]
    fn verified_status_requires_kernel_clean() {
        let mut d = ok_draft();
        d.axiom_verdict = Some(AxiomVerdict::ForbiddenAxiom);
        // status stays "verified" but verdict is forbidden -> build must reject
        assert!(LeanVerification::build(d, &key()).is_err());
    }

    #[test]
    fn compiler_checked_status_is_valid() {
        let mut d = ok_draft();
        d.status = "compiler_checked".to_string();
        d.axiom_verdict = Some(AxiomVerdict::ForbiddenAxiom);
        d.axioms = vec!["Lean.ofReduceBool".to_string()];
        let r = LeanVerification::build(d, &key()).expect("compiler_checked builds");
        r.verify().expect("verify");
        assert_eq!(
            r.to_attachment_integrity(),
            crate::verifier_attachment::MethodIntegrity::Compromised
        );
    }

    #[test]
    fn integrity_mapping_is_sound_for_kernel_clean() {
        let r = LeanVerification::build(ok_draft(), &key()).expect("build");
        assert_eq!(
            r.to_attachment_integrity(),
            crate::verifier_attachment::MethodIntegrity::Sound
        );
    }

    /// The A6 reject vector, end to end: a `native_decide` Lean record (the
    /// flagship Sidon cert's shape) becomes a `compiler_checked` /
    /// `Compromised` attachment that the gate excludes, so it can never carry
    /// a finding to `Verified` through the Lean leg — only the independent
    /// Sound method counts.
    #[test]
    fn native_decide_record_cannot_gate_verified_end_to_end() {
        use crate::verifier_attachment::{
            AdversarialProbe, AttachmentDraft, AttachmentOutcome, GateStatus, MatchToClaim,
            MethodIntegrity, ProbeKind, ProbeResult, VerifierAttachment, VerifierMethod,
            claim_digest, derive_gate_status,
        };

        // 1. The native_decide Lean record tiers as compiler_checked.
        let mut d = ok_draft();
        d.status = "compiler_checked".to_string();
        d.axiom_verdict = Some(AxiomVerdict::ForbiddenAxiom);
        d.axioms = vec![
            "Lean.ofReduceBool".to_string(),
            "Lean.trustCompiler".to_string(),
        ];
        let lean_rec = LeanVerification::build(d, &key()).expect("build compiler_checked");
        assert_eq!(
            lean_rec.to_attachment_integrity(),
            MethodIntegrity::Compromised
        );

        let digest = claim_digest("a(8) >= 33 (OEIS A309370)");
        let probe = AdversarialProbe {
            kind: ProbeKind::CounterexampleSearch,
            result: ProbeResult::Survived,
            note: String::new(),
        };
        let mk = |method, solver: &str, indep: Vec<String>| {
            VerifierAttachment::build(AttachmentDraft {
                target: "vf_0123456789abcdef".to_string(),
                claim_digest: digest.clone(),
                verifier_method: method,
                solver_id: solver.to_string(),
                independent_of: indep,
                match_to_claim: MatchToClaim {
                    matches: true,
                    checker_actor: "ci".to_string(),
                },
                adversarial_probes: vec![probe.clone()],
                outcome: AttachmentOutcome::Passed,
                verifier_actor: "ci".to_string(),
                note: String::new(),
            })
            .unwrap()
        };

        // 2. The Lean attachment carries the compromised integrity; the Rust
        //    frozen verifier is the Sound method.
        let lean_att = mk(VerifierMethod::LeanKernel, "lean4@4.29.1", vec![])
            .with_method_integrity(lean_rec.to_attachment_integrity())
            .unwrap();
        let rust_att = mk(
            VerifierMethod::ComputationalSearch,
            "vela-verify",
            vec![lean_att.id.clone()],
        )
        .with_method_integrity(MethodIntegrity::Sound)
        .unwrap();

        // Only one SOUND matched attachment remains -> G1 unmet, G5 explains
        // the exclusion. Never Verified on a native_decide proof.
        let outcome = derive_gate_status(&digest, &[lean_att, rust_att]);
        assert_eq!(outcome.status, GateStatus::NeedsVerification);
        assert!(outcome.reasons.iter().any(|r| r.starts_with("G5")));
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
