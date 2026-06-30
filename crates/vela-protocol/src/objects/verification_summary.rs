//! `vsum_`: a Vela Verification Summary.
//!
//! A policy-stamped status over a claim subject. It borrows the in-toto VSA
//! SHAPE (verifier identity, policy identity, input attestations, status) but is
//! Vela-native and makes no SLSA-level claim: this is scientific claim
//! verification, not software-artifact integrity. The load-bearing addition over
//! a bare gate status is the policy id and digest, so "verified" names exactly
//! what it was verified under and stays replayable. See
//! `docs/TRUST_MODEL_REDESIGN.md` section 7.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERIFICATION_SUMMARY_SCHEMA: &str = "vela.verification_summary.v1";

/// A content-addressed verification summary over one claim subject.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationSummary {
    pub schema: String,
    /// `vsum_` + first 16 hex of the canonical digest.
    pub id: String,
    /// The claim digest this summary is about (the in-toto subject).
    pub subject_digest: String,
    /// The policy this status was derived under, and its content digest. A
    /// summary missing either is refused by [`VerificationSummary::validate`].
    pub policy_id: String,
    pub policy_digest: String,
    /// `verified` | `needs_verification` | `refuted`.
    pub status: String,
    /// The gate reasons (empty exactly when verified).
    pub reason_codes: Vec<String>,
    /// The `vva_` attachment ids the gate considered.
    pub input_attachments: Vec<String>,
}

impl VerificationSummary {
    fn derive_id(&self) -> String {
        let mut c = self.clone();
        c.id = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&c).unwrap_or_default();
        format!("vsum_{}", &hex::encode(Sha256::digest(bytes))[..16])
    }

    /// A summary that cannot name its policy is refused: "verified" without a
    /// content-addressed policy digest is not replayable in meaning.
    pub fn validate(&self) -> Result<(), String> {
        if self.policy_id.is_empty() || self.policy_digest.is_empty() {
            return Err(
                "verification summary must name its policy (policy_id + policy_digest); a status without a policy digest is not replayable"
                    .to_string(),
            );
        }
        Ok(())
    }
}

/// Derive a Vela Verification Summary for a claim: run the gate (G1-G5), then
/// stamp the canonical policy id and digest. The summary carries the exact
/// policy it was derived under, so the meaning of "verified" is replayable.
#[must_use]
pub fn derive_verification_summary(
    claim_digest: &str,
    attachments: &[crate::verifier_attachment::VerifierAttachment],
) -> VerificationSummary {
    use crate::verifier_attachment::GateStatus;
    let outcome = crate::verifier_attachment::derive_gate_status(claim_digest, attachments);
    let policy = crate::verification_policy::canonical_gate_policy();
    let status = match outcome.status {
        GateStatus::Verified => "verified",
        GateStatus::NeedsVerification => "needs_verification",
        GateStatus::Refuted => "refuted",
    };
    let mut summary = VerificationSummary {
        schema: VERIFICATION_SUMMARY_SCHEMA.to_string(),
        id: String::new(),
        subject_digest: claim_digest.to_string(),
        policy_id: policy.id,
        policy_digest: policy.canonical_digest,
        status: status.to_string(),
        reason_codes: outcome.reasons,
        input_attachments: attachments.iter().map(|a| a.id.clone()).collect(),
    };
    summary.id = summary.derive_id();
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_names_its_policy_and_is_content_addressed() {
        let summary = derive_verification_summary("abc123", &[]);
        // Empty attachments => needs_verification, but the summary still names
        // the policy it was derived under, so the status is replayable.
        assert_eq!(summary.status, "needs_verification");
        assert!(summary.policy_id.starts_with("vpol_"));
        assert_eq!(summary.policy_digest.len(), 64);
        assert!(summary.id.starts_with("vsum_"));
        assert!(summary.validate().is_ok());
    }

    #[test]
    fn summary_without_policy_is_refused() {
        let mut summary = derive_verification_summary("abc123", &[]);
        summary.policy_digest = String::new();
        assert!(summary.validate().is_err());
    }
}
