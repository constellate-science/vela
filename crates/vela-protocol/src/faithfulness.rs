//! Faithfulness attestation (`vfa_`): the signed object binding a
//! human-authored informal claim to the formal statement that purports to
//! capture it.
//!
//! ## The gap this closes (measured, and owned by no one)
//!
//! A proof-assistant kernel certifies a proof of the *formal* statement. It
//! says nothing about whether that statement *means* the informal claim a
//! human cares about. That gap is not hypothetical: `miniF2F-Lean Revisited`
//! (arXiv 2511.03108) measured a reported 97% autoformalization accuracy
//! collapsing to 62.7-66% under human review and **34.8% end-to-end** once the
//! final proof is checked against the *original informal statement*. "LLMs
//! marked many formalizations as correct even though they differed from the
//! intended statements." No prover lab ships a first-class, signed attestation
//! that an informal claim and a formal statement correspond. This module is
//! that object.
//!
//! ## Relationship to the gate
//!
//! [`crate::verifier_attachment::ProbeKind::FormalismFidelity`] is the
//! *adversarial probe* run inside the gate (prove S and ¬S; both provable =>
//! misformalized). A [`FaithfulnessAttestation`] is the *standalone, portable,
//! citable* artifact: a named attester signing that formal statement S
//! faithfully encodes informal claim C, by some [`FidelityMethod`]. It is to
//! the probe what a `vlv_` record is to a `lake build` run. An `Unfaithful`
//! verdict mints a *candidate* [`crate::contradiction::Contradiction`] via
//! [`crate::contradiction::Contradiction::from_misformalization`], never
//! auto-adjudicated.
//!
//! Doctrine: this attests *faithfulness*, not *correctness*. A faithful
//! formalization of a false claim is still faithful; a kernel proof of an
//! unfaithful statement still proves nothing about the claim. The two signals
//! are orthogonal and both required before a Lean proof can carry an informal
//! claim to `Verified`.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const FAITHFULNESS_SCHEMA: &str = "vela.faithfulness_attestation.v0.1";

/// How the attester judged that the formal statement captures the claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FidelityMethod {
    /// A named human read the informal claim and the formal statement and
    /// judged the correspondence.
    HumanReview,
    /// A prover was thrown at the formal statement S *and* its negation ¬S;
    /// both provable means the statement is vacuous/misformalized.
    NegationProbe,
    /// The formal statement was translated back to informal text and compared
    /// to the original claim.
    RoundTripBacktranslation,
    /// Independent agreement of multiple reviewers.
    MultiReviewer,
}

impl FidelityMethod {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HumanReview => "human_review",
            Self::NegationProbe => "negation_probe",
            Self::RoundTripBacktranslation => "round_trip_backtranslation",
            Self::MultiReviewer => "multi_reviewer",
        }
    }
}

/// The attester's verdict on the informal-to-formal correspondence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FidelityVerdict {
    /// The formal statement faithfully captures the informal claim.
    Faithful,
    /// The formal statement does NOT capture the claim (vacuous, trivial,
    /// strictly weaker/stronger, or a different statement).
    Unfaithful,
    /// The attester could not determine faithfulness.
    Uncertain,
}

impl FidelityVerdict {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Faithful => "faithful",
            Self::Unfaithful => "unfaithful",
            Self::Uncertain => "uncertain",
        }
    }
}

/// The one canonical claim digest, defined in `verifier_attachment` and
/// re-exported so a claim has one digest everywhere.
pub use crate::verifier_attachment::claim_digest;

/// A signed attestation that a formal statement faithfully encodes an informal
/// claim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaithfulnessAttestation {
    pub schema: String,
    /// `vfa_<16hex>`, content-addressed over the signed body.
    pub attestation_id: String,
    /// Digest of the human-authored informal claim (`sha256(trim)[:16]`).
    pub informal_claim_digest: String,
    /// A reference to the formal statement: a `vla_` anchor id, a `vlv_`/`vpv_`
    /// id, or any stable locator for the formalization.
    pub formal_statement_ref: String,
    /// sha256 (64 hex) of the exact formal statement text, pinning the
    /// attestation to the precise formalization it judged.
    pub formal_statement_sha256: String,
    pub method: FidelityMethod,
    pub verdict: FidelityVerdict,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// The named attester (`reviewer:` or `agent:`).
    pub attester_actor: String,
    pub attested_at: String,
    pub signature: String,
    pub signer_pubkey_hex: String,
}

/// Fields a caller supplies; schema, id, and signature are derived.
#[derive(Debug, Clone)]
pub struct FaithfulnessDraft {
    /// The informal claim text (its digest is computed).
    pub informal_claim: String,
    pub formal_statement_ref: String,
    /// The exact formal statement text (its sha256 is computed).
    pub formal_statement: String,
    pub method: FidelityMethod,
    pub verdict: FidelityVerdict,
    pub note: String,
    pub attester_actor: String,
    pub attested_at: String,
}

impl FaithfulnessAttestation {
    /// Build and sign a faithfulness attestation.
    pub fn build(draft: FaithfulnessDraft, key: &SigningKey) -> Result<Self, String> {
        if draft.informal_claim.trim().is_empty() {
            return Err("informal_claim cannot be empty".to_string());
        }
        if draft.formal_statement.trim().is_empty() {
            return Err("formal_statement cannot be empty".to_string());
        }
        if draft.attester_actor.trim().is_empty() {
            return Err("attester_actor cannot be empty".to_string());
        }
        let mut att = FaithfulnessAttestation {
            schema: FAITHFULNESS_SCHEMA.to_string(),
            attestation_id: String::new(),
            informal_claim_digest: claim_digest(&draft.informal_claim),
            formal_statement_ref: draft.formal_statement_ref,
            formal_statement_sha256: hex::encode(Sha256::digest(draft.formal_statement.as_bytes())),
            method: draft.method,
            verdict: draft.verdict,
            note: draft.note,
            attester_actor: draft.attester_actor,
            attested_at: draft.attested_at,
            signature: String::new(),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
        };
        let preimage = att.preimage_bytes();
        att.signature = hex::encode(crate::sign::sign_bytes(key, &preimage));
        att.attestation_id = att.derive_id();
        Ok(att)
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for field in [
            self.informal_claim_digest.as_str(),
            self.formal_statement_ref.as_str(),
            self.formal_statement_sha256.as_str(),
            self.method.as_str(),
            self.verdict.as_str(),
            self.attester_actor.as_str(),
            self.attested_at.as_str(),
            self.signer_pubkey_hex.as_str(),
        ] {
            out.extend_from_slice(field.as_bytes());
            out.push(b'|');
        }
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        hasher.update(b"|");
        hasher.update(self.signature.as_bytes());
        format!("vfa_{}", &hex::encode(hasher.finalize())[..16])
    }

    /// Verify the signature under the declared pubkey and that the id derives
    /// from the signed body.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != FAITHFULNESS_SCHEMA {
            return Err(format!(
                "faithfulness.schema must be `{FAITHFULNESS_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.attestation_id.starts_with("vfa_") {
            return Err(format!(
                "attestation id must start with `vfa_`, got `{}`",
                self.attestation_id
            ));
        }
        if !crate::sign::verify_action_signature(
            &self.preimage_bytes(),
            &self.signature,
            &self.signer_pubkey_hex,
        )? {
            return Err("faithfulness signature does not verify under the declared pubkey".to_string());
        }
        let rederived = self.derive_id();
        if rederived != self.attestation_id {
            return Err(format!(
                "attestation_id mismatch: declared {}, rebuilt {}",
                self.attestation_id, rederived
            ));
        }
        Ok(())
    }

    /// Whether this attestation affirms faithfulness.
    #[must_use]
    pub fn is_faithful(&self) -> bool {
        self.verdict == FidelityVerdict::Faithful
    }

    /// On an `Unfaithful` verdict, mint a CANDIDATE misformalization
    /// contradiction between the finding and its formalization (never
    /// auto-adjudicated). Returns `None` for faithful/uncertain verdicts.
    #[must_use]
    pub fn to_misformalization(
        &self,
        frontier_id: &str,
        finding_id: &str,
    ) -> Option<crate::contradiction::Contradiction> {
        if self.verdict != FidelityVerdict::Unfaithful {
            return None;
        }
        let basis = format!(
            "faithfulness attestation {} ({}): formal statement {} does not capture the informal claim",
            self.attestation_id,
            self.method.as_str(),
            self.formal_statement_ref
        );
        Some(crate::contradiction::Contradiction::from_misformalization(
            frontier_id,
            finding_id,
            &self.attestation_id,
            &basis,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn ok_draft() -> FaithfulnessDraft {
        FaithfulnessDraft {
            informal_claim: "a(8) >= 33 for OEIS A309370".to_string(),
            formal_statement_ref: "vla_abc123def4567890".to_string(),
            formal_statement: "theorem a309370_a8_ge_33 : IsSidon witness8 /\\ witness8.length = 33"
                .to_string(),
            method: FidelityMethod::HumanReview,
            verdict: FidelityVerdict::Faithful,
            note: "witness encodes the binary Sidon set; statement matches the OEIS definition"
                .to_string(),
            attester_actor: "reviewer:will-blair".to_string(),
            attested_at: "2026-06-09T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn builds_signs_and_verifies() {
        let a = FaithfulnessAttestation::build(ok_draft(), &key()).unwrap();
        assert!(a.attestation_id.starts_with("vfa_"));
        assert_eq!(a.informal_claim_digest, claim_digest("a(8) >= 33 for OEIS A309370"));
        assert_eq!(a.formal_statement_sha256.len(), 64);
        assert!(a.is_faithful());
        a.verify().unwrap();
    }

    #[test]
    fn tampered_verdict_fails_verify() {
        let mut a = FaithfulnessAttestation::build(ok_draft(), &key()).unwrap();
        a.verdict = FidelityVerdict::Unfaithful;
        assert!(a.verify().is_err(), "verdict must be inside the signed preimage");
    }

    #[test]
    fn empty_fields_rejected() {
        let mut d = ok_draft();
        d.formal_statement = "  ".to_string();
        assert!(FaithfulnessAttestation::build(d, &key()).is_err());
    }

    #[test]
    fn unfaithful_mints_candidate_misformalization() {
        let mut d = ok_draft();
        d.verdict = FidelityVerdict::Unfaithful;
        d.method = FidelityMethod::NegationProbe;
        d.note = "statement and its negation both provable".to_string();
        let a = FaithfulnessAttestation::build(d, &key()).unwrap();
        let c = a.to_misformalization("vfr_x", "vf_finding").expect("unfaithful mints contradiction");
        use crate::contradiction::ContradictionStatus;
        assert_eq!(c.status, ContradictionStatus::Candidate);
        assert_eq!(c.claim_boundary()["authoritative"], false);
    }

    #[test]
    fn faithful_mints_nothing() {
        let a = FaithfulnessAttestation::build(ok_draft(), &key()).unwrap();
        assert!(a.to_misformalization("vfr_x", "vf_finding").is_none());
    }

    #[test]
    fn json_roundtrip() {
        let a = FaithfulnessAttestation::build(ok_draft(), &key()).unwrap();
        let s = serde_json::to_string(&a).unwrap();
        let back: FaithfulnessAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
        back.verify().unwrap();
    }
}
