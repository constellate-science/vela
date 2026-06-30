//! Statement-faithfulness attestation (`vsa_`): a key-holding human's
//! signed judgment that a FORMAL statement faithfully encodes an
//! INFORMAL problem.
//!
//! Why this is its own signed object (doctrine rule 3): kernel
//! verification proves the formal statement follows from the axioms; it
//! says nothing about whether that statement is the problem anyone
//! meant. That binding is irreducibly human judgment, and it needs its
//! own signature, its own timestamp, and its own audit trail — separate
//! from the proof verifier and separate from review. This is the
//! formalization ecosystem's hardest lesson (misformalized Erdős
//! statements in formal-conjectures; AlphaProof Nexus's manual expert
//! validation step).
//!
//! The trust ladder consequence: a finding whose evidence is a formal
//! proof should reach full "verified" only when BOTH the proof
//! reproduces AND the statement is attested faithful. An attestation of
//! `variant` is honest middle ground (the proof is real; the statement
//! is a variant of the named problem); `unfaithful` is a first-class
//! negative result that caps the finding.

use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const STATEMENT_ATTESTATION_SCHEMA: &str = "vela.statement_attestation.v0.1";

/// The attester's verdict on the informal ↔ formal binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaithfulnessVerdict {
    /// The formal statement faithfully encodes the informal problem.
    Faithful,
    /// The formal statement is a meaningful variant (weaker, stronger,
    /// or specialized) of the informal problem — real work, honestly
    /// scoped, but NOT the named problem itself.
    Variant,
    /// The formal statement does not encode the informal problem
    /// (trivial, vacuous, or wrong). A first-class negative result.
    Unfaithful,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StatementAttestation {
    pub schema: String,
    /// Content-addressed id: `vsa_` + sha256(canonical body, id = "")[:16].
    pub id: String,
    /// The finding (or problem record) this attestation is about.
    pub target: String,
    /// Where the informal problem lives (e.g.
    /// "erdosproblems.com #12" or "OEIS A309370").
    pub informal_ref: String,
    /// Where the formal statement lives (repo path / URL at a commit).
    pub formal_ref: String,
    /// sha256 (hex) of the formal statement artifact's exact bytes.
    pub formal_statement_hash: String,
    pub verdict: FaithfulnessVerdict,
    /// The attester's reasoning — what was compared, what diverges.
    pub note: String,
    /// MUST be a `reviewer:` actor: this is human judgment by design.
    pub attested_by: String,
    pub attested_at: String,
    /// Ed25519 over the canonical body with `signature` empty —
    /// MANDATORY: an unsigned attestation does not exist.
    pub signature: String,
    pub signer_pubkey_hex: String,
    /// Co-authorship attribution: the non-human actor (e.g. an AI) that drafted
    /// the formalization. The outer `attested_by` stays the accountable human
    /// reviewer and `build()`'s reviewer-only refusal is unaffected; this only
    /// records that an AI helped. Absent on pre-redesign attestations, so they
    /// serialize and content-address byte-identically (`skip_serializing_if`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<crate::provenance::Provenance>,
}

pub struct AttestationDraft {
    pub target: String,
    pub informal_ref: String,
    pub formal_ref: String,
    pub formal_statement_hash: String,
    pub verdict: FaithfulnessVerdict,
    pub note: String,
    pub attested_by: String,
    pub attested_at: String,
}

impl StatementAttestation {
    /// Build, content-address, and sign. Refuses non-`reviewer:` actors:
    /// statement faithfulness is the one judgment the protocol reserves
    /// for humans (an agent may PROPOSE a finding; it may not attest
    /// that a formalization means what a human meant).
    pub fn build(draft: AttestationDraft, key: &ed25519_dalek::SigningKey) -> Result<Self, String> {
        if !draft.attested_by.starts_with("reviewer:") {
            return Err(format!(
                "statement attestation requires a reviewer: actor (human judgment by design); got '{}'",
                draft.attested_by
            ));
        }
        if draft.target.trim().is_empty() {
            return Err("attestation target cannot be empty".to_string());
        }
        if draft.informal_ref.trim().is_empty() || draft.formal_ref.trim().is_empty() {
            return Err("informal_ref and formal_ref are both required".to_string());
        }
        if draft.formal_statement_hash.len() != 64
            || hex::decode(&draft.formal_statement_hash).is_err()
        {
            return Err("formal_statement_hash must be 32 bytes of hex (sha256)".to_string());
        }
        if draft.note.trim().is_empty() {
            return Err(
                "an attestation without reasoning is a rubber stamp; note is required".to_string(),
            );
        }
        let mut att = StatementAttestation {
            schema: STATEMENT_ATTESTATION_SCHEMA.to_string(),
            id: String::new(),
            target: draft.target,
            informal_ref: draft.informal_ref,
            formal_ref: draft.formal_ref,
            formal_statement_hash: draft.formal_statement_hash,
            verdict: draft.verdict,
            note: draft.note,
            attested_by: draft.attested_by,
            attested_at: draft.attested_at,
            signature: String::new(),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
            provenance: None,
        };
        att.id = att.derive_id()?;
        att.signature = hex::encode(key.sign(&att.signing_bytes()?).to_bytes());
        Ok(att)
    }

    /// Attach co-authorship attribution (the AI that drafted this formalization)
    /// and re-sign. Kept separate from `build()` so existing call sites are
    /// untouched and the outer reviewer-only refusal in `build()` is the only
    /// place a human-vs-non-human check on the SIGNER lives. The provenance ids
    /// must all be non-human (`Provenance::validate`), so a human can never be
    /// recorded here instead of as the accountable `attested_by` signer. Since
    /// `provenance` is part of the signed body, the id and signature are
    /// re-derived.
    pub fn with_provenance(
        mut self,
        provenance: crate::provenance::Provenance,
        key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, String> {
        if provenance.is_empty() {
            return Ok(self);
        }
        provenance.validate()?;
        self.provenance = Some(provenance);
        self.id = String::new();
        self.signature = String::new();
        self.id = self.derive_id()?;
        self.signature = hex::encode(key.sign(&self.signing_bytes()?).to_bytes());
        Ok(self)
    }

    /// Canonical bytes with `signature` cleared (the id is part of the
    /// signed content; the signature is not part of the id).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut c = self.clone();
        c.signature = String::new();
        let body = crate::canonical::to_canonical_bytes(&c)?;
        Ok(crate::signing_input::signing_input(
            crate::signing_input::SigVersion::V0,
            crate::signing_input::payload_type::STATEMENT_ATTESTATION,
            &body,
        ))
    }

    pub fn derive_id(&self) -> Result<String, String> {
        let mut c = self.clone();
        c.id = String::new();
        c.signature = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&c)?;
        Ok(format!("vsa_{}", &hex::encode(Sha256::digest(bytes))[..16]))
    }

    /// Full integrity check: id re-derives, namespace holds, signature
    /// verifies under the embedded pubkey.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != STATEMENT_ATTESTATION_SCHEMA {
            return Err(format!("unknown schema '{}'", self.schema));
        }
        if !self.attested_by.starts_with("reviewer:") {
            return Err("attested_by must be a reviewer: actor".to_string());
        }
        let expected = self.derive_id()?;
        if expected != self.id {
            return Err(format!(
                "id does not re-derive: stored {}, derived {expected}",
                self.id
            ));
        }
        let pk: [u8; 32] = hex::decode(&self.signer_pubkey_hex)
            .map_err(|e| format!("pubkey hex: {e}"))?
            .try_into()
            .map_err(|_| "pubkey must be 32 bytes".to_string())?;
        let vk =
            ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|e| format!("pubkey: {e}"))?;
        let sig: [u8; 64] = hex::decode(&self.signature)
            .map_err(|e| format!("signature hex: {e}"))?
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        vk.verify(
            &self.signing_bytes()?,
            &ed25519_dalek::Signature::from_bytes(&sig),
        )
        .map_err(|_| "signature does not verify".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[9u8; 32])
    }

    fn draft() -> AttestationDraft {
        AttestationDraft {
            target: "vf_0000000000000001".to_string(),
            informal_ref: "erdosproblems.com #12".to_string(),
            formal_ref: "alphaproof-nexus-results@0647711:APNOutputs/ErdosProblems/erdos_12.parts.i.lean".to_string(),
            formal_statement_hash: "a".repeat(64),
            verdict: FaithfulnessVerdict::Faithful,
            note: "Compared the Lean statement against Erdős' original phrasing; quantifiers and asymptotics match.".to_string(),
            attested_by: "reviewer:test".to_string(),
            attested_at: "2026-06-10T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn builds_signs_verifies() {
        let a = StatementAttestation::build(draft(), &key()).unwrap();
        assert!(a.id.starts_with("vsa_"));
        a.verify().unwrap();
    }

    #[test]
    fn refuses_agent_attester() {
        let mut d = draft();
        d.attested_by = "agent:claude".to_string();
        assert!(StatementAttestation::build(d, &key()).is_err());
    }

    #[test]
    fn refuses_empty_note() {
        let mut d = draft();
        d.note = " ".to_string();
        assert!(StatementAttestation::build(d, &key()).is_err());
    }

    #[test]
    fn tamper_breaks_verify() {
        let mut a = StatementAttestation::build(draft(), &key()).unwrap();
        a.verdict = FaithfulnessVerdict::Unfaithful;
        assert!(a.verify().is_err());
    }
}
