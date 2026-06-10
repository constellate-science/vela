//! Significance as an honest slot: a signed, attributed, non-repudiable
//! endorsement (`ven_`) — stored, never aggregated.
//!
//! ## The honest position
//!
//! Correctness has a third-party recomputation check; significance does not. It
//! is a prediction about future community use, and every signal of it
//! (endorsement, citation, attention) is an opinion, which is the gameable
//! object. So the substrate must never *compute* significance and never confer
//! it. The most it can offer is **accountability**: a named identity signs
//! "this matters, for this reason," the signature is permanent and publicly
//! costly to the signer's reputation, and the substrate stores it **without
//! aggregating it into a score.**
//!
//! Its only anti-gaming property is that you cannot endorse anonymously,
//! cheaply, or deniably. Stated plainly: this resists sybil and throwaway
//! gaming; it does NOT resist coordinated endorsement rings, reputation
//! laundering, or sponsored consensus. Sybil-resistant identity, who-may-stake,
//! and ring detection are **named open requirements the substrate deliberately
//! does not solve** (see `docs/SIGNIFICANCE_SLOT.md`).
//!
//! There is deliberately **no `significance_score` anywhere in the protocol,
//! and no reducer path that folds endorsements into a scalar.** An endorsement
//! is a first-class record you read individually, with its author and reason
//! attached. The discipline of shipping a *slot* rather than a *score* is the
//! honesty commitment.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ENDORSEMENT_SCHEMA: &str = "vela.endorsement.v0.1";

/// A signed, content-addressed significance endorsement. Stored as an
/// individual record; never summed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endorsement {
    pub schema: String,
    /// `ven_<16hex>`, content-addressed over the body with `endorsement_id`,
    /// `signature`, `signer_pubkey_hex` zeroed.
    pub endorsement_id: String,
    /// The record this endorses (`vf_`/`vfr_`/`vat_`/`vtr_`).
    pub target_record: String,
    /// The named actor making the claim (`reviewer:` / `agent:` …). The stake:
    /// you cannot endorse anonymously — the identity is bound and non-repudiable.
    pub endorser: String,
    /// Optional kind of significance asserted (e.g. "novel", "useful",
    /// "foundational"). Free, never enumerated into a score.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dimension: String,
    /// Why it matters — the accountable reason, required. An endorsement with
    /// no stated reason is rejected; the reason is what the signer stakes.
    pub rationale: String,
    /// ISO-8601 time of the endorsement.
    pub at: String,
    pub signature: String,
    pub signer_pubkey_hex: String,
}

/// Everything needed to build an [`Endorsement`] except the derived id/signature.
pub struct EndorsementDraft {
    pub target_record: String,
    pub endorser: String,
    pub dimension: String,
    pub rationale: String,
    pub at: String,
}

impl Endorsement {
    /// Build + sign, mirroring `Attempt::build`.
    pub fn build(draft: EndorsementDraft, key: &SigningKey) -> Result<Self, String> {
        if draft.target_record.trim().is_empty() {
            return Err("endorsement.target_record cannot be empty".to_string());
        }
        if draft.endorser.trim().is_empty() {
            return Err(
                "endorsement.endorser cannot be empty (significance must be attributed)"
                    .to_string(),
            );
        }
        if draft.rationale.trim().is_empty() {
            return Err(
                "endorsement.rationale cannot be empty (the reason is what the signer stakes)"
                    .to_string(),
            );
        }
        let mut e = Endorsement {
            schema: ENDORSEMENT_SCHEMA.to_string(),
            endorsement_id: String::new(),
            target_record: draft.target_record,
            endorser: draft.endorser,
            dimension: draft.dimension,
            rationale: draft.rationale,
            at: draft.at,
            signature: String::new(),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
        };
        let preimage = e.id_preimage_bytes()?;
        e.signature = hex::encode(crate::sign::sign_bytes(key, &preimage));
        e.endorsement_id = e.derive_id()?;
        Ok(e)
    }

    fn id_preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut preimage = self.clone();
        preimage.endorsement_id = String::new();
        preimage.signature = String::new();
        preimage.signer_pubkey_hex = String::new();
        crate::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize endorsement preimage: {e}"))
    }

    /// `ven_<16hex>` over the canonical content preimage.
    pub fn derive_id(&self) -> Result<String, String> {
        let bytes = self.id_preimage_bytes()?;
        Ok(format!(
            "ven_{}",
            &hex::encode(Sha256::digest(&bytes))[..16]
        ))
    }

    /// Verify: re-derive id + Ed25519 signature.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != ENDORSEMENT_SCHEMA {
            return Err(format!(
                "endorsement.schema must be `{ENDORSEMENT_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.endorsement_id.starts_with("ven_") {
            return Err(format!(
                "endorsement id must start with `ven_`, got `{}`",
                self.endorsement_id
            ));
        }
        let preimage = self.id_preimage_bytes()?;
        if !crate::sign::verify_action_signature(
            &preimage,
            &self.signature,
            &self.signer_pubkey_hex,
        )? {
            return Err(
                "endorsement signature does not verify under the declared pubkey".to_string(),
            );
        }
        let rederived = self.derive_id()?;
        if rederived != self.endorsement_id {
            return Err(format!(
                "endorsement_id mismatch: declared {}, rebuilt {}",
                self.endorsement_id, rederived
            ));
        }
        Ok(())
    }

    /// Build the canonical `endorsement.deposited` event.
    #[must_use]
    pub fn deposit_event(
        &self,
        actor_id: &str,
        actor_type: &str,
        reason: &str,
    ) -> crate::events::StateEvent {
        let payload =
            serde_json::json!({ "endorsement": serde_json::to_value(self).unwrap_or_default() });
        crate::events::new_endorsement_deposited_event(
            &self.endorsement_id,
            actor_id,
            actor_type,
            reason,
            payload,
            vec![
                "A signed significance endorsement. It is stored as one record and NEVER \
                 aggregated into a score; significance is social, off-substrate, uncomputed."
                    .to_string(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn draft(target: &str, who: &str) -> EndorsementDraft {
        EndorsementDraft {
            target_record: target.into(),
            endorser: who.into(),
            dimension: "foundational".into(),
            rationale: "first cross-domain transfer; unlocks the DNA-code frontier".into(),
            at: "2026-06-09T00:00:00Z".into(),
        }
    }

    #[test]
    fn build_verify_roundtrip() {
        let e = Endorsement::build(draft("vtr_aaaaaaaaaaaaaaaa", "reviewer:alon"), &key()).unwrap();
        assert!(e.endorsement_id.starts_with("ven_"));
        e.verify().unwrap();
    }

    #[test]
    fn empty_rationale_rejected() {
        let mut d = draft("vtr_x", "reviewer:x");
        d.rationale = "  ".into();
        assert!(Endorsement::build(d, &key()).is_err());
    }

    #[test]
    fn anonymous_endorsement_rejected() {
        let mut d = draft("vtr_x", "");
        d.endorser = "".into();
        assert!(Endorsement::build(d, &key()).is_err());
    }

    #[test]
    fn tamper_breaks_verify() {
        let mut e = Endorsement::build(draft("vtr_x", "reviewer:x"), &key()).unwrap();
        e.rationale = "actually it doesn't matter".into();
        assert!(e.verify().is_err());
    }
}
