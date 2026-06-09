//! v0.200: Evaluation Record (`ver_*`).
//!
//! A unified record for replication, benchmark, validation, and
//! peer-review outcomes. Composes with the v0.71 Replication /
//! Prediction primitives — `ver_*` is the layer above that lets
//! statements like "this Diff Pack was replicated by Lab X" or
//! "this tool benched at score Y on benchmark Z" exist as first-
//! class signed objects on the substrate.
//!
//! Substrate-honest framing: a record pins what an evaluator
//! claims about a target object. The target must already exist on
//! the frontier (the loader validates this when an external import
//! path is wired). Outcome is one of {succeeded, failed, partial,
//! inconclusive}; the SDK doctrine maps "inconclusive" to "agent
//! couldn't decide; needs human review" — a substrate-honest
//! escape hatch.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const EVALUATION_RECORD_SCHEMA: &str = "vela.evaluation_record.v0.1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    Vsd,
    Vtr,
    Vf,
    Vpf,
    Vtd,
    Vaa,
}

impl TargetKind {
    pub fn canonical(&self) -> &'static str {
        match self {
            TargetKind::Vsd => "vsd",
            TargetKind::Vtr => "vtr",
            TargetKind::Vf => "vf",
            TargetKind::Vpf => "vpf",
            TargetKind::Vtd => "vtd",
            TargetKind::Vaa => "vaa",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationKind {
    Replication,
    Benchmark,
    Validation,
    PeerReview,
}

impl EvaluationKind {
    pub fn canonical(&self) -> &'static str {
        match self {
            EvaluationKind::Replication => "replication",
            EvaluationKind::Benchmark => "benchmark",
            EvaluationKind::Validation => "validation",
            EvaluationKind::PeerReview => "peer_review",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Failed,
    Partial,
    Inconclusive,
}

impl Outcome {
    pub fn canonical(&self) -> &'static str {
        match self {
            Outcome::Succeeded => "succeeded",
            Outcome::Failed => "failed",
            Outcome::Partial => "partial",
            Outcome::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvaluationRecord {
    pub schema: String,
    pub record_id: String,
    pub target_kind: TargetKind,
    pub target_id: String,
    pub evaluation_kind: EvaluationKind,
    pub outcome: Outcome,
    pub evaluator_actor: String,
    pub evaluated_at: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RecordDraft {
    pub target_kind: TargetKind,
    pub target_id: String,
    pub evaluation_kind: EvaluationKind,
    pub outcome: Outcome,
    pub evaluator_actor: String,
    pub evaluated_at: String,
    pub evidence_refs: Vec<String>,
    pub benchmark_id: Option<String>,
    pub score: Option<f64>,
    pub notes: Option<String>,
}

impl EvaluationRecord {
    /// Build an unsigned record from a draft. The record_id is
    /// content-addressed; signing is a separate step via `sign`.
    pub fn build(draft: RecordDraft) -> Result<Self, String> {
        validate_draft(&draft)?;
        let mut r = Self {
            schema: EVALUATION_RECORD_SCHEMA.to_string(),
            record_id: String::new(),
            target_kind: draft.target_kind,
            target_id: draft.target_id,
            evaluation_kind: draft.evaluation_kind,
            outcome: draft.outcome,
            evaluator_actor: draft.evaluator_actor,
            evaluated_at: draft.evaluated_at,
            evidence_refs: draft.evidence_refs,
            benchmark_id: draft.benchmark_id,
            score: draft.score,
            notes: draft.notes,
            signature: None,
            signer_pubkey_hex: None,
        };
        r.record_id = r.derive_id();
        Ok(r)
    }

    pub fn sign(&mut self, key: &SigningKey) {
        let preimage = self.preimage_bytes();
        let sig = key.sign(&preimage);
        self.signature = Some(hex::encode(sig.to_bytes()));
        self.signer_pubkey_hex = Some(hex::encode(key.verifying_key().to_bytes()));
    }

    /// Canonical bytes over which record_id is derived AND signatures
    /// are computed.
    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.target_kind.canonical().as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.target_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.evaluation_kind.canonical().as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.outcome.canonical().as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.evaluator_actor.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.evaluated_at.as_bytes());
        out.push(b'|');
        for (i, r) in self.evidence_refs.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(r.as_bytes());
        }
        out.push(b'|');
        if let Some(b) = &self.benchmark_id {
            out.extend_from_slice(b.as_bytes());
        }
        out.push(b'|');
        if let Some(s) = self.score {
            // Stable float formatting: avoid locale-dependent
            // serialization. Use {:?} (Rust Debug) which gives a
            // round-trippable representation.
            out.extend_from_slice(format!("{s:?}").as_bytes());
        }
        out.push(b'|');
        if let Some(n) = &self.notes {
            out.extend_from_slice(n.as_bytes());
        }
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        format!("ver_{}", &hex::encode(hasher.finalize())[..16])
    }

    pub fn verify(&self) -> Result<(), String> {
        let rederived = self.derive_id();
        if rederived != self.record_id {
            return Err(format!(
                "record_id mismatch: declared {}, rebuilt {}",
                self.record_id, rederived
            ));
        }
        if let (Some(sig_hex), Some(pub_hex)) = (&self.signature, &self.signer_pubkey_hex) {
            let pubkey_bytes = hex::decode(pub_hex).map_err(|e| format!("decode pubkey: {e}"))?;
            let pubkey_arr: [u8; 32] = pubkey_bytes
                .try_into()
                .map_err(|_| "pubkey must be 32 bytes".to_string())?;
            let verifying =
                VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| format!("verifying key: {e}"))?;
            let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("decode signature: {e}"))?;
            let sig_arr: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| "signature must be 64 bytes".to_string())?;
            let sig = Signature::from_bytes(&sig_arr);
            verifying
                .verify(&self.preimage_bytes(), &sig)
                .map_err(|e| format!("signature verify: {e}"))?;
        } else if self.signature.is_some() || self.signer_pubkey_hex.is_some() {
            return Err("signature and signer_pubkey_hex must be set together".to_string());
        }
        Ok(())
    }
}

fn validate_draft(d: &RecordDraft) -> Result<(), String> {
    let prefix = d.target_kind.canonical();
    let expected_prefix = format!("{prefix}_");
    if !d.target_id.starts_with(&expected_prefix) {
        return Err(format!(
            "target_id must start with `{expected_prefix}` for target_kind `{prefix}`, got `{}`",
            d.target_id
        ));
    }
    if d.evaluator_actor.is_empty() {
        return Err("evaluator_actor cannot be empty".to_string());
    }
    if d.evaluated_at.is_empty() {
        return Err("evaluated_at cannot be empty".to_string());
    }
    if let Some(s) = d.score
        && !s.is_finite()
    {
        return Err("score must be a finite number".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn ok_draft() -> RecordDraft {
        RecordDraft {
            target_kind: TargetKind::Vsd,
            target_id: "vsd_5076e7b3ff8e6b0f".to_string(),
            evaluation_kind: EvaluationKind::Replication,
            outcome: Outcome::Succeeded,
            evaluator_actor: "lab:replication_site_42".to_string(),
            evaluated_at: "2026-05-11T00:00:00Z".to_string(),
            evidence_refs: vec!["vrep_abc123".to_string()],
            benchmark_id: None,
            score: None,
            notes: Some(
                "Replicated 2/3 successes; 1 attempt failed on cohort variance.".to_string(),
            ),
        }
    }

    #[test]
    fn builds_with_deterministic_id() {
        let r1 = EvaluationRecord::build(ok_draft()).unwrap();
        let r2 = EvaluationRecord::build(ok_draft()).unwrap();
        assert_eq!(r1.record_id, r2.record_id);
        assert!(r1.record_id.starts_with("ver_"));
        assert_eq!(r1.record_id.len(), 4 + 16);
    }

    #[test]
    fn different_outcome_changes_id() {
        let r1 = EvaluationRecord::build(ok_draft()).unwrap();
        let mut d2 = ok_draft();
        d2.outcome = Outcome::Partial;
        let r2 = EvaluationRecord::build(d2).unwrap();
        assert_ne!(r1.record_id, r2.record_id);
    }

    #[test]
    fn target_kind_prefix_enforced() {
        let mut d = ok_draft();
        d.target_kind = TargetKind::Vtr;
        // target_id still says vsd_; reject.
        assert!(EvaluationRecord::build(d).is_err());
    }

    #[test]
    fn benchmark_record_with_score_round_trips() {
        let mut d = ok_draft();
        d.target_kind = TargetKind::Vtd;
        d.target_id = "vtd_d50b932e406862a6".to_string();
        d.evaluation_kind = EvaluationKind::Benchmark;
        d.benchmark_id = Some("astabench:protein-fold:v1".to_string());
        d.score = Some(0.84);
        let r = EvaluationRecord::build(d).unwrap();
        let s = serde_json::to_string(&r).unwrap();
        let back: EvaluationRecord = serde_json::from_str(&s).unwrap();
        assert_eq!(r, back);
        back.verify().unwrap();
    }

    #[test]
    fn sign_then_verify() {
        let mut r = EvaluationRecord::build(ok_draft()).unwrap();
        r.sign(&key());
        r.verify().unwrap();
    }

    #[test]
    fn tampered_body_after_sign_fails_verify() {
        let mut r = EvaluationRecord::build(ok_draft()).unwrap();
        r.sign(&key());
        r.outcome = Outcome::Failed;
        // record_id no longer matches re-derivation.
        assert!(r.verify().is_err());
    }

    #[test]
    fn unsigned_record_still_verifies_its_id() {
        let r = EvaluationRecord::build(ok_draft()).unwrap();
        r.verify().unwrap();
    }

    #[test]
    fn non_finite_score_rejected() {
        let mut d = ok_draft();
        d.score = Some(f64::NAN);
        assert!(EvaluationRecord::build(d.clone()).is_err());
        d.score = Some(f64::INFINITY);
        assert!(EvaluationRecord::build(d).is_err());
    }
}
