//! v0.217: Verdict Conflict Resolution (`vdc_*`).
//!
//! Resolves contradicting verdicts on overlapping Diff Pack members.
//! When reviewer A issues verdict=accept on pack P and reviewer B
//! issues verdict=reject on pack P', and P and P' share a member
//! proposal, the substrate has — until v0.217 — no story for which
//! verdict wins. The promoter would apply last-write-wins, which
//! silently drops one reviewer's intent.
//!
//! v0.217 makes the conflict a first-class signed record. Three
//! resolution modes:
//!
//!   majority       — count verdicts; the most common outcome wins.
//!   owner_override — the frontier owner's verdict supersedes peers.
//!   escalation     — handed up to a higher-authority reviewer; the
//!                    record opens a new review cycle rather than
//!                    picking a side.
//!
//! Substrate-honest framing: the resolution does not silence the
//! losing verdicts. The conflicting `vpv_*` ids stay on the log;
//! the `vdc_*` record explicitly cites them and records why one
//! won. A consumer auditing the frontier can replay the conflict
//! to understand the disagreement, not just the outcome.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const VERDICT_CONFLICT_SCHEMA: &str = "vela.verdict_conflict.v0.1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionMode {
    Majority,
    OwnerOverride,
    Escalation,
}

impl ResolutionMode {
    pub fn canonical(&self) -> &'static str {
        match self {
            ResolutionMode::Majority => "majority",
            ResolutionMode::OwnerOverride => "owner_override",
            ResolutionMode::Escalation => "escalation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerdictConflict {
    pub schema: String,
    pub conflict_id: String,
    pub frontier_id: String,
    pub verdicts: Vec<String>,
    pub shared_member_ids: Vec<String>,
    pub resolution_mode: ResolutionMode,
    pub resolution_actor: String,
    pub resolved_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub winning_verdict_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pubkey_hex: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConflictDraft {
    pub frontier_id: String,
    pub verdicts: Vec<String>,
    pub shared_member_ids: Vec<String>,
    pub resolution_mode: ResolutionMode,
    pub resolution_actor: String,
    pub resolved_at: String,
    pub winning_verdict_id: Option<String>,
    pub rationale: Option<String>,
}

impl VerdictConflict {
    pub fn build(draft: ConflictDraft) -> Result<Self, String> {
        validate_draft(&draft)?;
        let mut c = Self {
            schema: VERDICT_CONFLICT_SCHEMA.to_string(),
            conflict_id: String::new(),
            frontier_id: draft.frontier_id,
            verdicts: draft.verdicts,
            shared_member_ids: draft.shared_member_ids,
            resolution_mode: draft.resolution_mode,
            resolution_actor: draft.resolution_actor,
            resolved_at: draft.resolved_at,
            winning_verdict_id: draft.winning_verdict_id,
            rationale: draft.rationale,
            signature: None,
            signer_pubkey_hex: None,
        };
        c.conflict_id = c.derive_id();
        Ok(c)
    }

    pub fn sign(&mut self, key: &SigningKey) {
        let preimage = self.preimage_bytes();
        self.signature = Some(hex::encode(crate::sign::sign_bytes(key, &preimage)));
        self.signer_pubkey_hex = Some(hex::encode(key.verifying_key().to_bytes()));
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.frontier_id.as_bytes());
        out.push(b'|');
        // Verdicts: order-sensitive (the order reviewers issued them
        // matters for the conflict narrative).
        for (i, v) in self.verdicts.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(v.as_bytes());
        }
        out.push(b'|');
        // Shared members: sort before hashing — the set membership
        // is what matters, not the order.
        let mut sorted: Vec<&String> = self.shared_member_ids.iter().collect();
        sorted.sort();
        for (i, m) in sorted.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(m.as_bytes());
        }
        out.push(b'|');
        out.extend_from_slice(self.resolution_mode.canonical().as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.resolution_actor.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.resolved_at.as_bytes());
        out.push(b'|');
        if let Some(w) = &self.winning_verdict_id {
            out.extend_from_slice(w.as_bytes());
        }
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        format!("vdc_{}", &hex::encode(hasher.finalize())[..16])
    }

    pub fn verify(&self) -> Result<(), String> {
        let rederived = self.derive_id();
        if rederived != self.conflict_id {
            return Err(format!(
                "conflict_id mismatch: declared {}, rebuilt {}",
                self.conflict_id, rederived
            ));
        }
        if let (Some(sig), Some(pub_hex)) = (&self.signature, &self.signer_pubkey_hex) {
            if !crate::sign::verify_action_signature(&self.preimage_bytes(), sig, pub_hex)? {
                return Err("verdict_conflict signature does not verify under signer_pubkey_hex".to_string());
            }
        } else if self.signature.is_some() || self.signer_pubkey_hex.is_some() {
            return Err("signature and signer_pubkey_hex must be set together".to_string());
        }
        Ok(())
    }
}

fn validate_draft(d: &ConflictDraft) -> Result<(), String> {
    if !d.frontier_id.starts_with("vfr_") {
        return Err(format!(
            "frontier_id must start with `vfr_`, got `{}`",
            d.frontier_id
        ));
    }
    if d.verdicts.len() < 2 {
        return Err(format!(
            "verdicts must contain at least 2 contradicting vpv_* ids, got {}",
            d.verdicts.len()
        ));
    }
    for v in &d.verdicts {
        if !v.starts_with("vpv_") {
            return Err(format!("verdict id must start with `vpv_`, got `{v}`"));
        }
    }
    if d.shared_member_ids.is_empty() {
        return Err("shared_member_ids must contain at least one vpr_* id".to_string());
    }
    for m in &d.shared_member_ids {
        if !m.starts_with("vpr_") {
            return Err(format!("member id must start with `vpr_`, got `{m}`"));
        }
    }
    if d.resolution_actor.is_empty() {
        return Err("resolution_actor cannot be empty".to_string());
    }
    if d.resolved_at.is_empty() {
        return Err("resolved_at cannot be empty".to_string());
    }
    if let Some(w) = &d.winning_verdict_id {
        if !w.starts_with("vpv_") {
            return Err(format!(
                "winning_verdict_id must start with `vpv_`, got `{w}`"
            ));
        }
        if !d.verdicts.contains(w) {
            return Err(format!(
                "winning_verdict_id `{w}` must be one of the listed verdicts"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn ok_draft() -> ConflictDraft {
        ConflictDraft {
            frontier_id: "vfr_a22c9022674a2304".to_string(),
            verdicts: vec![
                "vpv_aaaaaaaaaaaaaaaa".to_string(),
                "vpv_bbbbbbbbbbbbbbbb".to_string(),
            ],
            shared_member_ids: vec!["vpr_516c01698109aa42".to_string()],
            resolution_mode: ResolutionMode::OwnerOverride,
            resolution_actor: "reviewer:will-blair".to_string(),
            resolved_at: "2026-05-14T00:00:00Z".to_string(),
            winning_verdict_id: Some("vpv_aaaaaaaaaaaaaaaa".to_string()),
            rationale: Some("Owner override after reading both deliberation threads.".to_string()),
        }
    }

    #[test]
    fn builds_with_deterministic_id() {
        let c1 = VerdictConflict::build(ok_draft()).unwrap();
        let c2 = VerdictConflict::build(ok_draft()).unwrap();
        assert_eq!(c1.conflict_id, c2.conflict_id);
        assert!(c1.conflict_id.starts_with("vdc_"));
        assert_eq!(c1.conflict_id.len(), 4 + 16);
    }

    #[test]
    fn shared_member_set_order_does_not_affect_id() {
        let c1 = VerdictConflict::build(ok_draft()).unwrap();
        let mut d2 = ok_draft();
        d2.shared_member_ids = vec![
            "vpr_zzzzzzzzzzzzzzzz".to_string(),
            "vpr_516c01698109aa42".to_string(),
        ];
        let c2 = VerdictConflict::build(d2.clone()).unwrap();
        let mut d3 = d2;
        d3.shared_member_ids.reverse();
        let c3 = VerdictConflict::build(d3).unwrap();
        // c2 and c3 differ from c1 (different membership) but
        // c2 and c3 should match each other (sorted membership).
        assert_ne!(c1.conflict_id, c2.conflict_id);
        assert_eq!(c2.conflict_id, c3.conflict_id);
    }

    #[test]
    fn verdict_order_does_affect_id() {
        let c1 = VerdictConflict::build(ok_draft()).unwrap();
        let mut d2 = ok_draft();
        d2.verdicts.reverse();
        let c2 = VerdictConflict::build(d2).unwrap();
        assert_ne!(c1.conflict_id, c2.conflict_id);
    }

    #[test]
    fn at_least_two_verdicts_required() {
        let mut d = ok_draft();
        d.verdicts.pop();
        assert!(VerdictConflict::build(d).is_err());
    }

    #[test]
    fn winning_verdict_must_be_in_list() {
        let mut d = ok_draft();
        d.winning_verdict_id = Some("vpv_not_in_list".to_string());
        assert!(VerdictConflict::build(d).is_err());
    }

    #[test]
    fn sign_then_verify() {
        let key = SigningKey::generate(&mut OsRng);
        let mut c = VerdictConflict::build(ok_draft()).unwrap();
        c.sign(&key);
        c.verify().unwrap();
        c.resolution_actor = "reviewer:tampered".to_string();
        assert!(c.verify().is_err());
    }

    #[test]
    fn json_round_trip() {
        let key = SigningKey::generate(&mut OsRng);
        let mut c = VerdictConflict::build(ok_draft()).unwrap();
        c.sign(&key);
        let s = serde_json::to_string(&c).unwrap();
        let back: VerdictConflict = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
        back.verify().unwrap();
    }
}
