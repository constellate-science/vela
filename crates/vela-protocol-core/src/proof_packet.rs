//! v0.338: ProofPacket — hash-stable, signature-verifiable receipts for
//! external verification.
//!
//! Doctrine: a ProofPacket is what an institution ships to prove a
//! decision was made on the substrate it claims. Any third party can
//! recompute the canonical hash from the packet body and verify the
//! signature under the declared public key. Two implementations
//! producing a packet for the same decision must produce byte-identical
//! canonical bytes (and therefore the same hash).
//!
//! Distinct from sibling packet primitives in this crate:
//!
//! - `packet.rs` — Canonical state replay packet. A *directory* of
//!   canonical artifacts (manifest.json, packet.lock.json, etc) that
//!   a peer uses to replay frontier state. Heavy; used for federation
//!   bundles.
//! - `review_packet.rs` — Task handoff packet. A human-readable bundle
//!   for one reviewer to hand work to another. Local-frontier scope.
//! - `proof_packet.rs` (this file) — Single-JSON external-verification
//!   receipt. Hash-stable, signed, public-shareable.
//!
//! Atlas-side: this primitive was the `pp_*` "Proof Packet" extension
//! in earlier cycles, with schema `atlas.proof-packet.v0.1`. Promoted
//! to first-class vela-protocol in v0.338 under schema
//! `vela.proof_packet.v0.1`. The Atlas-side migration (Phase R.5)
//! reads both schema strings; new packets ship with the canonical name.
//!
//! Hash discipline: canonical JSON (sorted object keys, no whitespace,
//! UTF-8). Mirrors Atlas's TS `canonicalize()`. Two implementations
//! produce byte-identical canonical strings.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROOF_PACKET_SCHEMA: &str = "vela.proof_packet.v0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofPacketKind {
    Hire,
    ModelPromotion,
    ConjectureTransition,
    /// Open enum: federation peers may issue domain-specific kinds.
    /// Stored as the discriminant value in serde; consumers that
    /// don't know the kind treat the packet opaquely.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketStatus {
    Current,
    Superseded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceChainEntry {
    pub finding_id: String,
    pub frontier_id: String,
    pub pillar: String,
    pub assertion_text: String,
    pub signed: bool,
    pub retracted: bool,
    pub contested: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StandardCandleRef {
    pub kind: String,
    #[serde(rename = "ref")]
    pub candle_ref: String,
    pub outcome: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewHistoryEntry {
    pub event_id: String,
    pub kind: String,
    pub actor: String,
    pub timestamp: String,
    pub signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReproducibilityNote {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetractionStatus {
    pub any_retracted: bool,
    pub retracted_count: u32,
    pub contested_count: u32,
}

/// External co-signature recorded after the packet was built. A peer
/// institution verifies the hash and signs to attest. Co-signatures
/// do not affect the canonical hash — they're metadata recorded
/// alongside.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalVerification {
    /// Actor id of the verifying party (e.g. "peer:aria",
    /// "reviewer:external-foundation").
    pub actor_id: String,
    /// ISO 8601 timestamp.
    pub verified_at: String,
    /// Hex-encoded co-signature over the packet hash.
    pub signature: String,
    /// Hex-encoded public key.
    pub signer_pubkey_hex: String,
    /// Free-form attestation text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Hash-stable, signature-verifiable receipt for one institutional
/// decision.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofPacket {
    pub schema: String,
    /// Stable id: `pp_<kind>_<context_id>` typically. Issuer-defined;
    /// recorded verbatim. Hash is derived independently.
    pub packet_id: String,
    pub kind: ProofPacketKind,
    /// Context the packet is about (person_id, model_version,
    /// conjecture_id).
    pub context_id: String,
    pub context_label: String,
    pub claim: String,
    pub evidence_chain: Vec<EvidenceChainEntry>,
    pub standard_candles: Vec<StandardCandleRef>,
    pub review_history: Vec<ReviewHistoryEntry>,
    pub reproducibility_note: ReproducibilityNote,
    pub retraction_status: RetractionStatus,
    pub signer_actor_id: String,
    /// ISO 8601 timestamp the issuer signed at.
    pub signed_at: String,
    /// `sha256:<64 hex>` over canonical JSON of every field except
    /// `packet_hash`, `packet_signature`, `built_at`, and
    /// `external_verifications`.
    pub packet_hash: String,
    /// Hex-encoded ed25519 signature over `packet_hash` bytes.
    pub packet_signature: String,
    /// Hex-encoded public key.
    pub signer_pubkey_hex: String,
    pub status: PacketStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    pub built_at: String,
    /// Co-signatures from third parties verifying the hash + signature.
    /// Not part of the canonical hash.
    #[serde(default)]
    pub external_verifications: Vec<ExternalVerification>,
}

/// Draft inputs to build a packet. `packet_id` is issuer-defined and
/// recorded verbatim; the hash is derived from the canonical body.
#[derive(Debug, Clone)]
pub struct ProofPacketDraft {
    pub packet_id: String,
    pub kind: ProofPacketKind,
    pub context_id: String,
    pub context_label: String,
    pub claim: String,
    pub evidence_chain: Vec<EvidenceChainEntry>,
    pub standard_candles: Vec<StandardCandleRef>,
    pub review_history: Vec<ReviewHistoryEntry>,
    pub reproducibility_note: ReproducibilityNote,
    pub retraction_status: RetractionStatus,
    pub signer_actor_id: String,
    pub signed_at: String,
    pub built_at: String,
}

impl ProofPacket {
    /// Build + sign a ProofPacket. The hash covers every field except
    /// `packet_hash`, `packet_signature`, `built_at`, and
    /// `external_verifications`. The signature signs over the hash
    /// bytes (not the canonical body) so external verifiers can
    /// recompute hash and verify signature independently.
    pub fn build(draft: ProofPacketDraft, key: &SigningKey) -> Result<Self, String> {
        validate_draft(&draft)?;
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        let mut packet = Self {
            schema: PROOF_PACKET_SCHEMA.to_string(),
            packet_id: draft.packet_id,
            kind: draft.kind,
            context_id: draft.context_id,
            context_label: draft.context_label,
            claim: draft.claim,
            evidence_chain: draft.evidence_chain,
            standard_candles: draft.standard_candles,
            review_history: draft.review_history,
            reproducibility_note: draft.reproducibility_note,
            retraction_status: draft.retraction_status,
            signer_actor_id: draft.signer_actor_id,
            signed_at: draft.signed_at,
            packet_hash: String::new(),
            packet_signature: String::new(),
            signer_pubkey_hex: pubkey_hex,
            status: PacketStatus::Current,
            superseded_by: None,
            built_at: draft.built_at,
            external_verifications: Vec::new(),
        };
        packet.packet_hash = packet.compute_hash()?;
        let hash_bytes_hex = packet
            .packet_hash
            .strip_prefix("sha256:")
            .ok_or("packet_hash must start with sha256:")?;
        let hash_bytes = hex::decode(hash_bytes_hex).map_err(|e| format!("decode hash: {e}"))?;
        let sig = key.sign(&hash_bytes);
        packet.packet_signature = hex::encode(sig.to_bytes());
        Ok(packet)
    }

    /// Compute the canonical hash over every field except those
    /// listed in the doctrine above. Two implementations producing
    /// the same packet body must produce the same hash.
    pub fn compute_hash(&self) -> Result<String, String> {
        let value = serde_json::to_value(self).map_err(|e| format!("serialize packet: {e}"))?;
        let mut obj = value
            .as_object()
            .ok_or("packet must serialize to an object")?
            .clone();
        obj.remove("packet_hash");
        obj.remove("packet_signature");
        obj.remove("built_at");
        obj.remove("external_verifications");
        let canonical = canonicalize_value(&serde_json::Value::Object(obj));
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    /// Recompute hash, verify it matches, verify signature.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != PROOF_PACKET_SCHEMA {
            return Err(format!(
                "schema mismatch: expected {PROOF_PACKET_SCHEMA}, got {}",
                self.schema
            ));
        }
        let recomputed = self.compute_hash()?;
        if recomputed != self.packet_hash {
            return Err(format!(
                "hash mismatch: declared {}, recomputed {}",
                self.packet_hash, recomputed
            ));
        }
        let hash_bytes_hex = self
            .packet_hash
            .strip_prefix("sha256:")
            .ok_or("packet_hash must start with sha256:")?;
        let hash_bytes = hex::decode(hash_bytes_hex).map_err(|e| format!("decode hash: {e}"))?;
        let pubkey_bytes =
            hex::decode(&self.signer_pubkey_hex).map_err(|e| format!("decode pubkey: {e}"))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| "pubkey must be 32 bytes".to_string())?;
        let verifying =
            VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| format!("verifying key: {e}"))?;
        let sig_bytes =
            hex::decode(&self.packet_signature).map_err(|e| format!("decode signature: {e}"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying
            .verify(&hash_bytes, &sig)
            .map_err(|e| format!("signature verify: {e}"))?;
        Ok(())
    }

    /// Append a third-party external verification. The verifier signs
    /// over the packet's `packet_hash` bytes (not the canonical body)
    /// so the attestation is portable.
    pub fn add_external_verification(
        &mut self,
        verifier_actor_id: &str,
        key: &SigningKey,
        verified_at: &str,
        note: Option<&str>,
    ) -> Result<(), String> {
        let hash_bytes_hex = self
            .packet_hash
            .strip_prefix("sha256:")
            .ok_or("packet_hash must start with sha256:")?;
        let hash_bytes = hex::decode(hash_bytes_hex).map_err(|e| format!("decode hash: {e}"))?;
        let sig = key.sign(&hash_bytes);
        self.external_verifications.push(ExternalVerification {
            actor_id: verifier_actor_id.to_string(),
            verified_at: verified_at.to_string(),
            signature: hex::encode(sig.to_bytes()),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
            note: note.map(String::from),
        });
        Ok(())
    }

    /// Verify every external verification.
    pub fn verify_external_verifications(&self) -> Result<usize, String> {
        let hash_bytes_hex = self
            .packet_hash
            .strip_prefix("sha256:")
            .ok_or("packet_hash must start with sha256:")?;
        let hash_bytes = hex::decode(hash_bytes_hex).map_err(|e| format!("decode hash: {e}"))?;
        let mut n = 0;
        for v in &self.external_verifications {
            let pubkey_bytes = hex::decode(&v.signer_pubkey_hex)
                .map_err(|e| format!("decode pubkey for {}: {e}", v.actor_id))?;
            let pubkey_arr: [u8; 32] = pubkey_bytes
                .try_into()
                .map_err(|_| "pubkey must be 32 bytes".to_string())?;
            let verifying =
                VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| format!("verifying key: {e}"))?;
            let sig_bytes = hex::decode(&v.signature)
                .map_err(|e| format!("decode signature for {}: {e}", v.actor_id))?;
            let sig_arr: [u8; 64] = sig_bytes
                .try_into()
                .map_err(|_| "signature must be 64 bytes".to_string())?;
            let sig = Signature::from_bytes(&sig_arr);
            verifying
                .verify(&hash_bytes, &sig)
                .map_err(|e| format!("verify for {}: {e}", v.actor_id))?;
            n += 1;
        }
        Ok(n)
    }
}

/// Canonical JSON serialization: sorted object keys, no whitespace,
/// no trailing zeros on numbers. Matches Atlas's TS `canonicalize()`.
fn canonicalize_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => {
            serde_json::to_string(s).unwrap_or_else(|_| String::from("\"\""))
        }
        serde_json::Value::Array(arr) => {
            let parts: Vec<String> = arr.iter().map(canonicalize_value).collect();
            format!("[{}]", parts.join(","))
        }
        serde_json::Value::Object(obj) => {
            let mut keys: Vec<&String> = obj.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|k| {
                    let kstr = serde_json::to_string(k).unwrap_or_else(|_| String::from("\"\""));
                    let vstr = canonicalize_value(&obj[*k]);
                    format!("{kstr}:{vstr}")
                })
                .collect();
            format!("{{{}}}", parts.join(","))
        }
    }
}

fn validate_draft(d: &ProofPacketDraft) -> Result<(), String> {
    if d.packet_id.is_empty() {
        return Err("packet_id must not be empty".to_string());
    }
    if d.context_id.is_empty() {
        return Err("context_id must not be empty".to_string());
    }
    if d.claim.is_empty() {
        return Err("claim must not be empty".to_string());
    }
    if d.signer_actor_id.is_empty() {
        return Err("signer_actor_id must not be empty".to_string());
    }
    if d.signed_at.is_empty() {
        return Err("signed_at must not be empty".to_string());
    }
    if d.built_at.is_empty() {
        return Err("built_at must not be empty".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn ok_draft() -> ProofPacketDraft {
        ProofPacketDraft {
            packet_id: "pp_hire_alice-allen_hired12".to_string(),
            kind: ProofPacketKind::Hire,
            context_id: "prs_alice-allen_hired12".to_string(),
            context_label: "Alice Allen".to_string(),
            claim: "Episteme hired Alice Allen 2026-04-15".to_string(),
            evidence_chain: vec![EvidenceChainEntry {
                finding_id: "vf_abc1234567890def".to_string(),
                frontier_id: "vfr_energy_v0".to_string(),
                pillar: "energy".to_string(),
                assertion_text: "Alice Allen leads Roland lab on …".to_string(),
                signed: true,
                retracted: false,
                contested: false,
                reviewed_at: Some("2026-04-10T00:00:00Z".to_string()),
            }],
            standard_candles: vec![StandardCandleRef {
                kind: "person".into(),
                candle_ref: "prs_alice-allen".to_string(),
                outcome: "hired".to_string(),
                notes: String::new(),
            }],
            review_history: vec![],
            reproducibility_note: ReproducibilityNote {
                data_url: None,
                code_url: None,
                model_version: None,
                dataset_hash: None,
                notes: Some("v0.338 test fixture".to_string()),
            },
            retraction_status: RetractionStatus {
                any_retracted: false,
                retracted_count: 0,
                contested_count: 0,
            },
            signer_actor_id: "operator:will-blair".to_string(),
            signed_at: "2026-05-25T00:00:00Z".to_string(),
            built_at: "2026-05-25T00:00:01Z".to_string(),
        }
    }

    #[test]
    fn build_signs_and_hashes() {
        let p = ProofPacket::build(ok_draft(), &key()).unwrap();
        assert_eq!(p.schema, PROOF_PACKET_SCHEMA);
        assert!(p.packet_hash.starts_with("sha256:"));
        assert_eq!(p.packet_hash.len(), "sha256:".len() + 64);
        assert!(!p.packet_signature.is_empty());
        assert_eq!(p.status, PacketStatus::Current);
        p.verify().unwrap();
    }

    #[test]
    fn verify_detects_tampered_claim() {
        let mut p = ProofPacket::build(ok_draft(), &key()).unwrap();
        p.claim = "Episteme hired someone else".to_string();
        assert!(p.verify().is_err());
    }

    #[test]
    fn external_verification_signs_and_verifies() {
        let mut p = ProofPacket::build(ok_draft(), &key()).unwrap();
        let peer_key = SigningKey::from_bytes(&[42u8; 32]);
        p.add_external_verification(
            "peer:aria",
            &peer_key,
            "2026-05-26T00:00:00Z",
            Some("ARIA verifies the hash"),
        )
        .unwrap();
        assert_eq!(p.external_verifications.len(), 1);
        assert_eq!(p.verify_external_verifications().unwrap(), 1);
        // Packet still verifies — external_verifications excluded from hash.
        p.verify().unwrap();
    }

    #[test]
    fn external_verifications_do_not_affect_hash() {
        let mut p1 = ProofPacket::build(ok_draft(), &key()).unwrap();
        let hash_before = p1.packet_hash.clone();
        let peer_key = SigningKey::from_bytes(&[42u8; 32]);
        p1.add_external_verification("peer:x", &peer_key, "2026-05-26T00:00:00Z", None)
            .unwrap();
        let hash_after = p1.compute_hash().unwrap();
        assert_eq!(hash_before, hash_after);
    }

    #[test]
    fn canonicalize_sorts_keys() {
        let v = serde_json::json!({ "b": 1, "a": 2, "c": [3, 2, 1] });
        let c = canonicalize_value(&v);
        assert_eq!(c, "{\"a\":2,\"b\":1,\"c\":[3,2,1]}");
    }

    #[test]
    fn canonicalize_nested() {
        let v = serde_json::json!({
            "z": { "y": 1, "x": 2 },
            "a": [{ "q": 1, "p": 2 }]
        });
        let c = canonicalize_value(&v);
        assert_eq!(c, "{\"a\":[{\"p\":2,\"q\":1}],\"z\":{\"x\":2,\"y\":1}}");
    }

    #[test]
    fn json_roundtrip() {
        let p = ProofPacket::build(ok_draft(), &key()).unwrap();
        let s = serde_json::to_string(&p).unwrap();
        let back: ProofPacket = serde_json::from_str(&s).unwrap();
        assert_eq!(p, back);
        back.verify().unwrap();
    }

    #[test]
    fn deterministic_under_fixed_key() {
        let p1 = ProofPacket::build(ok_draft(), &key()).unwrap();
        let p2 = ProofPacket::build(ok_draft(), &key()).unwrap();
        assert_eq!(p1.packet_hash, p2.packet_hash);
        assert_eq!(p1.packet_signature, p2.packet_signature);
    }

    #[test]
    fn validate_rejects_empty_claim() {
        let mut d = ok_draft();
        d.claim = String::new();
        let err = ProofPacket::build(d, &key()).unwrap_err();
        assert!(err.contains("claim"));
    }
}
