//! v0.195: Agent Attestation Envelope (`vaa_*`).
//!
//! A signed envelope around any LLM-produced artifact. Names the
//! model + version + tool calls + token counts + output hash +
//! parent prompt hash. Any v0.193 Scientific Diff Pack or v0.194
//! Trajectory step references its `vaa_*` so the chain of custody
//! from agent run → produced artifact is auditable.
//!
//! Substrate-honest framing: the envelope does not vouch for the
//! correctness of the agent's outputs — it just pins what model
//! ran with what inputs and produced what outputs. A reviewer
//! still has to read the diff pack and accept or reject; the
//! attestation just makes "this came from Claude Opus 4.7 with
//! this prompt" a first-class, signed statement.
//!
//! Mirrors the lean_verification.rs (v0.170) and scientific_diff.rs
//! (v0.193) signing patterns verbatim — same build/sign/verify
//! shape, same id-derivation pattern.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const AGENT_ATTESTATION_SCHEMA: &str = "vela.agent_attestation.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolCall {
    pub tool_name: String,
    pub input_hash: String,
    pub output_hash: String,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentAttestation {
    pub schema: String,
    pub attestation_id: String,
    pub agent_actor: String,
    pub model_name: String,
    pub model_version: String,
    pub started_at: String,
    pub finished_at: String,
    pub total_tokens: u64,
    pub tool_calls: Vec<ToolCall>,
    pub output_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_attestation: Option<String>,
    pub signature: String,
    pub signer_pubkey_hex: String,
}

#[derive(Debug, Clone)]
pub struct AttestationDraft {
    pub agent_actor: String,
    pub model_name: String,
    pub model_version: String,
    pub started_at: String,
    pub finished_at: String,
    pub total_tokens: u64,
    pub tool_calls: Vec<ToolCall>,
    pub output_hashes: Vec<String>,
    pub prompt_hash: Option<String>,
    pub parent_attestation: Option<String>,
}

impl AgentAttestation {
    /// Build + sign the envelope. The attestation_id is content-
    /// addressed over the signed body; signing is required (an
    /// unsigned attestation is meaningless for chain-of-custody).
    pub fn build(draft: AttestationDraft, key: &SigningKey) -> Result<Self, String> {
        validate_draft(&draft)?;
        let mut envelope = Self {
            schema: AGENT_ATTESTATION_SCHEMA.to_string(),
            attestation_id: String::new(),
            agent_actor: draft.agent_actor,
            model_name: draft.model_name,
            model_version: draft.model_version,
            started_at: draft.started_at,
            finished_at: draft.finished_at,
            total_tokens: draft.total_tokens,
            tool_calls: draft.tool_calls,
            output_hashes: draft.output_hashes,
            prompt_hash: draft.prompt_hash,
            parent_attestation: draft.parent_attestation,
            signature: String::new(),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
        };
        let preimage = envelope.preimage_bytes();
        let sig = key.sign(&preimage);
        envelope.signature = hex::encode(sig.to_bytes());
        envelope.attestation_id = envelope.derive_id();
        Ok(envelope)
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.agent_actor.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.model_name.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.model_version.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.started_at.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.finished_at.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.total_tokens.to_string().as_bytes());
        out.push(b'|');
        for (i, tc) in self.tool_calls.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(tc.tool_name.as_bytes());
            out.push(b':');
            out.extend_from_slice(tc.input_hash.as_bytes());
            out.push(b':');
            out.extend_from_slice(tc.output_hash.as_bytes());
        }
        out.push(b'|');
        for (i, h) in self.output_hashes.iter().enumerate() {
            if i > 0 {
                out.push(b',');
            }
            out.extend_from_slice(h.as_bytes());
        }
        out.push(b'|');
        if let Some(p) = &self.prompt_hash {
            out.extend_from_slice(p.as_bytes());
        }
        out.push(b'|');
        if let Some(p) = &self.parent_attestation {
            out.extend_from_slice(p.as_bytes());
        }
        out.push(b'|');
        out.extend_from_slice(self.signer_pubkey_hex.as_bytes());
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        hasher.update(b"|");
        hasher.update(self.signature.as_bytes());
        format!("vaa_{}", &hex::encode(hasher.finalize())[..16])
    }

    /// Verify: re-derive attestation_id from body+signature; verify
    /// signature under declared pubkey.
    pub fn verify(&self) -> Result<(), String> {
        let pubkey_bytes =
            hex::decode(&self.signer_pubkey_hex).map_err(|e| format!("decode pubkey: {e}"))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| "pubkey must be 32 bytes".to_string())?;
        let verifying =
            VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| format!("verifying key: {e}"))?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| format!("decode signature: {e}"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying
            .verify(&self.preimage_bytes(), &sig)
            .map_err(|e| format!("signature verify: {e}"))?;
        let rederived = self.derive_id();
        if rederived != self.attestation_id {
            return Err(format!(
                "attestation_id mismatch: declared {}, rebuilt {}",
                self.attestation_id, rederived
            ));
        }
        Ok(())
    }
}

fn validate_draft(d: &AttestationDraft) -> Result<(), String> {
    if !d.agent_actor.starts_with("agent:") {
        return Err(format!(
            "agent_actor must start with `agent:`, got `{}`",
            d.agent_actor
        ));
    }
    if d.model_name.is_empty() {
        return Err("model_name cannot be empty".to_string());
    }
    if d.model_version.is_empty() {
        return Err("model_version cannot be empty".to_string());
    }
    for h in &d.output_hashes {
        if h.len() != 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("output_hash must be 64 hex chars, got `{h}`"));
        }
    }
    for tc in &d.tool_calls {
        if tc.input_hash.len() != 64 || !tc.input_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "tool_call.input_hash must be 64 hex chars, got `{}`",
                tc.input_hash
            ));
        }
        if tc.output_hash.len() != 64 || !tc.output_hash.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "tool_call.output_hash must be 64 hex chars, got `{}`",
                tc.output_hash
            ));
        }
    }
    if let Some(p) = &d.prompt_hash
        && (p.len() != 64 || !p.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(format!("prompt_hash must be 64 hex chars, got `{p}`"));
    }
    if let Some(p) = &d.parent_attestation
        && !p.starts_with("vaa_")
    {
        return Err(format!(
            "parent_attestation must start with `vaa_`, got `{p}`"
        ));
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

    fn ok_draft() -> AttestationDraft {
        AttestationDraft {
            agent_actor: "agent:test_scout".to_string(),
            model_name: "claude-opus-4.7".to_string(),
            model_version: "claude-opus-4.7-20260411".to_string(),
            started_at: "2026-05-11T00:00:00Z".to_string(),
            finished_at: "2026-05-11T00:00:42Z".to_string(),
            total_tokens: 12_500,
            tool_calls: vec![ToolCall {
                tool_name: "search_arxiv".to_string(),
                input_hash: "a".repeat(64),
                output_hash: "b".repeat(64),
                duration_ms: 1_200,
            }],
            output_hashes: vec!["c".repeat(64)],
            prompt_hash: Some("d".repeat(64)),
            parent_attestation: None,
        }
    }

    #[test]
    fn builds_signs_and_verifies() {
        let a = AgentAttestation::build(ok_draft(), &key()).unwrap();
        assert!(a.attestation_id.starts_with("vaa_"));
        a.verify().unwrap();
    }

    #[test]
    fn agent_actor_must_be_namespaced() {
        let mut d = ok_draft();
        d.agent_actor = "reviewer:human".to_string();
        assert!(AgentAttestation::build(d, &key()).is_err());
    }

    #[test]
    fn bad_hash_length_rejected() {
        let mut d = ok_draft();
        d.output_hashes = vec!["short".to_string()];
        assert!(AgentAttestation::build(d, &key()).is_err());
    }

    #[test]
    fn tool_call_hash_validated() {
        let mut d = ok_draft();
        d.tool_calls[0].input_hash = "short".to_string();
        assert!(AgentAttestation::build(d, &key()).is_err());
    }

    #[test]
    fn parent_attestation_namespace_enforced() {
        let mut d = ok_draft();
        d.parent_attestation = Some("vsd_not_vaa".to_string());
        assert!(AgentAttestation::build(d, &key()).is_err());
    }

    #[test]
    fn tampered_body_after_build_fails_verify() {
        let mut a = AgentAttestation::build(ok_draft(), &key()).unwrap();
        a.model_name = "claude-haiku-2.5".to_string();
        assert!(a.verify().is_err());
    }

    #[test]
    fn cross_impl_python_sdk_pinned_id() {
        // v0.196: pinned constant produced by the Python vela_agent
        // SDK on the same inputs and the same fixed all-zeros signing
        // key. Cross-impl drift flags here.
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let envelope = AgentAttestation::build(
            AttestationDraft {
                agent_actor: "agent:cross_check".to_string(),
                model_name: "claude-opus-4.7".to_string(),
                model_version: "v1".to_string(),
                started_at: "2026-05-11T00:00:00Z".to_string(),
                finished_at: "2026-05-11T00:00:42Z".to_string(),
                total_tokens: 100,
                tool_calls: vec![ToolCall {
                    tool_name: "t".to_string(),
                    input_hash: "a".repeat(64),
                    output_hash: "b".repeat(64),
                    duration_ms: 10,
                }],
                output_hashes: vec!["c".repeat(64)],
                prompt_hash: Some("d".repeat(64)),
                parent_attestation: None,
            },
            &key,
        )
        .unwrap();
        assert_eq!(envelope.attestation_id, "vaa_db61cc709fc3e69b");
        assert_eq!(
            envelope.signer_pubkey_hex,
            "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
        );
    }

    #[test]
    fn json_roundtrip() {
        let a = AgentAttestation::build(ok_draft(), &key()).unwrap();
        let s = serde_json::to_string(&a).unwrap();
        let back: AgentAttestation = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
        back.verify().unwrap();
    }
}
