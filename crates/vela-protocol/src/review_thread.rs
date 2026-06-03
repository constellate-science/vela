//! v0.168: review-comment-thread primitive. A `vrt_*` thread is
//! an ordered, append-only chain of signed `vrm_*` messages
//! attached to a substrate target (a proposal `vpr_*` or a
//! finding `vf_*`). Each message is content-addressed over its
//! body + signer + parent message + timestamp; threading is
//! enforced by `parent_message_id`.
//!
//! Substrate-honesty: review threads do not gate proposal
//! acceptance — they document the deliberation. The canonical
//! review verdict still flows through the v0.10+ proposal-
//! acceptance event-kind path. Threads are the substrate-
//! honest equivalent of comment sections: append-only,
//! signed, content-addressed.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const THREAD_SCHEMA: &str = "vela.review_thread.v0.1";
pub const MESSAGE_SCHEMA: &str = "vela.review_message.v0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadTargetKind {
    Proposal,
    Finding,
    /// v0.204: a thread can target a v0.193 Scientific Diff Pack
    /// (`vsd_*`). Comments are read-only chat about the pack;
    /// verdicts still flow through the workbench (v0.203-v0.205).
    DiffPack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewMessage {
    pub schema: String,
    pub message_id: String,
    pub thread_id: String,
    pub author_actor_id: String,
    pub author_pubkey_hex: String,
    pub body: String,
    /// Optional parent message id (for threaded replies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_message_id: Option<String>,
    pub posted_at: String,
    /// Ed25519 signature over the canonical preimage. May be
    /// empty if the substrate is operating in unsigned mode for
    /// local-only workbench use.
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewThread {
    pub schema: String,
    pub thread_id: String,
    pub target_kind: ThreadTargetKind,
    pub target_id: String,
    pub frontier_id: String,
    pub created_at: String,
    pub messages: Vec<ReviewMessage>,
}

impl ReviewThread {
    pub fn new(
        target_kind: ThreadTargetKind,
        target_id: String,
        frontier_id: String,
        created_at: String,
    ) -> Result<Self, String> {
        match target_kind {
            ThreadTargetKind::Proposal => {
                if !target_id.starts_with("vpr_") {
                    return Err(format!(
                        "proposal target must start with `vpr_`, got `{target_id}`"
                    ));
                }
            }
            ThreadTargetKind::Finding => {
                if !target_id.starts_with("vf_") {
                    return Err(format!(
                        "finding target must start with `vf_`, got `{target_id}`"
                    ));
                }
            }
            ThreadTargetKind::DiffPack => {
                if !target_id.starts_with("vsd_") {
                    return Err(format!(
                        "diff_pack target must start with `vsd_`, got `{target_id}`"
                    ));
                }
            }
        }
        if !frontier_id.starts_with("vfr_") {
            return Err(format!(
                "frontier_id must start with `vfr_`, got `{frontier_id}`"
            ));
        }
        let mut thread = ReviewThread {
            schema: THREAD_SCHEMA.to_string(),
            thread_id: String::new(),
            target_kind,
            target_id,
            frontier_id,
            created_at,
            messages: Vec::new(),
        };
        thread.thread_id = thread.derive_id();
        Ok(thread)
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.frontier_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.target_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.created_at.as_bytes());
        format!("vrt_{}", &hex::encode(hasher.finalize())[..16])
    }

    pub fn append_message(&mut self, msg: ReviewMessage) -> Result<(), String> {
        if msg.thread_id != self.thread_id {
            return Err(format!(
                "message thread_id {} does not match thread {}",
                msg.thread_id, self.thread_id
            ));
        }
        if let Some(ref parent) = msg.parent_message_id
            && !self.messages.iter().any(|m| m.message_id == *parent)
        {
            return Err(format!("parent_message_id {parent} not in thread"));
        }
        // Append-only: previous timestamp must be <= new timestamp
        // (treated lexicographically since we use RFC 3339).
        if let Some(last) = self.messages.last()
            && msg.posted_at < last.posted_at
        {
            return Err(format!(
                "out-of-order message: {} < {}",
                msg.posted_at, last.posted_at
            ));
        }
        self.messages.push(msg);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MessageDraft {
    pub thread_id: String,
    pub author_actor_id: String,
    pub body: String,
    pub parent_message_id: Option<String>,
    pub posted_at: String,
}

impl ReviewMessage {
    /// Build + sign a review message. The signature covers the
    /// canonical preimage of the message body with
    /// `signature` and `message_id` zeroed; `message_id` is then
    /// derived from the signed body.
    pub fn build(
        draft: MessageDraft,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, String> {
        if !draft.thread_id.starts_with("vrt_") {
            return Err(format!(
                "thread_id must start with `vrt_`, got `{}`",
                draft.thread_id
            ));
        }
        if draft.body.trim().is_empty() {
            return Err("body must be non-empty".to_string());
        }
        if let Some(ref p) = draft.parent_message_id
            && !p.starts_with("vrm_")
        {
            return Err(format!(
                "parent_message_id must start with `vrm_`, got `{p}`"
            ));
        }
        let mut msg = ReviewMessage {
            schema: MESSAGE_SCHEMA.to_string(),
            message_id: String::new(),
            thread_id: draft.thread_id,
            author_actor_id: draft.author_actor_id,
            author_pubkey_hex: hex::encode(signing_key.verifying_key().to_bytes()),
            body: draft.body,
            parent_message_id: draft.parent_message_id,
            posted_at: draft.posted_at,
            signature: String::new(),
        };
        let preimage = msg.preimage_bytes();
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(&preimage);
        msg.signature = hex::encode(sig.to_bytes());
        msg.message_id = msg.derive_id();
        Ok(msg)
    }

    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.thread_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.author_actor_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.author_pubkey_hex.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.body.as_bytes());
        out.push(b'|');
        if let Some(p) = &self.parent_message_id {
            out.extend_from_slice(p.as_bytes());
        }
        out.push(b'|');
        out.extend_from_slice(self.posted_at.as_bytes());
        out
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        hasher.update(b"|");
        hasher.update(self.signature.as_bytes());
        format!("vrm_{}", &hex::encode(hasher.finalize())[..16])
    }

    /// Verify the signature against `author_pubkey_hex`.
    pub fn verify(&self) -> Result<(), String> {
        use ed25519_dalek::Verifier;
        let pubkey_bytes =
            hex::decode(&self.author_pubkey_hex).map_err(|e| format!("decode pubkey hex: {e}"))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| "pubkey must be 32 bytes".to_string())?;
        let verifying = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr)
            .map_err(|e| format!("verifying key: {e}"))?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| format!("decode signature hex: {e}"))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "signature must be 64 bytes".to_string())?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        verifying
            .verify(&self.preimage_bytes(), &sig)
            .map_err(|e| format!("signature verify failed: {e}"))?;
        // Confirm id was derived from these signed bytes.
        let rederived = self.derive_id();
        if rederived != self.message_id {
            return Err(format!(
                "message_id mismatch: declared {}, rebuilt {}",
                self.message_id, rederived
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn thread() -> ReviewThread {
        ReviewThread::new(
            ThreadTargetKind::Proposal,
            "vpr_abc123".to_string(),
            "vfr_def456".to_string(),
            "2026-05-11T00:00:00Z".to_string(),
        )
        .expect("thread")
    }

    #[test]
    fn thread_id_is_content_addressed() {
        let a = thread();
        let b = ReviewThread::new(
            ThreadTargetKind::Proposal,
            "vpr_abc123".to_string(),
            "vfr_def456".to_string(),
            "2026-05-11T00:00:00Z".to_string(),
        )
        .expect("thread b");
        assert_eq!(a.thread_id, b.thread_id);
        assert!(a.thread_id.starts_with("vrt_"));
    }

    #[test]
    fn message_signs_and_verifies() {
        let k = key();
        let t = thread();
        let m = ReviewMessage::build(
            MessageDraft {
                thread_id: t.thread_id.clone(),
                author_actor_id: "vac_alice".to_string(),
                body: "First!".to_string(),
                parent_message_id: None,
                posted_at: "2026-05-11T01:00:00Z".to_string(),
            },
            &k,
        )
        .expect("build message");
        m.verify().expect("verify");
        assert!(m.message_id.starts_with("vrm_"));
    }

    #[test]
    fn tampered_message_fails_verify() {
        let k = key();
        let t = thread();
        let mut m = ReviewMessage::build(
            MessageDraft {
                thread_id: t.thread_id.clone(),
                author_actor_id: "vac_alice".to_string(),
                body: "Original".to_string(),
                parent_message_id: None,
                posted_at: "2026-05-11T01:00:00Z".to_string(),
            },
            &k,
        )
        .expect("build message");
        m.body = "Tampered".to_string();
        assert!(m.verify().is_err());
    }

    #[test]
    fn out_of_order_rejected() {
        let k = key();
        let mut t = thread();
        let m1 = ReviewMessage::build(
            MessageDraft {
                thread_id: t.thread_id.clone(),
                author_actor_id: "vac_alice".to_string(),
                body: "Late post".to_string(),
                parent_message_id: None,
                posted_at: "2026-05-11T03:00:00Z".to_string(),
            },
            &k,
        )
        .unwrap();
        t.append_message(m1).unwrap();
        let m2 = ReviewMessage::build(
            MessageDraft {
                thread_id: t.thread_id.clone(),
                author_actor_id: "vac_alice".to_string(),
                body: "Earlier".to_string(),
                parent_message_id: None,
                posted_at: "2026-05-11T02:00:00Z".to_string(),
            },
            &k,
        )
        .unwrap();
        assert!(t.append_message(m2).is_err());
    }

    #[test]
    fn unknown_parent_rejected() {
        let k = key();
        let mut t = thread();
        let m = ReviewMessage::build(
            MessageDraft {
                thread_id: t.thread_id.clone(),
                author_actor_id: "vac_alice".to_string(),
                body: "reply".to_string(),
                parent_message_id: Some("vrm_doesnotexist".to_string()),
                posted_at: "2026-05-11T01:00:00Z".to_string(),
            },
            &k,
        )
        .unwrap();
        assert!(t.append_message(m).is_err());
    }

    #[test]
    fn bad_target_prefix_rejected() {
        assert!(
            ReviewThread::new(
                ThreadTargetKind::Proposal,
                "wrong_prefix".to_string(),
                "vfr_x".to_string(),
                "2026-05-11T00:00:00Z".to_string(),
            )
            .is_err()
        );
    }
}
