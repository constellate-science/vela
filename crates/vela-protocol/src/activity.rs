//! The activity plane: non-authoritative records of what agents, tools, and
//! producers DID, kept strictly separate from accepted scientific state.
//!
//! "Activity is not state." An agent run, a retrieval, a model candidate, a
//! simulation: these are inputs and proposals, never evidence, until an accepted
//! transition admits a specific load-bearing atom. This module gives that
//! boundary a TYPE and an executable LAW.
//!
//!   - [`ActivityEnvelope`] (`vac_`) is a content-addressed record of one action
//!     against a named root, carrying its inputs/outputs, tool digests, a trace
//!     root, risk tags, and a CLAIMED relation. The claim is a proposal, not a
//!     finding.
//!   - [`RetrievalReceipt`] (`vrr_`) is a deterministic retrieval record: the
//!     dataset root, the query semantics, the tool digest, the result root, any
//!     completeness warnings, and a replay command.
//!   - [`assert_not_in_lineage`] is the law: no activity id may appear among the
//!     accepted-lineage atoms. The activity plane can be enormous without scaling
//!     false authority, because authority lives only in accepted transitions.
//!
//! These are intentionally NOT signed-or-rejected like accepted state: an
//! envelope may be unsigned (activity is cheap and high-volume). The id is a pure
//! content address; an optional signature binds an accountable actor. Mirrors the
//! content-addressing of [`crate::attempt::Attempt`].

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ACTIVITY_ENVELOPE_SCHEMA: &str = "vela.activity-envelope.v1";
pub const RETRIEVAL_RECEIPT_SCHEMA: &str = "vela.retrieval-receipt.v1";

/// The id prefixes the activity plane owns. Anything with one of these prefixes
/// is non-authoritative by construction.
pub const ACTIVITY_PREFIXES: [&str; 2] = ["vac_", "vrr_"];

/// True if `id` names an activity-plane artifact (and therefore can never be
/// accepted support).
pub fn is_activity_id(id: &str) -> bool {
    ACTIVITY_PREFIXES.iter().any(|p| id.starts_with(p))
}

/// A non-authoritative record of one action against a named root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEnvelope {
    pub schema: String,
    /// `vac_<16hex>`, content-addressed over the body with id/signature/signer
    /// zeroed. Key-independent.
    pub activity_id: String,
    pub actor_id: String,
    pub actor_type: String,
    /// `agent.run` | `retrieval` | `model.candidate` | `simulation` |
    /// `review.note` | other. Free-form, domain adapters refine it.
    pub kind: String,
    /// The frontier / presentation root this ran against.
    pub base_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_roots: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_digests: Vec<String>,
    /// Content hash of the full trace artifact (the raw transcript lives in
    /// object storage; only its address is bound here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_root: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub risk_tags: Vec<String>,
    /// What this activity CLAIMS (e.g. "improves A309370(13)"). A proposal, never
    /// accepted from here.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claimed_relation: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signer_pubkey_hex: String,
}

/// Fields a caller supplies; schema, id, and signature are derived.
#[derive(Debug, Clone, Default)]
pub struct ActivityDraft {
    pub actor_id: String,
    pub actor_type: String,
    pub kind: String,
    pub base_root: String,
    pub input_roots: Vec<String>,
    pub output_roots: Vec<String>,
    pub tool_digests: Vec<String>,
    pub trace_root: Option<String>,
    pub risk_tags: Vec<String>,
    pub claimed_relation: String,
    pub created_at: String,
}

impl ActivityEnvelope {
    /// Content-address an envelope from a draft (unsigned). Activity is cheap and
    /// high-volume; a signature is optional and added by [`Self::sign`].
    pub fn new(draft: ActivityDraft) -> Result<Self, String> {
        if draft.base_root.trim().is_empty() {
            return Err("activity.base_root cannot be empty (root it ran against)".to_string());
        }
        if draft.kind.trim().is_empty() {
            return Err("activity.kind cannot be empty".to_string());
        }
        let mut env = ActivityEnvelope {
            schema: ACTIVITY_ENVELOPE_SCHEMA.to_string(),
            activity_id: String::new(),
            actor_id: draft.actor_id,
            actor_type: draft.actor_type,
            kind: draft.kind,
            base_root: draft.base_root,
            input_roots: draft.input_roots,
            output_roots: draft.output_roots,
            tool_digests: draft.tool_digests,
            trace_root: draft.trace_root,
            risk_tags: draft.risk_tags,
            claimed_relation: draft.claimed_relation,
            created_at: draft.created_at,
            signature: String::new(),
            signer_pubkey_hex: String::new(),
        };
        env.activity_id = env.derive_id()?;
        Ok(env)
    }

    fn id_preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut p = self.clone();
        p.activity_id = String::new();
        p.signature = String::new();
        p.signer_pubkey_hex = String::new();
        crate::canonical::to_canonical_bytes(&p)
            .map_err(|e| format!("canonicalize activity preimage: {e}"))
    }

    /// `vac_<16hex>` over the canonical content preimage.
    pub fn derive_id(&self) -> Result<String, String> {
        let bytes = self.id_preimage_bytes()?;
        Ok(format!(
            "vac_{}",
            &hex::encode(Sha256::digest(&bytes))[..16]
        ))
    }

    /// Optionally bind an accountable signer over the same content preimage.
    pub fn sign(&mut self, key: &ed25519_dalek::SigningKey) -> Result<(), String> {
        let preimage = self.id_preimage_bytes()?;
        self.signature = hex::encode(crate::sign::sign_bytes(key, &preimage));
        self.signer_pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        Ok(())
    }

    /// `false`, always. Activity never carries authority; only an accepted
    /// transition does. Present so the type makes the boundary explicit.
    pub fn is_authoritative(&self) -> bool {
        false
    }

    /// Re-derive the id and, if a signature is present, verify it over the
    /// content preimage. Any hand-edit fails here.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != ACTIVITY_ENVELOPE_SCHEMA {
            return Err(format!(
                "activity.schema must be `{ACTIVITY_ENVELOPE_SCHEMA}`"
            ));
        }
        if self.activity_id != self.derive_id()? {
            return Err("activity_id is not the content address of the body".to_string());
        }
        if !self.signature.is_empty() {
            let preimage = self.id_preimage_bytes()?;
            if !crate::sign::verify_action_signature(
                &preimage,
                &self.signature,
                &self.signer_pubkey_hex,
            )? {
                return Err(
                    "activity signature does not verify under the declared pubkey".to_string(),
                );
            }
        }
        Ok(())
    }
}

/// A deterministic retrieval record: what was fetched, under what query, with
/// what completeness, and how to replay it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalReceipt {
    pub schema: String,
    /// `vrr_<16hex>`, content-addressed.
    pub receipt_id: String,
    pub dataset_root: String,
    /// The exact query / filter semantics (not a prose summary).
    pub query: String,
    pub tool_digest: String,
    pub result_root: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completeness_warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub replay_command: String,
    pub created_at: String,
}

impl RetrievalReceipt {
    pub fn new(
        dataset_root: &str,
        query: &str,
        tool_digest: &str,
        result_root: &str,
        completeness_warnings: Vec<String>,
        replay_command: &str,
        created_at: &str,
    ) -> Result<Self, String> {
        if dataset_root.trim().is_empty() || result_root.trim().is_empty() {
            return Err("retrieval receipt needs dataset_root and result_root".to_string());
        }
        let mut r = RetrievalReceipt {
            schema: RETRIEVAL_RECEIPT_SCHEMA.to_string(),
            receipt_id: String::new(),
            dataset_root: dataset_root.to_string(),
            query: query.to_string(),
            tool_digest: tool_digest.to_string(),
            result_root: result_root.to_string(),
            completeness_warnings,
            replay_command: replay_command.to_string(),
            created_at: created_at.to_string(),
        };
        r.receipt_id = r.derive_id()?;
        Ok(r)
    }

    pub fn derive_id(&self) -> Result<String, String> {
        let mut p = self.clone();
        p.receipt_id = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&p)
            .map_err(|e| format!("canonicalize retrieval receipt: {e}"))?;
        Ok(format!(
            "vrr_{}",
            &hex::encode(Sha256::digest(&bytes))[..16]
        ))
    }

    pub fn is_authoritative(&self) -> bool {
        false
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.schema != RETRIEVAL_RECEIPT_SCHEMA {
            return Err(format!(
                "retrieval.schema must be `{RETRIEVAL_RECEIPT_SCHEMA}`"
            ));
        }
        if self.receipt_id != self.derive_id()? {
            return Err("receipt_id is not the content address of the body".to_string());
        }
        Ok(())
    }
}

/// The activity/state boundary, made executable: NO activity-plane id may appear
/// among the accepted-lineage atoms. If one has leaked into accepted state, that
/// is a soundness break (activity was admitted as authority without a
/// transition). Returns the offending ids.
pub fn assert_not_in_lineage(accepted_atoms: &BTreeSet<String>) -> Result<(), String> {
    let leaked: Vec<&String> = accepted_atoms
        .iter()
        .filter(|a| is_activity_id(a))
        .collect();
    if leaked.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "activity-plane ids leaked into accepted lineage (activity is not state): {leaked:?}"
        ))
    }
}

/// Activity-plane ids found in LINEAGE-BEARING positions of accepted records:
/// the dependency-link targets of live findings, and the target / independence
/// refs of verifier-gate attachments. These are the only positions a `vac_`/
/// `vrr_` id could occupy to become load-bearing, since activity envelopes live
/// in a separate store and never enter the event log. Returns `(holder_id,
/// leaked_atom)` pairs; empty means the activity/state boundary holds on this
/// record. This is [`assert_not_in_lineage`] applied to a live frontier: the
/// accept path rejects these at write, and `vela check` fails on any that exist.
pub fn activity_ids_in_lineage(
    findings: &[crate::bundle::FindingBundle],
    attachments: &[crate::verifier_attachment::VerifierAttachment],
) -> Vec<(String, String)> {
    let mut leaks = Vec::new();
    for f in findings
        .iter()
        .filter(|f| !f.flags.superseded && !f.flags.retracted)
    {
        for l in f.links.iter().filter(|l| is_activity_id(&l.target)) {
            leaks.push((f.id.clone(), l.target.clone()));
        }
    }
    for a in attachments {
        if is_activity_id(&a.target) {
            leaks.push((a.id.clone(), a.target.clone()));
        }
        for indep in a.independent_of.iter().filter(|i| is_activity_id(i)) {
            leaks.push((a.id.clone(), indep.clone()));
        }
    }
    leaks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> ActivityDraft {
        ActivityDraft {
            actor_id: "agent:canopus".into(),
            actor_type: "agent".into(),
            kind: "model.candidate".into(),
            base_root: "vpr_root_r".into(),
            claimed_relation: "improves A309370(13)".into(),
            created_at: "2026-06-18T00:00:00Z".into(),
            ..Default::default()
        }
    }

    #[test]
    fn envelope_is_content_addressed_and_nonauthoritative() {
        let e = ActivityEnvelope::new(draft()).unwrap();
        assert!(e.activity_id.starts_with("vac_"));
        assert!(!e.is_authoritative());
        e.verify().unwrap();
    }

    #[test]
    fn tamper_breaks_the_id() {
        let mut e = ActivityEnvelope::new(draft()).unwrap();
        e.claimed_relation = "improves A309370(99)".into(); // edit body, id stale
        assert!(e.verify().is_err());
    }

    #[test]
    fn optional_signature_round_trips() {
        let mut e = ActivityEnvelope::new(draft()).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        e.sign(&key).unwrap();
        e.verify().unwrap();
        assert!(!e.signature.is_empty());
    }

    #[test]
    fn retrieval_receipt_round_trips() {
        let r = RetrievalReceipt::new(
            "sha256:dataset",
            "A309370 where n<=24",
            "sha256:tool",
            "sha256:result",
            vec!["paginated; 2 pages not fetched".into()],
            "vela retrieve ...",
            "2026-06-18T00:00:00Z",
        )
        .unwrap();
        assert!(r.receipt_id.starts_with("vrr_"));
        assert!(!r.is_authoritative());
        r.verify().unwrap();
    }

    #[test]
    fn the_law_catches_a_leaked_activity_id() {
        let mut atoms = BTreeSet::new();
        atoms.insert("verifier:vela-verify.sidon".to_string());
        assert!(assert_not_in_lineage(&atoms).is_ok());
        atoms.insert("vac_deadbeefdeadbeef".to_string()); // activity leaked into lineage
        assert!(assert_not_in_lineage(&atoms).is_err());
    }

    #[test]
    fn lineage_scan_flags_activity_link_targets() {
        let mut f = crate::test_support::make_finding("vf_a", 1.0, "computational");
        // a normal finding carries no activity-plane lineage
        assert!(activity_ids_in_lineage(std::slice::from_ref(&f), &[]).is_empty());
        // depending on an activity envelope is a boundary break
        f.links.push(crate::bundle::Link {
            target: "vac_deadbeefdeadbeef".to_string(),
            link_type: "depends_on".to_string(),
            note: String::new(),
            inferred_by: "agent:test".to_string(),
            created_at: "2026-06-18T00:00:00Z".to_string(),
            mechanism: None,
        });
        let leaks = activity_ids_in_lineage(std::slice::from_ref(&f), &[]);
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].1, "vac_deadbeefdeadbeef");
    }
}
