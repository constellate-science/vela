//! Anchor links (`val_`): a signed, retractable assertion that a claim
//! (`vf_`) carries a specific external-catalogue anchor (OEIS A309370,
//! Erdős #707, a mathlib declaration, an arXiv id, an MSC class).
//!
//! Why this is its own signed object, not a field on the finding
//! (Math Atlas spec D1, and frontier-calculus Law 22, "claim-identity
//! receipts"): attaching an anchor is *fallible*. The equality of two
//! identical anchor triples is mechanical, but the *attachment* of an
//! anchor to a claim is a human/agent judgment that can be wrong and may
//! be corrected. So it is an append-only, signed, retractable event, never
//! a mutation of the content-addressed finding bytes. This is the
//! un-deferral of the frontier-calculus's deferred claim-identity
//! mechanism.
//!
//! Identity consequence: two claims that carry the *same* `HardIdentity`
//! anchor join into one atlas cell. `SoftCandidate` clusters for search
//! only; `SearchOnly` (MSC, arXiv, DOI) is tags, never identity. The join
//! is also context-indexed at projection time: a shared anchor across
//! different contexts does NOT merge (the frontier-calculus context wall),
//! it is a licensed transfer edge. `anchors_equal` here is the anchor-level
//! half of the test; the projection adds the context check.

use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ANCHOR_LINK_SCHEMA: &str = "vela.anchor_link.v0.1";

/// What kind of external object the anchor names. Different namespaces
/// have different identity semantics: a mathlib declaration is close to
/// statement identity (at a revision); an OEIS entry is a sequence/object;
/// an Erdős number is a problem entry that often hosts several subclaims;
/// arXiv is a work; MSC is a taxonomy. `kind` plus `join_policy` decide
/// whether an anchor may induce identity at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorKind {
    Statement,
    FormalDeclaration,
    MathematicalObject,
    ProblemEntry,
    Work,
    Taxonomy,
    Sequence,
    Dataset,
}

/// Whether an anchor may induce an identity join.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinPolicy {
    /// May induce `anchors_equal` (two claims with this exact anchor are
    /// the same atlas cell, modulo the projection's context check).
    HardIdentity,
    /// Clusters for search/suggestion only; never induces identity.
    SoftCandidate,
    /// Tags only (MSC, arXiv, DOI, DBLP); never identity, never clustering.
    SearchOnly,
}

/// A descriptive pointer into an external catalogue. Not a claim about
/// math; a claim about where this claim lives in the wider literature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Anchor {
    /// Catalogue namespace: "oeis" | "erdos" | "mathlib" | "arxiv" | "msc" | "dblp".
    pub namespace: String,
    /// The id within that namespace: "A309370" | "707" | "Nat.Sidon.bound".
    pub id: String,
    /// Disambiguates sub-claims under one external id (controlled vocab),
    /// e.g. "lower-bound a(n)". Required: an Erdős number is not one claim.
    pub role: String,
    pub kind: AnchorKind,
    pub join_policy: JoinPolicy,
    /// For mutable catalogues: the OEIS revision, mathlib commit, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    /// Stronger disambiguator when a catalogue id is coarse: a fingerprint
    /// of the exact statement this anchor binds to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement_fingerprint: Option<String>,
}

/// A signed, content-addressed, retractable attachment of an anchor to a
/// claim. Carried as a `payload.anchor_link` on an `anchor.attached` event
/// and removed by an `anchor.retracted` event (loader = reducer).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnchorLink {
    pub schema: String,
    /// Content-addressed id: `val_` + sha256(canonical body, id+sig empty)[:16].
    pub id: String,
    /// The claim (`vf_`) this anchor is attached to.
    pub target: String,
    pub anchor: Anchor,
    pub attached_by: String,
    pub attached_at: String,
    /// Ed25519 over the canonical body with `signature` empty. An unsigned
    /// anchor link does not exist.
    pub signature: String,
    pub signer_pubkey_hex: String,
}

pub struct AnchorLinkDraft {
    pub target: String,
    pub anchor: Anchor,
    pub attached_by: String,
    pub attached_at: String,
}

impl AnchorLink {
    pub fn build(draft: AnchorLinkDraft, key: &ed25519_dalek::SigningKey) -> Result<Self, String> {
        if draft.target.trim().is_empty() {
            return Err("anchor link target cannot be empty".to_string());
        }
        if draft.anchor.namespace.trim().is_empty() || draft.anchor.id.trim().is_empty() {
            return Err("anchor namespace and id are both required".to_string());
        }
        if draft.anchor.role.trim().is_empty() {
            return Err(
                "anchor role is required (an external id is rarely one claim; name the role)"
                    .to_string(),
            );
        }
        let mut link = AnchorLink {
            schema: ANCHOR_LINK_SCHEMA.to_string(),
            id: String::new(),
            target: draft.target,
            anchor: draft.anchor,
            attached_by: draft.attached_by,
            attached_at: draft.attached_at,
            signature: String::new(),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
        };
        link.id = link.derive_id()?;
        link.signature = hex::encode(key.sign(&link.signing_bytes()?).to_bytes());
        Ok(link)
    }

    /// Canonical bytes with `signature` cleared (the id is part of the
    /// signed content; the signature is not part of the id).
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut c = self.clone();
        c.signature = String::new();
        crate::canonical::to_canonical_bytes(&c)
    }

    pub fn derive_id(&self) -> Result<String, String> {
        let mut c = self.clone();
        c.id = String::new();
        c.signature = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&c)?;
        Ok(format!("val_{}", &hex::encode(Sha256::digest(bytes))[..16]))
    }

    /// Full integrity check: id re-derives, schema holds, signature
    /// verifies under the embedded pubkey.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != ANCHOR_LINK_SCHEMA {
            return Err(format!("unknown schema '{}'", self.schema));
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

/// The anchor-level half of the identity test: two anchors join only when
/// they are byte-identical on the identity-bearing fields AND both opt into
/// `HardIdentity`. The projection adds the context check on top (the
/// frontier-calculus context wall): a shared anchor across distinct
/// contexts is a transfer edge, never a merge.
#[must_use]
pub fn anchors_equal(a: &Anchor, b: &Anchor) -> bool {
    a.join_policy == JoinPolicy::HardIdentity
        && b.join_policy == JoinPolicy::HardIdentity
        && a.namespace == b.namespace
        && a.id == b.id
        && a.role == b.role
        && a.namespace_version == b.namespace_version
        && a.statement_fingerprint == b.statement_fingerprint
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
    }

    fn anchor(role: &str, policy: JoinPolicy) -> Anchor {
        Anchor {
            namespace: "oeis".to_string(),
            id: "A309370".to_string(),
            role: role.to_string(),
            kind: AnchorKind::Sequence,
            join_policy: policy,
            namespace_version: None,
            source_revision: None,
            statement_fingerprint: None,
        }
    }

    fn draft() -> AnchorLinkDraft {
        AnchorLinkDraft {
            target: "vf_0000000000000001".to_string(),
            anchor: anchor("lower-bound a(n)", JoinPolicy::HardIdentity),
            attached_by: "reviewer:test".to_string(),
            attached_at: "2026-06-15T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn builds_signs_verifies() {
        let link = AnchorLink::build(draft(), &key()).unwrap();
        assert!(link.id.starts_with("val_"));
        link.verify().unwrap();
    }

    #[test]
    fn id_is_content_addressed_and_deterministic() {
        let a = AnchorLink::build(draft(), &key()).unwrap();
        let b = AnchorLink::build(draft(), &key()).unwrap();
        assert_eq!(
            a.id, b.id,
            "same draft + key must content-address identically"
        );
    }

    #[test]
    fn tamper_breaks_verify() {
        let mut link = AnchorLink::build(draft(), &key()).unwrap();
        link.target = "vf_ffffffffffffffff".to_string();
        assert!(
            link.verify().is_err(),
            "tampered target must fail id re-derivation"
        );
    }

    #[test]
    fn empty_role_is_rejected() {
        let mut d = draft();
        d.anchor.role = "  ".to_string();
        assert!(AnchorLink::build(d, &key()).is_err());
    }

    #[test]
    fn hard_identity_anchors_with_same_triple_join() {
        let a = anchor("lower-bound a(n)", JoinPolicy::HardIdentity);
        let b = anchor("lower-bound a(n)", JoinPolicy::HardIdentity);
        assert!(anchors_equal(&a, &b));
    }

    #[test]
    fn different_role_does_not_join() {
        let a = anchor("lower-bound a(n)", JoinPolicy::HardIdentity);
        let b = anchor("upper-bound a(n)", JoinPolicy::HardIdentity);
        assert!(
            !anchors_equal(&a, &b),
            "role disambiguates sub-claims under one id"
        );
    }

    #[test]
    fn soft_or_search_policy_never_joins() {
        // Even a byte-identical SearchOnly/SoftCandidate anchor must not induce identity.
        let a = anchor("lower-bound a(n)", JoinPolicy::SearchOnly);
        let b = anchor("lower-bound a(n)", JoinPolicy::SearchOnly);
        assert!(!anchors_equal(&a, &b));
        let c = anchor("lower-bound a(n)", JoinPolicy::SoftCandidate);
        let d = anchor("lower-bound a(n)", JoinPolicy::SoftCandidate);
        assert!(!anchors_equal(&c, &d));
    }
}
