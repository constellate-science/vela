//! Co-authorship provenance: the GitHub `Co-authored-by` pattern made
//! cryptographic.
//!
//! A state transition records WHO contributed to it as signed-over
//! ATTRIBUTION. The accountable party is the event (or attestation) signer, a
//! durable human key for any verdict. Everyone named here is attributed, never
//! a signer: an AI that drafted the proposal, the CI that produced evidence.
//! Because the block lives inside the signed bytes, it is tamper-evident and
//! auditable, yet it contributes zero signing authority.
//!
//! The no-signer property is STRUCTURAL, not documentary. [`Provenance::validate`]
//! refuses any id that classifies as human (via [`crate::events::actor_kind`]),
//! so a human key can never hide here to dodge the accountable signature, and a
//! signature-verification path that consults only `actor.id` can never be
//! tricked into treating a co-author name as a signer. See
//! `docs/TRUST_MODEL_REDESIGN.md` section 4.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Co-authorship attribution attached to an event payload or a `vsa_`
/// statement attestation. Both lists hold NON-HUMAN actor ids only; the
/// accountable human is the outer signer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// Non-human actors that drafted or assisted (the `Co-authored-by`
    /// analogue). Never authoritative.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub co_authors: Vec<CoAuthor>,
    /// Verifier / CI actors whose self-signed evidence this transition relied
    /// on. Each entry points at the `vva_` ids that carry their own signatures,
    /// so the decision CITES evidence without absorbing its authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attested_by: Vec<Attestor>,
}

/// A non-human actor that drafted or assisted in producing a transition.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoAuthor {
    /// A non-human actor id, e.g. `agent:claude`. Refused by [`Provenance::validate`]
    /// if it classifies as human.
    pub id: String,
    /// Declared actor class (e.g. `agent`). Decorative: the load-bearing class
    /// comes from `id` via [`crate::events::actor_kind`], not from this field.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    /// What the co-author did, e.g. `drafted`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    /// UNVERIFIED free-text tool/model provenance, e.g.
    /// `claude-code/1.x (model: claude-opus-4-8)`. The `Generated-By` split:
    /// tool/model provenance distinct from people-shaped authorship. It is never
    /// resolved to a key and is never an attestation ABOUT the model.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub generated_by: String,
}

/// A verifier / CI actor whose self-signed evidence a transition relied on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestor {
    /// A verifier / CI actor id, e.g. `ci:vela-verify`. Refused by
    /// [`Provenance::validate`] if it classifies as human.
    pub id: String,
    /// Declared actor class. Decorative, like [`CoAuthor::class`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    /// What the attestor did, e.g. `verified`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    /// The self-signed `vva_` evidence ids this decision cites.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachment_ids: Vec<String>,
}

impl Provenance {
    /// No attribution to record. An empty block is never serialized, so an event
    /// without co-authors stays byte-identical to the pre-redesign shape.
    pub fn is_empty(&self) -> bool {
        self.co_authors.is_empty() && self.attested_by.is_empty()
    }

    /// Structural no-signer guard: every named id MUST be non-human. A human id
    /// inside `provenance` would be a typed name standing in for the accountable
    /// signature, the exact anti-pattern the trust thesis forbids, so it is a
    /// hard build-time error rather than a silent attribution.
    pub fn validate(&self) -> Result<(), String> {
        for ca in &self.co_authors {
            if crate::events::actor_kind(&ca.id) == "human" {
                return Err(format!(
                    "provenance.co_authors may not name a human id ('{}'): the accountable human is the signer, never a co-author",
                    ca.id
                ));
            }
        }
        for at in &self.attested_by {
            if crate::events::actor_kind(&at.id) == "human" {
                return Err(format!(
                    "provenance.attested_by may not name a human id ('{}'): evidence is signed by machine verifiers, not humans",
                    at.id
                ));
            }
        }
        Ok(())
    }
}

/// Insert a validated provenance block into an event payload under the
/// `provenance` key. An empty block is a no-op, so the event stays
/// byte-identical (preserving its `vev_` and `event_log_hash`). A populated
/// block is validated first, so a human id can never enter a signed payload as
/// a non-signer.
pub fn attach_to_payload(payload: &mut Value, prov: &Provenance) -> Result<(), String> {
    if prov.is_empty() {
        return Ok(());
    }
    prov.validate()?;
    let obj = payload
        .as_object_mut()
        .ok_or("provenance: event payload must be a JSON object to carry a provenance block")?;
    obj.insert(
        "provenance".to_string(),
        serde_json::to_value(prov).map_err(|e| format!("provenance: serialize: {e}"))?,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn agent_coauthor() -> CoAuthor {
        CoAuthor {
            id: "agent:claude".to_string(),
            class: "agent".to_string(),
            role: "drafted".to_string(),
            generated_by: "claude-code (model: claude-opus-4-8)".to_string(),
        }
    }

    #[test]
    fn validate_accepts_non_human_ids() {
        let p = Provenance {
            co_authors: vec![agent_coauthor()],
            attested_by: vec![Attestor {
                id: "ci:vela-verify".to_string(),
                class: "agent".to_string(),
                role: "verified".to_string(),
                attachment_ids: vec!["vva_abc".to_string()],
            }],
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_refuses_human_co_author() {
        let p = Provenance {
            co_authors: vec![CoAuthor {
                id: "reviewer:will-blair".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        // A human id smuggled in as a co-author must be a hard error: the
        // accountable human signs, they are never merely attributed.
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_refuses_human_attestor() {
        let p = Provenance {
            attested_by: vec![Attestor {
                id: "reviewer:will-blair".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn attach_empty_is_a_noop_byte_identical() {
        let mut payload = json!({ "proposal_id": "vpr_x", "verdict": "accepted" });
        let before = payload.clone();
        attach_to_payload(&mut payload, &Provenance::default()).unwrap();
        // An absent block must never perturb the payload, so the event's vev_
        // and event_log_hash are unchanged for every pre-redesign event.
        assert_eq!(payload, before);
        assert!(payload.get("provenance").is_none());
    }

    #[test]
    fn attach_populated_inserts_block() {
        let mut payload = json!({ "proposal_id": "vpr_x" });
        let p = Provenance {
            co_authors: vec![agent_coauthor()],
            ..Default::default()
        };
        attach_to_payload(&mut payload, &p).unwrap();
        assert_eq!(payload["provenance"]["co_authors"][0]["id"], "agent:claude");
    }

    #[test]
    fn attach_refuses_human_before_writing() {
        let mut payload = json!({ "proposal_id": "vpr_x" });
        let p = Provenance {
            co_authors: vec![CoAuthor {
                id: "reviewer:will-blair".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(attach_to_payload(&mut payload, &p).is_err());
        // The guard fires before mutation: a rejected block leaves no trace.
        assert!(payload.get("provenance").is_none());
    }

    #[test]
    fn empty_block_serializes_to_empty_object() {
        // skip_serializing_if keeps both lists out of the JSON when empty, so a
        // defaulted Provenance is the empty object and adds nothing to a body.
        let v = serde_json::to_value(Provenance::default()).unwrap();
        assert_eq!(v, json!({}));
    }
}
