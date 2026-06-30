//! Co-authorship provenance, shaped on W3C PROV (entity / activity / agent).
//!
//! A state transition records WHO contributed to it as signed-over ATTRIBUTION.
//! The accountable party is the event (or attestation) signer, a durable human
//! key for any judgment. Everyone named here is a contribution, never an
//! authority: an AI that drafted the proposal, the CI that produced evidence.
//! Because the block lives inside the signed bytes it is tamper-evident and
//! auditable, yet it carries zero signing authority.
//!
//! Three planes are kept distinct and never collapsed: scientific authorship
//! (claims, releases), cryptographic accountability (the event signer), and
//! machine contribution (this block). The UI may render "Co-authored with
//! Claude"; the schema says `machine_contributions`, so it never implies an AI
//! is a scientific or accountable author.
//!
//! The no-signer property is STRUCTURAL. [`Provenance::validate`] refuses any id
//! that classifies as human (via [`crate::events::actor_kind`]) and any machine
//! contribution claiming authority, so a human key can never hide here to dodge
//! the accountable signature, and a verification path that consults only
//! `actor.id` can never treat a contribution as a signer. See
//! `docs/TRUST_MODEL_REDESIGN.md` sections 5 and 13.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Co-authorship attribution attached to an event payload or a `vsa_`
/// statement attestation. Every named id is NON-HUMAN; the accountable human is
/// the outer signer.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// What happened (PROV activity): drafted, formalized, verified, reviewed,
    /// accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activity: Option<Activity>,
    /// Non-human actors that contributed (the `Co-authored-by` analogue). Never
    /// authoritative.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub machine_contributions: Vec<MachineContribution>,
    /// Verifier / CI actors whose self-signed evidence this transition relied
    /// on. Each entry points at the `vva_` ids that carry their own signatures,
    /// so the decision CITES evidence without absorbing its authority.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_refs: Vec<EvidenceRef>,
    /// Inputs consumed (claim / proposal / object ids).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_refs: Vec<String>,
    /// Outputs produced (event / attestation / release ids).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_refs: Vec<String>,
}

/// The PROV activity a transition performed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Activity {
    /// `drafted` | `formalized` | `verified` | `reviewed` | `accepted`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub started_at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ended_at: String,
}

fn authority_none() -> String {
    "none".to_string()
}

/// A non-human actor that contributed to producing a transition.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineContribution {
    /// A non-human actor id, e.g. `agent:claude`. Refused by
    /// [`Provenance::validate`] if it classifies as human.
    pub id: String,
    /// Declared actor class (`agent`, `ci`). Decorative: the load-bearing class
    /// comes from `id` via [`crate::events::actor_kind`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    /// What the contributor did, e.g. `drafted`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    /// The tool surface, e.g. `claude-code`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub tool: String,
    /// UNVERIFIED free-text model/version provenance, e.g.
    /// `model: claude-opus-4-8`. Never resolved to a key, never an attestation
    /// ABOUT the model.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub generated_by: String,
    /// Always `none`. A machine contribution cannot assert authority;
    /// [`Provenance::validate`] refuses any other value. Present on the wire so
    /// the non-authoritative status is explicit, matching PROV's agent-role
    /// separation.
    #[serde(default = "authority_none")]
    pub authority: String,
}

/// A verifier / CI actor whose self-signed evidence a transition relied on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRef {
    /// A verifier / CI actor id, e.g. `ci:vela-verify`. Refused by
    /// [`Provenance::validate`] if it classifies as human.
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub role: String,
    /// The self-signed `vva_` evidence ids this decision cites.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachment_ids: Vec<String>,
}

impl Provenance {
    /// No attribution to record. An empty block is never serialized, so an event
    /// without provenance stays byte-identical to the pre-redesign shape.
    pub fn is_empty(&self) -> bool {
        self.activity.is_none()
            && self.machine_contributions.is_empty()
            && self.evidence_refs.is_empty()
            && self.input_refs.is_empty()
            && self.output_refs.is_empty()
    }

    /// Structural no-signer guard: every named id MUST be non-human, and no
    /// machine contribution may claim authority. A human id, or an asserted
    /// authority, would be a name standing in for the accountable signature, the
    /// exact anti-pattern the trust thesis forbids, so each is a hard error.
    pub fn validate(&self) -> Result<(), String> {
        for mc in &self.machine_contributions {
            if crate::events::actor_kind(&mc.id) == "human" {
                return Err(format!(
                    "provenance.machine_contributions may not name a human id ('{}'): the accountable human is the signer, never a contribution",
                    mc.id
                ));
            }
            if !mc.authority.is_empty() && mc.authority != "none" {
                return Err(format!(
                    "provenance.machine_contributions['{}'].authority must be 'none': a machine contribution cannot assert authority",
                    mc.id
                ));
            }
        }
        for er in &self.evidence_refs {
            if crate::events::actor_kind(&er.id) == "human" {
                return Err(format!(
                    "provenance.evidence_refs may not name a human id ('{}'): evidence is signed by machine verifiers, not humans",
                    er.id
                ));
            }
        }
        Ok(())
    }
}

/// Insert a validated provenance block into an event payload under the
/// `provenance` key. An empty block is a no-op, so the event stays
/// byte-identical (preserving its `vev_` and `event_log_hash`). A populated
/// block is validated first, so a human id can never enter a signed payload as a
/// non-signer.
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

    fn agent_contribution() -> MachineContribution {
        MachineContribution {
            id: "agent:claude".to_string(),
            class: "agent".to_string(),
            role: "drafted".to_string(),
            tool: "claude-code".to_string(),
            generated_by: "model: claude-opus-4-8".to_string(),
            authority: "none".to_string(),
        }
    }

    #[test]
    fn validate_accepts_non_human_ids() {
        let p = Provenance {
            activity: Some(Activity {
                kind: "accepted".to_string(),
                ..Default::default()
            }),
            machine_contributions: vec![agent_contribution()],
            evidence_refs: vec![EvidenceRef {
                id: "ci:vela-verify".to_string(),
                class: "ci".to_string(),
                role: "verified".to_string(),
                attachment_ids: vec!["vva_abc".to_string()],
            }],
            ..Default::default()
        };
        assert!(p.validate().is_ok());
    }

    #[test]
    fn validate_refuses_human_contribution() {
        let p = Provenance {
            machine_contributions: vec![MachineContribution {
                id: "reviewer:will-blair".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        // A human id smuggled in as a contribution must be a hard error: the
        // accountable human signs, they are never merely attributed.
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_refuses_human_evidence_ref() {
        let p = Provenance {
            evidence_refs: vec![EvidenceRef {
                id: "reviewer:will-blair".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(p.validate().is_err());
    }

    #[test]
    fn validate_refuses_machine_claiming_authority() {
        let mut mc = agent_contribution();
        mc.authority = "signer".to_string();
        let p = Provenance {
            machine_contributions: vec![mc],
            ..Default::default()
        };
        // A machine contribution that asserts authority is rejected: authority
        // is always the signer path, never a provenance entry.
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
            machine_contributions: vec![agent_contribution()],
            ..Default::default()
        };
        attach_to_payload(&mut payload, &p).unwrap();
        assert_eq!(
            payload["provenance"]["machine_contributions"][0]["id"],
            "agent:claude"
        );
        assert_eq!(
            payload["provenance"]["machine_contributions"][0]["authority"],
            "none"
        );
    }

    #[test]
    fn attach_refuses_human_before_writing() {
        let mut payload = json!({ "proposal_id": "vpr_x" });
        let p = Provenance {
            machine_contributions: vec![MachineContribution {
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
        // skip_serializing_if keeps every field out of the JSON when empty, so a
        // defaulted Provenance is the empty object and adds nothing to a body.
        let v = serde_json::to_value(Provenance::default()).unwrap();
        assert_eq!(v, json!({}));
    }
}
