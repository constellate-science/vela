//! Typed, signed, content-addressed Attempt (`vat_`) + ResolutionEvent
//! (`vre_`).
//!
//! ## The hole this closes
//!
//! Our own banked work lived in a Python ledger
//! (`scripts/canopus_attempts.py`) whose records are hand-editable JSON with
//! `att_` ids hashed from a pipe-delimited string. A proposer agent could
//! silently rewrite a banked attempt, and negatives/failed searches had no
//! first-class shape. This module lifts the attempt into the protocol as a
//! content-addressed, Ed25519-signed object — so any edit to a banked attempt
//! breaks both its `vat_` id and its signature in one `verify()` — and makes
//! the failed-attempt denominator and reproduction fraction first-class.
//!
//! ## Two objects, mirroring the Contradiction precedent
//!
//! - [`Attempt`] (`vat_`) is the immutable, signed deposit. Its id is
//!   content-addressed over the canonical body (id + signature +
//!   signer_pubkey zeroed), so the **same logical body yields the same id in
//!   Rust and Python** (`conformance/attempt-id.json` pins this), exactly like
//!   the `vex_` experiment. The signature binds a named signer to that body.
//! - [`ResolutionEvent`] (`vre_`) is an append-only lifecycle transition
//!   (`candidate → verified | refuted | superseded | redundant_with_literature`).
//!   It travels in a signed `attempt.resolved` [`crate::events::StateEvent`]
//!   (added in events.rs), and the reducer keeps the latest per attempt. The
//!   `verified` outcome carries a `gate_ref`, never a stored boolean — the
//!   gate result is derived from the `vva_` attachments on read, the same
//!   discipline the substrate already uses for `gate_status`.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ATTEMPT_SCHEMA: &str = "vela.attempt.v0.1";
pub const RESOLUTION_EVENT_SCHEMA: &str = "vela.resolution_event.v0.1";

/// Reproduction as an explicit fraction: `successes` of `total` independent
/// re-runs reproduced the claim. `0/0` means not yet reproduced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reproduction {
    pub successes: u64,
    pub total: u64,
}

/// The full cost of an attempt, including the failures that the headline
/// success hides. A frontier that shows only wins reproduces the exact
/// transparency hole the community calls out in lab repos.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptCost {
    /// Total attempts run for this claim (successes + failures + triage).
    pub total_attempts: u64,
    /// How many of those failed (the denominator made explicit).
    pub failed_attempts: u64,
    /// Free-form compute note (e.g. "788K randomized runs, 16 cores, 3h").
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub compute_note: String,
}

/// Who/what proposed the attempt and when.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub proposer: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub run: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub date: String,
}

/// The generic Producer primitive (v0.700 minimal core): which system emitted
/// the attempt, its version, and a digest of its configuration. Generalizes the
/// Sidon producer so any solver, an API reasoning model, an open prover, or a
/// closed agent, declares itself uniformly. The ablation and the retained-loop
/// handoff key on this to compare like producers and detect cross-producer reuse.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProducerRef {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub system: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub config_digest: String,
}

fn is_default_producer(p: &ProducerRef) -> bool {
    *p == ProducerRef::default()
}

/// A signed, content-addressed banked attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    pub schema: String,
    /// `vat_<16hex>`, content-addressed over the canonical body with
    /// `attempt_id`, `signature`, `signer_pubkey_hex` zeroed. Key-independent
    /// so Rust and Python derive the same id from the same body.
    pub attempt_id: String,
    pub problem: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub frontier: String,
    pub kind: String,
    pub claim: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    /// The proposer's self-reported status. DISPLAY ONLY; never trusted. The
    /// verified status is derived from the gate + ResolutionEvents on read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub claimed_status: String,
    /// `sha256(claim.trim())[:16]`, the same rule the gate and Python use.
    pub claim_digest: String,
    #[serde(default, skip_serializing_if = "is_default_reproduction")]
    pub reproduction: Reproduction,
    #[serde(default, skip_serializing_if = "is_default_cost")]
    pub cost: AttemptCost,
    /// What was learned, including from failure — so negatives survive as
    /// research assets, not as nothing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub insight: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related_problems: Vec<u32>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reusable_for: String,
    /// Ids of the `vva_` verifier attachments that earn this attempt's trust.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verifier_attachments: Vec<String>,
    /// Honest deliverable grade (anti-inflation), if assigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deliverable_grade: Option<String>,
    #[serde(default, skip_serializing_if = "is_default_provenance")]
    pub provenance: Provenance,
    // ── v0.700 Attempt Packet (the producer-forced minimal-core promotion) ──
    // Additive + skip-guarded, so legacy attempts serialize and content-address
    // byte-identically. These fields make the retained-producer handoff and the
    // inherited-state ablation measurable.
    /// The frontier root this attempt was made against. The pin that makes
    /// "Agent B with vs without Agent A's accepted state" a controlled compare,
    /// and that lets a later root be a clean continuation.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub base_frontier_root: String,
    /// The residual obligation this attempt targeted (free-form id; the
    /// Obligation/StatementVariant nouns stay domain-local until promoted).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target_obligation_id: String,
    /// The statement variant attempted (free-form id).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub statement_variant_id: String,
    /// Method families exercised. Drives duplicate-search detection in the ablation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub method_families: Vec<String>,
    /// Obligations left open after this attempt (free-form ids).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remaining_obligations: Vec<String>,
    /// Named obstructions encountered, free-form `kind:scope` until the
    /// Obstruction noun is promoted under a second producer's pressure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub named_obstructions: Vec<String>,
    /// What produced this attempt (the generic Producer primitive).
    #[serde(default, skip_serializing_if = "is_default_producer")]
    pub producer: ProducerRef,
    pub signature: String,
    pub signer_pubkey_hex: String,
}

fn is_default_reproduction(r: &Reproduction) -> bool {
    *r == Reproduction::default()
}
fn is_default_cost(c: &AttemptCost) -> bool {
    *c == AttemptCost::default()
}
fn is_default_provenance(p: &Provenance) -> bool {
    *p == Provenance::default()
}

/// Fields a caller supplies; schema, id, claim_digest, and signature are
/// derived.
#[derive(Debug, Clone, Default)]
pub struct AttemptDraft {
    pub problem: u32,
    pub frontier: String,
    pub kind: String,
    pub claim: String,
    pub detail: String,
    pub claimed_status: String,
    pub reproduction: Reproduction,
    pub cost: AttemptCost,
    pub insight: String,
    pub depends_on: Vec<String>,
    pub related_problems: Vec<u32>,
    pub reusable_for: String,
    pub verifier_attachments: Vec<String>,
    pub deliverable_grade: Option<String>,
    pub provenance: Provenance,
    // v0.700 Attempt Packet fields (all optional).
    pub base_frontier_root: String,
    pub target_obligation_id: String,
    pub statement_variant_id: String,
    pub method_families: Vec<String>,
    pub remaining_obligations: Vec<String>,
    pub named_obstructions: Vec<String>,
    pub producer: ProducerRef,
}

/// The one canonical claim digest (`sha256(claim.trim())[:16]`), defined in
/// `verifier_attachment` and re-exported here so a claim has one digest
/// everywhere (and matches `canopus_trust.py`).
pub use crate::verifier_attachment::claim_digest;

impl Attempt {
    /// Build and sign a banked attempt. The id is content-addressed over the
    /// canonical body (key-independent); the signature binds the signer.
    pub fn build(draft: AttemptDraft, key: &SigningKey) -> Result<Self, String> {
        if draft.problem == 0 {
            return Err("attempt.problem must be a positive problem number".to_string());
        }
        if draft.kind.trim().is_empty() {
            return Err("attempt.kind cannot be empty".to_string());
        }
        if draft.claim.trim().is_empty() {
            return Err("attempt.claim cannot be empty".to_string());
        }
        if draft.cost.failed_attempts > draft.cost.total_attempts {
            return Err("attempt.cost.failed_attempts cannot exceed total_attempts".to_string());
        }
        if draft.reproduction.successes > draft.reproduction.total {
            return Err("attempt.reproduction.successes cannot exceed total".to_string());
        }
        let mut att = Attempt {
            schema: ATTEMPT_SCHEMA.to_string(),
            attempt_id: String::new(),
            problem: draft.problem,
            frontier: draft.frontier,
            kind: draft.kind,
            claim_digest: claim_digest(&draft.claim),
            claim: draft.claim,
            detail: draft.detail,
            claimed_status: draft.claimed_status,
            reproduction: draft.reproduction,
            cost: draft.cost,
            insight: draft.insight,
            depends_on: draft.depends_on,
            related_problems: draft.related_problems,
            reusable_for: draft.reusable_for,
            verifier_attachments: draft.verifier_attachments,
            deliverable_grade: draft.deliverable_grade,
            provenance: draft.provenance,
            base_frontier_root: draft.base_frontier_root,
            target_obligation_id: draft.target_obligation_id,
            statement_variant_id: draft.statement_variant_id,
            method_families: draft.method_families,
            remaining_obligations: draft.remaining_obligations,
            named_obstructions: draft.named_obstructions,
            producer: draft.producer,
            signature: String::new(),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
        };
        let preimage = att.id_preimage_bytes()?;
        att.signature = hex::encode(crate::sign::sign_bytes(key, &preimage));
        att.attempt_id = att.derive_id()?;
        Ok(att)
    }

    /// The canonical-JSON bytes the id and signature are taken over: the body
    /// with `attempt_id`, `signature`, and `signer_pubkey_hex` zeroed. Zeroing
    /// the signer keeps the id a pure content address of the attempt, the same
    /// in Rust and Python.
    fn id_preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut preimage = self.clone();
        preimage.attempt_id = String::new();
        preimage.signature = String::new();
        preimage.signer_pubkey_hex = String::new();
        crate::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize attempt preimage: {e}"))
    }

    /// `vat_<16hex>` over the canonical content preimage.
    pub fn derive_id(&self) -> Result<String, String> {
        let bytes = self.id_preimage_bytes()?;
        Ok(format!(
            "vat_{}",
            &hex::encode(Sha256::digest(&bytes))[..16]
        ))
    }

    /// Build the canonical `attempt.deposited` event that persists this
    /// signed deposit to the frontier event log. The full object travels in
    /// `payload.attempt`; the reducer verifies and upserts it.
    #[must_use]
    pub fn deposit_event(
        &self,
        actor_id: &str,
        actor_type: &str,
        reason: &str,
    ) -> crate::events::StateEvent {
        let payload =
            serde_json::json!({ "attempt": serde_json::to_value(self).unwrap_or_default() });
        crate::events::new_attempt_deposited_event(
            &self.attempt_id,
            actor_id,
            actor_type,
            reason,
            payload,
            vec![
                "A signed banked attempt. Trust is earned via its verifier_attachments + the gate, never from claimed_status."
                    .to_string(),
            ],
        )
    }

    /// Verify: re-derive the id, verify the signature over the content
    /// preimage under the declared pubkey, and check `claim_digest` matches
    /// the claim. Any hand-edit to the body fails here.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != ATTEMPT_SCHEMA {
            return Err(format!(
                "attempt.schema must be `{ATTEMPT_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.attempt_id.starts_with("vat_") {
            return Err(format!(
                "attempt id must start with `vat_`, got `{}`",
                self.attempt_id
            ));
        }
        if self.claim_digest != claim_digest(&self.claim) {
            return Err("attempt.claim_digest does not match claim".to_string());
        }
        let preimage = self.id_preimage_bytes()?;
        if !crate::sign::verify_action_signature(
            &preimage,
            &self.signature,
            &self.signer_pubkey_hex,
        )? {
            return Err("attempt signature does not verify under the declared pubkey".to_string());
        }
        let rederived = self.derive_id()?;
        if rederived != self.attempt_id {
            return Err(format!(
                "attempt_id mismatch: declared {}, rebuilt {}",
                self.attempt_id, rederived
            ));
        }
        Ok(())
    }
}

/// The terminal outcome a ResolutionEvent records. `verified` carries the
/// gate reference rather than a stored boolean; `refuted` names the probe;
/// `superseded`/`redundant_with_literature` carry the pointer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AttemptResolution {
    /// The gate derived `verified` from the attached `vva_` evidence. The
    /// `gate_ref` cites the evaluation; the boolean is never stored.
    Verified { gate_ref: String },
    /// An adversarial probe refuted the claim. `by_probe` names it.
    Refuted { by_probe: String },
    /// A later attempt supersedes this one (corrected statement / better
    /// bound). `by` is the superseding `vat_` id.
    Superseded { by: String },
    /// Found to duplicate prior literature. `refs` are the citations.
    RedundantWithLiterature { refs: Vec<String> },
}

impl AttemptResolution {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verified",
            Self::Refuted { .. } => "refuted",
            Self::Superseded { .. } => "superseded",
            Self::RedundantWithLiterature { .. } => "redundant_with_literature",
        }
    }
}

/// An append-only lifecycle transition on an [`Attempt`]. Content-addressed
/// (`vre_`); authenticity comes from the signed `attempt.resolved`
/// [`crate::events::StateEvent`] it travels in (mirrors how a Contradiction's
/// resolution is carried by a signed event, not self-signed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionEvent {
    pub schema: String,
    /// `vre_<16hex>` over `attempt_id | resolution | actor | at`.
    pub resolution_id: String,
    /// The `vat_` this resolves.
    pub attempt_id: String,
    pub resolution: AttemptResolution,
    /// The named actor rendering the judgment (`reviewer:` / `agent:`).
    pub actor: String,
    /// ISO-8601 valid time of the transition.
    pub at: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl ResolutionEvent {
    /// Build a resolution event, deriving its content-addressed id.
    pub fn new(
        attempt_id: &str,
        resolution: AttemptResolution,
        actor: &str,
        at: &str,
        note: &str,
    ) -> Result<Self, String> {
        if !attempt_id.starts_with("vat_") {
            return Err(format!(
                "resolution target must be a `vat_` id, got `{attempt_id}`"
            ));
        }
        if actor.trim().is_empty() {
            return Err("resolution actor cannot be empty".to_string());
        }
        let mut ev = ResolutionEvent {
            schema: RESOLUTION_EVENT_SCHEMA.to_string(),
            resolution_id: String::new(),
            attempt_id: attempt_id.to_string(),
            resolution,
            actor: actor.to_string(),
            at: at.to_string(),
            note: note.to_string(),
        };
        ev.resolution_id = ev.derive_id()?;
        Ok(ev)
    }

    /// `vre_<16hex>` over the canonical body with the id zeroed.
    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.resolution_id = String::new();
        let bytes = crate::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize resolution preimage: {e}"))?;
        Ok(format!(
            "vre_{}",
            &hex::encode(Sha256::digest(&bytes))[..16]
        ))
    }

    /// Build the canonical `attempt.resolved` event carrying this transition.
    /// Authenticity comes from the signed event log; the object travels in
    /// `payload.resolution`.
    #[must_use]
    pub fn to_state_event(&self, actor_type: &str, reason: &str) -> crate::events::StateEvent {
        let payload =
            serde_json::json!({ "resolution": serde_json::to_value(self).unwrap_or_default() });
        crate::events::new_attempt_resolved_event(
            &self.attempt_id,
            &self.actor,
            actor_type,
            reason,
            payload,
            vec![],
        )
    }

    /// Structural validity: schema, id prefix, id integrity.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != RESOLUTION_EVENT_SCHEMA {
            return Err(format!(
                "resolution.schema must be `{RESOLUTION_EVENT_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.resolution_id.starts_with("vre_") {
            return Err(format!(
                "resolution id must start with `vre_`, got `{}`",
                self.resolution_id
            ));
        }
        let derived = self.derive_id()?;
        if derived != self.resolution_id {
            return Err(format!(
                "resolution id mismatch: stored {}, derived {}",
                self.resolution_id, derived
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn ok_draft() -> AttemptDraft {
        AttemptDraft {
            problem: 309,
            frontier: "sidon-a309370".to_string(),
            kind: "lower_bound".into(),
            claim: "a(8) >= 33".to_string(),
            detail: "witness of 33 binary vectors, pairwise sums distinct".to_string(),
            claimed_status: "verified_computationally".to_string(),
            reproduction: Reproduction {
                successes: 3,
                total: 3,
            },
            cost: AttemptCost {
                total_attempts: 1200,
                failed_attempts: 1199,
                compute_note: "CP-SAT, 8 cores".to_string(),
            },
            insight: "binary alphabet keeps sums in {0,1,2}".to_string(),
            depends_on: vec![],
            related_problems: vec![773],
            reusable_for: "any B2 set over {0,1}^n".to_string(),
            verifier_attachments: vec!["vva_0123456789abcdef".to_string()],
            deliverable_grade: Some("improved_published_bound".to_string()),
            provenance: Provenance {
                proposer: "Opus 4.8".to_string(),
                run: "wf_demo".to_string(),
                date: "2026-06-09".to_string(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn packet_fields_round_trip_and_legacy_id_is_stable() {
        // A packet-bearing attempt carries the v0.700 fields, round-trips through
        // canonical JSON, and re-verifies; the producer/root/obstruction fields
        // are part of the content address (a tampered root breaks the id).
        let mut d = ok_draft();
        d.base_frontier_root = "sha256:deadbeef".into();
        d.target_obligation_id = "sidon:a309370:n8".into();
        d.method_families = vec!["cp-sat".into(), "randomized-restart".into()];
        d.remaining_obligations = vec!["sidon:a309370:n9".into()];
        d.named_obstructions = vec!["search-does-not-scale:greedy".into()];
        d.producer = ProducerRef {
            system: "claude".into(),
            version: "opus-4-8".into(),
            config_digest: "sha256:cfg".into(),
        };
        let a = Attempt::build(d, &key()).unwrap();
        a.verify().unwrap();
        let round: Attempt = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        assert_eq!(round, a);
        round.verify().unwrap();
        assert_eq!(round.producer.system, "claude");
        assert_eq!(round.base_frontier_root, "sha256:deadbeef");
        // A legacy attempt (no packet fields) keeps a distinct, stable id.
        let legacy = Attempt::build(ok_draft(), &key()).unwrap();
        assert_ne!(legacy.attempt_id, a.attempt_id);
    }

    #[test]
    fn builds_signs_and_verifies() {
        let a = Attempt::build(ok_draft(), &key()).unwrap();
        assert!(a.attempt_id.starts_with("vat_"));
        assert_eq!(a.claim_digest, claim_digest("a(8) >= 33"));
        a.verify().unwrap();
    }

    #[test]
    fn tampered_body_breaks_id_and_signature() {
        let mut a = Attempt::build(ok_draft(), &key()).unwrap();
        // Hand-edit a banked attempt: the claim no longer matches the digest,
        // the id no longer re-derives, and the signature no longer verifies.
        a.claim = "a(8) >= 99".to_string();
        assert!(a.verify().is_err());
    }

    #[test]
    fn id_is_key_independent_content_address() {
        // The same body signed by two DIFFERENT keys yields the SAME vat_ id
        // (the id is a content address; the signer is recorded separately).
        let a1 = Attempt::build(ok_draft(), &key()).unwrap();
        let a2 = Attempt::build(ok_draft(), &key()).unwrap();
        assert_eq!(a1.attempt_id, a2.attempt_id);
        assert_ne!(a1.signature, a2.signature);
        assert_ne!(a1.signer_pubkey_hex, a2.signer_pubkey_hex);
    }

    #[test]
    fn cross_impl_pinned_id() {
        // Pinned vat_ id for fixed inputs under the all-zeros key. The Python
        // ledger's canonical-JSON derivation must reproduce this byte-for-byte
        // (conformance/attempt-id.json + verify_attempt_id.py).
        let key = SigningKey::from_bytes(&[0u8; 32]);
        let draft = AttemptDraft {
            problem: 1,
            frontier: "f".to_string(),
            kind: "k".into(),
            claim: "c".to_string(),
            ..Default::default()
        };
        let a = Attempt::build(draft, &key).unwrap();
        // Pinned id, reproduced byte-for-byte by `conformance/verify_attempt_id.py`
        // from the same canonical body. Cross-impl drift flags here.
        assert_eq!(a.attempt_id, "vat_0008df5d18b5bdea");
        assert_eq!(a.claim_digest, "2e7d2c03a9507ae2");
    }

    #[test]
    fn rejects_impossible_reproduction_and_cost() {
        let mut d = ok_draft();
        d.reproduction = Reproduction {
            successes: 5,
            total: 3,
        };
        assert!(Attempt::build(d, &key()).is_err());
        let mut d2 = ok_draft();
        d2.cost = AttemptCost {
            total_attempts: 2,
            failed_attempts: 9,
            compute_note: String::new(),
        };
        assert!(Attempt::build(d2, &key()).is_err());
    }

    #[test]
    fn resolution_event_is_content_addressed() {
        let a = Attempt::build(ok_draft(), &key()).unwrap();
        let ev = ResolutionEvent::new(
            &a.attempt_id,
            AttemptResolution::Verified {
                gate_ref: "gate@vva_0123456789abcdef".to_string(),
            },
            "reviewer:will-blair",
            "2026-06-09T00:00:00Z",
            "two independent methods + surviving probe",
        )
        .unwrap();
        assert!(ev.resolution_id.starts_with("vre_"));
        assert_eq!(ev.resolution.as_str(), "verified");
        ev.verify().unwrap();
    }

    #[test]
    fn resolution_rejects_non_vat_target() {
        let r = ResolutionEvent::new(
            "vf_not_an_attempt",
            AttemptResolution::Refuted {
                by_probe: "case_b".to_string(),
            },
            "reviewer:x",
            "2026-06-09T00:00:00Z",
            "",
        );
        assert!(r.is_err());
    }

    #[test]
    fn json_roundtrip() {
        let a = Attempt::build(ok_draft(), &key()).unwrap();
        let s = serde_json::to_string(&a).unwrap();
        let back: Attempt = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
        back.verify().unwrap();
    }
}
