//! Typed, signed, content-addressed cross-domain Transfer (`vtr_`).
//!
//! ## The asset this is
//!
//! A `vtr_` certifies that claim **A** (gate-verified in domain X) discharges a
//! named **premise of claim B** (domain Y), via a verification-preserving map
//! (a verifier-homomorphism) whose soundness is itself kernel-verified. It is
//! the one record a single-domain captive substrate structurally cannot mint:
//! it has no second frontier's gate-verified claim to point at and no
//! cross-frontier theorem to anchor the link.
//!
//! ## What it does NOT claim
//!
//! A transfer **does not re-prove A and does not re-run A's verifier.** It
//! binds three references to already-trusted objects:
//!   1. A's *existing* gate outcome (by claim digest + the `vva_` attachment ids
//!      that earn it),
//!   2. a kernel-verified `Transfer A B` theorem (by its `vlv_`), and
//!   3. the exact premise of B it discharges (by digest).
//! The trust base is the Lean kernel + the `tcb_policy` axiom allowlist (via the
//! `vlv_` axiom audit) + A's own G1–G5 gate. Nothing platform-adjudicated. A
//! consumer who already trusts A and the kernel gets B's premise discharged for
//! free; a consumer who trusts neither inherits exactly those two dependencies,
//! made auditable. It does not claim B is true (one premise is discharged), nor
//! that A is true beyond its gate status.
//!
//! Like every other status in the substrate (`gate_status`, Belnap,
//! `attempt_resolutions`), admission is a pure function of signed objects,
//! recomputed on read via [`derive_transfer_status`] — never a stored boolean.
//! That is precisely what lets two independent consumers reach the same verdict.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const TRANSFER_SCHEMA: &str = "vela.transfer.v0.1";

/// The witness the homomorphism's soundness rests on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferKind {
    /// Soundness is a kernel-verified Lean verifier-homomorphism (a
    /// `Transfer A B` whose `sound` field is a real proof). The strong form:
    /// trust base is the Lean kernel + the axiom allowlist.
    LeanHomomorphism,
    /// Soundness is an executable frozen verifier that re-checks the mapped
    /// object passes B's verifier. Weaker: the trust base additionally includes
    /// that verifier, which `derive_transfer_status` flags in its reasons.
    FrozenVerifier,
}

/// The verification-preserving map A → B, named by the artifact that proves it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomomorphismDescriptor {
    pub kind: TransferKind,
    /// For `LeanHomomorphism`: the Lean decl implementing `Transfer A B`
    /// (e.g. "Vela.TransferCWCtoDNA.cwcToDNA"). For `FrozenVerifier`: the
    /// verifier id (e.g. "vela-verify:dnacode").
    pub map_decl: String,
    /// Source frontier type tag — must equal A's domain (e.g. "constant_weight_code").
    pub source_type: String,
    /// Target frontier type tag — must equal B's premise domain (e.g. "dna_code").
    pub target_type: String,
    /// The `vlv_` Lean verification of the transfer theorem (`LeanHomomorphism`).
    /// Empty for `FrozenVerifier`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub theorem_verification: String,
    /// The Theorem-23-family theorem id in the lean-anchors registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem_id: Option<u32>,
}

/// A signed, content-addressed cross-domain transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transfer {
    pub schema: String,
    /// `vtr_<16hex>`, content-addressed over the canonical body with
    /// `transfer_id`, `signature`, `signer_pubkey_hex` zeroed. Key-independent
    /// so Rust and Python derive the same id from the same body.
    pub transfer_id: String,

    // --- SOURCE (the carried claim, domain X) ---
    /// The source claim object (`vf_`/`vfr_`/`vat_`) in domain X.
    pub source_claim: String,
    /// `sha256(A.claim.trim())[:16]` — the same digest the gate keys A on.
    pub source_claim_digest: String,
    /// A's gate status AS DECLARED. DISPLAY ONLY; re-derived at verify time via
    /// `derive_transfer_status`, never trusted from here (mirrors
    /// `attempt.claimed_status`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub source_gate_status_claimed: String,
    /// The `vva_` attachment ids that earn A's gate status (the evidence set,
    /// bound into the signed body).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_attachments: Vec<String>,

    // --- TARGET (the discharged premise, domain Y) ---
    /// The target claim object (`vf_`/`vfr_`) whose premise this discharges.
    pub target_claim: String,
    /// `sha256(premise.trim())[:16]` of the *exact* premise A discharges — not
    /// all of B. Pins the link to one obligation.
    pub target_premise_digest: String,

    // --- THE LINK ---
    pub homomorphism: HomomorphismDescriptor,

    #[serde(default, skip_serializing_if = "is_default_provenance")]
    pub provenance: crate::attempt::Provenance,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,

    pub signature: String,
    pub signer_pubkey_hex: String,
}

fn is_default_provenance(p: &crate::attempt::Provenance) -> bool {
    *p == crate::attempt::Provenance::default()
}

/// Everything needed to build a [`Transfer`] except the derived id/signature.
/// `Deserialize` so a producer can mint from a draft JSON (`vela transfer mint`).
#[derive(Deserialize)]
pub struct TransferDraft {
    pub source_claim: String,
    pub source_claim_digest: String,
    #[serde(default)]
    pub source_gate_status_claimed: String,
    #[serde(default)]
    pub source_attachments: Vec<String>,
    pub target_claim: String,
    pub target_premise_digest: String,
    pub homomorphism: HomomorphismDescriptor,
    #[serde(default)]
    pub provenance: crate::attempt::Provenance,
    #[serde(default)]
    pub note: String,
}

impl Transfer {
    /// Build + sign. The id is a pure content address of the canonical body
    /// (key-independent); the signature binds the signer. Mirrors `Attempt::build`.
    pub fn build(draft: TransferDraft, key: &SigningKey) -> Result<Self, String> {
        if draft.source_claim.trim().is_empty() {
            return Err("transfer.source_claim cannot be empty".to_string());
        }
        if draft.target_claim.trim().is_empty() {
            return Err("transfer.target_claim cannot be empty".to_string());
        }
        if draft.target_premise_digest.trim().is_empty() {
            return Err(
                "transfer.target_premise_digest cannot be empty (T5: a transfer must \
                        discharge a specific premise, not all of B)"
                    .to_string(),
            );
        }
        let h = &draft.homomorphism;
        if h.map_decl.trim().is_empty() {
            return Err("transfer.homomorphism.map_decl cannot be empty".to_string());
        }
        if h.source_type.trim().is_empty() || h.target_type.trim().is_empty() {
            return Err(
                "transfer.homomorphism source_type/target_type cannot be empty".to_string(),
            );
        }
        if h.kind == TransferKind::LeanHomomorphism && !h.theorem_verification.starts_with("vlv_") {
            return Err(
                "a LeanHomomorphism transfer requires a `vlv_` theorem_verification".to_string(),
            );
        }
        let mut t = Transfer {
            schema: TRANSFER_SCHEMA.to_string(),
            transfer_id: String::new(),
            source_claim: draft.source_claim,
            source_claim_digest: draft.source_claim_digest,
            source_gate_status_claimed: draft.source_gate_status_claimed,
            source_attachments: draft.source_attachments,
            target_claim: draft.target_claim,
            target_premise_digest: draft.target_premise_digest,
            homomorphism: draft.homomorphism,
            provenance: draft.provenance,
            note: draft.note,
            signature: String::new(),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
        };
        let preimage = t.id_preimage_bytes()?;
        t.signature = hex::encode(crate::sign::sign_bytes(key, &preimage));
        t.transfer_id = t.derive_id()?;
        Ok(t)
    }

    /// The canonical-JSON bytes the id and signature are taken over: the body
    /// with `transfer_id`, `signature`, `signer_pubkey_hex` zeroed.
    fn id_preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut preimage = self.clone();
        preimage.transfer_id = String::new();
        preimage.signature = String::new();
        preimage.signer_pubkey_hex = String::new();
        crate::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize transfer preimage: {e}"))
    }

    /// `vtr_<16hex>` over the canonical content preimage.
    pub fn derive_id(&self) -> Result<String, String> {
        let bytes = self.id_preimage_bytes()?;
        Ok(format!(
            "vtr_{}",
            &hex::encode(Sha256::digest(&bytes))[..16]
        ))
    }

    /// Structural verify: re-derive the id, verify the signature over the
    /// content preimage. Any hand-edit to the body fails here. (Admission — that
    /// the link is sound — is a separate read-time check, [`derive_transfer_status`].)
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != TRANSFER_SCHEMA {
            return Err(format!(
                "transfer.schema must be `{TRANSFER_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        if !self.transfer_id.starts_with("vtr_") {
            return Err(format!(
                "transfer id must start with `vtr_`, got `{}`",
                self.transfer_id
            ));
        }
        let preimage = self.id_preimage_bytes()?;
        if !crate::sign::verify_action_signature(
            &preimage,
            &self.signature,
            &self.signer_pubkey_hex,
        )? {
            return Err("transfer signature does not verify under the declared pubkey".to_string());
        }
        let rederived = self.derive_id()?;
        if rederived != self.transfer_id {
            return Err(format!(
                "transfer_id mismatch: declared {}, rebuilt {}",
                self.transfer_id, rederived
            ));
        }
        Ok(())
    }

    /// Build the canonical `transfer.deposited` event. The full object travels
    /// in `payload.transfer`; the reducer verifies and upserts it.
    #[must_use]
    pub fn deposit_event(
        &self,
        actor_id: &str,
        actor_type: &str,
        reason: &str,
    ) -> crate::events::StateEvent {
        let payload =
            serde_json::json!({ "transfer": serde_json::to_value(self).unwrap_or_default() });
        crate::events::new_transfer_deposited_event(
            &self.transfer_id,
            actor_id,
            actor_type,
            reason,
            payload,
            vec![
                "A signed cross-domain transfer. It certifies the LINK is sound given A's \
                 gate-status; it does NOT re-prove A or re-run A's verifier."
                    .to_string(),
            ],
        )
    }
}

/// The derived admission status of a transfer. Like [`crate::verifier_attachment::GateStatus`],
/// there is no constructor that sets this directly — only [`derive_transfer_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    /// The default: not enough verified evidence to admit the link.
    NeedsVerification,
    /// T1–T5 all satisfied: A's claim discharges B's premise.
    Admitted,
    /// A's source claim is refuted, or the transfer theorem's method integrity
    /// is compromised (e.g. `native_decide`/`sorry`). Terminal until revised.
    Rejected,
}

/// The full outcome: a status plus the reasons it is not [`TransferStatus::Admitted`]
/// (empty exactly when admitted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutcome {
    pub status: TransferStatus,
    pub reasons: Vec<String>,
}

impl TransferOutcome {
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        self.status == TransferStatus::Admitted
    }
}

/// The domain tags a resolver pulled from A's actual frontier and B's premise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainTags {
    pub source: String,
    pub target: String,
}

/// The frozen-verifier ids admissible as a `FrozenVerifier` transfer witness.
/// Anything else forces `NeedsVerification` (the weaker form is gated to known,
/// audited executable verifiers, never an arbitrary string).
const ALLOWED_FROZEN_VERIFIERS: &[&str] = &[
    "vela-verify:sidon",
    "vela-verify:cap",
    "vela-verify:golomb",
    "vela-verify:bh",
    "vela-verify:constantweight",
    "vela-verify:linearcode",
    "vela-verify:dnacode",
    "vela-verify:covering",
    "vela-verify:stabilizer",
];

/// Derive whether a transfer is admitted: a pure function of already-signed
/// objects (T1–T5), recomputed on read, never stored. Mirrors
/// [`crate::verifier_attachment::derive_gate_status`].
///
/// - `source_gate`: A's gate outcome, derived by the caller over the `vva_`
///   attachments matching `transfer.source_claim_digest`.
/// - `theorem_verification`: the `vlv_` of the transfer theorem (for
///   `LeanHomomorphism`); `None` is allowed only for `FrozenVerifier`.
/// - `domain_tags`: A's actual domain and B's premise's domain, resolved from state.
#[must_use]
pub fn derive_transfer_status(
    transfer: &Transfer,
    source_gate: &crate::verifier_attachment::GateOutcome,
    theorem_verification: Option<&crate::lean_verification::LeanVerification>,
    domain_tags: &DomainTags,
) -> TransferOutcome {
    use crate::verifier_attachment::{GateStatus, MethodIntegrity};
    let mut reasons = Vec::new();
    let mut rejected = false;

    // T4 well-formed (structural integrity of the link itself).
    if let Err(e) = transfer.verify() {
        reasons.push(format!("T4: transfer is not well-formed: {e}"));
    }

    // T1 source-verified — consume A's EXISTING gate outcome, never recompute.
    match source_gate.status {
        GateStatus::Verified => {}
        GateStatus::Refuted => {
            rejected = true;
            reasons.push(
                "T1: source claim A is REFUTED — the transfer cannot discharge B".to_string(),
            );
        }
        GateStatus::NeedsVerification => {
            reasons.push("T1: source claim A is not gate-verified (NeedsVerification)".to_string());
        }
    }

    // T2 method integrity of the homomorphism witness.
    match transfer.homomorphism.kind {
        TransferKind::LeanHomomorphism => match theorem_verification {
            None => reasons.push(
                "T2: LeanHomomorphism transfer has no resolved `vlv_` theorem verification"
                    .to_string(),
            ),
            Some(v) => {
                if let Err(e) = v.verify() {
                    reasons.push(format!("T2: transfer theorem `vlv_` does not verify: {e}"));
                } else if v.status != "verified" {
                    reasons.push(format!(
                        "T2: transfer theorem status is `{}`, not `verified`",
                        v.status
                    ));
                }
                match v.to_attachment_integrity() {
                    MethodIntegrity::Sound => {}
                    MethodIntegrity::Compromised => {
                        rejected = true;
                        reasons.push("T2: transfer theorem method integrity COMPROMISED \
                                      (forbidden axiom — e.g. native_decide/sorry — or failed kernel re-check)"
                            .to_string());
                    }
                    MethodIntegrity::Unattested => reasons
                        .push("T2: transfer theorem has no axiom audit (Unattested)".to_string()),
                }
            }
        },
        TransferKind::FrozenVerifier => {
            if ALLOWED_FROZEN_VERIFIERS.contains(&transfer.homomorphism.map_decl.as_str()) {
                reasons.push(format!(
                    "note: FrozenVerifier transfer — trust base additionally includes the executable \
                     verifier `{}`, not only the Lean kernel",
                    transfer.homomorphism.map_decl
                ));
            } else {
                reasons.push(format!(
                    "T2: FrozenVerifier `{}` is not in the audited allowlist",
                    transfer.homomorphism.map_decl
                ));
            }
        }
    }

    // T3 type-match: the homomorphism's declared A→B types must equal A's actual
    // domain and B's premise's domain. A map proven for X→Y cannot discharge a Z premise.
    if transfer.homomorphism.source_type != domain_tags.source {
        reasons.push(format!(
            "T3: homomorphism source_type `{}` != A's domain `{}`",
            transfer.homomorphism.source_type, domain_tags.source
        ));
    }
    if transfer.homomorphism.target_type != domain_tags.target {
        reasons.push(format!(
            "T3: homomorphism target_type `{}` != B's premise domain `{}`",
            transfer.homomorphism.target_type, domain_tags.target
        ));
    }

    // T5 premise-binding: a specific premise, not all of B.
    if transfer.target_premise_digest.trim().is_empty() {
        reasons.push("T5: target_premise_digest is empty (no specific premise pinned)".to_string());
    }

    // A `note:` reason (the FrozenVerifier trust-base disclosure) does not block
    // admission; only T-clause failures do.
    let blocking = reasons.iter().any(|r| !r.starts_with("note:"));
    let status = if rejected {
        TransferStatus::Rejected
    } else if blocking {
        TransferStatus::NeedsVerification
    } else {
        TransferStatus::Admitted
    };
    TransferOutcome { status, reasons }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lean_verification::{KernelRecheck, LeanVerification, VerificationDraft};
    use crate::tcb_policy::AxiomVerdict;
    use crate::verifier_attachment::{GateOutcome, GateStatus};
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn lean_decl_descriptor(theorem_verification: &str) -> HomomorphismDescriptor {
        HomomorphismDescriptor {
            kind: TransferKind::LeanHomomorphism,
            map_decl: "Vela.TransferCWCtoDNA.cwcToDNA".to_string(),
            source_type: "constant_weight_code".to_string(),
            target_type: "dna_code".to_string(),
            theorem_verification: theorem_verification.to_string(),
            theorem_id: Some(35),
        }
    }

    fn draft(theorem_verification: &str) -> TransferDraft {
        TransferDraft {
            source_claim: "vat_aaaaaaaaaaaaaaaa".to_string(),
            source_claim_digest: crate::verifier_attachment::claim_digest("A(n,d,w) >= 12"),
            source_gate_status_claimed: "verified".to_string(),
            source_attachments: vec!["vva_bbbbbbbbbbbbbbbb".to_string()],
            target_claim: "vfr_cccccccccccccccc".to_string(),
            target_premise_digest: crate::verifier_attachment::claim_digest(
                "a DNA code of size >= 12 exists",
            ),
            homomorphism: lean_decl_descriptor(theorem_verification),
            provenance: crate::attempt::Provenance::default(),
            note: String::new(),
        }
    }

    /// A kernel-clean (or compromised) Lean verification for the transfer theorem.
    fn lean_v(kernel_clean: bool) -> LeanVerification {
        let d = VerificationDraft {
            anchor_id: "vla_dddddddddddddddd".to_string(),
            theorem_id: 35,
            module: "Vela/Transfer.lean".to_string(),
            module_sha256: "0".repeat(64),
            lean_toolchain: "leanprover/lean4:v4.29.1".to_string(),
            mathlib_revision: "abc".to_string(),
            verifier_output_hash: "0".repeat(64),
            status: if kernel_clean {
                "verified".to_string()
            } else {
                "failed_axiom_check".to_string()
            },
            verified_at: "2026-06-09T00:00:00Z".to_string(),
            verifier_actor: "test".to_string(),
            tcb_id: "vtcb_dddddddddddddddd".to_string(),
            axioms: vec![
                "propext".to_string(),
                "Classical.choice".to_string(),
                "Quot.sound".to_string(),
            ],
            axiom_verdict: Some(if kernel_clean {
                AxiomVerdict::KernelClean
            } else {
                AxiomVerdict::ForbiddenAxiom
            }),
            kernel_recheck: Some(KernelRecheck::Passed),
            axioms_output_hash: "0".repeat(64),
        };
        LeanVerification::build(d, &key()).unwrap()
    }

    fn verified_gate() -> GateOutcome {
        GateOutcome {
            status: GateStatus::Verified,
            reasons: vec![],
        }
    }

    #[test]
    fn build_verify_roundtrip_and_id_prefix() {
        let t = Transfer::build(draft("vlv_eeeeeeeeeeeeeeee"), &key()).unwrap();
        assert!(t.transfer_id.starts_with("vtr_"));
        t.verify().unwrap();
    }

    #[test]
    fn tampered_body_fails_t4() {
        let mut t = Transfer::build(draft("vlv_eeeeeeeeeeeeeeee"), &key()).unwrap();
        t.target_premise_digest = crate::verifier_attachment::claim_digest("a DIFFERENT premise");
        assert!(t.verify().is_err());
    }

    #[test]
    fn admits_when_all_clauses_pass() {
        let v = lean_v(true);
        let t = Transfer::build(draft(&v.verification_id), &key()).unwrap();
        let tags = DomainTags {
            source: "constant_weight_code".into(),
            target: "dna_code".into(),
        };
        let out = derive_transfer_status(&t, &verified_gate(), Some(&v), &tags);
        assert_eq!(
            out.status,
            TransferStatus::Admitted,
            "reasons: {:?}",
            out.reasons
        );
    }

    #[test]
    fn native_decide_theorem_cannot_admit() {
        let v = lean_v(false); // forbidden axiom -> Compromised integrity
        let t = Transfer::build(draft(&v.verification_id), &key()).unwrap();
        let tags = DomainTags {
            source: "constant_weight_code".into(),
            target: "dna_code".into(),
        };
        let out = derive_transfer_status(&t, &verified_gate(), Some(&v), &tags);
        assert_eq!(out.status, TransferStatus::Rejected);
    }

    #[test]
    fn refuted_source_drives_rejected() {
        let v = lean_v(true);
        let t = Transfer::build(draft(&v.verification_id), &key()).unwrap();
        let tags = DomainTags {
            source: "constant_weight_code".into(),
            target: "dna_code".into(),
        };
        let refuted = GateOutcome {
            status: GateStatus::Refuted,
            reasons: vec!["probe refuted".into()],
        };
        let out = derive_transfer_status(&t, &refuted, Some(&v), &tags);
        assert_eq!(out.status, TransferStatus::Rejected);
    }

    #[test]
    fn type_mismatch_is_not_admitted() {
        let v = lean_v(true);
        let t = Transfer::build(draft(&v.verification_id), &key()).unwrap();
        let tags = DomainTags {
            source: "sidon".into(),
            target: "dna_code".into(),
        }; // wrong source
        let out = derive_transfer_status(&t, &verified_gate(), Some(&v), &tags);
        assert_eq!(out.status, TransferStatus::NeedsVerification);
        assert!(out.reasons.iter().any(|r| r.starts_with("T3")));
    }

    #[test]
    fn unverified_source_needs_verification() {
        let v = lean_v(true);
        let t = Transfer::build(draft(&v.verification_id), &key()).unwrap();
        let tags = DomainTags {
            source: "constant_weight_code".into(),
            target: "dna_code".into(),
        };
        let needs = GateOutcome {
            status: GateStatus::NeedsVerification,
            reasons: vec![],
        };
        let out = derive_transfer_status(&t, &needs, Some(&v), &tags);
        assert_eq!(out.status, TransferStatus::NeedsVerification);
    }
}
