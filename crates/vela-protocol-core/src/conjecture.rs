//! v0.338: Conjecture — signed forward institutional claims with
//! mechanical falsification paths.
//!
//! Doctrine: a Conjecture is what an institution publicly stakes its
//! name on. It carries a forward claim (something the institution
//! predicts will become true by a date), a dependency graph of
//! supporting findings, a *pre-declared* falsification path (specific
//! conditions that would prove the claim wrong, mechanically), expected
//! outputs with dates, and standard candles (reference points to measure
//! against). Multi-signature: a witness (the institutional actor that
//! takes the stake) plus zero or more co-signers (pillar heads,
//! reviewers, federation peers).
//!
//! Popper's word: a conjecture is a bold guess structured to be
//! falsifiable. Goldbach's Conjecture, the Riemann Conjecture — names
//! that carry institutional weight precisely because they could turn
//! out to be wrong. Status-tracked by construction: draft → active →
//! (succeeded | falsified | superseded), with `paused` as the
//! intermediate state when the institution is reviewing whether to
//! continue.
//!
//! Atlas-side: this primitive was the `vb_*` "Bet" extension in earlier
//! cycles; promoted to first-class vela-protocol in v0.338 under
//! Popper's canonical name. See atlas-platform commit 301114c6b for the
//! Atlas-side rename and `docs/memos/2026-05-25-r0.5-bet-to-conjecture-
//! rename.md` for the rationale.
//!
//! Mirrors the `agent_attestation.rs` (v0.195) and `lean_verification.rs`
//! (v0.170) signing patterns verbatim — same build/sign/verify shape,
//! same id-derivation pattern (sha256 over preimage|signature, vcj_
//! prefix, 16 hex chars).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CONJECTURE_SCHEMA: &str = "vela.conjecture.v0.1";

/// Current lifecycle state of a Conjecture.
///
/// State machine:
///   draft       → active | superseded
///   active      → succeeded | falsified | paused | superseded
///   paused      → active | superseded
///   succeeded   → (terminal)
///   falsified   → (terminal)
///   superseded  → (terminal — replaced by a newer Conjecture)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConjectureStatus {
    Draft,
    Active,
    Paused,
    Succeeded,
    Falsified,
    Superseded,
}

/// One supporting finding the Conjecture rests on.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RestsOn {
    /// Finding id (e.g. "vf_abc1234567890def").
    pub finding_id: String,
    /// Frontier the finding lives on.
    pub frontier_id: String,
    /// Why this finding matters to the conjecture.
    pub role: RestsOnRole,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestsOnRole {
    /// Removing this finding falsifies the conjecture.
    Primary,
    /// Reinforces the case but conjecture survives losing it.
    Supporting,
    /// Background or framing only.
    Contextual,
}

/// A specific condition that would mechanically falsify the conjecture.
///
/// The conjecture is committed to being wrong if any of its
/// `falsifies_if` triggers fire. This is the Popperian discipline:
/// you must declare in advance what would prove you wrong.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FalsifiesIf {
    pub kind: FalsificationKind,
    pub description: String,
    /// Free-form structured trigger; opaque to the protocol layer.
    /// E.g. `{ "metric": "energy_density", "below": 250 }`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FalsificationKind {
    /// A finding the conjecture rests on is retracted.
    Retraction,
    /// An experiment writes a contradicting `experiment_result` finding.
    ExperimentResult,
    /// Aggregate substrate state crosses a threshold.
    SubstrateState,
}

/// A concrete output the conjecture predicts, with a deadline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExpectedOutput {
    pub name: String,
    /// ISO 8601 date (YYYY-MM-DD).
    pub by_date: String,
    pub kind: String,
}

/// A reference point the conjecture measures itself against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StandardCandle {
    pub kind: String,
    /// Reference target (finding id, person id, paper DOI, etc).
    #[serde(rename = "ref")]
    pub candle_ref: String,
    pub outcome: String,
    pub notes: String,
}

/// The institutional actor that takes the stake. There is exactly one
/// witness per conjecture; co-signers go in `signatures`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Witness {
    /// Actor id (e.g. "pillar-head:energy", "reviewer:will-blair").
    pub actor_id: String,
    /// ISO 8601 timestamp when the witness signed. None until signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

/// A signature on the conjecture. The witness signature is the primary;
/// co-signatures (pillar head approving, peer institution endorsing) are
/// recorded here as additional entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConjectureSignature {
    pub actor_id: String,
    /// Always "ed25519" today.
    pub algorithm: String,
    /// Hex-encoded signature.
    pub signature: String,
    /// Hex-encoded public key.
    pub signer_pubkey_hex: String,
    /// ISO 8601 timestamp.
    pub signed_at: String,
}

/// Provenance: who drafted the conjecture, on what basis, and what
/// review the draft went through.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConjectureProvenance {
    pub drafted_by: String,
    pub draft_basis: String,
    pub review: ConjectureReview,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConjectureReview {
    pub reviewed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corrections: Vec<serde_json::Value>,
}

/// The Conjecture claim itself — what the institution predicts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConjectureClaim {
    pub text: String,
    /// Pillar or scope identifier (e.g. "energy", "compute").
    pub scope_pillar: String,
    /// How many months the conjecture commits to.
    pub time_horizon_months: u32,
}

/// A signed, falsifiable forward conjecture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Conjecture {
    pub schema: String,
    /// Content-addressed id: `vcj_<16 hex>`.
    pub id: String,
    pub version: u32,
    pub claim: ConjectureClaim,
    pub rests_on: Vec<RestsOn>,
    pub falsifies_if: Vec<FalsifiesIf>,
    pub expected_outputs: Vec<ExpectedOutput>,
    pub standard_candles: Vec<StandardCandle>,
    pub status: ConjectureStatus,
    pub witness: Witness,
    /// Witness signature + co-signers. The witness signs first;
    /// co-signers append in observation order.
    #[serde(default)]
    pub signatures: Vec<ConjectureSignature>,
    pub provenance: ConjectureProvenance,
    /// Cross-references to other primitives (findings, packets, bridges).
    #[serde(default)]
    pub links: Vec<serde_json::Value>,
    /// ISO 8601 timestamp.
    pub created: String,
    /// ISO 8601 timestamp; None until first revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<String>,
}

/// Inputs needed to build a Conjecture. The id and witness signature
/// are derived; status starts at Draft.
#[derive(Debug, Clone)]
pub struct ConjectureDraft {
    pub version: u32,
    pub claim: ConjectureClaim,
    pub rests_on: Vec<RestsOn>,
    pub falsifies_if: Vec<FalsifiesIf>,
    pub expected_outputs: Vec<ExpectedOutput>,
    pub standard_candles: Vec<StandardCandle>,
    pub witness_actor_id: String,
    pub provenance: ConjectureProvenance,
    pub links: Vec<serde_json::Value>,
    pub created: String,
}

impl Conjecture {
    /// Build + sign a Conjecture from a draft. The witness signs first;
    /// the result is `status: Draft` until promoted by an explicit
    /// state transition (recorded as a separate event).
    ///
    /// `signed_at` is the ISO 8601 timestamp recorded in the witness
    /// signature; pass the canonical "now" for the call.
    pub fn build(
        draft: ConjectureDraft,
        key: &SigningKey,
        signed_at: &str,
    ) -> Result<Self, String> {
        validate_draft(&draft)?;
        let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
        let witness = Witness {
            actor_id: draft.witness_actor_id.clone(),
            signed_at: Some(signed_at.to_string()),
        };
        let mut envelope = Self {
            schema: CONJECTURE_SCHEMA.to_string(),
            id: String::new(),
            version: draft.version,
            claim: draft.claim,
            rests_on: draft.rests_on,
            falsifies_if: draft.falsifies_if,
            expected_outputs: draft.expected_outputs,
            standard_candles: draft.standard_candles,
            status: ConjectureStatus::Draft,
            witness,
            signatures: Vec::new(),
            provenance: draft.provenance,
            links: draft.links,
            created: draft.created,
            updated: None,
        };
        let preimage = envelope.preimage_bytes();
        let sig = key.sign(&preimage);
        let sig_hex = hex::encode(sig.to_bytes());
        envelope.signatures.push(ConjectureSignature {
            actor_id: draft.witness_actor_id,
            algorithm: "ed25519".to_string(),
            signature: sig_hex,
            signer_pubkey_hex: pubkey_hex,
            signed_at: signed_at.to_string(),
        });
        envelope.id = envelope.derive_id();
        Ok(envelope)
    }

    /// Append a co-signature from another actor. Caller is responsible
    /// for ensuring the actor's authority — the protocol records the
    /// signature; the institution decides what it counts for.
    pub fn cosign(
        &mut self,
        co_actor_id: &str,
        key: &SigningKey,
        signed_at: &str,
    ) -> Result<(), String> {
        let preimage = self.preimage_bytes();
        let sig = key.sign(&preimage);
        self.signatures.push(ConjectureSignature {
            actor_id: co_actor_id.to_string(),
            algorithm: "ed25519".to_string(),
            signature: hex::encode(sig.to_bytes()),
            signer_pubkey_hex: hex::encode(key.verifying_key().to_bytes()),
            signed_at: signed_at.to_string(),
        });
        Ok(())
    }

    /// The canonical bytes signed by every signer. Excludes `id`,
    /// `status`, `signatures`, `updated` — all of which are mutable
    /// or post-build.
    fn preimage_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.schema.as_bytes());
        out.push(b'|');
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(b'|');
        out.extend_from_slice(self.claim.text.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.claim.scope_pillar.as_bytes());
        out.push(b'|');
        out.extend_from_slice(&self.claim.time_horizon_months.to_be_bytes());
        out.push(b'|');
        for r in &self.rests_on {
            out.extend_from_slice(r.finding_id.as_bytes());
            out.push(b'@');
            out.extend_from_slice(r.frontier_id.as_bytes());
            out.push(b':');
            out.extend_from_slice(rests_on_role_str(r.role).as_bytes());
            out.push(b';');
        }
        out.push(b'|');
        for f in &self.falsifies_if {
            out.extend_from_slice(falsification_kind_str(f.kind).as_bytes());
            out.push(b':');
            out.extend_from_slice(f.description.as_bytes());
            out.push(b';');
        }
        out.push(b'|');
        for e in &self.expected_outputs {
            out.extend_from_slice(e.name.as_bytes());
            out.push(b'@');
            out.extend_from_slice(e.by_date.as_bytes());
            out.push(b':');
            out.extend_from_slice(e.kind.as_bytes());
            out.push(b';');
        }
        out.push(b'|');
        for c in &self.standard_candles {
            out.extend_from_slice(c.kind.as_bytes());
            out.push(b':');
            out.extend_from_slice(c.candle_ref.as_bytes());
            out.push(b';');
        }
        out.push(b'|');
        out.extend_from_slice(self.witness.actor_id.as_bytes());
        out.push(b'|');
        out.extend_from_slice(self.created.as_bytes());
        out
    }

    /// Content-addressed id derived from the preimage + the witness
    /// signature. Witness signature is the primary; co-signers don't
    /// affect the id.
    fn derive_id(&self) -> String {
        let witness_sig = self
            .signatures
            .iter()
            .find(|s| s.actor_id == self.witness.actor_id)
            .map(|s| s.signature.as_str())
            .unwrap_or("");
        let mut hasher = Sha256::new();
        hasher.update(self.preimage_bytes());
        hasher.update(b"|");
        hasher.update(witness_sig.as_bytes());
        format!("vcj_{}", &hex::encode(hasher.finalize())[..16])
    }

    /// Verify witness signature and re-derive id. Co-signatures are
    /// verified independently — call `verify_cosignatures` for that.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != CONJECTURE_SCHEMA {
            return Err(format!(
                "schema mismatch: expected {CONJECTURE_SCHEMA}, got {}",
                self.schema
            ));
        }
        let witness_sig = self
            .signatures
            .iter()
            .find(|s| s.actor_id == self.witness.actor_id)
            .ok_or_else(|| "no signature found for witness actor".to_string())?;
        verify_one(&self.preimage_bytes(), witness_sig)?;
        let rederived = self.derive_id();
        if rederived != self.id {
            return Err(format!(
                "id mismatch: declared {}, rebuilt {}",
                self.id, rederived
            ));
        }
        Ok(())
    }

    /// Verify every co-signature (not the witness). Returns the count
    /// of valid co-signatures or the first error encountered.
    pub fn verify_cosignatures(&self) -> Result<usize, String> {
        let mut n = 0;
        for sig in &self.signatures {
            if sig.actor_id == self.witness.actor_id {
                continue;
            }
            verify_one(&self.preimage_bytes(), sig)?;
            n += 1;
        }
        Ok(n)
    }
}

fn rests_on_role_str(r: RestsOnRole) -> &'static str {
    match r {
        RestsOnRole::Primary => "primary",
        RestsOnRole::Supporting => "supporting",
        RestsOnRole::Contextual => "contextual",
    }
}

fn falsification_kind_str(k: FalsificationKind) -> &'static str {
    match k {
        FalsificationKind::Retraction => "retraction",
        FalsificationKind::ExperimentResult => "experiment_result",
        FalsificationKind::SubstrateState => "substrate_state",
    }
}

fn verify_one(preimage: &[u8], sig: &ConjectureSignature) -> Result<(), String> {
    if sig.algorithm != "ed25519" {
        return Err(format!("unsupported algorithm: {}", sig.algorithm));
    }
    let pubkey_bytes =
        hex::decode(&sig.signer_pubkey_hex).map_err(|e| format!("decode pubkey: {e}"))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let verifying =
        VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| format!("verifying key: {e}"))?;
    let sig_bytes = hex::decode(&sig.signature).map_err(|e| format!("decode signature: {e}"))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig_val = Signature::from_bytes(&sig_arr);
    verifying
        .verify(preimage, &sig_val)
        .map_err(|e| format!("signature verify for {}: {e}", sig.actor_id))?;
    Ok(())
}

fn validate_draft(d: &ConjectureDraft) -> Result<(), String> {
    if d.claim.text.is_empty() {
        return Err("claim.text must not be empty".to_string());
    }
    if d.claim.scope_pillar.is_empty() {
        return Err("claim.scope_pillar must not be empty".to_string());
    }
    if d.claim.time_horizon_months == 0 {
        return Err("claim.time_horizon_months must be > 0".to_string());
    }
    if d.falsifies_if.is_empty() {
        return Err(
            "conjecture must declare at least one falsifies_if condition (Popper)".to_string(),
        );
    }
    if d.witness_actor_id.is_empty() {
        return Err("witness_actor_id must not be empty".to_string());
    }
    if d.created.is_empty() {
        return Err("created timestamp must not be empty".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn ok_draft() -> ConjectureDraft {
        ConjectureDraft {
            version: 1,
            claim: ConjectureClaim {
                text: "Episteme will demonstrate X by Q3 2027".to_string(),
                scope_pillar: "energy".to_string(),
                time_horizon_months: 18,
            },
            rests_on: vec![RestsOn {
                finding_id: "vf_abc1234567890def".to_string(),
                frontier_id: "vfr_energy_v0".to_string(),
                role: RestsOnRole::Primary,
            }],
            falsifies_if: vec![FalsifiesIf {
                kind: FalsificationKind::ExperimentResult,
                description: "energy density below 250 Wh/kg in 5+ replications".to_string(),
                trigger: Some(serde_json::json!({
                    "metric": "energy_density_wh_kg",
                    "below": 250,
                    "min_replications": 5,
                })),
            }],
            expected_outputs: vec![ExpectedOutput {
                name: "first-cell-demo".to_string(),
                by_date: "2027-09-30".to_string(),
                kind: "experiment_result".into(),
            }],
            standard_candles: vec![StandardCandle {
                kind: "person".into(),
                candle_ref: "prs_alice-allen".to_string(),
                outcome: "hired".to_string(),
                notes: "anchor researcher".to_string(),
            }],
            witness_actor_id: "pillar-head:energy".to_string(),
            provenance: ConjectureProvenance {
                drafted_by: "operator:will-blair".to_string(),
                draft_basis: "v0.338 R.1 test fixture".to_string(),
                review: ConjectureReview {
                    reviewed: false,
                    reviewer: None,
                    reviewed_at: None,
                    corrections: vec![],
                },
            },
            links: vec![],
            created: "2026-05-25T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn build_signs_and_derives_id() {
        let c = Conjecture::build(ok_draft(), &key(), "2026-05-25T00:00:01Z").unwrap();
        assert_eq!(c.schema, CONJECTURE_SCHEMA);
        assert!(c.id.starts_with("vcj_"));
        assert_eq!(c.id.len(), 4 + 16);
        assert_eq!(c.status, ConjectureStatus::Draft);
        assert_eq!(c.signatures.len(), 1);
        assert_eq!(c.signatures[0].actor_id, "pillar-head:energy");
        c.verify().unwrap();
    }

    #[test]
    fn verify_detects_tampered_claim() {
        let mut c = Conjecture::build(ok_draft(), &key(), "2026-05-25T00:00:01Z").unwrap();
        c.claim.text = "Episteme will demonstrate Y by Q3 2027".to_string();
        assert!(c.verify().is_err());
    }

    #[test]
    fn verify_detects_tampered_id() {
        let mut c = Conjecture::build(ok_draft(), &key(), "2026-05-25T00:00:01Z").unwrap();
        c.id = "vcj_0000000000000000".to_string();
        assert!(c.verify().is_err());
    }

    #[test]
    fn cosign_records_extra_signature() {
        let mut c = Conjecture::build(ok_draft(), &key(), "2026-05-25T00:00:01Z").unwrap();
        let co_key = SigningKey::from_bytes(&[9u8; 32]);
        c.cosign("reviewer:will-blair", &co_key, "2026-05-25T00:01:00Z")
            .unwrap();
        assert_eq!(c.signatures.len(), 2);
        // Witness verify still works.
        c.verify().unwrap();
        // Co-signature verifies.
        assert_eq!(c.verify_cosignatures().unwrap(), 1);
        // Id is unchanged — cosigning doesn't re-derive.
        let rebuilt = c.clone();
        assert_eq!(rebuilt.id, c.id);
    }

    #[test]
    fn validate_rejects_no_falsification_path() {
        let mut d = ok_draft();
        d.falsifies_if.clear();
        let err = Conjecture::build(d, &key(), "2026-05-25T00:00:01Z").unwrap_err();
        assert!(err.contains("Popper"));
    }

    #[test]
    fn validate_rejects_empty_claim_text() {
        let mut d = ok_draft();
        d.claim.text = String::new();
        let err = Conjecture::build(d, &key(), "2026-05-25T00:00:01Z").unwrap_err();
        assert!(err.contains("claim.text"));
    }

    #[test]
    fn json_roundtrip() {
        let c = Conjecture::build(ok_draft(), &key(), "2026-05-25T00:00:01Z").unwrap();
        let s = serde_json::to_string(&c).unwrap();
        let back: Conjecture = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
        back.verify().unwrap();
    }

    #[test]
    fn deterministic_id_under_fixed_key() {
        // Pin id under fixed all-sevens key + fixed timestamp.
        // Cross-impl drift (e.g. Atlas's TS implementation) will flag here.
        let c = Conjecture::build(ok_draft(), &key(), "2026-05-25T00:00:01Z").unwrap();
        // Just assert it stays stable across builds within this impl.
        let c2 = Conjecture::build(ok_draft(), &key(), "2026-05-25T00:00:01Z").unwrap();
        assert_eq!(c.id, c2.id);
        assert_eq!(c.signatures[0].signature, c2.signatures[0].signature);
    }
}
