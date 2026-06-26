//! The transfer registry: a derived, lane-organized index over the accepted
//! cross-domain transfers (`vtr_`).
//!
//! Each `vtr_` ([`Transfer`]) is one signed verifier-preserving link A → B.
//! Scattered as witness files they are hard to read as a whole; this folds them
//! into one map: the lanes (certified / target-checked / exploratory, per
//! `docs/THEORY.md Appendix C §7`), the domain pairs they connect, and per link the
//! proof roots and the structural check. It is a pure projection (the
//! loader=reducer doctrine, like the frontier map): it RECORDS and INDEXES what
//! exists. It does NOT re-verify the link (that is [`Transfer::verify`]) and
//! does NOT decide admission (that is `derive_transfer_status`, which needs the
//! live gate). The core fold is written over `&[Transfer]` so it is unit-testable
//! without touching the on-disk witnesses; the CLI loads the files and calls it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::transfer::{Transfer, TransferKind};

pub const TRANSFER_REGISTRY_SCHEMA: &str = "vela.transfer-registry.v0.1";

/// The transfer-calculus lane (`docs/THEORY.md Appendix C §7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferLane {
    /// Verifier-preservation proof OR exact-checker certificate. State-bearing:
    /// composes inside the verifier-preserving category.
    Certified,
    /// The source proposes the target; source verification does NOT imply target
    /// verification (a target receipt is required). E.g. a neural operator or an
    /// algorithm candidate.
    TargetChecked,
    /// A hypothesis or analogy. No state effect.
    Exploratory,
}

/// The lane a transfer occupies, derived from its homomorphism kind. Both shipped
/// kinds carry a soundness artifact (a Lean verifier-homomorphism or a frozen
/// verifier), so they are certified. The target-checked and exploratory lanes are
/// represented for the records that will carry them, but no `vtr_` kind mints them
/// today, so the registry honestly reports them as empty until one does.
pub fn lane_of(t: &Transfer) -> TransferLane {
    match t.homomorphism.kind {
        TransferKind::LeanHomomorphism | TransferKind::FrozenVerifier => TransferLane::Certified,
    }
}

/// One row of the registry: the link, its lane, the proof roots it stands on, and
/// its structural integrity. Derived from a [`Transfer`]; nothing here is a stored
/// verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    pub transfer_id: String,
    pub lane: TransferLane,
    pub source_claim: String,
    pub target_claim: String,
    pub source_type: String,
    pub target_type: String,
    /// `"constant_weight_code → dna_code"` — the domain pair, the grouping key.
    pub domain_pair: String,
    pub kind: TransferKind,
    /// The map decl (a Lean decl or a verifier id) — the link's implementation.
    pub map_decl: String,
    /// The `vlv_` Lean verification of the transfer theorem (empty for a frozen
    /// verifier).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub theorem_verification: String,
    /// The Theorem-23-family id in the lean-anchors registry, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub theorem_id: Option<u32>,
    /// Structural integrity: `vtr_` id re-derivation + Ed25519 signature
    /// ([`Transfer::verify`]). NOT the admission gate.
    pub structural_ok: bool,
    /// Why `structural_ok` is false, when it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structural_error: Option<String>,
}

/// Per-lane counts over the registry.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneCounts {
    pub certified: usize,
    pub target_checked: usize,
    pub exploratory: usize,
}

/// The registry: a projection over the transfers it was built from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRegistry {
    pub schema: String,
    pub total: usize,
    /// How many of `total` pass the structural check.
    pub structural_ok: usize,
    pub lanes: LaneCounts,
    /// `domain_pair` → the `vtr_` ids connecting it, sorted — the cross-domain
    /// links grouped by what they connect.
    pub by_domain_pair: BTreeMap<String, Vec<String>>,
    /// One row per transfer, sorted by domain pair then id.
    pub records: Vec<TransferRecord>,
}

fn record_of(t: &Transfer) -> TransferRecord {
    let h = &t.homomorphism;
    let (structural_ok, structural_error) = match t.verify() {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    };
    TransferRecord {
        transfer_id: t.transfer_id.clone(),
        lane: lane_of(t),
        source_claim: t.source_claim.clone(),
        target_claim: t.target_claim.clone(),
        source_type: h.source_type.clone(),
        target_type: h.target_type.clone(),
        domain_pair: format!("{} → {}", h.source_type, h.target_type),
        kind: h.kind.clone(),
        map_decl: h.map_decl.clone(),
        theorem_verification: h.theorem_verification.clone(),
        theorem_id: h.theorem_id,
        structural_ok,
        structural_error,
    }
}

/// Fold a set of transfers into the registry projection. Deduplicates by
/// `transfer_id` (a content address, so duplicates are identical), sorts
/// deterministically. Pure: no I/O, no gate, no network.
pub fn build_registry(transfers: &[Transfer]) -> TransferRegistry {
    let mut by_id: BTreeMap<String, TransferRecord> = BTreeMap::new();
    for t in transfers {
        by_id.insert(t.transfer_id.clone(), record_of(t));
    }
    let mut records: Vec<TransferRecord> = by_id.into_values().collect();
    records.sort_by(|a, b| {
        a.domain_pair
            .cmp(&b.domain_pair)
            .then(a.transfer_id.cmp(&b.transfer_id))
    });

    let mut lanes = LaneCounts::default();
    let mut by_domain_pair: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut structural_ok = 0usize;
    for r in &records {
        match r.lane {
            TransferLane::Certified => lanes.certified += 1,
            TransferLane::TargetChecked => lanes.target_checked += 1,
            TransferLane::Exploratory => lanes.exploratory += 1,
        }
        if r.structural_ok {
            structural_ok += 1;
        }
        by_domain_pair
            .entry(r.domain_pair.clone())
            .or_default()
            .push(r.transfer_id.clone());
    }

    TransferRegistry {
        schema: TRANSFER_REGISTRY_SCHEMA.to_string(),
        total: records.len(),
        structural_ok,
        lanes,
        by_domain_pair,
        records,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::{HomomorphismDescriptor, TransferDraft};
    use ed25519_dalek::SigningKey;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn transfer(src_type: &str, tgt_type: &str, src: &str, tgt: &str) -> Transfer {
        let draft = TransferDraft {
            source_claim: src.to_string(),
            source_claim_digest: "0".repeat(16),
            source_gate_status_claimed: String::new(),
            source_attachments: vec![],
            target_claim: tgt.to_string(),
            target_premise_digest: "1".repeat(16),
            homomorphism: HomomorphismDescriptor {
                kind: TransferKind::LeanHomomorphism,
                map_decl: format!("Vela.Transfer{src_type}to{tgt_type}.map"),
                source_type: src_type.to_string(),
                target_type: tgt_type.to_string(),
                theorem_verification: format!("vlv_{}", "a".repeat(16)),
                theorem_id: Some(35),
            },
            provenance: Default::default(),
            note: String::new(),
        };
        Transfer::build(draft, &key()).expect("build transfer")
    }

    #[test]
    fn folds_lanes_pairs_and_structural_check() {
        let a = transfer("cwc", "dna", "vat_cwc_1", "vfr_dna_1");
        let b = transfer("sidon", "golomb", "vf_sidon_1", "vfr_golomb_1");
        let reg = build_registry(&[a.clone(), b]);
        assert_eq!(reg.total, 2);
        assert_eq!(reg.lanes.certified, 2);
        assert_eq!(reg.lanes.target_checked, 0);
        assert_eq!(reg.structural_ok, 2, "freshly built transfers verify");
        assert!(reg.by_domain_pair.contains_key("cwc → dna"));
        assert!(reg.by_domain_pair.contains_key("sidon → golomb"));
        // records are sorted by domain pair
        assert_eq!(reg.records[0].domain_pair, "cwc → dna");
        assert_eq!(reg.records[0].theorem_id, Some(35));
    }

    #[test]
    fn dedupes_by_content_address() {
        let a = transfer("cwc", "dna", "vat_cwc_1", "vfr_dna_1");
        let reg = build_registry(&[a.clone(), a]);
        assert_eq!(reg.total, 1, "same vtr_ id folds once");
    }

    #[test]
    fn flags_tampered_transfer_without_failing_the_fold() {
        let mut a = transfer("cwc", "dna", "vat_cwc_1", "vfr_dna_1");
        a.source_claim = "vat_TAMPERED".to_string(); // id no longer re-derives
        let reg = build_registry(&[a]);
        assert_eq!(reg.total, 1);
        assert_eq!(reg.structural_ok, 0);
        assert!(reg.records[0].structural_error.is_some());
    }
}
