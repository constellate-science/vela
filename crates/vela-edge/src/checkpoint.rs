//! v0.147: signed registry checkpoints.
//!
//! A checkpoint is a registry operator's signed claim that at
//! sequence N the registry held exactly the given set of entries,
//! summarized by a content-addressed root over the canonical
//! entry list. Consumers verify the signature against the
//! operator's pubkey, recompute the root from the registry they
//! hold, and assert the two agree.
//!
//! Forms a chain via `previous_checkpoint`; v0.148 federation
//! cross-checks the chain across hubs.
//!
//! The root is a sha256 over canonical bytes of an alphabetically-
//! sorted list of `(vfr_id, latest_snapshot_hash,
//! latest_event_log_hash, owner_pubkey, signature)` tuples. It is
//! NOT a Merkle tree at v0.147; per-entry inclusion proofs would
//! require committing to a Merkle structure and a future cycle
//! can extend the shape if needed. The flat root is sufficient
//! for the substrate-honest "two hubs agree on registry state"
//! claim that v0.148 federation lands on.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use vela_protocol::registry::{Registry, RegistryEntry};

pub const CHECKPOINT_SCHEMA: &str = "vela.registry_checkpoint.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryCheckpoint {
    pub schema: String,
    pub checkpoint_id: String,
    pub hub_id: String,
    pub sequence: u64,
    pub entry_count: u64,
    pub registry_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_checkpoint: Option<String>,
    pub signer_pubkey: String,
    pub signature: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct CheckpointDraft {
    pub hub_id: String,
    pub sequence: u64,
    pub previous_checkpoint: Option<String>,
    pub created_at: String,
}

/// Compute the registry root: sha256 over canonical bytes of an
/// alphabetically-sorted list of `(vfr_id, latest_snapshot_hash,
/// latest_event_log_hash, owner_pubkey, signature)` tuples. Two
/// hubs that hold the same entries produce the same root.
pub fn compute_registry_root(registry: &Registry) -> Result<String, String> {
    let mut entries: Vec<&RegistryEntry> = registry.entries.iter().collect();
    entries.sort_by(|a, b| a.vfr_id.cmp(&b.vfr_id));
    let summary: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "vfr_id": e.vfr_id,
                "latest_snapshot_hash": e.latest_snapshot_hash,
                "latest_event_log_hash": e.latest_event_log_hash,
                "owner_pubkey": e.owner_pubkey,
                "signature": e.signature,
            })
        })
        .collect();
    let bytes = vela_protocol::canonical::to_canonical_bytes(&summary)
        .map_err(|e| format!("canonicalize registry summary: {e}"))?;
    let digest = Sha256::digest(&bytes);
    Ok(format!("sha256:{}", hex::encode(digest)))
}

impl RegistryCheckpoint {
    /// Build a checkpoint over a registry, signing it with the
    /// supplied hub-operator key. The signature covers the
    /// canonical preimage of the checkpoint body with
    /// `signature` and `checkpoint_id` zeroed; the
    /// `checkpoint_id` is then derived from the signed preimage
    /// (so two checkpoints with identical body + signature share
    /// the same id, and a tampered signature surfaces as a hash
    /// mismatch).
    pub fn build(
        registry: &Registry,
        draft: CheckpointDraft,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<Self, String> {
        let root = compute_registry_root(registry)?;
        let mut checkpoint = RegistryCheckpoint {
            schema: CHECKPOINT_SCHEMA.to_string(),
            checkpoint_id: String::new(),
            hub_id: draft.hub_id,
            sequence: draft.sequence,
            entry_count: registry.entries.len() as u64,
            registry_root: root,
            previous_checkpoint: draft.previous_checkpoint,
            signer_pubkey: hex::encode(signing_key.verifying_key().to_bytes()),
            signature: String::new(),
            created_at: draft.created_at,
        };
        let preimage = checkpoint.preimage_bytes()?;
        use ed25519_dalek::Signer;
        let sig = signing_key.sign(&preimage);
        checkpoint.signature = hex::encode(sig.to_bytes());
        checkpoint.checkpoint_id = checkpoint.derive_id()?;
        Ok(checkpoint)
    }

    /// Canonical preimage bytes for the signature. Excludes
    /// `signature` and `checkpoint_id` so the preimage is
    /// derivable from the rest of the body alone.
    pub fn preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut preimage = self.clone();
        preimage.signature = String::new();
        preimage.checkpoint_id = String::new();
        vela_protocol::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize checkpoint preimage: {e}"))
    }

    /// Content-addressed id over the (signed) body, including the
    /// signature so a tampered signature surfaces as an id
    /// mismatch.
    pub fn derive_id(&self) -> Result<String, String> {
        let mut preimage = self.clone();
        preimage.checkpoint_id = String::new();
        let bytes = vela_protocol::canonical::to_canonical_bytes(&preimage)
            .map_err(|e| format!("canonicalize checkpoint id preimage: {e}"))?;
        let digest = Sha256::digest(&bytes);
        Ok(format!("vrc_{}", &hex::encode(digest)[..16]))
    }

    /// Verify the checkpoint: re-derive the id and assert match,
    /// re-compute the registry root and assert match, verify the
    /// Ed25519 signature against `signer_pubkey`.
    pub fn verify(&self, registry: &Registry) -> Result<(), String> {
        if self.schema != CHECKPOINT_SCHEMA {
            return Err(format!(
                "checkpoint.schema must be `{CHECKPOINT_SCHEMA}`, got `{}`",
                self.schema
            ));
        }
        let derived_id = self.derive_id()?;
        if derived_id != self.checkpoint_id {
            return Err(format!(
                "checkpoint_id mismatch: stored `{}`, derived `{}`",
                self.checkpoint_id, derived_id
            ));
        }
        let derived_root = compute_registry_root(registry)?;
        if derived_root != self.registry_root {
            return Err(format!(
                "registry_root mismatch: checkpoint claims `{}`, registry hashes to `{}`",
                self.registry_root, derived_root
            ));
        }
        if self.entry_count != registry.entries.len() as u64 {
            return Err(format!(
                "entry_count mismatch: checkpoint claims {}, registry has {}",
                self.entry_count,
                registry.entries.len()
            ));
        }
        let pk_bytes =
            hex::decode(&self.signer_pubkey).map_err(|e| format!("signer_pubkey not hex: {e}"))?;
        if pk_bytes.len() != 32 {
            return Err(format!(
                "signer_pubkey must be 32 bytes (got {})",
                pk_bytes.len()
            ));
        }
        let pk = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes
                .as_slice()
                .try_into()
                .map_err(|e| format!("signer_pubkey: {e}"))?,
        )
        .map_err(|e| format!("signer_pubkey malformed: {e}"))?;
        let sig_bytes =
            hex::decode(&self.signature).map_err(|e| format!("signature not hex: {e}"))?;
        if sig_bytes.len() != 64 {
            return Err(format!(
                "signature must be 64 bytes (got {})",
                sig_bytes.len()
            ));
        }
        let sig = ed25519_dalek::Signature::from_bytes(
            sig_bytes
                .as_slice()
                .try_into()
                .map_err(|e| format!("signature: {e}"))?,
        );
        let preimage = self.preimage_bytes()?;
        use ed25519_dalek::Verifier;
        pk.verify(&preimage, &sig)
            .map_err(|e| format!("checkpoint signature does not verify: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::registry::{ENTRY_SCHEMA, Registry, RegistryEntry};

    fn make_entry(vfr: &str) -> RegistryEntry {
        RegistryEntry {
            schema: ENTRY_SCHEMA.to_string(),
            vfr_id: vfr.to_string(),
            name: format!("{vfr}-name"),
            owner_actor_id: "owner".to_string(),
            owner_pubkey: "0".repeat(64),
            latest_snapshot_hash: format!("snap-{vfr}"),
            latest_event_log_hash: format!("log-{vfr}"),
            network_locator: format!("file:///{vfr}"),
            license: None,
            signed_publish_at: "2026-05-11T00:00:00+00:00".to_string(),
            signature: "f".repeat(128),
        }
    }

    fn make_registry(vfrs: &[&str]) -> Registry {
        Registry {
            schema: "vela.registry.v0.1".to_string(),
            entries: vfrs.iter().map(|v| make_entry(v)).collect(),
        }
    }

    fn make_key() -> ed25519_dalek::SigningKey {
        use rand::rngs::OsRng;
        ed25519_dalek::SigningKey::generate(&mut OsRng)
    }

    #[test]
    fn registry_root_deterministic_over_same_state() {
        let r = make_registry(&["vfr_a", "vfr_b"]);
        let a = compute_registry_root(&r).unwrap();
        let b = compute_registry_root(&r).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn registry_root_independent_of_entry_order() {
        let r1 = make_registry(&["vfr_a", "vfr_b", "vfr_c"]);
        let r2 = make_registry(&["vfr_c", "vfr_a", "vfr_b"]);
        let a = compute_registry_root(&r1).unwrap();
        let b = compute_registry_root(&r2).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn registry_root_changes_with_entry_set() {
        let r1 = make_registry(&["vfr_a", "vfr_b"]);
        let r2 = make_registry(&["vfr_a", "vfr_c"]);
        let a = compute_registry_root(&r1).unwrap();
        let b = compute_registry_root(&r2).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn checkpoint_roundtrips() {
        let r = make_registry(&["vfr_a", "vfr_b"]);
        let sk = make_key();
        let cp = RegistryCheckpoint::build(
            &r,
            CheckpointDraft {
                hub_id: "hub:test".to_string(),
                sequence: 1,
                previous_checkpoint: None,
                created_at: "2026-05-11T00:00:00+00:00".to_string(),
            },
            &sk,
        )
        .unwrap();
        assert!(cp.checkpoint_id.starts_with("vrc_"));
        assert_eq!(cp.entry_count, 2);
        cp.verify(&r).unwrap();
    }

    #[test]
    fn checkpoint_fails_against_tampered_registry() {
        let r1 = make_registry(&["vfr_a", "vfr_b"]);
        let r2 = make_registry(&["vfr_a", "vfr_c"]);
        let sk = make_key();
        let cp = RegistryCheckpoint::build(
            &r1,
            CheckpointDraft {
                hub_id: "hub:test".to_string(),
                sequence: 1,
                previous_checkpoint: None,
                created_at: "2026-05-11T00:00:00+00:00".to_string(),
            },
            &sk,
        )
        .unwrap();
        let err = cp.verify(&r2).unwrap_err();
        assert!(err.contains("registry_root"), "got: {err}");
    }

    #[test]
    fn checkpoint_fails_with_tampered_signature() {
        let r = make_registry(&["vfr_a"]);
        let sk = make_key();
        let mut cp = RegistryCheckpoint::build(
            &r,
            CheckpointDraft {
                hub_id: "hub:test".to_string(),
                sequence: 1,
                previous_checkpoint: None,
                created_at: "2026-05-11T00:00:00+00:00".to_string(),
            },
            &sk,
        )
        .unwrap();
        cp.signature = "0".repeat(128);
        let err = cp.verify(&r).unwrap_err();
        assert!(
            err.contains("mismatch") || err.contains("does not verify"),
            "got: {err}"
        );
    }
}
