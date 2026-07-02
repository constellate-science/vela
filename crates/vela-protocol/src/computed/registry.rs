//! Phase S (v0.5): registry primitive — verifiable distribution.
//!
//! A registry is a directory of `RegistryEntry`s, each one a signed
//! manifest pointing at a frontier publication. Pulling a frontier
//! through a registry verifies:
//!
//! 1. The manifest signature was produced by the owner's pubkey.
//! 2. The pulled frontier's snapshot_hash matches the registered value.
//! 3. The pulled frontier's event_log_hash matches the registered value.
//!
//! Cross-frontier *links* (`vf_…@vfr_…` references) are deferred to
//! v0.6. v0.5's registry is the npm-tarball-with-a-signature shape:
//! archival, reproducibility, integrity-checked transfer between
//! collaborating institutions.
//!
//! A registry is NOT a Vela frontier (deferred to v0.6 once
//! cross-frontier semantics exist). For now it's a flat
//! `entries.json` + `pubkeys.json` pair on disk or fetched over HTTP.

use serde::{Deserialize, Serialize};
use serde_json::json;

pub const REGISTRY_SCHEMA: &str = "vela.registry.v0.1";
pub const ENTRY_SCHEMA: &str = "vela.registry-entry.v0.1";

/// A single signed publication of a frontier into a registry. The
/// `signature` is Ed25519 over the canonical preimage of the entry's
/// fields *minus* the signature itself. Two implementations agree on
/// the signing-bytes derivation by following the same canonical-JSON
/// rule already used for `vev_…`/`vpr_…`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegistryEntry {
    #[serde(default = "default_entry_schema")]
    pub schema: String,
    pub vfr_id: String,
    pub name: String,
    pub owner_actor_id: String,
    /// Hex-encoded Ed25519 public key (64 hex chars).
    pub owner_pubkey: String,
    /// SHA-256 hex of the canonical snapshot at publication time.
    pub latest_snapshot_hash: String,
    /// SHA-256 hex of the canonical event log at publication time.
    pub latest_event_log_hash: String,
    /// Where to fetch the frontier from (`file://`, `http://`, or
    /// `git+...`). v0.5 supports `file://` and bare paths; HTTP and git
    /// transports are scaffolded but unimplemented (v0.6).
    pub network_locator: String,
    /// RFC3339 timestamp of when the entry was signed.
    pub signed_publish_at: String,
    /// Hex-encoded Ed25519 signature over the canonical preimage of
    /// the entry's other fields.
    pub signature: String,
    /// v0.154: optional SPDX license identifier (e.g. `CC-BY-4.0`,
    /// `CC0-1.0`, `MIT`, `Apache-2.0`). FAIR-compliance + reuse
    /// rights for downstream consumers. Pre-v0.154 entries serialize
    /// without this field (skip_if_none). Consumer policy decides
    /// whether to accept `UNLICENSED` (i.e. `None`) entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    /// v0.711: SHA-256 hex of the content-addressed *extras manifest* — the
    /// loose `.vela/` files a snapshot+artifact-blob clone does NOT
    /// reconstruct (governance `policy/`, `releases/`, the verifier sources
    /// under `tasks/`+`workspaces/`, `evaluations/`, `tool_descriptors/`).
    /// Its presence is what lets a cold clone restore the FULL `.vela/`
    /// tree, so the hub is a complete backup and `.vela/` can become a
    /// gitignored cache. Pre-v0.711 entries serialize without it
    /// (skip_if_none) and verify byte-identically — `entry_signing_bytes`
    /// folds it into the preimage only when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extras_manifest_hash: Option<String>,
}

fn default_entry_schema() -> String {
    ENTRY_SCHEMA.to_string()
}

/// Build the canonical preimage for an entry's signature.
///
/// Excludes the `signature` field itself. Same canonical-JSON rule as
/// `event_signing_bytes` and `proposal_signing_bytes`: a second
/// implementation following only the canonical-JSON spec produces
/// byte-identical signing bytes.
/// A signed frontier-deprecation record: the registry-lifecycle analogue
/// of actor revocation. Append-only, earliest-wins, never undone — once a
/// frontier is deprecated it stays deprecated (a successor frontier is a
/// new vfr_id, not a resurrection). Only the entry's owner key can sign a
/// deprecation (the same continuity rule as re-publish).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct DeprecationRecord {
    pub schema: String,
    pub vfr_id: String,
    pub deprecated_at: String,
    pub reason: String,
    pub signature: String,
    pub signer_pubkey_hex: String,
}

pub const DEPRECATION_SCHEMA: &str = "vela.frontier-deprecation.v0.1";

pub fn deprecation_signing_bytes(rec: &DeprecationRecord) -> Result<Vec<u8>, String> {
    let preimage = serde_json::json!({
        "schema": rec.schema,
        "vfr_id": rec.vfr_id,
        "deprecated_at": rec.deprecated_at,
        "reason": rec.reason,
    });
    let body = crate::canonical::to_canonical_bytes(&preimage)?;
    Ok(crate::signing_input::signing_input(
        crate::signing_input::SigVersion::V0,
        crate::signing_input::payload_type::REGISTRY_DEPRECATION,
        &body,
    ))
}

pub fn sign_deprecation(
    rec: &DeprecationRecord,
    key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    use ed25519_dalek::Signer;
    let bytes = deprecation_signing_bytes(rec)?;
    Ok(hex::encode(key.sign(&bytes).to_bytes()))
}

pub fn verify_deprecation(rec: &DeprecationRecord) -> Result<bool, String> {
    use ed25519_dalek::Verifier;
    if rec.schema != DEPRECATION_SCHEMA {
        return Err(format!(
            "deprecation schema must be {DEPRECATION_SCHEMA}, got {}",
            rec.schema
        ));
    }
    let bytes = deprecation_signing_bytes(rec)?;
    let pk_bytes: [u8; 32] = hex::decode(&rec.signer_pubkey_hex)
        .map_err(|e| format!("pubkey hex: {e}"))?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("pubkey: {e}"))?;
    let sig_bytes: [u8; 64] = hex::decode(&rec.signature)
        .map_err(|e| format!("signature hex: {e}"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    Ok(vk.verify(&bytes, &sig).is_ok())
}

/// A signed git-remote registration: the frontier's effective owner binds a
/// git repository as the frontier's ingestion source (ADR 0001 / HUB.md: the
/// hub is an index over git-replayed state; the repo's committed
/// `.vela/events` log is the authority). This is the ONE owner-signed act in
/// the git-ingestion lane — after it, the hub re-derives the index from the
/// repo itself; the ingested state's authority is the individually signed
/// events, verified on replay, not a manifest signature.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GitRemoteRegistration {
    pub schema: String,
    pub vfr_id: String,
    /// The clone URL (https://... or git@...). Recorded verbatim.
    pub git_remote: String,
    /// Branch or ref to ingest (e.g. `main`).
    pub git_ref: String,
    /// Subdirectory holding the frontier when the repo is a multi-frontier
    /// monorepo (e.g. `frontiers/sidon-sets` in vela-frontiers). Empty for
    /// a repo whose root IS the frontier. Signed: a registration binds the
    /// exact tree the ingestor replays.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub git_subdir: String,
    pub registered_at: String,
    pub signature: String,
    pub signer_pubkey_hex: String,
}

pub const GIT_REMOTE_SCHEMA: &str = "vela.frontier-git-remote.v0.1";

pub fn git_remote_signing_bytes(rec: &GitRemoteRegistration) -> Result<Vec<u8>, String> {
    let mut preimage = serde_json::json!({
        "schema": rec.schema,
        "vfr_id": rec.vfr_id,
        "git_remote": rec.git_remote,
        "git_ref": rec.git_ref,
        "registered_at": rec.registered_at,
    });
    // Signed only when present, so pre-subdir registrations keep verifying
    // byte-identically.
    if !rec.git_subdir.is_empty() {
        preimage["git_subdir"] = serde_json::Value::String(rec.git_subdir.clone());
    }
    let body = crate::canonical::to_canonical_bytes(&preimage)?;
    Ok(crate::signing_input::signing_input(
        crate::signing_input::SigVersion::V0,
        crate::signing_input::payload_type::REGISTRY_GIT_REMOTE,
        &body,
    ))
}

pub fn sign_git_remote(
    rec: &GitRemoteRegistration,
    key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    use ed25519_dalek::Signer;
    let bytes = git_remote_signing_bytes(rec)?;
    Ok(hex::encode(key.sign(&bytes).to_bytes()))
}

pub fn verify_git_remote(rec: &GitRemoteRegistration) -> Result<bool, String> {
    use ed25519_dalek::Verifier;
    if rec.schema != GIT_REMOTE_SCHEMA {
        return Err(format!(
            "git-remote registration schema must be {GIT_REMOTE_SCHEMA}, got {}",
            rec.schema
        ));
    }
    let bytes = git_remote_signing_bytes(rec)?;
    let pk_bytes: [u8; 32] = hex::decode(&rec.signer_pubkey_hex)
        .map_err(|e| format!("pubkey hex: {e}"))?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("pubkey: {e}"))?;
    let sig_bytes: [u8; 64] = hex::decode(&rec.signature)
        .map_err(|e| format!("signature hex: {e}"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    Ok(vk.verify(&bytes, &sig).is_ok())
}

/// A signed owner-rotation record: the CURRENT owner key authorizes a
/// successor key for a frontier. Append-only — rotations chain, and the
/// effective owner at any moment is the latest rotation's successor (or
/// the original publisher if none). This is the designed key-rotation
/// path; without it, an entry published under a retired key is stuck
/// behind the owner-continuity guard forever.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OwnerRotationRecord {
    pub schema: String,
    pub vfr_id: String,
    pub new_owner_pubkey: String,
    pub rotated_at: String,
    pub reason: String,
    pub signature: String,
    pub signer_pubkey_hex: String,
}

pub const OWNER_ROTATION_SCHEMA: &str = "vela.frontier-owner-rotation.v0.1";

pub fn rotation_signing_bytes(rec: &OwnerRotationRecord) -> Result<Vec<u8>, String> {
    let preimage = serde_json::json!({
        "schema": rec.schema,
        "vfr_id": rec.vfr_id,
        "new_owner_pubkey": rec.new_owner_pubkey,
        "rotated_at": rec.rotated_at,
        "reason": rec.reason,
    });
    let body = crate::canonical::to_canonical_bytes(&preimage)?;
    Ok(crate::signing_input::signing_input(
        crate::signing_input::SigVersion::V0,
        crate::signing_input::payload_type::REGISTRY_ROTATION,
        &body,
    ))
}

pub fn sign_rotation(
    rec: &OwnerRotationRecord,
    key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    use ed25519_dalek::Signer;
    let bytes = rotation_signing_bytes(rec)?;
    Ok(hex::encode(key.sign(&bytes).to_bytes()))
}

pub fn verify_rotation(rec: &OwnerRotationRecord) -> Result<bool, String> {
    use ed25519_dalek::Verifier;
    if rec.schema != OWNER_ROTATION_SCHEMA {
        return Err(format!(
            "rotation schema must be {OWNER_ROTATION_SCHEMA}, got {}",
            rec.schema
        ));
    }
    if rec.new_owner_pubkey.len() != 64 || hex::decode(&rec.new_owner_pubkey).is_err() {
        return Err("new_owner_pubkey must be 32 bytes of hex".to_string());
    }
    let bytes = rotation_signing_bytes(rec)?;
    let pk_bytes: [u8; 32] = hex::decode(&rec.signer_pubkey_hex)
        .map_err(|e| format!("pubkey hex: {e}"))?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).map_err(|e| format!("pubkey: {e}"))?;
    let sig_bytes: [u8; 64] = hex::decode(&rec.signature)
        .map_err(|e| format!("signature hex: {e}"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    Ok(vk.verify(&bytes, &sig).is_ok())
}

/// A signed maintainer-set action: the frontier owner (or a current
/// maintainer) adds or removes a maintainer key. The effective set is
/// the latest action per pubkey — the Linux signed-tag pull model
/// applied to accept authority. Append-only, fully audited.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct MaintainerActionRecord {
    pub schema: String,
    pub vfr_id: String,
    /// "add" | "remove"
    pub action: String,
    pub maintainer_pubkey: String,
    pub authorized_at: String,
    pub reason: String,
    pub signature: String,
    pub signer_pubkey_hex: String,
}

pub const MAINTAINER_ACTION_SCHEMA: &str = "vela.frontier-maintainer.v0.1";

pub fn maintainer_signing_bytes(rec: &MaintainerActionRecord) -> Result<Vec<u8>, String> {
    let preimage = serde_json::json!({
        "schema": rec.schema,
        "vfr_id": rec.vfr_id,
        "action": rec.action,
        "maintainer_pubkey": rec.maintainer_pubkey,
        "authorized_at": rec.authorized_at,
        "reason": rec.reason,
    });
    let body = crate::canonical::to_canonical_bytes(&preimage)?;
    Ok(crate::signing_input::signing_input(
        crate::signing_input::SigVersion::V0,
        crate::signing_input::payload_type::REGISTRY_MAINTAINER,
        &body,
    ))
}

pub fn sign_maintainer_action(
    rec: &MaintainerActionRecord,
    key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    use ed25519_dalek::Signer;
    let bytes = maintainer_signing_bytes(rec)?;
    Ok(hex::encode(key.sign(&bytes).to_bytes()))
}

pub fn verify_maintainer_action(rec: &MaintainerActionRecord) -> Result<bool, String> {
    use ed25519_dalek::Verifier;
    if rec.schema != MAINTAINER_ACTION_SCHEMA {
        return Err(format!(
            "maintainer-action schema must be {MAINTAINER_ACTION_SCHEMA}, got {}",
            rec.schema
        ));
    }
    if !matches!(rec.action.as_str(), "add" | "remove") {
        return Err("action must be add|remove".to_string());
    }
    if rec.maintainer_pubkey.len() != 64 || hex::decode(&rec.maintainer_pubkey).is_err() {
        return Err("maintainer_pubkey must be 32 bytes of hex".to_string());
    }
    let bytes = maintainer_signing_bytes(rec)?;
    let pk: [u8; 32] = hex::decode(&rec.signer_pubkey_hex)
        .map_err(|e| format!("pubkey hex: {e}"))?
        .try_into()
        .map_err(|_| "pubkey must be 32 bytes".to_string())?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk).map_err(|e| format!("pubkey: {e}"))?;
    let sig: [u8; 64] = hex::decode(&rec.signature)
        .map_err(|e| format!("signature hex: {e}"))?
        .try_into()
        .map_err(|_| "signature must be 64 bytes".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig);
    Ok(vk.verify(&bytes, &sig).is_ok())
}

pub fn entry_signing_bytes(entry: &RegistryEntry) -> Result<Vec<u8>, String> {
    let mut preimage = serde_json::Map::new();
    preimage.insert("schema".into(), json!(entry.schema));
    preimage.insert("vfr_id".into(), json!(entry.vfr_id));
    preimage.insert("name".into(), json!(entry.name));
    preimage.insert("owner_actor_id".into(), json!(entry.owner_actor_id));
    preimage.insert("owner_pubkey".into(), json!(entry.owner_pubkey));
    preimage.insert(
        "latest_snapshot_hash".into(),
        json!(entry.latest_snapshot_hash),
    );
    preimage.insert(
        "latest_event_log_hash".into(),
        json!(entry.latest_event_log_hash),
    );
    preimage.insert("network_locator".into(), json!(entry.network_locator));
    preimage.insert("signed_publish_at".into(), json!(entry.signed_publish_at));
    // v0.711: fold the extras-manifest pointer into the preimage ONLY when
    // present, so pre-v0.711 entries (None) produce byte-identical signing
    // bytes and their existing signatures keep verifying.
    if let Some(h) = &entry.extras_manifest_hash {
        preimage.insert("extras_manifest_hash".into(), json!(h));
    }
    let body = crate::canonical::to_canonical_bytes(&serde_json::Value::Object(preimage))?;
    Ok(crate::signing_input::signing_input(
        crate::signing_input::SigVersion::V0,
        crate::signing_input::payload_type::REGISTRY_ENTRY,
        &body,
    ))
}

/// Sign an unsigned entry (with `signature` as empty string), returning
/// a hex-encoded Ed25519 signature.
pub fn sign_entry(
    entry: &RegistryEntry,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<String, String> {
    use ed25519_dalek::Signer;
    let bytes = entry_signing_bytes(entry)?;
    Ok(hex::encode(signing_key.sign(&bytes).to_bytes()))
}

/// Verify an entry's `signature` against `owner_pubkey`.
pub fn verify_entry(entry: &RegistryEntry) -> Result<bool, String> {
    let bytes = entry_signing_bytes(entry)?;
    crate::sign::verify_action_signature(&bytes, &entry.signature, &entry.owner_pubkey)
}

// ── Local file-backed registry ───────────────────────────────────────
