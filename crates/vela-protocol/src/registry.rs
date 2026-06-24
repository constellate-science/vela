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

use std::path::{Path, PathBuf};

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
}

fn default_entry_schema() -> String {
    ENTRY_SCHEMA.to_string()
}

/// On-disk registry shape: a JSON file containing the schema marker
/// and an array of entries. Multiple publications of the same `vfr_id`
/// are appended; readers select the latest by `signed_publish_at`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    #[serde(default = "default_registry_schema")]
    pub schema: String,
    #[serde(default)]
    pub entries: Vec<RegistryEntry>,
}

fn default_registry_schema() -> String {
    REGISTRY_SCHEMA.to_string()
}

impl Default for Registry {
    fn default() -> Self {
        Self {
            schema: REGISTRY_SCHEMA.to_string(),
            entries: Vec::new(),
        }
    }
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
    crate::canonical::to_canonical_bytes(&preimage)
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
    crate::canonical::to_canonical_bytes(&preimage)
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
    crate::canonical::to_canonical_bytes(&preimage)
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
    let preimage = json!({
        "schema": entry.schema,
        "vfr_id": entry.vfr_id,
        "name": entry.name,
        "owner_actor_id": entry.owner_actor_id,
        "owner_pubkey": entry.owner_pubkey,
        "latest_snapshot_hash": entry.latest_snapshot_hash,
        "latest_event_log_hash": entry.latest_event_log_hash,
        "network_locator": entry.network_locator,
        "signed_publish_at": entry.signed_publish_at,
    });
    crate::canonical::to_canonical_bytes(&preimage)
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

/// Load a registry from a local file (JSON). Returns an empty registry
/// if the file does not exist.
pub fn load_local(path: &Path) -> Result<Registry, String> {
    if !path.exists() {
        return Ok(Registry::default());
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("read registry {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("parse registry {}: {e}", path.display()))
}

pub fn save_local(path: &Path, registry: &Registry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    let raw =
        serde_json::to_string_pretty(registry).map_err(|e| format!("serialize registry: {e}"))?;
    std::fs::write(path, raw).map_err(|e| format!("write registry {}: {e}", path.display()))?;
    Ok(())
}

/// Resolve a registry URL/path into a local *write* path. Used by
/// `vela registry publish` which can only target a local file.
/// v0.6 supports:
///   - bare path: `/path/to/registry.json`
///   - `file://` URL
///   - directory: appends `entries.json`
///
/// HTTP and git transports are rejected here (publish-side only); for
/// read-side fetches use [`load_any`] which handles HTTP.
pub fn resolve_local(locator: &str) -> Result<PathBuf, String> {
    if locator.starts_with("http://") || locator.starts_with("https://") {
        return Err(
            "HTTP transport for registry write (publish) is deferred to v0.8; for reads, use https:// with `vela registry list/pull`."
                .to_string(),
        );
    }
    if locator.starts_with("git+") {
        return Err("Git transport for registries is deferred to v0.8".to_string());
    }
    let stripped = locator.strip_prefix("file://").unwrap_or(locator);
    let path = PathBuf::from(stripped);
    if path.is_dir() {
        Ok(path.join("entries.json"))
    } else {
        Ok(path)
    }
}

/// Fetch a registry from anywhere it might live. v0.7 (this phase):
///   - bare path / `file://` — local file (delegates to `load_local`)
///   - `https://…/entries.json` — fetched via blocking HTTP, parsed
///     identically to a local file
///   - `https://hub.example` / `https://hub.example/` — appends
///     `/entries` automatically
///
/// HTTP fetch returns the same `Registry` shape; the hub serves the
/// canonical-JSON manifest verbatim, so signature verification works
/// byte-for-byte without re-canonicalization.
pub fn load_any(locator: &str) -> Result<Registry, String> {
    if locator.starts_with("http://") || locator.starts_with("https://") {
        let url = registry_listing_url(locator);
        std::thread::spawn(move || {
            let client = reqwest::blocking::Client::builder()
                .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .map_err(|e| format!("build http client: {e}"))?;
            let resp = client
                .get(&url)
                .send()
                .map_err(|e| format!("GET {url}: {e}"))?;
            if !resp.status().is_success() {
                return Err(format!("GET {url}: HTTP {}", resp.status()));
            }
            let text = resp
                .text()
                .map_err(|e| format!("read response body: {e}"))?;
            serde_json::from_str(&text).map_err(|e| format!("parse remote registry {url}: {e}"))
        })
        .join()
        .map_err(|_| "remote registry fetch worker panicked".to_string())?
    } else {
        let path = resolve_local(locator)?;
        load_local(&path)
    }
}

fn registry_listing_url(locator: &str) -> String {
    let trimmed = locator.trim_end_matches('/');
    if trimmed.ends_with("/entries") || trimmed.ends_with("/entries.json") {
        return trimmed.to_string();
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"));
    if without_scheme.is_some_and(|rest| !rest.contains('/')) {
        return format!("{trimmed}/entries");
    }
    locator.to_string()
}

/// Fetch a frontier file from its locator (the `network_locator` field
/// on a registry entry) into a local destination path. Supports
/// `file://`, bare paths, and `https://`. Returns the destination path
/// on success.
pub fn fetch_frontier_to(locator: &str, dest: &Path) -> Result<(), String> {
    if locator.starts_with("http://") || locator.starts_with("https://") {
        fetch_http_frontier_to(locator, dest).map_err(|e| e.to_string())
    } else {
        let stripped = locator.strip_prefix("file://").unwrap_or(locator);
        let source = PathBuf::from(stripped);
        std::fs::copy(&source, dest)
            .map(|_| ())
            .map_err(|e| format!("copy {} → {}: {e}", source.display(), dest.display()))
    }
}

/// Build the event-first snapshot endpoint for a hub registry locator.
/// Returns `None` for local registries. The caller should still verify
/// the downloaded bytes against the signed manifest.
pub fn event_first_snapshot_locator(registry_locator: &str, vfr_id: &str) -> Option<String> {
    if !registry_locator.starts_with("http://") && !registry_locator.starts_with("https://") {
        return None;
    }
    let trimmed = registry_locator.trim_end_matches('/');
    let root = trimmed
        .strip_suffix("/entries")
        .or_else(|| trimmed.strip_suffix("/entries.json"))
        .unwrap_or(trimmed);
    Some(format!("{root}/entries/{vfr_id}/snapshot"))
}

/// Fetch a frontier for a registry entry, preferring the event-first hub
/// read path when the registry itself came from a hub URL. Falls back
/// to `network_locator` only for older hubs that do not expose the
/// snapshot endpoint. Verification remains the caller's job.
pub fn fetch_frontier_to_prefer_event_hub(
    entry: &RegistryEntry,
    registry_locator: Option<&str>,
    dest: &Path,
) -> Result<(), String> {
    if let Some(hub_snapshot) =
        registry_locator.and_then(|locator| event_first_snapshot_locator(locator, &entry.vfr_id))
    {
        match fetch_http_frontier_to(&hub_snapshot, dest) {
            Ok(()) => return Ok(()),
            Err(e) if e.status_is_legacy_endpoint_miss() => {}
            Err(e) => {
                return Err(format!(
                    "event-first hub snapshot fetch failed: {e}; not falling back to network_locator"
                ));
            }
        }
    }
    fetch_frontier_to(&entry.network_locator, dest)
}

#[derive(Debug)]
struct HttpFetchError {
    locator: String,
    status: Option<reqwest::StatusCode>,
    message: String,
}

impl HttpFetchError {
    fn status_is_legacy_endpoint_miss(&self) -> bool {
        matches!(self.status.map(|s| s.as_u16()), Some(404 | 405 | 501))
    }
}

impl std::fmt::Display for HttpFetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.status {
            Some(status) => write!(f, "GET {}: HTTP {status}", self.locator),
            None => write!(f, "GET {}: {}", self.locator, self.message),
        }
    }
}

fn fetch_http_frontier_to(locator: &str, dest: &Path) -> Result<(), HttpFetchError> {
    let locator_for_error = locator.to_string();
    let locator = locator.to_string();
    let dest = dest.to_path_buf();
    std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| HttpFetchError {
                locator: locator.clone(),
                status: None,
                message: format!("build http client: {e}"),
            })?;
        let resp = client.get(&locator).send().map_err(|e| HttpFetchError {
            locator: locator.clone(),
            status: None,
            message: e.to_string(),
        })?;
        if !resp.status().is_success() {
            return Err(HttpFetchError {
                locator: locator.clone(),
                status: Some(resp.status()),
                message: String::new(),
            });
        }
        let bytes = resp.bytes().map_err(|e| HttpFetchError {
            locator: locator.clone(),
            status: None,
            message: format!("read frontier bytes: {e}"),
        })?;
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| HttpFetchError {
                locator: locator.clone(),
                status: None,
                message: format!("mkdir {}: {e}", parent.display()),
            })?;
        }
        std::fs::write(&dest, &bytes).map_err(|e| HttpFetchError {
            locator,
            status: None,
            message: format!("write {}: {e}", dest.display()),
        })
    })
    .join()
    .unwrap_or_else(|_| {
        Err(HttpFetchError {
            locator: locator_for_error,
            status: None,
            message: "HTTP fetch worker panicked".to_string(),
        })
    })
}

/// Server response shape from `POST <hub>/entries`.
#[derive(Debug, Clone, Deserialize)]
pub struct PublishResponse {
    pub ok: bool,
    #[serde(default)]
    pub duplicate: bool,
    #[serde(default)]
    pub vfr_id: String,
    #[serde(default)]
    pub signed_publish_at: String,
}

/// Push a signed entry to a remote hub. The transport is doctrine-light:
/// canonical JSON over HTTPS POST. The hub verifies the signature and
/// stores the bytes verbatim.
///
/// `hub_url` may be either the hub root (`https://hub.constellate.science`) or
/// the entries endpoint (`https://hub.constellate.science/entries`); we append
/// `/entries` if missing.
///
/// v0.55: when `substrate` is `Some`, the full Project is included
/// inline in the publish body. The hub verifies its hash against the
/// signed manifest, stores a snapshot export when configured, and
/// promotes event/projection rows for live reads. Pass `None` only for
/// manifest-only registry history; event-first hubs will not promote
/// that row to live frontier state.
///
/// The signed preimage is not affected: `entry_signing_bytes` (and
/// therefore the signature) excludes `substrate`. The hub re-canonicalises
/// the entry portion of the body to verify the signature, ignoring
/// the `substrate` sibling.
pub fn publish_remote(
    entry: &RegistryEntry,
    hub_url: &str,
    substrate: Option<&crate::project::Project>,
) -> Result<PublishResponse, String> {
    if !hub_url.starts_with("http://") && !hub_url.starts_with("https://") {
        return Err(format!(
            "publish_remote requires http:// or https:// URL, got: {hub_url}"
        ));
    }
    let trimmed = hub_url.trim_end_matches('/');
    let url = if trimmed.ends_with("/entries") {
        trimmed.to_string()
    } else {
        format!("{trimmed}/entries")
    };

    // Body shape:
    //   - manifest-only (legacy): canonical bytes of `entry`.
    //   - inline substrate (v0.55+): entry fields + "substrate" sibling
    //     key, serialised as plain (non-canonical) JSON. The hub
    //     re-canonicalises just the entry portion to verify the signature.
    let body: Vec<u8> = match substrate {
        None => crate::canonical::to_canonical_bytes(entry)
            .map_err(|e| format!("canonicalize entry: {e}"))?,
        Some(project) => {
            let mut wrapper =
                serde_json::to_value(entry).map_err(|e| format!("serialise entry: {e}"))?;
            let project_value =
                serde_json::to_value(project).map_err(|e| format!("serialise substrate: {e}"))?;
            if let serde_json::Value::Object(map) = &mut wrapper {
                map.insert("substrate".to_string(), project_value);
            } else {
                return Err("entry did not serialise to a JSON object".to_string());
            }
            serde_json::to_vec(&wrapper).map_err(|e| format!("serialise body: {e}"))?
        }
    };

    std::thread::spawn(move || {
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")))
            // Substrate can be tens of MB on broad frontiers (the BBB-superset
            // ALZ corpus is ~21 MB). Allow generous time on the upload + hub
            // hash verification + DB insert.
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| format!("build http client: {e}"))?;
        let resp = client
            .post(&url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .map_err(|e| format!("POST {url}: {e}"))?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| format!("read response body: {e}"))?;
        if !status.is_success() {
            // Try to extract a server-supplied message; otherwise surface the body.
            let msg = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                .unwrap_or(text);
            return Err(format!("POST {url}: HTTP {status}: {msg}"));
        }
        serde_json::from_str(&text).map_err(|e| format!("parse publish response: {e}"))
    })
    .join()
    .map_err(|_| "remote publish worker panicked".to_string())?
}

/// Strip a trailing `/entries` (and slashes) so `/blobs/<hash>` composes
/// cleanly whether the caller passes the hub root or its `/entries` URL.
fn hub_root_of(hub_url: &str) -> String {
    hub_url
        .trim_end_matches('/')
        .trim_end_matches("/entries")
        .trim_end_matches('/')
        .to_string()
}

/// Result of uploading a frontier's content-addressed artifact blobs to a
/// hub blob tier (the publish-side half of round-trip completeness).
#[derive(Debug, Clone, Default)]
pub struct BlobUploadReport {
    pub uploaded: usize,
    pub duplicate: usize,
    pub skipped_remote: usize,
    /// Locators whose bytes were not present on disk (a partial upload).
    pub missing_local: Vec<String>,
}

/// Upload the BYTES behind a frontier's local artifacts (witnesses, proof
/// packets, `local_blob` datasets) to the hub blob tier, content-addressed
/// by their committed `content_hash`. This is what makes a published
/// frontier *cloneable*: a pull recovers the objects, and these uploads make
/// the payloads they reference fetchable, so a cold clone can `vela
/// reproduce`.
///
/// Idempotent and dedup-friendly: a blob already on the hub returns
/// `duplicate` and is not re-sent (git-style "only push missing objects").
/// Each upload is content-addressed and self-verifying — the hub recomputes
/// the hash — so no signature over the inert bytes is needed; the authority
/// is the `content_hash` the owner already signed into the snapshot.
pub fn upload_artifact_blobs(
    frontier_root: &Path,
    project: &crate::project::Project,
    hub_url: &str,
    pubkey_hex: &str,
) -> Result<BlobUploadReport, String> {
    use sha2::{Digest, Sha256};
    let hub_root = hub_root_of(hub_url);
    let mut jobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut report = BlobUploadReport::default();
    for artifact in &project.artifacts {
        if artifact.retracted {
            continue;
        }
        if artifact.storage_mode != "local_blob" && artifact.storage_mode != "local_file" {
            report.skipped_remote += 1;
            continue;
        }
        let hash_hex = artifact
            .content_hash
            .strip_prefix("sha256:")
            .unwrap_or(&artifact.content_hash)
            .to_string();
        if hash_hex.len() != 64 {
            continue;
        }
        let Some(locator) = &artifact.locator else {
            continue;
        };
        if locator.is_empty() || locator.contains("://") {
            continue;
        }
        let path = frontier_root.join(locator);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => {
                report.missing_local.push(locator.clone());
                continue;
            }
        };
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != hash_hex {
            return Err(format!(
                "artifact {} on-disk blob {} hashes to {actual}, not the committed {hash_hex}",
                artifact.id,
                path.display()
            ));
        }
        jobs.push((hash_hex, bytes));
    }
    if jobs.is_empty() {
        return Ok(report);
    }
    let pubkey = pubkey_hex.to_string();
    let (uploaded, duplicate) = std::thread::spawn(move || -> Result<(usize, usize), String> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| format!("build http client: {e}"))?;
        let mut up = 0usize;
        let mut dup = 0usize;
        for (hash, bytes) in jobs {
            let url = format!("{hub_root}/blobs/{hash}");
            let resp = client
                .put(&url)
                .header("content-type", "application/octet-stream")
                .header("x-vela-pubkey", &pubkey)
                .body(bytes)
                .send()
                .map_err(|e| format!("PUT {url}: {e}"))?;
            let status = resp.status();
            let text = resp.text().unwrap_or_default();
            if !status.is_success() {
                let msg = serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
                    .unwrap_or(text);
                return Err(format!("PUT {url}: HTTP {status}: {msg}"));
            }
            let is_dup = serde_json::from_str::<serde_json::Value>(&text)
                .ok()
                .and_then(|v| v.get("duplicate").and_then(serde_json::Value::as_bool))
                .unwrap_or(false);
            if is_dup {
                dup += 1;
            } else {
                up += 1;
            }
        }
        Ok((up, dup))
    })
    .join()
    .map_err(|_| "blob upload worker panicked".to_string())??;
    report.uploaded = uploaded;
    report.duplicate = duplicate;
    Ok(report)
}

/// Fetch a content-addressed blob by hex hash from a hub blob tier. The hub
/// answers with a 302 to the immutable CDN object; reqwest follows it. The
/// blob tier is UNTRUSTED transport — the caller MUST verify the returned
/// bytes against the expected `content_hash` (`write_working_frontier`
/// does), so a wrong or poisoned blob is caught on receipt, never trusted.
pub fn fetch_blob(hub_url: &str, hash_hex: &str) -> Result<Vec<u8>, String> {
    let hub_root = hub_root_of(hub_url);
    let url = format!("{hub_root}/blobs/{hash_hex}");
    let hash = hash_hex.to_string();
    std::thread::spawn(move || -> Result<Vec<u8>, String> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| format!("build http client: {e}"))?;
        let resp = client
            .get(&url)
            .send()
            .map_err(|e| format!("GET {url}: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("GET {url}: HTTP {status}"));
        }
        let bytes = resp.bytes().map_err(|e| format!("read blob {hash}: {e}"))?;
        Ok(bytes.to_vec())
    })
    .join()
    .map_err(|_| "blob fetch worker panicked".to_string())?
}

/// Append a signed entry to a registry, replacing any prior entry
/// for the same `vfr_id` (latest-publish-wins).
///
/// Verifies the entry's signature against its declared `owner_pubkey`
/// before persisting; refuses to register an entry that fails
/// verification (callers must sign first).
pub fn publish_entry(registry_path: &Path, entry: RegistryEntry) -> Result<(), String> {
    if !verify_entry(&entry)? {
        return Err("registry entry signature does not verify".to_string());
    }
    let mut registry = load_local(registry_path)?;
    registry
        .entries
        .retain(|existing| existing.vfr_id != entry.vfr_id);
    registry.entries.push(entry);
    save_local(registry_path, &registry)
}

/// Find the latest entry for `vfr_id` in a local registry, by
/// `signed_publish_at`. Returns None if no entry exists.
pub fn find_latest(registry: &Registry, vfr_id: &str) -> Option<RegistryEntry> {
    registry
        .entries
        .iter()
        .filter(|entry| entry.vfr_id == vfr_id)
        .max_by_key(|entry| entry.signed_publish_at.clone())
        .cloned()
}

/// Pull verification: given a registry entry and the path to a
/// pulled-frontier file on disk, verify that:
///
/// 1. The entry's signature verifies against its declared pubkey.
/// 2. The frontier's `snapshot_hash` matches the entry's
///    `latest_snapshot_hash`.
/// 3. The frontier's `event_log_hash` matches the entry's
///    `latest_event_log_hash`.
///
/// Returns Ok(()) if all three hold; Err(reason) on any mismatch.
pub fn verify_pull(entry: &RegistryEntry, frontier_path: &Path) -> Result<(), String> {
    if !verify_entry(entry)? {
        return Err("registry entry signature does not verify".to_string());
    }
    let frontier = crate::repo::load_from_path(frontier_path)
        .map_err(|e| format!("load frontier {}: {e}", frontier_path.display()))?;
    let snapshot = crate::events::snapshot_hash(&frontier);
    if snapshot != entry.latest_snapshot_hash {
        return Err(format!(
            "snapshot_hash mismatch: registry={}, frontier={}",
            entry.latest_snapshot_hash, snapshot
        ));
    }
    let event_log = crate::events::event_log_hash(&frontier.events);
    if event_log != entry.latest_event_log_hash {
        return Err(format!(
            "event_log_hash mismatch: registry={}, frontier={}",
            entry.latest_event_log_hash, event_log
        ));
    }
    Ok(())
}

// ── v0.8: transitive pull-and-verify ─────────────────────────────────

/// Outcome of `pull_transitive`. The primary frontier and every
/// recursively-resolved cross-frontier dependency end up as files on
/// disk; `verified` lists the `vfr_id`s whose snapshot pin matched.
#[derive(Debug, Clone)]
pub struct PullResult {
    /// Path to the primary frontier file.
    pub primary_path: std::path::PathBuf,
    /// `vfr_id` → on-disk path for every dependency successfully pulled.
    pub deps: std::collections::HashMap<String, std::path::PathBuf>,
    /// Order in which `vfr_id`s were verified (primary first, then deps
    /// in walk order). Useful for stable output / logging.
    pub verified: Vec<String>,
}

/// Pull a frontier and recursively pull every cross-frontier
/// dependency it declares, verifying each pinned snapshot hash along
/// the way. The primary's manifest must live in `registry`.
///
/// Doctrine notes:
/// - Verification is total: any snapshot mismatch, missing locator, or
///   missing dep-manifest aborts the whole pull. Partial trust is not
///   a state v0.8 supports.
/// - Cycles are impossible by content-addressing (a vfr_id is a hash
///   of bytes that include the dependency list). A visited-set guards
///   anyway; revisiting the same vfr_id is a no-op.
/// - `max_depth` caps recursion. The primary is depth 0; its direct
///   deps are depth 1, and so on. Reaching `max_depth` without
///   exhausting deps is an error so the caller can decide to retry
///   with a higher cap.
pub fn pull_transitive(
    registry: &Registry,
    primary_vfr: &str,
    out_dir: &Path,
    max_depth: usize,
) -> Result<PullResult, String> {
    use std::collections::{HashMap, HashSet, VecDeque};

    std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;

    // Look up the primary entry, fetch the frontier, verify total.
    let primary_entry = find_latest(registry, primary_vfr)
        .ok_or_else(|| format!("primary {primary_vfr} not found in registry"))?;
    let primary_path = out_dir.join(format!("{primary_vfr}.json"));
    fetch_frontier_to(&primary_entry.network_locator, &primary_path)
        .map_err(|e| format!("fetch primary {primary_vfr}: {e}"))?;
    verify_pull(&primary_entry, &primary_path)
        .map_err(|e| format!("verify primary {primary_vfr}: {e}"))?;

    let mut deps: HashMap<String, std::path::PathBuf> = HashMap::new();
    let mut verified: Vec<String> = vec![primary_vfr.to_string()];
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(primary_vfr.to_string());

    // BFS: each queue entry carries (vfr_id, frontier_path, depth).
    let mut queue: VecDeque<(String, std::path::PathBuf, usize)> = VecDeque::new();
    queue.push_back((primary_vfr.to_string(), primary_path.clone(), 0));

    while let Some((cur_vfr, cur_path, depth)) = queue.pop_front() {
        let frontier =
            crate::repo::load_from_path(&cur_path).map_err(|e| format!("reload {cur_vfr}: {e}"))?;

        for dep in frontier.cross_frontier_deps() {
            let Some(dep_vfr) = dep.vfr_id.clone() else {
                continue;
            };
            if visited.contains(&dep_vfr) {
                continue; // already pulled (deduped + cycle-safe)
            }
            if depth + 1 > max_depth {
                return Err(format!(
                    "transitive pull exceeded max depth {max_depth} at {dep_vfr} (declared by {cur_vfr})"
                ));
            }
            let dep_locator = dep
                .locator
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    format!(
                        "cross-frontier dep {dep_vfr} (declared by {cur_vfr}) has no locator; cannot fetch"
                    )
                })?;
            let dep_pinned = dep
                .pinned_snapshot_hash
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    format!(
                        "cross-frontier dep {dep_vfr} (declared by {cur_vfr}) has no pinned_snapshot_hash; cannot verify"
                    )
                })?;

            // Manifest must live in this same registry. (Hub-to-hub
            // federation — pulling deps from a different registry — is
            // deferred to v0.9.)
            let dep_entry = find_latest(registry, &dep_vfr).ok_or_else(|| {
                format!(
                    "cross-frontier dep {dep_vfr} (declared by {cur_vfr}) not present in registry"
                )
            })?;

            let dep_path = out_dir.join(format!("{dep_vfr}.json"));
            fetch_frontier_to(dep_locator, &dep_path)
                .map_err(|e| format!("fetch dep {dep_vfr}: {e}"))?;
            verify_pull(&dep_entry, &dep_path).map_err(|e| format!("verify dep {dep_vfr}: {e}"))?;

            // Heart of the pin: compare the *dependent's* declared
            // pinned snapshot to the *dependency's* actual snapshot.
            // The dep's manifest snapshot is what `verify_pull` already
            // checked against the file; equality there means the file's
            // canonical snapshot equals `dep_entry.latest_snapshot_hash`.
            // So the pin check is just: dep_pinned == dep_entry's hash.
            if dep_pinned != dep_entry.latest_snapshot_hash {
                return Err(format!(
                    "pinned_snapshot_hash mismatch for {dep_vfr}: dependent {cur_vfr} pinned {dep_pinned}, registry has {actual}",
                    actual = dep_entry.latest_snapshot_hash
                ));
            }

            visited.insert(dep_vfr.clone());
            verified.push(dep_vfr.clone());
            deps.insert(dep_vfr.clone(), dep_path.clone());
            queue.push_back((dep_vfr, dep_path, depth + 1));
        }
    }

    Ok(PullResult {
        primary_path,
        deps,
        verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    fn keypair() -> (SigningKey, String) {
        let key = SigningKey::generate(&mut OsRng);
        let pubkey = hex::encode(key.verifying_key().to_bytes());
        (key, pubkey)
    }

    #[test]
    fn event_first_snapshot_locator_normalizes_hub_registry_urls() {
        assert_eq!(
            event_first_snapshot_locator("https://hub.constellate.science/entries", "vfr_demo")
                .as_deref(),
            Some("https://hub.constellate.science/entries/vfr_demo/snapshot")
        );
        assert_eq!(
            event_first_snapshot_locator("https://hub.constellate.science/", "vfr_demo").as_deref(),
            Some("https://hub.constellate.science/entries/vfr_demo/snapshot")
        );
        assert_eq!(
            event_first_snapshot_locator("file:///tmp/registry.json", "vfr_demo"),
            None
        );
    }

    #[test]
    fn registry_listing_url_accepts_hub_roots() {
        assert_eq!(
            registry_listing_url("https://hub.constellate.science"),
            "https://hub.constellate.science/entries"
        );
        assert_eq!(
            registry_listing_url("https://hub.constellate.science/"),
            "https://hub.constellate.science/entries"
        );
        assert_eq!(
            registry_listing_url("https://hub.constellate.science/entries"),
            "https://hub.constellate.science/entries"
        );
        assert_eq!(
            registry_listing_url("https://example.com/registry.json"),
            "https://example.com/registry.json"
        );
    }

    fn sample_entry(pubkey: &str) -> RegistryEntry {
        RegistryEntry {
            schema: ENTRY_SCHEMA.to_string(),
            vfr_id: "vfr_aaaaaaaaaaaaaaaa".to_string(),
            name: "Test Frontier".to_string(),
            owner_actor_id: "reviewer:test".to_string(),
            owner_pubkey: pubkey.to_string(),
            latest_snapshot_hash: "a".repeat(64),
            latest_event_log_hash: "b".repeat(64),
            network_locator: "/tmp/x.json".to_string(),
            license: None,
            signed_publish_at: "2026-04-25T00:00:00Z".to_string(),
            signature: String::new(),
        }
    }

    #[test]
    fn entry_sign_and_verify_round_trip() {
        let (key, pubkey) = keypair();
        let mut entry = sample_entry(&pubkey);
        entry.signature = sign_entry(&entry, &key).unwrap();
        assert!(verify_entry(&entry).unwrap(), "entry must self-verify");
    }

    #[test]
    fn tampered_entry_fails_verification() {
        let (key, pubkey) = keypair();
        let mut entry = sample_entry(&pubkey);
        entry.signature = sign_entry(&entry, &key).unwrap();
        entry.latest_snapshot_hash = "f".repeat(64);
        assert!(
            !verify_entry(&entry).unwrap(),
            "tampered entry must fail to verify"
        );
    }

    #[test]
    fn publish_entry_replaces_prior_for_same_vfr_id() {
        let (key, pubkey) = keypair();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("entries.json");
        let mut entry = sample_entry(&pubkey);
        entry.signature = sign_entry(&entry, &key).unwrap();
        publish_entry(&path, entry.clone()).unwrap();

        // Re-publish with newer timestamp + new snapshot.
        let mut entry2 = entry.clone();
        entry2.latest_snapshot_hash = "c".repeat(64);
        entry2.signed_publish_at = "2026-04-26T00:00:00Z".to_string();
        entry2.signature = sign_entry(&entry2, &key).unwrap();
        publish_entry(&path, entry2.clone()).unwrap();

        let registry = load_local(&path).unwrap();
        assert_eq!(registry.entries.len(), 1);
        assert_eq!(
            registry.entries[0].latest_snapshot_hash,
            entry2.latest_snapshot_hash
        );
        let latest = find_latest(&registry, &entry.vfr_id).unwrap();
        assert_eq!(latest.signed_publish_at, "2026-04-26T00:00:00Z");
    }

    #[test]
    fn publish_rejects_unsigned_entry() {
        let (_key, pubkey) = keypair();
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("entries.json");
        let entry = sample_entry(&pubkey); // signature is empty
        let result = publish_entry(&path, entry);
        assert!(result.is_err(), "unsigned entry must be rejected");
    }

    // ── v0.8: transitive pull-and-verify ──────────────────────────────

    /// Build a frontier file at `path`, return its (vfr_id,
    /// snapshot_hash, event_log_hash). Uses `project::assemble` to make
    /// a real frontier (real frontier_id, real hashes), so the
    /// resulting RegistryEntry is verifiable end-to-end.
    fn make_real_frontier(
        dir: &Path,
        name: &str,
        seed: &str,
        deps: Vec<crate::project::ProjectDependency>,
    ) -> (std::path::PathBuf, String, String, String) {
        use crate::bundle::{
            Assertion, Conditions, Confidence, ConfidenceMethod, Evidence, Extraction,
            FindingBundle, Flags, Provenance,
        };
        let assertion = Assertion {
            text: format!("Test assertion {seed}"),
            assertion_type: "mechanism".into(),
            entities: vec![],
            relation: None,
            direction: None,
            causal_claim: None,
            causal_evidence_grade: None,
        };
        let provenance = Provenance {
            source_type: "published_paper".into(),
            doi: Some(format!("10.0000/{seed}")),
            url: None,
            title: format!("Test {seed}"),
            authors: vec![],
            year: Some(2024),
            license: None,
            publisher: None,
            funders: vec![],
            extraction: Extraction {
                method: "llm_extraction".into(),
                model: None,
                model_version: None,
                extracted_at: "1970-01-01T00:00:00Z".into(),
                extractor_version: "vela/0.2.0".into(),
            },
            review: None,
        };
        let id = FindingBundle::content_address(&assertion, &provenance);
        let finding = FindingBundle {
            id,
            version: 1,
            previous_version: None,
            assertion,
            evidence: Evidence {
                evidence_type: "experimental".into(),
                model_system: String::new(),
                method: String::new(),
                replicated: false,
                replication_count: None,
                evidence_spans: vec![],
            },
            conditions: Conditions {
                text: String::new(),
                duration: None,
            },
            confidence: Confidence {
                kind: Default::default(),
                score: 0.5,
                basis: "test".into(),
                method: ConfidenceMethod::LlmInitial,
                components: None,
                extraction_confidence: 0.5,
            },
            provenance,
            flags: Flags {
                gap: false,
                negative_space: false,
                contested: false,
                retracted: false,
                declining: false,
                gravity_well: false,
                review_state: None,
                superseded: false,
                signature_threshold: None,
                jointly_accepted: false,
            },
            links: vec![],
            annotations: vec![],
            attachments: vec![],
            created: chrono::Utc::now().to_rfc3339(),
            updated: None,

            access_tier: crate::access_tier::AccessTier::Public,
        };
        let mut p = crate::project::assemble(name, vec![finding], 1, 0, "Test");
        p.project.dependencies = deps;
        let path = dir.join(format!("{name}.json"));
        let json = serde_json::to_string_pretty(&p).unwrap();
        std::fs::write(&path, json).unwrap();
        let vfr_id = p.frontier_id();
        let snapshot = crate::events::snapshot_hash(&p);
        let event_log = crate::events::event_log_hash(&p.events);
        (path, vfr_id, snapshot, event_log)
    }

    fn signed_entry(
        key: &SigningKey,
        pubkey: &str,
        vfr_id: &str,
        name: &str,
        path: &Path,
        snapshot: &str,
        event_log: &str,
    ) -> RegistryEntry {
        let mut entry = RegistryEntry {
            schema: ENTRY_SCHEMA.to_string(),
            vfr_id: vfr_id.to_string(),
            name: name.to_string(),
            owner_actor_id: "reviewer:test".to_string(),
            owner_pubkey: pubkey.to_string(),
            latest_snapshot_hash: snapshot.to_string(),
            latest_event_log_hash: event_log.to_string(),
            network_locator: format!("file://{}", path.display()),
            license: None,
            signed_publish_at: chrono::Utc::now().to_rfc3339(),
            signature: String::new(),
        };
        entry.signature = sign_entry(&entry, key).unwrap();
        entry
    }

    #[test]
    fn pull_transitive_resolves_one_level() {
        let (key, pubkey) = keypair();
        let tmp = TempDir::new().unwrap();
        let stage = tmp.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let out = tmp.path().join("out");

        // Frontier A — leaf, no deps.
        let (a_path, a_vfr, a_snap, a_eventlog) =
            make_real_frontier(&stage, "frontier-a", "aaa", vec![]);
        // Frontier B declares A as a dep with the right snapshot pin.
        let (b_path, b_vfr, b_snap, b_eventlog) = make_real_frontier(
            &stage,
            "frontier-b",
            "bbb",
            vec![crate::project::ProjectDependency {
                name: "frontier-a".into(),
                source: "vela.hub".into(),
                version: None,
                pinned_hash: None,
                vfr_id: Some(a_vfr.clone()),
                locator: Some(format!("file://{}", a_path.display())),
                pinned_snapshot_hash: Some(a_snap.clone()),
            }],
        );

        let mut registry = Registry::default();
        registry.entries.push(signed_entry(
            &key,
            &pubkey,
            &a_vfr,
            "frontier-a",
            &a_path,
            &a_snap,
            &a_eventlog,
        ));
        registry.entries.push(signed_entry(
            &key,
            &pubkey,
            &b_vfr,
            "frontier-b",
            &b_path,
            &b_snap,
            &b_eventlog,
        ));

        let result = pull_transitive(&registry, &b_vfr, &out, 4).unwrap();
        assert_eq!(result.verified.len(), 2, "both frontiers verified");
        assert!(result.verified.contains(&b_vfr));
        assert!(result.verified.contains(&a_vfr));
        assert!(result.deps.contains_key(&a_vfr));
        assert!(out.join(format!("{b_vfr}.json")).exists());
        assert!(out.join(format!("{a_vfr}.json")).exists());
    }

    #[test]
    fn pull_transitive_fails_on_pin_mismatch() {
        let (key, pubkey) = keypair();
        let tmp = TempDir::new().unwrap();
        let stage = tmp.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let out = tmp.path().join("out");

        let (a_path, a_vfr, a_snap, a_eventlog) =
            make_real_frontier(&stage, "frontier-a", "aaa", vec![]);
        // B pins a *different* snapshot than the registry has for A.
        let bad_pin = "f".repeat(64);
        let (b_path, b_vfr, b_snap, b_eventlog) = make_real_frontier(
            &stage,
            "frontier-b",
            "bbb",
            vec![crate::project::ProjectDependency {
                name: "frontier-a".into(),
                source: "vela.hub".into(),
                version: None,
                pinned_hash: None,
                vfr_id: Some(a_vfr.clone()),
                locator: Some(format!("file://{}", a_path.display())),
                pinned_snapshot_hash: Some(bad_pin),
            }],
        );

        let mut registry = Registry::default();
        registry.entries.push(signed_entry(
            &key,
            &pubkey,
            &a_vfr,
            "frontier-a",
            &a_path,
            &a_snap,
            &a_eventlog,
        ));
        registry.entries.push(signed_entry(
            &key,
            &pubkey,
            &b_vfr,
            "frontier-b",
            &b_path,
            &b_snap,
            &b_eventlog,
        ));

        let err = pull_transitive(&registry, &b_vfr, &out, 4).unwrap_err();
        assert!(
            err.contains("pinned_snapshot_hash mismatch"),
            "expected pin-mismatch error, got: {err}"
        );
    }

    #[test]
    fn pull_transitive_errors_when_dep_missing_from_registry() {
        let (key, pubkey) = keypair();
        let tmp = TempDir::new().unwrap();
        let stage = tmp.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let out = tmp.path().join("out");

        let (a_path, a_vfr, a_snap, _a_eventlog) =
            make_real_frontier(&stage, "frontier-a", "aaa", vec![]);
        let (b_path, b_vfr, b_snap, b_eventlog) = make_real_frontier(
            &stage,
            "frontier-b",
            "bbb",
            vec![crate::project::ProjectDependency {
                name: "frontier-a".into(),
                source: "vela.hub".into(),
                version: None,
                pinned_hash: None,
                vfr_id: Some(a_vfr.clone()),
                locator: Some(format!("file://{}", a_path.display())),
                pinned_snapshot_hash: Some(a_snap),
            }],
        );

        // Registry only has B; A is not registered.
        let mut registry = Registry::default();
        registry.entries.push(signed_entry(
            &key,
            &pubkey,
            &b_vfr,
            "frontier-b",
            &b_path,
            &b_snap,
            &b_eventlog,
        ));

        let err = pull_transitive(&registry, &b_vfr, &out, 4).unwrap_err();
        assert!(err.contains("not present in registry"));
    }
}
