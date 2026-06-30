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
/// Run a blocking reqwest call on a dedicated OS thread (so it never blocks
/// inside an async runtime), with a pre-built client carrying the standard
/// user-agent + timeout. Consolidates the client-build + thread-spawn + join
/// boilerplate shared by every registry HTTP call; each caller keeps its own
/// request/response logic in `f`.
fn run_blocking_http<T, F>(timeout_secs: u64, f: F) -> Result<T, String>
where
    F: FnOnce(&reqwest::blocking::Client) -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || -> Result<T, String> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(concat!("vela/", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| format!("build http client: {e}"))?;
        f(&client)
    })
    .join()
    .map_err(|_| "http worker thread panicked".to_string())?
}

pub fn load_any(locator: &str) -> Result<Registry, String> {
    if locator.starts_with("http://") || locator.starts_with("https://") {
        let url = registry_listing_url(locator);
        run_blocking_http(30, move |client| {
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

    // Substrate can be tens of MB on broad frontiers; allow generous time on
    // the upload + hub hash verification + DB insert.
    run_blocking_http(120, move |client| {
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
    let (uploaded, duplicate) = run_blocking_http(120, move |client| {
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
    })?;
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
    run_blocking_http(120, move |client| {
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
}

// ---------------------------------------------------------------------------
// v0.711: extras manifest — make the hub a COMPLETE backup of `.vela/`.
//
// A snapshot+artifact-blob clone reconstructs the protocol core (events,
// findings, proposals, actors, artifacts) but silently drops the loose
// `.vela/` files no `Project` field carries: governance `policy/`,
// `releases/`, the verifier sources under `tasks/`+`workspaces/`,
// `evaluations/`, `tool_descriptors/`. Those are source/provenance, not
// regenerable views, so dropping them blocks `.vela/` from becoming a
// gitignored cache. The extras manifest content-addresses every such file
// and is itself content-addressed; its hash rides in the (signed) registry
// entry, OUTSIDE `snapshot_hash`, so adding it never moves the integrity
// anchor and never needs a re-sign of the substrate.
// ---------------------------------------------------------------------------

pub const EXTRAS_MANIFEST_SCHEMA: &str = "vela.extras_manifest.v0.1";

/// `(manifest_hash, blobs)` — every extra file plus the manifest itself, as
/// content-addressed `(hash, bytes)` pairs ready to stage or upload.
pub type ExtrasBundle = (String, Vec<(String, Vec<u8>)>);

/// One loose `.vela/` file, content-addressed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtrasEntry {
    /// Path relative to the frontier's `.vela/` dir, e.g. `policy/review_policy.md`.
    pub rel_path: String,
    /// SHA-256 hex (64 chars, no `sha256:` prefix — matches the blob store key).
    pub content_hash: String,
    pub size_bytes: u64,
}

/// The content-addressed manifest of a frontier's loose `.vela/` files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtrasManifest {
    #[serde(default)]
    pub schema: String,
    pub entries: Vec<ExtrasEntry>,
}

/// `.vela/` top-level dirs a snapshot+artifact-blob clone already rebuilds.
/// Kept next to the loader's write-set (`repo::save_vela_repo`); the
/// `check-vela-coverage.sh` gate is the fail-closed backstop for any drift.
const SNAPSHOT_RECONSTRUCTED_DIRS: &[&str] = &[
    "events",
    "findings",
    "proposals",
    "artifacts",
    "code-artifacts",
    "datasets",
    "artifact-blobs",
];
/// Top-level `.vela/` files the snapshot already rebuilds.
const SNAPSHOT_RECONSTRUCTED_FILES: &[&str] = &[
    "actors.json",
    "config.toml",
    "proof-state.json",
    "signatures.json",
];
/// v0.712: per-machine task-execution scratch — NOT canonical frontier state,
/// so neither committed nor backed up to the hub (the worktree analogue, cf.
/// `workspace.rs`). `vela task` writes these locally; they are regenerated by
/// running a task, not reconstructed from a clone. Excluded from the extras
/// manifest so they stay local-only.
const LOCAL_ONLY_DIRS: &[&str] = &["tasks", "workspaces"];

/// Walk `<frontier>/.vela` and return every file a snapshot+artifact-blob
/// clone would NOT reconstruct, as `(rel_path_under_dotvela, bytes)`, sorted
/// by path for a deterministic manifest.
pub fn collect_extras(frontier_root: &Path) -> Result<Vec<(String, Vec<u8>)>, String> {
    let vela = frontier_root.join(".vela");
    if !vela.is_dir() {
        return Ok(Vec::new());
    }
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let mut stack = vec![vela.clone()];
    while let Some(dir) = stack.pop() {
        let rd = std::fs::read_dir(&dir).map_err(|e| format!("read_dir {}: {e}", dir.display()))?;
        for entry in rd {
            let entry = entry.map_err(|e| e.to_string())?;
            let path = entry.path();
            let rel = path
                .strip_prefix(&vela)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let top = rel.split('/').next().unwrap_or("");
            if SNAPSHOT_RECONSTRUCTED_DIRS.contains(&top) || LOCAL_ONLY_DIRS.contains(&top) {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else {
                if !rel.contains('/') && SNAPSHOT_RECONSTRUCTED_FILES.contains(&rel.as_str()) {
                    continue;
                }
                let bytes =
                    std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
                out.push((rel, bytes));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Build a frontier's extras manifest. Returns
/// `(manifest_hash, blobs)` where `blobs` is every extra file PLUS the
/// manifest itself as `(hash, bytes)`, ready to stage locally or upload.
/// `None` when the frontier has no extras (a fully snapshot-covered tree).
pub fn build_extras_manifest(frontier_root: &Path) -> Result<Option<ExtrasBundle>, String> {
    use sha2::{Digest, Sha256};
    let extras = collect_extras(frontier_root)?;
    if extras.is_empty() {
        return Ok(None);
    }
    let mut entries = Vec::with_capacity(extras.len());
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::with_capacity(extras.len() + 1);
    for (rel, bytes) in &extras {
        let hash = hex::encode(Sha256::digest(bytes));
        entries.push(ExtrasEntry {
            rel_path: rel.clone(),
            content_hash: hash.clone(),
            size_bytes: bytes.len() as u64,
        });
        blobs.push((hash, bytes.clone()));
    }
    let manifest = ExtrasManifest {
        schema: EXTRAS_MANIFEST_SCHEMA.to_string(),
        entries,
    };
    let manifest_value =
        serde_json::to_value(&manifest).map_err(|e| format!("serialize extras manifest: {e}"))?;
    let manifest_bytes = crate::canonical::to_canonical_bytes(&manifest_value)?;
    let manifest_hash = hex::encode(Sha256::digest(&manifest_bytes));
    blobs.push((manifest_hash.clone(), manifest_bytes));
    Ok(Some((manifest_hash, blobs)))
}

/// Stage content-addressed blobs into a local store at `{dir}/sha256/{hash}`.
/// The offline analogue of a hub blob tier — `vela clone --blobs-from {dir}`
/// reads them back. Idempotent: skips a hash already present. Returns the
/// number of NEW blobs written.
pub fn stage_blobs_local(dir: &Path, blobs: &[(String, Vec<u8>)]) -> Result<usize, String> {
    let store = dir.join("sha256");
    std::fs::create_dir_all(&store).map_err(|e| format!("create blob store: {e}"))?;
    let mut written = 0usize;
    for (hash, bytes) in blobs {
        let p = store.join(hash);
        if !p.exists() {
            std::fs::write(&p, bytes).map_err(|e| format!("write blob {hash}: {e}"))?;
            written += 1;
        }
    }
    Ok(written)
}

/// Upload content-addressed blobs to a hub blob tier (`PUT {hub}/blobs/{hash}`),
/// the same shape as `upload_artifact_blobs`. Returns `(uploaded, duplicate)`.
pub fn upload_blobs_http(
    hub_url: &str,
    pubkey_hex: &str,
    blobs: Vec<(String, Vec<u8>)>,
) -> Result<(usize, usize), String> {
    if blobs.is_empty() {
        return Ok((0, 0));
    }
    let hub_root = hub_root_of(hub_url);
    let pubkey = pubkey_hex.to_string();
    run_blocking_http(120, move |client| {
        let mut up = 0usize;
        let mut dup = 0usize;
        for (hash, bytes) in blobs {
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
}

/// Restore a frontier's extras into `dest/.vela/` from a content-addressed
/// blob source. `fetch` resolves a hash to bytes (local mirror or hub). Each
/// file is hash-verified before write. Returns `(restored, missing)`.
pub fn restore_extras(
    dest: &Path,
    manifest_hash: &str,
    fetch: &mut dyn FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<(usize, Vec<String>), String> {
    use sha2::{Digest, Sha256};
    // A missing manifest is a PARTIAL clone, not a fault: the snapshot core
    // still reconstructs (the integrity hashes are unaffected). Report it as a
    // missing extra so callers can surface the gap, mirroring how artifact
    // `blobs_missing` is handled — never crash a clone from an incomplete
    // mirror. (A corrupt manifest — fetched but wrong-hash — still errors.)
    let manifest_bytes = match fetch(manifest_hash) {
        Ok(b) => b,
        Err(_) => return Ok((0, vec![format!("extras-manifest:{manifest_hash}")])),
    };
    let actual = hex::encode(Sha256::digest(&manifest_bytes));
    if actual != manifest_hash {
        return Err(format!(
            "extras manifest hashes to {actual}, not the entry's {manifest_hash}"
        ));
    }
    let manifest: ExtrasManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("parse extras manifest: {e}"))?;
    let vela = dest.join(".vela");
    let mut restored = 0usize;
    let mut missing = Vec::new();
    for entry in &manifest.entries {
        let bytes = match fetch(&entry.content_hash) {
            Ok(b) => b,
            Err(_) => {
                missing.push(entry.rel_path.clone());
                continue;
            }
        };
        let got = hex::encode(Sha256::digest(&bytes));
        if got != entry.content_hash {
            return Err(format!(
                "extra {} hashes to {got}, not the committed {}",
                entry.rel_path, entry.content_hash
            ));
        }
        let out = vela.join(&entry.rel_path);
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(&out, &bytes).map_err(|e| format!("write {}: {e}", out.display()))?;
        restored += 1;
    }
    Ok((restored, missing))
}

/// Deliver a signed proposal-acceptance to a hub
/// (`POST {hub}/entries/{vfr}/proposals/{pid}/accept`). The detached signature
/// is over the canonical accept preimage (vfr, proposal, reviewer, reason);
/// the hub re-derives the same preimage and verifies it against the signer's
/// registered, non-revoked reviewer key. Key-custody: the human signs; this
/// only transports their signature. Returns `(http_status, body)`.
pub fn post_accept_to_hub(
    hub_url: &str,
    vfr_id: &str,
    proposal_id: &str,
    reason: &str,
    signer_pubkey_hex: &str,
    signature_hex: &str,
) -> Result<(u16, String), String> {
    let hub_root = hub_root_of(hub_url);
    let url = format!("{hub_root}/entries/{vfr_id}/proposals/{proposal_id}/accept");
    let body = serde_json::json!({ "reason": reason });
    let pk = signer_pubkey_hex.to_string();
    let sig = signature_hex.to_string();
    run_blocking_http(60, move |client| {
        let resp = client
            .post(&url)
            .header("X-Vela-Signer-Pubkey", &pk)
            .header("X-Vela-Signature", &sig)
            .json(&body)
            .send()
            .map_err(|e| format!("POST {url}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        Ok((status, text))
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use tempfile::TempDir;

    #[test]
    fn extras_manifest_round_trips_and_excludes_snapshot_dirs() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let vela = root.join(".vela");
        std::fs::create_dir_all(vela.join("policy")).unwrap();
        std::fs::create_dir_all(vela.join("workspaces/vtask_x")).unwrap();
        std::fs::create_dir_all(vela.join("events")).unwrap();
        // Extra the snapshot can't rebuild — backed up:
        std::fs::write(vela.join("policy/review.md"), b"be strict").unwrap();
        // Local-only task scratch — NOT backed up (v0.712):
        std::fs::write(vela.join("workspaces/vtask_x/verify.py"), b"print(1)").unwrap();
        // Snapshot-reconstructed — MUST be excluded from extras:
        std::fs::write(vela.join("events/e1.json"), b"{}").unwrap();
        std::fs::write(vela.join("actors.json"), b"[]").unwrap();

        let (manifest_hash, blobs) = build_extras_manifest(root)
            .unwrap()
            .expect("frontier has extras");
        // 1 extra file + the manifest blob; events/actors (snapshot) and
        // workspaces/ (local-only) excluded.
        assert_eq!(blobs.len(), 2, "1 extra + 1 manifest");

        // Stage to a content-addressed store, restore into a fresh dest.
        let store = tmp.path().join("store");
        stage_blobs_local(&store, &blobs).unwrap();
        let dest = TempDir::new().unwrap();
        let mut fetch = |h: &str| -> Result<Vec<u8>, String> {
            std::fs::read(store.join("sha256").join(h)).map_err(|e| e.to_string())
        };
        let (restored, missing) = restore_extras(dest.path(), &manifest_hash, &mut fetch).unwrap();
        assert_eq!(restored, 1);
        assert!(missing.is_empty());
        assert_eq!(
            std::fs::read(dest.path().join(".vela/policy/review.md")).unwrap(),
            b"be strict"
        );
        // Snapshot-reconstructed AND local-only task scratch were NOT folded in.
        assert!(
            !dest
                .path()
                .join(".vela/workspaces/vtask_x/verify.py")
                .exists()
        );
        assert!(!dest.path().join(".vela/events/e1.json").exists());
        assert!(!dest.path().join(".vela/actors.json").exists());
    }

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
            extras_manifest_hash: None,
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
}
