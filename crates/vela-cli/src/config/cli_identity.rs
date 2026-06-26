//! Managed identity — the ergonomics layer that hides key files and ids.
//!
//! Before this, every signed command took `--key <path>` plus `--actor` /
//! `--reviewer` / `--owner`, and `--to <hub>`. A first-time producer had to
//! juggle a key-file path, remember their actor id, and pass a hub URL on
//! every call. That friction, not the cryptography, is what blocked
//! adoption.
//!
//! A `vela id create` writes a single profile to `~/.vela/identity.json`:
//! the generated key, the actor id, the default hub. After that, the
//! signing commands resolve all four from the profile, so the common path
//! is just `vela publish` with no flags. The crypto is unchanged and fully
//! present; it is simply no longer in the user's face.
//!
//! Precedence for every resolver: an explicit flag wins, then a `VELA_*`
//! environment variable, then the stored profile. Nothing is silent: when
//! none resolves, the error names the exact next command to run.

use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::cli::{fail_return, parse_signing_key};

/// The default public hub. Matches the constant baked into the registry
/// commands so an unconfigured user still reaches the live hub.
pub(crate) const DEFAULT_HUB: &str = "https://hub.constellate.science";

/// One stored identity. Written to `~/.vela/identity.json`. The private
/// key itself lives in its own file (`key_path`), never inline here, so
/// this file is safe to read for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Identity {
    /// Schema tag for forward migration.
    #[serde(default = "default_version")]
    pub version: String,
    /// The actor id used as reviewer / owner / proposer, e.g.
    /// `reviewer:alice` or `agent:my-bot`.
    pub actor_id: String,
    /// `human` or `agent` (classified from `actor_id` at create time).
    #[serde(default = "default_actor_type")]
    pub actor_type: String,
    /// Absolute path to the Ed25519 private key (hex seed).
    pub key_path: String,
    /// Hex-encoded Ed25519 public key — the thing a maintainer registers
    /// with `vela actor add`. Stored for display so the user never has to
    /// `cat` the key file.
    pub pubkey: String,
    /// Default hub base URL.
    #[serde(default = "default_hub")]
    pub hub_url: String,
}

fn default_version() -> String {
    "1.0".to_string()
}
fn default_actor_type() -> String {
    "human".to_string()
}
fn default_hub() -> String {
    DEFAULT_HUB.to_string()
}

/// `~/.vela` — the per-user Vela home.
pub(crate) fn vela_home() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".vela")
}

/// `~/.vela/identity.json`.
pub(crate) fn identity_path() -> PathBuf {
    vela_home().join("identity.json")
}

/// Load the stored identity, if any. `None` when the file is absent or
/// unreadable (treated as "not set up yet", not an error).
pub(crate) fn load_identity() -> Option<Identity> {
    let path = identity_path();
    let text = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Persist an identity, creating `~/.vela` if needed.
pub(crate) fn save_identity(identity: &Identity) -> Result<(), String> {
    let dir = vela_home();
    std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
    let path = identity_path();
    let json =
        serde_json::to_string_pretty(identity).map_err(|e| format!("serialize identity: {e}"))?;
    std::fs::write(&path, format!("{json}\n")).map_err(|e| format!("write {}: {e}", path.display()))
}

// ── Resolvers: flag > VELA_* env > profile > error-with-hint ──────────

const SETUP_HINT: &str = "no identity configured — run `vela id create --handle <your-name>` once \
     (generates a key, stores it, prints the line a maintainer runs to register you)";

/// Resolve the actor id. `--actor` / `--reviewer` / `--owner` flag wins,
/// then `$VELA_ACTOR_ID`, then the stored profile.
pub(crate) fn resolve_actor(flag: Option<&str>) -> String {
    if let Some(a) = flag.filter(|s| !s.trim().is_empty()) {
        return a.to_string();
    }
    if let Ok(a) = std::env::var("VELA_ACTOR_ID")
        && !a.trim().is_empty()
    {
        return a;
    }
    match load_identity() {
        Some(id) => id.actor_id,
        None => fail_return(SETUP_HINT),
    }
}

/// Resolve the hub base URL. `--to` / `--hub` flag wins, then
/// `$VELA_HUB_URL`, then the profile, then the baked-in default hub (so an
/// unconfigured `verify` against a known vfr still works).
pub(crate) fn resolve_hub(flag: Option<&str>) -> String {
    if let Some(h) = flag.filter(|s| !s.trim().is_empty()) {
        return h.to_string();
    }
    if let Ok(h) = std::env::var("VELA_HUB_URL")
        && !h.trim().is_empty()
    {
        return h;
    }
    load_identity()
        .map(|id| id.hub_url)
        .unwrap_or_else(|| DEFAULT_HUB.to_string())
}

/// Resolve a signing key path. `--key` flag wins, then `$VELA_KEY_PATH`,
/// then the profile's `key_path`.
pub(crate) fn resolve_key_path(flag: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = flag {
        return Some(p.to_path_buf());
    }
    if let Ok(p) = std::env::var("VELA_KEY_PATH")
        && !p.trim().is_empty()
    {
        return Some(PathBuf::from(p));
    }
    load_identity().map(|id| PathBuf::from(id.key_path))
}

/// Resolve and load the signing key, exiting with a setup hint when none
/// is configured. Use for commands where a key is mandatory.
pub(crate) fn resolve_signing_key(flag: Option<&Path>) -> SigningKey {
    match resolve_signing_key_opt(flag) {
        Some(key) => key,
        None => fail_return(SETUP_HINT),
    }
}

/// Resolve the signing key if one is configured, else `None`. Use for
/// commands where signing is optional (keyless bootstrap still allowed).
pub(crate) fn resolve_signing_key_opt(flag: Option<&Path>) -> Option<SigningKey> {
    let path = resolve_key_path(flag)?;
    let hex = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| fail_return(&format!("read key {}: {e}", path.display())));
    Some(parse_signing_key(hex.trim()))
}
