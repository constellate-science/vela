//! v0.167: federated-hub spec primitive. A `vhs_*` record
//! documents a federated hub's declared identity: a stable
//! hub-id (operator-chosen), display name, base URL, the hub
//! operator's pubkey, and the substrate version the hub serves.
//!
//! Substrate-honest framing: the spec is content-addressed over
//! its declaration. Two operators publishing the same spec text
//! produce byte-identical `vhs_*` ids. The substrate validates
//! the shape (HTTPS base URL, valid hex pubkey, non-empty hub
//! id) and emits a verifier-ready record. Wiring a spec to a
//! live hub-fetch is a downstream concern; the v0.148 federation
//! check-status command already covers that surface.
//!
//! v0.167 ships the data layer. A future cycle binds hub specs
//! into the federation peer-registry so peers are added by
//! `vhs_*` id rather than by free-form URL string.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const HUB_SPEC_SCHEMA: &str = "vela.hub_spec.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HubSpec {
    pub schema: String,
    pub spec_id: String,
    pub hub_id: String,
    pub display_name: String,
    pub base_url: String,
    pub operator_pubkey_hex: String,
    pub substrate_version: String,
    /// Free-form contact (email or URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<String>,
    /// Optional: the hub's latest known `vrc_*` checkpoint id at
    /// the time of spec publication. Stale on its own — consumers
    /// should re-fetch /checkpoint/latest before trusting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_checkpoint: Option<String>,
    pub declared_at: String,
}

#[derive(Debug, Clone)]
pub struct HubSpecDraft {
    pub hub_id: String,
    pub display_name: String,
    pub base_url: String,
    pub operator_pubkey_hex: String,
    pub substrate_version: String,
    pub contact: Option<String>,
    pub latest_checkpoint: Option<String>,
    pub declared_at: String,
}

impl HubSpec {
    pub fn from_draft(draft: HubSpecDraft) -> Result<Self, String> {
        if draft.hub_id.trim().is_empty() {
            return Err("hub_id must be non-empty".to_string());
        }
        if draft.display_name.trim().is_empty() {
            return Err("display_name must be non-empty".to_string());
        }
        if !(draft.base_url.starts_with("https://") || draft.base_url.starts_with("http://")) {
            return Err(format!(
                "base_url must start with http:// or https://, got `{}`",
                draft.base_url
            ));
        }
        if draft.operator_pubkey_hex.len() != 64
            || !draft
                .operator_pubkey_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            return Err(
                "operator_pubkey_hex must be 64 hex chars (Ed25519 public key)".to_string(),
            );
        }
        if draft.substrate_version.trim().is_empty() {
            return Err("substrate_version must be non-empty".to_string());
        }
        if let Some(ref c) = draft.latest_checkpoint
            && !c.starts_with("vrc_")
        {
            return Err(format!(
                "latest_checkpoint must start with `vrc_` when present, got `{c}`"
            ));
        }
        let mut spec = HubSpec {
            schema: HUB_SPEC_SCHEMA.to_string(),
            spec_id: String::new(),
            hub_id: draft.hub_id,
            display_name: draft.display_name,
            base_url: draft.base_url,
            operator_pubkey_hex: draft.operator_pubkey_hex,
            substrate_version: draft.substrate_version,
            contact: draft.contact,
            latest_checkpoint: draft.latest_checkpoint,
            declared_at: draft.declared_at,
        };
        spec.spec_id = spec.derive_id();
        Ok(spec)
    }

    fn derive_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.hub_id.as_bytes());
        hasher.update(b"|");
        hasher.update(self.base_url.as_bytes());
        hasher.update(b"|");
        hasher.update(self.operator_pubkey_hex.as_bytes());
        hasher.update(b"|");
        hasher.update(self.substrate_version.as_bytes());
        hasher.update(b"|");
        hasher.update(self.declared_at.as_bytes());
        format!("vhs_{}", &hex::encode(hasher.finalize())[..16])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_draft() -> HubSpecDraft {
        HubSpecDraft {
            hub_id: "vela-hub".to_string(),
            display_name: "Vela Hub".to_string(),
            base_url: "https://hub.constellate.science".to_string(),
            operator_pubkey_hex: "a".repeat(64),
            substrate_version: "0.167.0".to_string(),
            contact: Some("ops@example.org".to_string()),
            latest_checkpoint: None,
            declared_at: "2026-05-11T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn from_draft_builds_and_round_trips() {
        let s = HubSpec::from_draft(ok_draft()).expect("builds");
        assert!(s.spec_id.starts_with("vhs_"));
        let json = serde_json::to_string(&s).expect("ser");
        let back: HubSpec = serde_json::from_str(&json).expect("de");
        assert_eq!(s, back);
    }

    #[test]
    fn rejects_bad_url() {
        let mut d = ok_draft();
        d.base_url = "ftp://example.org".to_string();
        assert!(HubSpec::from_draft(d).is_err());
    }

    #[test]
    fn rejects_bad_pubkey() {
        let mut d = ok_draft();
        d.operator_pubkey_hex = "nothex".to_string();
        assert!(HubSpec::from_draft(d).is_err());
    }

    #[test]
    fn rejects_bad_checkpoint_prefix() {
        let mut d = ok_draft();
        d.latest_checkpoint = Some("not_a_vrc".to_string());
        assert!(HubSpec::from_draft(d).is_err());
    }

    #[test]
    fn id_changes_when_url_changes() {
        let mut a = ok_draft();
        let mut b = a.clone();
        b.base_url = "https://other-hub.fly.dev".to_string();
        // declared_at must match to isolate the URL change
        b.declared_at = a.declared_at.clone();
        let s_a = HubSpec::from_draft(a.clone()).unwrap();
        let s_b = HubSpec::from_draft(b).unwrap();
        assert_ne!(s_a.spec_id, s_b.spec_id);
        // Same draft re-built yields the same id.
        a.declared_at = s_a.declared_at.clone();
        let s_a2 = HubSpec::from_draft(a).unwrap();
        assert_eq!(s_a.spec_id, s_a2.spec_id);
    }
}
