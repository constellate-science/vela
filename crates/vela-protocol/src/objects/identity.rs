//! Producer identity binding (`vib_`): a self-signed proof that a key controls
//! an actor id, plus authoritative revocation.
//!
//! ## What this adds over `ActorRecord`
//!
//! `sign::ActorRecord` is a *registry entry*: it maps `actor.id -> public_key`,
//! but the binding is asserted by whoever writes the registry, not proven by the
//! key-holder. An [`IdentityBinding`] closes that gap. It is signed **by the very
//! key it binds**, so the signature is a proof of possession: only the holder of
//! `public_key_hex` could have produced it. It also records `actor_class`
//! (human / agent / org), which the substrate previously only inferred from the
//! id prefix.
//!
//! ## Revocation is authoritative because it is self-signed
//!
//! An [`IdentityRevocation`] (`vir_`) is signed by the same key it revokes. A
//! holder who loses trust in their own key, or who is done with an id, signs a
//! revocation; the reducer then derives the binding as inactive on read. No
//! third party can revoke your binding, and you cannot deny revoking your own.
//!
//! ## The honest limit
//!
//! This proves key possession and binds a class. It does NOT prove the actor is
//! a distinct human (one person can self-sign a hundred bindings), so it is the
//! foundation for, not the solution to, the sybil-resistance named open in
//! `docs/SIGNIFICANCE_SLOT.md`. Distinct-personhood is a layer above this one.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const IDENTITY_BINDING_SCHEMA: &str = "vela.identity_binding.v0.1";
pub const IDENTITY_REVOCATION_SCHEMA: &str = "vela.identity_revocation.v0.1";

/// What kind of actor controls the id. Inferred-by-prefix before; bound here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorClass {
    Human,
    Agent,
    Org,
}

/// A self-signed proof that `public_key_hex` controls `actor_id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityBinding {
    pub schema: String,
    /// `vib_<16hex>`, content-addressed over the body with id/signature zeroed.
    pub binding_id: String,
    /// Stable namespaced id, e.g. "reviewer:will-blair".
    pub actor_id: String,
    pub actor_class: ActorClass,
    /// The Ed25519 public key being bound. MUST equal the signer (proof of
    /// possession): the binding is signed by the key it binds.
    pub public_key_hex: String,
    pub created_at: String,
    pub signature: String,
}

/// Draft for [`IdentityBinding::build`].
pub struct IdentityBindingDraft {
    pub actor_id: String,
    pub actor_class: ActorClass,
    pub created_at: String,
}

impl IdentityBinding {
    /// Self-sign a binding: the key proves it controls `actor_id`.
    pub fn build(draft: IdentityBindingDraft, key: &SigningKey) -> Result<Self, String> {
        if draft.actor_id.trim().is_empty() {
            return Err("identity_binding.actor_id cannot be empty".to_string());
        }
        let mut b = IdentityBinding {
            schema: IDENTITY_BINDING_SCHEMA.to_string(),
            binding_id: String::new(),
            actor_id: draft.actor_id,
            actor_class: draft.actor_class,
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            created_at: draft.created_at,
            signature: String::new(),
        };
        let preimage = b.id_preimage_bytes()?;
        b.signature = hex::encode(crate::sign::sign_bytes(key, &preimage));
        b.binding_id = b.derive_id()?;
        Ok(b)
    }

    fn id_preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut p = self.clone();
        p.binding_id = String::new();
        p.signature = String::new();
        crate::canonical::to_canonical_bytes(&p)
            .map_err(|e| format!("canonicalize identity_binding preimage: {e}"))
    }

    pub fn derive_id(&self) -> Result<String, String> {
        let bytes = self.id_preimage_bytes()?;
        Ok(format!(
            "vib_{}",
            &hex::encode(Sha256::digest(&bytes))[..16]
        ))
    }

    /// Verify: id re-derives, and the signature is valid under
    /// `public_key_hex` — i.e. the key being bound actually signed this. That
    /// equality (signer == bound key) is the proof of possession.
    pub fn verify(&self) -> Result<(), String> {
        if self.schema != IDENTITY_BINDING_SCHEMA {
            return Err(format!(
                "identity_binding.schema must be `{IDENTITY_BINDING_SCHEMA}`"
            ));
        }
        if !self.binding_id.starts_with("vib_") {
            return Err(format!(
                "binding id must start with `vib_`, got `{}`",
                self.binding_id
            ));
        }
        let preimage = self.id_preimage_bytes()?;
        if !crate::sign::verify_action_signature(&preimage, &self.signature, &self.public_key_hex)?
        {
            return Err(
                "identity_binding signature does not verify under the bound key \
                        (no proof of possession)"
                    .to_string(),
            );
        }
        let rederived = self.derive_id()?;
        if rederived != self.binding_id {
            return Err(format!(
                "binding_id mismatch: declared {}, rebuilt {}",
                self.binding_id, rederived
            ));
        }
        Ok(())
    }
}

/// A self-signed revocation of an [`IdentityBinding`]. Signed by the same key it
/// revokes, so revocation is authoritative and non-repudiable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRevocation {
    pub schema: String,
    pub revocation_id: String,
    /// The `vib_` being revoked.
    pub binding_id: String,
    /// The key that signs (must equal the revoked binding's `public_key_hex`).
    pub public_key_hex: String,
    pub reason: String,
    pub revoked_at: String,
    pub signature: String,
}

/// Draft for [`IdentityRevocation::build`].
pub struct IdentityRevocationDraft {
    pub binding_id: String,
    pub reason: String,
    pub revoked_at: String,
}

impl IdentityRevocation {
    pub fn build(draft: IdentityRevocationDraft, key: &SigningKey) -> Result<Self, String> {
        if !draft.binding_id.starts_with("vib_") {
            return Err("identity_revocation.binding_id must be a `vib_` id".to_string());
        }
        let mut r = IdentityRevocation {
            schema: IDENTITY_REVOCATION_SCHEMA.to_string(),
            revocation_id: String::new(),
            binding_id: draft.binding_id,
            public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            reason: draft.reason,
            revoked_at: draft.revoked_at,
            signature: String::new(),
        };
        let preimage = r.id_preimage_bytes()?;
        r.signature = hex::encode(crate::sign::sign_bytes(key, &preimage));
        r.revocation_id = format!("vir_{}", &hex::encode(Sha256::digest(&preimage))[..16]);
        Ok(r)
    }

    fn id_preimage_bytes(&self) -> Result<Vec<u8>, String> {
        let mut p = self.clone();
        p.revocation_id = String::new();
        p.signature = String::new();
        crate::canonical::to_canonical_bytes(&p)
            .map_err(|e| format!("canonicalize identity_revocation preimage: {e}"))
    }

    pub fn verify(&self) -> Result<(), String> {
        let preimage = self.id_preimage_bytes()?;
        if !crate::sign::verify_action_signature(&preimage, &self.signature, &self.public_key_hex)?
        {
            return Err(
                "identity_revocation signature does not verify under the declared key".to_string(),
            );
        }
        Ok(())
    }

    /// Authoritative check: this revocation legitimately revokes `binding` iff it
    /// is signed by the SAME key the binding bound. A revocation signed by any
    /// other key is not authoritative and is ignored.
    #[must_use]
    pub fn authoritatively_revokes(&self, binding: &IdentityBinding) -> bool {
        self.binding_id == binding.binding_id
            && self.public_key_hex == binding.public_key_hex
            && self.verify().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn draft() -> IdentityBindingDraft {
        IdentityBindingDraft {
            actor_id: "reviewer:will-blair".into(),
            actor_class: ActorClass::Human,
            created_at: "2026-06-09T00:00:00Z".into(),
        }
    }

    #[test]
    fn self_signed_binding_verifies() {
        let b = IdentityBinding::build(draft(), &key()).unwrap();
        assert!(b.binding_id.starts_with("vib_"));
        b.verify().unwrap();
    }

    #[test]
    fn binding_signed_by_other_key_fails_possession() {
        let mut b = IdentityBinding::build(draft(), &key()).unwrap();
        // Swap in a different key's pubkey: the signature no longer matches the
        // bound key, so proof-of-possession fails.
        b.public_key_hex = hex::encode(key().verifying_key().to_bytes());
        assert!(b.verify().is_err());
    }

    #[test]
    fn self_revocation_is_authoritative_and_foreign_is_not() {
        let k = key();
        let b = IdentityBinding::build(draft(), &k).unwrap();
        let rev = IdentityRevocation::build(
            IdentityRevocationDraft {
                binding_id: b.binding_id.clone(),
                reason: "key rotated".into(),
                revoked_at: "2026-06-10T00:00:00Z".into(),
            },
            &k,
        )
        .unwrap();
        assert!(rev.authoritatively_revokes(&b), "same key must revoke");

        // A revocation by a different key targeting the same binding is NOT authoritative.
        let foreign = IdentityRevocation::build(
            IdentityRevocationDraft {
                binding_id: b.binding_id.clone(),
                reason: "malicious".into(),
                revoked_at: "2026-06-10T00:00:00Z".into(),
            },
            &key(),
        )
        .unwrap();
        assert!(
            !foreign.authoritatively_revokes(&b),
            "foreign key cannot revoke"
        );
    }
}
