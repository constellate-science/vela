//! The one signing rule.
//!
//! Every signature in Vela is taken over the bytes returned by
//! [`signing_input`]. Before this, each object hand-assembled its own canonical
//! preimage and signed it directly, so a second producer had to reimplement
//! each builder to verify. Now the per-object builders produce a canonical body
//! and frame it through this single function, so the signing rule is one place.
//!
//! Two versions, and the version is the migration seam (`docs/TRUST_MODEL_REDESIGN.md`
//! sections 3 and 12):
//!
//! - **v0** is the historical form: the raw canonical body, byte-identical to
//!   the pre-facade builders. Every existing signature verifies under it.
//! - **v1** frames the body with DSSE Pre-Authentication Encoding (PAE), which
//!   binds both a typed media string and the body length under the signature.
//!
//! v1 is wired but not yet the default: the flip to v1 for new signatures, and
//! the re-sign that retires v0, are later phases. PAE does NOT remove canonical
//! JSON: the body is still the RFC-8785 canonicalization used to mint ids and
//! log hashes. The win is one typed byte-framing rule a producer can implement
//! by concatenation.

/// Signing-input version. The marker that selects the framing rule, carried per
/// signature so historical v0 signatures keep verifying after v1 lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigVersion {
    /// Raw canonical body, byte-identical to the pre-facade builders.
    #[default]
    V0,
    /// DSSE/PAE-framed body.
    V1,
}

/// DSSE Pre-Authentication Encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`, with lengths in ASCII
/// decimal. Binds the payload type and the exact body bytes under one signature.
#[must_use]
pub fn pae(payload_type: &str, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload_type.len() + body.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(body.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(body);
    out
}

/// The bytes that go under a signature. `body` is the object's canonical
/// (RFC-8785) JSON. v0 returns it unchanged, so routing a builder through this
/// is byte-identical to signing the canonical body directly; v1 frames it with
/// [`pae`].
#[must_use]
pub fn signing_input(version: SigVersion, payload_type: &str, body: &[u8]) -> Vec<u8> {
    match version {
        SigVersion::V0 => body.to_vec(),
        SigVersion::V1 => pae(payload_type, body),
    }
}

/// Versioned Vela media types, one per signed object. The type is authenticated
/// under v1 (it enters the PAE frame) but never enters an id or log-hash
/// preimage, so historical ids are untouched by the facade.
pub mod payload_type {
    pub const EVENT: &str = "application/vnd.vela.event+json";
    pub const PROPOSAL: &str = "application/vnd.vela.proposal+json";
    pub const STATEMENT_ATTESTATION: &str = "application/vnd.vela.statement_attestation+json";
    pub const ANCHOR: &str = "application/vnd.vela.anchor+json";
    pub const ACCEPT: &str = "application/vnd.vela.accept+json";
    pub const ACTIVITY_RECORD: &str = "application/vnd.vela.activity_record+json";
    pub const REGISTRY_DEPRECATION: &str = "application/vnd.vela.registry.deprecation+json";
    pub const REGISTRY_GIT_REMOTE: &str = "application/vnd.vela.registry.git_remote+json";
    pub const REGISTRY_ROTATION: &str = "application/vnd.vela.registry.rotation+json";
    pub const REGISTRY_MAINTAINER: &str = "application/vnd.vela.registry.maintainer+json";
    pub const REGISTRY_ENTRY: &str = "application/vnd.vela.registry.entry+json";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v0_is_identity_on_the_body() {
        // The byte-identity contract: routing any builder through v0 must equal
        // signing the canonical body directly, so existing signatures and the
        // gate are untouched. If this ever drifts, every stored signature breaks
        // loudly here instead of silently failing to verify.
        let body = br#"{"a":1,"b":"x"}"#;
        assert_eq!(
            signing_input(SigVersion::V0, payload_type::EVENT, body),
            body
        );
    }

    #[test]
    fn pae_frames_type_and_length() {
        let body = b"hello";
        let framed = signing_input(SigVersion::V1, "t", body);
        assert_eq!(framed, b"DSSEv1 1 t 5 hello");
    }

    #[test]
    fn v0_and_v1_differ() {
        // The flip must change the signed bytes, so a v1 signature can never be
        // mistaken for a v0 one over the same body.
        let body = b"x";
        assert_ne!(
            signing_input(SigVersion::V0, payload_type::EVENT, body),
            signing_input(SigVersion::V1, payload_type::EVENT, body)
        );
    }
}
