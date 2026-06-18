//! The Vela Sidon Producer Profile v1 — the production realization of the
//! finite, positive, ranked Scientific State Kernel for one live frontier:
//! lower bounds for OEIS A309370 (Sidon sets in the binary cube).
//!
//! This module is the Rust side of a three-implementation conformance contract
//! (Rust / Python / TypeScript). The Python reference and the deterministic
//! fixtures live under `research/sidon-producer-profile/`; this port must agree
//! with them byte for byte on packet IDs, signatures, and the committed roots.
//! See `docs/SIDON_PRODUCER_PROFILE_V1.md` for the profile specification and
//! `docs/RUST_VERTICAL_SLICE.md` for the production path this realizes.
//!
//! The scheme is built up in verified layers:
//!   - [`canonical`] — the domain-separated canonical JSON subset and content
//!     identifiers (the bedrock every ID and root commits to);
//!   - [`packets`] — the signed packet envelope (the nine packet types, their
//!     IDs, and Ed25519 signatures).
//!
//! Later layers (composed lineage circuit, active-view restriction, the
//! `vela.sidon.best-lower-bound.v1` observation evaluator, and explicit
//! staleness resolution) land on top of this bedrock.

pub mod canonical;
pub mod packets;

pub use canonical::{CANON_DOMAIN, canonical_bytes, content_id, digest, sha256_value};
pub use packets::{
    PACKET_ID_DOMAIN, SCHEMA_VERSION, SIGNATURE_DOMAIN, deterministic_signing_key, packet_body,
    packet_id, prefix_for, public_key_b64, signed_packet, signing_preimage, verify_signed_packet,
};
