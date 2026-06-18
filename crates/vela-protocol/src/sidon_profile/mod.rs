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
//!     IDs, and Ed25519 signatures);
//!   - [`kernel`] — the finite, positive, ranked Scientific State Kernel:
//!     composed bag-lineage `Gamma_P`, the four roots, and minimal environments;
//!   - [`evaluator`] — the `vela.sidon.best-lower-bound.v1` evaluator and the
//!     authoritative-read observation replay.
//!
//! Later layers (the reducer that compiles accepted events into clauses, the
//! `vela sidon` CLI surface, and the HTTP observation endpoint) land on top.

pub mod canonical;
pub mod evaluator;
pub mod frontier;
pub mod kernel;
pub mod packets;
pub mod producer;

pub use canonical::{CANON_DOMAIN, canonical_bytes, content_id, digest, sha256_value};
pub use evaluator::{
    EVALUATOR_ID, FRONTIER_ID, PROFILE_ID, RULE_ATOM, VIEW_POLICY_ID, append_verified_route,
    best_bounds, bound_cell, claim, current_bound, register_bound_metadata, state_commitment,
    verify_observation_replay, witness_cell,
};
pub use frontier::{
    Obligation, build_frontier_map, frontier_transition, next_bound_obligations,
    obligation_discharged, obligation_status, verify_positive_gap_monotonicity,
};
pub use kernel::{
    Clause, Monomial, Polynomial, Presentation, active_environments, active_view_root,
    compile_gamma, evaluator_digest, is_hitting_set, lineage_root, minimal_environments, supported,
};
pub use packets::{
    PACKET_ID_DOMAIN, SCHEMA_VERSION, SIGNATURE_DOMAIN, deterministic_signing_key, packet_body,
    packet_id, prefix_for, public_key_b64, signed_packet, signing_preimage, verify_signed_packet,
};
pub use producer::{
    fixture_time, make_observation, make_result, make_support_function, make_task, validate_shape,
};
