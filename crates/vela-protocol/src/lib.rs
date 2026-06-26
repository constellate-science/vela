//! The Vela protocol kernel: the typed, content-addressed substrate that turns
//! scientific activity into signed, replayable state.
//!
//! Layering (a module's tier, not its file location):
//! - **kernel** — the trust-critical core: `events` (canonical event types),
//!   `reducer` (the deterministic frontier state machine), `sign` (Ed25519),
//!   `bundle` (proof packets), `canonical` (canonical bytes/ids), `repo` (I/O).
//! - **state** — computed views over the log: `state`, `registry`, `frontier_repo`.
//! - **analysis** — derived, non-authoritative projections: `atlas`, `transfer`,
//!   `verifier_attachment`, `status_provenance`, `frontier_graph`, `boundary`,
//!   `contradiction`, `evidence_diff`.
//! - **policy** — governance: `acceptance_policy`, `frontier_policy`, `tcb_policy`,
//!   `access_tier`.
//! - **domains** — domain profiles: `sidon_profile`, `lean_verification`.
//!
//! Id prefixes (content-addressed unless noted): `vf_` finding, `vev_` signed
//! event, `vfr_` frontier, `vpr_` proposal, `val_` signed anchor, `vtr_` signed
//! transfer, `vva_` verifier attachment, `vsa_` statement attestation. Authority
//! is key custody: an agent may draft, only a key-holding human signs an accept.

pub mod acceptance_policy;
pub mod access_tier;
pub mod activity;
pub mod anchor;
pub mod atlas;
pub mod attempt;
pub mod boundary;
pub mod bundle;
pub mod canonical;
pub mod cli_style;
pub mod contradiction;
pub mod diff;
pub mod diff_pack_review;
pub mod endorsement;
pub mod events;
pub mod evidence_ci;
pub mod evidence_diff;
pub mod frontier_bound;
pub mod frontier_graph;
pub mod frontier_policy;
pub mod frontier_repo;
pub mod frontier_template;
pub mod identity;
pub mod lean_verification;
pub mod merkle;
pub mod nanopub;
pub mod pathfind;
pub mod project;
pub mod proof_verification;
pub mod propagate;
pub mod proposals;
pub mod reducer;
pub mod registry;
pub mod released_diff_pack;
pub mod repo;
pub mod scientific_diff;
pub mod sidon_profile;
pub mod sign;
pub mod sources;
pub mod state;
pub mod statement_attestation;
pub mod status_provenance;
pub mod tcb_policy;
pub mod transfer;
pub mod transfer_registry;
pub mod verdict_conflict;
pub mod verifier_attachment;
pub mod workspace;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
