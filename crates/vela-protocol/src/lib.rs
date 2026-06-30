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

mod kernel;
pub use kernel::{bundle, canonical, events, reducer, repo, sign};
mod computed;
pub use computed::{
    frontier_repo, project, registry, sources, state, transfer_registry, workspace,
};
mod analysis;
pub use analysis::{
    atlas, boundary, contradiction, diff, diff_pack_review, evidence_ci, evidence_diff,
    frontier_bound, frontier_graph, pathfind, propagate, released_diff_pack, scientific_diff,
    status_provenance, transfer, verdict_conflict, verifier_attachment,
};
mod policy;
pub use policy::{acceptance_policy, access_tier, endorsement, frontier_policy, tcb_policy};
mod domains;
pub use domains::{lean_verification, proof_verification, sidon_profile};
mod objects;
pub use objects::{
    activity, anchor, attempt, cli_style, frontier_template, identity, merkle, nanopub, provenance,
    statement_attestation,
};

pub mod proposals;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
