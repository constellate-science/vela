//! The trust-critical core: canonical events, the deterministic reducer, Ed25519 signing, proof bundles, canonical bytes/ids, frontier I/O.
//! Re-exported flat at the crate root; this grouping is file organization only.

pub mod bundle;
pub mod canonical;
pub mod events;
pub mod reducer;
pub mod repo;
pub mod sign;
