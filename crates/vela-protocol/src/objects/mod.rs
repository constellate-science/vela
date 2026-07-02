//! Record/identity object types: anchors, attempts, attestations, identity, merkle, styling.
//! Re-exported flat at the crate root; this grouping is file organization only.

pub mod activity;
pub mod anchor;
pub mod attempt;
pub mod cli_style;
pub mod frontier_template;
pub mod identity;
pub mod merkle;
pub mod nanopub;
pub mod provenance;
pub mod receipt;
pub mod statement_attestation;
#[path = "policy.rs"]
pub mod verification_policy;
pub mod verification_summary;
