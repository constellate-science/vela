//! Frontier validation, linting, conformance, grading, normalization, permissions.
//! Re-exported flat (`vela_edge::*`) at the crate root; file organization only.

pub mod conformance;
pub mod deliverable_grade;
pub mod lint;
pub mod normalize;
pub mod permission;
pub mod state_integrity;
pub mod validate;
