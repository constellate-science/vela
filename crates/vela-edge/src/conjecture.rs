//! v0.338 (Atlas R.1) → v0.338 R.4.b unblock: re-export from
//! vela-protocol-core.
//!
//! The Conjecture primitive lives in `vela-protocol-core` so it can
//! target wasm32 without dragging in the full vela-protocol crate's
//! server-side deps (tokio, sqlx, reqwest, axum). This file re-exports
//! the core types so consumers of vela-protocol keep their existing
//! imports working unchanged.

pub use vela_protocol_core::conjecture::*;
