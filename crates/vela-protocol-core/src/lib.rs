//! vela-protocol-core — minimal-dependency core types for the Vela protocol.
//!
//! Lives separately from the full `vela-protocol` crate so it can
//! target `wasm32-unknown-unknown` without dragging in tokio / sqlx /
//! reqwest / axum / hyper. The full `vela-protocol` crate re-exports
//! these types, so server code keeps importing from `vela_protocol::*`.
//!
//! v0.338.0 (Atlas R.4.b unblock) extracted modules:
//! - `conjecture` — Conjecture primitive (signed forward institutional
//!   claims with mechanical falsification paths). `vcj_*` ids.
//! - `proof_packet` — ProofPacket primitive (hash-stable signature-
//!   verifiable receipts for external verification). `pp_*` ids.

pub mod conjecture;
pub mod proof_packet;
