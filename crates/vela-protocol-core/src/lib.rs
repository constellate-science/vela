//! vela-protocol-core — minimal-dependency core types for the Vela protocol.
//!
//! Lives separately from the full `vela-protocol` crate so it can
//! target `wasm32-unknown-unknown` without dragging in tokio / sqlx /
//! reqwest / axum / hyper. Consumers import these types directly from
//! `vela_protocol_core::*` (the web/wasm path) or via the thin
//! `vela_edge::{conjecture, proof_packet}` re-export shims (server code);
//! `vela-protocol` itself does not depend on this crate.
//!
//! v0.338.0 (Atlas R.4.b unblock) extracted modules:
//! - `conjecture` — Conjecture primitive (signed forward institutional
//!   claims with mechanical falsification paths). `vcj_*` ids.
//! - `proof_packet` — ProofPacket primitive (hash-stable signature-
//!   verifiable receipts for external verification). `pp_*` ids.

pub mod conjecture;
pub mod proof_packet;
