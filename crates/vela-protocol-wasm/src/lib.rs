//! WASM bindings for vela-protocol's Conjecture + ProofPacket primitives.
//!
//! Consumed by `atlas-platform`'s Next.js app to replace the parallel
//! TypeScript reimplementations in `apps/atlas/lib/substrate/*.ts`
//! with the canonical Rust implementation. Read-only paths (`verify`,
//! `verify_external_verifications`) ship first because they don't need
//! `getrandom` and work in any WASM runtime including Vercel
//! serverless. Write paths (`build`, `cosign`) need rand and will
//! ship in a follow-up that wires the `getrandom = { features = ["js"] }`
//! feature for browser/serverless environments.
//!
//! Build:
//!   cd ~/personal/vela
//!   wasm-pack build crates/vela-protocol-wasm --target web --release
//!
//! Atlas-side consumption (after R.4.b lands):
//!   import { verifyConjecture, verifyProofPacket } from
//!     "vela-protocol-wasm";

use serde_wasm_bindgen::{from_value, to_value};
use vela_protocol_core::conjecture::Conjecture;
use vela_protocol_core::proof_packet::ProofPacket;
use wasm_bindgen::prelude::*;

/// Verify a Conjecture JSON-serialized object. Returns `Ok(())` (an
/// empty JS object) on success, throws on error.
///
/// Equivalent to:
///   let c: Conjecture = serde_json::from_str(json)?;
///   c.verify()?;
#[wasm_bindgen(js_name = verifyConjecture)]
pub fn verify_conjecture(value: JsValue) -> Result<JsValue, JsValue> {
    let c: Conjecture = from_value(value).map_err(|e| JsValue::from_str(&format!("{e}")))?;
    c.verify().map_err(|e| JsValue::from_str(&e))?;
    to_value(&serde_json::json!({
        "ok": true,
        "id": c.id,
        "status": c.status,
        "witness": c.witness.actor_id,
        "signatures": c.signatures.len(),
    }))
    .map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Verify every co-signature on a Conjecture. Returns the count of
/// valid co-signatures.
#[wasm_bindgen(js_name = verifyConjectureCosignatures)]
pub fn verify_conjecture_cosignatures(value: JsValue) -> Result<u32, JsValue> {
    let c: Conjecture = from_value(value).map_err(|e| JsValue::from_str(&format!("{e}")))?;
    c.verify_cosignatures()
        .map(|n| n as u32)
        .map_err(|e| JsValue::from_str(&e))
}

/// Verify a ProofPacket: recompute canonical hash, verify hash bytes
/// against signature under declared pubkey.
#[wasm_bindgen(js_name = verifyProofPacket)]
pub fn verify_proof_packet(value: JsValue) -> Result<JsValue, JsValue> {
    let p: ProofPacket = from_value(value).map_err(|e| JsValue::from_str(&format!("{e}")))?;
    p.verify().map_err(|e| JsValue::from_str(&e))?;
    to_value(&serde_json::json!({
        "ok": true,
        "packet_id": p.packet_id,
        "hash": p.packet_hash,
        "kind": p.kind,
        "signer": p.signer_actor_id,
        "external_verifications": p.external_verifications.len(),
    }))
    .map_err(|e| JsValue::from_str(&format!("{e}")))
}

/// Verify every external_verification on a ProofPacket. Returns the
/// count of valid co-signatures.
#[wasm_bindgen(js_name = verifyProofPacketExternals)]
pub fn verify_proof_packet_externals(value: JsValue) -> Result<u32, JsValue> {
    let p: ProofPacket = from_value(value).map_err(|e| JsValue::from_str(&format!("{e}")))?;
    p.verify_external_verifications()
        .map(|n| n as u32)
        .map_err(|e| JsValue::from_str(&e))
}

/// Recompute a ProofPacket's canonical hash without verifying the
/// signature. Useful for tools that want to confirm hash stability
/// independently.
#[wasm_bindgen(js_name = computeProofPacketHash)]
pub fn compute_proof_packet_hash(value: JsValue) -> Result<String, JsValue> {
    let p: ProofPacket = from_value(value).map_err(|e| JsValue::from_str(&format!("{e}")))?;
    p.compute_hash().map_err(|e| JsValue::from_str(&e))
}

/// Return the schema version string this WASM build was compiled with.
/// Atlas can compare against its expected version on load.
#[wasm_bindgen(js_name = schemaVersion)]
pub fn schema_version() -> JsValue {
    JsValue::from_str(concat!(
        env!("CARGO_PKG_VERSION"),
        " · vela.conjecture.v0.1 · vela.proof_packet.v0.1"
    ))
}
