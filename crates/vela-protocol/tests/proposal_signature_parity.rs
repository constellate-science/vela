//! TS↔Rust proposal-signing parity.
//!
//! The in-browser BYO-key Claim Request path (apps/web: lib/proposal-canonical
//! + lib/proposal-sign, @noble/ed25519) signs a StateProposal client-side and
//! POSTs it straight to the hub. This test pins that the bytes signed in the
//! browser are byte-identical to the bytes the hub verifies: it loads a
//! TS-generated, deterministic fixture and checks both invariants the hub
//! checks at the propose boundary —
//!
//!   1. the content-addressed `vpr_` id recomputes from the proposal, and
//!   2. the detached Ed25519 signature verifies over the canonical signing
//!      preimage against the signer's pubkey.
//!
//! If the TS canonicalization or either preimage shape ever drifts from
//! `vela_protocol::{canonical, sign}`, this test fails. Regenerate the fixture
//! with `bun run apps/web/scripts/gen-proposal-parity-fixture.ts` (only needed
//! when the wire shape legitimately changes).

use vela_protocol::proposals::{StateProposal, proposal_id};
use vela_protocol::sign::verify_proposal_signature;

const FIXTURE: &str = include_str!("fixtures/ts_signed_proposal.json");

#[test]
fn ts_signed_proposal_verifies_in_rust() {
    let fixture: serde_json::Value = serde_json::from_str(FIXTURE).expect("parse fixture json");

    let pubkey_hex = fixture["pubkey_hex"].as_str().expect("pubkey_hex");
    let signature_hex = fixture["signature_hex"].as_str().expect("signature_hex");
    let proposal: StateProposal =
        serde_json::from_value(fixture["proposal"].clone()).expect("deserialize StateProposal");

    // 1. Content address: the TS-computed vpr_ id matches the Rust recompute.
    assert_eq!(
        proposal_id(&proposal),
        proposal.id,
        "TS proposal_id diverged from the Rust content address (canonical id preimage drift)"
    );

    // 2. Signature: the TS detached signature verifies over the Rust signing
    //    preimage. This is the load-bearing cross-impl check.
    let ok = verify_proposal_signature(&proposal, signature_hex, pubkey_hex)
        .expect("verify_proposal_signature should not error on a well-formed fixture");
    assert!(
        ok,
        "TS-signed proposal failed Rust signature verification — the browser \
         signing preimage is not byte-identical to sign::proposal_signing_bytes"
    );
}
