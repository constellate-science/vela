//! Canonical-hashing conformance — pins `vela.canonical-json/v1`.
//!
//! `conformance/canonical-hashing.json` is the portable spec of the canonical
//! JSON form every content-addressed id hashes (see
//! `vela-protocol/src/canonical.rs`). Each vector fixes an input value, its
//! exact canonical string, and the SHA-256 of those bytes. This test asserts
//! the Rust implementation reproduces both byte-for-byte, so any other
//! implementation (the Python `vev_` re-verifier, a future client) can pin
//! itself to the same vectors and know its content-addresses will match.

use std::path::PathBuf;

use serde_json::Value;
use vela_protocol::canonical::{sha256_canonical, to_canonical_string};

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("canonical-hashing.json")
}

#[test]
fn canonical_hashing_vectors_match_rust() {
    let raw = std::fs::read_to_string(vectors_path()).expect("read canonical-hashing.json");
    let doc: Value = serde_json::from_str(&raw).expect("parse canonical-hashing.json");
    assert_eq!(
        doc["format_id"], "vela.canonical-json/v1",
        "vector file pins the wrong format id"
    );
    let vectors = doc["vectors"].as_array().expect("vectors is an array");
    assert!(!vectors.is_empty(), "no vectors to check");

    for v in vectors {
        let name = v["name"].as_str().unwrap_or("<unnamed>");
        let input = &v["input"];
        let want_canon = v["canonical"]
            .as_str()
            .expect("vector has canonical string");
        let want_sha = v["sha256"].as_str().expect("vector has sha256");

        let got_canon = to_canonical_string(input)
            .unwrap_or_else(|e| panic!("vector {name}: canonicalize failed: {e}"));
        assert_eq!(
            got_canon, want_canon,
            "vector {name}: canonical string diverged\n  want: {want_canon}\n  got:  {got_canon}"
        );

        let got_sha =
            sha256_canonical(input).unwrap_or_else(|e| panic!("vector {name}: sha256 failed: {e}"));
        assert_eq!(
            got_sha, want_sha,
            "vector {name}: sha256 diverged (canonical bytes differ from the pinned form)"
        );
    }
}

#[test]
fn non_finite_floats_cannot_reach_a_content_address() {
    // A NaN/Inf must never hash to an implementation-defined string. Two
    // layers enforce this: (1) `serde_json::Value` cannot hold a non-finite
    // number — it coerces to `null` at construction, so it can never reach
    // canonicalization as a Number; (2) for the rarer path where a custom
    // `Serialize` impl emits a non-finite Number, `canonical.rs` rejects it.
    // This test pins layer (1): NaN is neutralized to `null` before hashing,
    // so the canonical form is well-defined and finite either way.
    let nan = serde_json::json!({ "x": f64::NAN });
    let canon = to_canonical_string(&nan).expect("NaN coerced to null is canonicalizable");
    assert_eq!(
        canon, "{\"x\":null}",
        "non-finite float must coerce to null, never survive into a content-address"
    );
}
