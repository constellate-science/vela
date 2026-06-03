//! Canonical JSON serialization for content-addressed Vela primitives.
//!
//! Every content-addressed ID in the protocol — `vf_…` (finding),
//! `vev_…` (canonical event), `vpr_…` (proposal), the snapshot hash, the
//! event-log hash — is derived by hashing the canonical JSON bytes of a
//! value. For two implementations to produce identical IDs from the same
//! logical content, the serialization MUST be deterministic.
//!
//! `serde_json::to_vec` is not deterministic: it preserves declaration
//! order for structs but order is implementation-dependent for maps that
//! contain `serde_json::Value::Object`, and there is no whitespace
//! contract. This module produces a canonical form:
//!
//!   - Object keys are sorted lexicographically by string comparison
//!     (recursively, at every depth).
//!   - No whitespace between tokens.
//!   - Number formatting follows `serde_json`'s default round-trip rules
//!     (which use Ryu for floats — shortest decimal that round-trips).
//!   - Strings use standard JSON escaping. UTF-8 input is preserved
//!     verbatim; non-ASCII characters are NOT `\u`-escaped.
//!
//! In spirit this matches RFC 8785 (JSON Canonicalization Scheme) for the
//! subset of values Vela emits — sorted keys, compact output, deterministic
//! number form. Conformance vectors at `tests/conformance/canonical-hashing.json`
//! pin the exact output for a small set of inputs so any v0.3 implementation
//! can verify byte-for-byte equivalence.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

/// Serialize `value` to canonical JSON bytes.
///
/// Returns the canonical UTF-8 byte representation of the value, suitable
/// for hashing into a content-addressed ID. Two callers serializing the
/// same logical value produce byte-identical output.
///
/// # Errors
///
/// Returns an error if `value` cannot be serialized as JSON, contains
/// non-finite floats (NaN, ±Inf), or is otherwise invalid JSON.
pub fn to_canonical_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, String> {
    let v = serde_json::to_value(value)
        .map_err(|e| format!("canonical: serialize to value failed: {e}"))?;
    let canon = canonicalize(v)?;
    serde_json::to_vec(&canon)
        .map_err(|e| format!("canonical: serialize canonical form failed: {e}"))
}

/// String version of `to_canonical_bytes` for callers that want UTF-8 text.
///
/// Always valid UTF-8 because the bytes are JSON.
pub fn to_canonical_string<T: Serialize + ?Sized>(value: &T) -> Result<String, String> {
    let bytes = to_canonical_bytes(value)?;
    String::from_utf8(bytes).map_err(|e| format!("canonical: invalid utf-8: {e}"))
}

/// Walk a `Value`, sorting object keys recursively. Float values are
/// validated to be finite (NaN / ±Inf are rejected).
fn canonicalize(value: Value) -> Result<Value, String> {
    match value {
        Value::Object(map) => {
            // Re-insert into a BTreeMap to get lexicographic key ordering,
            // then convert back to serde_json::Map. The result preserves
            // the sort order on serialization because serde_json's `Map`
            // is itself BTreeMap-backed by default.
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k, canonicalize(v)?);
            }
            let mut out = serde_json::Map::with_capacity(sorted.len());
            for (k, v) in sorted {
                out.insert(k, v);
            }
            Ok(Value::Object(out))
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(canonicalize(item)?);
            }
            Ok(Value::Array(out))
        }
        Value::Number(ref n) => {
            // Reject non-finite floats. serde_json::Number itself can't
            // represent NaN / ±Inf in a roundtrip-safe way; if one ever
            // sneaks in via a custom Serialize impl, refuse.
            if let Some(f) = n.as_f64()
                && !f.is_finite()
            {
                return Err("canonical: non-finite float in input".to_string());
            }
            Ok(value)
        }
        // Strings, bools, null pass through.
        other => Ok(other),
    }
}

/// SHA-256 of the canonical bytes, returned as lowercase hex.
///
/// The single function used everywhere the protocol derives a
/// content-addressed ID. Replaces every ad-hoc
/// `serde_json::to_vec(...) + Sha256::digest(...)` pattern in the kernel.
pub fn sha256_canonical<T: Serialize + ?Sized>(value: &T) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let bytes = to_canonical_bytes(value)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_keys_sort_at_every_depth() {
        let unordered = json!({
            "z": 1,
            "a": {
                "y": 2,
                "b": 3,
            },
            "m": [{"q": 4, "p": 5}],
        });
        let canon = to_canonical_string(&unordered).unwrap();
        // Keys at every depth must appear in lexicographic order.
        assert_eq!(canon, r#"{"a":{"b":3,"y":2},"m":[{"p":5,"q":4}],"z":1}"#);
    }

    #[test]
    fn whitespace_is_stripped() {
        let v = json!({"key": "value"});
        let canon = to_canonical_string(&v).unwrap();
        assert!(!canon.contains(' '));
        assert!(!canon.contains('\n'));
    }

    #[test]
    fn array_order_is_preserved() {
        let v = json!([3, 1, 2]);
        let canon = to_canonical_string(&v).unwrap();
        assert_eq!(canon, "[3,1,2]");
    }

    #[test]
    fn unicode_strings_pass_through() {
        let v = json!({"text": "amyloid-β"});
        let canon = to_canonical_string(&v).unwrap();
        assert!(canon.contains("amyloid-β"));
    }

    #[test]
    fn same_logical_content_produces_same_bytes() {
        let a = json!({"x": 1, "y": 2});
        let b = json!({"y": 2, "x": 1});
        let bytes_a = to_canonical_bytes(&a).unwrap();
        let bytes_b = to_canonical_bytes(&b).unwrap();
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn sha256_canonical_is_stable() {
        let a = json!({"hello": "world"});
        let h1 = sha256_canonical(&a).unwrap();
        let h2 = sha256_canonical(&a).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }
}
