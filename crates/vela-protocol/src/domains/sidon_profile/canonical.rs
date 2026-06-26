//! Canonical encoding and content identifiers for the Vela Sidon Producer
//! Profile v1.
//!
//! This is a DISTINCT, domain-separated scheme from [`crate::canonical`]. The
//! producer profile commits to a restricted JSON value domain — null, boolean,
//! integer, NFC-normalized string, array, and string-keyed object; floats are
//! forbidden — and hashes a domain-tagged preimage. It exists so the Rust,
//! Python, and TypeScript producer implementations derive byte-identical
//! packet IDs and roots.
//!
//! The reference implementation is
//! `research/sidon-producer-profile/reference/canonical.py`; the
//! `tests/sidon_profile_conformance.rs` test pins this Rust port against the
//! landed fixtures (every recomputed packet ID must equal the Python-generated
//! one, byte for byte).
//!
//! ## Why this matches the Python reference byte for byte
//!
//! Python encodes with `json.dumps(sort_keys=True, separators=(",", ":"),
//! ensure_ascii=False, allow_nan=False)`. For this value domain that is
//! identical to `serde_json`'s compact output:
//!   - keys sorted lexicographically by Unicode scalar order (Rust `str` `Ord`
//!     over UTF-8 equals Python's default string sort);
//!   - no inter-token whitespace;
//!   - integers in plain decimal form;
//!   - the same string escaping (`\"`, `\\`, the five short escapes, and the
//!     six-character `\u00XX` form for the remaining C0 controls), with all
//!     non-ASCII emitted as raw UTF-8.
//!
//! The only profile-specific steps `serde_json` does not perform — NFC
//! normalization, float rejection, post-NFC duplicate-key rejection, and the
//! `CANON_DOMAIN` hash prefix — are applied here explicitly.

use std::collections::BTreeMap;

use serde_json::Value;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// Domain tag prepended to the canonical bytes before hashing. Matches
/// `CANON_DOMAIN` in the Python reference.
pub const CANON_DOMAIN: &[u8] = b"vela.canonical-json-subset.v1\x00";

/// Normalize a value into the canonical JSON subset, recursively:
///   - `null` / booleans / integers pass through;
///   - floats are rejected (the profile forbids non-integer numbers);
///   - strings and object keys are NFC-normalized;
///   - keys that collide after NFC normalization are rejected.
///
/// Object keys are sorted here (via [`BTreeMap`]) so the subsequent
/// `serde_json` serialization is key-sorted regardless of whether the
/// `preserve_order` feature is enabled.
fn normalize(value: &Value, path: &str) -> Result<Value, String> {
    match value {
        Value::Null | Value::Bool(_) => Ok(value.clone()),
        Value::Number(n) => {
            if n.is_f64() {
                return Err(format!("floating-point value forbidden at {path}"));
            }
            Ok(value.clone())
        }
        Value::String(s) => Ok(Value::String(s.nfc().collect::<String>())),
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for (i, item) in items.iter().enumerate() {
                out.push(normalize(item, &format!("{path}[{i}]"))?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(map) => {
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (key, child) in map {
                let nkey: String = key.nfc().collect();
                let nchild = normalize(child, &format!("{path}.{nkey}"))?;
                if sorted.insert(nkey.clone(), nchild).is_some() {
                    return Err(format!(
                        "duplicate key after NFC normalization at {path}: {nkey:?}"
                    ));
                }
            }
            // Re-insert in sorted order: with `preserve_order` off the Map is
            // a BTreeMap (already sorted); with it on the Map is an IndexMap
            // that keeps this sorted insertion order. Either way the output is
            // key-sorted.
            let mut obj = serde_json::Map::with_capacity(sorted.len());
            for (key, child) in sorted {
                obj.insert(key, child);
            }
            Ok(Value::Object(obj))
        }
    }
}

/// The canonical UTF-8 bytes of a value: NFC-normalized, float-free, with
/// object keys sorted and no inter-token whitespace.
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let normalized = normalize(value, "$")?;
    serde_json::to_vec(&normalized).map_err(|e| format!("sidon canonical: serialize failed: {e}"))
}

/// SHA-256 over `CANON_DOMAIN || canonical_bytes(value)`, as lowercase hex.
pub fn sha256_value(value: &Value) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hasher.update(CANON_DOMAIN);
    hasher.update(canonical_bytes(value)?);
    Ok(hex::encode(hasher.finalize()))
}

/// The `sha256:`-prefixed digest form used for artifact and claim digests.
pub fn digest(value: &Value) -> Result<String, String> {
    Ok(format!("sha256:{}", sha256_value(value)?))
}

/// A content identifier: `prefix || sha256_value(value)`. The prefix must end
/// with `_` (e.g. `vop_`, `vsf_`).
pub fn content_id(prefix: &str, value: &Value) -> Result<String, String> {
    if !prefix.ends_with('_') {
        return Err("content-id prefix must end with '_'".to_string());
    }
    Ok(format!("{prefix}{}", sha256_value(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sort_at_every_depth_compact() {
        let v = json!({"z": 1, "a": {"y": 2, "b": 3}, "m": [{"q": 4, "p": 5}]});
        let bytes = canonical_bytes(&v).unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"a":{"b":3,"y":2},"m":[{"p":5,"q":4}],"z":1}"#
        );
    }

    #[test]
    fn floats_are_rejected() {
        let v = json!({"x": 1.5});
        assert!(canonical_bytes(&v).is_err());
    }

    #[test]
    fn integers_pass_through() {
        assert_eq!(
            String::from_utf8(canonical_bytes(&json!({"k": 6})).unwrap()).unwrap(),
            r#"{"k":6}"#
        );
    }

    #[test]
    fn nul_in_string_escapes_to_six_chars() {
        // A NUL inside a string must encode as the six characters
        // backslash-u-0-0-0-0, matching Python's json.dumps(ensure_ascii=False).
        // The packet-id domain string ("vela.packet-id.v1\0") relies on this.
        let v = json!({ "domain": "x\u{0}" });
        let s = String::from_utf8(canonical_bytes(&v).unwrap()).unwrap();
        assert_eq!(s, "{\"domain\":\"x\\u0000\"}");
    }

    #[test]
    fn content_id_requires_trailing_underscore() {
        assert!(content_id("vop", &json!({})).is_err());
        assert!(content_id("vop_", &json!({})).is_ok());
    }

    #[test]
    fn non_ascii_is_raw_not_escaped() {
        let v = json!({"t": "amyloid-beta-\u{03b2}"});
        let s = String::from_utf8(canonical_bytes(&v).unwrap()).unwrap();
        assert!(s.contains('\u{03b2}'));
        assert!(!s.contains("\\u"));
    }
}
