//! Content-addressed schema/reducer artifacts.
//!
//! Implements the schema-artifact part of `docs/THEORY.md`
//! Section 5.1, where event tuples reference a content-addressed
//! `schema` field that pins the replay semantics:
//!
//! > schema = content-addressed schema and reducer reference
//!
//! And §5.5:
//!
//! > Schema and reducer artifacts are fixed by content hash.
//!
//! ## What this module ships
//!
//! - [`SchemaArtifact`]: a typed, content-addressed artifact whose
//!   id is the SHA-256 of its canonical content.
//! - [`SchemaRegistry`]: a registry mapping artifact id to artifact,
//!   used to verify that an event references a known schema before
//!   replay.
//! - Verification primitives that future event-replay code can call
//!   to check schema availability and detect schema drift.
//!
//! ## What this module does NOT do
//!
//! It does not yet replace the existing `StateEvent::schema: String`
//! version-tag field. That replacement is a wider substrate change
//! (target v0.85+) that ripples into canonicalization,
//! event-id derivation, and existing event-set hashes. This module
//! ships the artifact + registry primitive on which that
//! replacement will sit.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A content-addressed schema or reducer artifact.
///
/// The `id` is derived from the canonical serialization of
/// `(name, version, body)`. Equal artifacts have equal ids;
/// different artifacts have ids that differ except with negligible
/// probability under SHA-256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaArtifact {
    /// Content-addressed id, prefixed with `vsa_` (Vela Schema
    /// Artifact). This is `H(canonical(name, version, body))`.
    pub id: String,
    /// Human-readable name (e.g. `vela.event.finding_asserted`).
    pub name: String,
    /// Semver-style version string (e.g. `v0.1`).
    pub version: String,
    /// Body of the artifact: the actual schema or reducer
    /// specification, kept as a JSON value to avoid committing to
    /// any one schema language at the substrate layer.
    pub body: serde_json::Value,
}

impl SchemaArtifact {
    /// Build a new artifact, computing the content-addressed id
    /// from the canonical serialization of `(name, version, body)`.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        body: serde_json::Value,
    ) -> Result<Self, String> {
        let name = name.into();
        let version = version.into();
        let id = Self::derive_id(&name, &version, &body)?;
        Ok(Self {
            id,
            name,
            version,
            body,
        })
    }

    /// Derive the content-addressed id without constructing an
    /// artifact. Useful for verifying that a stored artifact's id
    /// matches its content.
    pub fn derive_id(
        name: &str,
        version: &str,
        body: &serde_json::Value,
    ) -> Result<String, String> {
        // Canonical form: a JSON object with sorted keys
        // {body, name, version}. We use BTreeMap to enforce key
        // ordering. The body is a JSON value already, so we
        // canonicalize it via serde_json with sorted keys.
        let canonical = canonical_json(&serde_json::json!({
            "body": body,
            "name": name,
            "version": version,
        }))?;
        let mut hasher = Sha256::new();
        hasher.update(canonical.as_bytes());
        let hash = hasher.finalize();
        Ok(format!("vsa_{}", hex::encode(&hash[..16])))
    }

    /// Verify that this artifact's stored id matches the id derived
    /// from its content.
    pub fn verify_id(&self) -> Result<(), String> {
        let derived = Self::derive_id(&self.name, &self.version, &self.body)?;
        if derived == self.id {
            Ok(())
        } else {
            Err(format!(
                "schema artifact id mismatch: stored={}, derived={}",
                self.id, derived
            ))
        }
    }
}

/// Canonicalize a JSON value: sort all object keys recursively and
/// serialize without whitespace. This is the canonicalization
/// scheme used for content-addressing schema artifacts.
fn canonical_json(value: &serde_json::Value) -> Result<String, String> {
    fn canon(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut sorted: BTreeMap<String, serde_json::Value> = BTreeMap::new();
                for (k, vv) in map {
                    sorted.insert(k.clone(), canon(vv));
                }
                let mut out = serde_json::Map::new();
                for (k, vv) in sorted {
                    out.insert(k, vv);
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(canon).collect())
            }
            other => other.clone(),
        }
    }
    serde_json::to_string(&canon(value)).map_err(|e| format!("canonicalize: {e}"))
}

/// A registry of known schema artifacts.
///
/// Replay code uses the registry to verify that every event's
/// schema reference points to an available artifact. Missing
/// artifacts mean the event cannot be replayed deterministically;
/// federation policy must fetch missing artifacts before replay
/// proceeds (analogous to the missing-ancestor case in §5.2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaRegistry {
    artifacts: BTreeMap<String, SchemaArtifact>,
}

impl SchemaRegistry {
    /// Empty registry.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Insert an artifact, verifying its id matches its content.
    ///
    /// Returns an error if the artifact's stored id does not match
    /// its derived id. This catches tampering at registration time
    /// rather than at replay time.
    pub fn insert(&mut self, artifact: SchemaArtifact) -> Result<(), String> {
        artifact.verify_id()?;
        self.artifacts.insert(artifact.id.clone(), artifact);
        Ok(())
    }

    /// Look up an artifact by id.
    pub fn get(&self, id: &str) -> Option<&SchemaArtifact> {
        self.artifacts.get(id)
    }

    /// Whether the registry contains an artifact with the given id.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.artifacts.contains_key(id)
    }

    /// Number of artifacts in the registry.
    #[must_use]
    pub fn len(&self) -> usize {
        self.artifacts.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.artifacts.is_empty()
    }

    /// All artifact ids in canonical (sorted) order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.artifacts.keys().map(String::as_str)
    }

    /// Detect schema artifacts referenced by `referenced` but
    /// missing from the registry. Used at replay-time to determine
    /// whether replay can proceed.
    pub fn missing<I: AsRef<str>>(&self, referenced: &[I]) -> Vec<String> {
        referenced
            .iter()
            .filter(|id| !self.artifacts.contains_key(id.as_ref()))
            .map(|id| id.as_ref().to_string())
            .collect()
    }

    /// Inspect a slice of events and return any
    /// `schema_artifact_id` values that are not present in the
    /// registry. Events with `schema_artifact_id == None` are
    /// skipped (they predate the artifact-registry mechanism per
    /// docs/THEORY.md §5.1 and use the legacy string `schema`
    /// field).
    ///
    /// Returned ids are deduplicated and sorted lexically.
    pub fn unknown_event_artifacts(&self, events: &[crate::events::StateEvent]) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        let mut missing = std::collections::BTreeSet::new();
        for ev in events {
            let Some(id) = ev.schema_artifact_id.as_deref() else {
                continue;
            };
            if seen.contains(id) {
                continue;
            }
            seen.insert(id.to_string());
            if !self.artifacts.contains_key(id) {
                missing.insert(id.to_string());
            }
        }
        missing.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_body() -> serde_json::Value {
        json!({
            "type": "object",
            "required": ["finding_id", "actor"],
            "properties": {
                "finding_id": {"type": "string"},
                "actor":      {"type": "string"},
            }
        })
    }

    #[test]
    fn artifact_id_is_content_addressed() {
        let a = SchemaArtifact::new("event.finding_asserted", "v0.1", sample_body()).unwrap();
        let b = SchemaArtifact::new("event.finding_asserted", "v0.1", sample_body()).unwrap();
        assert_eq!(a.id, b.id);
        assert!(a.id.starts_with("vsa_"));
    }

    #[test]
    fn different_content_yields_different_ids() {
        let a = SchemaArtifact::new("event.finding_asserted", "v0.1", sample_body()).unwrap();
        let b = SchemaArtifact::new("event.finding_asserted", "v0.2", sample_body()).unwrap();
        assert_ne!(a.id, b.id);

        let mut other_body = sample_body();
        other_body["properties"]["new_field"] = json!({"type": "string"});
        let c = SchemaArtifact::new("event.finding_asserted", "v0.1", other_body).unwrap();
        assert_ne!(a.id, c.id);
    }

    #[test]
    fn verify_id_rejects_tampered_artifact() {
        let mut a = SchemaArtifact::new("event.x", "v0.1", json!({"k": "v"})).unwrap();
        assert!(a.verify_id().is_ok());
        // Tamper with the body but keep the id.
        a.body = json!({"k": "v2"});
        assert!(a.verify_id().is_err());
    }

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let unsorted = json!({"b": 1, "a": {"d": 4, "c": 3}});
        let sorted = json!({"a": {"c": 3, "d": 4}, "b": 1});
        assert_eq!(
            canonical_json(&unsorted).unwrap(),
            canonical_json(&sorted).unwrap()
        );
    }

    #[test]
    fn key_order_does_not_affect_id() {
        let body1 = json!({"a": 1, "b": 2});
        let body2 = json!({"b": 2, "a": 1});
        let a = SchemaArtifact::new("x", "v0.1", body1).unwrap();
        let b = SchemaArtifact::new("x", "v0.1", body2).unwrap();
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn registry_insert_and_lookup() {
        let mut reg = SchemaRegistry::empty();
        let a = SchemaArtifact::new("event.x", "v0.1", sample_body()).unwrap();
        let id = a.id.clone();
        reg.insert(a).unwrap();
        assert!(reg.contains(&id));
        assert!(reg.get(&id).is_some());
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn registry_rejects_tampered_artifact_at_insert() {
        let mut reg = SchemaRegistry::empty();
        let mut a = SchemaArtifact::new("event.x", "v0.1", sample_body()).unwrap();
        // Tamper with body without updating id.
        a.body = json!({"different": "content"});
        let result = reg.insert(a);
        assert!(result.is_err());
        assert!(reg.is_empty());
    }

    #[test]
    fn missing_returns_unregistered_ids() {
        let mut reg = SchemaRegistry::empty();
        let a = SchemaArtifact::new("event.x", "v0.1", sample_body()).unwrap();
        let known = a.id.clone();
        reg.insert(a).unwrap();

        let referenced = vec![
            known.clone(),
            "vsa_unknown1".to_string(),
            "vsa_unknown2".to_string(),
        ];
        let missing = reg.missing(&referenced);
        assert_eq!(missing, vec!["vsa_unknown1", "vsa_unknown2"]);
    }

    #[test]
    fn missing_returns_empty_when_all_present() {
        let mut reg = SchemaRegistry::empty();
        let a = SchemaArtifact::new("event.x", "v0.1", sample_body()).unwrap();
        let id = a.id.clone();
        reg.insert(a).unwrap();
        assert!(reg.missing(&[id]).is_empty());
    }

    #[test]
    fn registry_serde_round_trip() {
        let mut reg = SchemaRegistry::empty();
        let a = SchemaArtifact::new("event.x", "v0.1", sample_body()).unwrap();
        let b = SchemaArtifact::new("event.y", "v0.2", json!({"different": true})).unwrap();
        reg.insert(a).unwrap();
        reg.insert(b).unwrap();

        let json = serde_json::to_string(&reg).unwrap();
        let restored: SchemaRegistry = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, reg);
    }

    #[test]
    fn id_uses_vsa_prefix_and_hex() {
        let a = SchemaArtifact::new("x", "v0.1", json!({})).unwrap();
        assert!(a.id.starts_with("vsa_"));
        let hex_part = &a.id[4..];
        assert_eq!(hex_part.len(), 32); // 16 bytes * 2 hex chars
        assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ids_are_returned_in_canonical_order() {
        let mut reg = SchemaRegistry::empty();
        // Insert in non-canonical order
        for n in ["zeta", "alpha", "beta"] {
            let a = SchemaArtifact::new(n, "v0.1", json!({"n": n})).unwrap();
            reg.insert(a).unwrap();
        }
        // Ids are returned sorted, regardless of insertion order
        let ids: Vec<&str> = reg.ids().collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    fn sample_event(id_seed: &str, artifact: Option<&str>) -> crate::events::StateEvent {
        use crate::events::{StateActor, StateEvent, StateTarget};
        StateEvent {
            schema: "vela.event.v0.1".into(),
            id: format!("vev_{}", id_seed),
            kind: "test.event".into(),
            target: StateTarget {
                r#type: "finding".into(),
                id: "vf_x".into(),
            },
            actor: StateActor {
                id: "test".into(),
                r#type: "system".into(),
            },
            timestamp: "2026-05-09T00:00:00Z".into(),
            reason: "test".into(),
            before_hash: String::new(),
            after_hash: String::new(),
            payload: json!(null),
            caveats: vec![],
            signature: None,
            schema_artifact_id: artifact.map(String::from),
        }
    }

    #[test]
    fn unknown_event_artifacts_returns_only_missing_referenced_ids() {
        let mut reg = SchemaRegistry::empty();
        let known_artifact = SchemaArtifact::new("event.x", "v0.1", json!({})).unwrap();
        let known_id = known_artifact.id.clone();
        reg.insert(known_artifact).unwrap();

        let events = vec![
            // Event referencing a known artifact: not missing.
            sample_event("001", Some(&known_id)),
            // Event referencing an unknown artifact: missing.
            sample_event("002", Some("vsa_unknown")),
            // Event without an artifact reference: skipped.
            sample_event("003", None),
        ];
        let missing = reg.unknown_event_artifacts(&events);
        assert_eq!(missing, vec!["vsa_unknown"]);
    }

    #[test]
    fn unknown_event_artifacts_deduplicates() {
        let reg = SchemaRegistry::empty();
        let events = vec![
            sample_event("001", Some("vsa_missing")),
            sample_event("002", Some("vsa_missing")),
            sample_event("003", Some("vsa_missing")),
        ];
        let missing = reg.unknown_event_artifacts(&events);
        assert_eq!(missing, vec!["vsa_missing"]);
    }

    #[test]
    fn schema_artifact_id_does_not_affect_event_id() {
        // Critical invariant: setting schema_artifact_id must NOT
        // change event.id. Otherwise existing events would be
        // forced to migrate, breaking replay determinism on every
        // historical hub.
        use crate::events::compute_event_id;
        let without = sample_event("001", None);
        let with = sample_event("001", Some("vsa_someartifact"));
        // Compute fresh event ids from both (sample_event sets
        // a placeholder; compute_event_id ignores it and rederives).
        let id_without = compute_event_id(&without);
        let id_with = compute_event_id(&with);
        assert_eq!(
            id_without, id_with,
            "schema_artifact_id must not be part of canonical event-id preimage"
        );
    }

    #[test]
    fn pre_v0_89_events_serialize_byte_identically() {
        // An event with schema_artifact_id=None must serialize
        // without the new field, so pre-v0.89 frontiers round-trip.
        let event = sample_event("001", None);
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            !json.contains("schema_artifact_id"),
            "schema_artifact_id should be skipped when None; full json: {json}"
        );
    }

    #[test]
    fn v0_89_event_with_artifact_includes_field() {
        let event = sample_event("001", Some("vsa_test"));
        let json = serde_json::to_string(&event).unwrap();
        assert!(
            json.contains("schema_artifact_id"),
            "schema_artifact_id should appear when Some"
        );
        assert!(
            json.contains("vsa_test"),
            "the artifact id value should appear"
        );
    }
}
