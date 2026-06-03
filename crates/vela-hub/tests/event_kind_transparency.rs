//! R2: Verify the hub treats v0.56 + v0.57 event kinds as opaque
//! transport rows. The hub does not dispatch on event.kind; it
//! stores `(id, kind, target.type, target.id, ...)` as columns
//! and serves them back. This test confirms each new kind
//! round-trips through StateEvent serialization without loss.

use serde_json::json;
use vela_protocol::events::{StateActor, StateEvent, StateTarget};

fn roundtrip(kind: &str, target_type: &str, target_id: &str, payload: serde_json::Value) {
    let event = StateEvent {
        schema: vela_protocol::events::EVENT_SCHEMA.to_string(),
        id: "vev_test".to_string(),
        kind: kind.to_string(),
        target: StateTarget {
            r#type: target_type.to_string(),
            id: target_id.to_string(),
        },
        actor: StateActor {
            id: "agent:test".to_string(),
            r#type: "agent".to_string(),
        },
        timestamp: "2026-05-08T00:00:00Z".to_string(),
        reason: "transparency fixture".to_string(),
        before_hash: vela_protocol::events::NULL_HASH.to_string(),
        after_hash: vela_protocol::events::NULL_HASH.to_string(),
        payload,
        caveats: vec![],
        signature: None,
        schema_artifact_id: None,
    };
    let serialized = serde_json::to_string(&event).expect("serialize");
    let parsed: StateEvent = serde_json::from_str(&serialized).expect("deserialize");
    assert_eq!(parsed.kind, kind);
    assert_eq!(parsed.target.r#type, target_type);
    assert_eq!(parsed.target.id, target_id);
}

#[test]
fn evidence_atom_locator_repaired_round_trips() {
    roundtrip(
        "evidence_atom.locator_repaired",
        "evidence_atom",
        "vea_test",
        json!({
            "proposal_id": "vpr_test",
            "source_id": "vs_test",
            "locator": "doi:10.1/test",
        }),
    );
}

#[test]
fn finding_span_repaired_round_trips() {
    roundtrip(
        "finding.span_repaired",
        "finding",
        "vf_test",
        json!({
            "proposal_id": "vpr_test",
            "section": "abstract",
            "text": "fixture span body",
        }),
    );
}

#[test]
fn finding_entity_resolved_round_trips() {
    roundtrip(
        "finding.entity_resolved",
        "finding",
        "vf_test",
        json!({
            "proposal_id": "vpr_test",
            "entity_name": "PDGFRB",
            "source": "hgnc",
            "id": "8804",
            "confidence": 0.95,
        }),
    );
}
