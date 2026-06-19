//! Cross-layer test: a packet directory written by `export` (edge) is read
//! back by `repo::load_from_path` (core), preserving findings and review
//! events. This lived in vela-protocol's repo tests while export was in the
//! waist; it now lives here, where both layers are reachable.

use tempfile::TempDir;
use vela_edge::export;
use vela_protocol::bundle::{ReviewAction, ReviewEvent};
use vela_protocol::repo;
use vela_protocol::test_support::{make_finding, make_project};

#[test]
fn load_from_path_reads_export_packet_dir() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("packet-frontier");

    let mut original = make_project(
        "packet-frontier",
        vec![make_finding("vf_pkt1", 0.81, "mechanism")],
    );
    original.review_events.push(ReviewEvent {
        id: "rev_pkt1".into(),
        workspace: Some("sidon".into()),
        finding_id: "vf_pkt1".into(),
        reviewer: "reviewer:test".into(),
        reviewed_at: "2026-01-01T00:00:00Z".into(),
        scope: Some("external".into()),
        status: Some("accepted".into()),
        action: ReviewAction::Approved,
        reason: "Imported from another lab".into(),
        evidence_considered: vec![],
        state_change: None,
    });
    original.stats.review_event_count = original.review_events.len();

    export::export_packet(&original, &dir).unwrap();

    let loaded = repo::load_from_path(&dir).unwrap();
    assert_eq!(loaded.project.name, "packet-frontier");
    assert_eq!(loaded.findings.len(), 1);
    assert_eq!(loaded.review_events.len(), 1);
    assert_eq!(loaded.stats.review_event_count, 1);
}
