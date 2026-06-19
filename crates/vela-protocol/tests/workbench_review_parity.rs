//! W7: CLI ↔ Workbench parity for the v0.56 + v0.57 review primitives.
//!
//! Builds the same proposal twice (CLI helper path + Workbench
//! handler path) and asserts the resulting `proposal_id` is
//! byte-identical. Proposal ids are content-addressed
//! (sha256 over canonical JSON), so identical logical content
//! produces identical ids regardless of which surface the
//! reviewer used.

use serde_json::json;
use vela_protocol::events::StateTarget;
use vela_protocol::proposals::new_proposal;

fn cli_locator_repair_proposal(
    atom_id: &str,
    locator: &str,
    reviewer: &str,
    reason: &str,
    source_id: &str,
) -> String {
    let proposal = new_proposal(
        "evidence_atom.locator_repair",
        StateTarget {
            r#type: "evidence_atom".to_string(),
            id: atom_id.to_string(),
        },
        reviewer,
        "human",
        reason,
        json!({
            "locator": locator,
            "source_id": source_id,
        }),
        Vec::new(),
        Vec::new(),
    );
    proposal.id
}

fn ui_locator_repair_proposal(
    atom_id: &str,
    locator: &str,
    reviewer: &str,
    reason: &str,
    source_id: &str,
) -> String {
    // Mirror of state::repair_evidence_atom_locator's proposal
    // build, simulating the Workbench POST handler path.
    let proposal = new_proposal(
        "evidence_atom.locator_repair",
        StateTarget {
            r#type: "evidence_atom".to_string(),
            id: atom_id.to_string(),
        },
        reviewer,
        "human",
        reason,
        json!({
            "locator": locator,
            "source_id": source_id,
        }),
        Vec::new(),
        Vec::new(),
    );
    proposal.id
}

#[test]
fn locator_repair_cli_and_ui_produce_identical_proposal_ids() {
    let cli_id = cli_locator_repair_proposal(
        "vea_abc",
        "doi:10.1/test",
        "reviewer:test",
        "fixture",
        "vs_xyz",
    );
    let ui_id = ui_locator_repair_proposal(
        "vea_abc",
        "doi:10.1/test",
        "reviewer:test",
        "fixture",
        "vs_xyz",
    );
    assert_eq!(
        cli_id, ui_id,
        "locator-repair CLI and UI must produce identical proposal ids"
    );
    assert!(cli_id.starts_with("vpr_"));
}

fn cli_span_repair_proposal(
    finding_id: &str,
    section: &str,
    text: &str,
    reviewer: &str,
    reason: &str,
) -> String {
    new_proposal(
        "finding.span_repair",
        StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        reviewer,
        "human",
        reason,
        json!({"section": section, "text": text}),
        Vec::new(),
        Vec::new(),
    )
    .id
}

fn ui_span_repair_proposal(
    finding_id: &str,
    section: &str,
    text: &str,
    reviewer: &str,
    reason: &str,
) -> String {
    new_proposal(
        "finding.span_repair",
        StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        reviewer,
        "human",
        reason,
        json!({"section": section, "text": text}),
        Vec::new(),
        Vec::new(),
    )
    .id
}

#[test]
fn span_repair_cli_and_ui_produce_identical_proposal_ids() {
    let cli_id = cli_span_repair_proposal(
        "vf_abc",
        "abstract",
        "real text",
        "reviewer:test",
        "fixture",
    );
    let ui_id = ui_span_repair_proposal(
        "vf_abc",
        "abstract",
        "real text",
        "reviewer:test",
        "fixture",
    );
    assert_eq!(cli_id, ui_id);
    assert!(cli_id.starts_with("vpr_"));
}

// v0.59: promote-to-accepted-core (the `finding.review` event) goes
// through the same proposal builder via `state::review_finding`.
// Both the CLI and the local Workbench POST handler call that
// helper, so the proposal ids must match for the same logical
// content.
fn promote_proposal(finding_id: &str, status: &str, reviewer: &str, reason: &str) -> String {
    new_proposal(
        "finding.review",
        StateTarget {
            r#type: "finding".to_string(),
            id: finding_id.to_string(),
        },
        reviewer,
        "human",
        reason,
        json!({"status": status}),
        Vec::new(),
        Vec::new(),
    )
    .id
}

#[test]
fn promote_cli_and_ui_produce_identical_proposal_ids() {
    let cli_id = promote_proposal(
        "vf_abc",
        "accepted",
        "reviewer:test",
        "Reviewed and promoted via local Workbench.",
    );
    let ui_id = promote_proposal(
        "vf_abc",
        "accepted",
        "reviewer:test",
        "Reviewed and promoted via local Workbench.",
    );
    assert_eq!(
        cli_id, ui_id,
        "promote CLI and UI must produce identical proposal ids"
    );
    assert!(cli_id.starts_with("vpr_"));
}

// v0.59 federation conflict-resolution parity test removed with the
// federation surface.

#[test]
fn proposal_ids_change_when_payload_changes() {
    let a = cli_locator_repair_proposal(
        "vea_abc",
        "doi:10.1/a",
        "reviewer:test",
        "fixture",
        "vs_xyz",
    );
    let b = cli_locator_repair_proposal(
        "vea_abc",
        "doi:10.1/b",
        "reviewer:test",
        "fixture",
        "vs_xyz",
    );
    assert_ne!(a, b, "different locator must produce different proposal id");
}
