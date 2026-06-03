use std::fs;

use tempfile::tempdir;
use vela_protocol::frontier_policy::{
    PolicyDocumentKind, load_policy_summary, review_requirement_for_operation,
};

fn write_frontier(root: &std::path::Path, policy_block: &str) {
    fs::write(
        root.join("frontier.yaml"),
        format!(
            r#"schema: vela.frontier_manifest.v0.1
layout: vela.frontier_repo.v0.1
frontier_id: vfr_testpolicy0001
name: Policy test frontier
policies:
{policy_block}
"#
        ),
    )
    .unwrap();
}

#[test]
fn loads_policy_documents_from_manifest_references() {
    let tmp = tempdir().unwrap();
    write_frontier(
        tmp.path(),
        r#"  evidence: .vela/policy/evidence_policy.md
  review: .vela/policy/review_policy.md
  confidence: .vela/policy/confidence_policy.md
  agent: .vela/policy/agent_policy.md
"#,
    );
    let dir = tmp.path().join(".vela").join("policy");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("evidence_policy.md"),
        "---\ntitle: Evidence policy\nversion: 1\n---\nPrefer registered clinical evidence.\n",
    )
    .unwrap();
    fs::write(
        dir.join("review_policy.md"),
        "---\ntitle: Review policy\nrequired_roles:\n  - domain_reviewer\n---\nConfidence changes need domain review.\n",
    )
    .unwrap();
    fs::write(
        dir.join("confidence_policy.md"),
        "---\ntitle: Confidence policy\n---\nDo not move confidence without a cited reason.\n",
    )
    .unwrap();
    fs::write(
        dir.join("agent_policy.md"),
        "---\ntitle: Agent policy\n---\nAgents may propose but not accept.\n",
    )
    .unwrap();

    let summary = load_policy_summary(tmp.path()).unwrap();
    assert!(summary.ok);
    assert_eq!(summary.frontier_id.as_deref(), Some("vfr_testpolicy0001"));
    assert_eq!(summary.documents.len(), 4);
    assert!(summary.missing_required.is_empty());
    assert!(
        summary
            .documents
            .iter()
            .any(|doc| doc.kind == PolicyDocumentKind::Evidence && doc.title == "Evidence policy")
    );
    assert!(!summary.defaults_used);
}

#[test]
fn discovers_default_policy_directory_without_manifest_references() {
    let tmp = tempdir().unwrap();
    write_frontier(tmp.path(), "  review: review/policy.yaml\n");
    let dir = tmp.path().join(".vela").join("policy");
    fs::create_dir_all(&dir).unwrap();
    for name in [
        "evidence_policy.md",
        "review_policy.md",
        "confidence_policy.md",
        "agent_policy.md",
    ] {
        fs::write(dir.join(name), format!("---\ntitle: {name}\n---\nbody\n")).unwrap();
    }

    let summary = load_policy_summary(tmp.path()).unwrap();
    assert!(summary.ok);
    assert_eq!(summary.documents.len(), 4);
    assert!(
        summary
            .documents
            .iter()
            .all(|doc| !doc.declared_in_manifest)
    );
}

#[test]
fn reports_missing_policy_documents_without_failing_small_fixtures() {
    let tmp = tempdir().unwrap();
    write_frontier(tmp.path(), "  review: review/policy.yaml\n");

    let summary = load_policy_summary(tmp.path()).unwrap();
    assert!(!summary.ok);
    assert!(summary.defaults_used);
    assert_eq!(summary.missing_required.len(), 4);
}

#[test]
fn computes_policy_aware_review_requirements() {
    let tmp = tempdir().unwrap();
    write_frontier(
        tmp.path(),
        r#"  evidence: .vela/policy/evidence_policy.md
  review: .vela/policy/review_policy.md
  confidence: .vela/policy/confidence_policy.md
  agent: .vela/policy/agent_policy.md
"#,
    );
    let dir = tmp.path().join(".vela").join("policy");
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("evidence_policy.md"),
        "---\ntitle: Evidence\n---\nbody\n",
    )
    .unwrap();
    fs::write(
        dir.join("review_policy.md"),
        r#"---
title: Review
required_roles:
  confidence_change:
    - domain_reviewer
    - method_reviewer
  contradiction_change:
    - domain_reviewer
  clinical_translation:
    - domain_reviewer
    - safety_reviewer
  retraction_impact:
    - method_reviewer
    - source_reviewer
---
body
"#,
    )
    .unwrap();
    fs::write(
        dir.join("confidence_policy.md"),
        "---\ntitle: Confidence\nrequires_source_or_evidence_ref: true\n---\nbody\n",
    )
    .unwrap();
    fs::write(
        dir.join("agent_policy.md"),
        "---\ntitle: Agent\nagents_may:\n  - propose_diff_pack\n---\nbody\n",
    )
    .unwrap();

    let summary = load_policy_summary(tmp.path()).unwrap();
    let confidence = review_requirement_for_operation(
        Some(&summary),
        "revise_confidence",
        "finding.review",
        false,
    );
    assert_eq!(confidence.review_class, "confidence_change");
    assert_eq!(confidence.required_reviewer_count, 2);
    assert_eq!(
        confidence.reviewer_roles,
        vec!["domain_reviewer".to_string(), "method_reviewer".to_string()]
    );
    assert!(
        confidence
            .required_reason_fields
            .contains(&"source_or_evidence_ref".to_string())
    );
    assert!(
        confidence
            .allowed_agent_actions
            .contains(&"propose_diff_pack".to_string())
    );

    let contradiction = review_requirement_for_operation(
        Some(&summary),
        "mark_contradiction",
        "finding.tension",
        false,
    );
    assert_eq!(contradiction.review_class, "contradiction_change");
    assert_eq!(contradiction.required_reviewer_count, 1);
    assert_eq!(
        contradiction.reviewer_roles,
        vec!["domain_reviewer".to_string()]
    );

    let clinical = review_requirement_for_operation(
        Some(&summary),
        "add_finding",
        "clinical_translation.note",
        false,
    );
    assert_eq!(clinical.review_class, "clinical_translation");
    assert!(
        clinical
            .required_reason_fields
            .contains(&"impact_scope".to_string())
    );

    let retraction = review_requirement_for_operation(
        Some(&summary),
        "request_downstream_review",
        "retraction.impact",
        true,
    );
    assert_eq!(retraction.review_class, "retraction_impact");
    assert_eq!(
        retraction.reviewer_roles,
        vec!["method_reviewer".to_string(), "source_reviewer".to_string()]
    );

    let source_repair =
        review_requirement_for_operation(Some(&summary), "repair_locator", "locator.repair", false);
    assert_eq!(source_repair.review_class, "source_repair");
    assert_eq!(source_repair.required_reviewer_count, 1);

    let low_risk =
        review_requirement_for_operation(Some(&summary), "add_link", "finding.link", false);
    assert_eq!(low_risk.review_class, "low_risk");
    assert_eq!(low_risk.reviewer_roles, vec!["local_reviewer".to_string()]);
}
