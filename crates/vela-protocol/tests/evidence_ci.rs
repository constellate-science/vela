use std::path::PathBuf;

use vela_protocol::evidence_ci::{self, EvidenceCiStatus};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn evidence_ci_reports_frontier_review_readiness() {
    let frontier = repo_root().join("projects/anti-amyloid-translation");
    let report = evidence_ci::run_frontier(&frontier).expect("evidence ci report");

    assert!(report.ok, "release-critical checks should pass");
    assert_eq!(report.command, "evidence-ci");
    assert!(report.summary.total > 0);
    assert!(evidence_ci::required_check_ids(&report).contains("source.id_presence"));
    assert!(evidence_ci::required_check_ids(&report).contains("policy.review_requirement"));
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "contradiction.scan_status")
    );
}

#[test]
fn diff_pack_evidence_ci_blocks_missing_source_artifacts() {
    let frontier = repo_root().join("examples/early-ad");
    let report = evidence_ci::run_diff_pack(&frontier, "vsd_be61da0cdcba08ed")
        .expect("diff pack evidence ci report");

    assert_eq!(report.command, "diff-pack.validate");
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "diff_pack.signature_or_id"
                && check.status == EvidenceCiStatus::Passed)
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "policy.review_requirement")
    );
}
