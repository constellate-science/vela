use vela_protocol::evidence_ci;
use vela_protocol::project;
use vela_protocol::repo;

/// Evidence CI runs over any frontier and always emits the release-critical
/// policy and contradiction-scan checks. This guards the general check
/// structure independently of any one campaign's data.
#[test]
fn evidence_ci_reports_frontier_review_readiness() {
    let dir = tempfile::tempdir().expect("tempdir");
    let frontier_path = dir.path().join("frontier.json");
    let frontier = project::assemble("evidence-ci test", vec![], 0, 0, "test frontier");
    repo::save_to_path(&frontier_path, &frontier).expect("save frontier");

    let report = evidence_ci::run_frontier(&frontier_path).expect("evidence ci report");

    assert_eq!(report.command, "evidence-ci");
    assert!(
        evidence_ci::required_check_ids(&report).contains("policy.review_requirement"),
        "policy.review_requirement is a release-critical check"
    );
    assert!(
        report
            .checks
            .iter()
            .any(|check| check.id == "contradiction.scan_status"),
        "contradiction scan status must always be reported"
    );
}
