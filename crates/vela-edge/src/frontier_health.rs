//! Frontier health projection.
//!
//! Health is an operational view over local frontier state. It reports
//! review debt, stale proof, source queue issues, and missing scoped
//! attestations. It does not decide whether a scientific claim is true.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::frontier_task::{self, FrontierTaskStatus};
use crate::reviewer_identity;
use crate::source_inbox::{self, SourceInboxState};
use vela_protocol::evidence_ci::{self, EvidenceCiSeverity};
use vela_protocol::frontier_policy;
use vela_protocol::project::Project;
use vela_protocol::released_diff_pack::ReleasedVerdict;
use vela_protocol::repo::{self, VelaSource};
use vela_protocol::scientific_diff::ScientificDiffPack;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierHealthReport {
    pub ok: bool,
    pub command: String,
    pub frontier_id: String,
    pub frontier_path: String,
    pub checked_at: String,
    pub policy_class: String,
    pub metrics: FrontierHealthMetrics,
    #[serde(default)]
    pub issues: Vec<FrontierHealthIssue>,
    #[serde(default)]
    pub links: Vec<FrontierHealthLink>,
    #[serde(default)]
    pub threshold_classes: Vec<FrontierHealthThreshold>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierHealthMetrics {
    pub active_tasks: usize,
    pub blocked_tasks: usize,
    pub awaiting_review_tasks: usize,
    pub pending_diff_packs: usize,
    pub accepted_diff_packs: usize,
    pub rejected_diff_packs: usize,
    pub revision_requested_diff_packs: usize,
    pub proof_status: String,
    pub stale_proof: bool,
    pub source_inbox_issues: usize,
    pub evidence_ci_failures: usize,
    pub evidence_ci_warnings: usize,
    pub stale_claims: usize,
    pub contradiction_debt: usize,
    pub retraction_impacts: usize,
    pub max_review_latency_days: i64,
    pub missing_attestations: usize,
    pub missing_attestation_targets: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierHealthIssue {
    pub id: String,
    pub severity: String,
    pub count: usize,
    pub label: String,
    pub message: String,
    pub href: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierHealthLink {
    pub label: String,
    pub href: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierHealthThreshold {
    pub review_class: String,
    pub required_reviewer_count: usize,
    #[serde(default)]
    pub reviewer_roles: Vec<String>,
}

pub fn analyze(frontier_path: &Path) -> Result<FrontierHealthReport, String> {
    let project = repo::load_from_path(frontier_path)?;
    let repo_root = local_repo_root(frontier_path);
    let local_path = repo_root.as_deref().unwrap_or(frontier_path);
    let evidence = evidence_ci::run_frontier(frontier_path)?;
    let policy = frontier_policy::load_policy_summary(frontier_path).ok();

    let task_list = repo_root
        .as_deref()
        .and_then(|root| frontier_task::list_tasks(root).ok());
    let active_tasks = task_list
        .as_ref()
        .map(|list| {
            list.tasks
                .iter()
                .filter(|task| !task.status.is_terminal())
                .count()
        })
        .unwrap_or(0);
    let blocked_tasks = task_list
        .as_ref()
        .map(|list| {
            list.tasks
                .iter()
                .filter(|task| !task.blockers.is_empty())
                .count()
        })
        .unwrap_or(0);
    let awaiting_review_tasks = task_list
        .as_ref()
        .map(|list| {
            list.tasks
                .iter()
                .filter(|task| task.status == FrontierTaskStatus::AwaitingReview)
                .count()
        })
        .unwrap_or(0);
    let retraction_task_impacts = task_list
        .as_ref()
        .map(|list| {
            list.tasks
                .iter()
                .filter(|task| {
                    !task.status.is_terminal()
                        && (task.risk_class == "retraction_impact"
                            || task.task_type.contains("retraction"))
                })
                .count()
        })
        .unwrap_or(0);

    let source_list = repo_root
        .as_deref()
        .and_then(|root| source_inbox::list_records(root).ok());
    let source_inbox_issues = source_list
        .as_ref()
        .map(|list| {
            list.records
                .iter()
                .filter(|record| {
                    matches!(
                        record.state,
                        SourceInboxState::Quarantined | SourceInboxState::Retracted
                    ) || is_source_stale(record)
                })
                .count()
        })
        .unwrap_or(0);
    let source_retractions = source_list
        .as_ref()
        .map(|list| {
            list.records
                .iter()
                .filter(|record| record.state == SourceInboxState::Retracted)
                .count()
        })
        .unwrap_or(0);

    let (
        pending_diff_packs,
        accepted_diff_packs,
        rejected_diff_packs,
        revision_requested_diff_packs,
    ) = diff_pack_counts(&project);
    let (missing_attestations, missing_attestation_targets) =
        missing_attestations(&project, local_path, repo_root.as_ref().is_some());

    let evidence_ci_failures = evidence.summary.release_blocking_failed;
    let evidence_ci_warnings = evidence.summary.warnings;
    let stale_claims = stale_claim_count(&evidence);
    let contradiction_debt = contradiction_debt(&project);
    let proof_status = project.proof_state.latest_packet.status.clone();
    let stale_proof = !matches!(proof_status.as_str(), "fresh" | "current" | "ready");
    let max_review_latency_days = max_review_latency_days(&project);
    let retraction_impacts = source_retractions
        + retraction_task_impacts
        + project
            .events
            .iter()
            .filter(|event| event.kind.as_str().contains("retract"))
            .count();

    let metrics = FrontierHealthMetrics {
        active_tasks,
        blocked_tasks,
        awaiting_review_tasks,
        pending_diff_packs,
        accepted_diff_packs,
        rejected_diff_packs,
        revision_requested_diff_packs,
        proof_status,
        stale_proof,
        source_inbox_issues,
        evidence_ci_failures,
        evidence_ci_warnings,
        stale_claims,
        contradiction_debt,
        retraction_impacts,
        max_review_latency_days,
        missing_attestations,
        missing_attestation_targets,
    };

    let mut report = FrontierHealthReport {
        ok: false,
        command: "frontier.health".to_string(),
        frontier_id: project.frontier_id(),
        frontier_path: frontier_path.display().to_string(),
        checked_at: Utc::now().to_rfc3339(),
        policy_class: if policy.as_ref().is_some_and(|p| p.ok) {
            "frontier_policy".to_string()
        } else {
            "built_in_defaults".to_string()
        },
        metrics,
        issues: Vec::new(),
        links: health_links(),
        threshold_classes: threshold_classes(policy.as_ref()),
        caveats: vec![
            "Health is an operating projection for local review. It is not a truth verdict."
                .to_string(),
            "Hosted surfaces must remain read-only; the local review server (`vela serve`) and CLI own review actions."
                .to_string(),
        ],
    };
    report.issues = build_issues(&report.metrics);
    report.ok = !report.issues.iter().any(|issue| issue.severity == "error");
    Ok(report)
}

fn diff_pack_counts(project: &Project) -> (usize, usize, usize, usize) {
    let mut pending = 0;
    let mut accepted = 0;
    let mut rejected = 0;
    let mut revise = 0;
    for record in &project.released_diff_packs {
        match record.verdict {
            Some(ReleasedVerdict::Accept) => accepted += 1,
            Some(ReleasedVerdict::Reject) => rejected += 1,
            Some(ReleasedVerdict::Revise) => revise += 1,
            None => pending += 1,
        }
    }
    (pending, accepted, rejected, revise)
}

fn missing_attestations(
    project: &Project,
    repo_path: &Path,
    is_local_repo: bool,
) -> (usize, usize) {
    if !is_local_repo {
        return (0, 0);
    }
    let mut missing = 0usize;
    let mut targets = 0usize;
    for record in &project.released_diff_packs {
        if record.verdict.is_some() {
            continue;
        }
        let Some(pack) = load_diff_pack(repo_path, &record.pack_id) else {
            continue;
        };
        let summary = pack.review_summary(repo_path);
        let required = summary.required_reviewers;
        if required.is_empty() {
            continue;
        }
        let missing_roles =
            reviewer_identity::missing_roles_for_target(repo_path, &pack.pack_id, &required)
                .unwrap_or(required);
        if !missing_roles.is_empty() {
            missing += missing_roles.len();
            targets += 1;
        }
    }
    (missing, targets)
}

fn load_diff_pack(repo_path: &Path, pack_id: &str) -> Option<ScientificDiffPack> {
    let path = repo_path
        .join(".vela")
        .join("diff_packs")
        .join(format!("{pack_id}.json"));
    let body = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&body).ok()
}

fn stale_claim_count(evidence: &evidence_ci::EvidenceCiReport) -> usize {
    evidence
        .checks
        .iter()
        .filter(|check| {
            check.target_type == "finding"
                && matches!(
                    check.severity,
                    EvidenceCiSeverity::Warn | EvidenceCiSeverity::Error
                )
                && matches!(
                    check.id.as_str(),
                    "source.id_presence"
                        | "source.canonical_locator"
                        | "evidence.span_presence"
                        | "trial.registry_reference"
                        | "condition.population"
                        | "condition.comparator_or_baseline"
                        | "condition.endpoint"
                )
        })
        .map(|check| check.target_id.clone())
        .collect::<BTreeSet<_>>()
        .len()
}

fn contradiction_debt(project: &Project) -> usize {
    project
        .findings
        .iter()
        .flat_map(|finding| finding.links.iter())
        .filter(|link| link.link_type == "contradicts")
        .count()
}

fn max_review_latency_days(project: &Project) -> i64 {
    let mut max_days = 0i64;
    for proposal in &project.proposals {
        if proposal.status == "pending_review" {
            max_days = max_days.max(age_days(
                proposal
                    .drafted_at
                    .as_deref()
                    .unwrap_or(proposal.created_at.as_str()),
            ));
        }
    }
    for pack in &project.released_diff_packs {
        if pack.verdict.is_none() {
            max_days = max_days.max(age_days(&pack.released_at));
        }
    }
    max_days
}

fn age_days(timestamp: &str) -> i64 {
    DateTime::parse_from_rfc3339(timestamp)
        .ok()
        .map(|dt| {
            Utc::now()
                .signed_duration_since(dt.with_timezone(&Utc))
                .num_days()
                .max(0)
        })
        .unwrap_or(0)
}

fn is_source_stale(record: &source_inbox::SourceInboxRecord) -> bool {
    if record.state == SourceInboxState::Retracted {
        return false;
    }
    age_days(&record.updated_at) > 30
}

fn threshold_classes(
    policy: Option<&frontier_policy::FrontierPolicySummary>,
) -> Vec<FrontierHealthThreshold> {
    [
        ("low_risk", "add_evidence_atom", false),
        ("source_repair", "repair_locator", false),
        ("entity_issue", "resolve_entity", false),
        ("confidence_change", "revise_confidence", false),
        ("contradiction_change", "mark_contradiction", false),
        ("decision_impact", "request_downstream_review", true),
        ("retraction_impact", "retraction_impact", true),
    ]
    .into_iter()
    .map(|(review_class, operation, downstream)| {
        let requirement = frontier_policy::review_requirement_for_operation(
            policy, operation, "health", downstream,
        );
        FrontierHealthThreshold {
            review_class: review_class.to_string(),
            required_reviewer_count: requirement.required_reviewer_count,
            reviewer_roles: requirement.reviewer_roles,
        }
    })
    .collect()
}

fn health_links() -> Vec<FrontierHealthLink> {
    vec![
        FrontierHealthLink {
            label: "tasks".to_string(),
            href: "/tasks".to_string(),
            count: 0,
        },
        FrontierHealthLink {
            label: "source inbox".to_string(),
            href: "/source-inbox".to_string(),
            count: 0,
        },
        FrontierHealthLink {
            label: "Diff Packs".to_string(),
            href: "/diff-packs".to_string(),
            count: 0,
        },
        FrontierHealthLink {
            label: "Evidence CI".to_string(),
            href: "/review/session".to_string(),
            count: 0,
        },
        FrontierHealthLink {
            label: "proof".to_string(),
            href: "/proof".to_string(),
            count: 0,
        },
    ]
}

fn build_issues(metrics: &FrontierHealthMetrics) -> Vec<FrontierHealthIssue> {
    let mut issues = Vec::new();
    push_issue(
        &mut issues,
        metrics.stale_proof.then_some(1),
        "proof_freshness",
        "error",
        "Stale proof",
        "Recorded proof is not fresh against current frontier state.",
        "/proof",
        None,
    );
    push_issue(
        &mut issues,
        nonzero(metrics.evidence_ci_failures),
        "evidence_ci_failures",
        "error",
        "Evidence CI failures",
        "Release-blocking Evidence CI checks need review.",
        "/review/session",
        None,
    );
    push_issue(
        &mut issues,
        nonzero(metrics.missing_attestations),
        "missing_attestations",
        "warn",
        "Missing attestations",
        "One or more pending Diff Packs are missing required scoped reviewer roles.",
        "/diff-packs",
        None,
    );
    push_issue(
        &mut issues,
        nonzero(metrics.blocked_tasks),
        "blocked_tasks",
        "warn",
        "Blocked tasks",
        "Local frontier tasks have unresolved blockers.",
        "/tasks",
        None,
    );
    push_issue(
        &mut issues,
        nonzero(metrics.source_inbox_issues),
        "source_inbox_issues",
        "warn",
        "Source inbox issues",
        "Source records are quarantined, retracted, or stale.",
        "/source-inbox",
        None,
    );
    push_issue(
        &mut issues,
        nonzero(metrics.stale_claims),
        "stale_claims",
        "warn",
        "Claims needing source review",
        "Evidence CI found source, condition, trial, or locator debt on findings.",
        "/review/inbox",
        None,
    );
    push_issue(
        &mut issues,
        nonzero(metrics.contradiction_debt),
        "contradiction_debt",
        "warn",
        "Contradiction debt",
        "Contradictory links are visible and should stay in the review loop.",
        "/conflicts",
        None,
    );
    push_issue(
        &mut issues,
        nonzero(metrics.retraction_impacts),
        "retraction_impacts",
        "warn",
        "Retraction impacts",
        "Retraction-linked source or event state needs downstream review.",
        "/source-inbox?state=retracted",
        None,
    );
    push_issue(
        &mut issues,
        (metrics.max_review_latency_days > 7).then_some(metrics.max_review_latency_days as usize),
        "review_latency",
        "warn",
        "Review latency",
        "At least one pending proposal or Diff Pack has waited more than seven days.",
        "/review/inbox",
        None,
    );
    issues
}

fn push_issue(
    issues: &mut Vec<FrontierHealthIssue>,
    count: Option<usize>,
    id: &str,
    severity: &str,
    label: &str,
    message: &str,
    href: &str,
    target_id: Option<String>,
) {
    if let Some(count) = count.filter(|count| *count > 0) {
        issues.push(FrontierHealthIssue {
            id: id.to_string(),
            severity: severity.to_string(),
            count,
            label: label.to_string(),
            message: message.to_string(),
            href: href.to_string(),
            target_id,
        });
    }
}

fn nonzero(value: usize) -> Option<usize> {
    (value > 0).then_some(value)
}

fn local_repo_root(path: &Path) -> Option<PathBuf> {
    match repo::detect(path).ok()? {
        VelaSource::VelaRepo(root) => Some(root),
        VelaSource::ProjectFile(_) | VelaSource::PacketDir(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(name)
    }

    #[test]
    fn reports_local_frontier_operating_state() {
        let path = fixture("examples/early-ad");
        if !path.exists() {
            eprintln!("skipping: campaign fixture {path:?} absent in this checkout");
            return;
        }
        let report = analyze(&path).unwrap();
        assert_eq!(report.command, "frontier.health");
        assert!(report.metrics.pending_diff_packs >= 1);
        assert!(report.metrics.missing_attestations >= 1);
        assert!(report.metrics.stale_proof);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.id == "missing_attestations")
        );
    }

    #[test]
    fn file_frontier_degrades_without_local_queues() {
        let path = fixture("frontiers/bbb-alzheimer.json");
        if !path.exists() {
            eprintln!("skipping: campaign fixture {path:?} absent in this checkout");
            return;
        }
        let report = analyze(&path).unwrap();
        assert_eq!(report.metrics.active_tasks, 0);
        assert_eq!(report.metrics.source_inbox_issues, 0);
        assert!(!report.threshold_classes.is_empty());
    }
}
