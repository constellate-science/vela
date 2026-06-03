//! Local frontier controllers.
//!
//! Controllers reconcile operational signals into local task records. They do
//! not accept evidence, change claims, or refresh proof packets directly.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::frontier_health::{self, FrontierHealthReport};
use crate::frontier_task::{
    self, FrontierTask, FrontierTaskDraft, FrontierTaskStatus, FrontierTaskSummary,
};
use crate::repo;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FrontierControllerKind {
    StaleEvidence,
    SourceFreshness,
    ContradictionDebt,
    ProofFreshness,
    MissingAttestation,
}

impl FrontierControllerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StaleEvidence => "stale-evidence",
            Self::SourceFreshness => "source-freshness",
            Self::ContradictionDebt => "contradiction-debt",
            Self::ProofFreshness => "proof-freshness",
            Self::MissingAttestation => "missing-attestation",
        }
    }
}

impl fmt::Display for FrontierControllerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FrontierControllerKind {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "stale-evidence" => Ok(Self::StaleEvidence),
            "source-freshness" => Ok(Self::SourceFreshness),
            "contradiction-debt" => Ok(Self::ContradictionDebt),
            "proof-freshness" => Ok(Self::ProofFreshness),
            "missing-attestation" => Ok(Self::MissingAttestation),
            other => Err(format!(
                "controller kind must be one of stale-evidence | source-freshness | contradiction-debt | proof-freshness | missing-attestation; got `{other}`"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierControllerRun {
    pub ok: bool,
    pub command: String,
    pub frontier_id: String,
    pub frontier_path: String,
    pub kind: FrontierControllerKind,
    pub dry_run: bool,
    pub checked_at: String,
    pub health_issue_count: usize,
    pub task_summary_before: FrontierTaskSummary,
    pub task_summary_after: FrontierTaskSummary,
    #[serde(default)]
    pub proposals: Vec<FrontierControllerTaskProposal>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierControllerTaskProposal {
    pub task_id: String,
    pub action: String,
    pub task_type: String,
    pub objective: String,
    #[serde(default)]
    pub inputs: Vec<String>,
    pub risk_class: String,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    pub status: FrontierTaskStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<FrontierTask>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ControllerTaskDraft {
    task_type: String,
    objective: String,
    inputs: Vec<String>,
    risk_class: String,
    acceptance_criteria: Vec<String>,
}

pub fn run(
    frontier_path: &Path,
    kind: FrontierControllerKind,
    dry_run: bool,
) -> Result<FrontierControllerRun, String> {
    let root = frontier_task::repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let health = frontier_health::analyze(&root)?;
    let before = frontier_task::task_summary(&root);
    let drafts = task_drafts(kind, &health);
    let mut proposals = Vec::new();

    for draft in drafts {
        proposals.push(materialize_task(
            &root,
            &project.frontier_id(),
            draft,
            dry_run,
        )?);
    }

    let after = frontier_task::task_summary(&root);
    Ok(FrontierControllerRun {
        ok: true,
        command: "controller.run".to_string(),
        frontier_id: project.frontier_id(),
        frontier_path: root.display().to_string(),
        kind,
        dry_run,
        checked_at: Utc::now().to_rfc3339(),
        health_issue_count: health.issues.len(),
        task_summary_before: before,
        task_summary_after: after,
        proposals,
        caveats: vec![
            "Controllers create local review tasks. They do not mutate accepted frontier state."
                .to_string(),
            "Dry-run output is a reconciliation preview; rerun without --dry-run to write tasks."
                .to_string(),
        ],
    })
}

fn task_drafts(
    kind: FrontierControllerKind,
    health: &FrontierHealthReport,
) -> Vec<ControllerTaskDraft> {
    let metrics = &health.metrics;
    match kind {
        FrontierControllerKind::StaleEvidence => {
            if metrics.stale_claims == 0
                && metrics.evidence_ci_failures == 0
                && metrics.evidence_ci_warnings == 0
            {
                Vec::new()
            } else {
                vec![ControllerTaskDraft {
                    task_type: "stale_evidence_review".to_string(),
                    objective: format!(
                        "Review {} finding(s) with source, evidence, condition, or locator debt.",
                        metrics.stale_claims
                    ),
                    inputs: vec![
                        "health:stale_claims".to_string(),
                        "evidence-ci:frontier".to_string(),
                    ],
                    risk_class: "source_repair".to_string(),
                    acceptance_criteria: vec![
                        "affected findings are inspected against source anchors".to_string(),
                        "accepted fixes are proposed as Diff Packs or review events".to_string(),
                        "unresolved source debt remains visible in Evidence CI".to_string(),
                    ],
                }]
            }
        }
        FrontierControllerKind::SourceFreshness => {
            if metrics.source_inbox_issues == 0 {
                Vec::new()
            } else {
                vec![ControllerTaskDraft {
                    task_type: "source_freshness_review".to_string(),
                    objective: format!(
                        "Review {} source-inbox record(s) that are stale, quarantined, or retracted.",
                        metrics.source_inbox_issues
                    ),
                    inputs: vec!["source-inbox:issues".to_string()],
                    risk_class: "source_repair".to_string(),
                    acceptance_criteria: vec![
                        "source identity and locator are checked".to_string(),
                        "quarantined or retracted sources are routed to review".to_string(),
                        "no source record is treated as accepted evidence by the controller"
                            .to_string(),
                    ],
                }]
            }
        }
        FrontierControllerKind::ContradictionDebt => {
            if metrics.contradiction_debt == 0 {
                Vec::new()
            } else {
                vec![ControllerTaskDraft {
                    task_type: "contradiction_debt_review".to_string(),
                    objective: format!(
                        "Review {} contradictory link(s) and decide whether downstream state needs a Diff Pack.",
                        metrics.contradiction_debt
                    ),
                    inputs: vec!["health:contradiction_debt".to_string()],
                    risk_class: "contradiction_change".to_string(),
                    acceptance_criteria: vec![
                        "contradictory links are inspected with their evidence".to_string(),
                        "downstream findings are listed when confidence may change".to_string(),
                        "review outcome is recorded before any frontier update".to_string(),
                    ],
                }]
            }
        }
        FrontierControllerKind::ProofFreshness => {
            if !metrics.stale_proof {
                Vec::new()
            } else {
                vec![ControllerTaskDraft {
                    task_type: "proof_freshness_review".to_string(),
                    objective: format!(
                        "Regenerate and validate the proof packet because recorded proof state is {}.",
                        metrics.proof_status
                    ),
                    inputs: vec![format!("proof:{}", metrics.proof_status)],
                    risk_class: "proof_freshness".to_string(),
                    acceptance_criteria: vec![
                        "proof packet is regenerated from local frontier state".to_string(),
                        "packet validation passes against the regenerated output".to_string(),
                        "Workbench proof state reports current or explains remaining stale state"
                            .to_string(),
                    ],
                }]
            }
        }
        FrontierControllerKind::MissingAttestation => {
            if metrics.missing_attestation_targets == 0 {
                Vec::new()
            } else {
                vec![ControllerTaskDraft {
                    task_type: "missing_attestation_review".to_string(),
                    objective: format!(
                        "Collect missing scoped attestations for {} pending Diff Pack target(s).",
                        metrics.missing_attestation_targets
                    ),
                    inputs: vec!["diff-packs:missing-attestation".to_string()],
                    risk_class: "decision_impact".to_string(),
                    acceptance_criteria: vec![
                        "required reviewer roles are identified from frontier policy".to_string(),
                        "attestations are recorded with typed reviewer id, role, and reason"
                            .to_string(),
                        "Diff Pack review remains pending until requirements are met".to_string(),
                    ],
                }]
            }
        }
    }
}

fn materialize_task(
    root: &Path,
    frontier_id: &str,
    draft: ControllerTaskDraft,
    dry_run: bool,
) -> Result<FrontierControllerTaskProposal, String> {
    let task_draft = FrontierTaskDraft {
        frontier_id: frontier_id.to_string(),
        task_type: draft.task_type.clone(),
        objective: draft.objective.clone(),
        inputs: draft.inputs.clone(),
        risk_class: draft.risk_class.clone(),
        blockers: Vec::new(),
        acceptance_criteria: draft.acceptance_criteria.clone(),
    };
    let task_id = frontier_task::derive_task_id(&task_draft)?;
    let existing = frontier_task::load_task(root, &task_id).ok();
    let (action, task) = if dry_run {
        ("planned".to_string(), existing)
    } else if let Some(task) = existing {
        ("existing".to_string(), Some(task))
    } else {
        let task = frontier_task::create_task(
            root,
            draft.task_type.clone(),
            draft.objective.clone(),
            draft.inputs.clone(),
            draft.risk_class.clone(),
            Vec::new(),
            draft.acceptance_criteria.clone(),
            FrontierTaskStatus::Eligible,
        )?;
        ("created".to_string(), Some(task))
    };

    Ok(FrontierControllerTaskProposal {
        task_id,
        action,
        task_type: draft.task_type,
        objective: draft.objective,
        inputs: draft.inputs,
        risk_class: draft.risk_class,
        acceptance_criteria: draft.acceptance_criteria,
        status: FrontierTaskStatus::Eligible,
        task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_kind_parses_kebab_case() {
        assert_eq!(
            "source-freshness"
                .parse::<FrontierControllerKind>()
                .unwrap(),
            FrontierControllerKind::SourceFreshness
        );
        assert!(
            "source_freshness"
                .parse::<FrontierControllerKind>()
                .is_err()
        );
    }

    #[test]
    fn proof_freshness_draft_depends_on_stale_proof() {
        let mut report = FrontierHealthReport {
            ok: false,
            command: "frontier.health".to_string(),
            frontier_id: "vfr_demo".to_string(),
            frontier_path: "demo".to_string(),
            checked_at: "2026-05-13T00:00:00Z".to_string(),
            policy_class: "frontier_policy".to_string(),
            metrics: Default::default(),
            issues: Vec::new(),
            links: Vec::new(),
            threshold_classes: Vec::new(),
            caveats: Vec::new(),
        };
        assert!(task_drafts(FrontierControllerKind::ProofFreshness, &report).is_empty());
        report.metrics.stale_proof = true;
        report.metrics.proof_status = "stale".to_string();
        let drafts = task_drafts(FrontierControllerKind::ProofFreshness, &report);
        assert_eq!(drafts.len(), 1);
        assert_eq!(drafts[0].task_type, "proof_freshness_review");
    }
}
