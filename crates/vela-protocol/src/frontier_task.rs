//! Local frontier tasks.
//!
//! Tasks are schedulable scientific work units. They are local operational
//! records under `.vela/tasks/`; they do not become accepted frontier truth
//! unless later review emits canonical frontier events.

use crate::frontier_health::{self, FrontierHealthReport};
use crate::{canonical, repo};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FrontierTaskStatus {
    Backlog,
    Eligible,
    Claimed,
    PreparingWorkspace,
    Running,
    ProposedDiff,
    AwaitingReview,
    RevisionRequested,
    Accepted,
    Rejected,
    Superseded,
    Archived,
}

impl FrontierTaskStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backlog => "backlog",
            Self::Eligible => "eligible",
            Self::Claimed => "claimed",
            Self::PreparingWorkspace => "preparing_workspace",
            Self::Running => "running",
            Self::ProposedDiff => "proposed_diff",
            Self::AwaitingReview => "awaiting_review",
            Self::RevisionRequested => "revision_requested",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
            Self::Archived => "archived",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Accepted | Self::Rejected | Self::Superseded | Self::Archived
        )
    }
}

impl fmt::Display for FrontierTaskStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FrontierTaskStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "backlog" => Ok(Self::Backlog),
            "eligible" => Ok(Self::Eligible),
            "claimed" => Ok(Self::Claimed),
            "preparing_workspace" => Ok(Self::PreparingWorkspace),
            "running" => Ok(Self::Running),
            "proposed_diff" => Ok(Self::ProposedDiff),
            "awaiting_review" => Ok(Self::AwaitingReview),
            "revision_requested" => Ok(Self::RevisionRequested),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "superseded" => Ok(Self::Superseded),
            "archived" => Ok(Self::Archived),
            other => Err(format!(
                "task status must be one of backlog | eligible | claimed | preparing_workspace | running | proposed_diff | awaiting_review | revision_requested | accepted | rejected | superseded | archived; got `{other}`"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierTask {
    pub id: String,
    pub frontier_id: String,
    #[serde(rename = "type")]
    pub task_type: String,
    pub objective: String,
    #[serde(default)]
    pub inputs: Vec<String>,
    pub risk_class: String,
    #[serde(default)]
    pub blockers: Vec<String>,
    pub status: FrontierTaskStatus,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierTaskDraft {
    pub frontier_id: String,
    #[serde(rename = "type")]
    pub task_type: String,
    pub objective: String,
    #[serde(default)]
    pub inputs: Vec<String>,
    pub risk_class: String,
    #[serde(default)]
    pub blockers: Vec<String>,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierTaskList {
    pub frontier_id: String,
    pub frontier_path: String,
    pub total: usize,
    #[serde(default)]
    pub tasks: Vec<FrontierTask>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierTaskSummary {
    pub total: usize,
    pub active: usize,
    pub blocked: usize,
    pub awaiting_review: usize,
    pub terminal: usize,
}

impl FrontierTaskSummary {
    pub fn from_tasks(tasks: &[FrontierTask]) -> Self {
        Self {
            total: tasks.len(),
            active: tasks
                .iter()
                .filter(|task| !task.status.is_terminal())
                .count(),
            blocked: tasks
                .iter()
                .filter(|task| !task.blockers.is_empty())
                .count(),
            awaiting_review: tasks
                .iter()
                .filter(|task| task.status == FrontierTaskStatus::AwaitingReview)
                .count(),
            terminal: tasks
                .iter()
                .filter(|task| task.status.is_terminal())
                .count(),
        }
    }
}

pub fn create_task(
    frontier_path: &Path,
    task_type: String,
    objective: String,
    inputs: Vec<String>,
    risk_class: String,
    blockers: Vec<String>,
    acceptance_criteria: Vec<String>,
    status: FrontierTaskStatus,
) -> Result<FrontierTask, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let now = chrono::Utc::now().to_rfc3339();
    let draft = FrontierTaskDraft {
        frontier_id: project.frontier_id(),
        task_type: non_empty("type", task_type)?,
        objective: non_empty("objective", objective)?,
        inputs: clean_list(inputs),
        risk_class: non_empty("risk class", risk_class)?,
        blockers: clean_list(blockers),
        acceptance_criteria: clean_list(acceptance_criteria),
    };
    let id = derive_task_id(&draft)?;
    let task = FrontierTask {
        id,
        frontier_id: draft.frontier_id,
        task_type: draft.task_type,
        objective: draft.objective,
        inputs: draft.inputs,
        risk_class: draft.risk_class,
        blockers: draft.blockers,
        status,
        acceptance_criteria: draft.acceptance_criteria,
        created_at: now.clone(),
        updated_at: now,
        claimed_by: None,
        closed_reason: None,
    };
    write_task(&root, &task, false)?;
    Ok(task)
}

pub fn list_tasks(frontier_path: &Path) -> Result<FrontierTaskList, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let mut tasks = Vec::new();
    let dir = tasks_dir(&root);
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| format!("read tasks directory {}: {e}", dir.display()))?
        {
            let entry = entry.map_err(|e| format!("read task entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                tasks.push(read_task_file(&path)?);
            }
        }
    }
    tasks.sort_by(|a, b| {
        a.status
            .cmp(&b.status)
            .then_with(|| b.updated_at.cmp(&a.updated_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(FrontierTaskList {
        frontier_id: project.frontier_id(),
        frontier_path: root.display().to_string(),
        total: tasks.len(),
        tasks,
    })
}

pub fn load_task(frontier_path: &Path, task_id: &str) -> Result<FrontierTask, String> {
    let root = repo_root(frontier_path)?;
    let id = validate_task_id(task_id)?;
    read_task_file(&tasks_dir(&root).join(format!("{id}.json")))
}

pub fn claim_task(
    frontier_path: &Path,
    task_id: &str,
    reviewer: String,
) -> Result<FrontierTask, String> {
    let root = repo_root(frontier_path)?;
    let mut task = load_task(&root, task_id)?;
    task.claimed_by = Some(non_empty("reviewer", reviewer)?);
    task.status = FrontierTaskStatus::Claimed;
    task.updated_at = chrono::Utc::now().to_rfc3339();
    write_task(&root, &task, true)?;
    Ok(task)
}

pub fn close_task(
    frontier_path: &Path,
    task_id: &str,
    status: FrontierTaskStatus,
    reason: String,
) -> Result<FrontierTask, String> {
    if !status.is_terminal() {
        return Err(format!(
            "close status must be accepted, rejected, superseded, or archived; got `{status}`"
        ));
    }
    let root = repo_root(frontier_path)?;
    let mut task = load_task(&root, task_id)?;
    task.status = status;
    task.closed_reason = Some(non_empty("reason", reason)?);
    task.updated_at = chrono::Utc::now().to_rfc3339();
    write_task(&root, &task, true)?;
    Ok(task)
}

pub fn set_task_status(
    frontier_path: &Path,
    task_id: &str,
    status: FrontierTaskStatus,
) -> Result<FrontierTask, String> {
    let root = repo_root(frontier_path)?;
    let mut task = load_task(&root, task_id)?;
    task.status = status;
    task.updated_at = chrono::Utc::now().to_rfc3339();
    write_task(&root, &task, true)?;
    Ok(task)
}

pub fn task_summary(frontier_path: &Path) -> FrontierTaskSummary {
    list_tasks(frontier_path)
        .map(|list| FrontierTaskSummary::from_tasks(&list.tasks))
        .unwrap_or(FrontierTaskSummary {
            total: 0,
            active: 0,
            blocked: 0,
            awaiting_review: 0,
            terminal: 0,
        })
}

pub fn derive_task_id(draft: &FrontierTaskDraft) -> Result<String, String> {
    let hash = canonical::sha256_canonical(draft)?;
    Ok(format!("vtask_{}", &hash[..16]))
}

pub fn repo_root(frontier_path: &Path) -> Result<PathBuf, String> {
    match repo::detect(frontier_path)? {
        repo::VelaSource::VelaRepo(root) => Ok(root),
        repo::VelaSource::ProjectFile(_) | repo::VelaSource::PacketDir(_) => Err(format!(
            "frontier tasks require a local .vela/ repository; got {}",
            frontier_path.display()
        )),
    }
}

pub fn tasks_dir(frontier_root: &Path) -> PathBuf {
    frontier_root.join(".vela").join("tasks")
}

fn write_task(root: &Path, task: &FrontierTask, overwrite: bool) -> Result<(), String> {
    validate_task_id(&task.id)?;
    let dir = tasks_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("create tasks directory {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", task.id));
    if path.exists() && !overwrite {
        return Err(format!(
            "task {} already exists at {}",
            task.id,
            path.display()
        ));
    }
    let body = serde_json::to_string_pretty(task)
        .map_err(|e| format!("serialize task {}: {e}", task.id))?;
    std::fs::write(&path, format!("{body}\n"))
        .map_err(|e| format!("write task {}: {e}", path.display()))
}

fn read_task_file(path: &Path) -> Result<FrontierTask, String> {
    let body =
        std::fs::read_to_string(path).map_err(|e| format!("read task {}: {e}", path.display()))?;
    let task: FrontierTask =
        serde_json::from_str(&body).map_err(|e| format!("parse task {}: {e}", path.display()))?;
    validate_task_id(&task.id)?;
    Ok(task)
}

fn validate_task_id(task_id: &str) -> Result<String, String> {
    let ok = task_id.starts_with("vtask_")
        && task_id.len() == "vtask_".len() + 16
        && task_id["vtask_".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase());
    if ok {
        Ok(task_id.to_string())
    } else {
        Err(format!("invalid frontier task id `{task_id}`"))
    }
}

fn non_empty(label: &str, value: String) -> Result<String, String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        Err(format!("task {label} is required"))
    } else {
        Ok(trimmed)
    }
}

fn clean_list(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_snake_case() {
        assert_eq!(
            "awaiting_review".parse::<FrontierTaskStatus>().unwrap(),
            FrontierTaskStatus::AwaitingReview
        );
        assert_eq!(
            FrontierTaskStatus::ProposedDiff.to_string(),
            "proposed_diff"
        );
    }

    #[test]
    fn task_id_is_stable_over_canonical_seed() {
        let draft = FrontierTaskDraft {
            frontier_id: "vfr_demo".to_string(),
            task_type: "source_ingestion".to_string(),
            objective: "Check whether a source changes one claim.".to_string(),
            inputs: vec!["doi:10.1/demo".to_string()],
            risk_class: "source_repair".to_string(),
            blockers: vec![],
            acceptance_criteria: vec!["source is linked to evidence".to_string()],
        };
        let first = derive_task_id(&draft).unwrap();
        let second = derive_task_id(&draft).unwrap();
        assert_eq!(first, second);
        assert!(first.starts_with("vtask_"));
    }
}

// ---------------------------------------------------------------------------
// Local frontier controllers (merged from the former `frontier_controller`
// module). Controllers reconcile operational signals into local task records.
// They do not accept evidence, change claims, or refresh proof packets.
// ---------------------------------------------------------------------------

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
    let root = crate::frontier_task::repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let health = frontier_health::analyze(&root)?;
    let before = crate::frontier_task::task_summary(&root);
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

    let after = crate::frontier_task::task_summary(&root);
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
    let task_id = crate::frontier_task::derive_task_id(&task_draft)?;
    let existing = crate::frontier_task::load_task(root, &task_id).ok();
    let (action, task) = if dry_run {
        ("planned".to_string(), existing)
    } else if let Some(task) = existing {
        ("existing".to_string(), Some(task))
    } else {
        let task = crate::frontier_task::create_task(
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
mod controller_tests {
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
