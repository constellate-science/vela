//! Review packets for local frontier tasks.
//!
//! A review packet is a human-readable handoff built from a task
//! workspace, optional Scientific Diff Pack, and Evidence CI. It is a
//! review artifact. It does not accept frontier state.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::evidence_ci::{self, EvidenceCiReport};
use crate::frontier_task::{self, FrontierTask};
use crate::scientific_diff::DiffPackReviewSummary;
use crate::{repo, task_workspace};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacket {
    pub schema: String,
    pub packet_id: String,
    pub created_at: String,
    pub frontier_id: String,
    pub frontier_path: String,
    pub task: ReviewPacketTask,
    #[serde(default)]
    pub sources: Vec<ReviewPacketSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diff_pack: Option<ReviewPacketDiff>,
    pub evidence_ci: ReviewPacketEvidenceCi,
    #[serde(default)]
    pub affected_findings: Vec<String>,
    #[serde(default)]
    pub downstream_impacts: Vec<String>,
    pub proof_freshness_impact: String,
    #[serde(default)]
    pub required_reviewers: Vec<String>,
    #[serde(default)]
    pub reviewer_questions: Vec<String>,
    pub commands: ReviewPacketCommands,
    pub workspace_path: String,
    pub markdown_path: String,
    pub json_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacketTask {
    pub id: String,
    pub objective: String,
    pub task_type: String,
    pub risk_class: String,
    pub status: String,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacketSource {
    pub input: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacketDiff {
    pub pack_id: String,
    pub summary: String,
    pub aggregate_kind: String,
    pub members: usize,
    #[serde(default)]
    pub operation_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub operation_table: Vec<ReviewPacketOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacketOperation {
    pub proposal_id: String,
    pub operation_class: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    pub review_class: String,
    pub required_reviewer_count: usize,
    #[serde(default)]
    pub required_roles: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacketEvidenceCi {
    pub ok: bool,
    pub scope: String,
    pub total: usize,
    pub warnings: usize,
    pub failed: usize,
    pub release_blocking_failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacketCommands {
    pub inspect_diff_pack: String,
    pub validate_evidence_ci: String,
    pub accept: String,
    pub reject: String,
    pub request_revision: String,
    pub promote_verdicts: String,
    pub regenerate_proof: String,
    pub validate_packet: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewPacketBuild {
    pub packet: ReviewPacket,
    pub markdown: String,
    pub json: String,
}

pub fn build(
    frontier_path: &Path,
    task_id: &str,
    out: Option<&Path>,
) -> Result<ReviewPacketBuild, String> {
    let root = frontier_task::repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let task = frontier_task::load_task(&root, task_id)?;
    let status = ensure_workspace(&root, task_id)?;
    let pack_id = discover_pack_id(&root, &task, &status)?;
    let diff_summary = if let Some(pack_id) = &pack_id {
        Some(load_diff_summary(&root, pack_id)?)
    } else {
        None
    };
    let evidence_ci_report = if let Some(pack_id) = &pack_id {
        evidence_ci::run_diff_pack(&root, pack_id)?
    } else {
        evidence_ci::run_frontier(&root)?
    };

    let sources = status
        .source_artifacts
        .iter()
        .map(|source| ReviewPacketSource {
            input: source.input.clone(),
            status: source.status.clone(),
            workspace_path: source.workspace_path.clone(),
            sha256: source.sha256.clone(),
        })
        .collect::<Vec<_>>();

    let (
        diff_pack,
        affected_findings,
        downstream_impacts,
        proof_freshness_impact,
        required_reviewers,
    ) = diff_summary.as_ref().map(diff_sections).unwrap_or_else(|| {
        (
            None,
            Vec::new(),
            Vec::new(),
            "unchanged_by_packet".to_string(),
            vec!["local_reviewer".to_string()],
        )
    });
    let reviewer_questions = reviewer_questions(
        &task,
        evidence_ci_report.summary.warnings,
        evidence_ci_report.summary.release_blocking_failed,
        diff_pack.as_ref(),
    );
    let commands = commands_for(&root, task_id, pack_id.as_deref());
    let packet_id = packet_id(&root, task_id, pack_id.as_deref(), &evidence_ci_report)?;
    let workspace_path = task_workspace::workspace_root(&root, task_id)?;
    let markdown_path = workspace_path.join("review_packet.md");
    let json_path = workspace_path.join("review_packet.json");
    let created_at = existing_packet_created_at(&json_path, &packet_id)
        .unwrap_or_else(|| Utc::now().to_rfc3339());
    let packet = ReviewPacket {
        schema: "vela.review-packet.v0".to_string(),
        packet_id,
        created_at,
        frontier_id: project.frontier_id(),
        frontier_path: root.display().to_string(),
        task: ReviewPacketTask {
            id: task.id.clone(),
            objective: task.objective.clone(),
            task_type: task.task_type.clone(),
            risk_class: task.risk_class.clone(),
            status: task.status.to_string(),
            acceptance_criteria: task.acceptance_criteria.clone(),
        },
        sources,
        diff_pack,
        evidence_ci: evidence_ci_section(&evidence_ci_report),
        affected_findings,
        downstream_impacts,
        proof_freshness_impact,
        required_reviewers,
        reviewer_questions,
        commands,
        workspace_path: workspace_path.display().to_string(),
        markdown_path: markdown_path.display().to_string(),
        json_path: json_path.display().to_string(),
    };
    let markdown = render_markdown(&packet);
    let json =
        serde_json::to_string_pretty(&packet).map_err(|e| format!("serialize packet: {e}"))?;
    write_file(&markdown_path, markdown.as_bytes())?;
    write_file(&json_path, format!("{json}\n").as_bytes())?;
    if let Some(out) = out {
        write_file(out, markdown.as_bytes())?;
    }
    Ok(ReviewPacketBuild {
        packet,
        markdown,
        json,
    })
}

fn ensure_workspace(
    root: &Path,
    task_id: &str,
) -> Result<task_workspace::TaskWorkspaceStatus, String> {
    let status = task_workspace::workspace_status(root, task_id)?;
    if status.exists {
        Ok(status)
    } else {
        task_workspace::init_workspace(root, task_id)
    }
}

fn discover_pack_id(
    root: &Path,
    task: &FrontierTask,
    status: &task_workspace::TaskWorkspaceStatus,
) -> Result<Option<String>, String> {
    for input in &task.inputs {
        if let Some(pack_id) = input.strip_prefix("diff-pack:") {
            return Ok(Some(pack_id.trim().to_string()));
        }
        if input.starts_with("vsd_") {
            return Ok(Some(input.trim().to_string()));
        }
    }
    let workspace = PathBuf::from(&status.workspace_path);
    let workspace_pack_dir = workspace.join("diff_pack");
    if workspace_pack_dir.is_dir() {
        for entry in std::fs::read_dir(&workspace_pack_dir)
            .map_err(|e| format!("read diff_pack workspace directory: {e}"))?
        {
            let path = entry
                .map_err(|e| format!("read diff_pack entry: {e}"))?
                .path();
            if path.extension().is_some_and(|ext| ext == "json")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                && stem.starts_with("vsd_")
            {
                return Ok(Some(stem.to_string()));
            }
        }
    }
    let pack_dir = root.join(".vela").join("diff_packs");
    let proposal_inputs = task
        .inputs
        .iter()
        .filter_map(|input| input.strip_prefix("proposal:"))
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .collect::<BTreeSet<_>>();
    if pack_dir.is_dir() {
        if !proposal_inputs.is_empty() {
            let mut exact_matches = Vec::new();
            let mut partial_matches = Vec::new();
            for entry in std::fs::read_dir(&pack_dir)
                .map_err(|e| format!("read diff pack directory {}: {e}", pack_dir.display()))?
            {
                let path = entry
                    .map_err(|e| format!("read diff pack entry: {e}"))?
                    .path();
                if path.extension().is_some_and(|ext| ext == "json")
                    && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                    && stem.starts_with("vsd_")
                {
                    let body = std::fs::read_to_string(&path)
                        .map_err(|e| format!("read diff pack {}: {e}", path.display()))?;
                    let pack: crate::scientific_diff::ScientificDiffPack =
                        serde_json::from_str(&body)
                            .map_err(|e| format!("parse diff pack {}: {e}", path.display()))?;
                    let pack_proposals = pack
                        .proposals
                        .iter()
                        .map(String::as_str)
                        .collect::<BTreeSet<_>>();
                    if proposal_inputs
                        .iter()
                        .all(|proposal_id| pack_proposals.contains(proposal_id))
                    {
                        exact_matches.push(stem.to_string());
                    } else if proposal_inputs
                        .iter()
                        .any(|proposal_id| pack_proposals.contains(proposal_id))
                    {
                        partial_matches.push(stem.to_string());
                    }
                }
            }
            exact_matches.sort();
            exact_matches.dedup();
            if exact_matches.len() == 1 {
                return Ok(exact_matches.pop());
            }
            partial_matches.sort();
            partial_matches.dedup();
            if partial_matches.len() == 1 {
                return Ok(partial_matches.pop());
            }
        }
        let mut ids = Vec::new();
        for entry in std::fs::read_dir(&pack_dir)
            .map_err(|e| format!("read diff pack directory {}: {e}", pack_dir.display()))?
        {
            let path = entry
                .map_err(|e| format!("read diff pack entry: {e}"))?
                .path();
            if path.extension().is_some_and(|ext| ext == "json")
                && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                && stem.starts_with("vsd_")
            {
                ids.push(stem.to_string());
            }
        }
        ids.sort();
        if ids.len() == 1 {
            return Ok(ids.pop());
        }
    }
    Ok(None)
}

fn load_diff_summary(root: &Path, pack_id: &str) -> Result<DiffPackReviewSummary, String> {
    let pack_path = root
        .join(".vela")
        .join("diff_packs")
        .join(format!("{pack_id}.json"));
    let body = std::fs::read_to_string(&pack_path)
        .map_err(|e| format!("read diff pack {}: {e}", pack_path.display()))?;
    let pack: crate::scientific_diff::ScientificDiffPack =
        serde_json::from_str(&body).map_err(|e| format!("parse diff pack: {e}"))?;
    pack.verify()
        .map_err(|e| format!("verify diff pack {pack_id}: {e}"))?;
    Ok(pack.review_summary(root))
}

fn diff_sections(
    summary: &DiffPackReviewSummary,
) -> (
    Option<ReviewPacketDiff>,
    Vec<String>,
    Vec<String>,
    String,
    Vec<String>,
) {
    let operations = summary
        .proposed_operations
        .iter()
        .map(|op| ReviewPacketOperation {
            proposal_id: op.proposal_id.clone(),
            operation_class: op.operation_class.clone(),
            kind: op.kind.clone(),
            target_id: op.target_id.clone(),
            review_class: op.review_class.clone(),
            required_reviewer_count: op.required_reviewer_count,
            required_roles: op.required_reviewer_roles.clone(),
            summary: op.summary.clone(),
        })
        .collect::<Vec<_>>();
    (
        Some(ReviewPacketDiff {
            pack_id: summary.pack_id.clone(),
            summary: summary.summary.clone(),
            aggregate_kind: summary.aggregate_kind.clone(),
            members: summary.members,
            operation_counts: summary.operation_counts.clone(),
            operation_table: operations,
        }),
        summary.affected_findings.clone(),
        summary.downstream_impacts.clone(),
        if summary.proof_freshness_impact {
            "stale_if_accepted".to_string()
        } else {
            "no_direct_packet_impact".to_string()
        },
        summary.required_reviewers.clone(),
    )
}

fn evidence_ci_section(report: &EvidenceCiReport) -> ReviewPacketEvidenceCi {
    ReviewPacketEvidenceCi {
        ok: report.ok,
        scope: report.scope.clone(),
        total: report.summary.total,
        warnings: report.summary.warnings,
        failed: report.summary.failed,
        release_blocking_failed: report.summary.release_blocking_failed,
    }
}

fn reviewer_questions(
    task: &FrontierTask,
    warnings: usize,
    release_blocking_failed: usize,
    diff_pack: Option<&ReviewPacketDiff>,
) -> Vec<String> {
    let mut questions = vec![
        format!(
            "Does the task objective match the proposed review scope: {}?",
            task.objective
        ),
        "Are the cited sources and evidence spans sufficient for local review?".to_string(),
        "Do the proposed operations preserve the stated frontier boundary?".to_string(),
    ];
    if warnings > 0 {
        questions.push(format!(
            "Which of the {warnings} Evidence CI warning(s) should become source repair or revision tasks?"
        ));
    }
    if release_blocking_failed > 0 {
        questions.push(
            "Which release-blocking Evidence CI failure(s) must be fixed before verdict?"
                .to_string(),
        );
    }
    if diff_pack.is_some() {
        questions.push(
            "If accepted, which proof packet should be regenerated and validated?".to_string(),
        );
    }
    questions
}

fn commands_for(root: &Path, task_id: &str, pack_id: Option<&str>) -> ReviewPacketCommands {
    let frontier = root.display().to_string();
    let pack = pack_id.unwrap_or("vsd_PACK_ID");
    ReviewPacketCommands {
        inspect_diff_pack: format!("vela diff-pack inspect {frontier} {pack} --json"),
        validate_evidence_ci: format!(
            "vela diff-pack validate {frontier} {pack} --evidence-ci --json"
        ),
        accept: format!(
            "curl -fsS -X POST http://127.0.0.1:PORT/diff-packs/{pack}/accept -d reviewer=reviewer:you -d reason='bounded review reason'"
        ),
        reject: format!(
            "curl -fsS -X POST http://127.0.0.1:PORT/diff-packs/{pack}/reject -d reviewer=reviewer:you -d reason='bounded review reason'"
        ),
        request_revision: format!(
            "curl -fsS -X POST http://127.0.0.1:PORT/diff-packs/{pack}/revise -d reviewer=reviewer:you -d reason='bounded review reason'"
        ),
        promote_verdicts: format!("vela diff-pack promote-verdicts {frontier} --json"),
        regenerate_proof: format!(
            "vela proof {frontier} --out /tmp/{task_id}-proof --record-proof-state --json"
        ),
        validate_packet: format!("vela packet validate /tmp/{task_id}-proof --json"),
    }
}

fn packet_id(
    root: &Path,
    task_id: &str,
    pack_id: Option<&str>,
    evidence_ci: &EvidenceCiReport,
) -> Result<String, String> {
    let value = serde_json::json!({
        "schema": "vela.review-packet-id.v0",
        "frontier": root.display().to_string(),
        "task_id": task_id,
        "pack_id": pack_id,
        "evidence_ci_scope": &evidence_ci.scope,
        "evidence_ci_total": evidence_ci.summary.total,
    });
    let hash = crate::canonical::sha256_canonical(&value)?;
    Ok(format!("vrp_{}", &hash[..16]))
}

fn render_markdown(packet: &ReviewPacket) -> String {
    let mut out = String::new();
    out.push_str("# Review packet\n\n");
    out.push_str(&format!("Packet: `{}`\n\n", packet.packet_id));
    out.push_str(&format!("Frontier: `{}`\n\n", packet.frontier_id));
    out.push_str("## Task\n\n");
    out.push_str(&format!("- id: `{}`\n", packet.task.id));
    out.push_str(&format!("- objective: {}\n", packet.task.objective));
    out.push_str(&format!("- type: `{}`\n", packet.task.task_type));
    out.push_str(&format!("- risk class: `{}`\n", packet.task.risk_class));
    out.push_str(&format!("- status: `{}`\n", packet.task.status));
    if !packet.task.acceptance_criteria.is_empty() {
        out.push_str("- acceptance criteria:\n");
        for criterion in &packet.task.acceptance_criteria {
            out.push_str(&format!("  - {criterion}\n"));
        }
    }
    out.push_str("\n## Sources\n\n");
    if packet.sources.is_empty() {
        out.push_str("No copied source artifacts are present in the workspace.\n\n");
    } else {
        out.push_str("| input | status | workspace path | hash |\n");
        out.push_str("| --- | --- | --- | --- |\n");
        for source in &packet.sources {
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                source.input,
                source.status,
                source.workspace_path.as_deref().unwrap_or("n/a"),
                source.sha256.as_deref().unwrap_or("n/a")
            ));
        }
        out.push('\n');
    }
    out.push_str("## Diff summary\n\n");
    if let Some(diff) = &packet.diff_pack {
        out.push_str(&format!("- pack: `{}`\n", diff.pack_id));
        out.push_str(&format!("- summary: {}\n", diff.summary));
        out.push_str(&format!("- aggregate kind: `{}`\n", diff.aggregate_kind));
        out.push_str(&format!("- members: {}\n\n", diff.members));
        out.push_str(
            "| proposal | operation | kind | target | review class | reviewers | note |\n",
        );
        out.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
        for op in &diff.operation_table {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | `{}` | {} | {} |\n",
                op.proposal_id,
                op.operation_class,
                op.kind,
                op.target_id.as_deref().unwrap_or("n/a"),
                op.review_class,
                op.required_roles.join(", "),
                op.summary.replace('|', "/")
            ));
        }
        out.push('\n');
    } else {
        out.push_str("No Scientific Diff Pack was linked to this task.\n\n");
    }
    out.push_str("## Evidence CI\n\n");
    out.push_str(&format!(
        "- status: `{}`\n- scope: `{}`\n- checks: {}\n- warnings: {}\n- failed: {}\n- release-blocking failures: {}\n\n",
        if packet.evidence_ci.ok { "ready" } else { "blocked" },
        packet.evidence_ci.scope,
        packet.evidence_ci.total,
        packet.evidence_ci.warnings,
        packet.evidence_ci.failed,
        packet.evidence_ci.release_blocking_failed
    ));
    out.push_str("## Impact\n\n");
    out.push_str(&format!(
        "- proof freshness impact: `{}`\n",
        packet.proof_freshness_impact
    ));
    out.push_str(&list_block("affected findings", &packet.affected_findings));
    out.push_str(&list_block(
        "downstream impacts",
        &packet.downstream_impacts,
    ));
    out.push_str(&list_block(
        "required reviewers",
        &packet.required_reviewers,
    ));
    out.push_str("\n## Reviewer questions\n\n");
    for question in &packet.reviewer_questions {
        out.push_str(&format!("- {question}\n"));
    }
    out.push_str("\n## Commands\n\n");
    out.push_str(&command_block(
        "inspect diff pack",
        &packet.commands.inspect_diff_pack,
    ));
    out.push_str(&command_block(
        "validate Evidence CI",
        &packet.commands.validate_evidence_ci,
    ));
    out.push_str(&command_block("accept", &packet.commands.accept));
    out.push_str(&command_block("reject", &packet.commands.reject));
    out.push_str(&command_block(
        "request revision",
        &packet.commands.request_revision,
    ));
    out.push_str(&command_block(
        "promote verdicts",
        &packet.commands.promote_verdicts,
    ));
    out.push_str(&command_block(
        "regenerate proof",
        &packet.commands.regenerate_proof,
    ));
    out.push_str(&command_block(
        "validate packet",
        &packet.commands.validate_packet,
    ));
    out.push_str(
        "\nReview packet validates review readiness. It does not accept scientific state.\n",
    );
    out
}

fn list_block(label: &str, values: &[String]) -> String {
    let mut out = format!("\n### {label}\n\n");
    if values.is_empty() {
        out.push_str("None declared.\n");
    } else {
        for value in values {
            out.push_str(&format!("- {value}\n"));
        }
    }
    out
}

fn command_block(label: &str, command: &str) -> String {
    format!("### {label}\n\n```bash\n{command}\n```\n\n")
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create review packet parent {}: {e}", parent.display()))?;
    }
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))
}

fn existing_packet_created_at(path: &Path, packet_id: &str) -> Option<String> {
    let body = std::fs::read_to_string(path).ok()?;
    let packet: serde_json::Value = serde_json::from_str(&body).ok()?;
    if packet.get("packet_id")?.as_str()? == packet_id {
        packet
            .get("created_at")?
            .as_str()
            .map(std::string::ToString::to_string)
    } else {
        None
    }
}
