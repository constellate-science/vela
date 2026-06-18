//! The code-reproduction executor — the second Body executor.
//!
//! The mechanistic-interpretability flagship proved the executable-frontier
//! loop with a *computational* executor (ablation experiments → replication
//! attestation → auto-accept). This generalizes that loop to a second executor
//! kind: run a task's reproduction command in its isolated workspace, capture
//! the output, and feed the result back into the frontier as pending proposals
//! through the existing artifact-to-state path. No auto-accept — a reviewer
//! accepts in the inbox, exactly like every other proposal.
//!
//! The loop: frontier → task → THIS executor → result artifact → proposal →
//! review → state update. Two executor kinds over one Record is the
//! generalization the control-plane vision rests on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::artifact_to_state::{
    self, ArtifactPacket, PacketArtifact, PacketCandidateClaim, PacketProducer,
};
use crate::frontier_task::{self, FrontierTaskStatus};
use crate::task_workspace;

/// The outcome of one reproduction run.
#[derive(Debug, Clone, Serialize)]
pub struct ExecuteReport {
    pub ok: bool,
    pub command: String,
    pub task_id: String,
    pub exit_code: i32,
    pub outcome: String,
    pub log_path: String,
    pub packet_id: String,
    pub proposal_ids: Vec<String>,
    pub finding_proposals: usize,
    pub artifact_proposals: usize,
}

/// Reproduction entrypoint names looked for in the task workspace, in order.
const ENTRYPOINTS: &[&str] = &["run.sh", "repro.sh", "reproduce.sh"];

/// True if a file name is (or content-addressably ends with) an entrypoint.
/// init_workspace copies declared inputs as `sha256-<hash>-<basename>`, so an
/// exact match alone would miss them; suffix-match catches both forms.
fn is_entrypoint(file_name: &str) -> bool {
    ENTRYPOINTS
        .iter()
        .any(|n| file_name == *n || file_name.ends_with(&format!("-{n}")))
}

/// Walk the workspace (shallow, then one level into sources/) for a known
/// reproduction entrypoint. Returns the script path if found.
fn find_entrypoint(workspace: &Path) -> Option<PathBuf> {
    let roots = [workspace.to_path_buf(), workspace.join("sources")];
    for root in &roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let mut subdirs = Vec::new();
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file() {
                if let Some(name) = p.file_name().and_then(|s| s.to_str())
                    && is_entrypoint(name)
                {
                    return Some(p);
                }
            } else if p.is_dir() {
                subdirs.push(p);
            }
        }
        // one level deeper (a copied repo lands in a subdir)
        for sub in subdirs {
            if let Ok(entries) = std::fs::read_dir(&sub) {
                for e in entries.flatten() {
                    let p = e.path();
                    if p.is_file()
                        && let Some(name) = p.file_name().and_then(|s| s.to_str())
                        && is_entrypoint(name)
                    {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

/// Run the reproduction for `task_id`, capture its output, and import the result
/// as pending proposals. The frontier is mutated only through the proposal
/// queue — the executor never writes canonical state directly.
pub fn execute_task(
    frontier_path: &Path,
    task_id: &str,
    actor_id: &str,
) -> Result<ExecuteReport, String> {
    if actor_id.trim().is_empty() {
        return Err("actor must be non-empty".to_string());
    }
    let root = frontier_task::repo_root(frontier_path)?;
    let task = frontier_task::load_task(&root, task_id)?;

    // Materialize the isolated workspace (copies the task's declared inputs into
    // sources/), then mark the task running.
    let ws = task_workspace::init_workspace(&root, task_id)?;
    let workspace = PathBuf::from(&ws.workspace_path);
    frontier_task::set_task_status(&root, task_id, FrontierTaskStatus::Running)?;

    let script = find_entrypoint(&workspace).ok_or_else(|| {
        format!(
            "no reproduction entrypoint in workspace {} (expected one of {:?} in the task inputs)",
            workspace.display(),
            ENTRYPOINTS
        )
    })?;
    let command = format!("bash {}", script.display());

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&workspace)
        .output()
        .map_err(|e| format!("failed to run '{command}': {e}"))?;
    let exit_code = output.status.code().unwrap_or(-1);
    let outcome = if exit_code == 0 {
        "succeeded"
    } else {
        "failed"
    };

    // Persist the captured output as the run log — the result artifact.
    let logs_dir = workspace.join("logs");
    std::fs::create_dir_all(&logs_dir).map_err(|e| format!("create logs dir: {e}"))?;
    let log_path = logs_dir.join("execution.log");
    let mut log: Vec<u8> = Vec::new();
    log.extend_from_slice(
        format!("# command\n{command}\n\n# exit_code\n{exit_code}\n\n").as_bytes(),
    );
    log.extend_from_slice(b"# stdout\n");
    log.extend_from_slice(&output.stdout);
    log.extend_from_slice(b"\n# stderr\n");
    log.extend_from_slice(&output.stderr);
    std::fs::write(&log_path, &log).map_err(|e| format!("write execution log: {e}"))?;

    let content_hash = format!("sha256:{}", hex::encode(Sha256::digest(&log)));
    let now = chrono::Utc::now().to_rfc3339();
    let artifact_id = format!("repro_output_{task_id}");

    let mut metadata: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    metadata.insert("exit_code".to_string(), serde_json::json!(exit_code));
    metadata.insert("command".to_string(), serde_json::json!(command));
    metadata.insert(
        "executor".to_string(),
        serde_json::json!("code-reproduction"),
    );

    let packet = ArtifactPacket {
        schema: artifact_to_state::ARTIFACT_PACKET_SCHEMA.to_string(),
        packet_id: format!("cap_repro_{task_id}"),
        producer: PacketProducer {
            kind: "agent".into(),
            id: actor_id.to_string(),
            name: "Code-reproduction executor".to_string(),
        },
        topic: format!("Code reproduction of task {task_id}"),
        created_at: now,
        artifacts: vec![PacketArtifact {
            id: artifact_id.clone(),
            kind: "model_output".into(),
            title: format!("Reproduction output ({outcome})"),
            locator: format!("file://{}", log_path.display()),
            content_hash,
            parents: vec![],
            metadata,
        }],
        candidate_claims: vec![PacketCandidateClaim {
            id: format!("claim_repro_{task_id}"),
            assertion: format!(
                "Automated reproduction of '{}' {} (exit code {}).",
                task.objective, outcome, exit_code
            ),
            assertion_type: "methodological".to_string(),
            evidence_artifact_ids: vec![artifact_id.clone()],
            source_refs: vec![],
            conditions: vec![format!("entrypoint: {command}")],
            confidence: if exit_code == 0 { 0.7 } else { 0.3 },
            caveats: vec![
                "Automated reproduction result; pending reviewer acceptance.".to_string(),
            ],
        }],
        open_needs: vec![],
        caveats: vec![],
    };

    let packet_json =
        serde_json::to_string_pretty(&packet).map_err(|e| format!("serialize packet: {e}"))?;
    let packet_path = workspace.join("repro_packet.json");
    std::fs::write(&packet_path, packet_json).map_err(|e| format!("write packet: {e}"))?;

    let report = artifact_to_state::import_packet_at_path(&root, &packet_path, actor_id, false)?;

    // Reproduction is reviewer-gated: move to ProposedDiff, never auto-accept.
    frontier_task::set_task_status(&root, task_id, FrontierTaskStatus::ProposedDiff)?;

    Ok(ExecuteReport {
        ok: true,
        command,
        task_id: task_id.to_string(),
        exit_code,
        outcome: outcome.to_string(),
        log_path: log_path.display().to_string(),
        packet_id: packet.packet_id,
        proposal_ids: report.proposal_ids,
        finding_proposals: report.finding_proposals,
        artifact_proposals: report.artifact_proposals,
    })
}
