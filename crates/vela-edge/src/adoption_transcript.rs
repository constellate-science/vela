//! First external adoption transcript.
//!
//! The transcript is an operational checklist. It does not certify scientific
//! truth and it does not mutate frontier state.

use crate::adoption_log::{self, AdoptionFrictionSummary};
use crate::frontier_task;
use vela_protocol::repo;
use crate::source_inbox;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

pub const ADOPTION_TRANSCRIPT_SCHEMA: &str = "vela.adoption_transcript.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptionTranscript {
    pub ok: bool,
    pub schema: String,
    pub frontier_path: String,
    pub frontier_id: String,
    pub frontier_name: String,
    #[serde(default)]
    pub commands: Vec<String>,
    pub friction_summary: AdoptionFrictionSummary,
    pub markdown: String,
}

pub fn build(frontier_path: &Path) -> Result<AdoptionTranscript, String> {
    let project = repo::load_from_path(frontier_path)?;
    let source_list = source_inbox::list_records(frontier_path).ok();
    let task_list = frontier_task::list_tasks(frontier_path).ok();
    let friction_summary = adoption_log::list(frontier_path)
        .map(|list| list.summary)
        .unwrap_or_default();
    let pending_pack = project
        .released_diff_packs
        .iter()
        .find(|pack| pack.verdict.is_none());
    let first_source = source_list
        .as_ref()
        .and_then(|list| list.records.first())
        .map(|record| record.id.clone());
    let first_task = task_list
        .as_ref()
        .and_then(|list| list.tasks.first())
        .map(|task| task.id.clone());

    let frontier = frontier_path.display().to_string();
    let mut commands = vec![
        format!("vela doctor {frontier}"),
        format!("vela policy check {frontier} --json"),
        format!("vela source-inbox list {frontier} --json"),
        format!("vela task list {frontier} --json"),
        format!("vela frontier health {frontier} --json"),
        format!("vela evidence-ci {frontier} --json"),
    ];

    if let Some(pack) = pending_pack {
        commands.push(format!(
            "vela diff-pack inspect {frontier} {} --json",
            pack.pack_id
        ));
    } else if let Some(source_id) = first_source {
        commands.push(format!(
            "vela source-inbox create-task {frontier} {source_id} --json"
        ));
    } else {
        commands.push(format!(
            "vela source-inbox resolve {frontier} --doi 10.1056/NEJMoa2212948 --json"
        ));
    }

    if let Some(task_id) = first_task {
        commands.push(format!(
            "vela review-packet build {frontier} {task_id} --json"
        ));
    } else {
        commands.push(format!(
            "vela task create {frontier} --type source_ingestion --objective \"Review source impact\" --status eligible --json"
        ));
    }

    commands.extend([
        format!("vela proof {frontier} --out /tmp/vela-proof"),
        "vela packet validate /tmp/vela-proof".to_string(),
        format!("vela workbench {frontier} --port 3741"),
    ]);

    let markdown = render_markdown(
        &project.project.name,
        &project.frontier_id(),
        &frontier,
        pending_pack.map(|pack| pack.pack_id.as_str()),
        &commands,
        &friction_summary,
    );

    Ok(AdoptionTranscript {
        ok: true,
        schema: ADOPTION_TRANSCRIPT_SCHEMA.to_string(),
        frontier_path: frontier,
        frontier_id: project.frontier_id(),
        frontier_name: project.project.name,
        commands,
        friction_summary,
        markdown,
    })
}

pub fn write_markdown(frontier_path: &Path, out: &Path) -> Result<AdoptionTranscript, String> {
    let transcript = build(frontier_path)?;
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("create transcript directory {}: {e}", parent.display()))?;
    }
    fs::write(out, &transcript.markdown)
        .map_err(|e| format!("write adoption transcript {}: {e}", out.display()))?;
    Ok(transcript)
}

fn render_markdown(
    name: &str,
    frontier_id: &str,
    frontier_path: &str,
    pending_pack: Option<&str>,
    commands: &[String],
    friction_summary: &AdoptionFrictionSummary,
) -> String {
    let pack_note = pending_pack
        .map(|pack| format!("Pending Diff Pack: `{pack}`."))
        .unwrap_or_else(|| {
            "No pending Diff Pack found. Start by routing source-inbox work into a task."
                .to_string()
        });
    let command_block = commands
        .iter()
        .map(|command| format!("{command}\n"))
        .collect::<String>();
    let friction_block = if friction_summary.total == 0 {
        "No local adoption friction records yet.".to_string()
    } else {
        let by_kind = friction_summary
            .by_kind
            .iter()
            .map(|(kind, count)| format!("- {kind}: {count}\n"))
            .collect::<String>();
        format!(
            "{} local adoption friction record(s).\n\nBy kind:\n{}",
            friction_summary.total, by_kind
        )
    };
    format!(
        "# Vela Adoption Transcript\n\nFrontier: {name}\nFrontier id: `{frontier_id}`\nPath: `{frontier_path}`\n\n{pack_note}\n\nThese commands inspect local state. Review and write actions still require explicit reviewer identity and reason.\n\n```bash\n{command_block}```\n\n## Adoption friction\n\n{friction_block}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_protocol::frontier_repo::{self, InitOptions};
    use crate::source_resolver::{self, SourceResolveRequest};
    use tempfile::TempDir;

    #[test]
    fn transcript_uses_source_task_when_no_pack_exists() {
        let tmp = TempDir::new().unwrap();
        frontier_repo::initialize(
            tmp.path(),
            InitOptions {
                name: "Transcript frontier",
                template: "adoption-frontier",
                initialize_git: false,
            },
        )
        .unwrap();
        source_resolver::resolve_into_inbox(
            tmp.path(),
            SourceResolveRequest {
                doi: Some("10.1056/NEJMoa2212948".to_string()),
                pmid: None,
                pmcid: None,
                nct: None,
                url: None,
                local_path: None,
                fetch_metadata: false,
            },
        )
        .unwrap();
        let transcript = build(tmp.path()).unwrap();
        assert!(transcript.markdown.contains("No pending Diff Pack"));
        assert!(
            transcript
                .commands
                .iter()
                .any(|command| command.contains("source-inbox create-task"))
        );
        assert!(
            transcript
                .commands
                .iter()
                .any(|command| command.contains("vela packet validate"))
        );
    }
}
