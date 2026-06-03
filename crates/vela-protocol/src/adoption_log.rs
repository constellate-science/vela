//! Local-only adoption friction log.
//!
//! These records capture where first users get stuck. They stay in the
//! selected local frontier and are not transmitted.

use crate::{frontier_task, repo};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const ADOPTION_FRICTION_SCHEMA: &str = "vela.adoption_friction.v0.1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptionFrictionRecord {
    pub schema: String,
    pub id: String,
    pub frontier_id: String,
    pub step: String,
    #[serde(default = "default_category")]
    pub category: String,
    pub kind: String,
    pub note: String,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptionFrictionFollowUp {
    pub ok: bool,
    pub record: AdoptionFrictionRecord,
    pub task: frontier_task::FrontierTask,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptionFrictionList {
    pub ok: bool,
    pub frontier_id: String,
    pub path: String,
    pub total: usize,
    #[serde(default)]
    pub records: Vec<AdoptionFrictionRecord>,
    pub summary: AdoptionFrictionSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdoptionFrictionSummary {
    pub total: usize,
    pub open: usize,
    pub closed: usize,
    #[serde(default)]
    pub by_kind: BTreeMap<String, usize>,
    #[serde(default)]
    pub by_category: BTreeMap<String, usize>,
    #[serde(default)]
    pub by_step: BTreeMap<String, usize>,
    pub linked_to_task: usize,
}

pub fn log(
    frontier_path: &Path,
    step: &str,
    kind: &str,
    note: &str,
) -> Result<AdoptionFrictionRecord, String> {
    log_with_category(frontier_path, step, None, kind, note)
}

pub fn log_with_category(
    frontier_path: &Path,
    step: &str,
    category: Option<&str>,
    kind: &str,
    note: &str,
) -> Result<AdoptionFrictionRecord, String> {
    validate_kind(kind)?;
    let category = category
        .map(normalize_category)
        .unwrap_or_else(|| derive_category(step));
    validate_category(&category)?;
    let project = repo::load_from_path(frontier_path)?;
    let created_at = chrono::Utc::now().to_rfc3339();
    let mut hasher = Sha256::new();
    hasher.update(project.frontier_id());
    hasher.update(step.trim());
    hasher.update(kind.trim());
    hasher.update(note.trim());
    hasher.update(&created_at);
    let id = format!("vaf_{}", &hex::encode(hasher.finalize())[..16]);
    let record = AdoptionFrictionRecord {
        schema: ADOPTION_FRICTION_SCHEMA.to_string(),
        id,
        frontier_id: project.frontier_id(),
        step: step.trim().to_string(),
        category,
        kind: kind.trim().to_string(),
        note: note.trim().to_string(),
        status: default_status(),
        linked_task_id: None,
        closed_at: None,
        closed_reason: None,
        updated_at: None,
        created_at,
    };
    let path = friction_path(frontier_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create adoption log dir: {e}"))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("open adoption friction log {}: {e}", path.display()))?;
    let line =
        serde_json::to_string(&record).map_err(|e| format!("serialize friction record: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("write adoption friction log: {e}"))?;
    Ok(record)
}

pub fn list(frontier_path: &Path) -> Result<AdoptionFrictionList, String> {
    let project = repo::load_from_path(frontier_path)?;
    let path = friction_path(frontier_path);
    let records = read_records(&path)?;
    let summary = summarize(&records);
    Ok(AdoptionFrictionList {
        ok: true,
        frontier_id: project.frontier_id(),
        path: path.display().to_string(),
        total: records.len(),
        records,
        summary,
    })
}

pub fn classify(
    frontier_path: &Path,
    record_id: &str,
    category: &str,
) -> Result<AdoptionFrictionRecord, String> {
    let category = normalize_category(category);
    validate_category(&category)?;
    update_record(frontier_path, record_id, |record| {
        record.category = category.clone();
        record.updated_at = Some(chrono::Utc::now().to_rfc3339());
    })
}

pub fn link_task(
    frontier_path: &Path,
    record_id: &str,
    task_id: &str,
) -> Result<AdoptionFrictionRecord, String> {
    let task = frontier_task::load_task(frontier_path, task_id)?;
    update_record(frontier_path, record_id, |record| {
        record.linked_task_id = Some(task.id.clone());
        record.updated_at = Some(chrono::Utc::now().to_rfc3339());
    })
}

pub fn close(
    frontier_path: &Path,
    record_id: &str,
    reason: &str,
) -> Result<AdoptionFrictionRecord, String> {
    let reason = non_empty("reason", reason)?;
    update_record(frontier_path, record_id, |record| {
        let now = chrono::Utc::now().to_rfc3339();
        record.status = "closed".to_string();
        record.closed_at = Some(now.clone());
        record.closed_reason = Some(reason.clone());
        record.updated_at = Some(now);
    })
}

pub fn create_follow_up_task(
    frontier_path: &Path,
    record_id: &str,
    objective: Option<String>,
    status: frontier_task::FrontierTaskStatus,
) -> Result<AdoptionFrictionFollowUp, String> {
    let record = find_record(frontier_path, record_id)?;
    let objective = objective
        .map(|value| non_empty("objective", &value))
        .transpose()?
        .unwrap_or_else(|| {
            format!(
                "Resolve adoption friction {} in {}: {}",
                record.id, record.category, record.note
            )
        });
    let task = frontier_task::create_task(
        frontier_path,
        "adoption_friction_followup".to_string(),
        objective,
        vec![record.id.clone()],
        "reviewer_friction".to_string(),
        vec![],
        vec![
            "friction record is inspected".to_string(),
            "local reviewer can confirm the confusing step is resolved".to_string(),
        ],
        status,
    )?;
    let record = link_task(frontier_path, record_id, &task.id)?;
    Ok(AdoptionFrictionFollowUp {
        ok: true,
        record,
        task,
    })
}

fn find_record(frontier_path: &Path, record_id: &str) -> Result<AdoptionFrictionRecord, String> {
    let path = friction_path(frontier_path);
    read_records(&path)?
        .into_iter()
        .find(|record| record.id == record_id)
        .ok_or_else(|| format!("adoption friction record not found: {record_id}"))
}

fn update_record<F>(
    frontier_path: &Path,
    record_id: &str,
    mut update: F,
) -> Result<AdoptionFrictionRecord, String>
where
    F: FnMut(&mut AdoptionFrictionRecord),
{
    let path = friction_path(frontier_path);
    let mut records = read_records(&path)?;
    let mut updated = None;
    for record in &mut records {
        if record.id == record_id {
            update(record);
            updated = Some(record.clone());
            break;
        }
    }
    let updated =
        updated.ok_or_else(|| format!("adoption friction record not found: {record_id}"))?;
    write_records(&path, &records)?;
    Ok(updated)
}

fn read_records(path: &Path) -> Result<Vec<AdoptionFrictionRecord>, String> {
    let mut records = Vec::new();
    if path.is_file() {
        for (index, line) in fs::read_to_string(path)
            .map_err(|e| format!("read adoption friction log {}: {e}", path.display()))?
            .lines()
            .enumerate()
        {
            if line.trim().is_empty() {
                continue;
            }
            let record = serde_json::from_str::<AdoptionFrictionRecord>(line)
                .map_err(|e| format!("parse adoption friction log line {}: {e}", index + 1))?;
            records.push(record);
        }
    }
    Ok(records)
}

fn write_records(path: &Path, records: &[AdoptionFrictionRecord]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create adoption log dir: {e}"))?;
    }
    let mut body = String::new();
    for record in records {
        body.push_str(
            &serde_json::to_string(record)
                .map_err(|e| format!("serialize friction record: {e}"))?,
        );
        body.push('\n');
    }
    fs::write(path, body)
        .map_err(|e| format!("write adoption friction log {}: {e}", path.display()))
}

pub fn friction_path(frontier_path: &Path) -> PathBuf {
    frontier_path
        .join(".vela")
        .join("adoption")
        .join("friction.jsonl")
}

pub fn summarize(records: &[AdoptionFrictionRecord]) -> AdoptionFrictionSummary {
    let mut summary = AdoptionFrictionSummary {
        total: records.len(),
        ..AdoptionFrictionSummary::default()
    };
    for record in records {
        if record.status == "closed" {
            summary.closed += 1;
        } else {
            summary.open += 1;
        }
        *summary.by_kind.entry(record.kind.clone()).or_insert(0) += 1;
        *summary
            .by_category
            .entry(record.category.clone())
            .or_insert(0) += 1;
        *summary.by_step.entry(record.step.clone()).or_insert(0) += 1;
        if record.linked_task_id.is_some() {
            summary.linked_to_task += 1;
        }
    }
    summary
}

pub fn valid_categories() -> &'static [&'static str] {
    &[
        "install",
        "source-intake",
        "workbench-navigation",
        "diff-pack-review",
        "proof",
        "share",
        "trust-boundary",
        "docs",
    ]
}

pub fn valid_kinds() -> &'static [&'static str] {
    &[
        "confusing",
        "missing_doc",
        "command_failed",
        "slow_step",
        "trust_blocker",
        "useful_object",
    ]
}

fn validate_category(category: &str) -> Result<(), String> {
    if valid_categories().contains(&category) {
        Ok(())
    } else {
        Err(format!(
            "adoption friction category must be one of {}; got `{category}`",
            valid_categories().join(", ")
        ))
    }
}

fn validate_kind(kind: &str) -> Result<(), String> {
    if valid_kinds().contains(&kind) {
        Ok(())
    } else {
        Err(format!(
            "adoption friction kind must be one of {}; got `{kind}`",
            valid_kinds().join(", ")
        ))
    }
}

fn derive_category(step: &str) -> String {
    let step = step.trim().to_ascii_lowercase();
    if step.contains("install") || step.contains("build") {
        "install"
    } else if step.contains("source") {
        "source-intake"
    } else if step.contains("diff") || step.contains("pack") {
        "diff-pack-review"
    } else if step.contains("proof") || step.contains("packet validate") {
        "proof"
    } else if step.contains("share") {
        "share"
    } else if step.contains("trust") || step.contains("hub") || step.contains("boundary") {
        "trust-boundary"
    } else if step.contains("doc") || step.contains("readme") {
        "docs"
    } else {
        "workbench-navigation"
    }
    .to_string()
}

fn normalize_category(category: &str) -> String {
    category.trim().replace('_', "-").to_ascii_lowercase()
}

fn default_category() -> String {
    "workbench-navigation".to_string()
}

fn default_status() -> String {
    "open".to_string()
}

fn non_empty(label: &str, value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(format!("adoption friction {label} is required"))
    } else {
        Ok(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontier_repo::{self, InitOptions};
    use tempfile::TempDir;

    #[test]
    fn logs_and_summarizes_local_friction() {
        let tmp = TempDir::new().unwrap();
        frontier_repo::initialize(
            tmp.path(),
            InitOptions {
                name: "Friction frontier",
                template: "adoption-frontier",
                initialize_git: false,
            },
        )
        .unwrap();
        log(tmp.path(), "source-inbox", "confusing", "Which locator?").unwrap();
        log(
            tmp.path(),
            "proof",
            "useful_object",
            "Packet validate helped.",
        )
        .unwrap();
        let list = list(tmp.path()).unwrap();
        assert_eq!(list.total, 2);
        assert_eq!(list.summary.by_kind["confusing"], 1);
        assert_eq!(list.summary.by_step["source-inbox"], 1);
        assert!(friction_path(tmp.path()).is_file());
    }

    #[test]
    fn rejects_unknown_kind() {
        let tmp = TempDir::new().unwrap();
        frontier_repo::initialize(
            tmp.path(),
            InitOptions {
                name: "Friction frontier",
                template: "adoption-frontier",
                initialize_git: false,
            },
        )
        .unwrap();
        assert!(log(tmp.path(), "setup", "telemetry", "No").is_err());
    }
}
