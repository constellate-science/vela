//! Local source inbox records.
//!
//! The source inbox is an operational queue for source material before it is
//! evidence. Records live under `.vela/source-inbox/`; accepted frontier truth
//! still requires reviewed events.

use crate::frontier_task::{self, FrontierTask, FrontierTaskStatus};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use vela_protocol::canonical;
use vela_protocol::frontier_policy::{self, OperationReviewRequirement};
use vela_protocol::repo;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SourceInboxState {
    Discovered,
    Retrieved,
    Parsed,
    Verified,
    Quarantined,
    Ingested,
    LinkedToDiff,
    Deprecated,
    Retracted,
}

impl SourceInboxState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Retrieved => "retrieved",
            Self::Parsed => "parsed",
            Self::Verified => "verified",
            Self::Quarantined => "quarantined",
            Self::Ingested => "ingested",
            Self::LinkedToDiff => "linked_to_diff",
            Self::Deprecated => "deprecated",
            Self::Retracted => "retracted",
        }
    }
}

impl fmt::Display for SourceInboxState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SourceInboxState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "discovered" => Ok(Self::Discovered),
            "retrieved" => Ok(Self::Retrieved),
            "parsed" => Ok(Self::Parsed),
            "verified" => Ok(Self::Verified),
            "quarantined" => Ok(Self::Quarantined),
            "ingested" => Ok(Self::Ingested),
            "linked_to_diff" => Ok(Self::LinkedToDiff),
            "deprecated" => Ok(Self::Deprecated),
            "retracted" => Ok(Self::Retracted),
            other => Err(format!(
                "source inbox state must be one of discovered | retrieved | parsed | verified | quarantined | ingested | linked_to_diff | deprecated | retracted; got `{other}`"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceInboxRecord {
    pub id: String,
    pub frontier_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub title: String,
    pub locator: String,
    pub source_type: String,
    pub state: SourceInboxState,
    pub risk_class: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieved_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_task_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceInboxDraft {
    pub frontier_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub title: String,
    pub locator: String,
    pub source_type: String,
    pub risk_class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceInboxList {
    pub frontier_id: String,
    pub frontier_path: String,
    pub total: usize,
    #[serde(default)]
    pub records: Vec<SourceInboxRecord>,
    #[serde(default)]
    pub rejected_imports: Vec<SourceInboxRejectedImport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceInboxRejectedImport {
    pub schema: String,
    pub rejected_at: String,
    pub input_path: String,
    pub format: String,
    pub row_number: usize,
    pub raw: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceInboxTaskResult {
    pub record: SourceInboxRecord,
    pub task: FrontierTask,
    pub review_requirement: OperationReviewRequirement,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SourceInboxAddOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    pub title: String,
    pub locator: String,
    pub source_type: String,
    pub state: SourceInboxState,
    pub risk_class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

pub fn add_record(
    frontier_path: &Path,
    options: SourceInboxAddOptions,
) -> Result<SourceInboxRecord, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let now = chrono::Utc::now().to_rfc3339();
    let draft = SourceInboxDraft {
        frontier_id: project.frontier_id(),
        source_id: clean_optional(options.source_id),
        title: non_empty("title", options.title)?,
        locator: non_empty("locator", options.locator)?,
        source_type: non_empty("source type", options.source_type)?,
        risk_class: non_empty("risk class", options.risk_class)?,
    };
    let id = derive_source_inbox_id(&draft)?;
    let record = SourceInboxRecord {
        id,
        frontier_id: draft.frontier_id,
        source_id: draft.source_id,
        title: draft.title,
        locator: draft.locator,
        source_type: draft.source_type,
        state: options.state,
        risk_class: draft.risk_class,
        created_at: now.clone(),
        updated_at: now.clone(),
        retrieved_at: matches!(
            options.state,
            SourceInboxState::Retrieved
                | SourceInboxState::Parsed
                | SourceInboxState::Verified
                | SourceInboxState::Ingested
                | SourceInboxState::LinkedToDiff
        )
        .then(|| now.clone()),
        verified_at: (options.state == SourceInboxState::Verified).then(|| now.clone()),
        linked_task_id: None,
        content_hash: clean_optional(options.content_hash),
        notes: clean_list(options.notes),
        metadata: options.metadata,
    };
    write_record(&root, &record, false)?;
    Ok(record)
}
pub fn list_records(frontier_path: &Path) -> Result<SourceInboxList, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let mut records = Vec::new();
    let dir = source_inbox_dir(&root);
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| format!("read source inbox directory {}: {e}", dir.display()))?
        {
            let entry = entry.map_err(|e| format!("read source inbox entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                records.push(read_record_file(&path)?);
            }
        }
    }
    records.sort_by(|a, b| {
        a.state
            .cmp(&b.state)
            .then_with(|| b.updated_at.cmp(&a.updated_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(SourceInboxList {
        frontier_id: project.frontier_id(),
        frontier_path: root.display().to_string(),
        total: records.len(),
        records,
        rejected_imports: list_rejected_imports(&root)?,
    })
}

pub fn load_record(frontier_path: &Path, record_id: &str) -> Result<SourceInboxRecord, String> {
    let root = repo_root(frontier_path)?;
    let id = validate_source_inbox_id(record_id)?;
    read_record_file(&source_inbox_dir(&root).join(format!("{id}.json")))
}

pub fn verify_record(
    frontier_path: &Path,
    record_id: &str,
    reviewer: String,
    reason: String,
) -> Result<SourceInboxRecord, String> {
    let root = repo_root(frontier_path)?;
    let mut record = load_record(&root, record_id)?;
    let reviewer = typed_reviewer(reviewer)?;
    let reason = non_empty("reason", reason)?;
    let now = chrono::Utc::now().to_rfc3339();
    record.state = SourceInboxState::Verified;
    record.verified_at = Some(now.clone());
    record.updated_at = now;
    record
        .metadata
        .insert("verified_by".to_string(), json!(reviewer));
    record
        .metadata
        .insert("verification_reason".to_string(), json!(reason));
    write_record(&root, &record, true)?;
    Ok(record)
}
pub fn create_task_from_record(
    frontier_path: &Path,
    record_id: &str,
    objective: Option<String>,
    status: FrontierTaskStatus,
) -> Result<SourceInboxTaskResult, String> {
    let root = repo_root(frontier_path)?;
    let mut record = load_record(&root, record_id)?;
    let requirement = review_requirement_for_record(&root, &record);
    let objective = objective
        .and_then(|value| {
            let trimmed = value.trim().to_string();
            (!trimmed.is_empty()).then_some(trimmed)
        })
        .unwrap_or_else(|| {
            format!(
                "Review source inbox record {} for frontier impact.",
                record.id
            )
        });
    let mut inputs = vec![record.id.clone(), record.locator.clone()];
    if let Some(source_id) = &record.source_id {
        inputs.push(source_id.clone());
    }
    let task = frontier_task::create_task(
        &root,
        "source_ingestion".to_string(),
        objective,
        inputs,
        record.risk_class.clone(),
        Vec::new(),
        vec![
            "source identity and locator are checked".to_string(),
            "candidate evidence remains separate from accepted evidence".to_string(),
            "proposal impact is reviewed before any frontier event is accepted".to_string(),
        ],
        status,
    )?;
    record.linked_task_id = Some(task.id.clone());
    record.state = SourceInboxState::Ingested;
    record.updated_at = chrono::Utc::now().to_rfc3339();
    record.metadata.insert(
        "policy_review_class".to_string(),
        json!(requirement.review_class.clone()),
    );
    write_record(&root, &record, true)?;
    Ok(SourceInboxTaskResult {
        record,
        task,
        review_requirement: requirement,
    })
}

pub fn review_requirement_for_record(
    frontier_path: &Path,
    record: &SourceInboxRecord,
) -> OperationReviewRequirement {
    let summary = frontier_policy::load_policy_summary(frontier_path).ok();
    let operation = match record.risk_class.as_str() {
        "retraction_impact" => "request_downstream_review",
        "clinical_translation" => "clinical_translation",
        "entity_issue" => "resolve_entity",
        _ => "repair_locator",
    };
    frontier_policy::review_requirement_for_operation(
        summary.as_ref(),
        operation,
        "source_inbox",
        matches!(
            record.risk_class.as_str(),
            "decision_impact" | "retraction_impact"
        ),
    )
}

pub fn derive_source_inbox_id(draft: &SourceInboxDraft) -> Result<String, String> {
    let hash = canonical::sha256_canonical(draft)?;
    Ok(format!("vsrcin_{}", &hash[..16]))
}
pub fn repo_root(frontier_path: &Path) -> Result<PathBuf, String> {
    match repo::detect(frontier_path)? {
        repo::VelaSource::VelaRepo(root) => Ok(root),
        repo::VelaSource::ProjectFile(_) | repo::VelaSource::PacketDir(_) => Err(format!(
            "source inbox requires a local .vela/ repository; got {}",
            frontier_path.display()
        )),
    }
}

pub fn source_inbox_dir(frontier_root: &Path) -> PathBuf {
    frontier_root.join(".vela").join("source-inbox")
}

pub fn rejected_imports_path(frontier_root: &Path) -> PathBuf {
    source_inbox_dir(frontier_root).join("rejected-imports.jsonl")
}

pub fn list_rejected_imports(
    frontier_path: &Path,
) -> Result<Vec<SourceInboxRejectedImport>, String> {
    let root = repo_root(frontier_path)?;
    let path = rejected_imports_path(&root);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    let body = std::fs::read_to_string(&path)
        .map_err(|e| format!("read rejected source imports {}: {e}", path.display()))?;
    let mut rows = Vec::new();
    for (idx, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: SourceInboxRejectedImport = serde_json::from_str(line).map_err(|e| {
            format!(
                "parse rejected source import {} line {}: {e}",
                path.display(),
                idx + 1
            )
        })?;
        rows.push(row);
    }
    rows.sort_by(|a, b| {
        b.rejected_at
            .cmp(&a.rejected_at)
            .then_with(|| a.input_path.cmp(&b.input_path))
            .then_with(|| a.row_number.cmp(&b.row_number))
    });
    Ok(rows)
}

fn write_record(root: &Path, record: &SourceInboxRecord, overwrite: bool) -> Result<(), String> {
    validate_source_inbox_id(&record.id)?;
    let dir = source_inbox_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("create source inbox directory {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", record.id));
    if path.exists() && !overwrite {
        return Err(format!(
            "source inbox record {} already exists at {}",
            record.id,
            path.display()
        ));
    }
    let body = serde_json::to_string_pretty(record)
        .map_err(|e| format!("serialize source inbox record {}: {e}", record.id))?;
    std::fs::write(&path, format!("{body}\n"))
        .map_err(|e| format!("write source inbox record {}: {e}", path.display()))
}

fn read_record_file(path: &Path) -> Result<SourceInboxRecord, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("read source inbox record {}: {e}", path.display()))?;
    let record: SourceInboxRecord = serde_json::from_str(&body)
        .map_err(|e| format!("parse source inbox record {}: {e}", path.display()))?;
    validate_source_inbox_id(&record.id)?;
    Ok(record)
}

fn validate_source_inbox_id(record_id: &str) -> Result<String, String> {
    let ok = record_id.starts_with("vsrcin_")
        && record_id.len() == "vsrcin_".len() + 16
        && record_id["vsrcin_".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase());
    if ok {
        Ok(record_id.to_string())
    } else {
        Err(format!("invalid source inbox id `{record_id}`"))
    }
}

fn typed_reviewer(value: String) -> Result<String, String> {
    let value = non_empty("reviewer", value)?;
    if value.contains(':') {
        Ok(value)
    } else {
        Err("reviewer must be typed, for example reviewer:you".to_string())
    }
}

fn non_empty(label: &str, value: String) -> Result<String, String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        Err(format!("source inbox {label} is required"))
    } else {
        Ok(trimmed)
    }
}

fn clean_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim().to_string();
        (!trimmed.is_empty()).then_some(trimmed)
    })
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
    fn source_inbox_id_is_stable() {
        let draft = SourceInboxDraft {
            frontier_id: "vfr_demo".to_string(),
            source_id: Some("source.demo".to_string()),
            title: "Demo source".to_string(),
            locator: "doi:10.5555/demo".to_string(),
            source_type: "paper".to_string(),
            risk_class: "source_repair".to_string(),
        };
        assert_eq!(
            derive_source_inbox_id(&draft).unwrap(),
            derive_source_inbox_id(&draft).unwrap()
        );
    }

    #[test]
    fn state_round_trips_snake_case() {
        assert_eq!(
            "linked_to_diff".parse::<SourceInboxState>().unwrap(),
            SourceInboxState::LinkedToDiff
        );
        assert_eq!(SourceInboxState::Quarantined.to_string(), "quarantined");
    }
}
