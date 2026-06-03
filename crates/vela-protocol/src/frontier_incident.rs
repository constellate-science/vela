//! Local frontier incident response records.
//!
//! Incidents are review triggers for source corrections, retractions,
//! extraction failures, registry mismatches, high-impact contradictions,
//! and translation risk. They live under `.vela/incidents/` and can create
//! local tasks for affected findings. They do not retract or rewrite
//! accepted frontier state by themselves.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::frontier_task::{self, FrontierTask, FrontierTaskDraft, FrontierTaskStatus};
use crate::source_inbox::{self, SourceInboxRecord, SourceInboxState};
use crate::{canonical, repo};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FrontierIncidentType {
    SourceRetracted,
    SourceCorrected,
    ExtractionError,
    TrialRegistryMismatch,
    HighImpactContradiction,
    TranslationRisk,
}

impl FrontierIncidentType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceRetracted => "source_retracted",
            Self::SourceCorrected => "source_corrected",
            Self::ExtractionError => "extraction_error",
            Self::TrialRegistryMismatch => "trial_registry_mismatch",
            Self::HighImpactContradiction => "high_impact_contradiction",
            Self::TranslationRisk => "translation_risk",
        }
    }

    pub fn risk_class(self) -> &'static str {
        match self {
            Self::SourceRetracted | Self::SourceCorrected => "retraction_impact",
            Self::ExtractionError | Self::TrialRegistryMismatch => "source_repair",
            Self::HighImpactContradiction => "contradiction_change",
            Self::TranslationRisk => "clinical_translation",
        }
    }
}

impl fmt::Display for FrontierIncidentType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FrontierIncidentType {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().replace('-', "_").as_str() {
            "source_retracted" => Ok(Self::SourceRetracted),
            "source_corrected" => Ok(Self::SourceCorrected),
            "extraction_error" => Ok(Self::ExtractionError),
            "trial_registry_mismatch" => Ok(Self::TrialRegistryMismatch),
            "high_impact_contradiction" => Ok(Self::HighImpactContradiction),
            "translation_risk" => Ok(Self::TranslationRisk),
            other => Err(format!(
                "incident type must be one of source_retracted | source_corrected | extraction_error | trial_registry_mismatch | high_impact_contradiction | translation_risk; got `{other}`"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FrontierIncidentStatus {
    Open,
    Closed,
}

impl FrontierIncidentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

impl fmt::Display for FrontierIncidentStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for FrontierIncidentStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "open" => Ok(Self::Open),
            "closed" => Ok(Self::Closed),
            other => Err(format!(
                "incident status must be one of open | closed; got `{other}`"
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierIncident {
    pub id: String,
    pub frontier_id: String,
    #[serde(rename = "type")]
    pub incident_type: FrontierIncidentType,
    pub status: FrontierIncidentStatus,
    pub severity: String,
    pub title: String,
    pub reason: String,
    pub opened_by: String,
    pub opened_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default)]
    pub affected_sources: Vec<String>,
    #[serde(default)]
    pub affected_evidence_atoms: Vec<String>,
    #[serde(default)]
    pub affected_findings: Vec<String>,
    #[serde(default)]
    pub linked_task_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_reason: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierIncidentDraft {
    pub frontier_id: String,
    #[serde(rename = "type")]
    pub incident_type: FrontierIncidentType,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierIncidentOpenOptions {
    pub incident_type: FrontierIncidentType,
    pub severity: String,
    pub title: String,
    pub reason: String,
    pub opened_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finding_id: Option<String>,
    #[serde(default)]
    pub metadata: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierIncidentList {
    pub frontier_id: String,
    pub frontier_path: String,
    pub total: usize,
    #[serde(default)]
    pub incidents: Vec<FrontierIncident>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierIncidentOpenResult {
    pub incident: FrontierIncident,
    pub impact: RetractionImpactReport,
    #[serde(default)]
    pub tasks: Vec<FrontierTask>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RetractionImpactReport {
    pub frontier_id: String,
    pub source_id: String,
    #[serde(default)]
    pub resolved_source_ids: Vec<String>,
    #[serde(default)]
    pub source_inbox_records: Vec<String>,
    #[serde(default)]
    pub affected_sources: Vec<String>,
    #[serde(default)]
    pub affected_evidence_atoms: Vec<String>,
    #[serde(default)]
    pub affected_findings: Vec<String>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

pub fn open_incident(
    frontier_path: &Path,
    options: FrontierIncidentOpenOptions,
) -> Result<FrontierIncidentOpenResult, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let source_id = clean_optional(options.source_id);
    let finding_id = clean_optional(options.finding_id);
    let title = non_empty("title", options.title)?;
    let draft = FrontierIncidentDraft {
        frontier_id: project.frontier_id(),
        incident_type: options.incident_type,
        title: title.clone(),
        source_id: source_id.clone(),
        finding_id: finding_id.clone(),
    };
    let id = derive_incident_id(&draft)?;
    let path = incidents_dir(&root).join(format!("{id}.json"));
    if path.exists() {
        let incident = read_incident_file(&path)?;
        let impact = retraction_impact(
            &root,
            incident
                .source_id
                .as_deref()
                .unwrap_or_else(|| incident.finding_id.as_deref().unwrap_or(&incident.id)),
        )?;
        let tasks = incident
            .linked_task_ids
            .iter()
            .filter_map(|task_id| frontier_task::load_task(&root, task_id).ok())
            .collect();
        return Ok(FrontierIncidentOpenResult {
            incident,
            impact,
            tasks,
        });
    }

    let mut impact = if let Some(source_id) = source_id.as_deref() {
        retraction_impact(&root, source_id)?
    } else {
        RetractionImpactReport {
            frontier_id: project.frontier_id(),
            source_id: finding_id
                .clone()
                .unwrap_or_else(|| format!("incident:{id}")),
            resolved_source_ids: Vec::new(),
            source_inbox_records: Vec::new(),
            affected_sources: Vec::new(),
            affected_evidence_atoms: Vec::new(),
            affected_findings: finding_id.iter().cloned().collect(),
            caveats: vec![
                "No source id was supplied; impact is scoped to the finding id if present."
                    .to_string(),
            ],
        }
    };
    if let Some(finding_id) = finding_id.as_ref() {
        insert_sorted(&mut impact.affected_findings, finding_id.clone());
    }

    let tasks = create_incident_tasks(&root, &id, options.incident_type, &impact)?;
    let now = chrono::Utc::now().to_rfc3339();
    let incident = FrontierIncident {
        id,
        frontier_id: project.frontier_id(),
        incident_type: options.incident_type,
        status: FrontierIncidentStatus::Open,
        severity: non_empty("severity", options.severity)?,
        title,
        reason: non_empty("reason", options.reason)?,
        opened_by: typed_actor(options.opened_by)?,
        opened_at: now.clone(),
        updated_at: now,
        source_id: source_id.clone(),
        finding_id,
        affected_sources: impact.affected_sources.clone(),
        affected_evidence_atoms: impact.affected_evidence_atoms.clone(),
        affected_findings: impact.affected_findings.clone(),
        linked_task_ids: tasks.iter().map(|task| task.id.clone()).collect(),
        closed_by: None,
        closed_reason: None,
        metadata: options.metadata,
    };
    write_incident(&root, &incident, false)?;
    if matches!(
        options.incident_type,
        FrontierIncidentType::SourceRetracted | FrontierIncidentType::SourceCorrected
    ) {
        mark_matching_source_inbox_records(
            &root,
            source_id.as_deref(),
            options.incident_type,
            &incident.id,
        )?;
    }
    Ok(FrontierIncidentOpenResult {
        incident,
        impact,
        tasks,
    })
}

pub fn list_incidents(frontier_path: &Path) -> Result<FrontierIncidentList, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let mut incidents = Vec::new();
    let dir = incidents_dir(&root);
    if dir.is_dir() {
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| format!("read incidents directory {}: {e}", dir.display()))?
        {
            let entry = entry.map_err(|e| format!("read incident entry: {e}"))?;
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "json") {
                incidents.push(read_incident_file(&path)?);
            }
        }
    }
    incidents.sort_by(|a, b| {
        a.status
            .cmp(&b.status)
            .then_with(|| b.updated_at.cmp(&a.updated_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    Ok(FrontierIncidentList {
        frontier_id: project.frontier_id(),
        frontier_path: root.display().to_string(),
        total: incidents.len(),
        incidents,
    })
}

pub fn close_incident(
    frontier_path: &Path,
    incident_id: &str,
    reviewer: String,
    reason: String,
) -> Result<FrontierIncident, String> {
    let root = repo_root(frontier_path)?;
    let id = validate_incident_id(incident_id)?;
    let mut incident = read_incident_file(&incidents_dir(&root).join(format!("{id}.json")))?;
    incident.status = FrontierIncidentStatus::Closed;
    incident.closed_by = Some(typed_actor(reviewer)?);
    incident.closed_reason = Some(non_empty("reason", reason)?);
    incident.updated_at = chrono::Utc::now().to_rfc3339();
    write_incident(&root, &incident, true)?;
    Ok(incident)
}

pub fn retraction_impact(
    frontier_path: &Path,
    source_id: &str,
) -> Result<RetractionImpactReport, String> {
    let root = repo_root(frontier_path)?;
    let project = repo::load_from_path(&root)?;
    let source_id = non_empty("source id", source_id.to_string())?;

    let source_inbox_records = matching_source_inbox_records(&root, &source_id);
    let mut keys: BTreeSet<String> = BTreeSet::new();
    keys.insert(source_id.clone());
    for record in &source_inbox_records {
        if let Some(source_id) = record.source_id.as_deref() {
            keys.insert(source_id.to_string());
        }
        keys.insert(record.locator.clone());
        keys.insert(normalize_locator_key(&record.locator));
    }

    let mut affected_sources = Vec::new();
    let mut resolved_source_ids = Vec::new();
    let mut affected_findings: BTreeSet<String> = BTreeSet::new();
    for source in &project.sources {
        if source_matches(source, &keys) {
            insert_sorted(&mut affected_sources, source.id.clone());
            insert_sorted(&mut resolved_source_ids, source.id.clone());
            for finding_id in &source.finding_ids {
                affected_findings.insert(finding_id.clone());
            }
        }
    }
    if project
        .findings
        .iter()
        .any(|finding| finding.id == source_id)
    {
        affected_findings.insert(source_id.clone());
    }

    let resolved: BTreeSet<String> = resolved_source_ids.iter().cloned().collect();
    let mut affected_evidence_atoms = Vec::new();
    for atom in &project.evidence_atoms {
        if resolved.contains(&atom.source_id) || keys.contains(&atom.source_id) {
            insert_sorted(&mut affected_evidence_atoms, atom.id.clone());
            affected_findings.insert(atom.finding_id.clone());
        }
    }

    let mut affected_findings: Vec<String> = affected_findings.into_iter().collect();
    affected_findings.sort();
    let mut caveats = vec![
        "Retraction impact is an operational review query. It does not retract claims.".to_string(),
    ];
    if affected_findings.is_empty() {
        caveats.push("No matching source, evidence atom, or finding was found.".to_string());
    }

    Ok(RetractionImpactReport {
        frontier_id: project.frontier_id(),
        source_id,
        resolved_source_ids,
        source_inbox_records: source_inbox_records
            .iter()
            .map(|record| record.id.clone())
            .collect(),
        affected_sources,
        affected_evidence_atoms,
        affected_findings,
        caveats,
    })
}

pub fn incident_summary(frontier_path: &Path) -> FrontierIncidentSummary {
    list_incidents(frontier_path)
        .map(|list| FrontierIncidentSummary::from_incidents(&list.incidents))
        .unwrap_or_default()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FrontierIncidentSummary {
    pub total: usize,
    pub open: usize,
    pub closed: usize,
}

impl FrontierIncidentSummary {
    pub fn from_incidents(incidents: &[FrontierIncident]) -> Self {
        Self {
            total: incidents.len(),
            open: incidents
                .iter()
                .filter(|incident| incident.status == FrontierIncidentStatus::Open)
                .count(),
            closed: incidents
                .iter()
                .filter(|incident| incident.status == FrontierIncidentStatus::Closed)
                .count(),
        }
    }
}

pub fn incidents_for_finding(frontier_path: &Path, finding_id: &str) -> Vec<FrontierIncident> {
    list_incidents(frontier_path)
        .map(|list| {
            list.incidents
                .into_iter()
                .filter(|incident| {
                    incident.finding_id.as_deref() == Some(finding_id)
                        || incident
                            .affected_findings
                            .iter()
                            .any(|target| target == finding_id)
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn derive_incident_id(draft: &FrontierIncidentDraft) -> Result<String, String> {
    let hash = canonical::sha256_canonical(draft)?;
    Ok(format!("vinc_{}", &hash[..16]))
}

pub fn repo_root(frontier_path: &Path) -> Result<PathBuf, String> {
    match repo::detect(frontier_path)? {
        repo::VelaSource::VelaRepo(root) => Ok(root),
        repo::VelaSource::ProjectFile(_) | repo::VelaSource::PacketDir(_) => Err(format!(
            "frontier incidents require a local .vela/ repository; got {}",
            frontier_path.display()
        )),
    }
}

pub fn incidents_dir(frontier_root: &Path) -> PathBuf {
    frontier_root.join(".vela").join("incidents")
}

fn create_incident_tasks(
    root: &Path,
    incident_id: &str,
    incident_type: FrontierIncidentType,
    impact: &RetractionImpactReport,
) -> Result<Vec<FrontierTask>, String> {
    let project = repo::load_from_path(root)?;
    let mut tasks = Vec::new();
    for finding_id in &impact.affected_findings {
        let objective = format!("Review incident {incident_id} impact on finding {finding_id}.");
        let draft = FrontierTaskDraft {
            frontier_id: project.frontier_id(),
            task_type: "incident_response".to_string(),
            objective: objective.clone(),
            inputs: vec![
                incident_id.to_string(),
                impact.source_id.clone(),
                finding_id.clone(),
            ],
            risk_class: incident_type.risk_class().to_string(),
            blockers: Vec::new(),
            acceptance_criteria: vec![
                "source status and affected evidence are inspected".to_string(),
                "claim state changes are proposed as reviewed events only".to_string(),
                "downstream translation surfaces are checked before reuse".to_string(),
            ],
        };
        let task_id = frontier_task::derive_task_id(&draft)?;
        let task = match frontier_task::load_task(root, &task_id) {
            Ok(task) => task,
            Err(_) => frontier_task::create_task(
                root,
                draft.task_type,
                draft.objective,
                draft.inputs,
                draft.risk_class,
                draft.blockers,
                draft.acceptance_criteria,
                FrontierTaskStatus::AwaitingReview,
            )?,
        };
        tasks.push(task);
    }
    Ok(tasks)
}

fn matching_source_inbox_records(root: &Path, key: &str) -> Vec<SourceInboxRecord> {
    source_inbox::list_records(root)
        .map(|list| {
            list.records
                .into_iter()
                .filter(|record| source_inbox_record_matches(record, key))
                .collect()
        })
        .unwrap_or_default()
}

fn source_inbox_record_matches(record: &SourceInboxRecord, key: &str) -> bool {
    record.id == key
        || record.source_id.as_deref() == Some(key)
        || record.locator == key
        || normalize_locator_key(&record.locator) == normalize_locator_key(key)
}

fn mark_matching_source_inbox_records(
    root: &Path,
    source_id: Option<&str>,
    incident_type: FrontierIncidentType,
    incident_id: &str,
) -> Result<(), String> {
    let Some(source_id) = source_id else {
        return Ok(());
    };
    for record in matching_source_inbox_records(root, source_id) {
        let state = match incident_type {
            FrontierIncidentType::SourceRetracted => SourceInboxState::Retracted,
            FrontierIncidentType::SourceCorrected => SourceInboxState::Quarantined,
            _ => record.state,
        };
        source_inbox::update_record_state(
            root,
            &record.id,
            state,
            Some(format!("linked frontier incident {incident_id}")),
            Some(json!(incident_id)),
        )?;
    }
    Ok(())
}

fn source_matches(source: &crate::sources::SourceRecord, keys: &BTreeSet<String>) -> bool {
    let values = [
        Some(source.id.as_str()),
        Some(source.locator.as_str()),
        source.doi.as_deref(),
        source.pmid.as_deref(),
        (!source.title.trim().is_empty()).then_some(source.title.as_str()),
    ];
    values
        .into_iter()
        .flatten()
        .any(|value| keys.contains(value) || keys.contains(&normalize_locator_key(value)))
}

fn write_incident(root: &Path, incident: &FrontierIncident, overwrite: bool) -> Result<(), String> {
    validate_incident_id(&incident.id)?;
    let dir = incidents_dir(root);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("create incidents directory {}: {e}", dir.display()))?;
    let path = dir.join(format!("{}.json", incident.id));
    if path.exists() && !overwrite {
        return Err(format!(
            "incident {} already exists at {}",
            incident.id,
            path.display()
        ));
    }
    let body = serde_json::to_string_pretty(incident)
        .map_err(|e| format!("serialize incident {}: {e}", incident.id))?;
    std::fs::write(&path, format!("{body}\n"))
        .map_err(|e| format!("write incident {}: {e}", path.display()))
}

fn read_incident_file(path: &Path) -> Result<FrontierIncident, String> {
    let body = std::fs::read_to_string(path)
        .map_err(|e| format!("read incident {}: {e}", path.display()))?;
    let incident: FrontierIncident = serde_json::from_str(&body)
        .map_err(|e| format!("parse incident {}: {e}", path.display()))?;
    validate_incident_id(&incident.id)?;
    Ok(incident)
}

fn validate_incident_id(incident_id: &str) -> Result<String, String> {
    let ok = incident_id.starts_with("vinc_")
        && incident_id.len() == "vinc_".len() + 16
        && incident_id["vinc_".len()..]
            .chars()
            .all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase());
    if ok {
        Ok(incident_id.to_string())
    } else {
        Err(format!("invalid frontier incident id `{incident_id}`"))
    }
}

fn typed_actor(value: String) -> Result<String, String> {
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
        Err(format!("incident {label} is required"))
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

fn insert_sorted(values: &mut Vec<String>, value: String) {
    if !values.iter().any(|existing| existing == &value) {
        values.push(value);
        values.sort();
    }
}

fn normalize_locator_key(value: &str) -> String {
    value
        .trim()
        .trim_start_matches("doi:")
        .trim_start_matches("pmid:")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incident_type_accepts_kebab_case() {
        assert_eq!(
            "source-retracted".parse::<FrontierIncidentType>().unwrap(),
            FrontierIncidentType::SourceRetracted
        );
        assert_eq!(
            FrontierIncidentType::TranslationRisk.to_string(),
            "translation_risk"
        );
    }

    #[test]
    fn incident_id_is_stable() {
        let draft = FrontierIncidentDraft {
            frontier_id: "vfr_demo".to_string(),
            incident_type: FrontierIncidentType::SourceRetracted,
            title: "Demo retraction".to_string(),
            source_id: Some("vs_demo".to_string()),
            finding_id: None,
        };
        assert_eq!(
            derive_incident_id(&draft).unwrap(),
            derive_incident_id(&draft).unwrap()
        );
    }
}
