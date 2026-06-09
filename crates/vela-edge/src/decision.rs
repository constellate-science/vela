//! Validated frontier-owned decision projections.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use vela_protocol::project::Project;

pub const DECISION_BRIEF_SCHEMA: &str = "vela.decision-brief.v1";
pub const TRIAL_OUTCOMES_SCHEMA: &str = "vela.trial-outcomes.v1";
pub const SOURCE_VERIFICATION_SCHEMA: &str = "vela.source-verification.v1";
pub const SOURCE_INGEST_PLAN_SCHEMA: &str = "vela.source-ingest-plan.v1";

const DECISION_BRIEF_FILE: &str = "decision-brief.v1.json";
const TRIAL_OUTCOMES_FILE: &str = "trial-outcomes.v1.json";
const SOURCE_VERIFICATION_FILE: &str = "source-verification.v1.json";
const SOURCE_INGEST_PLAN_FILE: &str = "source-ingest-plan.v1.json";

const KNOWN_QUESTION_IDS: &[&str] = &[
    "clinical-benefit",
    "biomarkers-vs-cognition",
    "bace-failures",
    "aria-apoe4-risk",
    "delivery-constraints",
    "next-discriminating-evidence",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionBrief {
    pub schema: String,
    pub frontier_id: Option<String>,
    pub updated_at: String,
    pub source_frontier: String,
    #[serde(default)]
    pub projection_boundary: Option<DecisionProjectionBoundary>,
    pub questions: Vec<DecisionQuestion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionProjectionBoundary {
    pub status: String,
    pub reviewer_profile: String,
    pub counts_as_medical_guidance: bool,
    pub outside_review_claimed: bool,
    pub agent_confidence_policy: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionQuestion {
    pub id: String,
    pub title: String,
    pub short_answer: String,
    pub caveat: String,
    pub confidence: String,
    pub supporting_findings: Vec<String>,
    #[serde(default)]
    pub tension_findings: Vec<String>,
    #[serde(default)]
    pub gap_findings: Vec<String>,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub evidence_basis: Vec<DecisionEvidenceBasis>,
    pub what_would_change_this_answer: String,
    #[serde(default)]
    pub correction_paths: Vec<DecisionCorrectionPath>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionEvidenceBasis {
    pub finding_id: String,
    pub role: String,
    pub source_locator: String,
    pub review_status: String,
    pub caveat: String,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionCorrectionPath {
    pub finding_id: String,
    pub summary: String,
    #[serde(default)]
    pub event_ids: Vec<String>,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialOutcomes {
    pub schema: String,
    pub frontier_id: Option<String>,
    pub updated_at: String,
    pub rows: Vec<TrialOutcomeRow>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrialOutcomeRow {
    pub id: String,
    pub program: String,
    pub drug: String,
    pub mechanism: String,
    pub phase: String,
    #[serde(default)]
    pub nct_ids: Vec<String>,
    pub population: String,
    pub disease_stage: String,
    pub amyloid_confirmation: String,
    pub duration: String,
    pub primary_endpoint: String,
    pub cognitive_result: String,
    pub biomarker_result: String,
    pub aria_or_safety_result: String,
    pub regulatory_status: String,
    #[serde(default)]
    pub source_locators: Vec<String>,
    #[serde(default)]
    pub finding_ids: Vec<String>,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceVerification {
    pub schema: String,
    pub frontier_id: Option<String>,
    pub verified_at: String,
    #[serde(default)]
    pub notes: Vec<String>,
    pub sources: Vec<VerifiedSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIngestPlan {
    pub schema: String,
    pub frontier_id: Option<String>,
    pub name: String,
    pub verified_at: String,
    #[serde(default)]
    pub policy: serde_json::Value,
    pub entries: Vec<SourceIngestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceIngestEntry {
    pub id: String,
    pub name: String,
    pub category: String,
    pub priority: String,
    pub representation: String,
    pub source_type: String,
    pub locator: String,
    pub ingest_status: String,
    pub current_frontier_artifact_id: Option<String>,
    pub access_terms: String,
    pub license_note: String,
    #[serde(default)]
    pub target_findings: Vec<String>,
    pub target_use: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedSource {
    pub id: String,
    pub title: String,
    pub url: String,
    pub agency: String,
    pub current_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionIssue {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectionLoad<T>
where
    T: Serialize,
{
    pub ok: bool,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_readiness: Option<DecisionReadiness>,
    pub issues: Vec<ProjectionIssue>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionReadiness {
    pub schema: String,
    pub status: String,
    pub ready: bool,
    pub boundary: String,
    pub substrate: DecisionReadinessSubstrate,
    pub blockers: Vec<DecisionReadinessBlocker>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionReadinessSubstrate {
    pub findings: usize,
    pub human_reviewed_findings: usize,
    pub agent_reviewed_findings: usize,
    pub high_confidence_findings: usize,
    pub average_confidence: f64,
    pub question_count: usize,
    pub stated_high_confidence_questions: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionReadinessBlocker {
    pub id: String,
    pub message: String,
}

pub fn decision_projection_dir(source: &Path) -> Option<PathBuf> {
    if source.is_dir() {
        let dir = source.join("decision");
        return dir.exists().then_some(dir);
    }
    source
        .parent()
        .map(|parent| parent.join("decision"))
        .filter(|dir| dir.exists())
}

pub fn load_decision_brief(source: &Path, project: &Project) -> ProjectionLoad<DecisionBrief> {
    let mut report = load_projection(
        source,
        project,
        DECISION_BRIEF_FILE,
        validate_decision_brief,
    );
    if let Some(brief) = report.projection.as_ref() {
        report.decision_readiness = Some(assess_decision_readiness(brief, project));
    }
    report
}

pub fn load_trial_outcomes(source: &Path, project: &Project) -> ProjectionLoad<TrialOutcomes> {
    load_projection(
        source,
        project,
        TRIAL_OUTCOMES_FILE,
        validate_trial_outcomes,
    )
}

pub fn load_source_verification(
    source: &Path,
    project: &Project,
) -> ProjectionLoad<SourceVerification> {
    load_projection(
        source,
        project,
        SOURCE_VERIFICATION_FILE,
        validate_source_verification,
    )
}

pub fn load_source_ingest_plan(
    source: &Path,
    project: &Project,
) -> ProjectionLoad<SourceIngestPlan> {
    let Some(dir) = source_ingest_projection_dir(source) else {
        return ProjectionLoad {
            ok: false,
            available: false,
            projection: None,
            decision_readiness: None,
            issues: vec![],
            error: Some("source ingest plan directory not found".to_string()),
        };
    };
    load_projection_from_dir(
        &dir,
        project,
        SOURCE_INGEST_PLAN_FILE,
        validate_source_ingest_plan,
    )
}

fn load_projection<T, F>(
    source: &Path,
    project: &Project,
    file_name: &str,
    validate: F,
) -> ProjectionLoad<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
    F: Fn(&T, &Project) -> Vec<ProjectionIssue>,
{
    let Some(dir) = decision_projection_dir(source) else {
        return ProjectionLoad {
            ok: false,
            available: false,
            projection: None,
            decision_readiness: None,
            issues: vec![],
            error: Some("decision projection directory not found".to_string()),
        };
    };
    load_projection_from_dir(&dir, project, file_name, validate)
}

fn load_projection_from_dir<T, F>(
    dir: &Path,
    project: &Project,
    file_name: &str,
    validate: F,
) -> ProjectionLoad<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
    F: Fn(&T, &Project) -> Vec<ProjectionIssue>,
{
    let path = dir.join(file_name);
    let Ok(bytes) = fs::read_to_string(&path) else {
        return ProjectionLoad {
            ok: false,
            available: false,
            projection: None,
            decision_readiness: None,
            issues: vec![],
            error: Some(format!("projection file not found: {}", path.display())),
        };
    };
    let projection = match serde_json::from_str::<T>(&bytes) {
        Ok(projection) => projection,
        Err(error) => {
            return ProjectionLoad {
                ok: false,
                available: true,
                projection: None,
                decision_readiness: None,
                issues: vec![],
                error: Some(format!("parse {}: {error}", path.display())),
            };
        }
    };
    let issues = validate(&projection, project);
    ProjectionLoad {
        ok: issues.is_empty(),
        available: true,
        projection: Some(projection),
        decision_readiness: None,
        issues,
        error: None,
    }
}

pub fn assess_decision_readiness(brief: &DecisionBrief, project: &Project) -> DecisionReadiness {
    let stated_high_confidence_questions = brief
        .questions
        .iter()
        .filter(|question| question.confidence.to_lowercase().contains("high"))
        .count();
    let high_confidence_findings = project.stats.confidence_distribution.high_gt_80;
    let mut blockers = Vec::new();

    if stated_high_confidence_questions > 0 && high_confidence_findings == 0 {
        blockers.push(DecisionReadinessBlocker {
            id: "confidence_substrate_mismatch".to_string(),
            message: format!(
                "{stated_high_confidence_questions} decision questions state high confidence, but the measured substrate has 0 findings with confidence >=0.80"
            ),
        });
    }

    let ready = blockers.is_empty();
    DecisionReadiness {
        schema: "vela.decision-readiness.v0.1".to_string(),
        status: if ready {
            "decision_ready".to_string()
        } else {
            "not_decision_ready".to_string()
        },
        ready,
        boundary: "Decision readiness is derived from current frontier state. It is not clinical guidance, settled science, or proof that outside review is complete.".to_string(),
        substrate: DecisionReadinessSubstrate {
            findings: project.stats.findings,
            human_reviewed_findings: project.stats.human_reviewed,
            agent_reviewed_findings: project.stats.agent_reviewed,
            high_confidence_findings,
            average_confidence: project.stats.avg_confidence,
            question_count: brief.questions.len(),
            stated_high_confidence_questions,
        },
        blockers,
    }
}

pub fn source_ingest_projection_dir(source: &Path) -> Option<PathBuf> {
    if source.is_dir() {
        let dir = source.join("ingest");
        return dir.exists().then_some(dir);
    }
    source
        .parent()
        .map(|parent| parent.join("ingest"))
        .filter(|dir| dir.exists())
}

pub fn validate_decision_brief(brief: &DecisionBrief, project: &Project) -> Vec<ProjectionIssue> {
    let finding_ids = project
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<HashSet<_>>();
    let artifact_ids = project
        .artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<HashSet<_>>();
    let event_ids = project
        .events
        .iter()
        .map(|event| event.id.as_str())
        .collect::<HashSet<_>>();
    let mut issues = validate_projection_frontier_id(brief.frontier_id.as_deref(), project);
    issues.extend(validate_decision_brief_against_sets(
        brief,
        &finding_ids,
        &artifact_ids,
        &event_ids,
    ));
    issues
}

pub fn validate_trial_outcomes(
    outcomes: &TrialOutcomes,
    project: &Project,
) -> Vec<ProjectionIssue> {
    let finding_ids = project
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<HashSet<_>>();
    let artifact_ids = project
        .artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<HashSet<_>>();
    let mut issues = validate_projection_frontier_id(outcomes.frontier_id.as_deref(), project);
    issues.extend(validate_trial_outcomes_against_sets(
        outcomes,
        &finding_ids,
        &artifact_ids,
    ));
    issues
}

pub fn validate_source_verification(
    verification: &SourceVerification,
    project: &Project,
) -> Vec<ProjectionIssue> {
    let mut issues = validate_projection_frontier_id(verification.frontier_id.as_deref(), project);
    issues.extend(validate_source_verification_shape(verification));
    issues
}

pub fn validate_source_ingest_plan(
    plan: &SourceIngestPlan,
    project: &Project,
) -> Vec<ProjectionIssue> {
    let finding_ids = project
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect::<HashSet<_>>();
    let artifact_ids = project
        .artifacts
        .iter()
        .map(|artifact| artifact.id.as_str())
        .collect::<HashSet<_>>();
    let mut issues = validate_projection_frontier_id(plan.frontier_id.as_deref(), project);
    issues.extend(validate_source_ingest_plan_against_sets(
        plan,
        &finding_ids,
        &artifact_ids,
    ));
    issues
}

fn validate_projection_frontier_id(
    projected_frontier_id: Option<&str>,
    project: &Project,
) -> Vec<ProjectionIssue> {
    let mut issues = Vec::new();
    let actual = project.frontier_id();
    match projected_frontier_id {
        Some(id) if id == actual => {}
        Some(id) => push_issue(
            &mut issues,
            "frontier_id",
            format!("projection frontier_id '{id}' does not match frontier '{actual}'"),
        ),
        None => push_issue(
            &mut issues,
            "frontier_id",
            "projection must pin the frontier_id it was reviewed against",
        ),
    }
    issues
}

fn validate_source_ingest_plan_against_sets(
    plan: &SourceIngestPlan,
    finding_ids: &HashSet<&str>,
    artifact_ids: &HashSet<&str>,
) -> Vec<ProjectionIssue> {
    let mut issues = Vec::new();
    if plan.schema != SOURCE_INGEST_PLAN_SCHEMA {
        push_issue(
            &mut issues,
            "schema",
            format!("expected {SOURCE_INGEST_PLAN_SCHEMA}"),
        );
    }
    require_non_empty(&mut issues, "name", &plan.name);
    require_non_empty(&mut issues, "verified_at", &plan.verified_at);
    if plan.entries.is_empty() {
        push_issue(
            &mut issues,
            "entries",
            "at least one source entry is required",
        );
    }
    let mut seen = HashSet::new();
    let mut categories = HashSet::new();
    let mut priorities = HashSet::new();
    let mut ingested = 0usize;
    for (idx, entry) in plan.entries.iter().enumerate() {
        let path = format!("entries[{idx}]");
        require_non_empty(&mut issues, &format!("{path}.id"), &entry.id);
        if !entry.id.trim().is_empty() && !seen.insert(entry.id.as_str()) {
            push_issue(
                &mut issues,
                format!("{path}.id"),
                format!("duplicate source entry id '{}'", entry.id),
            );
        }
        require_non_empty(&mut issues, &format!("{path}.name"), &entry.name);
        require_non_empty(&mut issues, &format!("{path}.category"), &entry.category);
        require_non_empty(&mut issues, &format!("{path}.priority"), &entry.priority);
        require_non_empty(
            &mut issues,
            &format!("{path}.representation"),
            &entry.representation,
        );
        require_non_empty(
            &mut issues,
            &format!("{path}.source_type"),
            &entry.source_type,
        );
        require_non_empty(
            &mut issues,
            &format!("{path}.ingest_status"),
            &entry.ingest_status,
        );
        require_non_empty(
            &mut issues,
            &format!("{path}.access_terms"),
            &entry.access_terms,
        );
        require_non_empty(
            &mut issues,
            &format!("{path}.license_note"),
            &entry.license_note,
        );
        require_non_empty(
            &mut issues,
            &format!("{path}.target_use"),
            &entry.target_use,
        );
        if !usable_source_locator(&entry.locator) {
            push_issue(
                &mut issues,
                format!("{path}.locator"),
                format!("source locator '{}' is not usable", entry.locator),
            );
        }
        categories.insert(entry.category.as_str());
        priorities.insert(entry.priority.as_str());
        if !matches!(entry.priority.as_str(), "P0" | "P1" | "P2") {
            push_issue(
                &mut issues,
                format!("{path}.priority"),
                "priority must be P0, P1, or P2",
            );
        }
        if !matches!(
            entry.ingest_status.as_str(),
            "ingested" | "pointer_only" | "candidate" | "excluded"
        ) {
            push_issue(
                &mut issues,
                format!("{path}.ingest_status"),
                "unknown ingest status",
            );
        }
        match entry.ingest_status.as_str() {
            "ingested" => {
                ingested += 1;
                let Some(id) = entry.current_frontier_artifact_id.as_deref() else {
                    push_issue(
                        &mut issues,
                        format!("{path}.current_frontier_artifact_id"),
                        "ingested entries must name a frontier artifact",
                    );
                    continue;
                };
                if !artifact_ids.contains(id) {
                    push_issue(
                        &mut issues,
                        format!("{path}.current_frontier_artifact_id"),
                        format!("artifact '{id}' does not resolve in frontier"),
                    );
                }
            }
            _ => {
                if entry.current_frontier_artifact_id.is_some() {
                    push_issue(
                        &mut issues,
                        format!("{path}.current_frontier_artifact_id"),
                        "only ingested entries may name a frontier artifact",
                    );
                }
            }
        }
        if entry.target_findings.is_empty() {
            push_issue(
                &mut issues,
                format!("{path}.target_findings"),
                "at least one target finding is required",
            );
        }
        for id in &entry.target_findings {
            if !finding_ids.contains(id.as_str()) {
                push_issue(
                    &mut issues,
                    format!("{path}.target_findings"),
                    format!("finding '{id}' does not resolve in frontier"),
                );
            }
        }
    }
    for required in [
        "clinical_trial_registry",
        "regulatory",
        "dataset_or_registry",
        "code_or_tool",
        "literature_or_table",
    ] {
        if !categories.contains(required) {
            push_issue(
                &mut issues,
                "entries.category",
                format!("missing source category '{required}'"),
            );
        }
    }
    for required in ["P0", "P1"] {
        if !priorities.contains(required) {
            push_issue(
                &mut issues,
                "entries.priority",
                format!("missing source priority '{required}'"),
            );
        }
    }
    if ingested == 0 {
        push_issue(
            &mut issues,
            "entries.ingest_status",
            "at least one source entry must be ingested",
        );
    }
    issues
}

fn validate_decision_brief_against_sets(
    brief: &DecisionBrief,
    finding_ids: &HashSet<&str>,
    artifact_ids: &HashSet<&str>,
    event_ids: &HashSet<&str>,
) -> Vec<ProjectionIssue> {
    let mut issues = Vec::new();
    if brief.schema != DECISION_BRIEF_SCHEMA {
        push_issue(
            &mut issues,
            "schema",
            format!("expected {DECISION_BRIEF_SCHEMA}"),
        );
    }
    if brief.questions.len() != KNOWN_QUESTION_IDS.len() {
        push_issue(
            &mut issues,
            "questions",
            format!("expected {} decision questions", KNOWN_QUESTION_IDS.len()),
        );
    }
    if let Some(boundary) = &brief.projection_boundary {
        validate_decision_projection_boundary(boundary, &mut issues);
    } else if brief
        .source_frontier
        .to_ascii_lowercase()
        .contains("anti-amyloid")
    {
        push_issue(
            &mut issues,
            "projection_boundary",
            "anti-amyloid decision projections must declare the review and medical-guidance boundary",
        );
    }
    let mut seen = HashSet::new();
    for (idx, question) in brief.questions.iter().enumerate() {
        let path = format!("questions[{idx}]");
        if !KNOWN_QUESTION_IDS.contains(&question.id.as_str()) {
            push_issue(
                &mut issues,
                format!("{path}.id"),
                format!("unknown decision question id '{}'", question.id),
            );
        }
        if !seen.insert(question.id.as_str()) {
            push_issue(
                &mut issues,
                format!("{path}.id"),
                format!("duplicate decision question id '{}'", question.id),
            );
        }
        require_non_empty(&mut issues, &format!("{path}.title"), &question.title);
        require_non_empty(
            &mut issues,
            &format!("{path}.short_answer"),
            &question.short_answer,
        );
        require_non_empty(&mut issues, &format!("{path}.caveat"), &question.caveat);
        require_non_empty(
            &mut issues,
            &format!("{path}.what_would_change_this_answer"),
            &question.what_would_change_this_answer,
        );
        if question.supporting_findings.is_empty() {
            push_issue(
                &mut issues,
                format!("{path}.supporting_findings"),
                "at least one supporting finding is required",
            );
        }
        for id in question
            .supporting_findings
            .iter()
            .chain(question.tension_findings.iter())
            .chain(question.gap_findings.iter())
        {
            if !finding_ids.contains(id.as_str()) {
                push_issue(
                    &mut issues,
                    format!("{path}.finding_refs"),
                    format!("finding '{id}' does not resolve in frontier"),
                );
            }
        }
        for id in &question.artifact_ids {
            if !artifact_ids.contains(id.as_str()) {
                push_issue(
                    &mut issues,
                    format!("{path}.artifact_ids"),
                    format!("artifact '{id}' does not resolve in frontier"),
                );
            }
        }
        validate_decision_evidence_basis(question, &path, artifact_ids, finding_ids, &mut issues);
        for (path_idx, correction_path) in question.correction_paths.iter().enumerate() {
            let correction_path_path = format!("{path}.correction_paths[{path_idx}]");
            require_non_empty(
                &mut issues,
                &format!("{correction_path_path}.summary"),
                &correction_path.summary,
            );
            require_non_empty(
                &mut issues,
                &format!("{correction_path_path}.status"),
                &correction_path.status,
            );
            if !finding_ids.contains(correction_path.finding_id.as_str()) {
                push_issue(
                    &mut issues,
                    format!("{correction_path_path}.finding_id"),
                    format!(
                        "finding '{}' does not resolve in frontier",
                        correction_path.finding_id
                    ),
                );
            }
            for id in &correction_path.event_ids {
                if !event_ids.contains(id.as_str()) {
                    push_issue(
                        &mut issues,
                        format!("{correction_path_path}.event_ids"),
                        format!("event '{id}' does not resolve in frontier"),
                    );
                }
            }
            for id in &correction_path.artifact_ids {
                if !artifact_ids.contains(id.as_str()) {
                    push_issue(
                        &mut issues,
                        format!("{correction_path_path}.artifact_ids"),
                        format!("artifact '{id}' does not resolve in frontier"),
                    );
                }
            }
        }
    }
    issues
}

fn validate_decision_projection_boundary(
    boundary: &DecisionProjectionBoundary,
    issues: &mut Vec<ProjectionIssue>,
) {
    require_non_empty(issues, "projection_boundary.status", &boundary.status);
    require_non_empty(
        issues,
        "projection_boundary.reviewer_profile",
        &boundary.reviewer_profile,
    );
    require_non_empty(
        issues,
        "projection_boundary.agent_confidence_policy",
        &boundary.agent_confidence_policy,
    );
    if boundary.counts_as_medical_guidance {
        push_issue(
            issues,
            "projection_boundary.counts_as_medical_guidance",
            "decision projections cannot count as medical guidance",
        );
    }
    if boundary.outside_review_claimed {
        push_issue(
            issues,
            "projection_boundary.outside_review_claimed",
            "outside review cannot be claimed by a projection boundary",
        );
    }
    let policy = boundary.agent_confidence_policy.to_ascii_lowercase();
    if !(policy.contains("no unreviewed agent confidence") || policy.contains("not promoted")) {
        push_issue(
            issues,
            "projection_boundary.agent_confidence_policy",
            "policy must block unreviewed agent confidence from decision surfaces",
        );
    }
}

fn validate_decision_evidence_basis(
    question: &DecisionQuestion,
    path: &str,
    artifact_ids: &HashSet<&str>,
    finding_ids: &HashSet<&str>,
    issues: &mut Vec<ProjectionIssue>,
) {
    if question.evidence_basis.is_empty() {
        push_issue(
            issues,
            format!("{path}.evidence_basis"),
            "source-backed decision questions require at least one basis row",
        );
        return;
    }
    let mut covered_findings = HashSet::new();
    for (basis_idx, basis) in question.evidence_basis.iter().enumerate() {
        let basis_path = format!("{path}.evidence_basis[{basis_idx}]");
        require_non_empty(
            issues,
            &format!("{basis_path}.finding_id"),
            &basis.finding_id,
        );
        require_non_empty(issues, &format!("{basis_path}.role"), &basis.role);
        require_non_empty(
            issues,
            &format!("{basis_path}.review_status"),
            &basis.review_status,
        );
        require_non_empty(issues, &format!("{basis_path}.caveat"), &basis.caveat);
        if !usable_source_locator(&basis.source_locator) {
            push_issue(
                issues,
                format!("{basis_path}.source_locator"),
                format!("source locator '{}' is not usable", basis.source_locator),
            );
        }
        if !matches!(basis.role.as_str(), "supporting" | "tension" | "gap") {
            push_issue(
                issues,
                format!("{basis_path}.role"),
                "basis role must be supporting, tension, or gap",
            );
        }
        if !finding_ids.contains(basis.finding_id.as_str()) {
            push_issue(
                issues,
                format!("{basis_path}.finding_id"),
                format!(
                    "finding '{}' does not resolve in frontier",
                    basis.finding_id
                ),
            );
        }
        let role_contains_finding = match basis.role.as_str() {
            "supporting" => question.supporting_findings.contains(&basis.finding_id),
            "tension" => question.tension_findings.contains(&basis.finding_id),
            "gap" => question.gap_findings.contains(&basis.finding_id),
            _ => false,
        };
        if !role_contains_finding {
            push_issue(
                issues,
                format!("{basis_path}.finding_id"),
                format!(
                    "finding '{}' is not listed under the '{}' role",
                    basis.finding_id, basis.role
                ),
            );
        }
        if basis.artifact_ids.is_empty() {
            push_issue(
                issues,
                format!("{basis_path}.artifact_ids"),
                "basis rows must name at least one artifact",
            );
        }
        for id in &basis.artifact_ids {
            if !artifact_ids.contains(id.as_str()) {
                push_issue(
                    issues,
                    format!("{basis_path}.artifact_ids"),
                    format!("artifact '{id}' does not resolve in frontier"),
                );
            }
        }
        covered_findings.insert(basis.finding_id.as_str());
    }
    if !question
        .supporting_findings
        .iter()
        .any(|id| covered_findings.contains(id.as_str()))
    {
        push_issue(
            issues,
            format!("{path}.evidence_basis"),
            "basis rows must include at least one supporting finding",
        );
    }
}

fn validate_trial_outcomes_against_sets(
    outcomes: &TrialOutcomes,
    finding_ids: &HashSet<&str>,
    artifact_ids: &HashSet<&str>,
) -> Vec<ProjectionIssue> {
    let mut issues = Vec::new();
    if outcomes.schema != TRIAL_OUTCOMES_SCHEMA {
        push_issue(
            &mut issues,
            "schema",
            format!("expected {TRIAL_OUTCOMES_SCHEMA}"),
        );
    }
    if outcomes.rows.is_empty() {
        push_issue(&mut issues, "rows", "at least one trial row is required");
    }
    let mut seen = HashSet::new();
    for (idx, row) in outcomes.rows.iter().enumerate() {
        let path = format!("rows[{idx}]");
        require_non_empty(&mut issues, &format!("{path}.id"), &row.id);
        if !row.id.trim().is_empty() && !seen.insert(row.id.as_str()) {
            push_issue(
                &mut issues,
                format!("{path}.id"),
                format!("duplicate trial row id '{}'", row.id),
            );
        }
        require_non_empty(&mut issues, &format!("{path}.program"), &row.program);
        require_non_empty(&mut issues, &format!("{path}.drug"), &row.drug);
        require_non_empty(
            &mut issues,
            &format!("{path}.primary_endpoint"),
            &row.primary_endpoint,
        );
        require_non_empty(
            &mut issues,
            &format!("{path}.regulatory_status"),
            &row.regulatory_status,
        );
        if row.source_locators.is_empty() {
            push_issue(
                &mut issues,
                format!("{path}.source_locators"),
                "at least one source locator is required",
            );
        }
        for locator in &row.source_locators {
            if !usable_source_locator(locator) {
                push_issue(
                    &mut issues,
                    format!("{path}.source_locators"),
                    format!("source locator '{locator}' is not usable"),
                );
            }
        }
        if row.finding_ids.is_empty() {
            push_issue(
                &mut issues,
                format!("{path}.finding_ids"),
                "at least one finding reference is required",
            );
        }
        for id in &row.finding_ids {
            if !finding_ids.contains(id.as_str()) {
                push_issue(
                    &mut issues,
                    format!("{path}.finding_ids"),
                    format!("finding '{id}' does not resolve in frontier"),
                );
            }
        }
        for id in &row.artifact_ids {
            if !artifact_ids.contains(id.as_str()) {
                push_issue(
                    &mut issues,
                    format!("{path}.artifact_ids"),
                    format!("artifact '{id}' does not resolve in frontier"),
                );
            }
        }
    }
    issues
}

fn validate_source_verification_shape(verification: &SourceVerification) -> Vec<ProjectionIssue> {
    let mut issues = Vec::new();
    if verification.schema != SOURCE_VERIFICATION_SCHEMA {
        push_issue(
            &mut issues,
            "schema",
            format!("expected {SOURCE_VERIFICATION_SCHEMA}"),
        );
    }
    require_non_empty(&mut issues, "verified_at", &verification.verified_at);
    if verification.sources.is_empty() {
        push_issue(
            &mut issues,
            "sources",
            "at least one verified source is required",
        );
    }
    let mut seen = HashSet::new();
    for (idx, source) in verification.sources.iter().enumerate() {
        let path = format!("sources[{idx}]");
        require_non_empty(&mut issues, &format!("{path}.id"), &source.id);
        if !source.id.trim().is_empty() && !seen.insert(source.id.as_str()) {
            push_issue(
                &mut issues,
                format!("{path}.id"),
                format!("duplicate source verification id '{}'", source.id),
            );
        }
        require_non_empty(&mut issues, &format!("{path}.title"), &source.title);
        require_non_empty(&mut issues, &format!("{path}.agency"), &source.agency);
        require_non_empty(
            &mut issues,
            &format!("{path}.current_status"),
            &source.current_status,
        );
        if !usable_source_locator(&source.url) {
            push_issue(
                &mut issues,
                format!("{path}.url"),
                format!("source url '{}' is not usable", source.url),
            );
        }
    }
    issues
}

fn usable_source_locator(locator: &str) -> bool {
    let trimmed = locator.trim();
    trimmed.starts_with("https://")
        || trimmed.starts_with("doi:")
        || trimmed.starts_with("pmid:")
        || trimmed.starts_with("NCT")
}

fn require_non_empty(issues: &mut Vec<ProjectionIssue>, path: &str, value: &str) {
    if value.trim().is_empty() {
        push_issue(issues, path, "field must be non-empty");
    }
}

fn push_issue(
    issues: &mut Vec<ProjectionIssue>,
    path: impl Into<String>,
    message: impl Into<String>,
) {
    issues.push(ProjectionIssue {
        path: path.into(),
        message: message.into(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_ids() -> HashSet<&'static str> {
        HashSet::from(["vf_known", "vf_tension", "vf_gap"])
    }

    fn artifact_ids() -> HashSet<&'static str> {
        HashSet::from(["va_known"])
    }

    fn event_ids() -> HashSet<&'static str> {
        HashSet::from(["vev_known"])
    }

    fn valid_question(id: &str) -> DecisionQuestion {
        DecisionQuestion {
            id: id.to_string(),
            title: "Question".to_string(),
            short_answer: "Bounded answer.".to_string(),
            caveat: "Scoped caveat.".to_string(),
            confidence: "medium".to_string(),
            supporting_findings: vec!["vf_known".to_string()],
            tension_findings: vec!["vf_tension".to_string()],
            gap_findings: vec!["vf_gap".to_string()],
            artifact_ids: vec!["va_known".to_string()],
            evidence_basis: vec![DecisionEvidenceBasis {
                finding_id: "vf_known".to_string(),
                role: "supporting".to_string(),
                source_locator: "pmid:12345678".to_string(),
                review_status: "reviewed with caveat".to_string(),
                caveat: "Used only inside the tested scope.".to_string(),
                artifact_ids: vec!["va_known".to_string()],
            }],
            what_would_change_this_answer: "A prospective readout.".to_string(),
            correction_paths: vec![DecisionCorrectionPath {
                finding_id: "vf_known".to_string(),
                summary: "Reviewed and caveated for proof use.".to_string(),
                event_ids: vec!["vev_known".to_string()],
                artifact_ids: vec!["va_known".to_string()],
                status: "reviewed".to_string(),
            }],
            tags: vec![],
        }
    }

    fn valid_brief() -> DecisionBrief {
        DecisionBrief {
            schema: DECISION_BRIEF_SCHEMA.to_string(),
            frontier_id: Some("vfr_test".to_string()),
            updated_at: "2026-05-06T00:00:00Z".to_string(),
            source_frontier: "Test frontier".to_string(),
            projection_boundary: None,
            questions: KNOWN_QUESTION_IDS
                .iter()
                .map(|id| valid_question(id))
                .collect(),
        }
    }

    #[test]
    fn decision_brief_validates_all_references() {
        let issues = validate_decision_brief_against_sets(
            &valid_brief(),
            &finding_ids(),
            &artifact_ids(),
            &event_ids(),
        );
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn decision_brief_reports_unknown_question_and_missing_refs() {
        let mut brief = valid_brief();
        brief.questions[0].id = "treatment-advice".to_string();
        brief.questions[0].supporting_findings = vec!["vf_missing".to_string()];
        brief.questions[0].artifact_ids = vec!["va_missing".to_string()];
        brief.questions[0].correction_paths[0].event_ids = vec!["vev_missing".to_string()];

        let issues = validate_decision_brief_against_sets(
            &brief,
            &finding_ids(),
            &artifact_ids(),
            &event_ids(),
        );
        let messages = issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(messages.contains("unknown decision question id"));
        assert!(messages.contains("finding 'vf_missing' does not resolve"));
        assert!(messages.contains("artifact 'va_missing' does not resolve"));
        assert!(messages.contains("event 'vev_missing' does not resolve"));
    }

    #[test]
    fn trial_summary_requires_source_locator_and_refs() {
        let outcomes = TrialOutcomes {
            schema: TRIAL_OUTCOMES_SCHEMA.to_string(),
            frontier_id: Some("vfr_test".to_string()),
            updated_at: "2026-05-06T00:00:00Z".to_string(),
            rows: vec![TrialOutcomeRow {
                id: "clarity-ad".to_string(),
                program: "CLARITY AD".to_string(),
                drug: "lecanemab".to_string(),
                mechanism: "anti-protofibril amyloid beta antibody".to_string(),
                phase: "Phase 3".to_string(),
                nct_ids: vec!["NCT03887455".to_string()],
                population: "Early symptomatic AD".to_string(),
                disease_stage: "MCI or mild dementia".to_string(),
                amyloid_confirmation: "Required".to_string(),
                duration: "18 months".to_string(),
                primary_endpoint: "CDR-SB".to_string(),
                cognitive_result: "Positive, modest absolute effect.".to_string(),
                biomarker_result: "Amyloid reduced.".to_string(),
                aria_or_safety_result: "ARIA risk requires monitoring.".to_string(),
                regulatory_status: "FDA traditional approval.".to_string(),
                source_locators: vec!["ftp://not-accepted".to_string()],
                finding_ids: vec!["vf_missing".to_string()],
                artifact_ids: vec!["va_missing".to_string()],
                tags: vec![],
            }],
        };

        let issues =
            validate_trial_outcomes_against_sets(&outcomes, &finding_ids(), &artifact_ids());
        let messages = issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(messages.contains("source locator 'ftp://not-accepted' is not usable"));
        assert!(messages.contains("finding 'vf_missing' does not resolve"));
        assert!(messages.contains("artifact 'va_missing' does not resolve"));
    }

    #[test]
    fn source_verification_requires_current_source_records() {
        let verification = SourceVerification {
            schema: SOURCE_VERIFICATION_SCHEMA.to_string(),
            frontier_id: Some("vfr_test".to_string()),
            verified_at: "2026-05-06T00:00:00Z".to_string(),
            notes: vec![],
            sources: vec![VerifiedSource {
                id: "fda-label".to_string(),
                title: "FDA label".to_string(),
                url: "https://www.accessdata.fda.gov/example.pdf".to_string(),
                agency: "FDA".to_string(),
                current_status: "Current label checked for the demo frontier.".to_string(),
            }],
        };

        let issues = validate_source_verification_shape(&verification);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn source_verification_reports_unusable_urls_and_missing_status() {
        let verification = SourceVerification {
            schema: SOURCE_VERIFICATION_SCHEMA.to_string(),
            frontier_id: Some("vfr_test".to_string()),
            verified_at: "".to_string(),
            notes: vec![],
            sources: vec![VerifiedSource {
                id: "cms".to_string(),
                title: "CMS record".to_string(),
                url: "ftp://not-supported".to_string(),
                agency: "CMS".to_string(),
                current_status: "".to_string(),
            }],
        };

        let issues = validate_source_verification_shape(&verification);
        let messages = issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(messages.contains("field must be non-empty"));
        assert!(messages.contains("source url 'ftp://not-supported' is not usable"));
    }

    #[test]
    fn source_ingest_plan_requires_artifacts_and_target_findings() {
        let plan = SourceIngestPlan {
            schema: SOURCE_INGEST_PLAN_SCHEMA.to_string(),
            frontier_id: Some("vfr_test".to_string()),
            name: "Focused source plan".to_string(),
            verified_at: "2026-05-06T00:00:00Z".to_string(),
            policy: serde_json::json!({}),
            entries: vec![
                SourceIngestEntry {
                    id: "ct-primary".to_string(),
                    name: "Primary trial registry".to_string(),
                    category: "clinical_trial_registry".to_string(),
                    priority: "P0".to_string(),
                    representation: "clinical_trial_record".to_string(),
                    source_type: "registry_record".to_string(),
                    locator: "https://clinicaltrials.gov/study/NCT03887455".to_string(),
                    ingest_status: "ingested".to_string(),
                    current_frontier_artifact_id: Some("va_known".to_string()),
                    access_terms: "Public registry metadata".to_string(),
                    license_note: "Registry terms apply".to_string(),
                    target_findings: vec!["vf_known".to_string()],
                    target_use: "Anchor the trial result".to_string(),
                },
                SourceIngestEntry {
                    id: "reg-label".to_string(),
                    name: "Regulatory label".to_string(),
                    category: "regulatory".to_string(),
                    priority: "P1".to_string(),
                    representation: "registry_record".to_string(),
                    source_type: "regulatory_record".to_string(),
                    locator: "https://www.fda.gov/example".to_string(),
                    ingest_status: "candidate".to_string(),
                    current_frontier_artifact_id: None,
                    access_terms: "Public locator".to_string(),
                    license_note: "Regulatory terms apply".to_string(),
                    target_findings: vec!["vf_known".to_string()],
                    target_use: "Track current label status".to_string(),
                },
                SourceIngestEntry {
                    id: "dataset-access".to_string(),
                    name: "Dataset access record".to_string(),
                    category: "dataset_or_registry".to_string(),
                    priority: "P1".to_string(),
                    representation: "dataset".to_string(),
                    source_type: "dataset_access_record".to_string(),
                    locator: "https://adni.loni.usc.edu/data-samples/access-data/".to_string(),
                    ingest_status: "candidate".to_string(),
                    current_frontier_artifact_id: None,
                    access_terms: "Registration required".to_string(),
                    license_note: "Do not mirror participant data".to_string(),
                    target_findings: vec!["vf_known".to_string()],
                    target_use: "Represent longitudinal biomarker access".to_string(),
                },
                SourceIngestEntry {
                    id: "code-gate".to_string(),
                    name: "Release gate".to_string(),
                    category: "code_or_tool".to_string(),
                    priority: "P1".to_string(),
                    representation: "code".to_string(),
                    source_type: "repository_code".to_string(),
                    locator: "https://github.com/vela-science/vela".to_string(),
                    ingest_status: "candidate".to_string(),
                    current_frontier_artifact_id: None,
                    access_terms: "Repository code".to_string(),
                    license_note: "Repository terms apply".to_string(),
                    target_findings: vec!["vf_known".to_string()],
                    target_use: "Make validation executable".to_string(),
                },
                SourceIngestEntry {
                    id: "decision-table".to_string(),
                    name: "Decision table".to_string(),
                    category: "literature_or_table".to_string(),
                    priority: "P1".to_string(),
                    representation: "table".to_string(),
                    source_type: "frontier_projection".to_string(),
                    locator: "https://vela-site.fly.dev/workbench".to_string(),
                    ingest_status: "candidate".to_string(),
                    current_frontier_artifact_id: None,
                    access_terms: "Public metadata".to_string(),
                    license_note: "Source terms apply".to_string(),
                    target_findings: vec!["vf_known".to_string()],
                    target_use: "Serve decision projection".to_string(),
                },
            ],
        };

        let issues =
            validate_source_ingest_plan_against_sets(&plan, &finding_ids(), &artifact_ids());
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn source_ingest_plan_reports_unresolved_ingested_entries() {
        let plan = SourceIngestPlan {
            schema: SOURCE_INGEST_PLAN_SCHEMA.to_string(),
            frontier_id: Some("vfr_test".to_string()),
            name: "Focused source plan".to_string(),
            verified_at: "2026-05-06T00:00:00Z".to_string(),
            policy: serde_json::json!({}),
            entries: vec![SourceIngestEntry {
                id: "ct-primary".to_string(),
                name: "Primary trial registry".to_string(),
                category: "clinical_trial_registry".to_string(),
                priority: "urgent".to_string(),
                representation: "clinical_trial_record".to_string(),
                source_type: "registry_record".to_string(),
                locator: "ftp://not-usable".to_string(),
                ingest_status: "ingested".to_string(),
                current_frontier_artifact_id: Some("va_missing".to_string()),
                access_terms: "Public registry metadata".to_string(),
                license_note: "Registry terms apply".to_string(),
                target_findings: vec!["vf_missing".to_string()],
                target_use: "Anchor the trial result".to_string(),
            }],
        };

        let issues =
            validate_source_ingest_plan_against_sets(&plan, &finding_ids(), &artifact_ids());
        let messages = issues
            .iter()
            .map(|issue| issue.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(messages.contains("source locator 'ftp://not-usable' is not usable"));
        assert!(messages.contains("priority must be P0, P1, or P2"));
        assert!(messages.contains("artifact 'va_missing' does not resolve"));
        assert!(messages.contains("finding 'vf_missing' does not resolve"));
    }
}
