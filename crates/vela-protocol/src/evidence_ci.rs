//! Evidence CI.
//!
//! Evidence CI is a review-readiness projection. It checks grounding,
//! locator, policy, and confidence-update inputs before review. It does
//! not decide whether a scientific claim is true.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::bundle::FindingBundle;
use crate::frontier_policy;
use crate::project::Project;
use crate::repo;
use crate::scientific_diff::ScientificDiffPack;
use crate::sources::{self, ConditionRecord, EvidenceAtom, SourceRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCiStatus {
    Passed,
    Warning,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCiSeverity {
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCiClassification {
    ReleaseBlocking,
    ReviewWarning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceCiCheck {
    pub id: String,
    pub group: String,
    pub classification: EvidenceCiClassification,
    pub status: EvidenceCiStatus,
    pub severity: EvidenceCiSeverity,
    pub target_type: String,
    pub target_id: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub release_blocking: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceCiSummary {
    pub total: usize,
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
    pub release_blocking: usize,
    pub review_warning: usize,
    pub info: usize,
    pub release_blocking_failed: usize,
    #[serde(default)]
    pub groups: Vec<EvidenceCiGroupSummary>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceCiGroupSummary {
    pub group: String,
    pub total: usize,
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
    pub release_blocking: usize,
    pub review_warning: usize,
    pub info: usize,
    pub release_blocking_failed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceCiReport {
    pub ok: bool,
    pub command: String,
    pub frontier_id: String,
    pub frontier_path: String,
    pub checked_at: String,
    pub scope: String,
    pub summary: EvidenceCiSummary,
    #[serde(default)]
    pub checks: Vec<EvidenceCiCheck>,
    #[serde(default)]
    pub caveats: Vec<String>,
}

impl EvidenceCiReport {
    fn finish(mut self) -> Self {
        self.summary = summarize(&self.checks);
        self.ok = self.summary.release_blocking_failed == 0;
        self
    }
}

pub fn run_frontier(frontier_path: &Path) -> Result<EvidenceCiReport, String> {
    let project = repo::load_from_path(frontier_path)?;
    Ok(run_project(&project, frontier_path))
}

/// In-memory Evidence CI over an already-loaded project. `frontier_path`
/// is read only for static policy documents and to label the report; all
/// frontier state (findings, proof) comes from the in-memory `project`.
///
/// This lets a caller run a *prospective* check on an unsaved, mutated
/// project — the basis of the accept-time Engine gate, which runs CI on
/// the post-accept state before deciding whether to persist it.
pub fn run_project(project: &Project, frontier_path: &Path) -> EvidenceCiReport {
    let frontier_id = project.frontier_id();
    let projection = sources::derive_projection(project);
    let source_by_finding = source_records_by_finding(&projection.sources);
    let atom_by_finding = evidence_atoms_by_finding(&projection.evidence_atoms);
    let condition_by_finding = condition_records_by_finding(&projection.condition_records);
    let mut checks = Vec::new();

    match frontier_policy::load_policy_summary(frontier_path) {
        Ok(summary) if summary.ok => checks.push(pass(
            "policy.review_requirement",
            "frontier",
            &frontier_id,
            "Frontier policy is available for review requirements.",
            None,
            true,
        )),
        Ok(summary) => checks.push(fail(
            "policy.review_requirement",
            "frontier",
            &frontier_id,
            "Frontier policy is missing required policy documents.",
            Some(format!("missing: {}", summary.missing_required.join(", "))),
            true,
        )),
        Err(e) => checks.push(fail(
            "policy.review_requirement",
            "frontier",
            &frontier_id,
            "Frontier policy could not be loaded.",
            Some(e),
            true,
        )),
    }

    checks.push(pass(
        "contradiction.scan_status",
        "frontier",
        &frontier_id,
        "Contradiction scan is available through local tension queries.",
        Some(format!(
            "{} finding bundle(s) are in scope.",
            project.findings.len()
        )),
        false,
    ));

    let proof_status = project.proof_state.latest_packet.status.as_str();
    if matches!(proof_status, "fresh" | "current" | "ready") {
        checks.push(pass(
            "proof.freshness",
            "frontier",
            &frontier_id,
            "Proof state is current for this frontier.",
            Some(proof_status.to_string()),
            false,
        ));
    } else {
        checks.push(warn(
            "proof.freshness",
            "frontier",
            &frontier_id,
            "Proof state is stale, missing, or needs regeneration before release.",
            Some(proof_status.to_string()),
        ));
    }

    for finding in &project.findings {
        let sources = source_by_finding
            .get(finding.id.as_str())
            .cloned()
            .unwrap_or_default();
        let atoms = atom_by_finding
            .get(finding.id.as_str())
            .cloned()
            .unwrap_or_default();
        let conditions = condition_by_finding
            .get(finding.id.as_str())
            .cloned()
            .unwrap_or_default();
        add_finding_checks(&mut checks, finding, &sources, &atoms, &conditions);
    }

    EvidenceCiReport {
        ok: false,
        command: "evidence-ci".to_string(),
        frontier_id,
        frontier_path: frontier_path.display().to_string(),
        checked_at: Utc::now().to_rfc3339(),
        scope: "frontier".to_string(),
        summary: EvidenceCiSummary::default(),
        checks,
        caveats: vec![
            "Evidence CI checks review readiness. It does not establish final truth.".to_string(),
            "Draft debt is reported as warning unless a release-critical policy or diff-pack check fails.".to_string(),
        ],
    }
    .finish()
}

pub fn run_diff_pack(frontier_path: &Path, pack_id: &str) -> Result<EvidenceCiReport, String> {
    let project = repo::load_from_path(frontier_path)?;
    let frontier_id = project.frontier_id();
    let pack_path = frontier_path
        .join(".vela")
        .join("diff_packs")
        .join(format!("{pack_id}.json"));
    let body = std::fs::read_to_string(&pack_path)
        .map_err(|e| format!("read diff pack {}: {e}", pack_path.display()))?;
    let pack: ScientificDiffPack =
        serde_json::from_str(&body).map_err(|e| format!("parse diff pack: {e}"))?;
    pack.verify()
        .map_err(|e| format!("verify diff pack {pack_id}: {e}"))?;
    let summary = pack.review_summary(frontier_path);
    let mut checks = Vec::new();

    checks.push(pass(
        "diff_pack.signature_or_id",
        "diff_pack",
        &pack.pack_id,
        "Diff Pack id verifies from canonical bytes.",
        if pack.signature.is_some() {
            Some("signature present and verified".to_string())
        } else {
            Some("unsigned pack".to_string())
        },
        true,
    ));

    let proof_status = project.proof_state.latest_packet.status.as_str();
    if matches!(proof_status, "fresh" | "current" | "ready") {
        checks.push(pass(
            "proof.freshness",
            "frontier",
            &frontier_id,
            "Proof state is current for this frontier.",
            Some(proof_status.to_string()),
            false,
        ));
    } else {
        checks.push(warn(
            "proof.freshness",
            "frontier",
            &frontier_id,
            "Proof state is stale, missing, or needs regeneration before release.",
            Some(proof_status.to_string()),
        ));
    }

    if summary.source_artifacts.is_empty() {
        checks.push(fail(
            "source.id_presence",
            "diff_pack",
            &pack.pack_id,
            "Diff Pack member proposals do not declare source artifacts.",
            None,
            true,
        ));
    } else {
        checks.push(pass(
            "source.id_presence",
            "diff_pack",
            &pack.pack_id,
            "Diff Pack declares source artifacts.",
            Some(format!(
                "{} source artifact(s)",
                summary.source_artifacts.len()
            )),
            true,
        ));
    }

    for op in &summary.proposed_operations {
        if op.required_reviewer_count == 0 || op.required_reviewer_roles.is_empty() {
            checks.push(fail(
                "policy.review_requirement",
                "proposal",
                &op.proposal_id,
                "Operation has no role-scoped review requirement.",
                Some(op.operation_class.clone()),
                true,
            ));
        } else {
            checks.push(pass(
                "policy.review_requirement",
                "proposal",
                &op.proposal_id,
                "Operation has a role-scoped review requirement.",
                Some(op.required_reviewer_roles.join(", ")),
                true,
            ));
        }

        if op.operation_class == "revise_confidence" {
            if op.source_or_evidence_refs.is_empty() {
                checks.push(fail(
                    "confidence_delta.source_reference",
                    "proposal",
                    &op.proposal_id,
                    "Confidence operation is missing a source or evidence reference.",
                    None,
                    true,
                ));
            } else {
                checks.push(pass(
                    "confidence_delta.source_reference",
                    "proposal",
                    &op.proposal_id,
                    "Confidence operation cites source or evidence input.",
                    Some(op.source_or_evidence_refs.join(", ")),
                    true,
                ));
            }
            if op
                .confidence_reason
                .as_deref()
                .unwrap_or_default()
                .trim()
                .is_empty()
            {
                checks.push(fail(
                    "confidence_delta.reason",
                    "proposal",
                    &op.proposal_id,
                    "Confidence operation is missing a bounded reason.",
                    None,
                    true,
                ));
            } else {
                checks.push(pass(
                    "confidence_delta.reason",
                    "proposal",
                    &op.proposal_id,
                    "Confidence operation has a bounded reason.",
                    op.confidence_reason.clone(),
                    true,
                ));
            }
        }
    }

    Ok(EvidenceCiReport {
        ok: false,
        command: "diff-pack.validate".to_string(),
        frontier_id,
        frontier_path: frontier_path.display().to_string(),
        checked_at: Utc::now().to_rfc3339(),
        scope: format!("diff_pack:{pack_id}"),
        summary: EvidenceCiSummary::default(),
        checks,
        caveats: vec![
            "Diff Pack Evidence CI validates review packet readiness before local review."
                .to_string(),
            "Accepted frontier state still requires reviewer action and canonical events."
                .to_string(),
        ],
    }
    .finish())
}

fn add_finding_checks(
    checks: &mut Vec<EvidenceCiCheck>,
    finding: &FindingBundle,
    sources: &[&SourceRecord],
    atoms: &[&EvidenceAtom],
    conditions: &[&ConditionRecord],
) {
    if sources.is_empty() {
        checks.push(warn(
            "source.id_presence",
            "finding",
            &finding.id,
            "Finding has no source record linked to it.",
            None,
        ));
    } else {
        checks.push(pass(
            "source.id_presence",
            "finding",
            &finding.id,
            "Finding has a source record.",
            Some(
                sources
                    .iter()
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            false,
        ));
    }

    if sources
        .iter()
        .any(|source| sources::source_has_canonical_locator(source))
    {
        checks.push(pass(
            "source.canonical_locator",
            "finding",
            &finding.id,
            "Finding has a canonical source locator.",
            Some(
                sources
                    .iter()
                    .map(|s| s.locator.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
            false,
        ));
    } else {
        checks.push(warn(
            "source.canonical_locator",
            "finding",
            &finding.id,
            "Finding source locator needs canonical repair.",
            None,
        ));
    }

    if atoms.iter().any(|atom| atom.locator.is_some()) {
        checks.push(pass(
            "evidence.span_presence",
            "finding",
            &finding.id,
            "Finding has an evidence atom locator.",
            None,
            false,
        ));
    } else {
        checks.push(warn(
            "evidence.span_presence",
            "finding",
            &finding.id,
            "Finding is missing a source evidence span or locator.",
            None,
        ));
    }

    if finding.evidence.evidence_type.trim().is_empty() {
        checks.push(warn(
            "evidence.type",
            "finding",
            &finding.id,
            "Finding evidence type is missing.",
            None,
        ));
    } else {
        checks.push(pass(
            "evidence.type",
            "finding",
            &finding.id,
            "Finding declares an evidence type.",
            Some(finding.evidence.evidence_type.clone()),
            false,
        ));
    }

    let combined = finding_text(finding);

    // Math-domain profile. The clinical / experimental study-design checks
    // below (trial registry, population, comparator/baseline, endpoint) only
    // carry meaning for an EMPIRICAL claim. A theoretical or formal claim —
    // an Erdős conjecture, a proved theorem — has no comparator arm, primary
    // endpoint, or study population, so firing those warnings on it is a
    // category error, not a real review gap (the original biomedical profile
    // raised ~2 such warnings per math finding). For a non-empirical claim
    // the four checks are recorded as not-applicable passes, keeping the
    // warning meaningful only where a study-design dimension actually exists.
    if !is_study_design_applicable(finding) {
        for (id, dimension) in [
            ("trial.registry_reference", "trial registry reference"),
            ("condition.population", "population or model context"),
            ("condition.comparator_or_baseline", "comparator or baseline"),
            ("condition.endpoint", "endpoint or measured outcome"),
        ] {
            checks.push(pass(
                id,
                "finding",
                &finding.id,
                "Study-design dimension is not applicable to a theoretical, formal, or benchmark-result claim.",
                Some(format!(
                    "{dimension} is not a dimension of a theoretical/formal/benchmark claim"
                )),
                false,
            ));
        }
        return;
    }

    if mentions_trial(&combined) && !has_trial_registry_ref(&combined, sources) {
        checks.push(warn(
            "trial.registry_reference",
            "finding",
            &finding.id,
            "Finding appears trial-related but lacks an NCT registry reference.",
            None,
        ));
    } else {
        checks.push(pass(
            "trial.registry_reference",
            "finding",
            &finding.id,
            "Trial registry reference check completed.",
            None,
            false,
        ));
    }

    if has_population(finding, &combined, conditions) {
        checks.push(pass(
            "condition.population",
            "finding",
            &finding.id,
            "Population or model context is declared.",
            None,
            false,
        ));
    } else {
        checks.push(warn(
            "condition.population",
            "finding",
            &finding.id,
            "Population or model context is missing or unclear.",
            None,
        ));
    }

    if conditions
        .iter()
        .any(|record| record.comparator_status == "declared")
    {
        checks.push(pass(
            "condition.comparator_or_baseline",
            "finding",
            &finding.id,
            "Comparator or baseline is declared.",
            None,
            false,
        ));
    } else {
        checks.push(warn(
            "condition.comparator_or_baseline",
            "finding",
            &finding.id,
            "Comparator or baseline is missing or unclear.",
            None,
        ));
    }

    if has_endpoint(&combined) {
        checks.push(pass(
            "condition.endpoint",
            "finding",
            &finding.id,
            "Endpoint or measured outcome is declared.",
            None,
            false,
        ));
    } else {
        checks.push(warn(
            "condition.endpoint",
            "finding",
            &finding.id,
            "Endpoint or measured outcome is missing or unclear.",
            None,
        ));
    }
}

fn source_records_by_finding(sources: &[SourceRecord]) -> BTreeMap<&str, Vec<&SourceRecord>> {
    let mut map = BTreeMap::<&str, Vec<&SourceRecord>>::new();
    for source in sources {
        for finding_id in &source.finding_ids {
            map.entry(finding_id.as_str()).or_default().push(source);
        }
    }
    map
}

fn evidence_atoms_by_finding(atoms: &[EvidenceAtom]) -> BTreeMap<&str, Vec<&EvidenceAtom>> {
    let mut map = BTreeMap::<&str, Vec<&EvidenceAtom>>::new();
    for atom in atoms {
        map.entry(atom.finding_id.as_str()).or_default().push(atom);
    }
    map
}

fn condition_records_by_finding(
    records: &[ConditionRecord],
) -> BTreeMap<&str, Vec<&ConditionRecord>> {
    let mut map = BTreeMap::<&str, Vec<&ConditionRecord>>::new();
    for record in records {
        map.entry(record.finding_id.as_str())
            .or_default()
            .push(record);
    }
    map
}

fn summarize(checks: &[EvidenceCiCheck]) -> EvidenceCiSummary {
    let mut groups = standard_group_map();
    let mut summary = EvidenceCiSummary {
        total: checks.len(),
        ..EvidenceCiSummary::default()
    };
    for check in checks {
        match check.status {
            EvidenceCiStatus::Passed => summary.passed += 1,
            EvidenceCiStatus::Warning => summary.warnings += 1,
            EvidenceCiStatus::Failed => summary.failed += 1,
        }
        match check.classification {
            EvidenceCiClassification::ReleaseBlocking => summary.release_blocking += 1,
            EvidenceCiClassification::ReviewWarning => summary.review_warning += 1,
            EvidenceCiClassification::Info => summary.info += 1,
        }
        if check.release_blocking && check.status == EvidenceCiStatus::Failed {
            summary.release_blocking_failed += 1;
        }
        let group = groups
            .entry(check.group.clone())
            .or_insert_with(|| EvidenceCiGroupSummary {
                group: check.group.clone(),
                ..EvidenceCiGroupSummary::default()
            });
        group.total += 1;
        match check.status {
            EvidenceCiStatus::Passed => group.passed += 1,
            EvidenceCiStatus::Warning => group.warnings += 1,
            EvidenceCiStatus::Failed => group.failed += 1,
        }
        match check.classification {
            EvidenceCiClassification::ReleaseBlocking => group.release_blocking += 1,
            EvidenceCiClassification::ReviewWarning => group.review_warning += 1,
            EvidenceCiClassification::Info => group.info += 1,
        }
        if check.release_blocking && check.status == EvidenceCiStatus::Failed {
            group.release_blocking_failed += 1;
        }
    }
    summary.groups = groups.into_values().collect();
    summary
}

fn standard_group_map() -> BTreeMap<String, EvidenceCiGroupSummary> {
    [
        "source_locator_coverage",
        "evidence_atom_quality",
        "confidence_change_support",
        "policy_requirements",
        "unresolved_warnings",
        "stale_proof",
    ]
    .into_iter()
    .map(|group| {
        (
            group.to_string(),
            EvidenceCiGroupSummary {
                group: group.to_string(),
                ..EvidenceCiGroupSummary::default()
            },
        )
    })
    .collect()
}

fn group_for_check(id: &str, status: &EvidenceCiStatus) -> String {
    if id.starts_with("source.") || id == "trial.registry_reference" {
        "source_locator_coverage"
    } else if id.starts_with("evidence.") || id.starts_with("condition.") {
        "evidence_atom_quality"
    } else if id.starts_with("confidence_delta.") {
        "confidence_change_support"
    } else if id.starts_with("policy.") {
        "policy_requirements"
    } else if id.starts_with("proof.") {
        "stale_proof"
    } else if *status == EvidenceCiStatus::Warning || *status == EvidenceCiStatus::Failed {
        "unresolved_warnings"
    } else {
        "info"
    }
    .to_string()
}

fn classification_for_check(
    status: &EvidenceCiStatus,
    release_blocking: bool,
) -> EvidenceCiClassification {
    if release_blocking {
        EvidenceCiClassification::ReleaseBlocking
    } else if *status == EvidenceCiStatus::Warning || *status == EvidenceCiStatus::Failed {
        EvidenceCiClassification::ReviewWarning
    } else {
        EvidenceCiClassification::Info
    }
}

fn pass(
    id: &str,
    target_type: &str,
    target_id: &str,
    message: &str,
    detail: Option<String>,
    release_blocking: bool,
) -> EvidenceCiCheck {
    let status = EvidenceCiStatus::Passed;
    let group = group_for_check(id, &status);
    let classification = classification_for_check(&status, release_blocking);
    EvidenceCiCheck {
        id: id.to_string(),
        group,
        classification,
        status,
        severity: EvidenceCiSeverity::Info,
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        message: message.to_string(),
        detail,
        release_blocking,
    }
}

fn warn(
    id: &str,
    target_type: &str,
    target_id: &str,
    message: &str,
    detail: Option<String>,
) -> EvidenceCiCheck {
    let status = EvidenceCiStatus::Warning;
    let release_blocking = false;
    let group = group_for_check(id, &status);
    let classification = classification_for_check(&status, release_blocking);
    EvidenceCiCheck {
        id: id.to_string(),
        group,
        classification,
        status,
        severity: EvidenceCiSeverity::Warn,
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        message: message.to_string(),
        detail,
        release_blocking,
    }
}

fn fail(
    id: &str,
    target_type: &str,
    target_id: &str,
    message: &str,
    detail: Option<String>,
    release_blocking: bool,
) -> EvidenceCiCheck {
    let status = EvidenceCiStatus::Failed;
    let group = group_for_check(id, &status);
    let classification = classification_for_check(&status, release_blocking);
    EvidenceCiCheck {
        id: id.to_string(),
        group,
        classification,
        status,
        severity: EvidenceCiSeverity::Error,
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        message: message.to_string(),
        detail,
        release_blocking,
    }
}

fn finding_text(finding: &FindingBundle) -> String {
    let mut parts = vec![
        finding.assertion.text.as_str(),
        finding.conditions.text.as_str(),
        finding.evidence.model_system.as_str(),
        finding.evidence.method.as_str(),
        finding.evidence.evidence_type.as_str(),
    ];
    if let Some(species) = finding.evidence.species.as_deref() {
        parts.push(species);
    }
    if let Some(effect) = finding.evidence.effect_size.as_deref() {
        parts.push(effect);
    }
    parts.join(" ").to_ascii_lowercase()
}

fn mentions_trial(text: &str) -> bool {
    text.contains("trial") || text.contains("phase ") || text.contains("randomized")
}

/// Whether the clinical / experimental study-design checks (trial registry,
/// population, comparator/baseline, endpoint) apply to this finding.
///
/// They apply to an EMPIRICAL claim and are a category error on a theoretical
/// or formal one (an Erdős conjecture has no comparator arm). A finding is
/// treated as empirical — checks apply, the original biomedical behaviour —
/// unless its assertion or evidence type marks it clearly theoretical/formal
/// AND it carries no empirical signal. The guard means a theoretical-typed
/// finding that still describes lab conditions or a trial keeps the checks,
/// so a *computational study of a clinical trial* is not misclassified.
fn is_study_design_applicable(finding: &FindingBundle) -> bool {
    const THEORETICAL_ASSERTION: &[&str] = &[
        "open_question",
        "theoretical",
        "conjecture",
        "theorem",
        "lemma",
        "proposition",
        "definition",
        "formal",
        // A benchmark result (model X scores Y on dataset Z) is empirical but
        // not a clinical study: its "comparator" is other models on the same
        // leaderboard, not a control arm, and it has no trial registry, primary
        // endpoint, or study population. The clinical study-design checks are a
        // category error on it, the same as on a theorem.
        "benchmark_result",
    ];
    const THEORETICAL_EVIDENCE: &[&str] = &["theoretical", "mathematical", "formal", "proof"];

    let assertion_type = finding.assertion.assertion_type.trim().to_ascii_lowercase();
    let evidence_type = finding.evidence.evidence_type.trim().to_ascii_lowercase();
    let theoretical = THEORETICAL_ASSERTION.contains(&assertion_type.as_str())
        || THEORETICAL_EVIDENCE.contains(&evidence_type.as_str());
    if !theoretical {
        return true;
    }

    // A theoretical-typed finding that still carries empirical signal (wet-lab
    // conditions or a trial mention) keeps the study-design checks.
    let c = &finding.conditions;
    c.clinical_trial
        || c.human_data
        || c.in_vivo
        || c.in_vitro
        || mentions_trial(&finding_text(finding))
}

fn has_trial_registry_ref(text: &str, sources: &[&SourceRecord]) -> bool {
    text.contains("nct")
        || sources.iter().any(|source| {
            let joined = format!(
                "{} {} {}",
                source.locator,
                source.title,
                source.content_hash.as_deref().unwrap_or("")
            )
            .to_ascii_lowercase();
            joined.contains("nct")
        })
}

fn has_population(finding: &FindingBundle, text: &str, conditions: &[&ConditionRecord]) -> bool {
    finding.conditions.human_data
        || finding.conditions.clinical_trial
        || !finding.conditions.species_verified.is_empty()
        || finding.evidence.species.is_some()
        || conditions.iter().any(|record| {
            record.species.is_some()
                || matches!(
                    record.translation_scope.as_str(),
                    "human" | "animal_model" | "in_vitro" | "computational"
                )
        })
        || [
            "patient",
            "patients",
            "human",
            "mouse",
            "mice",
            "rat",
            "cell",
            "cohort",
            "adult",
            "pediatric",
            "in vitro",
            "in vivo",
        ]
        .iter()
        .any(|needle| text.contains(needle))
}

fn has_endpoint(text: &str) -> bool {
    [
        "endpoint",
        "outcome",
        "survival",
        "cognition",
        "clearance",
        "uptake",
        "transport",
        "expression",
        "effect size",
        "p=",
        "p value",
        "hazard ratio",
        "odds ratio",
        "risk ratio",
        "auc",
        "measurement",
        "assay",
        "level",
        "concentration",
        "response",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

pub fn required_check_ids(report: &EvidenceCiReport) -> BTreeSet<String> {
    report.checks.iter().map(|check| check.id.clone()).collect()
}

/// Stable key for one check instance: `id@target_id`. The same check id
/// recurs once per finding, so the target disambiguates instances. Used
/// to diff a before/after report and isolate the checks a single state
/// change introduced.
fn check_key(check: &EvidenceCiCheck) -> String {
    format!("{}@{}", check.id, check.target_id)
}

/// Keys of the release-blocking checks that are currently *failing*.
/// A change that adds a key here introduces a release-blocking
/// regression — the Engine gate blocks truth-bearing acceptances on
/// exactly this set.
pub fn release_blocking_failures(report: &EvidenceCiReport) -> BTreeSet<String> {
    report
        .checks
        .iter()
        .filter(|c| c.release_blocking && c.status == EvidenceCiStatus::Failed)
        .map(check_key)
        .collect()
}

/// Keys of the review-warning checks — review-readiness gaps (missing
/// source id, locator, evidence span, …) that do not block release but
/// a reviewer should see. The Engine surfaces the ones a change
/// introduces, and `--strict` blocks on them.
pub fn review_warnings(report: &EvidenceCiReport) -> BTreeSet<String> {
    report
        .checks
        .iter()
        .filter(|c| c.status == EvidenceCiStatus::Warning)
        .map(check_key)
        .collect()
}
